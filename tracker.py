from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import psycopg2, os, uuid, io
from psycopg2.extras import RealDictCursor
from urllib.parse import unquote_plus
from dotenv import load_dotenv
import ipaddress
import hashlib
import hmac
import time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

load_dotenv()
DB_URL = os.getenv("DATABASE_URL")

def get_conn():
    return psycopg2.connect(DB_URL, cursor_factory=RealDictCursor, sslmode="require")

PIXEL_BYTES = bytes.fromhex(
    "89504E470D0A1A0A0000000D4948445200000001000000010806000000"
    "1F15C4890000000A49444154789C6360000000020001E221BC33000000"
    "0049454E44AE426082"
)

# Add a secret key for HMAC verification
HMAC_SECRET = os.getenv("HMAC_SECRET", "fallback-secret-key-change-this-in-production")

def generate_sender_token(sender_email, track_id, timestamp=None):
    if timestamp is None:
        timestamp = str(int(time.time()))
    message = f"{sender_email}:{track_id}:{timestamp}"
    signature = hmac.new(
        HMAC_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{timestamp}:{signature}"


def verify_sender_token(token, sender_email, track_id, max_age=3600):
    try:
        timestamp_str, signature = token.split(":")
        timestamp = int(timestamp_str)
        if time.time() - timestamp > max_age:
            return False
        expected_message = f"{sender_email}:{track_id}:{timestamp_str}"
        expected_signature = hmac.new(
            HMAC_SECRET.encode(),
            expected_message.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)
    except Exception:
        return False


def is_internal_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_loopback or
            ip_obj.is_private or
            ip_obj.is_reserved or
            ip_obj.is_link_local or
            ip_obj.is_multicast or
            str(ip_obj).startswith('127.') or
            str(ip_obj).startswith('10.') or
            str(ip_obj).startswith('192.168.') or
            (str(ip_obj).startswith('172.') and 16 <= ip_obj.packed[1] <= 31) or
            str(ip_obj) == '0.0.0.0'
        )
    except ValueError:
        return True


@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"➡️ Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    print(f"⬅️ Response status: {response.status_code}")
    return response


@app.get("/")
async def health_check():
    return {"status": "ok"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/_register_send")
async def register_send(payload: dict, request: Request):
    """Register a send. sender_email is optional; if missing we store NULL.
    Automation should send sender_email when available. This endpoint will no
    longer reject payloads missing sender_email."""
    cur = None
    conn = None
    try:
        sender_ip = request.client.host
        print(f"📝 Register send payload: {payload}")
        print(f"📝 Sender IP: {sender_ip}")

        # required fields: track_id + recipient_email
        required_fields = ["track_id", "recipient_email"]
        for field in required_fields:
            if field not in payload:
                print(f"❌ Missing required field: {field}")
                return JSONResponse({"ok": False, "error": f"Missing field: {field}"}, status_code=400)

        conn = get_conn()
        cur = conn.cursor()

        # allow optional sender_email
        sender_email = payload.get("sender_email")

        cur.execute("""
            INSERT INTO sends (track_id, recipient_email, gmail_message_id, sender_email, sender_ip)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (track_id) DO UPDATE SET
                recipient_email = EXCLUDED.recipient_email,
                gmail_message_id = EXCLUDED.gmail_message_id,
                sender_email = COALESCE(EXCLUDED.sender_email, sends.sender_email),
                sender_ip = COALESCE(EXCLUDED.sender_ip, sends.sender_ip)
        """, (
            payload["track_id"],
            payload["recipient_email"],
            payload.get("gmail_message_id"),
            sender_email,
            sender_ip
        ))
        conn.commit()

        print(f"✅ Registered send: track_id={payload['track_id']}, sender_email={sender_email}")
        return JSONResponse({"ok": True})

    except Exception as e:
        print("❌ register_send error:", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.get("/pixel/{track_id}.png")
async def pixel(
    track_id: str,
    request: Request,
    sender_token: str = Query(None),
    sender_email: str = Query(None)
):
    if not valid_uuid(track_id):
        raise HTTPException(status_code=404)

    ua = (request.headers.get("User-Agent") or "").lower()
    ip = request.client.host
    xff = request.headers.get("X-Forwarded-For", "")
    client_ip = xff.split(",")[0].strip() if xff else ip
    referer = (request.headers.get("Referer") or "").lower()

    print(f"🔍 Pixel request - Track ID: {track_id}, IP: {client_ip}")
    print(f"   Sender Token: {sender_token is not None}")
    print(f"   Sender Email param: {sender_email}")
    print(f"   Referer: {referer}")
    print(f"   User-Agent: {ua[:120]}...")

    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        # fetch the send info
        cur.execute("SELECT track_id, recipient_email, sender_email, sender_ip FROM sends WHERE track_id = %s", (track_id,))
        send_row = cur.fetchone()
        if not send_row:
            print(f"⚠️ No send record found for track_id: {track_id}")
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        recipient_email = send_row["recipient_email"]
        stored_sender_email = send_row.get("sender_email")
        stored_sender_ip = send_row.get("sender_ip")

        # 1) If sender_email query param provided and equals stored sender => ignore
        if sender_email and stored_sender_email and sender_email.lower() == stored_sender_email.lower():
            print(f"👤 Ignored sender open (query param matched stored sender): {sender_email}")
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # 2) If sender_token provided, verify HMAC against stored sender
        if sender_token and stored_sender_email:
            if verify_sender_token(sender_token, stored_sender_email, track_id):
                print(f"👤 Ignored sender open (valid sender token for {stored_sender_email})")
                return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # 3) If referer indicates Gmail sent folder and stored_sender_email matches actor, ignore
        is_gmail_referer = "mail.google.com" in referer
        sent_indicators = ["in%3Asent", "in:sent", "/#sent", "#sent", "label/sent", "mail/sent", "sent%20mail", "qm_sent", "ib_sent"]
        is_sent_folder = any(ind in referer for ind in sent_indicators)
        if is_gmail_referer and is_sent_folder and stored_sender_email:
            # We double-check remote IP vs stored sender_ip if available (some clients keep same IP)
            if stored_sender_ip and stored_sender_ip == client_ip:
                print(f"📬 Ignored Gmail sent folder open (ip match): {client_ip}")
                return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")
            # If IP mismatch, still ignore because referer strongly indicates sender viewing Sent
            print(f"📬 Ignored Gmail sent folder open (referer indicates sent)")
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # 4) Detect Google proxy
        is_google_proxy = any(p in ua for p in ["googleimageproxy", "ggpht.com", "imageproxy"]) or client_ip.startswith("66.") or client_ip.startswith("72.") or client_ip.startswith("64.") or client_ip.startswith("74.")

        # 5) Basic bot detection (only obvious bots)
        is_bot = any(b in ua for b in ["bot", "crawl", "spider", "monitoring", "checker", "scan"]) or ua == ""

        # Block only obvious bots or internal IPs
        if is_bot:
            print(f"🚫 BLOCKED bot request: UA={ua}")
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        if is_internal_ip(client_ip):
            print(f"🏠 BLOCKED internal IP: {client_ip}")
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # 6) Google proxy handling: ignore the *first* proxy prefetch, treat subsequent proxy fetches as real opens
        via_proxy = is_google_proxy
        proxy_count = 0
        cur.execute("SELECT COUNT(*) AS c FROM events WHERE track_id = %s AND via_proxy = TRUE", (track_id,))
        rc = cur.fetchone()
        if rc:
            proxy_count = rc["c"] if "c" in rc else rc[0]

        should_count_as_open = False
        if via_proxy:
            # If we have seen previous proxy fetch, treat this as a real open (user viewed after proxy)
            if proxy_count >= 1:
                should_count_as_open = True
            else:
                # first proxy fetch: log it but do not mark as confirmed open
                should_count_as_open = False
        else:
            # direct fetch from recipient's client counts
            should_count_as_open = True

        # 7) Insert event (we always record the fetch but mark via_proxy)
        cur.execute(
            "INSERT INTO events (track_id, event_type, ip_address, user_agent, is_bot, via_proxy) VALUES (%s, 'open', %s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (track_id, client_ip, ua, False, via_proxy)
        )
        conn.commit()

        if via_proxy:
            print(f"✅ Logged proxy open for: {recipient_email} (count_before={proxy_count})")
        else:
            print(f"✅ Logged direct open for: {recipient_email}")

        # 8) If this should be counted as confirmed open (non-proxy or subsequent proxy), ensure only one "confirmed" open exists
        if should_count_as_open:
            # We don't need a separate flag; existence of any open (direct) or multiple proxy entries will be considered by /status
            pass

    except Exception as e:
        print(f"❌ pixel error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")


@app.get("/click/{track_id}")
async def click(track_id: str, url: str):
    if not valid_uuid(track_id):
        raise HTTPException(status_code=404)
    decoded_url = unquote_plus(url)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO events (track_id, event_type, clicked_url, is_bot) VALUES (%s, 'click', %s, FALSE)",
        (track_id, decoded_url)
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(decoded_url)


@app.get("/status")
def get_status(
    gmail_message_id: str = Query(...),
    recipient_email: str = Query(None)
):
    conn = get_conn()
    cur = conn.cursor()

    # We consider a message 'read' if:
    #  - there exists a direct open event (via_proxy = FALSE)
    #  OR
    #  - there exist at least 2 proxy open events (via_proxy = TRUE) for that track_id
    # The SQL below checks for that condition and otherwise returns 'sent' when send exists.

    if recipient_email:
        cur.execute("""
            SELECT CASE
                WHEN EXISTS (
                    SELECT 1 FROM events e
                    JOIN sends s ON e.track_id = s.track_id
                    WHERE s.gmail_message_id = %s
                      AND s.recipient_email = %s
                      AND e.event_type = 'open'
                      AND e.via_proxy = FALSE
                ) THEN 'read'
                WHEN (SELECT COUNT(*) FROM events e2 JOIN sends s2 ON e2.track_id = s2.track_id
                      WHERE s2.gmail_message_id = %s AND s2.recipient_email = %s AND e2.event_type = 'open' AND e2.via_proxy = TRUE) >= 2
                  THEN 'read'
                WHEN EXISTS (
                    SELECT 1 FROM sends s WHERE s.gmail_message_id = %s AND s.recipient_email = %s
                ) THEN 'sent'
                ELSE 'unknown'
            END AS status
        """, (gmail_message_id, recipient_email, gmail_message_id, recipient_email, gmail_message_id, recipient_email))
    else:
        cur.execute("""
            SELECT CASE
                WHEN EXISTS (
                    SELECT 1 FROM events e
                    JOIN sends s ON e.track_id = s.track_id
                    WHERE s.gmail_message_id = %s
                      AND e.event_type = 'open'
                      AND e.via_proxy = FALSE
                ) THEN 'read'
                WHEN (SELECT COUNT(*) FROM events e2 JOIN sends s2 ON e2.track_id = s2.track_id
                      WHERE s2.gmail_message_id = %s AND e2.event_type = 'open' AND e2.via_proxy = TRUE) >= 2
                  THEN 'read'
                WHEN EXISTS (
                    SELECT 1 FROM sends s WHERE s.gmail_message_id = %s
                ) THEN 'sent'
                ELSE 'unknown'
            END AS status
        """, (gmail_message_id, gmail_message_id, gmail_message_id))

    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row or row["status"] == "unknown":
        print(f"⚠️ No send or open record found for Gmail ID: {gmail_message_id} ({recipient_email})")
        return JSONResponse({"status": "unknown"}, status_code=404)

    return JSONResponse({"status": row["status"]})


def valid_uuid(value):
    try:
        uuid.UUID(value)
        return True
    except Exception:
        return False