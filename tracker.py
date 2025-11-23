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
import datetime

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


def is_google_proxy_request(ua: str) -> bool:
    # Google proxy detection based on User-Agent
    return any(p in ua for p in ["googleimageproxy", "ggpht.com", "imageproxy"])

def is_google_scanner_ip(ip: str) -> bool:
    # Known Google scanner IP ranges
    # 72.14.x.x - Scanner
    # Removed 66.249.x.x as it is used for real mobile opens
    if ip.startswith("72.14."): return True
    return False

def is_gmail_sent_view(referer: str) -> bool:
    if "mail.google.com" not in referer:
        return False
    sent_indicators = ["in%3Asent", "in:sent", "/#sent", "#sent", "label/sent", "mail/sent", "sent%20mail", "qm_sent", "ib_sent"]
    return any(ind in referer for ind in sent_indicators)

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
        gmail_thread_id = payload.get("gmail_thread_id")

        cur.execute("""
            INSERT INTO sends (track_id, recipient_email, gmail_message_id, gmail_thread_id, sender_email, sender_ip)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (track_id) DO UPDATE SET
                recipient_email = EXCLUDED.recipient_email,
                gmail_message_id = EXCLUDED.gmail_message_id,
                gmail_thread_id = EXCLUDED.gmail_thread_id,
                sender_email = COALESCE(EXCLUDED.sender_email, sends.sender_email),
                sender_ip = COALESCE(EXCLUDED.sender_ip, sends.sender_ip)
        """, (
            payload["track_id"],
            payload["recipient_email"],
            payload.get("gmail_message_id"),
            gmail_thread_id,
            sender_email,
            sender_ip
        ))
        conn.commit()

        print(f"✅ Registered send: track_id={payload['track_id']}, sender_email={sender_email}, thread_id={gmail_thread_id}")
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

    # DEBUG: Log if we suspect a sent folder view but it's not caught
    if "mail.google.com" in referer and not is_gmail_sent_view(referer):
        print(f"⚠️ Potential MISSED Sent Folder view? Referer: {referer}")

    conn = None
    cur = None
    
    # Prepare response with Cache Busting headers
    response = StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    try:
        conn = get_conn()
        cur = conn.cursor()

        # fetch the send info
        cur.execute("SELECT track_id, recipient_email, sender_email, sender_ip, created_at FROM sends WHERE track_id = %s", (track_id,))
        send_row = cur.fetchone()
        if not send_row:
            print(f"⚠️ No send record found for track_id: {track_id}")
            return response

        recipient_email = send_row["recipient_email"]
        stored_sender_email = send_row.get("sender_email")
        stored_sender_ip = send_row.get("sender_ip")
        send_time = send_row.get("created_at")

        # 1) If sender_email query param provided and equals stored sender => ignore
        if sender_email and stored_sender_email and sender_email.lower() == stored_sender_email.lower():
            print(f"👤 Ignored sender open (query param matched stored sender): {sender_email}")
            return response

        # 2) If sender_token provided, verify HMAC against stored sender
        if sender_token and stored_sender_email:
            if verify_sender_token(sender_token, stored_sender_email, track_id):
                print(f"👤 Ignored sender open (valid sender token for {stored_sender_email})")
                return response

        # 3) If referer indicates Gmail sent folder, ignore
        if is_gmail_sent_view(referer):
            print(f"📬 Ignored Gmail sent folder open (referer indicates sent)")
            return response

        # 4) Detect Google proxy
        is_google_proxy = is_google_proxy_request(ua)
        is_google_scanner = is_google_scanner_ip(client_ip)

        # 5) Basic bot detection (only obvious bots)
        is_bot = any(b in ua for b in ["bot", "crawl", "spider", "monitoring", "checker", "scan"]) or ua == ""
        
        # 6) Time-Window Filtering (Ghost Open Fix)
        # If request is within 5 seconds of send time, mark as bot
        if send_time:
            now = datetime.datetime.now(datetime.timezone.utc)
            if send_time.tzinfo is None:
                send_time = send_time.replace(tzinfo=datetime.timezone.utc)
            
            time_diff = (now - send_time).total_seconds()
            print(f"⏱️ Time since send: {time_diff:.2f}s")
            
            if time_diff < 5.0:
                print(f"👻 Ghost Open detected (within 5s): marking as bot")
                is_bot = True

        # Mark scanners as bots
        if is_google_scanner:
            print(f"🤖 Google Scanner IP detected: {client_ip}")
            is_bot = True

        # Block only obvious bots or internal IPs
        if is_internal_ip(client_ip):
            print(f"🏠 BLOCKED internal IP: {client_ip}")
            return response

        # 7) Google proxy handling
        via_proxy = is_google_proxy
        
        # 8) Insert event
        cur.execute(
            "INSERT INTO events (track_id, event_type, ip_address, user_agent, is_bot, via_proxy) VALUES (%s, 'open', %s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (track_id, client_ip, ua, is_bot, via_proxy)
        )
        conn.commit()

        if is_bot:
             print(f"🤖 Logged BOT open for: {recipient_email}")
        elif via_proxy:
            print(f"✅ Logged proxy open for: {recipient_email}")
        else:
            print(f"✅ Logged direct open for: {recipient_email}")

    except Exception as e:
        print(f"❌ pixel error: {e}")
        return response
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return response


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
    #  - there exists a direct open event (via_proxy = FALSE) AND is_bot = FALSE
    #  OR
    #  - there exist at least 1 proxy open event (via_proxy = TRUE) AND is_bot = FALSE
    #    (Changed from 2 to 1 because we now filter bots via time-window)

    if recipient_email:
        cur.execute("""
            SELECT CASE
                WHEN EXISTS (
                    SELECT 1 FROM events e
                    JOIN sends s ON e.track_id = s.track_id
                    WHERE (s.gmail_message_id = %s OR s.gmail_thread_id = %s)
                      AND s.recipient_email = %s
                      AND e.event_type = 'open'
                      AND e.via_proxy = FALSE
                      AND e.is_bot = FALSE
                ) THEN 'read'
                WHEN (SELECT COUNT(*) FROM events e2 JOIN sends s2 ON e2.track_id = s2.track_id
                      WHERE (s2.gmail_message_id = %s OR s2.gmail_thread_id = %s) 
                      AND s2.recipient_email = %s AND e2.event_type = 'open' AND e2.via_proxy = TRUE AND e2.is_bot = FALSE) >= 1
                  THEN 'read'
                WHEN EXISTS (
                    SELECT 1 FROM sends s WHERE (s.gmail_message_id = %s OR s.gmail_thread_id = %s) AND s.recipient_email = %s
                ) THEN 'sent'
                ELSE 'unknown'
            END AS status
        """, (gmail_message_id, gmail_message_id, recipient_email, 
              gmail_message_id, gmail_message_id, recipient_email, 
              gmail_message_id, gmail_message_id, recipient_email))
    else:
        cur.execute("""
            SELECT CASE
                WHEN EXISTS (
                    SELECT 1 FROM events e
                    JOIN sends s ON e.track_id = s.track_id
                    WHERE (s.gmail_message_id = %s OR s.gmail_thread_id = %s)
                      AND e.event_type = 'open'
                      AND e.via_proxy = FALSE
                      AND e.is_bot = FALSE
                ) THEN 'read'
                WHEN (SELECT COUNT(*) FROM events e2 JOIN sends s2 ON e2.track_id = s2.track_id
                      WHERE (s2.gmail_message_id = %s OR s2.gmail_thread_id = %s) 
                      AND e2.event_type = 'open' AND e2.via_proxy = TRUE AND e2.is_bot = FALSE) >= 1
                  THEN 'read'
                WHEN EXISTS (
                    SELECT 1 FROM sends s WHERE (s.gmail_message_id = %s OR s.gmail_thread_id = %s)
                ) THEN 'sent'
                ELSE 'unknown'
            END AS status
        """, (gmail_message_id, gmail_message_id, 
              gmail_message_id, gmail_message_id, 
              gmail_message_id, gmail_message_id))

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
