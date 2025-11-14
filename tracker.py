from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import psycopg2, os, uuid, io
from psycopg2.extras import RealDictCursor
from urllib.parse import unquote_plus
from dotenv import load_dotenv
import ipaddress

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

import hashlib
import hmac
import time

# Add a secret key for HMAC verification
HMAC_SECRET = os.getenv("HMAC_SECRET", "your-secret-key-here")

def generate_sender_token(sender_email, track_id, timestamp=None):
    """Generate HMAC token to verify sender identity"""
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
    """Verify HMAC token and check expiration"""
    try:
        timestamp_str, signature = token.split(":")
        timestamp = int(timestamp_str)
        
        # Check token expiration
        if time.time() - timestamp > max_age:
            return False
            
        # Verify signature
        expected_message = f"{sender_email}:{track_id}:{timestamp_str}"
        expected_signature = hmac.new(
            HMAC_SECRET.encode(),
            expected_message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    except:
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
        return True  # Treat invalid IPs as internal

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
async def register_send(payload: dict):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sends (track_id, recipient_email, gmail_message_id)
            VALUES (%s, %s, %s)
            ON CONFLICT (track_id) DO NOTHING
        """, (
            payload["track_id"],
            payload["recipient_email"],
            payload.get("gmail_message_id"),
        ))
        conn.commit()
        return JSONResponse({"ok": True})
    except Exception as e:
        print("❌ register_send error:", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    finally:
        cur.close()
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

    ua = request.headers.get("User-Agent", "").lower()
    ip = request.client.host
    xff = request.headers.get("X-Forwarded-For", "")
    client_ip = xff.split(",")[0].strip() if xff else ip
    referer = request.headers.get("Referer", "").lower()  # This is used below

    print(f"🔍 Pixel request - Track ID: {track_id}, IP: {client_ip}")
    print(f"   Sender Token: {sender_token is not None}")
    print(f"   Sender Email: {sender_email}")
    print(f"   Referer: {referer}")  # Using referer here
    print(f"   User-Agent: {ua[:100]}...")

    try:
        conn = get_conn()
        cur = conn.cursor()

        # ✅ Get send record
        cur.execute("SELECT recipient_email, sender_email FROM sends WHERE track_id = %s", (track_id,))
        send_row = cur.fetchone()

        if not send_row:
            print(f"⚠️ No send record found for track_id: {track_id}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        recipient_email = send_row["recipient_email"]
        stored_sender_email = send_row["sender_email"]

        # ✅ FIRST: Check if this is the sender opening the email (highest priority)
        if sender_token and sender_email:
            is_valid_sender = verify_sender_token(sender_token, sender_email, track_id)
            if is_valid_sender and sender_email == stored_sender_email:
                print(f"👤 Ignored sender open: {sender_email}")
                cur.close()
                conn.close()
                return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # ✅ SECOND: Use referer to detect Gmail sent folder opens (fallback protection)
        is_gmail_sent_folder = (
            "mail.google.com" in referer and 
            any(indicator in referer for indicator in [
                "in%3Asent", "in:sent", "/#sent", "#sent", "label/sent", 
                "mail/sent", "sent%20mail", "category=sent", "search=sent"
            ])
        )
        
        if is_gmail_sent_folder:
            print(f"📬 Ignored Gmail sent folder open: {referer}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # ✅ THIRD: Block Google proxies and bots
        is_google_proxy = any(proxy_indicator in ua for proxy_indicator in [
            'googleimageproxy', 'ggpht.com', 'imageproxy', 'via ggpht.com'
        ]) or any(proxy_ip in client_ip for proxy_ip in [
            '66.249.', '64.233.', '72.14.', '74.125.'
        ])
        
        is_suspicious_ua = not ua or len(ua) < 20 or any(suspicious in ua for suspicious in [
            'bot', 'crawl', 'spider', 'monitoring', 'checker', 'scan'
        ])

        if is_google_proxy or is_suspicious_ua:
            print(f"🚫 BLOCKED proxy/bot request")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # ✅ FOURTH: Additional security - block internal IPs
        if is_internal_ip(client_ip):
            print(f"🏠 BLOCKED internal IP: {client_ip}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # ✅ FIFTH: Rate limiting
        cur.execute("""
            SELECT COUNT(*) as recent_opens 
            FROM events 
            WHERE ip_address = %s AND event_type = 'open' AND created_at > NOW() - INTERVAL '1 hour'
        """, (client_ip,))
        recent_opens = cur.fetchone()["recent_opens"]
        
        if recent_opens > 10:
            print(f"⏱️ RATE LIMITED IP: {client_ip} ({recent_opens} opens in last hour)")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # ✅ ONLY COUNT AS GENUINE if it passed ALL filters
        cur.execute("""
            INSERT INTO events (track_id, event_type, ip_address, user_agent, is_bot)
            VALUES (%s, 'open', %s, %s, FALSE)
            ON CONFLICT DO NOTHING
        """, (track_id, client_ip, ua))
        conn.commit()
        
        print(f"✅ Logged GENUINE recipient open:")
        print(f"   Recipient: {recipient_email}")
        print(f"   IP: {client_ip}")
        print(f"   Referer: {referer}")  # Using referer here too

    except Exception as e:
        print(f"❌ pixel error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        cur.close()
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

    if recipient_email:
        # Check if an open event exists for this message and recipient
        cur.execute("""
            SELECT 
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM events e
                        JOIN sends s ON e.track_id = s.track_id
                        WHERE s.gmail_message_id = %s AND s.recipient_email = %s AND e.event_type = 'open'
                    )
                    THEN 'read'
                    WHEN EXISTS (
                        SELECT 1 FROM sends s
                        WHERE s.gmail_message_id = %s AND s.recipient_email = %s
                    )
                    THEN 'sent'
                    ELSE 'unknown'
                END AS status
        """, (gmail_message_id, recipient_email, gmail_message_id, recipient_email))
    else:
        cur.execute("""
            SELECT 
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM events e
                        JOIN sends s ON e.track_id = s.track_id
                        WHERE s.gmail_message_id = %s AND e.event_type = 'open'
                    )
                    THEN 'read'
                    WHEN EXISTS (
                        SELECT 1 FROM sends s
                        WHERE s.gmail_message_id = %s
                    )
                    THEN 'sent'
                    ELSE 'unknown'
                END AS status
        """, (gmail_message_id, gmail_message_id))

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