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

def is_internal_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_loopback or
            ip_obj.is_private or
            ip_obj.is_reserved or
            ip_obj.is_link_local
        )
    except ValueError:
        return False

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
async def pixel(track_id: str, request: Request):
    if not valid_uuid(track_id):
        raise HTTPException(status_code=404)

    ua = request.headers.get("User-Agent", "").lower()
    ip = request.client.host
    xff = request.headers.get("X-Forwarded-For", "")
    client_ip = xff.split(",")[0].strip() if xff else ip
    referer = request.headers.get("Referer", "").lower()
    accept = request.headers.get("Accept", "").lower()

    print(f"🔍 Pixel request - Track ID: {track_id}, IP: {client_ip}")
    print(f"   Referer: {referer}")
    print(f"   User-Agent: {ua[:100]}...")
    print(f"   Accept: {accept}")

    try:
        conn = get_conn()
        cur = conn.cursor()

        # ✅ Check the DB for recipient email associated with the track_id
        cur.execute("SELECT recipient_email, gmail_message_id FROM sends WHERE track_id = %s", (track_id,))
        send_row = cur.fetchone()

        if not send_row:
            print(f"⚠️ No send record found for track_id: {track_id}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        recipient_email = send_row["recipient_email"]
        gmail_message_id = send_row["gmail_message_id"]

        # ✅ MULTI-LAYERED FILTERING - Only count as genuine if ALL conditions pass
        
        # Layer 1: IP-based filtering (check if internal/private IP)
        if is_internal_ip(client_ip):
            print(f"⚠️ Ignored internal IP: {client_ip}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # Layer 2: User-Agent filtering
        is_suspicious_ua = not ua or len(ua) < 25
        is_bot = any(bot in ua for bot in [
            'bot', 'crawl', 'spider', 'monitoring', 'checker', 'scan', 
            'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
            'yandexbot', 'facebookexternalhit'
        ])
        is_gmail_app = 'gmail' in ua and ('image-fetch' in ua or 'image-fetching' in ua)
        
        if is_suspicious_ua or is_bot or is_gmail_app:
            print(f"⚠️ Ignored suspicious UA - Suspicious: {is_suspicious_ua}, Bot: {is_bot}, Gmail App: {is_gmail_app}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # Layer 3: Referer-based filtering (STRICT)
        is_gmail_referer = "mail.google.com" in referer
        is_empty_referer = not referer or referer == "null"
        
        # Comprehensive sent folder detection
        sent_folder_indicators = [
            "in%3Asent", "in:sent", "/#sent", "#sent", "label/sent", 
            "mail/sent", "act=sm", "view=cm&fs=1", "&sf=sm&", "sent%20mail",
            "category=sent", "search=sent", "qm_sent", "ib_sent"
        ]
        
        is_sent_folder = any(indicator in referer for indicator in sent_folder_indicators)
        
        # Also check for Gmail image proxy (common in sent folder opens)
        is_gmail_image_proxy = "googleusercontent" in referer or "imageproxy" in referer
        
        # Layer 4: Accept header filtering (browsers vs email clients)
        is_browser_accept = 'text/html' in accept or 'application/xhtml+xml' in accept
        is_email_client = 'image/' in accept and not is_browser_accept

        # ✅ DECISION MATRIX - When to IGNORE the open:
        ignore_conditions = [
            # Always ignore if from Gmail sent folder
            (is_gmail_referer and is_sent_folder),
            
            # Always ignore if from Gmail image proxy (sent folder previews)
            is_gmail_image_proxy,
            
            # Ignore if empty referer AND looks like browser (likely sent folder)
            (is_empty_referer and is_browser_accept),
            
            # Ignore if it's clearly the sender's Gmail
            (is_gmail_referer and not is_email_client),
        ]
        
        if any(ignore_conditions):
            print(f"⚠️ Ignored non-recipient open:")
            print(f"   - Gmail+Sent: {is_gmail_referer and is_sent_folder}")
            print(f"   - Gmail Proxy: {is_gmail_image_proxy}")
            print(f"   - Empty Ref+Browser: {is_empty_referer and is_browser_accept}")
            print(f"   - Gmail+Not Email: {is_gmail_referer and not is_email_client}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # Layer 5: Rate limiting by IP (optional but recommended)
        cur.execute("""
            SELECT COUNT(*) as recent_opens 
            FROM events 
            WHERE ip_address = %s AND event_type = 'open' AND created_at > NOW() - INTERVAL '1 hour'
        """, (client_ip,))
        recent_opens = cur.fetchone()["recent_opens"]
        
        if recent_opens > 50:  # More than 50 opens per hour from same IP
            print(f"⚠️ Rate limited IP: {client_ip} ({recent_opens} opens in last hour)")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # ✅ If we passed all filters, count as genuine open
        cur.execute("""
            INSERT INTO events (track_id, event_type, ip_address, user_agent, is_bot)
            VALUES (%s, 'open', %s, %s, FALSE)
            ON CONFLICT DO NOTHING
        """, (track_id, client_ip, ua))
        conn.commit()
        
        print(f"✅ Logged GENUINE open for:")
        print(f"   Recipient: {recipient_email}")
        print(f"   Gmail ID: {gmail_message_id}")
        print(f"   IP: {client_ip}")
        print(f"   UA: {ua[:50]}...")

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