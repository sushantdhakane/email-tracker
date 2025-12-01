import asyncio
import requests
from user_agents import parse
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

# --- Configuration ---
PIXEL_BYTES = (
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
    b'\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
)
GOOGLE_PROXY_IPS = ["66.249.80.0/20", "66.102.0.0/20", "74.125.0.0/16", "64.233.160.0/19"]
HMAC_SECRET = os.getenv("HMAC_SECRET", "supersecretkey")

def get_conn():
    return psycopg2.connect(os.getenv("DATABASE_URL"), sslmode="require")

def is_google_proxy_request(user_agent):
    return "googleimageproxy" in user_agent.lower()

def is_google_scanner_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in GOOGLE_PROXY_IPS:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False

def verify_sender_token(token, sender_email, track_id):
    try:
        payload = f"{sender_email}:{track_id}"
        expected_signature = hmac.new(HMAC_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(token, expected_signature)
    except Exception:
        return False

def is_gmail_sent_view(referer):
    return "mail.google.com" in referer and "sent" in referer

def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return data.get("country"), data.get("city")
    except Exception:
        pass
    return None, None

def valid_uuid(value):
    try:
        uuid.UUID(value)
        return True
    except Exception:
        return False

@app.post("/register_send")
def register_send(payload: dict):
    # Expects: { "track_id": "...", "recipient": "...", "sender": "...", "subject": "..." }
    track_id = payload.get("track_id")
    recipient = payload.get("recipient")
    sender = payload.get("sender")
    subject = payload.get("subject")
    
    if not track_id or not recipient:
        raise HTTPException(status_code=400, detail="Missing track_id or recipient")

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO sends (track_id, recipient_email, sender_email, subject)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (track_id) DO UPDATE 
            SET subject = EXCLUDED.subject,
                recipient_email = EXCLUDED.recipient_email,
                sender_email = EXCLUDED.sender_email
        """, (track_id, recipient, sender, subject))
        conn.commit()
        return {"status": "registered", "track_id": track_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
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

    # 1. Capture Request Data
    ua_string = (request.headers.get("User-Agent") or "").lower()
    ip = request.client.host
    xff = request.headers.get("X-Forwarded-For", "")
    client_ip = xff.split(",")[0].strip() if xff else ip
    referer = (request.headers.get("Referer") or "").lower()

    # 2. Parse User-Agent (OS, Browser, Device)
    try:
        ua_parsed = parse(request.headers.get("User-Agent", ""))
        os_name = ua_parsed.os.family
        browser_name = ua_parsed.browser.family
        device_name = ua_parsed.device.family
    except Exception:
        os_name, browser_name, device_name = "Unknown", "Unknown", "Unknown"

    # 3. Resolve Location (Country, City)
    country, city = get_location(client_ip)

    # 4. Bot / Proxy Detection
    is_bot = is_google_scanner_ip(client_ip) or "bot" in ua_string
    via_proxy = is_google_proxy_request(ua_string)

    print(f"🔍 Pixel request - Track ID: {track_id}, IP: {client_ip}")
    print(f"   Location: {city}, {country} | OS: {os_name} | Browser: {browser_name}")

    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Fetch send info
        cur.execute("SELECT track_id, recipient_email, sender_email, sender_ip, created_at FROM sends WHERE track_id = %s", (track_id,))
        send_row = cur.fetchone()
        
        should_log = True
        if not send_row:
            print(f"⚠️ No send record found for track_id: {track_id}")
            should_log = False
        else:
            stored_sender_email = send_row.get("sender_email")

            # --- Sender Filtering Logic ---
            if sender_email and stored_sender_email and sender_email.lower() == stored_sender_email.lower():
                print(f"👤 Ignored sender open (query param matched)")
                should_log = False
            elif sender_token and stored_sender_email:
                if verify_sender_token(sender_token, stored_sender_email, track_id):
                    print(f"👤 Ignored sender open (valid token)")
                    should_log = False
            elif is_gmail_sent_view(referer):
                print(f"📬 Ignored Gmail sent folder open")
                should_log = False
            # ------------------------------

        if should_log:
            # Log the Open Event
            cur.execute("""
                INSERT INTO events (
                    track_id, event_type, ip_address, user_agent, is_bot, via_proxy,
                    country, city, os, browser, device, referrer
                ) VALUES (%s, 'open', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (
                track_id, client_ip, request.headers.get("User-Agent", ""), is_bot, via_proxy,
                country, city, os_name, browser_name, device_name, referer
            ))
            conn.commit()
            print(f"✅ Logged open for {track_id} from {city}, {country}")

    except Exception as e:
        print(f"❌ Error logging open: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    # Streaming Generator for Duration Tracking
    async def image_stream():
        start_time = time.time()
        try:
            yield PIXEL_BYTES
            while True:
                await asyncio.sleep(1)
                yield b""
        except Exception:
            pass
        finally:
            duration = int(time.time() - start_time)
            print(f"⏱️ Duration for {track_id}: {duration}s")
            
            # Update Duration in DB
            try:
                conn = get_conn()
                cur = conn.cursor()
                # Update the latest open event for this track_id
                cur.execute("""
                    UPDATE events 
                    SET duration = %s 
                    WHERE id = (
                        SELECT id FROM events 
                        WHERE track_id = %s AND event_type = 'open' 
                        ORDER BY created_at DESC LIMIT 1
                    )
                """, (duration, track_id))
                conn.commit()
                cur.close()
                conn.close()
            except Exception as e:
                print(f"❌ Error updating duration: {e}")

    # Return Streaming Response
    response = StreamingResponse(image_stream(), media_type="image/png")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
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
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Check for Active Status (Duration > 60s)
    # We prioritize 'active' over 'read'
    
    if recipient_email:
        cur.execute("""
            SELECT CASE
                WHEN (
                    SELECT MAX(duration) FROM events e
                    JOIN sends s ON e.track_id = s.track_id
                    WHERE (s.gmail_message_id = %s OR s.gmail_thread_id = %s)
                      AND s.recipient_email = %s
                      AND e.event_type = 'open'
                      AND e.is_bot = FALSE
                ) > 60 THEN 'active'
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
              gmail_message_id, gmail_message_id, recipient_email, 
              gmail_message_id, gmail_message_id, recipient_email))
    else:
        cur.execute("""
            SELECT CASE
                WHEN (
                    SELECT MAX(duration) FROM events e
                    JOIN sends s ON e.track_id = s.track_id
                    WHERE (s.gmail_message_id = %s OR s.gmail_thread_id = %s)
                      AND e.event_type = 'open'
                      AND e.is_bot = FALSE
                ) > 60 THEN 'active'
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
              gmail_message_id, gmail_message_id, 
              gmail_message_id, gmail_message_id))

    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row or row["status"] == "unknown":
        # print(f"⚠️ No send or open record found for Gmail ID: {gmail_message_id} ({recipient_email})")
        return JSONResponse({"status": "unknown"}, status_code=404)

    return JSONResponse({"status": row["status"]})
