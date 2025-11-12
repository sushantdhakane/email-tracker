from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import psycopg2, os, uuid, io
from psycopg2.extras import RealDictCursor
from urllib.parse import unquote_plus
from dotenv import load_dotenv

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
    via = request.headers.get("Via", "").lower()
    xff = request.headers.get("X-Forwarded-For", "")

    bot_signatures = [
        "bot", "crawler", "fetch", "prefetch", "appengine", "proxy", "gmail"
    ]
    bot_ips = ["64.18.", "74.125.", "209.85.", "172.217."]

    is_google_proxy = "googleimageproxy" in ua
    has_real_user_ip = bool(xff and not xff.startswith(("66.249.", "127.", "10.", "172.", "192.168")))

    # Filter prefetch/bots but allow Gmail proxy with real user IP
    if (any(word in ua for word in bot_signatures) or any(ip.startswith(p) for p in bot_ips)) and not (is_google_proxy and has_real_user_ip):
        print(f"⚠️ Ignored proxy/bot open from {ip} ({ua}) — via={via}, xff={xff}")
        return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (track_id, event_type, ip_address, user_agent, is_bot)
            VALUES (%s, 'open', %s, %s, FALSE)
        """, (track_id, xff or ip, ua))
        conn.commit()
        print(f"✅ Logged real open for {track_id} from {xff or ip}")
    except Exception as e:
        print("❌ pixel error:", e)
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

    # Use both identifiers if recipient_email is provided
    if recipient_email:
        cur.execute("""
            SELECT 
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM events e
                        JOIN sends s ON e.track_id = s.track_id
                        WHERE s.gmail_message_id = %s AND s.recipient_email = %s
                    )
                    THEN 'read'
                    ELSE 'sent'
                END AS status
            FROM sends
            WHERE gmail_message_id = %s AND recipient_email = %s
            LIMIT 1
        """, (gmail_message_id, recipient_email, gmail_message_id, recipient_email))
    else:
        cur.execute("""
            SELECT 
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM events e
                        JOIN sends s ON e.track_id = s.track_id
                        WHERE s.gmail_message_id = %s
                    )
                    THEN 'read'
                    ELSE 'sent'
                END AS status
            FROM sends
            WHERE gmail_message_id = %s
            LIMIT 1
        """, (gmail_message_id, gmail_message_id))

    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        print(f"⚠️ No record found for Gmail ID: {gmail_message_id} ({recipient_email})")
        return JSONResponse({"status": "unknown"}, status_code=404)

    return JSONResponse({"status": row["status"]})

def valid_uuid(value):
    try:
        uuid.UUID(value)
        return True
    except Exception:
        return False