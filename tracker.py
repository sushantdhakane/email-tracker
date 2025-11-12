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
    xff = request.headers.get("X-Forwarded-For", "")

    ignore_signatures = [
        "crawler", "fetch", "prefetch", "appengine", "proxy-checker", "headless"
    ]

    # ✅ Allow Gmail proxy requests (googleimageproxy) as legitimate opens
    is_gmail_proxy = "googleimageproxy" in ua
    is_bot = any(sig in ua for sig in ignore_signatures)

    if is_bot and not is_gmail_proxy:
        print(f"⚠️ Ignored bot/prefetch open from {ip} ({ua})")
        return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (track_id, event_type, ip_address, user_agent, is_bot)
            VALUES (%s, 'open', %s, %s, FALSE)
        """, (track_id, xff or ip, ua))
        conn.commit()
        cur.close()
        conn.close()
        print(f"✅ Logged open for {track_id} — UA={ua}")
    except Exception as e:
        print(f"❌ pixel error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

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