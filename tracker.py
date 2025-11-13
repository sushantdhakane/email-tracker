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

    ua = request.headers.get("User-Agent", "")
    ip = request.client.host
    xff = request.headers.get("X-Forwarded-For", "")
    client_ip = xff.split(",")[0].strip() if xff else ip
    referer = request.headers.get("Referer", "")

    try:
        conn = get_conn()
        cur = conn.cursor()

        # ✅ Check the DB for recipient email associated with the track_id
        cur.execute("SELECT recipient_email FROM sends WHERE track_id = %s", (track_id,))
        send_row = cur.fetchone()

        if not send_row:
            print(f"⚠️ No send record found for track_id: {track_id}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        recipient_email = send_row["recipient_email"]

        # Detect sender opening their own sent mail:
        if "mail.google.com" in referer and (
            "in%3Asent" in referer or
            "/#sent" in referer or
            "act=sm" in referer
        ):
            print(f"⚠️ Ignored sender open (sent folder) for {track_id}")
            cur.close()
            conn.close()
            return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")

        # ✅ Log genuine recipient open
        cur.execute("""
            INSERT INTO events (track_id, event_type, ip_address, user_agent, is_bot)
            SELECT %s, 'open', %s, %s, FALSE
            WHERE EXISTS (
                SELECT 1 FROM sends WHERE track_id = %s
            )
            ON CONFLICT DO NOTHING
        """, (track_id, client_ip, ua, track_id))
        conn.commit()
        cur.close()
        conn.close()

        print(f"✅ Logged genuine open for recipient: {recipient_email} (track_id: {track_id})")

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