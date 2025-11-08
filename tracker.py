from fastapi import FastAPI, Request, HTTPException
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
# Database connection string (Cloud SQL / Neon / Supabase)
DB_URL = os.getenv("DATABASE_URL")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"➡️ Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    print(f"⬅️ Response status: {response.status_code}")
    return response

@app.get("/")
async def health_check():
    return {"status": "ok"}

def get_conn():
    try:
        conn = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor, connect_timeout=10, sslmode='require')
        return conn
    except Exception as e:
        print("❌ Database connection error:", e)
        raise

# 1x1 transparent PNG
PIXEL_BYTES = bytes.fromhex(
    "89504E470D0A1A0A0000000D4948445200000001000000010806000000"
    "1F15C4890000000A49444154789C6360000000020001E221BC33000000"
    "0049454E44AE426082"
)

@app.post("/_register_send")
async def register_send(payload: dict):
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sends (track_id, recipient_email, subject, gmail_message_id)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (track_id) DO NOTHING
        """, (
            payload["track_id"],
            payload["recipient_email"],
            payload.get("subject"),
            payload.get("gmail_message_id"),
        ))
        conn.commit()
        cur.close()
        conn.close()
        return JSONResponse({"ok": True})
    except Exception as e:
        print("❌ register_send error:", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)

@app.get("/pixel/{track_id}.png")
async def pixel(track_id: str, request: Request):
    if not valid_uuid(track_id):
        raise HTTPException(status_code=404)
    conn = None
    cur = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO events (track_id, event_type, ip_address, user_agent) VALUES (%s, 'open', %s, %s)",
            (track_id, request.client.host, request.headers.get("user-agent"))
        )
        conn.commit()
        return StreamingResponse(io.BytesIO(PIXEL_BYTES), media_type="image/png")
    except Exception as e:
        print("❌ pixel error:", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.get("/pixel/{track_id}")
async def pixel_nopng(track_id: str, request: Request):
    return await pixel(track_id, request)

@app.get("/click/{track_id}")
async def click(track_id: str, url: str):
    if not valid_uuid(track_id):
        raise HTTPException(status_code=404)
    decoded_url = unquote_plus(url)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO events (track_id, event_type, clicked_url) VALUES (%s, 'click', %s)",
        (track_id, decoded_url)
    )
    conn.commit()
    cur.close()
    conn.close()
    return RedirectResponse(decoded_url)

@app.get("/stats")
def get_stats():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT s.recipient_email, s.subject, s.sent_at, COUNT(e.id) AS opens, 
               MAX(e.opened_at) AS last_open
        FROM sends s
        LEFT JOIN events e ON s.track_id = e.track_id
        GROUP BY s.recipient_email, s.subject, s.sent_at
        ORDER BY s.sent_at DESC;
    """)
    data = cur.fetchall()
    cur.close()
    conn.close()

    return data

def valid_uuid(value):
    try:
        uuid.UUID(value)
        return True
    except Exception:
        return False