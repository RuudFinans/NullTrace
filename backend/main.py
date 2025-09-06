# backend/main.py
from pathlib import Path
from typing import Dict, Set, Tuple
import logging
import secrets
import time
import re
import json
from collections import defaultdict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.websockets import WebSocketState
from pydantic import BaseModel
from uuid import uuid4

# ─────────────────────────────────────────────────────────────────────────────
# Logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("server")

# Paths / app
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
app = FastAPI()

# ─────────────────────────────────────────────────────────────────────────────
# CSP + sikkerhets-headers
# Vi bruker nonce i index.html importmap-taggen og tillater esm.sh for moduler.
@app.middleware("http")
async def add_csp_header(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce

    response: Response = await call_next(request)

    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval' https://esm.sh; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )

    response.headers["Content-Security-Policy"] = csp
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response

# ─────────────────────────────────────────────────────────────────────────────
# Statisk-filer og maler
app.mount(
    "/static",
    StaticFiles(directory=ROOT_DIR / "frontend" / "static"),
    name="static",
)
templates = Jinja2Templates(directory=ROOT_DIR / "frontend" / "templates")

# ─────────────────────────────────────────────────────────────────────────────
# Enkle helsesjekker
@app.get("/", include_in_schema=False)
async def root():
    return {"ok": True}

@app.head("/", include_in_schema=False)
async def root_head():
    return Response(status_code=200)

# Anbefalt: egen health-endpoint Render kan pinge
@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok"}

@app.head("/healthz", include_in_schema=False)
async def healthz_head():
    return Response(status_code=200)

# ─────────────────────────────────────────────────────────────────────────────
# Rom-tokens (kortlevd, én-gangs) for å hindre gjette/ubudne joins
TOKEN_TTL_SECONDS = 120  # 2 minutter
# room_id -> { token:str -> exp_ts:float }
_room_tokens: Dict[str, Dict[str, float]] = {}

ROOM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")

def _validate_room_id(room_id: str) -> None:
    if not ROOM_ID_RE.match(room_id):
        raise HTTPException(status_code=400, detail="Invalid room id")

def _issue_room_token(room_id: str) -> Tuple[str, float]:
    tok = secrets.token_urlsafe(32)
    exp = time.time() + TOKEN_TTL_SECONDS
    _room_tokens.setdefault(room_id, {})[tok] = exp
    return tok, exp

def _verify_room_token(room_id: str, token: str, consume: bool = True) -> bool:
    tokens = _room_tokens.get(room_id)
    now = time.time()
    if not tokens:
        return False
    exp = tokens.get(token)
    if not exp or exp <= now:
        # rydde ut utløpte
        for t, e in list(tokens.items()):
            if e <= now:
                tokens.pop(t, None)
        return False
    if consume:
        # én-gangs
        tokens.pop(token, None)
    return True

class TokenReq(BaseModel):
    room_id: str

class TokenResp(BaseModel):
    token: str
    exp: int

@app.post("/api/room-token", response_model=TokenResp)
async def api_room_token(req: TokenReq, request: Request):
    _validate_room_id(req.room_id)
    token, exp = _issue_room_token(req.room_id)
    # Origin-sjekk for enkel CSRF-reduksjon
    origin = request.headers.get("origin", "")
    base_scheme = "https" if request.url.scheme == "https" else "http"
    expected1 = f"{base_scheme}://{request.url.hostname}"
    expected2 = f"{expected1}:{request.url.port}" if request.url.port else expected1
    if origin and origin not in (expected1, expected2):
        log.warning("Suspicious token request origin=%s expected=%s|%s", origin, expected1, expected2)
    return TokenResp(token=token, exp=int(exp))

# ─────────────────────────────────────────────────────────────────────────────
# RoomManager
class RoomManager:
    def __init__(self):
        self.rooms: Dict[str, Set[WebSocket]] = {}

    def add(self, room: str, ws: WebSocket):
        self.rooms.setdefault(room, set()).add(ws)

    def remove(self, room: str, ws: WebSocket):
        self.rooms.get(room, set()).discard(ws)

    async def broadcast(self, room: str, sender: WebSocket, data: str):
        peers = list(self.rooms.get(room, set()))
        for peer in peers:
            if peer.application_state != WebSocketState.CONNECTED:
                self.remove(room, peer)
                continue
            if peer is sender:
                continue
            try:
                await peer.send_text(data)
            except Exception as e:
                log.debug("Broadcast send failed, removing peer: %s", e)
                self.remove(room, peer)

mgr = RoomManager()

# ─────────────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "uuid": uuid4(),  # cache-buster for static assets
    })

# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting (per IP) – skiller mellom chat, control og bulk (chaff/ping)
# Soft-drop ved brudd. Chaff/ping verken broadcastes eller teller mot RL.

CHAT_LIMIT = 90              # chat-meldinger ("t":"m")
CHAT_WINDOW_SECONDS = 10

CTRL_LIMIT = 120             # kontroll ("hello","announce","ct","gk","gk_req","leave", etc.)
CTRL_WINDOW_SECONDS = 10

# Chaff/ping teller ikke: BULK_* beholdes ikke brukt i sjekkene
BULK_LIMIT = 999999
BULK_WINDOW_SECONDS = 60

CONNECT_LIMIT = 30
CONNECT_WINDOW_SECONDS = 60
BAN_SECONDS = 60

MAX_MESSAGE_BYTES = 16384    # romsligere pga padding (3–5 KB hos oss)

client_times_chat = defaultdict(list)   # ip -> [ts,...]
client_times_ctrl = defaultdict(list)
client_times_bulk = defaultdict(list)   # beholdt for ev. observasjon
client_connect_times = defaultdict(list)
banned_ips: Dict[str, float] = {}       # ip -> ban_until_ts

def _client_ip_from_ws(ws: WebSocket) -> str:
    xff = ws.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return ws.client.host or "0.0.0.0"

def _prune_and_check(timestamps: list, limit: int, window: int) -> bool:
    now = time.time()
    while timestamps and timestamps[0] < now - window:
        timestamps.pop(0)
    if len(timestamps) >= limit:
        return False
    timestamps.append(now)
    return True

def is_banned(client_ip: str) -> bool:
    now = time.time()
    ban_until = banned_ips.get(client_ip)
    if ban_until and ban_until > now:
        return True
    if ban_until and ban_until <= now:
        log.debug("[SECURITY] Ban expired for %s", client_ip)
        banned_ips.pop(client_ip, None)
    return False

def is_connect_limited(client_ip: str) -> bool:
    ts = client_connect_times[client_ip]
    ok = _prune_and_check(ts, CONNECT_LIMIT, CONNECT_WINDOW_SECONDS)
    if not ok:
        banned_ips[client_ip] = time.time() + BAN_SECONDS
        log.debug("[SECURITY] Connect limit exceeded. Banned %s for %s seconds.", client_ip, BAN_SECONDS)
    return not ok

def _classify_message_kind(msg_text: str) -> str:
    """
    Returner 'bulk' for chaff/ping, 'chat' for t='m', ellers 'ctrl'.
    Faller tilbake til 'chat' hvis JSON ikke kan parses (safe default).
    """
    try:
        obj = json.loads(msg_text)
        t = obj.get("t")
        if t in ("chaff", "ping"):
            return "bulk"
        if t == "m":
            return "chat"
        return "ctrl"
    except Exception:
        return "chat"

def is_rate_limited_message(client_ip: str, msg_text: str) -> bool:
    kind = _classify_message_kind(msg_text)
    if kind == "bulk":
        # Chaff/ping teller ikke mot rate limit
        return False
    if kind == "ctrl":
        return not _prune_and_check(client_times_ctrl[client_ip], CTRL_LIMIT, CTRL_WINDOW_SECONDS)
    # chat (t='m')
    return not _prune_and_check(client_times_chat[client_ip], CHAT_LIMIT, CHAT_WINDOW_SECONDS)

def _is_bulk(msg_text: str) -> bool:
    try:
        t = json.loads(msg_text).get("t")
        return t in ("chaff", "ping")
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# WebSocket endepunkt
@app.websocket("/ws/{room_id}")
async def websocket_endpoint(ws: WebSocket, room_id: str):
    client_ip = _client_ip_from_ws(ws)

    # Ban/abuse
    if is_banned(client_ip):
        log.debug("[SECURITY] Connection refused for banned IP %s", client_ip)
        await ws.close(code=4001)
        return

    if is_connect_limited(client_ip):
        await ws.close(code=4002)
        return

    # Room ID sanity
    try:
        _validate_room_id(room_id)
    except HTTPException:
        await ws.close(code=4003)  # policy violation
        return

    # Origin-sjekk (nettlesere sender Origin)
    origin = ws.headers.get("origin", "")
    base_scheme = "https" if ws.url.scheme == "wss" else "http"
    expected1 = f"{base_scheme}://{ws.url.hostname}"
    expected2 = f"{expected1}:{ws.url.port}" if ws.url.port else expected1
    if origin and origin not in (expected1, expected2):
        log.warning("[SECURITY] WS origin mismatch: %s (expected %s|%s)", origin, expected1, expected2)
        await ws.close(code=4003)
        return

    # Rom-token i subprotocol
    token = ws.headers.get("sec-websocket-protocol", "")
    if not token or not _verify_room_token(room_id, token, consume=True):
        log.debug("[SECURITY] Missing/invalid room token for room=%s ip=%s", room_id, client_ip)
        await ws.close(code=4004)  # unauthorized
        return

    # Aksepter og echo valgt subprotocol
    await ws.accept(subprotocol=token)
    mgr.add(room_id, ws)

    try:
        while True:
            msg = await ws.receive_text()

            # Størrelse: soft drop (ingen broadcast) og hint tilbake
            if len(msg.encode("utf-8")) > MAX_MESSAGE_BYTES:
                try:
                    await ws.send_text('{"t":"rate","reason":"too_big"}')
                except Exception:
                    pass
                continue

            # Rate-limit: soft drop + hint
            if is_rate_limited_message(client_ip, msg):
                log.debug("[RL] Soft-drop from %s", client_ip)
                try:
                    await ws.send_text('{"t":"rate","reason":"too_fast"}')
                except Exception:
                    pass
                continue

            # Chaff/ping: sink på server – ikke broadcast til andre
            if _is_bulk(msg):
                continue

            await mgr.broadcast(room_id, ws, msg)
    except WebSocketDisconnect:
        mgr.remove(room_id, ws)

# .venv\Scripts\Activate.ps1
# uvicorn backend.main:app --reload --port 5000
