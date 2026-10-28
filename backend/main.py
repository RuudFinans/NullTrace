from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.websockets import WebSocketState

from . import access_db, wallet
from .http_security import (
    BoundedRateLimiter, SecurityBoundary, client_ip, http_limits,
    origin_allowed, production, validate_production_config,
)
from .access_security import (
    RESTORE_KEY_PREFIX,
    SESSION_COOKIE_NAME,
    USER_KEY_PREFIX,
    constant_time_equal,
    decrypt_claim_payload,
    env_bool,
    env_int,
    generate_order_secret,
    generate_restore_key,
    generate_session_token,
    generate_user_key,
    hash_access_key,
    hash_order_secret,
    hash_restore_key,
    hash_session_token,
    isoformat,
    parse_datetime,
    require_base64_secret,
    safe_error,
    utcnow,
)


try:
    from dotenv import load_dotenv

    load_dotenv(dotenv_path=(Path(__file__).resolve().parent.parent / ".env"))
except Exception:
    pass


logging.basicConfig(level=logging.INFO)
log = logging.getLogger("nulltrace.server")

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
CLIENT_BUILD = hashlib.sha256(b"".join(path.read_bytes() for path in sorted(
    (ROOT_DIR / "frontend" / "static").rglob("*.js")))).hexdigest()[:16]

@asynccontextmanager
async def lifespan(_app):
    await startup()
    try:
        yield
    finally:
        await shutdown()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=ROOT_DIR / "frontend" / "static"), name="static")
templates = Jinja2Templates(directory=ROOT_DIR / "frontend" / "templates")


async def _run_payment_background_loop(name: str, fn) -> None:
    retry_seconds = max(5, env_int("PAYMENT_BACKGROUND_RETRY_SECONDS", 15))
    while True:
        try:
            log.info("%s background loop starting", name)
            await fn(run_forever=True)
        except asyncio.CancelledError:
            log.info("%s background loop stopped", name)
            raise
        except Exception as exc:
            log.error("%s background loop crashed: %s", name, safe_error(exc))
            await asyncio.sleep(retry_seconds)


async def startup() -> None:
    validate_production_config()
    access_db.init_db()
    app.state.security_maintenance = asyncio.create_task(_security_maintenance())
    if env_bool("PAYMENT_BACKGROUND_WORKER_ENABLED", True):
        app.state.payment_background_tasks = [
            asyncio.create_task(_run_payment_background_loop("payment-watch", wallet.poll_pending_payments)),
            asyncio.create_task(_run_payment_background_loop("sweep", wallet.poll_unswept_deposits)),
        ]
        log.info("payment background worker enabled")
    else:
        app.state.payment_background_tasks = []
        log.info("payment background worker disabled")


async def shutdown() -> None:
    tasks = list(getattr(app.state, "payment_background_tasks", []) or [])
    maintenance = getattr(app.state, "security_maintenance", None)
    if maintenance:
        tasks.append(maintenance)
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response: Response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    if request.scope["path"].startswith(("/static/js/", "/static/libs/")):
        response.headers["Cache-Control"] = "no-cache"
    if not request.scope["path"].startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


app.add_middleware(SecurityBoundary)


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError):
    # Pydantic's default error includes the submitted password/access key.
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()
    ]}, headers={"Cache-Control": "no-store"})


@app.get("/manifest.webmanifest", include_in_schema=False)
async def manifest():
    return FileResponse(
        ROOT_DIR / "frontend" / "static" / "manifest.webmanifest",
        media_type="application/manifest+json",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/sw.js", include_in_schema=False)
async def service_worker():
    return FileResponse(
        ROOT_DIR / "frontend" / "static" / "sw.js",
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"},
    )


@app.head("/", include_in_schema=False)
async def root_head():
    return Response(status_code=200)


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok"}


@app.head("/healthz", include_in_schema=False)
async def healthz_head():
    return Response(status_code=200)


def _client_ip_from_request(request: Request) -> str:
    return client_ip(request)


def _client_ip_from_ws(ws: WebSocket) -> str:
    return client_ip(ws)


TOKEN_REQ_LIMIT = 60
TOKEN_REQ_WINDOW = 60
TOKEN_TTL_SECONDS = 120
ROOM_ID_RE = __import__("re").compile(r"^[A-Za-z0-9_-]{6,64}$")
CID_RE = __import__("re").compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
ADMIN_COOKIE_NAME = "nt_admin_session"
ADMIN_SESSION_HOURS = 8

room_replay: dict[str, list[tuple[float, str | None, str | None, str | None, str]]] = defaultdict(list)

_room_tokens: dict[str, dict[str, tuple[float, str]]] = {}
ws_limits = BoundedRateLimiter()
_admin_password_slots = asyncio.Semaphore(2)


def _admin_slug() -> str:
    return os.getenv("ADMIN_PATH", "").strip().strip("/")


def _admin_enabled() -> bool:
    return bool(_admin_slug() and os.getenv("ADMIN_PASSWORD_HASH", "").strip())


def _admin_api_base(slug: str) -> str:
    return f"/api/admin/{slug}"


def _b64decode_relaxed(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_admin_password(password: str) -> bool:
    encoded = os.getenv("ADMIN_PASSWORD_HASH", "").strip()
    if not encoded:
        return False
    try:
        algorithm, iterations_raw, salt_raw, expected_raw = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        if not 100_000 <= iterations <= 2_000_000 or len(password.encode("utf-8")) > 1024:
            return False
        salt = _b64decode_relaxed(salt_raw)
        expected = _b64decode_relaxed(expected_raw)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(derived, expected)
    except Exception:
        return False


def _set_admin_cookie(response: Response, request: Request, session_token: str) -> None:
    response.set_cookie(
        ADMIN_COOKIE_NAME,
        session_token,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="strict",
        max_age=ADMIN_SESSION_HOURS * 3600,
        path="/",
    )


def _clear_admin_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        ADMIN_COOKIE_NAME,
        secure=_cookie_secure(request),
        samesite="strict",
        path="/",
    )


def _require_admin_slug(slug: str) -> None:
    if not _admin_enabled() or not hmac.compare_digest(slug.encode("utf-8"), _admin_slug().encode("utf-8")):
        raise HTTPException(status_code=404, detail="Not found")


def _current_admin_session(request: Request) -> dict[str, Any]:
    token = request.cookies.get(ADMIN_COOKIE_NAME, "")
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    session = access_db.get_admin_session_by_hash(hash_session_token(token))
    if not session or session.get("revoked_at"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    expires_at = parse_datetime(session.get("expires_at"))
    if not expires_at or expires_at <= utcnow():
        access_db.revoke_admin_session(int(session["id"]))
        raise HTTPException(status_code=401, detail="Unauthorized")
    access_db.update_admin_session_seen(int(session["id"]))
    return session


def _visitor_hash(request: Request, day: str) -> str | None:
    try:
        key = require_base64_secret("SESSION_SECRET_BASE64")
    except Exception:
        return None
    ip = _client_ip_from_request(request)
    ua = request.headers.get("user-agent", "")[:220]
    lang = request.headers.get("accept-language", "")[:80]
    raw = f"{day}|{ip}|{ua}|{lang}".encode("utf-8")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def _track_page_visit(request: Request) -> None:
    if not env_bool("NT_VISITOR_METRICS", False):
        return
    try:
        day = utcnow().date().isoformat()
        access_db.increment_daily_metric("page_views", day=day)
        visitor_hash = _visitor_hash(request, day)
        if visitor_hash:
            access_db.remember_daily_visitor(day, visitor_hash)
    except Exception:
        pass


def _validate_room_id(room_id: str) -> None:
    if not ROOM_ID_RE.fullmatch(room_id):
        raise HTTPException(status_code=400, detail="Invalid room id")


def _prune_tokens() -> None:
    now = time.time()
    for room, tokens in list(_room_tokens.items()):
        for token, (expires, _) in list(tokens.items()):
            if expires <= now:
                del tokens[token]
        if not tokens:
            del _room_tokens[room]


def _issue_room_token(room_id: str, session_hash: str) -> tuple[str, float]:
    _prune_tokens()
    if sum(saved_hash == session_hash for tokens in _room_tokens.values()
           for _, saved_hash in tokens.values()) >= 16:
        raise HTTPException(status_code=429, detail="Too many unused connection tickets")
    if sum(map(len, _room_tokens.values())) >= 4096:
        raise HTTPException(status_code=503, detail="Try again later")
    token = secrets.token_urlsafe(32)
    exp = time.time() + TOKEN_TTL_SECONDS
    _room_tokens.setdefault(room_id, {})[token] = (exp, session_hash)
    return token, exp


def _verify_room_token(room_id: str, token: str, consume: bool = True) -> str | None:
    now = time.time()
    tokens = _room_tokens.get(room_id)
    if not tokens:
        return None
    entry = tokens.get(token)
    for saved_token, (exp, _) in list(tokens.items()):
        if exp <= now:
            tokens.pop(saved_token, None)
    if not entry:
        return None
    exp, session_hash = entry
    if exp <= now:
        tokens.pop(token, None)
        return None
    if consume:
        tokens.pop(token, None)
    return session_hash


def _cookie_secure(request: Request) -> bool:
    if production():
        return True
    default = request.url.scheme == "https"
    return env_bool("SESSION_COOKIE_SECURE", default)


def _set_session_cookie(response: Response, request: Request, session_token: str, max_age: int | None = None) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="strict",
        max_age=max_age,
        path="/",
    )


def _clear_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        secure=_cookie_secure(request),
        samesite="strict",
        path="/",
    )


def _generic_auth_error(status_code: int = 401) -> HTTPException:
    return HTTPException(status_code=status_code, detail="Invalid or expired access")


def _account_is_valid(account: dict[str, Any]) -> bool:
    if account.get("revoked_at"):
        return False
    paid_until = parse_datetime(account.get("paid_until"))
    return bool(paid_until and paid_until >= utcnow())


def _session_inactive_cutoff():
    return utcnow() - timedelta(seconds=env_int("SESSION_MAX_INACTIVE_SECONDS", 180))


def _current_session(request: Request) -> tuple[dict[str, Any], dict[str, Any]]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise _generic_auth_error()
    session_hash = hash_session_token(token)
    return _session_for_hash(session_hash)


def _session_for_hash(session_hash: str) -> tuple[dict[str, Any], dict[str, Any]]:
    session = access_db.get_session_by_hash(session_hash)
    if not session or session.get("revoked_at"):
        raise _generic_auth_error()
    last_heartbeat = parse_datetime(session.get("last_heartbeat_at"))
    if not last_heartbeat or last_heartbeat <= _session_inactive_cutoff():
        access_db.revoke_session(int(session["id"]), "inactive")
        raise _generic_auth_error()
    account = access_db.fetchone("SELECT * FROM access_accounts WHERE id = ?", (int(session["account_id"]),))
    if not account or not _account_is_valid(account):
        raise _generic_auth_error(402)
    expires_at = parse_datetime(session.get("expires_at"))
    if expires_at and expires_at < utcnow():
        access_db.revoke_session(int(session["id"]), "expired")
        raise _generic_auth_error(402)
    return session, account


def _request_session_for_account(request: Request, account_id: int) -> dict[str, Any] | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    session = access_db.get_session_by_hash(hash_session_token(token))
    if not session or session.get("revoked_at"):
        return None
    if int(session["account_id"]) != int(account_id):
        return None
    last_heartbeat = parse_datetime(session.get("last_heartbeat_at"))
    if not last_heartbeat or last_heartbeat <= _session_inactive_cutoff():
        access_db.revoke_session(int(session["id"]), "inactive")
        return None
    expires_at = parse_datetime(session.get("expires_at"))
    if expires_at and expires_at < utcnow():
        access_db.revoke_session(int(session["id"]), "expired")
        return None
    return session


def _create_session_response(request: Request, account: dict[str, Any]) -> JSONResponse:
    session_token = generate_session_token()
    session_hash = hash_session_token(session_token)
    paid_until = parse_datetime(account["paid_until"])
    access_db.create_session(int(account["id"]), session_hash, paid_until)
    response = JSONResponse({"status": "ok", "paidUntil": account["paid_until"]})
    max_age = None
    if paid_until:
        max_age = max(1, int((paid_until - utcnow()).total_seconds()))
    _set_session_cookie(response, request, session_token, max_age=max_age)
    access_db.audit_event("session_created", account_id=int(account["id"]), metadata={})
    return response


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PaymentCreateReq(StrictRequest):
    plan: str = Field(min_length=1, max_length=8)


class PaymentStatusReq(StrictRequest):
    orderId: int = Field(gt=0, le=2_147_483_647)
    orderSecret: str = Field(min_length=1, max_length=128)


class DevnetFundReq(PaymentStatusReq):
    pass


class SignInReq(StrictRequest):
    userKey: str = Field(min_length=1, max_length=128)


class RestoreReq(SignInReq):
    restoreKey: str = Field(min_length=1, max_length=128)


class TokenReq(StrictRequest):
    room_id: str = Field(min_length=6, max_length=64)


class AdminLoginReq(StrictRequest):
    password: str = Field(min_length=1, max_length=256)


class AdminGenerateAccessReq(StrictRequest):
    label: str = Field(default="", max_length=80)
    days: int = Field(default=3650, ge=1, le=36500)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    _track_page_visit(request)
    devnet_payment_faucet = wallet.devnet_payment_faucet_enabled()
    return templates.TemplateResponse(
        request=request, name="index.html",
        context={
            "request": request,
            "uuid": CLIENT_BUILD,
            "devnet_payment_faucet": devnet_payment_faucet,
        },
    )


@app.get("/access", response_class=HTMLResponse)
async def access_page(request: Request):
    return await index(request)


@app.get("/{admin_slug}", response_class=HTMLResponse)
async def admin_page(admin_slug: str, request: Request):
    _require_admin_slug(admin_slug)
    response = templates.TemplateResponse(
        request=request, name="admin.html",
        context={
            "request": request,
            "uuid": CLIENT_BUILD,
            "admin_slug": admin_slug,
            "admin_api_base": _admin_api_base(admin_slug),
        },
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@app.post("/api/admin/{admin_slug}/login")
async def api_admin_login(admin_slug: str, req: AdminLoginReq, request: Request):
    _require_admin_slug(admin_slug)
    async with _admin_password_slots:
        verified = await asyncio.to_thread(_verify_admin_password, req.password)
    if not verified:
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = generate_session_token()
    expires_at = utcnow() + timedelta(hours=ADMIN_SESSION_HOURS)
    access_db.create_admin_session(hash_session_token(token), expires_at)
    response = JSONResponse({"status": "ok"})
    _set_admin_cookie(response, request, token)
    return response


@app.post("/api/admin/{admin_slug}/logout")
async def api_admin_logout(admin_slug: str, request: Request):
    _require_admin_slug(admin_slug)
    response = JSONResponse({"status": "ok"})
    try:
        session = _current_admin_session(request)
        access_db.revoke_admin_session(int(session["id"]))
    except HTTPException:
        pass
    _clear_admin_cookie(response, request)
    return response


def _admin_stats() -> dict[str, Any]:
    cutoff = isoformat(_session_inactive_cutoff())
    totals = access_db.fetchone(
        """
        SELECT
          (SELECT COUNT(*) FROM access_accounts WHERE revoked_at IS NULL) AS accounts,
          (SELECT COUNT(*) FROM access_accounts WHERE plan = 'admin_free' AND revoked_at IS NULL) AS admin_free_accounts,
          (SELECT COUNT(*) FROM access_sessions WHERE revoked_at IS NULL AND last_heartbeat_at > ?) AS active_sessions,
          (SELECT COUNT(*) FROM payment_orders) AS payment_orders,
          (SELECT COUNT(*) FROM payment_orders WHERE status IN ('confirmed','swept')) AS paid_orders,
          (SELECT COALESCE(SUM(confirmed_balance_lamports), 0) FROM payment_orders WHERE status IN ('confirmed','swept')) AS confirmed_lamports
        """,
        (cutoff,),
    ) or {}
    metrics = access_db.fetchone(
        """
        SELECT
          COALESCE(SUM(page_views), 0) AS page_views,
          COALESCE(SUM(unique_visitors), 0) AS unique_visitors,
          COALESCE(SUM(room_tokens), 0) AS room_tokens,
          COALESCE(SUM(ws_connections), 0) AS ws_connections,
          COALESCE(SUM(chat_messages), 0) AS chat_messages,
          COALESCE(SUM(control_messages), 0) AS control_messages
        FROM admin_daily_metrics
        """
    ) or {}
    today = access_db.fetchone(
        "SELECT * FROM admin_daily_metrics WHERE day = ?",
        (utcnow().date().isoformat(),),
    ) or {}
    recent_days = access_db.fetchall(
        """
        SELECT day, page_views, unique_visitors, room_tokens, ws_connections, chat_messages, control_messages
        FROM admin_daily_metrics
        ORDER BY day DESC
        LIMIT 14
        """
    )
    recent_accounts = access_db.fetchall(
        """
        SELECT
          a.id, a.plan, a.paid_until, a.created_at, a.revoked_at,
          (SELECT COUNT(*) FROM access_sessions s WHERE s.account_id = a.id AND s.revoked_at IS NULL AND s.last_heartbeat_at > ?) AS active_sessions,
          (SELECT MAX(created_at) FROM audit_events e WHERE e.account_id = a.id AND e.event_type IN ('session_created','session_restored')) AS last_used_at
        FROM access_accounts a
        ORDER BY a.created_at DESC
        LIMIT 25
        """,
        (cutoff,),
    )
    generated = access_db.fetchall(
        """
        SELECT
          a.id, a.plan, a.paid_until, a.created_at,
          (SELECT COUNT(*) FROM access_sessions s WHERE s.account_id = a.id) AS session_count,
          (SELECT MAX(created_at) FROM audit_events e WHERE e.account_id = a.id AND e.event_type IN ('session_created','session_restored')) AS last_used_at,
          (SELECT metadata_json FROM audit_events e WHERE e.account_id = a.id AND e.event_type = 'admin_access_generated' ORDER BY e.created_at DESC LIMIT 1) AS metadata_json
        FROM access_accounts a
        WHERE a.plan = 'admin_free'
        ORDER BY a.created_at DESC
        LIMIT 50
        """
    )
    return {
        "totals": totals,
        "metrics": metrics,
        "today": today,
        "recentDays": recent_days,
        "recentAccounts": recent_accounts,
        "generatedAccess": generated,
    }


async def _cold_wallet_status() -> dict[str, Any]:
    address = os.getenv("SOLANA_COLD_WALLET_PUBLIC_KEY", "").strip()
    if not address:
        return {"configured": False}
    try:
        lamports = await wallet.get_deposit_balance_lamports(address)
        return {
            "configured": True,
            "address": address,
            "lamports": lamports,
            "sol": wallet.lamports_to_sol_string(lamports),
            "network": "devnet" if wallet.use_devnet() else "mainnet",
        }
    except Exception as exc:
        return {"configured": True, "address": address, "error": safe_error(exc)}


@app.get("/api/admin/{admin_slug}/dashboard")
async def api_admin_dashboard(admin_slug: str, request: Request):
    _require_admin_slug(admin_slug)
    _current_admin_session(request)
    payload = _admin_stats()
    payload["coldWallet"] = await _cold_wallet_status()
    return payload


@app.post("/api/admin/{admin_slug}/generate-access")
async def api_admin_generate_access(admin_slug: str, req: AdminGenerateAccessReq, request: Request):
    _require_admin_slug(admin_slug)
    _current_admin_session(request)
    days = max(1, min(int(req.days or 3650), 36500))
    label = (req.label or "").strip()[:80]
    user_key = generate_user_key()
    restore_key = generate_restore_key()
    now = utcnow()
    paid_until = now + timedelta(days=days)
    with access_db.db() as conn:
        cur = conn.execute(
            """
            INSERT INTO access_accounts(
              user_key_hash, restore_key_hash, plan, paid_until, created_at, updated_at
            )
            VALUES (?, ?, 'admin_free', ?, ?, ?)
            """,
            (
                hash_access_key(user_key),
                hash_restore_key(restore_key),
                isoformat(paid_until),
                isoformat(now),
                isoformat(now),
            ),
        )
        account_id = int(cur.lastrowid)
        access_db.audit_event(
            "admin_access_generated",
            account_id=account_id,
            metadata={"label": label, "days": days},
            conn=conn,
        )
    return {
        "accountId": account_id,
        "userKey": user_key,
        "restoreKey": restore_key,
        "paidUntil": isoformat(paid_until),
    }


@app.get("/api/access/plans")
async def api_access_plans():
    return {"plans": wallet.list_plans(), "devnetPaymentFaucet": wallet.devnet_payment_faucet_enabled()}


@app.post("/api/access/payment/create")
async def api_payment_create(req: PaymentCreateReq):
    if req.plan not in wallet.PLAN_CONFIG:
        raise HTTPException(status_code=400, detail="Invalid plan")

    usd_price = wallet.plan_price_usd(req.plan)
    sol_usd_rate = await wallet.get_sol_usd_price_cached()
    lamports = wallet.calculate_sol_amount_lamports(usd_price, sol_usd_rate)
    deposit_public_key, secret_key = wallet.create_deposit_wallet()
    encrypted_secret = wallet.encrypt_secret_key(secret_key)
    order_secret = generate_order_secret()
    order_secret_hash = hash_order_secret(order_secret)
    now = utcnow()
    expires_at = now + timedelta(minutes=env_int("PAYMENT_EXPIRES_MINUTES", 30))
    order_id = access_db.execute(
        """
        INSERT INTO payment_orders(
          order_secret_hash, status, plan, usd_price, sol_usd_rate, sol_amount_lamports,
          deposit_public_key, encrypted_deposit_secret_key, expires_at, created_at, updated_at
        )
        VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            order_secret_hash,
            req.plan,
            float(usd_price),
            float(sol_usd_rate),
            int(lamports),
            deposit_public_key,
            encrypted_secret,
            isoformat(expires_at),
            isoformat(now),
            isoformat(now),
        ),
    )
    access_db.audit_event(
        "payment_order_created",
        payment_order_id=order_id,
        metadata={
            "plan": req.plan,
            "usd_price": float(usd_price),
            "sol_usd_rate": float(sol_usd_rate),
            "sol_amount_lamports": int(lamports),
            "deposit_public_key": deposit_public_key,
        },
    )
    log.info("payment order created order_id=%s deposit=%s lamports=%s", order_id, deposit_public_key, lamports)
    return {
        "orderId": str(order_id),
        "orderSecret": order_secret,
        "depositAddress": deposit_public_key,
        "solAmount": wallet.lamports_to_sol_string(lamports),
        "lamports": int(lamports),
        "usdPrice": float(usd_price),
        "solUsdRate": float(sol_usd_rate),
        "expiresAt": isoformat(expires_at),
        "devnetPaymentFaucet": wallet.devnet_payment_faucet_enabled(),
    }


@app.post("/api/access/payment/devnet-fund")
async def api_payment_devnet_fund(req: DevnetFundReq):
    try:
        order_id = int(req.orderId)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid order")

    order = access_db.get_order_for_secret(order_id, hash_order_secret(req.orderSecret))
    if not order:
        raise HTTPException(status_code=404, detail="Payment order not found")
    try:
        return await wallet.fund_devnet_payment_order(order)
    except wallet.AccessConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except wallet.DevnetFundingError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/access/payment/status")
async def api_payment_status(req: PaymentStatusReq, request: Request):
    try:
        order_id = int(req.orderId)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid order")

    order = access_db.get_order_for_secret(order_id, hash_order_secret(req.orderSecret))
    if not order:
        raise HTTPException(status_code=404, detail="Payment order not found")

    if order["status"] == "pending":
        try:
            confirm_result = await wallet.confirm_payment_order_if_funded(order_id)
        except Exception as exc:
            log.warning("payment status chain check failed order_id=%s error=%s", order_id, safe_error(exc))
            confirm_result = {"status": "pending", "changed": False}
        if confirm_result.get("status") == "expired":
            return {"status": "expired"}
        if confirm_result.get("status") == "pending":
            return {
                "status": "pending",
                "balanceLamports": confirm_result.get("balanceLamports"),
                "requiredLamports": confirm_result.get("requiredLamports"),
            }
        order = access_db.get_order_for_secret(order_id, hash_order_secret(req.orderSecret))
        if not order:
            raise HTTPException(status_code=404, detail="Payment order not found")

    if order["status"] in {"expired", "failed"}:
        return {"status": order["status"]}
    if order["status"] not in {"confirmed", "swept"}:
        return {"status": order["status"]}

    with access_db.db() as conn:
        current = access_db.lock_order(conn, order_id)
        if current and not constant_time_equal(current["order_secret_hash"], hash_order_secret(req.orderSecret)):
            current = None
        if not current:
            raise HTTPException(status_code=404, detail="Payment order not found")
        if current.get("keys_claimed_at") or not current.get("encrypted_claim_payload"):
            return {"status": "confirmed", "keysAlreadyClaimed": True}
        payload = decrypt_claim_payload(current["encrypted_claim_payload"])
        conn.execute(
            """
            UPDATE payment_orders
            SET keys_claimed_at = ?, encrypted_claim_payload = NULL, updated_at = ?
            WHERE id = ?
            """,
            (isoformat(utcnow()), isoformat(utcnow()), order_id),
        )
        access_db.audit_event(
            "access_keys_claimed",
            account_id=int(current["created_account_id"]) if current.get("created_account_id") else None,
            payment_order_id=order_id,
            metadata={},
            conn=conn,
        )
        account = None
        if current.get("created_account_id"):
            account = access_db.row_to_dict(
                conn.execute("SELECT * FROM access_accounts WHERE id = ?", (int(current["created_account_id"]),)).fetchone()
            )

    payload_response = {
        "status": "confirmed",
        "userKey": payload["userKey"],
        "restoreKey": payload["restoreKey"],
        "paidUntil": payload["paidUntil"],
    }
    if not account:
        return payload_response

    session_token = generate_session_token()
    session_hash = hash_session_token(session_token)
    paid_until = parse_datetime(account["paid_until"])
    access_db.create_session(int(account["id"]), session_hash, paid_until)
    access_db.audit_event("session_created", account_id=int(account["id"]), metadata={})
    payload_response["signedIn"] = True
    response = JSONResponse(payload_response)
    max_age = None
    if paid_until:
        max_age = max(1, int((paid_until - utcnow()).total_seconds()))
    _set_session_cookie(response, request, session_token, max_age=max_age)
    return response


@app.post("/api/access/signin")
async def api_access_signin(req: SignInReq, request: Request):
    user_key = (req.userKey or "").strip()
    if not user_key.startswith(USER_KEY_PREFIX):
        raise _generic_auth_error()
    account = access_db.get_account_by_user_hash(hash_access_key(user_key))
    if not account or not _account_is_valid(account):
        raise _generic_auth_error()

    existing_session = _request_session_for_account(request, int(account["id"]))
    if existing_session:
        access_db.update_session_heartbeat(int(existing_session["id"]))
        return JSONResponse({"status": "ok", "paidUntil": account["paid_until"]})

    active = access_db.active_sessions(int(account["id"]), _session_inactive_cutoff())
    if active:
        return JSONResponse(
            {
                "status": "RESTORE_REQUIRED",
                "restoreRequired": True,
                "message": "This access is currently active somewhere else.",
            },
            status_code=409,
        )

    access_db.revoke_stale_sessions(int(account["id"]), _session_inactive_cutoff())
    return _create_session_response(request, account)


@app.post("/api/access/restore")
async def api_access_restore(req: RestoreReq, request: Request):
    user_key = (req.userKey or "").strip()
    restore_key = (req.restoreKey or "").strip()
    if not user_key.startswith(USER_KEY_PREFIX) or not restore_key.startswith(RESTORE_KEY_PREFIX):
        raise _generic_auth_error()

    account = access_db.get_account_by_user_hash(hash_access_key(user_key))
    if not account or not _account_is_valid(account):
        raise _generic_auth_error()
    expected_restore_hash = account["restore_key_hash"]
    provided_restore_hash = hash_restore_key(restore_key)
    if not constant_time_equal(expected_restore_hash, provided_restore_hash):
        raise _generic_auth_error()

    latest_restore = access_db.latest_audit_time(int(account["id"]), "session_restored")
    cooldown = env_int("RESTORE_RESET_COOLDOWN_SECONDS", 300)
    if cooldown > 0 and latest_restore and utcnow() < latest_restore + timedelta(seconds=cooldown):
        raise HTTPException(status_code=429, detail="Restore cooldown active")

    with access_db.db() as conn:
        access_db.revoke_sessions(int(account["id"]), "restore", conn=conn)
        access_db.audit_event("session_restored", account_id=int(account["id"]), metadata={}, conn=conn)
    return _create_session_response(request, account)


@app.post("/api/access/heartbeat")
async def api_access_heartbeat(request: Request):
    session, account = _current_session(request)
    access_db.update_session_heartbeat(int(session["id"]))
    return {
        "status": "ok",
        "paidUntil": account["paid_until"],
        "heartbeatSeconds": env_int("ACTIVE_SESSION_HEARTBEAT_SECONDS", 60),
    }


@app.post("/api/access/logout")
async def api_access_logout(request: Request):
    response = JSONResponse({"status": "ok"})
    try:
        session, _account = _current_session(request)
        access_db.revoke_session(int(session["id"]), "logout")
    except HTTPException:
        pass
    _clear_session_cookie(response, request)
    return response


def _require_internal_secret(request: Request) -> None:
    expected = os.getenv("INTERNAL_CRON_SECRET", "")
    provided = request.headers.get("X-Internal-Secret", "")
    if not expected or not hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/api/internal/payment-watch")
async def api_internal_payment_watch(request: Request):
    _require_internal_secret(request)
    return await wallet.poll_pending_payments(run_forever=False)


@app.post("/api/internal/sweep")
async def api_internal_sweep(request: Request):
    _require_internal_secret(request)
    return await wallet.poll_unswept_deposits(run_forever=False)


@app.post("/api/room-token")
async def api_room_token(req: TokenReq, request: Request):
    _validate_room_id(req.room_id)
    session, account = _current_session(request)
    if not ws_limits.allow(f"token:{session['session_token_hash']}", TOKEN_REQ_LIMIT, TOKEN_REQ_WINDOW):
        raise HTTPException(status_code=429, detail="Too many requests")

    if not origin_allowed(request):
        raise HTTPException(status_code=403, detail="Forbidden")

    token, exp = _issue_room_token(req.room_id, session["session_token_hash"])
    access_db.update_session_heartbeat(int(session["id"]))
    access_db.increment_daily_metric("room_tokens")
    return {"token": token, "exp": int(exp)}


class RoomManager:
    def __init__(self) -> None:
        self.rooms: dict[str, set[WebSocket]] = {}
        self.connections: dict[WebSocket, dict[str, Any]] = {}

    def has_capacity(self, room: str, session_hash: str) -> bool:
        return (len(self.connections) < 128
                and (room in self.rooms or len(self.rooms) < 64)
                and len(self.rooms.get(room, ())) < 16
                and sum(c["session_hash"] == session_hash for c in self.connections.values()) < 8)

    def add(self, room: str, ws: WebSocket, session_hash: str) -> None:
        self.rooms.setdefault(room, set()).add(ws)
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=32)
        self.connections[ws] = {"room": room, "session_hash": session_hash,
                                "cid": None, "hello": None, "queue": queue,
                                "writer": asyncio.create_task(self._writer(ws, queue))}

    async def _writer(self, ws: WebSocket, queue: asyncio.Queue[str]) -> None:
        try:
            while True:
                await asyncio.wait_for(ws.send_text(await queue.get()), timeout=5)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.close(ws, 1013)

    async def close(self, ws: WebSocket, code: int) -> None:
        try:
            await asyncio.wait_for(ws.close(code=code), timeout=2)
        except Exception:
            pass

    def enqueue(self, ws: WebSocket, data: str) -> None:
        state = self.connections.get(ws)
        if not state or state.get("closing"):
            return
        try:
            state["queue"].put_nowait(data)
        except asyncio.QueueFull:
            state["closing"] = True
            asyncio.create_task(self.close(ws, 1013))

    def remove(self, room: str, ws: WebSocket) -> None:
        self.rooms.get(room, set()).discard(ws)
        state = self.connections.pop(ws, None)
        if state:
            state["writer"].cancel()
        if not self.rooms.get(room):
            self.rooms.pop(room, None)
            room_replay.pop(room, None)

    async def broadcast(self, room: str, sender: WebSocket, data: str, to: str | None = None) -> None:
        for peer in list(self.rooms.get(room, set())):
            if peer.application_state == WebSocketState.CONNECTING:
                continue  # Admission is reserved before the asynchronous upgrade finishes.
            if peer.application_state != WebSocketState.CONNECTED:
                self.remove(room, peer)
                continue
            if peer is sender:
                continue
            if to and self.connections.get(peer, {}).get("cid") != to:
                continue
            self.enqueue(peer, data)


mgr = RoomManager()

CHAT_LIMIT = 90
CHAT_WINDOW_SECONDS = 10
CTRL_LIMIT = 120
CTRL_WINDOW_SECONDS = 10
CONNECT_LIMIT = 30
CONNECT_WINDOW_SECONDS = 60
REPLAY_TTL_SECONDS = max(0, min(env_int("NT_REPLAY_TTL_SECONDS", 35), 60))
MAX_REPLAY_PER_ROOM = max(0, min(env_int("NT_REPLAY_MAX_PER_ROOM", 32), 64))
MAX_MESSAGE_BYTES = 16384
message_metrics: dict[str, int] = defaultdict(int)


async def _security_maintenance() -> None:
    while True:
        await asyncio.sleep(5)
        _prune_tokens()
        http_limits.prune()
        ws_limits.prune()
        for room in list(room_replay):
            _prune_replay(room)
        # Check idle sockets too: restoring/revoking/expiring access cannot leave a live relay behind.
        invalid = set()
        for session_hash in {c["session_hash"] for c in mgr.connections.values()}:
            try:
                await asyncio.to_thread(_session_for_hash, session_hash)
            except Exception:
                invalid.add(session_hash)
        for ws, state in list(mgr.connections.items()):
            if state["session_hash"] in invalid:
                await mgr.close(ws, 4004)
        for field, count in list(message_metrics.items()):
            message_metrics[field] -= count
            if count:
                try:
                    await asyncio.to_thread(access_db.increment_daily_metric, field, count)
                except Exception as exc:
                    log.warning("metrics update failed: %s", safe_error(exc))


def _is_connect_limited(client_ip: str) -> bool:
    return not ws_limits.allow(f"connect:{client_ip}", CONNECT_LIMIT, CONNECT_WINDOW_SECONDS)


def _classify_message_kind(msg_text: str) -> str:
    try:
        msg_type = json.loads(msg_text).get("t")
    except Exception:
        return "chat"
    if not isinstance(msg_type, str):
        return "chat"
    if msg_type in {"chaff", "ping"}:
        return "bulk"
    if msg_type == "m":
        return "chat"
    return "ctrl"


def _is_rate_limited_message(session_hash: str, msg_text: str) -> bool:
    kind = _classify_message_kind(msg_text)
    if kind == "bulk":
        return not ws_limits.allow(f"bulk:{session_hash}", 60, 10)
    if kind == "ctrl":
        return not ws_limits.allow(f"ctrl:{session_hash}", CTRL_LIMIT, CTRL_WINDOW_SECONDS)
    return not ws_limits.allow(f"chat:{session_hash}", CHAT_LIMIT, CHAT_WINDOW_SECONDS)


def _is_bulk(msg_text: str) -> bool:
    try:
        return json.loads(msg_text).get("t") in {"chaff", "ping"}
    except Exception:
        return False


def _message_meta(msg_text: str) -> tuple[str | None, str | None, str | None, dict[str, Any] | None]:
    try:
        obj = json.loads(msg_text)
    except (ValueError, RecursionError):
        return None, None, None, None
    if not isinstance(obj, dict):
        return None, None, None, None
    msg_type = obj.get("t")
    if not isinstance(msg_type, str):
        return None, None, None, None
    cid = obj.get("cid") if isinstance(obj.get("cid"), str) and len(obj.get("cid")) <= 64 else None
    to = obj.get("to") if isinstance(obj.get("to"), str) and len(obj.get("to")) <= 64 else None
    return msg_type, cid, to, obj


def _prune_replay(room: str) -> None:
    cutoff = time.time() - REPLAY_TTL_SECONDS
    room_replay[room] = [entry for entry in room_replay.get(room, []) if entry[0] >= cutoff]
    if len(room_replay[room]) > MAX_REPLAY_PER_ROOM:
        room_replay[room] = room_replay[room][-MAX_REPLAY_PER_ROOM:]
    if not room_replay[room] or not MAX_REPLAY_PER_ROOM:
        room_replay.pop(room, None)


def _remember_replay(
    room: str,
    msg_type: str | None,
    cid: str | None,
    to: str | None,
    obj: dict[str, Any] | None,
    raw: str,
) -> str:
    if msg_type not in {"m", "gk"} or not cid or not REPLAY_TTL_SECONDS or not MAX_REPLAY_PER_ROOM:
        return raw
    now = time.time()
    if obj is not None:
        obj["rt"] = int(now * 1000)
        raw = json.dumps(obj, separators=(",", ":"))
    room_replay[room].append((now, msg_type, cid, to, raw))
    _prune_replay(room)
    return raw


async def _replay_recent(room: str, ws: WebSocket, cid: str) -> None:
    _prune_replay(room)
    for _ts, msg_type, sender_cid, target_cid, raw in list(room_replay.get(room, [])):
        if msg_type == "m" and sender_cid == cid:
            continue
        if msg_type == "gk" and target_cid != cid:
            continue
        mgr.enqueue(ws, raw)


@app.websocket("/ws/{room_id}")
async def websocket_endpoint(ws: WebSocket, room_id: str):
    client_ip = _client_ip_from_ws(ws)
    if _is_connect_limited(client_ip):
        await ws.close(code=4002)
        return
    try:
        _validate_room_id(room_id)
    except HTTPException:
        await ws.close(code=4003)
        return

    if not origin_allowed(ws, required=True):
        await ws.close(code=4003)
        return

    token = ws.headers.get("sec-websocket-protocol", "")
    session_hash = _verify_room_token(room_id, token, consume=True) if len(token) <= 64 else None
    if not session_hash:
        await ws.close(code=4004)
        return
    try:
        _session_for_hash(session_hash)
    except HTTPException:
        await ws.close(code=4004)
        return
    if not mgr.has_capacity(room_id, session_hash):
        await ws.close(code=1013)
        return

    # Reserve synchronously after checking capacity: parallel upgrades must not
    # all observe the same free slot before their first await.
    mgr.add(room_id, ws, session_hash)
    connection_cid: str | None = None
    try:
        await asyncio.wait_for(ws.accept(subprotocol=token), timeout=10)
        message_metrics["ws_connections"] += 1
        while True:
            event = await asyncio.wait_for(ws.receive(), timeout=90)
            if event["type"] == "websocket.disconnect":
                break
            msg = event.get("text")
            if not isinstance(msg, str):
                await mgr.close(ws, 1003)
                break
            if len(msg.encode("utf-8")) > MAX_MESSAGE_BYTES:
                await mgr.close(ws, 1009)
                break
            # A verified session identifies the sender even when many users share
            # one Render ingress peer. Reconnecting cannot reset this budget.
            if _is_rate_limited_message(session_hash, msg):
                await mgr.close(ws, 4000)
                break
            if _is_bulk(msg):
                continue

            msg_type, cid, to, obj = _message_meta(msg)
            if (not obj or msg_type not in {"hello", "ct", "gk", "gk_req", "gk_ack", "m", "leave"}
                    or not isinstance(cid, str) or not CID_RE.fullmatch(cid)):
                await mgr.close(ws, 1008)
                break
            if msg_type == "hello":
                hello = tuple(obj.get(k) for k in ("x", "k", "id", "sig"))
                if (any(not isinstance(v, str) for v in hello)
                        or any(len(v) != size for v, size in zip(hello, (44, 1580, 44, 88)))
                        or (connection_cid and (cid != connection_cid or mgr.connections[ws]["hello"] != hello))
                        or any(peer is not ws and state["room"] == room_id and state["cid"] == cid
                               for peer, state in mgr.connections.items())):
                    await mgr.close(ws, 1008)
                    break
                first_hello = connection_cid is None
                connection_cid = cid
                mgr.connections[ws].update(cid=cid, hello=hello)
                if first_hello:
                    await _replay_recent(room_id, ws, cid)
            elif not connection_cid or cid != connection_cid:
                await mgr.close(ws, 1008)
                break
            if msg_type == "leave":
                break
            if msg_type in {"ct", "gk", "gk_req", "gk_ack"} and (not to or not CID_RE.fullmatch(to)):
                await mgr.close(ws, 1008)
                break

            msg = _remember_replay(room_id, msg_type, cid, to, obj, msg)
            if msg_type == "m":
                message_metrics["chat_messages"] += 1
            elif msg_type and msg_type not in {"chaff", "ping"}:
                message_metrics["control_messages"] += 1
            await mgr.broadcast(room_id, ws, msg, to)
    except (WebSocketDisconnect, TimeoutError, RuntimeError):
        pass
    finally:
        mgr.remove(room_id, ws)
        if connection_cid:
            await mgr.broadcast(room_id, ws, json.dumps({"t": "leave", "cid": connection_cid}))
        await mgr.close(ws, 1000)


# .venv\Scripts\Activate.ps1
# uvicorn backend.main:app --reload --port 5000
