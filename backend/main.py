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
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.websockets import WebSocketState

from . import access_db, wallet
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

app = FastAPI()
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
            log.exception("%s background loop crashed: %s", name, safe_error(exc))
            await asyncio.sleep(retry_seconds)


@app.on_event("startup")
async def startup() -> None:
    access_db.init_db()
    if env_bool("PAYMENT_BACKGROUND_WORKER_ENABLED", True):
        app.state.payment_background_tasks = [
            asyncio.create_task(_run_payment_background_loop("payment-watch", wallet.poll_pending_payments)),
            asyncio.create_task(_run_payment_background_loop("sweep", wallet.poll_unswept_deposits)),
        ]
        log.info("payment background worker enabled")
    else:
        app.state.payment_background_tasks = []
        log.info("payment background worker disabled")


@app.on_event("shutdown")
async def shutdown() -> None:
    tasks = list(getattr(app.state, "payment_background_tasks", []) or [])
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
        "connect-src 'self' ws: wss:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


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
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _client_ip_from_ws(ws: WebSocket) -> str:
    xff = ws.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return ws.client.host if ws.client else "0.0.0.0"


def _prune_and_check(timestamps: list[float], limit: int, window: int) -> bool:
    now = time.time()
    while timestamps and timestamps[0] < now - window:
        timestamps.pop(0)
    if len(timestamps) >= limit:
        return False
    timestamps.append(now)
    return True


TOKEN_REQ_LIMIT = 60
TOKEN_REQ_WINDOW = 60
TOKEN_TTL_SECONDS = 120
ROOM_ID_RE = __import__("re").compile(r"^[A-Za-z0-9_-]{6,64}$")
ADMIN_COOKIE_NAME = "nt_admin_session"
ADMIN_SESSION_HOURS = 8

token_req_times: dict[str, list[float]] = defaultdict(list)
client_times_chat: dict[str, list[float]] = defaultdict(list)
client_times_ctrl: dict[str, list[float]] = defaultdict(list)
client_connect_times: dict[str, list[float]] = defaultdict(list)
banned_ips: dict[str, float] = {}
room_replay: dict[str, list[tuple[float, str | None, str | None, str | None, str]]] = defaultdict(list)

_room_tokens: dict[str, dict[str, tuple[float, int]]] = {}


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
    try:
        day = utcnow().date().isoformat()
        access_db.increment_daily_metric("page_views", day=day)
        visitor_hash = _visitor_hash(request, day)
        if visitor_hash:
            access_db.remember_daily_visitor(day, visitor_hash)
    except Exception:
        pass


def _validate_room_id(room_id: str) -> None:
    if not ROOM_ID_RE.match(room_id):
        raise HTTPException(status_code=400, detail="Invalid room id")


def _issue_room_token(room_id: str, account_id: int) -> tuple[str, float]:
    token = secrets.token_urlsafe(32)
    exp = time.time() + TOKEN_TTL_SECONDS
    _room_tokens.setdefault(room_id, {})[token] = (exp, account_id)
    return token, exp


def _verify_room_token(room_id: str, token: str, consume: bool = True) -> bool:
    now = time.time()
    tokens = _room_tokens.get(room_id)
    if not tokens:
        return False
    entry = tokens.get(token)
    for saved_token, (exp, _) in list(tokens.items()):
        if exp <= now:
            tokens.pop(saved_token, None)
    if not entry:
        return False
    exp, _account_id = entry
    if exp <= now:
        tokens.pop(token, None)
        return False
    if consume:
        tokens.pop(token, None)
    return True


def _cookie_secure(request: Request) -> bool:
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


class PaymentCreateReq(BaseModel):
    plan: str


class PaymentStatusReq(BaseModel):
    orderId: int | str
    orderSecret: str


class DevnetFundReq(BaseModel):
    orderId: int | str
    orderSecret: str


class SignInReq(BaseModel):
    userKey: str


class RestoreReq(BaseModel):
    userKey: str
    restoreKey: str


class TokenReq(BaseModel):
    room_id: str


class AdminLoginReq(BaseModel):
    password: str


class AdminGenerateAccessReq(BaseModel):
    label: str = ""
    days: int = 3650


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    _track_page_visit(request)
    devnet_payment_faucet = wallet.devnet_payment_faucet_enabled()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "uuid": uuid4(),
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
        "admin.html",
        {
            "request": request,
            "uuid": uuid4(),
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
    if not _verify_admin_password(req.password or ""):
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
        current = access_db.row_to_dict(
            conn.execute(
                "SELECT * FROM payment_orders WHERE id = ? AND order_secret_hash = ?",
                (order_id, hash_order_secret(req.orderSecret)),
            ).fetchone()
        )
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
    client_ip = _client_ip_from_request(request)
    if not _prune_and_check(token_req_times[client_ip], TOKEN_REQ_LIMIT, TOKEN_REQ_WINDOW):
        raise HTTPException(status_code=429, detail="Too many requests")

    origin = request.headers.get("origin", "")
    scheme = "https" if request.url.scheme == "https" else "http"
    expected1 = f"{scheme}://{request.url.hostname}"
    expected2 = f"{expected1}:{request.url.port}" if request.url.port else expected1
    if origin and origin not in (expected1, expected2):
        raise HTTPException(status_code=403, detail="Forbidden")

    token, exp = _issue_room_token(req.room_id, int(account["id"]))
    access_db.update_session_heartbeat(int(session["id"]))
    access_db.increment_daily_metric("room_tokens")
    return {"token": token, "exp": int(exp)}


class RoomManager:
    def __init__(self) -> None:
        self.rooms: dict[str, set[WebSocket]] = {}

    def add(self, room: str, ws: WebSocket) -> None:
        self.rooms.setdefault(room, set()).add(ws)

    def remove(self, room: str, ws: WebSocket) -> None:
        self.rooms.get(room, set()).discard(ws)

    async def broadcast(self, room: str, sender: WebSocket, data: str) -> None:
        for peer in list(self.rooms.get(room, set())):
            if peer.application_state != WebSocketState.CONNECTED:
                self.remove(room, peer)
                continue
            if peer is sender:
                continue
            try:
                await peer.send_text(data)
            except Exception:
                self.remove(room, peer)


mgr = RoomManager()

CHAT_LIMIT = 90
CHAT_WINDOW_SECONDS = 10
CTRL_LIMIT = 120
CTRL_WINDOW_SECONDS = 10
CONNECT_LIMIT = 30
CONNECT_WINDOW_SECONDS = 60
WS_BAN_SECONDS = 60
REPLAY_TTL_SECONDS = env_int("NT_REPLAY_TTL_SECONDS", 35)
MAX_REPLAY_PER_ROOM = env_int("NT_REPLAY_MAX_PER_ROOM", 200)
MAX_MESSAGE_BYTES = 16384


def _is_banned(client_ip: str) -> bool:
    now = time.time()
    until = banned_ips.get(client_ip)
    if until and until > now:
        return True
    if until and until <= now:
        banned_ips.pop(client_ip, None)
    return False


def _is_connect_limited(client_ip: str) -> bool:
    ok = _prune_and_check(client_connect_times[client_ip], CONNECT_LIMIT, CONNECT_WINDOW_SECONDS)
    if not ok:
        banned_ips[client_ip] = time.time() + WS_BAN_SECONDS
    return not ok


def _classify_message_kind(msg_text: str) -> str:
    try:
        msg_type = json.loads(msg_text).get("t")
    except Exception:
        return "chat"
    if msg_type in {"chaff", "ping"}:
        return "bulk"
    if msg_type == "m":
        return "chat"
    return "ctrl"


def _is_rate_limited_message(client_ip: str, msg_text: str) -> bool:
    kind = _classify_message_kind(msg_text)
    if kind == "bulk":
        return False
    if kind == "ctrl":
        return not _prune_and_check(client_times_ctrl[client_ip], CTRL_LIMIT, CTRL_WINDOW_SECONDS)
    return not _prune_and_check(client_times_chat[client_ip], CHAT_LIMIT, CHAT_WINDOW_SECONDS)


def _is_bulk(msg_text: str) -> bool:
    try:
        return json.loads(msg_text).get("t") in {"chaff", "ping"}
    except Exception:
        return False


def _message_meta(msg_text: str) -> tuple[str | None, str | None, str | None, dict[str, Any] | None]:
    try:
        obj = json.loads(msg_text)
    except Exception:
        return None, None, None, None
    msg_type = obj.get("t")
    cid = obj.get("cid") if isinstance(obj.get("cid"), str) and len(obj.get("cid")) <= 64 else None
    to = obj.get("to") if isinstance(obj.get("to"), str) and len(obj.get("to")) <= 64 else None
    return msg_type, cid, to, obj


def _prune_replay(room: str) -> None:
    cutoff = time.time() - REPLAY_TTL_SECONDS
    room_replay[room] = [entry for entry in room_replay[room] if entry[0] >= cutoff]
    if len(room_replay[room]) > MAX_REPLAY_PER_ROOM:
        room_replay[room] = room_replay[room][-MAX_REPLAY_PER_ROOM:]


def _remember_replay(
    room: str,
    msg_type: str | None,
    cid: str | None,
    to: str | None,
    obj: dict[str, Any] | None,
    raw: str,
) -> str:
    if msg_type not in {"m", "gk"} or not cid:
        return raw
    now = time.time()
    if obj is not None:
        obj.setdefault("rt", int(now * 1000))
        raw = json.dumps(obj, separators=(",", ":"))
    room_replay[room].append((now, msg_type, cid, to, raw))
    _prune_replay(room)
    return raw


async def _replay_recent(room: str, ws: WebSocket, cid: str) -> None:
    _prune_replay(room)
    for _ts, msg_type, sender_cid, target_cid, raw in list(room_replay[room]):
        if msg_type == "m" and sender_cid == cid:
            continue
        if msg_type == "gk" and target_cid != cid:
            continue
        try:
            await ws.send_text(raw)
        except Exception:
            break


@app.websocket("/ws/{room_id}")
async def websocket_endpoint(ws: WebSocket, room_id: str):
    client_ip = _client_ip_from_ws(ws)
    if _is_banned(client_ip):
        await ws.close(code=4001)
        return
    if _is_connect_limited(client_ip):
        await ws.close(code=4002)
        return
    try:
        _validate_room_id(room_id)
    except HTTPException:
        await ws.close(code=4003)
        return

    origin = ws.headers.get("origin", "")
    scheme = "https" if ws.url.scheme == "wss" else "http"
    expected1 = f"{scheme}://{ws.url.hostname}"
    expected2 = f"{expected1}:{ws.url.port}" if ws.url.port else expected1
    if origin and origin not in (expected1, expected2):
        await ws.close(code=4003)
        return

    token = ws.headers.get("sec-websocket-protocol", "")
    if not token or not _verify_room_token(room_id, token, consume=True):
        await ws.close(code=4004)
        return

    await ws.accept(subprotocol=token)
    mgr.add(room_id, ws)
    access_db.increment_daily_metric("ws_connections")
    connection_cid: str | None = None
    try:
        while True:
            msg = await ws.receive_text()
            if len(msg.encode("utf-8")) > MAX_MESSAGE_BYTES:
                try:
                    await ws.send_text('{"t":"rate","reason":"too_big"}')
                except Exception:
                    pass
                continue
            if _is_rate_limited_message(client_ip, msg):
                try:
                    await ws.send_text('{"t":"rate","reason":"too_fast"}')
                except Exception:
                    pass
                continue
            if _is_bulk(msg):
                continue

            msg_type, cid, to, obj = _message_meta(msg)
            if msg_type == "hello" and cid:
                connection_cid = cid
                await _replay_recent(room_id, ws, cid)
            elif msg_type == "leave" and cid != connection_cid:
                continue

            msg = _remember_replay(room_id, msg_type, cid, to, obj, msg)
            if msg_type == "m":
                access_db.increment_daily_metric("chat_messages")
            elif msg_type and msg_type not in {"chaff", "ping"}:
                access_db.increment_daily_metric("control_messages")
            await mgr.broadcast(room_id, ws, msg)
    except WebSocketDisconnect:
        mgr.remove(room_id, ws)
        if connection_cid:
            await mgr.broadcast(room_id, ws, json.dumps({"t": "leave", "cid": connection_cid}))


# .venv\Scripts\Activate.ps1
# uvicorn backend.main:app --reload --port 5000
