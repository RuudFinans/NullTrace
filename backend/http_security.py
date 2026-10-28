"""Small, bounded ingress controls; no external rate-limit service required."""
from __future__ import annotations

import asyncio
import os
import re
import time
from collections import OrderedDict, deque
from urllib.parse import urlsplit

from starlette.responses import JSONResponse

from .access_security import AccessConfigError, env_bool, require_base64_secret


def production() -> bool:
    return os.getenv("NT_ENV", "prod" if os.getenv("RENDER") else "dev") == "prod"


def render_web_service() -> bool:
    # Platform environment, never a request header. Render sets both automatically.
    return os.getenv("RENDER") == "true" and os.getenv("RENDER_SERVICE_TYPE") == "web"


def allowed_origins() -> set[str]:
    return {v.strip().rstrip("/") for v in os.getenv("NT_ALLOWED_ORIGINS", "").split(",") if v.strip()}


def origin_allowed(connection, *, required: bool = False) -> bool:
    origin = connection.headers.get("origin")
    if not origin:
        return not required
    allowed = allowed_origins()
    if allowed:
        return origin in allowed
    scheme = "https" if connection.url.scheme in {"https", "wss"} else "http"
    return origin == f"{scheme}://{connection.headers.get('host', '')}"


def validate_production_config() -> None:
    if not production():
        return
    origins = allowed_origins()
    if not origins or any(urlsplit(v).scheme != "https" or not urlsplit(v).hostname
                          or urlsplit(v).path or urlsplit(v).query or urlsplit(v).fragment
                          or urlsplit(v).username for v in origins):
        raise AccessConfigError("NT_ALLOWED_ORIGINS must contain explicit HTTPS origins in production")
    if not env_bool("SESSION_COOKIE_SECURE", True):
        raise AccessConfigError("SESSION_COOKIE_SECURE must be enabled in production")
    keys = [require_base64_secret(k) for k in (
        "ACCESS_KEY_PEPPER_BASE64", "SESSION_SECRET_BASE64", "DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64")]
    if len(set(keys)) != len(keys):
        raise AccessConfigError("Access, session and deposit encryption secrets must be different")
    if os.getenv("WEB_CONCURRENCY", "1") != "1":
        raise AccessConfigError("This in-memory chat relay requires one worker and one instance")
    if env_bool("DEVNET_PAYMENT_FAUCET_ENABLED", False):
        raise AccessConfigError("The devnet faucet must be disabled in production")
    if os.getenv("PAYMENT_FINALITY", "finalized") != "finalized":
        raise AccessConfigError("Production payments require finalized commitment")
    cron_secret = os.getenv("INTERNAL_CRON_SECRET", "")
    if cron_secret and len(cron_secret) < 32:
        raise AccessConfigError("INTERNAL_CRON_SECRET must be empty (disabled) or at least 32 characters")
    slug, password = os.getenv("ADMIN_PATH", ""), os.getenv("ADMIN_PASSWORD_HASH", "")
    if bool(slug) != bool(password):
        raise AccessConfigError("Configure both ADMIN_PATH and ADMIN_PASSWORD_HASH, or neither")
    if slug:
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", slug):
            raise AccessConfigError("ADMIN_PATH must be a random 24-128 character slug")
        try:
            algorithm, rounds, _, _ = password.split("$", 3)
            valid = algorithm == "pbkdf2_sha256" and 600_000 <= int(rounds) <= 2_000_000
        except ValueError:
            valid = False
        if not valid:
            raise AccessConfigError("ADMIN_PASSWORD_HASH requires PBKDF2-SHA256 with 600000-2000000 iterations")


class BoundedRateLimiter:
    """Reject new identities when full: rotating keys cannot evict active bans."""

    def __init__(self, capacity: int = 10_000):
        self.capacity = capacity
        self.entries: OrderedDict[str, tuple[float, deque[float]]] = OrderedDict()

    def prune(self) -> None:
        now = time.monotonic()
        for key, (expires, _) in list(self.entries.items()):
            if expires <= now:
                del self.entries[key]

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        if key not in self.entries:
            if len(self.entries) >= self.capacity:
                self.prune()
            if len(self.entries) >= self.capacity:
                return False
            self.entries[key] = (now + window, deque())
        _, times = self.entries[key]
        while times and times[0] <= now - window:
            times.popleft()
        if len(times) >= limit:
            return False
        times.append(now)
        self.entries[key] = (now + window, times)
        return True


http_limits = BoundedRateLimiter()


def client_ip(connection) -> str:
    # The actual connection peer. Forwarded IP headers never become client identity.
    # Behind Render this can be a shared ingress peer, not the visitor's public IP.
    return connection.client.host if connection.client else "unknown"


class SecurityBoundary:
    MAX_BODY = 16_384

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            return await self.app(scope, receive, send)
        headers = scope.get("headers", [])
        values = {}
        for key, value in headers:
            values.setdefault(key.lower(), []).append(value)

        async def reject(code, detail):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await JSONResponse({"detail": detail}, status_code=code, headers={
                    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                    **({"Retry-After": "60"} if code == 429 else {}),
                })(scope, receive, send)

        if sum(len(k) + len(v) for k, v in headers) > 16_384:
            return await reject(431, "Request headers too large")
        if render_web_service():
            # Render terminates public TLS and redirects public HTTP to HTTPS:
            # https://render.com/docs/tls . Its internal HTTP hop is expected.
            # This deployment assumption also covers private-network callers;
            # it does not authenticate them or prove the internal hop uses TLS.
            # Ignore all Forwarded/X-Forwarded-* headers, including client IPs.
            scope["scheme"] = "wss" if scope["type"] == "websocket" else "https"
        host_values = values.get(b"host", [])
        if len(host_values) != 1:
            return await reject(400, "Invalid host")
        host = host_values[0].decode("latin-1")
        # Reject URL delimiters, whitespace, credentials and malformed ports before URL reconstruction.
        if not re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?", host):
            return await reject(400, "Invalid host")
        allowed = allowed_origins()
        if allowed and host.lower() not in {urlsplit(v).netloc.lower() for v in allowed}:
            return await reject(400, "Invalid host")
        if production() and scope["scheme"] not in {"https", "wss"} and scope.get("path") != "/healthz":
            return await reject(400, "HTTPS required")
        if len(values.get(b"origin", [])) > 1:
            return await reject(403, "Invalid origin")
        # Prevent Windows UNC/network path resolution before StaticFiles sees the path.
        if "\\" in scope.get("path", "") or "\x00" in scope.get("path", ""):
            return await reject(400, "Invalid path")
        if scope["type"] == "websocket":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        method = scope.get("method", "GET")
        ip = (scope.get("client") or ("unknown", 0))[0]
        if path != "/healthz" and not path.startswith("/static/"):
            if not http_limits.allow(f"all:{ip}", 300, 60):
                return await reject(429, "Too many requests")
        range_header = values.get(b"range", [b""])[0]
        if len(range_header) > 256 or range_header.count(b",") > 3:
            return await reject(416, "Too many ranges")
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            from starlette.requests import Request
            request = Request(scope)
            if not origin_allowed(request) or request.headers.get("sec-fetch-site") in {"cross-site", "same-site"}:
                return await reject(403, "Forbidden origin")
            category, limit, window = "write", 120, 60
            if path.endswith("/login") and path.startswith("/api/admin/"):
                category, limit, window = "admin-login", 5, 60
            elif path in {"/api/access/signin", "/api/access/restore"}:
                category, limit, window = "auth", 15, 60
            elif path == "/api/access/payment/create":
                category, limit, window = "payment-create", 5, 300
            elif path == "/api/access/payment/devnet-fund":
                category, limit, window = "faucet", 2, 300
            elif path.startswith("/api/internal/"):
                category, limit, window = "internal", 4, 60
            if not http_limits.allow(f"{category}:{ip}", limit, window):
                return await reject(429, "Too many requests")
            if category in {"admin-login", "payment-create", "faucet"}:
                if not http_limits.allow(f"global:{category}", limit * 10, window):
                    return await reject(429, "Too many requests")
            lengths = values.get(b"content-length", [])
            if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
                return await reject(400, "Invalid content length")
            if lengths and len(lengths[0]) > 10:
                return await reject(413, "Request body too large")
            if lengths and int(lengths[0]) > self.MAX_BODY:
                return await reject(413, "Request body too large")

            async def read_body():
                body = bytearray()
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        return None
                    body.extend(event.get("body", b""))
                    if len(body) > self.MAX_BODY:
                        raise OverflowError
                    if not event.get("more_body", False):
                        return bytes(body)

            try:
                body = await asyncio.wait_for(read_body(), timeout=10)
            except OverflowError:
                return await reject(413, "Request body too large")
            except TimeoutError:
                return await reject(408, "Request body timeout")
            if body is None:
                return
            content_type = values.get(b"content-type", [b""])[0].split(b";", 1)[0].lower()
            if body and path.startswith("/api/") and content_type != b"application/json":
                return await reject(415, "Use application/json")
            consumed = False

            async def bounded_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            return await self.app(scope, bounded_receive, send)
        return await self.app(scope, receive, send)
