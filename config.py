# backend/config.py
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(dotenv_path=(Path(__file__).resolve().parent / ".env"))
except Exception:
    pass

# ─────────────────────────────────────────────────────────────────────────────
# Små env-helpers

def _env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)

def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default

def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}

def seconds(td: timedelta) -> int:
    """Hent antall hele sekunder fra timedelta."""
    return int(td.total_seconds())

# ─────────────────────────────────────────────────────────────────────────────
# App-meta

APP_NAME = _env_str("NT_APP_NAME", "NullTrace")
ENV      = _env_str("NT_ENV", "prod")  # "dev" | "prod"
DEBUG    = _env_bool("NT_DEBUG", ENV != "prod")

# ─────────────────────────────────────────────────────────────────────────────
# Sikkerhet / headers

@dataclass(frozen=True)
class Security:
    hsts: bool = _env_bool("NT_HSTS", True)
    strict_csp: bool = _env_bool("NT_CSP_STRICT", False)  # sett True når importmap har nonce og all inline er borte
    referrer_policy: str = _env_str("NT_REFERRER_POLICY", "no-referrer")
    frame_ancestors: str = _env_str("NT_FRAME_ANCESTORS", "'none'")
    img_src: str = _env_str("NT_IMG_SRC", "'self' data:")
    connect_src: str = _env_str("NT_CONNECT_SRC", "'self' ws: wss:")
    # NB: script-src bygges dynamisk i build_csp() pga nonce

SECURITY = Security()

def build_csp(nonce: str) -> str:
    """
    Bygg Content-Security-Policy header. Når SECURITY.strict_csp=True:
      - Ingen 'unsafe-inline'
      - Bruk 'nonce-<nonce>' og 'strict-dynamic'
    """
    if SECURITY.strict_csp:
        script_src = f"'self' 'nonce-{nonce}' 'wasm-unsafe-eval' 'strict-dynamic'"
    else:
        # Transitional til dere har fjernet all inline JS.
        script_src = "'self' 'unsafe-inline' 'wasm-unsafe-eval'"

    return (
        "default-src 'self'; "
        f"script-src {script_src}; "
        "style-src 'self'; "
        f"img-src {SECURITY.img_src}; "
        f"connect-src {SECURITY.connect_src}; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        f"frame-ancestors {SECURITY.frame_ancestors};"
    )

# ─────────────────────────────────────────────────────────────────────────────
# Rate-limits / misbruk

@dataclass(frozen=True)
class RateLimit:
    message_limit: int = _env_int("NT_MSG_LIMIT", 30)  # maks meldinger per vindu
    window: timedelta = timedelta(seconds=_env_int("NT_MSG_WINDOW_SECONDS", 10))
    connect_limit: int = _env_int("NT_CONN_LIMIT", 10)
    connect_window: timedelta = timedelta(seconds=_env_int("NT_CONN_WINDOW_SECONDS", 60))
    ban: timedelta = timedelta(seconds=_env_int("NT_BAN_SECONDS", 300))

RATELIMIT = RateLimit()

# ─────────────────────────────────────────────────────────────────────────────
# WebSocket-parametre

@dataclass(frozen=True)
class WSConfig:
    token_ttl: timedelta = timedelta(seconds=_env_int("NT_TOKEN_TTL_SECONDS", 120))
    max_message_bytes: int = _env_int("NT_MAX_MESSAGE_BYTES", 8192)

WS = WSConfig()

# ─────────────────────────────────────────────────────────────────────────────
# Meldings-/UI-tidsvinduer (server-side referanse; client bruker egne)
# Beholdt her dersom dere vil speile policyer på server.

SELF_DESTRUCT_TIMEOUT = timedelta(minutes=_env_int("NT_SELF_DESTRUCT_MIN", 5))
TIMED_LOCK_WINDOW     = timedelta(minutes=_env_int("NT_TIMED_LOCK_MIN", 1))

# Historisk/diagnostisk (ikke brukt i serveren pr nå, men beholdt for konsistens)
CHAFF_SIZE_BYTES = _env_int("NT_CHAFF_SIZE", 512)

# NullTrace access/payment environment

ACCESS_REQUIRED_ENV_KEYS = (
    "NULLTRACE_PRICE_1M_USD",
    "NULLTRACE_PRICE_6M_USD",
    "NULLTRACE_PRICE_1Y_USD",
    "SOL_USE_DEVNET",
    "SOLANA_RPC_DEV",
    "SOLANA_RPC_MAIN",
    "SOLANA_COLD_WALLET_PUBLIC_KEY",
    "SOL_PRICE_PROVIDER",
    "SOL_PRICE_CACHE_SECONDS",
    "SOL_PRICE_USD_FALLBACK",
    "PAYMENT_FINALITY",
    "PAYMENT_POLL_INTERVAL_SECONDS",
    "PAYMENT_EXPIRES_MINUTES",
    "SWEEP_ENABLED",
    "SWEEP_AFTER_SECONDS",
    "SWEEP_POLL_INTERVAL_SECONDS",
    "SWEEP_MIN_BALANCE_LAMPORTS",
    "SWEEP_RETRY_SECONDS",
    "ACCESS_KEY_PEPPER_BASE64",
    "SESSION_SECRET_BASE64",
    "DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64",
    "ACTIVE_SESSION_HEARTBEAT_SECONDS",
    "SESSION_MAX_INACTIVE_SECONDS",
    "RESTORE_RESET_COOLDOWN_SECONDS",
    "INTERNAL_CRON_SECRET",
)


@dataclass(frozen=True)
class AccessPaymentConfig:
    price_1m_usd: int = _env_int("NULLTRACE_PRICE_1M_USD", 100)
    price_6m_usd: int = _env_int("NULLTRACE_PRICE_6M_USD", 400)
    price_1y_usd: int = _env_int("NULLTRACE_PRICE_1Y_USD", 600)
    sol_use_devnet: bool = _env_bool("SOL_USE_DEVNET", True)
    solana_rpc_dev: str = _env_str("SOLANA_RPC_DEV", "https://api.devnet.solana.com")
    solana_rpc_main: str = _env_str("SOLANA_RPC_MAIN", "https://api.mainnet-beta.solana.com")
    sol_price_provider: str = _env_str("SOL_PRICE_PROVIDER", "coingecko")
    sol_price_cache_seconds: int = _env_int("SOL_PRICE_CACHE_SECONDS", 300)
    payment_finality: str = _env_str("PAYMENT_FINALITY", "finalized")
    payment_poll_interval_seconds: int = _env_int("PAYMENT_POLL_INTERVAL_SECONDS", 10)
    payment_expires_minutes: int = _env_int("PAYMENT_EXPIRES_MINUTES", 30)
    sweep_enabled: bool = _env_bool("SWEEP_ENABLED", True)
    sweep_after_seconds: int = _env_int("SWEEP_AFTER_SECONDS", 60)
    sweep_poll_interval_seconds: int = _env_int("SWEEP_POLL_INTERVAL_SECONDS", 60)
    sweep_min_balance_lamports: int = _env_int("SWEEP_MIN_BALANCE_LAMPORTS", 5000)
    sweep_retry_seconds: int = _env_int("SWEEP_RETRY_SECONDS", 120)
    active_session_heartbeat_seconds: int = _env_int("ACTIVE_SESSION_HEARTBEAT_SECONDS", 60)
    session_max_inactive_seconds: int = _env_int("SESSION_MAX_INACTIVE_SECONDS", 180)
    restore_reset_cooldown_seconds: int = _env_int("RESTORE_RESET_COOLDOWN_SECONDS", 300)


ACCESS_PAYMENT = AccessPaymentConfig()


def missing_access_env_keys() -> list[str]:
    return [key for key in ACCESS_REQUIRED_ENV_KEYS if os.getenv(key) is None]

# ─────────────────────────────────────────────────────────────────────────────
# Eksporterte alias for enkel bruk i main.py (holder navnene identiske):

MESSAGE_LIMIT             = RATELIMIT.message_limit
WINDOW_SECONDS            = seconds(RATELIMIT.window)

CONNECT_LIMIT             = RATELIMIT.connect_limit
CONNECT_WINDOW_SECONDS    = seconds(RATELIMIT.connect_window)

BAN_SECONDS               = seconds(RATELIMIT.ban)

TOKEN_TTL_SECONDS         = seconds(WS.token_ttl)
MAX_MESSAGE_BYTES         = WS.max_message_bytes

__all__ = [
    "APP_NAME", "ENV", "DEBUG",
    "SECURITY", "build_csp",
    "RATELIMIT", "WS",
    "SELF_DESTRUCT_TIMEOUT", "TIMED_LOCK_WINDOW", "CHAFF_SIZE_BYTES",
    "ACCESS_REQUIRED_ENV_KEYS", "ACCESS_PAYMENT", "missing_access_env_keys",
    # aliaser:
    "MESSAGE_LIMIT", "WINDOW_SECONDS",
    "CONNECT_LIMIT", "CONNECT_WINDOW_SECONDS",
    "BAN_SECONDS",
    "TOKEN_TTL_SECONDS", "MAX_MESSAGE_BYTES",
    "seconds",
]
