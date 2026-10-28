from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


USER_KEY_PREFIX = "nt_user_"
RESTORE_KEY_PREFIX = "nt_restore_"
SESSION_COOKIE_NAME = "nt_session"


class AccessConfigError(RuntimeError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


def env_float(key: str, default: float | None = None) -> float | None:
    raw = os.getenv(key)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise AccessConfigError(f"{key} must be a number") from exc


def env_bool(key: str, default: bool) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def require_base64_secret(key: str, min_bytes: int = 32) -> bytes:
    raw = os.getenv(key, "").strip()
    if not raw:
        raise AccessConfigError(f"{key} is required")
    padded = raw + "=" * (-len(raw) % 4)
    try:
        value = base64.b64decode(padded, validate=True)
    except Exception as exc:
        raise AccessConfigError(f"{key} must be base64") from exc
    if len(value) < min_bytes:
        raise AccessConfigError(f"{key} must decode to at least {min_bytes} bytes")
    return value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def random_secret_token(bytes_len: int = 32) -> str:
    return _b64url(secrets.token_bytes(bytes_len))


def generate_user_key() -> str:
    return USER_KEY_PREFIX + random_secret_token(32)


def generate_restore_key() -> str:
    return RESTORE_KEY_PREFIX + random_secret_token(32)


def generate_order_secret() -> str:
    return random_secret_token(32)


def generate_session_token() -> str:
    return random_secret_token(32)


def _hmac_hex(secret_env: str, value: str) -> str:
    key = require_base64_secret(secret_env)
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_access_key(value: str) -> str:
    return _hmac_hex("ACCESS_KEY_PEPPER_BASE64", value)


def hash_restore_key(value: str) -> str:
    return _hmac_hex("ACCESS_KEY_PEPPER_BASE64", value)


def hash_order_secret(value: str) -> str:
    return _hmac_hex("SESSION_SECRET_BASE64", value)


def hash_session_token(value: str) -> str:
    return _hmac_hex("SESSION_SECRET_BASE64", value)


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _aes_key_from_env(secret_env: str) -> bytes:
    raw = require_base64_secret(secret_env)
    if len(raw) == 32:
        return raw
    return hashlib.sha256(raw).digest()


def encrypt_bytes(plaintext: bytes, secret_env: str) -> str:
    context = f"NullTrace|at-rest|v2|{secret_env}".encode("ascii")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(
        _aes_key_from_env(secret_env))
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, context)
    return "v2." + _b64url(nonce + ciphertext)


def decrypt_bytes(payload: str, secret_env: str) -> bytes:
    versioned = payload.startswith("v2.")
    data = _b64url_decode(payload[3:] if versioned else payload)
    if len(data) < 28:
        raise AccessConfigError("encrypted payload is malformed")
    nonce, ciphertext = data[:12], data[12:]
    key = _aes_key_from_env(secret_env)
    context = None
    if versioned:
        context = f"NullTrace|at-rest|v2|{secret_env}".encode("ascii")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(key)
    # Legacy read support preserves existing encrypted deposit wallets during rollout.
    return AESGCM(key).decrypt(nonce, ciphertext, context)


def encrypt_deposit_secret(secret_key: bytes) -> str:
    return encrypt_bytes(secret_key, "DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64")


def decrypt_deposit_secret(payload: str) -> bytes:
    return decrypt_bytes(payload, "DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64")


def encrypt_claim_payload(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return encrypt_bytes(raw, "SESSION_SECRET_BASE64")


def decrypt_claim_payload(payload: str) -> dict[str, Any]:
    raw = decrypt_bytes(payload, "SESSION_SECRET_BASE64")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise AccessConfigError("claim payload is malformed")
    return value


def safe_error(exc: Exception) -> str:
    return exc.__class__.__name__
