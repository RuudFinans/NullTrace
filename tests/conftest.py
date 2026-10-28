from __future__ import annotations

import base64
import os

# Set before backend import; tests must never load local payment secrets or contact live RPC.
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ["PAYMENT_BACKGROUND_WORKER_ENABLED"] = "0"

import pytest


@pytest.fixture(autouse=True)
def isolated_security_env(monkeypatch, tmp_path):
    monkeypatch.setenv("NT_ENV", "dev")
    monkeypatch.delenv("NT_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("ADMIN_PATH", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("INTERNAL_CRON_SECRET", raising=False)
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("RENDER_SERVICE_TYPE", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("NULLTRACE_DATABASE_URL", raising=False)
    monkeypatch.setenv("NULLTRACE_DB_BACKEND", "sqlite")
    monkeypatch.setenv("NULLTRACE_DB_PATH", str(tmp_path / "security.sqlite3"))
    monkeypatch.setenv("PAYMENT_BACKGROUND_WORKER_ENABLED", "0")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "0")
    monkeypatch.setenv("SOL_USE_DEVNET", "1")
    monkeypatch.setenv("DEVNET_PAYMENT_FAUCET_ENABLED", "0")
    monkeypatch.setenv("PAYMENT_FINALITY", "finalized")
    for name, value in (("ACCESS_KEY_PEPPER_BASE64", b"a"),
                        ("SESSION_SECRET_BASE64", b"b"),
                        ("DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64", b"c")):
        monkeypatch.setenv(name, base64.b64encode(value * 32).decode())
    from backend import access_db, main
    access_db.init_db()
    main.http_limits.entries.clear()
    main.ws_limits.entries.clear()
    main._room_tokens.clear()
    main.room_replay.clear()
    main.message_metrics.clear()
    yield
