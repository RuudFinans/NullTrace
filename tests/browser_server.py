"""Disposable local server for browser tests; no real payments or user data."""
from __future__ import annotations

import base64
import os
import tempfile
from datetime import timedelta
from pathlib import Path

for name, value in {
    "PYTHON_DOTENV_DISABLED": "1", "NT_ENV": "dev", "PAYMENT_BACKGROUND_WORKER_ENABLED": "0",
    "SESSION_COOKIE_SECURE": "0", "NULLTRACE_DB_BACKEND": "sqlite", "SOL_USE_DEVNET": "1",
    "DEVNET_PAYMENT_FAUCET_ENABLED": "0", "NT_ALLOWED_ORIGINS": "",
    "RENDER": "false", "RENDER_SERVICE_TYPE": "",
}.items():
    os.environ[name] = value
for key, value in (("ACCESS_KEY_PEPPER_BASE64", b"a"), ("SESSION_SECRET_BASE64", b"b"),
                   ("DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64", b"c")):
    os.environ[key] = base64.b64encode(value * 32).decode()

from backend import access_db
from backend.access_security import hash_access_key, hash_restore_key, isoformat, utcnow
import uvicorn

if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="nulltrace-browser-") as directory:
        os.environ["NULLTRACE_DB_PATH"] = str(Path(directory) / "test.sqlite3")
        access_db.init_db()
        for label in ("host", "guest", "third"):
            now = utcnow()
            access_db.execute(
                """INSERT INTO access_accounts(user_key_hash, restore_key_hash, plan, paid_until, created_at, updated_at)
                   VALUES (?, ?, '1m', ?, ?, ?)""",
                (hash_access_key("nt_user_browser_" + label), hash_restore_key("test-restore"),
                 isoformat(now + timedelta(days=1)), isoformat(now), isoformat(now)),
            )
        uvicorn.run("backend.main:app", host="127.0.0.1", port=5017, access_log=False,
                    proxy_headers=False, ws_max_size=16384, ws_per_message_deflate=False)
