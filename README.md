NullTrace
=========

NullTrace is a PWA for private encrypted messaging. Access is activated by a Solana payment and then controlled by a one-session lease.

Environment
-----------

Create a private `.env` file on the server and fill every value. Do not commit `.env` or local example env files:

```env
NULLTRACE_PRICE_1M_USD=100
NULLTRACE_PRICE_6M_USD=400
NULLTRACE_PRICE_1Y_USD=600

NULLTRACE_DB_BACKEND=sqlite
NULLTRACE_DB_PATH=nulltrace_access.sqlite3
NULLTRACE_DATABASE_URL=

SOL_USE_DEVNET=1
SOLANA_RPC_DEV=https://api.devnet.solana.com
SOLANA_RPC_MAIN=https://api.mainnet-beta.solana.com
SOLANA_COLD_WALLET_PUBLIC_KEY=
DEVNET_PAYMENT_FAUCET_ENABLED=0
DEVNET_PAYMENT_FAUCET_MAX_LAMPORTS=2000000000

SOL_PRICE_PROVIDER=coingecko
SOL_PRICE_CACHE_SECONDS=300
SOL_PRICE_USD_FALLBACK=

PAYMENT_FINALITY=finalized
PAYMENT_POLL_INTERVAL_SECONDS=10
PAYMENT_EXPIRES_MINUTES=30
PAYMENT_BACKGROUND_WORKER_ENABLED=1
PAYMENT_BACKGROUND_RETRY_SECONDS=15

SWEEP_ENABLED=1
SWEEP_AFTER_SECONDS=60
SWEEP_POLL_INTERVAL_SECONDS=60
SWEEP_MIN_BALANCE_LAMPORTS=5000
SWEEP_RETRY_SECONDS=120

ACCESS_KEY_PEPPER_BASE64=
SESSION_SECRET_BASE64=
DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64=

ACTIVE_SESSION_HEARTBEAT_SECONDS=60
SESSION_MAX_INACTIVE_SECONDS=180
RESTORE_RESET_COOLDOWN_SECONDS=300

INTERNAL_CRON_SECRET=

ADMIN_PATH=
ADMIN_PASSWORD_HASH=
```

Generate secrets:

```powershell
python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Run that once each for `ACCESS_KEY_PEPPER_BASE64`, `SESSION_SECRET_BASE64`, and `DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64`.

Admin console:

- Set `ADMIN_PATH` to a long random slug. The admin page will be `/<ADMIN_PATH>`.
- Set `ADMIN_PASSWORD_HASH` to a PBKDF2 hash, not a plaintext password.

Generate an admin password hash:

```powershell
@'
import base64, getpass, hashlib, secrets
password = getpass.getpass("Admin password: ").encode()
salt = secrets.token_bytes(16)
iterations = 310000
digest = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)
enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
print(f"pbkdf2_sha256${iterations}${enc(salt)}${enc(digest)}")
'@ | python -
```

Database selection:

- Local testing: keep `NULLTRACE_DB_BACKEND=sqlite` and use `NULLTRACE_DB_PATH`.
- Render/Postgres: set `NULLTRACE_DB_BACKEND=postgres` and set `NULLTRACE_DATABASE_URL` to the Postgres URL. Render can also provide `DATABASE_URL`; the app will use it when `NULLTRACE_DATABASE_URL` is empty.

Database And Workers
--------------------

The app creates/migrates the configured access database on startup. To initialize manually:

```powershell
python -c "from backend.access_db import init_db; init_db()"
```

Run the web app:

```powershell
uvicorn backend.main:app --reload --port 5000
```

The web process starts the payment watcher and sweeper automatically when `PAYMENT_BACKGROUND_WORKER_ENABLED=1`. With `SWEEP_ENABLED=1`, finalized deposits are confirmed and swept to `SOLANA_COLD_WALLET_PUBLIC_KEY` from inside the running app process.

You can still run payment watcher and sweeper manually for maintenance/debugging:

```powershell
python -m backend.payment_worker payment-watch
python -m backend.payment_worker sweep
```

Or run both in one process:

```powershell
python -m backend.payment_worker all
```

Internal cron endpoints are also available and require `X-Internal-Secret: <INTERNAL_CRON_SECRET>`:

```text
POST /api/internal/payment-watch
POST /api/internal/sweep
```

Devnet Testing
--------------

Use `SOL_USE_DEVNET=1`, set `SOLANA_COLD_WALLET_PUBLIC_KEY` to a devnet wallet you control, and optionally set `SOL_PRICE_USD_FALLBACK` while testing. Set `DEVNET_PAYMENT_FAUCET_ENABLED=1` to show a payment-screen button that requests devnet SOL for the current order. Each payment order creates a fresh Solana deposit wallet, locks the SOL amount at creation, and stores only the encrypted deposit secret key.

Access Model
------------

Payment creates a `user_key` and `restore_key`. The `user_key` signs in when no active session exists. A session is active while the browser sends heartbeat within `SESSION_MAX_INACTIVE_SECONDS`. If another active session exists, sign-in returns `RESTORE_REQUIRED`; entering the `restore_key` revokes old sessions and moves access to the current browser.

iPhone/PWA Backup Flow
----------------------

After payment, NullTrace shows the keys once with reveal/hide, copy buttons, “Copy both keys”, and a screenshot-friendly backup card. Web Share is offered only when `navigator.share` exists, with a warning. Automatic `.txt` download is not the primary path and is hidden for iOS/PWA standalone.

Security Limitations
--------------------

This primarily stops simultaneous use of the same `user_key`. It does not stop two people from sharing a `user_key` and using it at different times. The `restore_key` can take over a session and must be stored safely. PWA/browser sessions are weaker than hardware-bound auth. If browser storage/cookies are cleared, the user must sign in again.

For a normal SOL deposit wallet there is no SPL `closeAccount`. The sweeper sends `balance - actual_transaction_fee` to the cold wallet and aims to leave 0 lamports. It does not reserve rent-exempt lamports and does not leave 0.0008-ish SOL behind.
