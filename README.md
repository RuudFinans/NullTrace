NullTrace
=========

NullTrace is a PWA for private encrypted messaging. Access is activated by a Solana payment and then controlled by a one-session lease.

Environment
-----------

Use Render environment variables in production, or a private `.env` locally. Do not commit secrets. Production also requires the security settings in the deployment section below:

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
iterations = 600000
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
python -m backend.serve
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

Production deployment after the 2026-10-24 security update
---------------------------------------------------------

The application remains one Python web process with its payment loops. No Redis, new API service, crypto service or external chat provider is required. Existing Solana RPC and price-provider calls remain. `render.yaml` is an optional blueprint for a single web service with a persistent SQLite disk; it has **not** been applied to a live Render account.

Use these Render settings:

| Setting | Value |
| --- | --- |
| Runtime | Python 3.13.17 (or a later tested security patch in the 3.13 series) |
| Build command | `pip install --require-hashes -r requirements.txt` |
| Start command | `python -m backend.serve` |
| Health check | `/healthz` |
| Instances / workers | Exactly **one** instance and **one** worker |
| SQLite storage | Persistent disk mounted at `/var/data`; database `/var/data/nulltrace_access.sqlite3` |
| JavaScript build | Prebuilt bundles are committed; rebuild locally/CI with Node 24.22.1, `npm ci --ignore-scripts`, `npm run build:libs` |

Render's ephemeral filesystem is unsuitable for the access/payment database. A persistent disk requires an appropriate paid Render plan. If the existing deployment uses PostgreSQL, keep its existing database and credentials; do not apply the blueprint's SQLite settings over it. The chat relay still requires one process/instance with PostgreSQL because membership, rate limits, tickets and short replay buffers are in memory.

Required security environment:

```env
NT_ENV=prod
SESSION_COOKIE_SECURE=1
NT_ALLOWED_ORIGINS=https://0trace.xyz
NT_VISITOR_METRICS=0
PAYMENT_FINALITY=finalized
DEVNET_PAYMENT_FAUCET_ENABLED=0
PAYMENT_BACKGROUND_WORKER_ENABLED=1
```

`NT_ALLOWED_ORIGINS` contains exact origins, including a port only if one is really used: no paths, wildcards or trailing slashes. For this installation, use `https://0trace.xyz`; add any other actual custom domains or the service's `https://...onrender.com` address separated by commas if they must serve the app. Include all verified custom domains that Render might use for its health-check Host header. `NT_ENV=prod` is selected automatically on Render when `NT_ENV` is absent, but setting it explicitly is clearer.

**No proxy CIDR variable is required.** [Render redirects public HTTP to HTTPS and terminates TLS](https://render.com/docs/tls). When Render's automatic environment identifies a web service (`RENDER=true` and `RENDER_SERVICE_TYPE=web`), the app represents this external connection as HTTPS/WSS even though Render's internal hop uses HTTP. This is a deployment assumption, not authentication of private-network callers or encryption of the internal hop. Keep the private workspace/network trusted. Other production deployments still require an actual HTTPS/WSS scope. `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Proto` and similar headers never establish client identity or scheme; Uvicorn's proxy parser stays disabled. Old `NT_TRUSTED_PROXY_CIDRS` / `TRUSTED_PROXY_CIDRS` settings can be removed and have no effect.

Without verified visitor IP metadata, HTTP and connection-attempt limits use the actual connection peer, which can be shared by visitors behind the same Render ingress. These shared budgets can throttle legitimate traffic during bursts or abuse; they are not advertised as per-visitor IP protection. Authenticated chat message and room-ticket limits use the validated access session, so unrelated chat users do not share a message budget and reconnecting does not reset it. Host/Origin validation, Secure cookies, access checks, global resource bounds and encryption remain enabled.

**`WEB_CONCURRENCY` is not a required manual environment setting.** It counts server processes, not simultaneous users. `python -m backend.serve` explicitly runs one process and normalizes the variable to `1` before app startup, including when Render supplies a higher CPU-based default. One process handles multiple users/rooms concurrently. Keep one Render instance because live room state is held in that process; a different launcher must also use one worker.

Keep three **independent**, private secrets of at least 32 decoded random bytes: `ACCESS_KEY_PEPPER_BASE64`, `SESSION_SECRET_BASE64`, `DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64`. Preserve the existing values during this upgrade. Replacing the pepper invalidates access keys; replacing the deposit key without re-encryption makes existing deposit wallets unreadable. Never generate replacement secrets just because the application is redeployed.

For real payments, keep `SOL_USE_DEVNET=0`, use the intended HTTPS mainnet RPC, verify `SOLANA_COLD_WALLET_PUBLIC_KEY` independently, and use finalized commitment. Keep the devnet faucet disabled. The internal cron endpoints are disabled if `INTERNAL_CRON_SECRET` is empty. If used, configure a random secret of at least 32 characters; the built-in payment loops normally make external cron unnecessary.

For administration, set **both** `ADMIN_PATH` and `ADMIN_PASSWORD_HASH`, or leave both unset to disable the console. Production requires a random 24–128 character slug and a PBKDF2-SHA256 hash with 600,000–2,000,000 iterations. Existing 310,000-iteration hashes must be regenerated with the example above (the password itself may stay the same). A hidden URL is only an additional barrier; authentication and throttling are always required.

Before release:

1. Back up the database and the existing secrets separately using access controls appropriate for wallet keys. For SQLite, use its backup API or stop the app before copying the database and outstanding WAL state. Verify that the backup can be restored; do not replace a populated database with a new empty disk.
2. Configure the runtime, origins and persistent database path before starting the new process. No proxy address list is needed on Render. Startup rejects insecure production settings. Schema changes run at startup: sweep leases and PostgreSQL BIGINT amounts, with existing records preserved.
3. End active chats for this deployment and have every participant reload. Protocol v3 and NT-C3 invitations reject all previous protocol versions; create new rooms and invitations. Existing access keys, session hashes and encrypted wallets remain compatible. Commit the prebuilt `frontend/static/libs/ratchet-wasm` assets along with the JavaScript changes; Render does not need a Rust toolchain.
4. Verify HTTPS, `/healthz`, secure cookies, normal sign-in, invitation/approval/message exchange, disconnect/rejoin, logout/restore, and both valid and hostile Origin/Host requests on the actual domain. Check that spoofed X-Forwarded-For prefixes do not bypass limits.
5. Test the payment path on devnet in a separate test configuration, then verify real production RPC/finality/cold-wallet settings. No real transaction was sent during the local review. Keep rollback backups; new `v2.` encrypted records are **not readable by the previous code**.

Browser caching is intentionally stricter: HTML, JavaScript, crypto bundles and API replies are not stored in the service worker cache. Old NullTrace caches are removed on service worker activation. JavaScript still benefits from HTTP ETag revalidation and a stable content-derived build version. Open tabs must reload to pick up security updates. Offline chat is not supported. No CSS or HTML layout was changed.

Protocol and threat model
-------------------------

Protocol v3 uses ephemeral Ed25519 identities and an authenticated X25519 + ML-KEM-768 handshake with HKDF-SHA256. Its signed transcript binds both participants' IDs/public keys, room, protocol suite/version, KEM ciphertext and the fresh native ratchet public key. Invalid or absent signatures abort key establishment. The host identity is pinned from an NT-C3 invitation. Bootstrap shared secrets are erased after creating the pairwise ratchet, and the guest also erases its bootstrap X25519/ML-KEM private keys. Reconnection requires new bootstrap keys and fresh admission.

Host/member control channels now use **vodozemac 0.11.1's Double Ratchet**, compiled into prebuilt browser WASM. This is a maintained project with an external audit history; that audit does **not** cover our exact version, initialization/lifecycle extensions, WASM wrapper or group integration. The wrapper uses fresh native X25519 ratchet keys, AES-256-CBC and a full 32-byte HMAC-SHA256, rejecting the legacy truncated-MAC mode. It authenticates application metadata inside the encrypted envelope and commits a cloned receive state only after authentication succeeds. There is no browser session-export or persistent key-storage API. Source, two small vendor extensions, license, provenance, asset hashes and rebuild instructions are in [crypto/ratchet-wasm/README.md](crypto/ratchet-wasm/README.md).

Each new group epoch has a random 32-byte seed delivered through those pairwise ratchets. The seed is kept in binary buffers, expanded into separate sender chains using domain-separated keyed BLAKE2b, then erased. Each message consumes a new HMAC-SHA512-derived 256-bit message key and advances the chain; both the old chain key and used message key are wiped. Group messages use XChaCha20-Poly1305 plus Ed25519 signatures binding sender, epoch, sequence and timestamp. A client never keeps a duplicate receive chain for its own sender identity. Up to 64 skipped keys per remote sender support reordering and expire 35 seconds after derivation; browser scheduling and memory cleanup are best effort. Invalid ciphertext does not advance receive chains or consume skipped keys.

Compare the **cryptographic fingerprints** using a trusted, separate channel before approving a participant. The host's pending list and guest confirmation now show fingerprints rather than treating a short UUID as proof of identity. Self-signed public keys alone do not identify a human. Deliver invitations through a trusted channel.

Joins/leaves cause immediate epoch rotation; removed members receive no new key envelopes. The host also schedules a fresh epoch every 30 seconds while connected. Guests send authenticated encrypted acknowledgements, enabling fresh DH contributions in both directions. This timer is not a guaranteed recovery deadline: suspended tabs, dropped packets and disconnects can delay exchanges. A partially transmitted epoch tears down the affected room state instead of rolling counters back. A host departure ends guests' sessions. There is no message persistence in the database. The relay can retain a bounded ciphertext buffer for up to 35 seconds for connection races, default 32 packets per room. Set `NT_REPLAY_TTL_SECONDS=0` or `NT_REPLAY_MAX_PER_ROOM=0` to disable this buffer. Keep device clocks synchronized for invitation/message expiry checks.

This improves the previous static wrapping/sender-key design: later **processed** state no longer retains the keys for already consumed messages or old control envelopes. A lagging recipient can still derive messages it has not processed until its chain advances or the epoch is erased. Group-wide classical post-compromise recovery requires the attacker to lose endpoint access, fresh honest DH turns on **every exposed surviving member's channel**, and a subsequent fresh group epoch. Recovery of only one pair does not heal the whole room. Retained/stolen signing keys with ongoing active impersonation, a malicious authorized member and a compromised browser/server remain outside that recovery claim.

**This is not RFC 9420 MLS, Signal-compatible messaging, or a proven improvement over Signal.** `mls.js` remains a historical filename for a host-managed group protocol. The initial ML-KEM handshake provides a post-quantum component, but this classical ratchet does not add continuing post-quantum recovery. Signal already specifies [SPQR and Triple Ratchet](https://signal.org/docs/specifications/doubleratchet/); simply adding classical Double Ratchet does not exceed those properties. A separate protocol review is still needed. No "best", "unbreakable" or fully post-quantum-authenticated claim follows from these changes.

The following limits still apply:

- A compromised browser/device, extension, server delivering modified JavaScript, or deployment account can defeat web E2EE. The application has no independently signed native client or external key-transparency system.
- ML-KEM protects the hybrid key agreement's post-quantum component; Ed25519 authentication is classical. Do not describe the entire protocol as fully post-quantum authenticated.
- Key wiping is best effort in JavaScript/Python; garbage collection, copies, browser memory and swap cannot be guaranteed erased. Receivers can save plaintext or take screenshots. Timed disappearance is not remote deletion.
- The server/host can observe room membership, timing, network metadata and ciphertext sizes. Payment/account records and audit events exist, and Solana transactions are public. Optional hashed visitor tracking is now off by default. Aggregate counters remain; platform/RPC logging is outside this code's control. Existing marketing statements such as "no accounts" must not be read as a guarantee that no access/payment metadata exists.
- Rate limits and finite queues mitigate application-level abuse; they cannot prevent every distributed or upstream denial-of-service attack. Limits currently include 128 total sockets, 64 rooms, 16 sockets per room, 8 sockets per access session, 16 KiB wire messages and 8 KiB plaintext messages. Slow consumers are disconnected rather than blocking other participants.
- Access keys are delivered once. Losing that response or failing to save the keys can still require operator support; encrypted claim data is deleted on claim. This existing payment UX was not redesigned.

Security review record — 2026-10-24
---------------------------------

Scope: this repository's backend, payment/access code, browser crypto and PWA cache, dependency manifests and deployment configuration. No live Render account, external websites, production logs, real wallet transfers, mobile Safari or live PostgreSQL instance was accessed. The pre-existing untracked `crypto/openmls-wasm/` experiment was left untouched; the later ratchet work adds a separate `crypto/ratchet-wasm/` directory.

The declared old Python pins matched **18 distinct CVE identifiers across 7 packages** in PyPI advisory data: AnyIO, cryptography, h11, idna, PyNaCl, python-dotenv and Starlette. Advisory matches are not proof that every vulnerable function was reachable. In particular, Starlette's vulnerable static-file/Range path was used by this app; h11 0.14.0 was a declared request-smuggling risk. Unused packages, including PyNaCl, numerical/geoscience packages and unused crypto experiments, were removed from runtime manifests. Python dependencies now have an exact, hashed runtime lock, and the development tools have a separate hashed lock.

The old npm audit reported four affected packages (one critical, two high, one moderate), including unused protobufjs and Rollup. The manifest was reduced to the two actual browser crypto libraries and the build/test tools, then rebuilt. Tracked `node_modules` and generated Python bytecode were removed from the Git index; dependencies are recreated from lockfiles. This accounts for the large deletion count. Local dependency/tool directories are ignored.

The PHP2Shell vulnerabilities CVE-2026-109618/109619 do not directly apply to this Python application; no PHP execution path was found here. Node CVE-2026-111497 affects Node's Brotli decoder, not browser JavaScript simply because a page uses JavaScript. This application does not serve requests through Node. Its local Node was 24.19.0, so an isolated official, SHA256-checked Node 24.22.1 was used for rebuilding and tests. The machine's global Node and PyCharm's Python 3.13.7 interpreter were not replaced. Upgrade them separately; production is pinned to Python 3.13.17. Other software on the host remains outside this review.

References: [PHP/FBI advisory](https://www.ic3.gov/PSA/2026/PSA261023), [Node October security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), [Python releases](https://www.python.org/downloads/), [Render FastAPI guidance](https://render.com/articles/fastapi-production-best-practices), [Signal's Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/), [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html).

Validation and maintenance
--------------------------

Double Ratchet follow-up (2026-10-28): **80 Python tests, 25 JavaScript/actual-WASM tests and 6 native Rust tests passed.** The three-session browser regression passed with the real scheduled epoch refresh, reconnect/reapproval, removal, logout, CSP and cache checks. Native compromise snapshots test deletion of consumed envelopes and recovery after fresh honest DH turns, including a snapshot taken after an acknowledgement that can still decrypt the next envelope. Group tests cover independent HMAC derivation, buffer erasure, skipped-key bounds/expiry, invalid-ciphertext rollback, partial-send teardown, replay and repeated three-member rotations with lost acknowledgements. RustSec reported no known vulnerabilities or warnings among 93 dependencies at advisory revision `99670cfc0bc574433034b75876a4b791ccaa2efb`. Rebuilding locally reproduced both delivery-asset hashes. No live deployment or independent external audit of this integration was performed.

The updated synthetic benchmark measured a 27.038 ms hybrid/ratchet bootstrap and 0.284 ms median / 0.482 ms p95 encrypt-sign-verify-decrypt time across 1,000 1 KiB messages on the local Node/WASM runtime. These are local samples, not production latency guarantees. The earlier timings and test counts below are historical records.

Render configuration follow-up (2026-10-28): the manual proxy CIDR requirement was removed and the launcher now owns the single-process setting. **80 Python tests passed**, including simulated Render internal HTTP/WSS, Secure cookies, Host/Origin rejection, spoofed forwarded headers, session-specific chat/ticket budgets and reconnect limits. The three-session browser regression also passed. No live Render deployment or real payment was performed for this follow-up. The 68-test result below records the earlier review.

Using the project's configured Python SDK and an isolated dependency directory, the review exercises access/payments, hostile input and origins, forwarded-IP spoofing, body/frame/rate limits, ticket/session revocation, socket identity binding, encrypted-storage compatibility, sweep leases and signed Solana transaction construction. Node tests cover handshake/capsule tampering, group impersonation, membership removal, replay, wrong recipient/room, nonce/counter handling and bounded buffers. Playwright tests run three independent browser sessions through sign-in, invitation/approval, chat, reconnect/reapproval, removal, host departure, logout, reload, CSP and cache rules.

Final local results: **68 Python tests and 11 crypto tests passed**, along with the three-session browser regression. Concurrent socket upgrades are explicitly tested against the per-session capacity limit, including failed-upgrade cleanup. The Python run has one dependency deprecation warning about Starlette's current HTTPX test client; it does not indicate a test failure. `npm audit` and the Python audit of all 71 locked runtime/development packages reported no known vulnerabilities; all 32 runtime pins are included in that audit. A hash-checked installation dry run passed, and all 32 runtime packages were successfully downloaded as hash-checked Linux x86-64/Python 3.13 wheels. This verifies package availability, not a live Linux/Render execution.

Bandit reported zero medium/high findings after two narrow, documented suppressions. Five low-severity `try/except/pass` findings were manually reviewed: optional dotenv loading in two modules, nonessential visitor metrics, socket-close cleanup and devnet error-format fallback. They remain visible in the full scan. The PyCharm build reported success with limited diagnostic support; executable tests provide the stronger validation here.

To reproduce in a clean environment:

```text
python -m pip install --require-hashes -r requirements-dev.txt
python -m pytest -q
python -m pip_audit --disable-pip --no-deps -r requirements.txt
python -m bandit -r backend config.py -ll
npm ci --ignore-scripts
npm audit
npm test
npm run build:libs
npx playwright install chromium
```

For the browser test, run `python -m tests.browser_server` in one terminal and `node tests/browser.test.mjs` in another. It uses only a disposable local database and synthetic access keys. Stop the server afterward. For a local synthetic crypto timing sample, run `node tests/benchmark_crypto.mjs`; this is not a production latency or load guarantee.

The two crypto bundles together decreased from 1,857,219 to 464,077 bytes (about 75% smaller, before HTTP compression). The initial local timing sample for 1,000 synthetic 1 KiB messages measured 0.274 ms median and 0.635 ms p95 for encrypt/sign/verify/decrypt, and 13.222 ms for the two-sided hybrid handshake. Hardware and browser results vary. Message metrics are now batched rather than writing to the database for every packet, and slow sockets have bounded independent queues.

The GitHub workflow runs tests, dependency checks, static analysis and bundle consistency checks on push/pull request. It also verifies the committed ratchet asset hashes, runs native compromise-snapshot tests, checks RustSec advisories and rebuilds/tests the WASM engine with pinned Rust/wasm-bindgen tools. These are development/CI steps, not Render runtime requirements. The updated workflow has not been run remotely during this review. Bandit's intentional container bind and allowlisted SQL column selection are documented at the two exact suppression sites; no broad directory exclusion hides findings.

Update locks deliberately, review package changes, then rerun the checks:

```text
python -m piptools compile --upgrade --generate-hashes --strip-extras --no-emit-index-url --no-emit-trusted-host --output-file requirements.txt requirements.in
python -m piptools compile --upgrade --allow-unsafe --generate-hashes --strip-extras --no-emit-index-url --no-emit-trusted-host --output-file requirements-dev.txt requirements-dev.in
```

An audit result of "no known vulnerabilities" is time-bound evidence about the scanned versions, not a promise of no unknown flaws. Deployment, backup restoration, live proxy validation and an independent cryptographic review remain operator responsibilities.
