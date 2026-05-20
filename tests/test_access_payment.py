from __future__ import annotations

import base64
import math
from datetime import timedelta

import pytest

from backend import access_db, wallet
from backend.access_security import (
    encrypt_claim_payload,
    generate_order_secret,
    hash_access_key,
    hash_order_secret,
    hash_restore_key,
    isoformat,
    utcnow,
)


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


@pytest.fixture(autouse=True)
def access_env(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("NULLTRACE_DATABASE_URL", raising=False)
    monkeypatch.setenv("NULLTRACE_DB_BACKEND", "sqlite")
    monkeypatch.setenv("NULLTRACE_DB_PATH", str(tmp_path / "access.sqlite3"))
    monkeypatch.setenv("NULLTRACE_PRICE_1M_USD", "100")
    monkeypatch.setenv("NULLTRACE_PRICE_6M_USD", "400")
    monkeypatch.setenv("NULLTRACE_PRICE_1Y_USD", "600")
    monkeypatch.setenv("ACCESS_KEY_PEPPER_BASE64", b64(b"a" * 32))
    monkeypatch.setenv("SESSION_SECRET_BASE64", b64(b"b" * 32))
    monkeypatch.setenv("DEPOSIT_WALLET_ENCRYPTION_KEY_BASE64", b64(b"c" * 32))
    monkeypatch.setenv("SOL_PRICE_PROVIDER", "coingecko")
    monkeypatch.setenv("SOL_PRICE_CACHE_SECONDS", "300")
    monkeypatch.setenv("SOL_PRICE_USD_FALLBACK", "")
    monkeypatch.setenv("PAYMENT_FINALITY", "finalized")
    monkeypatch.setenv("PAYMENT_EXPIRES_MINUTES", "30")
    monkeypatch.setenv("PAYMENT_BACKGROUND_WORKER_ENABLED", "0")
    monkeypatch.setenv("SESSION_MAX_INACTIVE_SECONDS", "180")
    monkeypatch.setenv("RESTORE_RESET_COOLDOWN_SECONDS", "0")
    monkeypatch.setenv("SOLANA_COLD_WALLET_PUBLIC_KEY", "11111111111111111111111111111111")
    monkeypatch.setenv("DEVNET_PAYMENT_FAUCET_ENABLED", "0")
    monkeypatch.setenv("DEVNET_PAYMENT_FAUCET_MAX_LAMPORTS", "2000000000")
    wallet._PRICE_CACHE.update(ts=0.0, usd=None)
    access_db.init_db()


def create_order(*, plan="1m", lamports=1000, status="pending", order_secret=None):
    public_key, secret_key = wallet.create_deposit_wallet()
    order_secret = order_secret or generate_order_secret()
    now = utcnow()
    order_id = access_db.execute(
        """
        INSERT INTO payment_orders(
          order_secret_hash, status, plan, usd_price, sol_usd_rate, sol_amount_lamports,
          deposit_public_key, encrypted_deposit_secret_key, expires_at, created_at, updated_at
        )
        VALUES (?, ?, ?, 100, 100, ?, ?, ?, ?, ?, ?)
        """,
        (
            hash_order_secret(order_secret),
            status,
            plan,
            lamports,
            public_key,
            wallet.encrypt_secret_key(secret_key),
            isoformat(now + timedelta(minutes=30)),
            isoformat(now),
            isoformat(now),
        ),
    )
    return order_id, order_secret, public_key


def test_plan_price_to_lamports_calculation():
    lamports = wallet.calculate_sol_amount_lamports(100, 150.25)
    assert lamports == math.ceil((100 / 150.25) * wallet.LAMPORTS_PER_SOL)


def test_database_backend_defaults_to_sqlite(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("NULLTRACE_DATABASE_URL", raising=False)
    monkeypatch.delenv("NULLTRACE_DB_BACKEND", raising=False)

    assert access_db.database_backend() == "sqlite"


def test_database_backend_uses_postgres_url(monkeypatch):
    monkeypatch.delenv("NULLTRACE_DB_BACKEND", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@example.com/db")

    assert access_db.database_backend() == "postgres"
    assert "SERIAL PRIMARY KEY" in access_db._schema_sql("postgres")


@pytest.mark.asyncio
async def test_sol_price_cache_does_not_fetch_too_often(monkeypatch):
    calls = 0

    async def fake_fetch(provider):
        nonlocal calls
        calls += 1
        return 150.0 + calls

    monkeypatch.setattr(wallet, "_fetch_sol_usd_price", fake_fetch)
    first = await wallet.get_sol_usd_price_cached()
    second = await wallet.get_sol_usd_price_cached()

    assert first == 151.0
    assert second == 151.0
    assert calls == 1


def test_user_and_restore_key_hashing_is_hmac_and_deterministic():
    user_key = "nt_user_test_value"
    restore_key = "nt_restore_test_value"

    assert hash_access_key(user_key) == hash_access_key(user_key)
    assert hash_restore_key(restore_key) == hash_restore_key(restore_key)
    assert hash_access_key(user_key) != user_key
    assert hash_restore_key(restore_key) != restore_key


def test_active_vs_stale_session_logic():
    now = utcnow()
    account_id = access_db.execute(
        """
        INSERT INTO access_accounts(user_key_hash, restore_key_hash, plan, paid_until, created_at, updated_at)
        VALUES (?, ?, '1m', ?, ?, ?)
        """,
        (
            hash_access_key("nt_user_active"),
            hash_restore_key("nt_restore_active"),
            isoformat(now + timedelta(days=1)),
            isoformat(now),
            isoformat(now),
        ),
    )
    active_id = access_db.create_session(account_id, "active_hash")
    stale_id = access_db.create_session(account_id, "stale_hash")
    access_db.execute(
        "UPDATE access_sessions SET last_heartbeat_at = ? WHERE id = ?",
        (isoformat(now - timedelta(seconds=600)), stale_id),
    )

    active = access_db.active_sessions(account_id, now - timedelta(seconds=180))
    assert [row["id"] for row in active] == [active_id]


@pytest.mark.asyncio
async def test_payment_confirmation_creates_account_when_balance_is_enough(monkeypatch):
    order_id, _secret, _public_key = create_order(lamports=5000)

    async def fake_balance(public_key, **kwargs):
        return 5000

    monkeypatch.setattr(wallet, "get_deposit_balance_lamports", fake_balance)
    result = await wallet.poll_pending_payments()

    order = access_db.get_order(order_id)
    assert result["confirmed"] == 1
    assert order["status"] == "confirmed"
    assert order["created_account_id"] is not None
    assert order["encrypted_claim_payload"]


@pytest.mark.asyncio
async def test_short_payment_does_not_activate_account(monkeypatch):
    order_id, _secret, _public_key = create_order(lamports=5000)

    async def fake_balance(public_key, **kwargs):
        return 4999

    monkeypatch.setattr(wallet, "get_deposit_balance_lamports", fake_balance)
    result = await wallet.poll_pending_payments()

    order = access_db.get_order(order_id)
    assert result["short"] == 1
    assert order["status"] == "pending"
    assert order["created_account_id"] is None


def test_restore_revokes_old_session():
    from fastapi.testclient import TestClient
    from backend.main import app

    user_key = "nt_user_restore_test"
    restore_key = "nt_restore_restore_test"
    now = utcnow()
    account_id = access_db.execute(
        """
        INSERT INTO access_accounts(user_key_hash, restore_key_hash, plan, paid_until, created_at, updated_at)
        VALUES (?, ?, '1m', ?, ?, ?)
        """,
        (
            hash_access_key(user_key),
            hash_restore_key(restore_key),
            isoformat(now + timedelta(days=1)),
            isoformat(now),
            isoformat(now),
        ),
    )
    old_session_id = access_db.create_session(account_id, "old_session_hash")

    with TestClient(app) as client:
        response = client.post("/api/access/restore", json={"userKey": user_key, "restoreKey": restore_key})

    old_session = access_db.fetchone("SELECT * FROM access_sessions WHERE id = ?", (old_session_id,))
    sessions = access_db.fetchall("SELECT * FROM access_sessions WHERE account_id = ?", (account_id,))
    assert response.status_code == 200
    assert old_session["revoked_at"] is not None
    assert len(sessions) == 2


def test_signin_accepts_existing_session_cookie_for_same_account():
    from fastapi.testclient import TestClient
    from backend.main import app

    user_key = "nt_user_existing_session"
    restore_key = "nt_restore_existing_session"
    now = utcnow()
    access_db.execute(
        """
        INSERT INTO access_accounts(user_key_hash, restore_key_hash, plan, paid_until, created_at, updated_at)
        VALUES (?, ?, '1m', ?, ?, ?)
        """,
        (
            hash_access_key(user_key),
            hash_restore_key(restore_key),
            isoformat(now + timedelta(days=1)),
            isoformat(now),
            isoformat(now),
        ),
    )

    with TestClient(app) as client:
        first = client.post("/api/access/signin", json={"userKey": user_key})
        second = client.post("/api/access/signin", json={"userKey": user_key})

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["status"] == "ok"


def test_restore_cooldown_zero_disables_cooldown(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import app

    monkeypatch.setenv("RESTORE_RESET_COOLDOWN_SECONDS", "0")
    user_key = "nt_user_no_restore_cooldown"
    restore_key = "nt_restore_no_restore_cooldown"
    now = utcnow()
    account_id = access_db.execute(
        """
        INSERT INTO access_accounts(user_key_hash, restore_key_hash, plan, paid_until, created_at, updated_at)
        VALUES (?, ?, '1m', ?, ?, ?)
        """,
        (
            hash_access_key(user_key),
            hash_restore_key(restore_key),
            isoformat(now + timedelta(days=1)),
            isoformat(now),
            isoformat(now),
        ),
    )
    access_db.audit_event("session_restored", account_id=account_id, metadata={})

    with TestClient(app) as client:
        response = client.post("/api/access/restore", json={"userKey": user_key, "restoreKey": restore_key})

    assert response.status_code == 200


def test_keys_are_not_returned_after_keys_claimed_at():
    from fastapi.testclient import TestClient
    from backend.main import app

    order_id, order_secret, _public_key = create_order(status="confirmed")
    payload = encrypt_claim_payload(
        {
            "userKey": "nt_user_claim_once",
            "restoreKey": "nt_restore_claim_once",
            "paidUntil": isoformat(utcnow() + timedelta(days=30)),
        }
    )
    access_db.execute(
        "UPDATE payment_orders SET encrypted_claim_payload = ? WHERE id = ?",
        (payload, order_id),
    )

    with TestClient(app) as client:
        first = client.post(
            "/api/access/payment/status",
            json={"orderId": str(order_id), "orderSecret": order_secret},
        )
        second = client.post(
            "/api/access/payment/status",
            json={"orderId": str(order_id), "orderSecret": order_secret},
        )

    assert first.status_code == 200
    assert first.json()["restoreKey"] == "nt_restore_claim_once"
    assert second.status_code == 200
    assert second.json() == {"status": "confirmed", "keysAlreadyClaimed": True}


def test_payment_status_checks_chain_and_claims_keys(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import app

    order_id, order_secret, _public_key = create_order(lamports=5000)

    async def fake_balance(public_key, **kwargs):
        return 5000

    monkeypatch.setattr(wallet, "get_deposit_balance_lamports", fake_balance)

    with TestClient(app) as client:
        response = client.post(
            "/api/access/payment/status",
            json={"orderId": str(order_id), "orderSecret": order_secret},
        )

    order = access_db.get_order(order_id)
    assert response.status_code == 200
    assert response.json()["status"] == "confirmed"
    assert response.json()["userKey"].startswith("nt_user_")
    assert order["status"] == "confirmed"


def test_payment_status_claim_signs_in_current_browser(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import app

    order_id, order_secret, _public_key = create_order(lamports=5000)

    async def fake_balance(public_key, **kwargs):
        return 5000

    monkeypatch.setattr(wallet, "get_deposit_balance_lamports", fake_balance)

    with TestClient(app) as client:
        claim = client.post(
            "/api/access/payment/status",
            json={"orderId": str(order_id), "orderSecret": order_secret},
        )
        heartbeat = client.post("/api/access/heartbeat", json={})

    assert claim.status_code == 200
    assert claim.json()["signedIn"] is True
    assert heartbeat.status_code == 200


def test_devnet_payment_faucet_is_hidden_by_default():
    from fastapi.testclient import TestClient
    from backend.main import app

    with TestClient(app) as client:
        response = client.get("/api/access/plans")

    assert response.status_code == 200
    assert response.json()["devnetPaymentFaucet"] is False


def test_devnet_payment_button_is_not_rendered_on_mainnet(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import app

    monkeypatch.setenv("SOL_USE_DEVNET", "0")
    monkeypatch.setenv("DEVNET_PAYMENT_FAUCET_ENABLED", "1")

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "devnetFundBtn" not in response.text
    assert "Send Devnet SOL" not in response.text


def test_devnet_payment_fund_endpoint_uses_order_secret(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import app

    monkeypatch.setenv("DEVNET_PAYMENT_FAUCET_ENABLED", "1")
    order_id, order_secret, public_key = create_order(lamports=5000)
    called = {}

    async def fake_fund(order):
        called["order"] = order
        return {
            "status": "funded",
            "signature": "sig",
            "lamports": int(order["sol_amount_lamports"]),
            "balanceLamports": int(order["sol_amount_lamports"]),
            "solAmount": wallet.lamports_to_sol_string(int(order["sol_amount_lamports"])),
        }

    monkeypatch.setattr(wallet, "fund_devnet_payment_order", fake_fund)

    with TestClient(app) as client:
        bad = client.post(
            "/api/access/payment/devnet-fund",
            json={"orderId": str(order_id), "orderSecret": "wrong"},
        )
        ok = client.post(
            "/api/access/payment/devnet-fund",
            json={"orderId": str(order_id), "orderSecret": order_secret},
        )

    assert bad.status_code == 404
    assert ok.status_code == 200
    assert ok.json()["status"] == "funded"
    assert called["order"]["deposit_public_key"] == public_key


def test_devnet_payment_fund_rpc_error_returns_json(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import app

    monkeypatch.setenv("DEVNET_PAYMENT_FAUCET_ENABLED", "1")
    order_id, order_secret, _public_key = create_order(lamports=5000)

    async def fake_fund(order):
        raise wallet.DevnetFundingError("devnet airdrop failed: faucet limit reached")

    monkeypatch.setattr(wallet, "fund_devnet_payment_order", fake_fund)

    with TestClient(app) as client:
        response = client.post(
            "/api/access/payment/devnet-fund",
            json={"orderId": str(order_id), "orderSecret": order_secret},
        )

    assert response.status_code == 502
    assert "faucet limit" in response.json()["detail"]


def test_sweep_amount_is_balance_minus_estimated_fee_only():
    assert wallet.calculate_sweep_amount(1_000_000, 5_000) == 995_000


@pytest.mark.asyncio
async def test_sweep_idempotency_does_not_resweep():
    order_id, _secret, public_key = create_order(status="confirmed")
    access_db.create_sweep(
        payment_order_id=order_id,
        deposit_public_key=public_key,
        cold_wallet_public_key="11111111111111111111111111111111",
        balance_before_lamports=1000,
        fee_lamports=5000,
        amount_sent_lamports=995000,
        balance_after_lamports=0,
        sweep_signature="sig",
        status="swept",
    )

    result = await wallet.sweep_deposit_to_cold(order_id)
    assert result["status"] == "already_swept"
