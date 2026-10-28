from __future__ import annotations

import asyncio
import base64
import json
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend import access_db, main, wallet
from backend.access_security import (
    AccessConfigError, decrypt_claim_payload, decrypt_deposit_secret,
    encrypt_claim_payload, encrypt_deposit_secret, generate_user_key,
    hash_access_key, hash_restore_key, isoformat, utcnow,
)
from backend.http_security import BoundedRateLimiter, validate_production_config


@pytest.fixture
def client():
    with TestClient(main.app, headers={"Origin": "http://testserver"}) as value:
        yield value


def login(client):
    user_key = generate_user_key()
    now = utcnow()
    account_id = access_db.execute(
        """INSERT INTO access_accounts(user_key_hash, restore_key_hash, plan, paid_until, created_at, updated_at)
           VALUES (?, ?, '1m', ?, ?, ?)""",
        (hash_access_key(user_key), hash_restore_key("restore"), isoformat(now + timedelta(days=1)),
         isoformat(now), isoformat(now)),
    )
    assert client.post("/api/access/signin", json={"userKey": user_key}).status_code == 200
    session = access_db.active_sessions(account_id, now - timedelta(seconds=180))[0]
    return account_id, session


def ticket(client, room="security-room"):
    response = client.post("/api/room-token", json={"room_id": room})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def hello(cid=None):
    # Relay tests deliberately use synthetic keys. Browser tests verify actual signatures.
    return {"t": "hello", "v": 2, "cid": cid or str(uuid4()),
            "x": "A" * 44, "k": "A" * 1580, "id": "A" * 44, "sig": "A" * 88}


def test_security_headers_and_static_containment(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    csp = response.headers["content-security-policy"]
    assert "connect-src 'self';" in csp and "unsafe-inline" not in csp
    assert "nonce-" in csp and "base-uri 'none'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert client.get("/openapi.json").status_code == 404
    for path in ("/static/../.env", "/static/%2e%2e/.env", "/static/%5c%5cattacker.invalid/share"):
        response = client.get(path)
        assert response.status_code in (400, 404)
        assert "ACCESS_KEY_PEPPER_BASE64=" not in response.text


@pytest.mark.parametrize("host", ["testserver/evil", "testserver?evil", "testserver#evil",
                                  "x@testserver", "testserver evil"])
def test_malformed_host_rejected(client, host):
    assert client.get("/healthz", headers={"Host": host}).status_code == 400


def test_host_allowlist(client, monkeypatch):
    monkeypatch.setenv("NT_ALLOWED_ORIGINS", "https://chat.example")
    assert client.get("/healthz").status_code == 400
    assert client.get("/healthz", headers={"Host": "chat.example"}).status_code == 200


@pytest.mark.parametrize("headers", [
    {"Origin": "https://attacker.invalid"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "same-site"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_csrf_rejected(client, headers):
    assert client.post("/api/access/signin", json={"userKey": "x"}, headers=headers).status_code == 403


def test_body_and_error_limits(client):
    secret = "sensitive-value-" * 40
    response = client.post("/api/access/signin", json={"userKey": secret})
    assert response.status_code == 422 and secret not in response.text
    assert client.post("/api/access/signin", content=b"x" * 16385,
                       headers={"Content-Type": "application/json"}).status_code == 413
    assert client.post("/api/access/signin", content=(b"x" * 9000 for _ in range(3)),
                       headers={"Content-Type": "application/json"}).status_code == 413
    assert client.post("/api/access/signin", content='{"userKey":"x"}',
                       headers={"Content-Type": "text/plain"}).status_code == 415
    assert client.post("/api/access/signin", json={"userKey": "x", "admin": True}).status_code == 422


def test_range_dos_rejected_but_video_range_works(client):
    assert client.get("/static/logo.png", headers={"Range": "bytes=" + "0" * 1000 + "-"}).status_code == 416
    assert client.get("/static/logo.png", headers={"Range": "bytes=0-1,3-4,6-7,9-10,12-13"}).status_code == 416
    response = client.get("/static/nulltrace.mp4", headers={"Range": "bytes=0-31"})
    assert response.status_code == 206 and len(response.content) == 32


def test_forged_forwarded_ip_cannot_bypass_signin_limit(client):
    for i in range(15):
        assert client.post("/api/access/signin", json={"userKey": "invalid"},
                           headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code == 401
    assert client.post("/api/access/signin", json={"userKey": "invalid"},
                       headers={"X-Forwarded-For": "198.51.100.1"}).status_code == 429


def test_rate_limiter_bounds_memory_and_does_not_evict_active_clients():
    limiter = BoundedRateLimiter(capacity=2)
    assert limiter.allow("one", 1, 60)
    assert limiter.allow("two", 1, 60)
    assert not limiter.allow("three", 1, 60)
    assert not limiter.allow("one", 1, 60)
    assert len(limiter.entries) == 2


def test_payment_create_budget_without_rpc(client, monkeypatch):
    async def price():
        return 100
    monkeypatch.setattr(wallet, "get_sol_usd_price_cached", price)
    for _ in range(5):
        assert client.post("/api/access/payment/create", json={"plan": "1m"}).status_code == 200
    assert client.post("/api/access/payment/create", json={"plan": "1m"}).status_code == 429


def test_admin_login_throttled_before_hashing(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PATH", "test-admin")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "enabled")
    count = 0
    def verify(_password):
        nonlocal count
        count += 1
        return False
    monkeypatch.setattr(main, "_verify_admin_password", verify)
    for _ in range(5):
        assert client.post("/api/admin/test-admin/login", json={"password": "bad"}).status_code == 401
    assert client.post("/api/admin/test-admin/login", json={"password": "bad"}).status_code == 429
    assert count == 5


def test_room_ticket_requires_login_and_is_single_use(client):
    assert client.post("/api/room-token", json={"room_id": "security-room"}).status_code == 401
    login(client)
    token = ticket(client)
    with client.websocket_connect("/ws/security-room", subprotocols=[token]):
        pass
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/security-room", subprotocols=[token]):
            pass
    assert not main.mgr.connections and not main.mgr.rooms


@pytest.mark.parametrize("origin", ["", "https://attacker.invalid", "null"])
def test_websocket_requires_same_origin(client, origin):
    login(client)
    token = ticket(client)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/security-room", subprotocols=[token], headers={"Origin": origin}):
            pass


def test_revoked_session_invalidates_unused_ticket(client):
    _, session = login(client)
    token = ticket(client)
    access_db.revoke_session(session["id"], "test")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/security-room", subprotocols=[token]):
            pass


def test_revocation_closes_idle_existing_socket(client):
    _, session = login(client)
    token = ticket(client)
    with client.websocket_connect("/ws/security-room", subprotocols=[token]) as ws:
        access_db.revoke_session(session["id"], "test")
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_text()
        assert error.value.code == 4004


@pytest.mark.parametrize("payload", [[], None, 7, "text", {"t": []}, {"t": "unknown", "cid": str(uuid4())}])
def test_malformed_websocket_json_closes_cleanly(client, payload):
    login(client)
    with client.websocket_connect("/ws/security-room", subprotocols=[ticket(client)]) as ws:
        ws.send_json(payload)
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_text()
        assert error.value.code == 1008
    assert not main.mgr.connections


def test_websocket_sender_spoofing_and_duplicate_ids_rejected(client):
    login(client)
    one, two = ticket(client), ticket(client)
    first_hello = hello()
    with client.websocket_connect("/ws/security-room", subprotocols=[one]) as ws1:
        ws1.send_json(first_hello)
        with client.websocket_connect("/ws/security-room", subprotocols=[two]) as ws2:
            ws2.send_json(first_hello)
            with pytest.raises(WebSocketDisconnect) as error:
                ws2.receive_text()
            assert error.value.code == 1008
        ws1.send_json({"t": "m", "cid": str(uuid4())})
        with pytest.raises(WebSocketDisconnect) as error:
            ws1.receive_text()
        assert error.value.code == 1008


def test_websocket_targeting_and_disconnect_cleanup(client):
    login(client)
    one, two, three = ticket(client), ticket(client), ticket(client)
    h1, h2, h3 = hello(), hello(), hello()
    with client.websocket_connect("/ws/security-room", subprotocols=[one]) as ws1:
        ws1.send_json(h1)
        with client.websocket_connect("/ws/security-room", subprotocols=[two]) as ws2:
            ws2.send_json(h2)
            assert ws1.receive_json()["cid"] == h2["cid"]
            with client.websocket_connect("/ws/security-room", subprotocols=[three]) as ws3:
                ws3.send_json(h3)
                ws1.receive_json()
                ws2.receive_json()
                packet = {"t": "ct", "cid": h1["cid"], "to": h2["cid"]}
                ws1.send_json(packet)
                assert ws2.receive_json() == packet
                marker = {"t": "m", "cid": h1["cid"], "c": "marker"}
                ws1.send_json(marker)
                assert ws3.receive_json()["c"] == "marker"  # No ct was leaked to this socket.
    assert not main.mgr.connections and not main.room_replay


@pytest.mark.parametrize("kind", ["oversize", "binary", "bulk"])
def test_websocket_transport_limits(client, kind):
    login(client)
    with client.websocket_connect("/ws/security-room", subprotocols=[ticket(client)]) as ws:
        if kind == "oversize":
            ws.send_text("x" * 16385)
        elif kind == "binary":
            ws.send_bytes(b"binary")
        else:
            for _ in range(61):
                ws.send_json({"t": "ping"})
        with pytest.raises(WebSocketDisconnect) as error:
            ws.receive_text()
        assert error.value.code == {"oversize": 1009, "binary": 1003, "bulk": 4000}[kind]


def test_at_rest_domain_separation_tampering_and_legacy_read(monkeypatch):
    plain = b"wallet-secret" * 3
    encrypted = encrypt_deposit_secret(plain)
    assert encrypted.startswith("v2.") and decrypt_deposit_secret(encrypted) == plain
    assert encrypt_deposit_secret(plain) != encrypted
    data = bytearray(base64.urlsafe_b64decode(encrypted[3:] + "=" * (-len(encrypted[3:]) % 4)))
    data[-1] ^= 1
    corrupt = "v2." + base64.urlsafe_b64encode(data).decode()
    with pytest.raises(InvalidTag):
        decrypt_deposit_secret(corrupt)
    # Even if an operator mistakenly reuses a root secret, v2 ciphertext purposes differ.
    monkeypatch.setenv("SESSION_SECRET_BASE64", base64.b64encode(b"c" * 32).decode())
    with pytest.raises(InvalidTag):
        decrypt_claim_payload(encrypted)
    nonce = b"n" * 12
    old = base64.urlsafe_b64encode(nonce + AESGCM(b"c" * 32).encrypt(nonce, plain, None)).decode()
    assert decrypt_deposit_secret(old) == plain
    payload = {"userKey": "test", "restoreKey": "test"}
    assert decrypt_claim_payload(encrypt_claim_payload(payload)) == payload


def test_production_config_fail_closed(monkeypatch):
    monkeypatch.setenv("NT_ENV", "prod")
    with pytest.raises(AccessConfigError):
        validate_production_config()
    monkeypatch.setenv("NT_ALLOWED_ORIGINS", "https://chat.example")
    with pytest.raises(AccessConfigError):
        validate_production_config()  # Secure cookies still disabled.
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "1")
    validate_production_config()
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    with pytest.raises(AccessConfigError):
        validate_production_config()


def test_postgres_only_requests_generated_ids_for_tables_with_ids():
    connection = access_db.DbConnection(None, "postgres")
    assert connection._prepare_query("INSERT INTO access_accounts(a) VALUES (?)")[1]
    query, returning = connection._prepare_query("INSERT INTO admin_daily_metrics(day) VALUES (?)")
    assert not returning and query.endswith("VALUES (%s)")


@pytest.mark.asyncio
async def test_solana_transactions_are_signed_and_use_correct_recipient():
    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.message import Message
    from solders.transaction import Transaction
    sender, recipient = Keypair(), Keypair()
    class RPC:
        async def get_fee_for_message(self, message, **kwargs):
            assert isinstance(message, Message)
            assert recipient.pubkey() in message.account_keys
            return SimpleNamespace(value=5000)
        async def send_transaction(self, transaction, **kwargs):
            assert isinstance(transaction, Transaction)
            transaction.verify()
            assert recipient.pubkey() in transaction.message.account_keys
            assert kwargs["opts"].skip_preflight is False
            return SimpleNamespace(value=transaction.signatures[0])
    rpc = RPC()
    blockhash = Hash.default()
    assert await wallet.estimate_transfer_fee_lamports(
        rpc, from_pubkey=sender.pubkey(), to_pubkey=recipient.pubkey(), blockhash=blockhash) == 5000
    assert await wallet.send_transfer_lamports(
        rpc, keypair=sender, to_pubkey=recipient.pubkey(), lamports=1000, blockhash=blockhash)


@pytest.mark.parametrize("price,rate", [(float("nan"), 100), (100, float("inf")), (0, 100)])
def test_invalid_prices_rejected(price, rate):
    with pytest.raises(ValueError):
        wallet.calculate_sol_amount_lamports(price, rate)
