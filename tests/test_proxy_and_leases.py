from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
from starlette.websockets import WebSocketDisconnect, WebSocketState

from backend import access_db, main, serve, wallet
from backend.http_security import SecurityBoundary, validate_production_config
from tests.test_access_payment import create_order
from tests.test_security import hello, login, ticket


@pytest.mark.asyncio
@pytest.mark.parametrize("scope_type", ["http", "websocket"])
@pytest.mark.parametrize("render,service_type,secure,accepted", [
    ("true", "web", False, True),
    ("false", "web", False, False),
    ("true", "pserv", False, False),
    ("", "", False, False),
    ("", "", True, True),
])
async def test_ingress_uses_platform_tls_and_never_forwarded_identity(
    monkeypatch, scope_type, render, service_type, secure, accepted,
):
    monkeypatch.setenv("NT_ENV", "prod")
    monkeypatch.setenv("NT_ALLOWED_ORIGINS", "https://0trace.xyz")
    monkeypatch.setenv("RENDER", render)
    monkeypatch.setenv("RENDER_SERVICE_TYPE", service_type)
    observed, output = {}, []
    async def downstream(scope, receive, send):
        observed.update(scope)
        if scope_type == "http":
            await JSONResponse({"ok": True})(scope, receive, send)
        else:
            await send({"type": "websocket.accept"})
            await send({"type": "websocket.close", "code": 1000})
    async def receive():
        return {"type": "http.request", "body": b""}
    async def send(event):
        output.append(event)
    scheme = ("https" if secure else "http") if scope_type == "http" else ("wss" if secure else "ws")
    scope = {"type": scope_type, "method": "GET", "path": "/", "scheme": scheme,
             "client": ("10.1.2.3", 123), "server": ("0trace.xyz", 80), "query_string": b"",
             "headers": [(b"host", b"0trace.xyz"), (b"origin", b"https://0trace.xyz"),
                         (b"x-forwarded-proto", b"https"), (b"x-forwarded-proto", b"http"),
                         (b"x-forwarded-for", b"192.0.2.66, 198.51.100.25, 10.2.3.4"),
                         (b"x-forwarded-for", b"invalid attacker input"),
                         (b"x-real-ip", b"192.0.2.77"), (b"cf-connecting-ip", b"192.0.2.88"),
                         (b"forwarded", b"for=192.0.2.99;proto=https;host=evil.example"),
                         (b"x-forwarded-host", b"evil.example"),
                         (b"render", b"true"), (b"render-service-type", b"web")]}
    await SecurityBoundary(downstream)(scope, receive, send)
    if accepted:
        assert observed["client"] == ("10.1.2.3", 123)
        assert observed["scheme"] == ("https" if scope_type == "http" else "wss")
    else:
        assert not observed
        if scope_type == "http":
            assert output[0]["status"] == 400
            assert b"HTTPS required" in output[1]["body"]
        else:
            assert output == [{"type": "websocket.close", "code": 1008}]


def test_render_login_and_chat_over_internal_http_keep_security_checks(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("RENDER_SERVICE_TYPE", "web")
    monkeypatch.delenv("NT_ENV")  # Render production detection also works without a manual setting.
    monkeypatch.setenv("NT_ALLOWED_ORIGINS", "https://0trace.xyz")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "1")

    async def internal_http_hop(scope, receive, send):
        if scope["type"] in {"http", "websocket"}:
            scope["scheme"] = "http" if scope["type"] == "http" else "ws"
            scope["client"] = ("10.1.2.3", 123)
        await main.app(scope, receive, send)

    with TestClient(internal_http_hop, base_url="https://0trace.xyz", headers={
        "Origin": "https://0trace.xyz", "X-Forwarded-Proto": "http", "X-Forwarded-For": "192.0.2.1",
    }) as client:
        login(client)
        cookie = next(c for c in client.cookies.jar if c.name == main.SESSION_COOKIE_NAME)
        assert cookie.secure
        assert client.get("/healthz").status_code == 200
        assert client.get("/healthz", headers={"Host": "evil.example"}).status_code == 400
        assert client.post("/api/room-token", json={"room_id": "security-room"},
                           headers={"Origin": "https://evil.example"}).status_code == 403
        with client.websocket_connect("wss://0trace.xyz/ws/security-room", subprotocols=[ticket(client)]):
            pass
        for headers in ({"Origin": "https://evil.example"}, {"Host": "evil.example"}):
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect("wss://0trace.xyz/ws/security-room", subprotocols=[ticket(client)], headers=headers):
                    pass
        # Forwarded identities cannot buy more login attempts through Render.
        for i in range(14):  # The successful login already used one of the 15 attempts.
            assert client.post("/api/access/signin", json={"userKey": "invalid"},
                               headers={"X-Forwarded-For": f"192.0.2.{i + 2}"}).status_code == 401
        assert client.post("/api/access/signin", json={"userKey": "invalid"},
                           headers={"X-Forwarded-For": "198.51.100.55"}).status_code == 429


def test_launcher_pins_one_process_despite_render_cpu_default(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("RENDER_SERVICE_TYPE", "web")
    monkeypatch.setenv("NT_ENV", "prod")
    monkeypatch.setenv("NT_ALLOWED_ORIGINS", "https://0trace.xyz")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "1")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")  # Render's Python runtime default.
    monkeypatch.setattr(serve.os, "umask", lambda _: 0)
    launched = []
    def launch(app, **settings):
        config = serve.uvicorn.Config(app, **settings)
        assert config.workers == 1 and config.proxy_headers is False
        validate_production_config()
        launched.append(app)
    monkeypatch.setattr(serve.uvicorn, "run", launch)
    serve.main()
    assert launched == ["backend.main:app"]


def test_ticket_budget_tracks_verified_session_not_shared_peer(monkeypatch):
    monkeypatch.setattr(main, "TOKEN_REQ_LIMIT", 1)
    with TestClient(main.app, headers={"Origin": "http://testserver"}) as client:
        login(client)
        ticket(client)
        assert client.post("/api/room-token", json={"room_id": "security-room"},
                           headers={"X-Forwarded-For": "192.0.2.5"}).status_code == 429
        login(client)  # A different account/session behind the same ingress still gets a ticket.
        ticket(client)


def test_chat_budget_survives_reconnect_but_is_not_shared_between_sessions(monkeypatch):
    monkeypatch.setattr(main, "CHAT_LIMIT", 2)
    with TestClient(main.app, headers={"Origin": "http://testserver"}) as client:
        login(client)
        first, reconnect = ticket(client), ticket(client)
        login(client)
        other_session = ticket(client)
        for token, message_count in ((first, 3), (reconnect, 1)):
            with client.websocket_connect("/ws/security-room", subprotocols=[token],
                                          headers={"X-Forwarded-For": "192.0.2.50"}) as ws:
                identity = hello()
                ws.send_json(identity)
                for _ in range(message_count):
                    ws.send_json({"t": "m", "cid": identity["cid"], "c": "synthetic"})
                with pytest.raises(WebSocketDisconnect) as error:
                    ws.receive_json()
                assert error.value.code == 4000
        with client.websocket_connect("/ws/security-room", subprotocols=[other_session]) as ws:
            identity = hello()
            ws.send_json(identity)
            ws.send_json({"t": "m", "cid": identity["cid"], "c": "synthetic"})
            ws.send_json({"t": "unknown", "cid": identity["cid"]})
            with pytest.raises(WebSocketDisconnect) as error:
                ws.receive_json()
            assert error.value.code == 1008  # The message passed; the invalid control was rejected.


@pytest.mark.asyncio
async def test_concurrent_sweeps_have_one_owner(monkeypatch):
    order_id, _, _ = create_order(status="confirmed")
    entered = 0
    async def operation(_order_id):
        nonlocal entered
        entered += 1
        await asyncio.sleep(0.03)
        return {"status": "swept"}
    monkeypatch.setattr(wallet, "_sweep_deposit_to_cold", operation)
    results = await asyncio.gather(wallet.sweep_deposit_to_cold(order_id),
                                   wallet.sweep_deposit_to_cold(order_id))
    assert entered == 1
    assert {r["status"] for r in results} == {"swept", "skipped"}
    assert access_db.get_order(order_id)["sweep_lease_token"] is None


def test_wrong_lease_owner_cannot_release_lock():
    order_id, _, _ = create_order(status="confirmed")
    token = access_db.acquire_sweep_lease(order_id)
    assert token
    access_db.release_sweep_lease(order_id, "not-the-owner")
    assert access_db.acquire_sweep_lease(order_id) is None
    access_db.release_sweep_lease(order_id, token)
    assert access_db.acquire_sweep_lease(order_id)


def test_postgres_amounts_support_more_than_two_sol():
    schema = access_db._schema_sql("postgres")
    assert "sol_amount_lamports BIGINT" in schema
    assert "amount_sent_lamports BIGINT" in schema


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_upgrade", [False, True])
async def test_parallel_socket_upgrades_reserve_capacity_and_release_it(monkeypatch, failed_upgrade):
    manager = main.RoomManager()
    monkeypatch.setattr(main, "mgr", manager)
    monkeypatch.setattr(main, "_client_ip_from_ws", lambda ws: "127.0.0.1")
    monkeypatch.setattr(main, "_is_connect_limited", lambda ip: False)
    monkeypatch.setattr(main, "origin_allowed", lambda ws, required: True)
    monkeypatch.setattr(main, "_verify_room_token", lambda *a, **kw: "session-hash")
    monkeypatch.setattr(main, "_session_for_hash", lambda key: ({}, {}))
    gate = asyncio.Event()

    class SlowUpgrade:
        def __init__(self):
            self.headers = {"sec-websocket-protocol": "synthetic-ticket"}
            self.application_state = WebSocketState.CONNECTING
            self.entered = asyncio.Event()
            self.close_codes = []

        async def accept(self, subprotocol):
            self.entered.set()
            await gate.wait()
            if failed_upgrade:
                raise RuntimeError("Disconnected during upgrade")
            self.application_state = WebSocketState.CONNECTED

        async def receive(self):
            return {"type": "websocket.disconnect"}

        async def send_text(self, data):
            raise AssertionError("No messages may be sent before the upgrade completes")

        async def close(self, code):
            self.close_codes.append(code)
            self.application_state = WebSocketState.DISCONNECTED

    sockets = [SlowUpgrade() for _ in range(8)]
    tasks = [asyncio.create_task(main.websocket_endpoint(ws, "capacity-room")) for ws in sockets]
    try:
        await asyncio.wait_for(asyncio.gather(*(ws.entered.wait() for ws in sockets)), timeout=2)
        assert len(manager.connections) == 8
        # Broadcasts must preserve reservations for sockets still upgrading.
        await manager.broadcast("capacity-room", None, "synthetic")
        assert len(manager.connections) == 8
        ninth = SlowUpgrade()
        await asyncio.wait_for(main.websocket_endpoint(ninth, "capacity-room"), timeout=2)
        assert ninth.close_codes == [1013]
        assert not ninth.entered.is_set()
    finally:
        gate.set()
        await asyncio.gather(*tasks)
    assert not manager.connections and not manager.rooms
