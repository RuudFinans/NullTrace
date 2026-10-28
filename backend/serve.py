"""Production entry point with bounded WebSocket transport settings."""
from __future__ import annotations

import os

import uvicorn


def main() -> None:
    os.umask(0o077)
    # Render may supply a CPU-based default greater than one. This relay keeps
    # room state in memory, so the launcher owns the single-process setting.
    os.environ["WEB_CONCURRENCY"] = "1"
    uvicorn.run(
        "backend.main:app",
        # Render requires this container bind; SecurityBoundary validates Host/Origin.
        host="0.0.0.0",  # nosec B104
        port=int(os.getenv("PORT", "5000")), workers=1,
        http="h11", ws="websockets", ws_max_size=16_384, ws_max_queue=16,
        ws_per_message_deflate=False, ws_ping_interval=20, ws_ping_timeout=20,
        timeout_keep_alive=5, limit_concurrency=256, backlog=128,
        proxy_headers=False,  # Never let forwarded headers replace the actual peer or scheme.
        server_header=False, access_log=False,
    )


if __name__ == "__main__":
    main()
