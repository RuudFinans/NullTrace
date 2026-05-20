from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from .access_security import isoformat, parse_datetime, utcnow


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = ROOT_DIR / "nulltrace_access.sqlite3"


def database_url() -> str:
    return os.getenv("NULLTRACE_DATABASE_URL") or os.getenv("DATABASE_URL") or ""


def database_backend() -> str:
    configured = os.getenv("NULLTRACE_DB_BACKEND", "").strip().lower()
    if configured in {"sqlite", "postgres"}:
        return configured
    url = database_url().strip().lower()
    if url.startswith(("postgres://", "postgresql://")):
        return "postgres"
    return "sqlite"


def db_path() -> Path:
    return Path(os.getenv("NULLTRACE_DB_PATH", str(DEFAULT_DB_PATH))).resolve()


def _sqlite_connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _postgres_connect():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError("Postgres requires installing psycopg[binary]") from exc

    url = database_url()
    if not url:
        raise RuntimeError("NULLTRACE_DATABASE_URL or DATABASE_URL is required for Postgres")
    if url.startswith("postgres://"):
        url = f"postgresql://{url[len('postgres://'):]}"
    return psycopg.connect(url, row_factory=dict_row)


def _connect():
    if database_backend() == "postgres":
        return DbConnection(_postgres_connect(), "postgres")
    return DbConnection(_sqlite_connect(), "sqlite")


class DbCursor:
    def __init__(self, cursor: Any, *, lastrowid: int | None = None) -> None:
        self._cursor = cursor
        self._lastrowid = lastrowid

    @property
    def lastrowid(self) -> int | None:
        if self._lastrowid is not None:
            return self._lastrowid
        return getattr(self._cursor, "lastrowid", None)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


class DbConnection:
    def __init__(self, conn: Any, backend: str) -> None:
        self._conn = conn
        self.backend = backend

    def _prepare_query(self, query: str) -> tuple[str, bool]:
        if self.backend != "postgres":
            return query, False
        prepared = query.replace("?", "%s")
        normalized = prepared.strip().lower()
        should_return_id = normalized.startswith("insert ") and " returning " not in normalized
        if should_return_id:
            prepared = f"{prepared.rstrip().rstrip(';')} RETURNING id"
        return prepared, should_return_id

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> DbCursor:
        prepared, should_return_id = self._prepare_query(query)
        cur = self._conn.execute(prepared, params)
        lastrowid = None
        if should_return_id:
            row = cur.fetchone()
            if row:
                lastrowid = int(row["id"] if isinstance(row, dict) else row[0])
        return DbCursor(cur, lastrowid=lastrowid)

    def executescript(self, script: str) -> None:
        if self.backend == "sqlite":
            self._conn.executescript(script)
            return
        for statement in (part.strip() for part in script.split(";")):
            if statement:
                self.execute(statement)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()


@contextmanager
def db() -> Iterator[DbConnection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _columns(conn: DbConnection, table: str) -> set[str]:
    if conn.backend == "postgres":
        rows = conn.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = ?
            """,
            (table,),
        ).fetchall()
        return {row["column_name"] for row in rows}
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_column(conn: DbConnection, table: str, name: str, definition: str) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def init_db() -> None:
    with db() as conn:
        conn.executescript(_schema_sql(conn.backend))
        _add_column(conn, "payment_orders", "encrypted_claim_payload", "TEXT")


def _schema_sql(backend: str) -> str:
    id_type = "SERIAL PRIMARY KEY" if backend == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    return f"""
        CREATE TABLE IF NOT EXISTS access_accounts (
          id {id_type},
          user_key_hash TEXT NOT NULL UNIQUE,
          restore_key_hash TEXT NOT NULL,
          plan TEXT NOT NULL,
          paid_until TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          revoked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS payment_orders (
          id {id_type},
          order_secret_hash TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('pending','confirmed','expired','failed','swept')),
          plan TEXT NOT NULL,
          usd_price REAL NOT NULL,
          sol_usd_rate REAL NOT NULL,
          sol_amount_lamports INTEGER NOT NULL,
          deposit_public_key TEXT NOT NULL UNIQUE,
          encrypted_deposit_secret_key TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          confirmed_at TEXT,
          confirmed_balance_lamports INTEGER,
          created_account_id INTEGER,
          encrypted_claim_payload TEXT,
          keys_claimed_at TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(created_account_id) REFERENCES access_accounts(id)
        );

        CREATE TABLE IF NOT EXISTS access_sessions (
          id {id_type},
          account_id INTEGER NOT NULL,
          session_token_hash TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL,
          last_heartbeat_at TEXT NOT NULL,
          revoked_at TEXT,
          revoke_reason TEXT,
          expires_at TEXT,
          FOREIGN KEY(account_id) REFERENCES access_accounts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sweeps (
          id {id_type},
          payment_order_id INTEGER NOT NULL,
          deposit_public_key TEXT NOT NULL,
          cold_wallet_public_key TEXT NOT NULL,
          balance_before_lamports INTEGER NOT NULL,
          fee_lamports INTEGER NOT NULL,
          amount_sent_lamports INTEGER NOT NULL,
          balance_after_lamports INTEGER,
          sweep_signature TEXT,
          status TEXT NOT NULL CHECK(status IN ('pending','swept','failed','dust_unspendable')),
          error TEXT,
          created_at TEXT NOT NULL,
          swept_at TEXT,
          FOREIGN KEY(payment_order_id) REFERENCES payment_orders(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_events (
          id {id_type},
          account_id INTEGER,
          payment_order_id INTEGER,
          event_type TEXT NOT NULL,
          metadata_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          FOREIGN KEY(account_id) REFERENCES access_accounts(id),
          FOREIGN KEY(payment_order_id) REFERENCES payment_orders(id)
        );

        CREATE TABLE IF NOT EXISTS admin_sessions (
          id {id_type},
          session_token_hash TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          revoked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS admin_daily_metrics (
          day TEXT NOT NULL PRIMARY KEY,
          page_views INTEGER NOT NULL DEFAULT 0,
          unique_visitors INTEGER NOT NULL DEFAULT 0,
          room_tokens INTEGER NOT NULL DEFAULT 0,
          ws_connections INTEGER NOT NULL DEFAULT 0,
          chat_messages INTEGER NOT NULL DEFAULT 0,
          control_messages INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admin_visit_seen (
          day TEXT NOT NULL,
          visitor_hash TEXT NOT NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY(day, visitor_hash)
        );

        CREATE INDEX IF NOT EXISTS idx_payment_status ON payment_orders(status, expires_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_account ON access_sessions(account_id, revoked_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_token ON access_sessions(session_token_hash);
        CREATE INDEX IF NOT EXISTS idx_audit_account_type ON audit_events(account_id, event_type, created_at);
        CREATE INDEX IF NOT EXISTS idx_sweeps_order_status ON sweeps(payment_order_id, status);
        CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(session_token_hash, revoked_at);
        CREATE INDEX IF NOT EXISTS idx_admin_visit_seen_day ON admin_visit_seen(day);
        """


def row_to_dict(row: Any | None) -> dict[str, Any] | None:
    return None if row is None else dict(row)


def fetchone(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with db() as conn:
        return row_to_dict(conn.execute(query, params).fetchone())


def fetchall(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with db() as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def execute(query: str, params: tuple[Any, ...] = ()) -> int:
    with db() as conn:
        cur = conn.execute(query, params)
        return int(cur.lastrowid or 0)


def audit_event(
    event_type: str,
    *,
    account_id: int | None = None,
    payment_order_id: int | None = None,
    metadata: dict[str, Any] | None = None,
    conn: DbConnection | None = None,
) -> None:
    target = conn
    close = False
    if target is None:
        target = _connect()
        close = True
    try:
        target.execute(
            """
            INSERT INTO audit_events(account_id, payment_order_id, event_type, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                account_id,
                payment_order_id,
                event_type,
                json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True),
                isoformat(utcnow()),
            ),
        )
        if close:
            target.commit()
    except Exception:
        if close:
            target.rollback()
        raise
    finally:
        if close:
            target.close()


def get_account_by_user_hash(user_key_hash: str) -> dict[str, Any] | None:
    return fetchone("SELECT * FROM access_accounts WHERE user_key_hash = ?", (user_key_hash,))


def get_session_by_hash(session_token_hash: str) -> dict[str, Any] | None:
    return fetchone("SELECT * FROM access_sessions WHERE session_token_hash = ?", (session_token_hash,))


def active_sessions(account_id: int, cutoff: datetime) -> list[dict[str, Any]]:
    return fetchall(
        """
        SELECT * FROM access_sessions
        WHERE account_id = ?
          AND revoked_at IS NULL
          AND last_heartbeat_at > ?
        ORDER BY last_heartbeat_at DESC
        """,
        (account_id, isoformat(cutoff)),
    )


def revoke_sessions(account_id: int, reason: str, *, conn: DbConnection | None = None) -> None:
    now = isoformat(utcnow())
    query = """
        UPDATE access_sessions
        SET revoked_at = ?, revoke_reason = ?
        WHERE account_id = ? AND revoked_at IS NULL
    """
    if conn is not None:
        conn.execute(query, (now, reason, account_id))
        return
    execute(query, (now, reason, account_id))


def revoke_stale_sessions(account_id: int, cutoff: datetime) -> None:
    execute(
        """
        UPDATE access_sessions
        SET revoked_at = ?, revoke_reason = 'stale'
        WHERE account_id = ? AND revoked_at IS NULL AND last_heartbeat_at <= ?
        """,
        (isoformat(utcnow()), account_id, isoformat(cutoff)),
    )


def create_session(account_id: int, session_token_hash: str, expires_at: datetime | None = None) -> int:
    now = isoformat(utcnow())
    return execute(
        """
        INSERT INTO access_sessions(
          account_id, session_token_hash, created_at, last_heartbeat_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (account_id, session_token_hash, now, now, isoformat(expires_at) if expires_at else None),
    )


def update_session_heartbeat(session_id: int) -> None:
    execute(
        "UPDATE access_sessions SET last_heartbeat_at = ? WHERE id = ?",
        (isoformat(utcnow()), session_id),
    )


def revoke_session(session_id: int, reason: str) -> None:
    execute(
        """
        UPDATE access_sessions
        SET revoked_at = ?, revoke_reason = ?
        WHERE id = ? AND revoked_at IS NULL
        """,
        (isoformat(utcnow()), reason, session_id),
    )


def create_admin_session(session_token_hash: str, expires_at: datetime) -> int:
    now = isoformat(utcnow())
    return execute(
        """
        INSERT INTO admin_sessions(session_token_hash, created_at, last_seen_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (session_token_hash, now, now, isoformat(expires_at)),
    )


def get_admin_session_by_hash(session_token_hash: str) -> dict[str, Any] | None:
    return fetchone("SELECT * FROM admin_sessions WHERE session_token_hash = ?", (session_token_hash,))


def update_admin_session_seen(session_id: int) -> None:
    execute(
        "UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?",
        (isoformat(utcnow()), session_id),
    )


def revoke_admin_session(session_id: int) -> None:
    execute(
        "UPDATE admin_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        (isoformat(utcnow()), session_id),
    )


def _ensure_metric_day(conn: DbConnection, day: str) -> None:
    now = isoformat(utcnow())
    row = conn.execute("SELECT day FROM admin_daily_metrics WHERE day = ?", (day,)).fetchone()
    if row:
        return
    conn.execute(
        """
        INSERT INTO admin_daily_metrics(day, created_at, updated_at)
        VALUES (?, ?, ?)
        """,
        (day, now, now),
    )


def increment_daily_metric(field: str, amount: int = 1, *, day: str | None = None) -> None:
    allowed = {"page_views", "unique_visitors", "room_tokens", "ws_connections", "chat_messages", "control_messages"}
    if field not in allowed:
        raise ValueError("invalid metric field")
    metric_day = day or utcnow().date().isoformat()
    with db() as conn:
        _ensure_metric_day(conn, metric_day)
        conn.execute(
            f"UPDATE admin_daily_metrics SET {field} = {field} + ?, updated_at = ? WHERE day = ?",
            (int(amount), isoformat(utcnow()), metric_day),
        )


def remember_daily_visitor(day: str, visitor_hash: str) -> bool:
    with db() as conn:
        _ensure_metric_day(conn, day)
        exists = conn.execute(
            "SELECT 1 FROM admin_visit_seen WHERE day = ? AND visitor_hash = ?",
            (day, visitor_hash),
        ).fetchone()
        if exists:
            return False
        conn.execute(
            "INSERT INTO admin_visit_seen(day, visitor_hash, created_at) VALUES (?, ?, ?)",
            (day, visitor_hash, isoformat(utcnow())),
        )
        conn.execute(
            """
            UPDATE admin_daily_metrics
            SET unique_visitors = unique_visitors + 1, updated_at = ?
            WHERE day = ?
            """,
            (isoformat(utcnow()), day),
        )
        return True


def latest_audit_time(account_id: int, event_type: str) -> datetime | None:
    row = fetchone(
        """
        SELECT created_at FROM audit_events
        WHERE account_id = ? AND event_type = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (account_id, event_type),
    )
    return parse_datetime(row["created_at"]) if row else None


def get_order(order_id: int) -> dict[str, Any] | None:
    return fetchone("SELECT * FROM payment_orders WHERE id = ?", (order_id,))


def get_order_for_secret(order_id: int, order_secret_hash: str) -> dict[str, Any] | None:
    return fetchone(
        "SELECT * FROM payment_orders WHERE id = ? AND order_secret_hash = ?",
        (order_id, order_secret_hash),
    )


def pending_orders() -> list[dict[str, Any]]:
    return fetchall("SELECT * FROM payment_orders WHERE status = 'pending' ORDER BY created_at ASC")


def confirmed_unswept_orders() -> list[dict[str, Any]]:
    return fetchall(
        """
        SELECT po.*
        FROM payment_orders po
        WHERE po.status IN ('confirmed', 'swept')
          AND po.confirmed_at IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM sweeps s
            WHERE s.payment_order_id = po.id
              AND s.status = 'swept'
          )
        ORDER BY po.confirmed_at ASC
        """
    )


def has_successful_sweep(payment_order_id: int) -> bool:
    row = fetchone(
        """
        SELECT id FROM sweeps
        WHERE payment_order_id = ? AND status = 'swept'
        LIMIT 1
        """,
        (payment_order_id,),
    )
    return row is not None


def create_sweep(
    *,
    payment_order_id: int,
    deposit_public_key: str,
    cold_wallet_public_key: str,
    balance_before_lamports: int,
    fee_lamports: int,
    amount_sent_lamports: int,
    balance_after_lamports: int | None,
    sweep_signature: str | None,
    status: str,
    error: str | None = None,
) -> int:
    now = utcnow()
    return execute(
        """
        INSERT INTO sweeps(
          payment_order_id, deposit_public_key, cold_wallet_public_key,
          balance_before_lamports, fee_lamports, amount_sent_lamports,
          balance_after_lamports, sweep_signature, status, error, created_at, swept_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payment_order_id,
            deposit_public_key,
            cold_wallet_public_key,
            balance_before_lamports,
            fee_lamports,
            amount_sent_lamports,
            balance_after_lamports,
            sweep_signature,
            status,
            error,
            isoformat(now),
            isoformat(now) if status == "swept" else None,
        ),
    )
