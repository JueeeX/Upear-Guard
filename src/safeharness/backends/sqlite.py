"""SQLite persistence for audit records and single-use capability state."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from safeharness.backends._audit import (
    agent_audit_row,
    gateway_audit_row,
    normalize_time,
    timestamp_text,
)
from safeharness.ports import AuditRecord, GatewayAuditRecord


_SCHEMA_VERSION = 1


class SQLiteCapabilityReplayStore:
    """Atomic replay protection that survives process restarts.

    SQLite is a single-node reference backend. Multiple gateway processes may
    share the same local database file, but a network filesystem is not a
    supported substitute for a distributed consistency backend.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout: float = 5.0,
        now=None,
    ) -> None:
        self.path = _database_path(path)
        self.busy_timeout = _positive_timeout(busy_timeout)
        self._now = now or _utc_now
        _initialize_database(self.path, self.busy_timeout)

    async def consume(self, token_id: str, expires_at: datetime) -> bool:
        if not isinstance(token_id, str) or not token_id:
            raise ValueError("token_id must not be empty")
        expiry = normalize_time(expires_at)
        now = normalize_time(self._now())
        if expiry <= now:
            return False
        return await asyncio.to_thread(self._consume, token_id, expiry, now)

    def _consume(self, token_id: str, expiry: datetime, now: datetime) -> bool:
        connection = _connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM capability_replay WHERE expires_at <= ?",
                (timestamp_text(now),),
            )
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO capability_replay
                    (token_id, consumed_at, expires_at)
                VALUES (?, ?, ?)
                """,
                (token_id, timestamp_text(now), timestamp_text(expiry)),
            )
            connection.commit()
            return cursor.rowcount == 1
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def purge_expired(self) -> int:
        return await asyncio.to_thread(self._purge_expired)

    async def health(self) -> bool:
        return await asyncio.to_thread(_database_writable, self.path, self.busy_timeout)

    def _purge_expired(self) -> int:
        connection = _connect(self.path, self.busy_timeout)
        try:
            cursor = connection.execute(
                "DELETE FROM capability_replay WHERE expires_at <= ?",
                (timestamp_text(normalize_time(self._now())),),
            )
            connection.commit()
            return cursor.rowcount
        finally:
            connection.close()


class SQLiteEnforcementReceiptReplayStore(SQLiteCapabilityReplayStore):
    """Persistent receipt replay protection using an independent table."""

    def _consume(self, token_id: str, expiry: datetime, now: datetime) -> bool:
        connection = _connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM enforcement_receipt_replay WHERE expires_at <= ?",
                (timestamp_text(now),),
            )
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO enforcement_receipt_replay
                    (receipt_id, consumed_at, expires_at)
                VALUES (?, ?, ?)
                """,
                (token_id, timestamp_text(now), timestamp_text(expiry)),
            )
            connection.commit()
            return cursor.rowcount == 1
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _purge_expired(self) -> int:
        connection = _connect(self.path, self.busy_timeout)
        try:
            cursor = connection.execute(
                "DELETE FROM enforcement_receipt_replay WHERE expires_at <= ?",
                (timestamp_text(normalize_time(self._now())),),
            )
            connection.commit()
            return cursor.rowcount
        finally:
            connection.close()

class SQLiteAuditSink:
    """Append-only structured audit sink for Agent and gateway records."""

    def __init__(self, path: str | Path, *, busy_timeout: float = 5.0) -> None:
        self.path = _database_path(path)
        self.busy_timeout = _positive_timeout(busy_timeout)
        _initialize_database(self.path, self.busy_timeout)

    async def write(self, record: AuditRecord) -> None:
        row = agent_audit_row(record)
        await asyncio.to_thread(self._insert, row)

    async def write_gateway(self, record: GatewayAuditRecord) -> None:
        row = gateway_audit_row(record)
        await asyncio.to_thread(self._insert, row)

    async def health(self) -> bool:
        return await asyncio.to_thread(_database_writable, self.path, self.busy_timeout)

    def _insert(self, row: Mapping[str, Any]) -> None:
        connection = _connect(self.path, self.busy_timeout)
        try:
            connection.execute(
                """
                INSERT INTO audit_records (
                    record_id, source, record_type, action, outcome, occurred_at,
                    tenant_id, agent_id, session_id, run_id, trace_id, event_id,
                    sequence, tool_name, tool_version, tool_integrity_digest,
                    invocation_digest, capability_fingerprint, decision_id,
                    receipt_id, disposition, reason_code, request_id, payload_json
                ) VALUES (
                    :record_id, :source, :record_type, :action, :outcome,
                    :occurred_at, :tenant_id, :agent_id, :session_id, :run_id,
                    :trace_id, :event_id, :sequence, :tool_name, :tool_version,
                    :tool_integrity_digest, :invocation_digest,
                    :capability_fingerprint, :decision_id, :receipt_id,
                    :disposition, :reason_code, :request_id, :payload_json
                )
                """,
                row,
            )
            connection.commit()
        finally:
            connection.close()

    async def query(
        self,
        *,
        tenant_id: str | None = None,
        session_id: str | None = None,
        source: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        where, values, limit = _audit_query(
            tenant_id=tenant_id,
            session_id=session_id,
            source=source,
            action=action,
            limit=limit,
        )
        return await asyncio.to_thread(self._query, where, values, limit)

    def _query(
        self, where: str, values: list[Any], limit: int
    ) -> list[dict[str, Any]]:
        connection = _connect(self.path, self.busy_timeout)
        try:
            return _query_audit_rows(connection, where, values, limit)
        finally:
            connection.close()


class SQLiteAuditReader:
    """Read an existing SafeHarness audit database without mutating it."""

    def __init__(self, path: str | Path, *, busy_timeout: float = 5.0) -> None:
        self.path = _existing_database_path(path)
        self.busy_timeout = _positive_timeout(busy_timeout)

    async def query(
        self,
        *,
        tenant_id: str | None = None,
        session_id: str | None = None,
        source: str | None = None,
        action: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        where, values, limit = _audit_query(
            tenant_id=tenant_id,
            session_id=session_id,
            source=source,
            action=action,
            limit=limit,
        )
        return await asyncio.to_thread(self._query, where, values, limit)

    def _query(
        self, where: str, values: list[Any], limit: int
    ) -> list[dict[str, Any]]:
        connection = _connect_read_only(self.path, self.busy_timeout)
        try:
            _validate_schema(connection)
            return _query_audit_rows(connection, where, values, limit)
        finally:
            connection.close()


def _initialize_database(path: str, busy_timeout: float) -> None:
    connection = _connect(path, busy_timeout)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS safeharness_schema (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS capability_replay (
                token_id TEXT PRIMARY KEY,
                consumed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_capability_replay_expiry
                ON capability_replay(expires_at);

            CREATE TABLE IF NOT EXISTS enforcement_receipt_replay (
                receipt_id TEXT PRIMARY KEY,
                consumed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_enforcement_receipt_replay_expiry
                ON enforcement_receipt_replay(expires_at);

            CREATE TABLE IF NOT EXISTS backend_health_probe (
                probe_id INTEGER PRIMARY KEY CHECK(probe_id = 1)
            );

            CREATE TABLE IF NOT EXISTS audit_records (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL,
                source TEXT NOT NULL,
                record_type TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                tool_version TEXT NOT NULL,
                tool_integrity_digest TEXT NOT NULL,
                invocation_digest TEXT NOT NULL,
                capability_fingerprint TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                request_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE(source, record_id)
            );

            CREATE INDEX IF NOT EXISTS idx_audit_tenant_time
                ON audit_records(tenant_id, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_session_sequence
                ON audit_records(session_id, sequence);
            CREATE INDEX IF NOT EXISTS idx_audit_gateway_tool
                ON audit_records(source, tool_name, occurred_at DESC);

            CREATE TRIGGER IF NOT EXISTS audit_records_no_update
            BEFORE UPDATE ON audit_records
            BEGIN
                SELECT RAISE(ABORT, 'SafeHarness audit records are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_records_no_delete
            BEFORE DELETE ON audit_records
            BEGIN
                SELECT RAISE(ABORT, 'SafeHarness audit records are append-only');
            END;
            """
        )
        connection.execute(
            """
            INSERT INTO safeharness_schema(component, version)
            VALUES ('sqlite_backend', ?)
            ON CONFLICT(component) DO NOTHING
            """,
            (_SCHEMA_VERSION,),
        )
        version = connection.execute(
            "SELECT version FROM safeharness_schema WHERE component = 'sqlite_backend'"
        ).fetchone()[0]
        if version != _SCHEMA_VERSION:
            raise RuntimeError(
                f"unsupported SafeHarness SQLite schema version: {version}"
            )
        connection.commit()
    finally:
        connection.close()


def _connect(path: str, busy_timeout: float) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path,
        timeout=busy_timeout,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout * 1000)}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


def _connect_read_only(path: str, busy_timeout: float) -> sqlite3.Connection:
    uri = f"{Path(path).as_uri()}?mode=ro"
    connection = sqlite3.connect(
        uri,
        uri=True,
        timeout=busy_timeout,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout * 1000)}")
    connection.execute("PRAGMA query_only = ON")
    return connection


def _database_writable(path: str, busy_timeout: float) -> bool:
    try:
        connection = _connect(path, busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR REPLACE INTO backend_health_probe(probe_id) VALUES (1)"
            )
            connection.rollback()
        finally:
            connection.close()
    except Exception:
        return False
    return True


def _database_path(value: str | Path) -> str:
    path = Path(value).expanduser()
    if str(path) == ":memory:":
        raise ValueError("use a filesystem path for persistent SQLite backends")
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path.resolve())


def _existing_database_path(value: str | Path) -> str:
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"SafeHarness audit database does not exist: {path}")
    return str(path)


def _audit_query(
    *,
    tenant_id: str | None,
    session_id: str | None,
    source: str | None,
    action: str | None,
    limit: int,
) -> tuple[str, list[Any], int]:
    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    filters = []
    values: list[Any] = []
    for column, value in (
        ("tenant_id", tenant_id),
        ("session_id", session_id),
        ("source", source),
        ("action", action),
    ):
        if value is not None:
            filters.append(f"{column} = ?")
            values.append(value)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    return where, values, int(limit)


def _query_audit_rows(
    connection: sqlite3.Connection,
    where: str,
    values: list[Any],
    limit: int,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        f"""
        SELECT * FROM audit_records
        {where}
        ORDER BY audit_id DESC
        LIMIT ?
        """,
        [*values, limit],
    ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        output.append(item)
    return output


def _validate_schema(connection: sqlite3.Connection) -> None:
    try:
        row = connection.execute(
            "SELECT version FROM safeharness_schema WHERE component = 'sqlite_backend'"
        ).fetchone()
    except sqlite3.DatabaseError as exc:
        raise RuntimeError("not a SafeHarness SQLite audit database") from exc
    if row is None or row[0] != _SCHEMA_VERSION:
        version = None if row is None else row[0]
        raise RuntimeError(f"unsupported SafeHarness SQLite schema version: {version}")


def _positive_timeout(value: float) -> float:
    timeout = float(value)
    if timeout <= 0:
        raise ValueError("busy_timeout must be positive")
    return timeout


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
