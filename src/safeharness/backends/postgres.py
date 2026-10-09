"""PostgreSQL append-only audit backend for production deployments."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping
from contextlib import closing
from typing import Any

from safeharness.backends._audit import AUDIT_COLUMNS, agent_audit_row, gateway_audit_row
from safeharness.ports import AuditRecord, GatewayAuditRecord


_SCHEMA_VERSION = 1
_DEFAULT_TABLE = "safeharness_audit_records"


class PostgreSQLAuditSink:
    """Persist sanitized audit rows in an append-only PostgreSQL table."""

    def __init__(
        self,
        dsn: str | None = None,
        *,
        connect: Callable[[], Any] | None = None,
        table: str = _DEFAULT_TABLE,
        initialize: bool = False,
    ) -> None:
        if (dsn is None) == (connect is None):
            raise ValueError("provide exactly one PostgreSQL DSN or connection factory")
        self.table = _identifier(table)
        self._connect = connect or _psycopg_connect(dsn or "")
        if initialize:
            self._initialize()

    def initialize_schema(
        self,
        *,
        runtime_role: str | None = None,
        reader_role: str | None = None,
    ) -> None:
        """Create the schema and optionally install least-privilege role grants."""

        self._initialize(runtime_role=runtime_role, reader_role=reader_role)

    async def write(self, record: AuditRecord) -> None:
        await asyncio.to_thread(self._insert, agent_audit_row(record))

    async def write_gateway(self, record: GatewayAuditRecord) -> None:
        await asyncio.to_thread(self._insert, gateway_audit_row(record))

    async def health(self) -> bool:
        return await asyncio.to_thread(self._health)

    def _initialize(
        self,
        *,
        runtime_role: str | None = None,
        reader_role: str | None = None,
    ) -> None:
        runtime = _role_identifier(runtime_role) if runtime_role else None
        reader = _role_identifier(reader_role) if reader_role else None
        if runtime is not None and runtime == reader:
            raise ValueError("PostgreSQL runtime and reader roles must be different")
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    for statement in _schema_statements(self.table):
                        cursor.execute(statement)
                    cursor.execute(
                        """
                        INSERT INTO safeharness_schema(component, version)
                        VALUES (%s, %s)
                        ON CONFLICT(component) DO NOTHING
                        """,
                        ("postgres_audit", _SCHEMA_VERSION),
                    )
                    cursor.execute(
                        "SELECT version FROM safeharness_schema WHERE component = %s",
                        ("postgres_audit",),
                    )
                    row = cursor.fetchone()
                    if row is None or row[0] != _SCHEMA_VERSION:
                        version = None if row is None else row[0]
                        raise RuntimeError(
                            f"unsupported SafeHarness PostgreSQL schema version: {version}"
                        )
                    for statement in _role_grant_statements(
                        self.table,
                        runtime_role=runtime,
                        reader_role=reader,
                    ):
                        cursor.execute(statement)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _insert(self, row: Mapping[str, Any]) -> None:
        values = tuple(row[column] for column in AUDIT_COLUMNS)
        placeholders = ["%s"] * len(AUDIT_COLUMNS)
        placeholders[AUDIT_COLUMNS.index("occurred_at")] = "CAST(%s AS timestamptz)"
        placeholders[AUDIT_COLUMNS.index("payload_json")] = "CAST(%s AS jsonb)"
        columns = ", ".join(AUDIT_COLUMNS)
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    cursor.execute(
                        f"INSERT INTO {self.table} ({columns}) "
                        f"VALUES ({', '.join(placeholders)})",
                        values,
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _health(self) -> bool:
        try:
            with closing(self._connect()) as connection:
                with closing(connection.cursor()) as cursor:
                    cursor.execute(
                        """
                        SELECT EXISTS (
                            SELECT 1 FROM safeharness_schema
                            WHERE component = %s AND version = %s
                        )
                        AND to_regclass(%s) IS NOT NULL
                        AND has_table_privilege(current_user, %s, 'INSERT')
                        """,
                        (
                            "postgres_audit",
                            _SCHEMA_VERSION,
                            self.table,
                            self.table,
                        ),
                    )
                    row = cursor.fetchone()
                connection.rollback()
        except Exception:
            return False
        return row is not None and row[0] is True


def _psycopg_connect(dsn: str) -> Callable[[], Any]:
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL audit requires: pip install 'safeharness[production]'"
        ) from exc

    def connect() -> Any:
        return psycopg.connect(dsn, autocommit=False)

    return connect


def _identifier(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,39}", value) is None:
        raise ValueError("PostgreSQL table must be an unqualified identifier")
    return value


def _role_identifier(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,62}", value
    ) is None:
        raise ValueError("PostgreSQL role must be an unquoted identifier")
    return value


def _role_grant_statements(
    table: str,
    *,
    runtime_role: str | None,
    reader_role: str | None,
) -> tuple[str, ...]:
    if runtime_role is None and reader_role is None:
        return ()
    sequence = f"{table}_audit_id_seq"
    statements = [
        f"REVOKE ALL ON TABLE {table} FROM PUBLIC",
        "REVOKE ALL ON TABLE safeharness_schema FROM PUBLIC",
        f"REVOKE ALL ON SEQUENCE {sequence} FROM PUBLIC",
    ]
    if runtime_role is not None:
        statements.extend(
            (
                f"GRANT SELECT ON TABLE safeharness_schema TO {runtime_role}",
                f"GRANT INSERT ON TABLE {table} TO {runtime_role}",
                f"GRANT USAGE ON SEQUENCE {sequence} TO {runtime_role}",
                f"REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
                f"ON TABLE {table} FROM {runtime_role}",
                f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
                f"ON TABLE safeharness_schema FROM {runtime_role}",
            )
        )
    if reader_role is not None:
        statements.extend(
            (
                f"GRANT SELECT ON TABLE safeharness_schema, {table} TO {reader_role}",
                f"GRANT SELECT ON SEQUENCE {sequence} TO {reader_role}",
                f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
                f"ON TABLE safeharness_schema, {table} FROM {reader_role}",
            )
        )
    return tuple(statements)


def _schema_statements(table: str) -> tuple[str, ...]:
    tenant_index = f"idx_{table}_tenant_time"
    session_index = f"idx_{table}_session_sequence"
    gateway_index = f"idx_{table}_gateway_tool"
    return (
        """
        CREATE TABLE IF NOT EXISTS safeharness_schema (
            component TEXT PRIMARY KEY,
            version INTEGER NOT NULL
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {table} (
            audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            record_id TEXT NOT NULL,
            source TEXT NOT NULL,
            record_type TEXT NOT NULL,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            occurred_at TIMESTAMPTZ NOT NULL,
            tenant_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            trace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            sequence BIGINT NOT NULL,
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
            payload_json JSONB NOT NULL,
            UNIQUE(source, record_id)
        )
        """,
        f"CREATE INDEX IF NOT EXISTS {tenant_index} "
        f"ON {table}(tenant_id, occurred_at DESC)",
        f"CREATE INDEX IF NOT EXISTS {session_index} "
        f"ON {table}(session_id, sequence)",
        f"CREATE INDEX IF NOT EXISTS {gateway_index} "
        f"ON {table}(source, tool_name, occurred_at DESC)",
        """
        CREATE OR REPLACE FUNCTION safeharness_reject_audit_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'SafeHarness audit records are append-only';
        END;
        $$
        """,
        f"DROP TRIGGER IF EXISTS safeharness_audit_no_update ON {table}",
        f"""
        CREATE TRIGGER safeharness_audit_no_update
            BEFORE UPDATE ON {table}
            FOR EACH ROW EXECUTE FUNCTION safeharness_reject_audit_mutation()
        """,
        f"DROP TRIGGER IF EXISTS safeharness_audit_no_delete ON {table}",
        f"""
        CREATE TRIGGER safeharness_audit_no_delete
            BEFORE DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION safeharness_reject_audit_mutation()
        """,
    )
