"""Shared PostgreSQL communication state for horizontally scaled gateways.

The communication protocol keeps replay consumption, delegation counters,
mailbox insertion, and the corresponding audit row in one database
transaction.  Message leasing uses ``FOR UPDATE SKIP LOCKED`` so two gateway
replicas can consume a mailbox concurrently without claiming the same row.
The dependency is optional; importing this module does not import psycopg.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import re
from collections.abc import Callable, Mapping
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from safeharness.api._mapping import json_safe
from safeharness.communication.models import (
    CommunicationAuditRecord,
    InterAgentMessage,
    MessageKind,
    MessageLease,
)
from safeharness.communication.maintenance import AuditCursor
from safeharness.communication.store import (
    CommunicationStoreResult,
    _ack_audit,
    _audit_with_outcome,
    _fingerprint,
    _normalize_time,
)
from safeharness.runtime.redaction import minimize_value


_SCHEMA_VERSION = 1
_SCHEMA_COMPONENT = "agent_communication_gateway"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
_AUDIT_COLUMNS = (
    "record_id",
    "action",
    "outcome",
    "occurred_at",
    "tenant_id",
    "sender_agent_id",
    "recipient_agent_id",
    "message_fingerprint",
    "message_kind",
    "content_sha256",
    "content_length",
    "delegation_fingerprint",
    "reason_code",
    "request_id",
    "details_json",
)
_AUDIT_COLUMNS_SQL = ", ".join(_AUDIT_COLUMNS)

_MESSAGE_COLUMNS = (
    "message_id",
    "message_fingerprint",
    "tenant_id",
    "sender_agent_id",
    "recipient_agent_id",
    "session_id",
    "run_id",
    "trace_id",
    "message_kind",
    "content",
    "content_sha256",
    "correlation_id",
    "parent_message_id",
    "delegation_id",
    "requested_capabilities_json",
    "metadata_json",
    "created_at",
    "expires_at",
    "state",
    "lease_id",
    "lease_until",
    "delivery_attempt",
    "acknowledged_at",
)


class PostgreSQLCommunicationStore:
    """Shared mailbox/replay state backed by PostgreSQL.

    ``connect`` is a DB-API connection factory used by tests and by callers
    that already manage a psycopg pool.  The normal ``dsn`` path creates a
    short-lived psycopg connection per operation; deployments can inject a
    pool-backed factory without changing the gateway protocol.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        connect: Callable[[], Any] | None = None,
        initialize: bool = False,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if (dsn is None) == (connect is None):
            raise ValueError("provide exactly one PostgreSQL DSN or connection factory")
        self._connect = connect or _psycopg_connect(dsn or "")
        self._now = now or (lambda: datetime.now(timezone.utc))
        if initialize:
            self.initialize_schema()

    def initialize_schema(
        self,
        *,
        runtime_role: str | None = None,
        reader_role: str | None = None,
        retention_role: str | None = None,
    ) -> None:
        """Create tables, append-only audit triggers, and least-privilege roles."""

        roles = _validate_roles(runtime_role, reader_role, retention_role)
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    for statement in _schema_statements():
                        cursor.execute(statement)
                    cursor.execute(
                        """
                        INSERT INTO safeharness_communication_schema(component, version)
                        VALUES (%s, %s)
                        ON CONFLICT(component) DO NOTHING
                        """,
                        (_SCHEMA_COMPONENT, _SCHEMA_VERSION),
                    )
                    cursor.execute(
                        """
                        SELECT version,
                               to_regclass('safeharness_communication_replay') IS NOT NULL,
                               to_regclass('safeharness_communication_delegation_usage') IS NOT NULL,
                               to_regclass('safeharness_communication_messages') IS NOT NULL,
                               to_regclass('safeharness_communication_audit') IS NOT NULL,
                               to_regclass('safeharness_communication_health') IS NOT NULL
                        FROM safeharness_communication_schema
                        WHERE component = %s
                        """,
                        (_SCHEMA_COMPONENT,),
                    )
                    row = cursor.fetchone()
                    if (
                        row is None
                        or int(row[0]) != _SCHEMA_VERSION
                        or any(value is not True for value in row[1:])
                    ):
                        found = None if row is None else row[0]
                        raise RuntimeError(
                            "unsupported SafeHarness communication schema version: "
                            f"expected {_SCHEMA_VERSION}, found {found}"
                        )
                    for statement in _role_grants(*roles):
                        cursor.execute(statement)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    async def enqueue(
        self,
        message: InterAgentMessage,
        audit: CommunicationAuditRecord,
        *,
        delegation_max_messages: int | None = None,
    ) -> CommunicationStoreResult:
        if delegation_max_messages is not None and not 1 <= delegation_max_messages <= 10_000:
            raise ValueError("delegation_max_messages must be between 1 and 10000")
        return await asyncio.to_thread(
            self._enqueue,
            message,
            audit,
            delegation_max_messages,
        )

    def _enqueue(
        self,
        message: InterAgentMessage,
        audit: CommunicationAuditRecord,
        delegation_max_messages: int | None,
    ) -> CommunicationStoreResult:
        now = _normalize_time(self._now())
        expires_at = _normalize_time(message.expires_at)
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    if expires_at <= now:
                        denial = _audit_with_outcome(
                            audit,
                            outcome="denied",
                            reason_code="communication_message_expired",
                        )
                        _insert_audit(cursor, denial)
                        connection.commit()
                        return CommunicationStoreResult(
                            False,
                            "communication_message_expired",
                            "The communication message has expired.",
                        )

                    # Reclaim an expired fingerprint atomically.  This avoids a
                    # DELETE privilege for the gateway runtime role.
                    cursor.execute(
                        """
                        INSERT INTO safeharness_communication_replay (
                            message_fingerprint, consumed_at, expires_at
                        ) VALUES (%s, CAST(%s AS timestamptz), CAST(%s AS timestamptz))
                        ON CONFLICT(message_fingerprint) DO UPDATE SET
                            consumed_at = EXCLUDED.consumed_at,
                            expires_at = EXCLUDED.expires_at
                        WHERE safeharness_communication_replay.expires_at
                              <= CAST(%s AS timestamptz)
                        RETURNING message_fingerprint
                        """,
                        (
                            message.message_fingerprint,
                            _timestamp(now),
                            _timestamp(expires_at),
                            _timestamp(now),
                        ),
                    )
                    if cursor.fetchone() is None:
                        denial = _audit_with_outcome(
                            audit,
                            outcome="denied",
                            reason_code="communication_message_replayed",
                        )
                        _insert_audit(cursor, denial)
                        connection.commit()
                        return CommunicationStoreResult(
                            False,
                            "communication_message_replayed",
                            "The communication message ID was already used.",
                        )

                    if delegation_max_messages is not None:
                        cursor.execute(
                            """
                            INSERT INTO safeharness_communication_delegation_usage (
                                tenant_id, delegation_id, used_messages, updated_at
                            ) VALUES (%s, %s, 1, CAST(%s AS timestamptz))
                            ON CONFLICT(tenant_id, delegation_id) DO UPDATE SET
                                used_messages =
                                    safeharness_communication_delegation_usage.used_messages + 1,
                                updated_at = EXCLUDED.updated_at
                            WHERE safeharness_communication_delegation_usage.used_messages
                                  < %s
                            RETURNING used_messages
                            """,
                            (
                                message.tenant_id,
                                message.delegation_id,
                                _timestamp(now),
                                delegation_max_messages,
                            ),
                        )
                        if cursor.fetchone() is None:
                            denial = _audit_with_outcome(
                                audit,
                                outcome="denied",
                                reason_code="delegation_message_limit_exceeded",
                            )
                            _insert_audit(cursor, denial)
                            connection.commit()
                            return CommunicationStoreResult(
                                False,
                                "delegation_message_limit_exceeded",
                                "The delegation message limit has been exhausted.",
                            )

                    cursor.execute(
                        """
                        INSERT INTO safeharness_communication_messages (
                            message_id, message_fingerprint, tenant_id, sender_agent_id,
                            recipient_agent_id, session_id, run_id, trace_id, message_kind,
                            content, content_sha256, correlation_id, parent_message_id,
                            delegation_id, requested_capabilities_json, metadata_json,
                            created_at, expires_at, state, lease_id, lease_until,
                            delivery_attempt, acknowledged_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            CAST(%s AS jsonb), CAST(%s AS jsonb),
                            CAST(%s AS timestamptz), CAST(%s AS timestamptz),
                            'pending', '', NULL, 0, NULL
                        )
                        """,
                        _message_values(message),
                    )
                    _insert_audit(cursor, audit)
                connection.commit()
                return CommunicationStoreResult(True)
            except Exception:
                connection.rollback()
                raise

    async def append_audit(self, record: CommunicationAuditRecord) -> None:
        await asyncio.to_thread(self._append_audit, record)

    def _append_audit(self, record: CommunicationAuditRecord) -> None:
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    _insert_audit(cursor, record)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    async def lease_messages(
        self,
        tenant_id: str,
        recipient_agent_id: str,
        *,
        limit: int,
        lease_duration: timedelta,
        request_id: str = "",
    ) -> tuple[MessageLease, ...]:
        _validate_lease_parameters(limit, lease_duration)
        return await asyncio.to_thread(
            self._lease_messages,
            tenant_id,
            recipient_agent_id,
            limit,
            lease_duration,
            request_id,
        )

    def _lease_messages(
        self,
        tenant_id: str,
        recipient_agent_id: str,
        limit: int,
        lease_duration: timedelta,
        request_id: str,
    ) -> tuple[MessageLease, ...]:
        now = _normalize_time(self._now())
        lease_until = now + lease_duration
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    cursor.execute(
                        """
                        SELECT message_id, message_fingerprint, tenant_id,
                               sender_agent_id, recipient_agent_id, session_id, run_id,
                               trace_id, message_kind, content, content_sha256,
                               correlation_id, parent_message_id, delegation_id,
                               requested_capabilities_json, metadata_json, created_at,
                               expires_at, state, lease_id, lease_until,
                               delivery_attempt, acknowledged_at
                        FROM safeharness_communication_messages
                        WHERE tenant_id = %s AND recipient_agent_id = %s
                          AND expires_at > CAST(%s AS timestamptz)
                          AND (
                              state = 'pending'
                              OR (state = 'leased' AND lease_until <= CAST(%s AS timestamptz))
                          )
                        ORDER BY created_at, message_id
                        LIMIT %s
                        FOR UPDATE SKIP LOCKED
                        """,
                        (
                            tenant_id,
                            recipient_agent_id,
                            _timestamp(now),
                            _timestamp(now),
                            limit,
                        ),
                    )
                    rows = cursor.fetchall()
                    leases: list[MessageLease] = []
                    for raw_row in rows:
                        row = _row_mapping(raw_row)
                        lease_id = str(uuid4())
                        attempt = int(row["delivery_attempt"]) + 1
                        cursor.execute(
                            """
                            UPDATE safeharness_communication_messages
                            SET state = 'leased', lease_id = %s,
                                lease_until = CAST(%s AS timestamptz),
                                delivery_attempt = %s
                            WHERE message_id = %s
                            """,
                            (lease_id, _timestamp(lease_until), attempt, row["message_id"]),
                        )
                        message = _message_from_row(row)
                        _insert_audit(
                            cursor,
                            CommunicationAuditRecord(
                                action="message_receive",
                                outcome="leased",
                                tenant_id=tenant_id,
                                sender_agent_id=message.sender_agent_id,
                                recipient_agent_id=recipient_agent_id,
                                message_fingerprint=message.message_fingerprint,
                                message_kind=message.kind.value,
                                content_sha256=message.content_sha256,
                                content_length=len(message.content),
                                delegation_fingerprint=_fingerprint(message.delegation_id),
                                request_id=request_id,
                                details={"delivery_attempt": attempt},
                            ),
                        )
                        leases.append(MessageLease(message, lease_id, lease_until, attempt))
                connection.commit()
                return tuple(leases)
            except Exception:
                connection.rollback()
                raise

    async def acknowledge(
        self,
        tenant_id: str,
        recipient_agent_id: str,
        message_id: str,
        lease_id: str,
        *,
        request_id: str = "",
    ) -> CommunicationStoreResult:
        return await asyncio.to_thread(
            self._acknowledge,
            tenant_id,
            recipient_agent_id,
            message_id,
            lease_id,
            request_id,
        )

    def _acknowledge(
        self,
        tenant_id: str,
        recipient_agent_id: str,
        message_id: str,
        lease_id: str,
        request_id: str,
    ) -> CommunicationStoreResult:
        now = _normalize_time(self._now())
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    cursor.execute(
                        """
                        SELECT message_id, message_fingerprint, tenant_id,
                               sender_agent_id, recipient_agent_id, session_id, run_id,
                               trace_id, message_kind, content, content_sha256,
                               correlation_id, parent_message_id, delegation_id,
                               requested_capabilities_json, metadata_json, created_at,
                               expires_at, state, lease_id, lease_until,
                               delivery_attempt, acknowledged_at
                        FROM safeharness_communication_messages
                        WHERE tenant_id = %s AND recipient_agent_id = %s
                          AND message_id = %s
                        FOR UPDATE
                        """,
                        (tenant_id, recipient_agent_id, message_id),
                    )
                    raw_row = cursor.fetchone()
                    row = None if raw_row is None else _row_mapping(raw_row)
                    if row is None:
                        _insert_audit(
                            cursor,
                            _ack_audit(
                                row=None,
                                tenant_id=tenant_id,
                                recipient_agent_id=recipient_agent_id,
                                message_id=message_id,
                                lease_id=lease_id,
                                outcome="denied",
                                reason_code="communication_message_not_found",
                                request_id=request_id,
                            ),
                        )
                        connection.commit()
                        return CommunicationStoreResult(
                            False,
                            "communication_message_not_found",
                            "The communication message does not exist.",
                        )
                    if not hmac.compare_digest(str(row["lease_id"]), lease_id):
                        _insert_audit(
                            cursor,
                            _ack_audit(
                                row=row,
                                tenant_id=tenant_id,
                                recipient_agent_id=recipient_agent_id,
                                message_id=message_id,
                                lease_id=lease_id,
                                outcome="denied",
                                reason_code="communication_lease_mismatch",
                                request_id=request_id,
                            ),
                        )
                        connection.commit()
                        return CommunicationStoreResult(
                            False,
                            "communication_lease_mismatch",
                            "The communication lease does not match.",
                        )
                    if row["state"] == "acknowledged":
                        _insert_audit(
                            cursor,
                            _ack_audit(
                                row=row,
                                tenant_id=tenant_id,
                                recipient_agent_id=recipient_agent_id,
                                message_id=message_id,
                                lease_id=lease_id,
                                outcome="idempotent",
                                reason_code="",
                                request_id=request_id,
                            ),
                        )
                        connection.commit()
                        return CommunicationStoreResult(True, idempotent=True)
                    lease_until = _parse_time(row["lease_until"])
                    if row["state"] != "leased" or lease_until <= now:
                        _insert_audit(
                            cursor,
                            _ack_audit(
                                row=row,
                                tenant_id=tenant_id,
                                recipient_agent_id=recipient_agent_id,
                                message_id=message_id,
                                lease_id=lease_id,
                                outcome="denied",
                                reason_code="communication_lease_expired",
                                request_id=request_id,
                            ),
                        )
                        connection.commit()
                        return CommunicationStoreResult(
                            False,
                            "communication_lease_expired",
                            "The communication lease has expired.",
                        )
                    cursor.execute(
                        """
                        UPDATE safeharness_communication_messages
                        SET state = 'acknowledged', acknowledged_at = CAST(%s AS timestamptz),
                            content = '', metadata_json = CAST('{}' AS jsonb),
                            requested_capabilities_json = CAST('[]' AS jsonb)
                        WHERE tenant_id = %s AND recipient_agent_id = %s
                          AND message_id = %s AND lease_id = %s
                        """,
                        (
                            _timestamp(now),
                            tenant_id,
                            recipient_agent_id,
                            message_id,
                            lease_id,
                        ),
                    )
                    _insert_audit(
                        cursor,
                        _ack_audit(
                            row=row,
                            tenant_id=tenant_id,
                            recipient_agent_id=recipient_agent_id,
                            message_id=message_id,
                            lease_id=lease_id,
                            outcome="acknowledged",
                            reason_code="",
                            request_id=request_id,
                        ),
                    )
                connection.commit()
                return CommunicationStoreResult(True)
            except Exception:
                connection.rollback()
                raise

    async def purge_expired(
        self,
        *,
        retention: timedelta = timedelta(days=7),
    ) -> int:
        """Delete mailbox and replay rows older than the retention window.

        Audit rows are append-only and are intentionally left for a separate
        archival/retention process.  Run this operation with the dedicated
        retention role granted by :meth:`initialize_schema`.
        """

        if not timedelta(hours=1) <= retention <= timedelta(days=90):
            raise ValueError("retention must be between 1 hour and 90 days")
        return await asyncio.to_thread(self._purge_expired, retention)

    def _purge_expired(self, retention: timedelta) -> int:
        now = _normalize_time(self._now())
        cutoff = now - retention
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    cursor.execute(
                        """
                        DELETE FROM safeharness_communication_messages
                        WHERE expires_at <= CAST(%s AS timestamptz)
                        """,
                        (_timestamp(cutoff),),
                    )
                    deleted = max(int(getattr(cursor, "rowcount", 0)), 0)
                    cursor.execute(
                        """
                        DELETE FROM safeharness_communication_replay
                        WHERE expires_at <= CAST(%s AS timestamptz)
                        """,
                        (_timestamp(cutoff),),
                    )
                connection.commit()
                return deleted
            except Exception:
                connection.rollback()
                raise

    async def health(self) -> bool:
        return await asyncio.to_thread(self._health)

    def _health(self) -> bool:
        try:
            with closing(self._connect()) as connection:
                with closing(connection.cursor()) as cursor:
                    cursor.execute(
                        """
                        SELECT version,
                               to_regclass('safeharness_communication_replay') IS NOT NULL,
                               to_regclass('safeharness_communication_delegation_usage') IS NOT NULL,
                               to_regclass('safeharness_communication_messages') IS NOT NULL,
                               to_regclass('safeharness_communication_audit') IS NOT NULL,
                               to_regclass('safeharness_communication_health') IS NOT NULL
                        FROM safeharness_communication_schema
                        WHERE component = %s
                        """,
                        (_SCHEMA_COMPONENT,),
                    )
                    row = cursor.fetchone()
                    if (
                        row is None
                        or int(row[0]) != _SCHEMA_VERSION
                        or any(value is not True for value in row[1:])
                    ):
                        connection.rollback()
                        return False
                    cursor.execute(
                        """
                        INSERT INTO safeharness_communication_health(probe_id, touched_at)
                        VALUES (1, CAST(%s AS timestamptz))
                        ON CONFLICT(probe_id) DO UPDATE SET touched_at = EXCLUDED.touched_at
                        """,
                        (_timestamp(_normalize_time(self._now())),),
                    )
                connection.rollback()
            return True
        except Exception:
            return False

    async def query_audit(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        return await asyncio.to_thread(self._query_audit, limit)

    def _query_audit(self, limit: int) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT record_id, action, outcome, occurred_at, tenant_id,
                           sender_agent_id, recipient_agent_id, message_fingerprint,
                           message_kind, content_sha256, content_length,
                           delegation_fingerprint, reason_code, request_id, details_json
                    FROM safeharness_communication_audit
                    ORDER BY occurred_at DESC, record_id DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
        return _audit_output(rows)

    async def scan_audit(
        self,
        *,
        after: AuditCursor | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        return await asyncio.to_thread(self._scan_audit, after, limit)

    def _scan_audit(
        self,
        after: AuditCursor | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            with closing(connection.cursor()) as cursor:
                if after is None:
                    cursor.execute(
                        f"""
                        SELECT {_AUDIT_COLUMNS_SQL}
                        FROM safeharness_communication_audit
                        ORDER BY occurred_at, record_id
                        LIMIT %s
                        """,
                        (limit,),
                    )
                else:
                    timestamp = _timestamp(after.occurred_at)
                    cursor.execute(
                        f"""
                        SELECT {_AUDIT_COLUMNS_SQL}
                        FROM safeharness_communication_audit
                        WHERE occurred_at > CAST(%s AS timestamptz)
                           OR (occurred_at = CAST(%s AS timestamptz) AND record_id > %s)
                        ORDER BY occurred_at, record_id
                        LIMIT %s
                        """,
                        (timestamp, timestamp, after.record_id, limit),
                    )
                rows = cursor.fetchall()
        return _audit_output(rows)


def _audit_output(rows: list[Any]) -> list[dict[str, Any]]:
    output = []
    for raw_row in rows:
        row = _row_mapping(raw_row, _AUDIT_COLUMNS)
        details = row["details_json"]
        if isinstance(details, str):
            details = json.loads(details)
        output.append(
            {
                **row,
                "occurred_at": _parse_time(row["occurred_at"]).isoformat(),
                "details": details,
            }
        )
        output[-1].pop("details_json", None)
    return output


def _schema_statements() -> tuple[str, ...]:
    return (
        """
        CREATE TABLE IF NOT EXISTS safeharness_communication_schema (
            component TEXT PRIMARY KEY,
            version INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS safeharness_communication_replay (
            message_fingerprint TEXT PRIMARY KEY,
            consumed_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_safeharness_communication_replay_expiry
            ON safeharness_communication_replay(expires_at)
        """,
        """
        CREATE TABLE IF NOT EXISTS safeharness_communication_delegation_usage (
            tenant_id TEXT NOT NULL,
            delegation_id TEXT NOT NULL,
            used_messages INTEGER NOT NULL CHECK(used_messages >= 0),
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(tenant_id, delegation_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS safeharness_communication_messages (
            message_id TEXT PRIMARY KEY,
            message_fingerprint TEXT NOT NULL UNIQUE,
            tenant_id TEXT NOT NULL,
            sender_agent_id TEXT NOT NULL,
            recipient_agent_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            trace_id TEXT NOT NULL,
            message_kind TEXT NOT NULL,
            content TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            parent_message_id TEXT NOT NULL,
            delegation_id TEXT NOT NULL,
            requested_capabilities_json JSONB NOT NULL,
            metadata_json JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending', 'leased', 'acknowledged')),
            lease_id TEXT NOT NULL,
            lease_until TIMESTAMPTZ,
            delivery_attempt INTEGER NOT NULL CHECK(delivery_attempt >= 0),
            acknowledged_at TIMESTAMPTZ
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_safeharness_communication_mailbox
            ON safeharness_communication_messages(
                tenant_id, recipient_agent_id, state, created_at
            )
        """,
        """
        CREATE TABLE IF NOT EXISTS safeharness_communication_audit (
            record_id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            occurred_at TIMESTAMPTZ NOT NULL,
            tenant_id TEXT NOT NULL,
            sender_agent_id TEXT NOT NULL,
            recipient_agent_id TEXT NOT NULL,
            message_fingerprint TEXT NOT NULL,
            message_kind TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            content_length INTEGER NOT NULL,
            delegation_fingerprint TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            request_id TEXT NOT NULL,
            details_json JSONB NOT NULL
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_safeharness_communication_audit_time
            ON safeharness_communication_audit(tenant_id, occurred_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_safeharness_communication_audit_export
            ON safeharness_communication_audit(occurred_at, record_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS safeharness_communication_health (
            probe_id INTEGER PRIMARY KEY CHECK(probe_id = 1),
            touched_at TIMESTAMPTZ NOT NULL
        )
        """,
        """
        CREATE OR REPLACE FUNCTION safeharness_reject_communication_audit_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'SafeHarness communication audit is append-only';
        END;
        $$
        """,
        """
        DROP TRIGGER IF EXISTS safeharness_communication_audit_no_update
            ON safeharness_communication_audit
        """,
        """
        CREATE TRIGGER safeharness_communication_audit_no_update
            BEFORE UPDATE ON safeharness_communication_audit
            FOR EACH ROW EXECUTE FUNCTION safeharness_reject_communication_audit_mutation()
        """,
        """
        DROP TRIGGER IF EXISTS safeharness_communication_audit_no_delete
            ON safeharness_communication_audit
        """,
        """
        CREATE TRIGGER safeharness_communication_audit_no_delete
            BEFORE DELETE ON safeharness_communication_audit
            FOR EACH ROW EXECUTE FUNCTION safeharness_reject_communication_audit_mutation()
        """,
    )


def _role_grants(
    runtime_role: str | None,
    reader_role: str | None,
    retention_role: str | None,
) -> tuple[str, ...]:
    tables = (
        "safeharness_communication_schema",
        "safeharness_communication_replay",
        "safeharness_communication_delegation_usage",
        "safeharness_communication_messages",
        "safeharness_communication_audit",
        "safeharness_communication_health",
    )
    statements = [*(f"REVOKE ALL ON TABLE {table} FROM PUBLIC" for table in tables)]
    if runtime_role is not None:
        statements.extend(
            (
                f"GRANT SELECT ON TABLE safeharness_communication_schema TO {runtime_role}",
                f"GRANT SELECT, INSERT, UPDATE ON TABLE "
                f"safeharness_communication_replay, "
                f"safeharness_communication_delegation_usage, "
                f"safeharness_communication_messages TO {runtime_role}",
                f"GRANT INSERT ON TABLE safeharness_communication_audit TO {runtime_role}",
                f"GRANT SELECT, INSERT, UPDATE ON TABLE safeharness_communication_health TO {runtime_role}",
                f"REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE "
                f"safeharness_communication_replay, "
                f"safeharness_communication_delegation_usage, "
                f"safeharness_communication_messages, "
                f"safeharness_communication_audit, "
                f"safeharness_communication_health FROM {runtime_role}",
            )
        )
    if reader_role is not None:
        statements.extend(
            (
                f"GRANT SELECT ON TABLE {', '.join(tables)} TO {reader_role}",
                f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE "
                f"{', '.join(tables)} FROM {reader_role}",
            )
        )
    if retention_role is not None:
        statements.extend(
            (
                f"GRANT SELECT ON TABLE safeharness_communication_schema, "
                f"safeharness_communication_replay, safeharness_communication_messages "
                f"TO {retention_role}",
                f"GRANT DELETE ON TABLE safeharness_communication_replay, "
                f"safeharness_communication_messages TO {retention_role}",
                f"REVOKE INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER ON TABLE "
                f"safeharness_communication_replay, safeharness_communication_messages "
                f"FROM {retention_role}",
            )
        )
    return tuple(statements)


def _validate_roles(
    runtime_role: str | None,
    reader_role: str | None,
    retention_role: str | None,
) -> tuple[str | None, str | None, str | None]:
    values = []
    for value in (runtime_role, reader_role, retention_role):
        if value is None or value == "":
            values.append(None)
            continue
        if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("PostgreSQL role must be an unquoted identifier")
        values.append(value)
    non_empty = [value for value in values if value is not None]
    if len(non_empty) != len(set(non_empty)):
        raise ValueError("PostgreSQL communication roles must be different")
    return values[0], values[1], values[2]


def _insert_audit(cursor: Any, record: CommunicationAuditRecord) -> None:
    cursor.execute(
        """
        INSERT INTO safeharness_communication_audit (
            record_id, action, outcome, occurred_at, tenant_id,
            sender_agent_id, recipient_agent_id, message_fingerprint,
            message_kind, content_sha256, content_length,
            delegation_fingerprint, reason_code, request_id, details_json
        ) VALUES (
            %s, %s, %s, CAST(%s AS timestamptz), %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, CAST(%s AS jsonb)
        )
        """,
        (
            record.record_id,
            record.action,
            record.outcome,
            _timestamp(record.occurred_at),
            record.tenant_id,
            record.sender_agent_id,
            record.recipient_agent_id,
            record.message_fingerprint,
            record.message_kind,
            record.content_sha256,
            record.content_length,
            record.delegation_fingerprint,
            record.reason_code,
            record.request_id,
            json.dumps(
                json_safe(minimize_value(record.details)),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        ),
    )


def _message_values(message: InterAgentMessage) -> tuple[Any, ...]:
    return (
        message.message_id,
        message.message_fingerprint,
        message.tenant_id,
        message.sender_agent_id,
        message.recipient_agent_id,
        message.session_id,
        message.run_id,
        message.trace_id,
        message.kind.value,
        message.content,
        message.content_sha256,
        message.correlation_id,
        message.parent_message_id,
        message.delegation_id,
        json.dumps(sorted(message.requested_capabilities), separators=(",", ":")),
        json.dumps(
            json_safe(message.metadata),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        _timestamp(message.created_at),
        _timestamp(message.expires_at),
    )


def _message_from_row(row: Mapping[str, Any]) -> InterAgentMessage:
    requested = row["requested_capabilities_json"]
    if isinstance(requested, str):
        requested = json.loads(requested)
    metadata = row["metadata_json"]
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    return InterAgentMessage(
        tenant_id=str(row["tenant_id"]),
        sender_agent_id=str(row["sender_agent_id"]),
        recipient_agent_id=str(row["recipient_agent_id"]),
        session_id=str(row["session_id"]),
        run_id=str(row["run_id"]),
        trace_id=str(row["trace_id"]),
        kind=MessageKind(str(row["message_kind"])),
        content=str(row["content"]),
        correlation_id=str(row["correlation_id"]),
        parent_message_id=str(row["parent_message_id"]),
        delegation_id=str(row["delegation_id"]),
        requested_capabilities=frozenset(requested),
        metadata=metadata,
        message_id=str(row["message_id"]),
        created_at=_parse_time(row["created_at"]),
        expires_at=_parse_time(row["expires_at"]),
    )


def _row_mapping(
    row: Any,
    columns: tuple[str, ...] = _MESSAGE_COLUMNS,
) -> dict[str, Any]:
    if isinstance(row, Mapping):
        return {column: row[column] for column in columns}
    return dict(zip(columns, row, strict=False))


def _parse_time(value: Any) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if isinstance(value, datetime):
        return _normalize_time(value)
    return _normalize_time(datetime.fromisoformat(str(value)))


def _timestamp(value: datetime) -> str:
    return _normalize_time(value).isoformat()


def _validate_lease_parameters(limit: int, lease_duration: timedelta) -> None:
    if not 1 <= limit <= 100:
        raise ValueError("message lease limit must be between 1 and 100")
    if not timedelta(seconds=1) <= lease_duration <= timedelta(minutes=10):
        raise ValueError("message lease duration must be between 1 and 600 seconds")


def _psycopg_connect(dsn: str) -> Callable[[], Any]:
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL communication state requires: "
            "pip install 'safeharness[production]'"
        ) from exc

    def connect() -> Any:
        return psycopg.connect(dsn, autocommit=False)

    return connect
