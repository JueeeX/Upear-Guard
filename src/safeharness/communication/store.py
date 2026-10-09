"""Persistent mailbox, replay, delegation-use, and communication audit state."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from safeharness.api._mapping import json_safe
from safeharness.communication.models import (
    CommunicationAuditRecord,
    InterAgentMessage,
    MessageKind,
    MessageLease,
)
from safeharness.communication.maintenance import AuditCursor
from safeharness.runtime.redaction import minimize_value


_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class CommunicationStoreResult:
    allowed: bool
    reason_code: str = ""
    reason: str = ""
    idempotent: bool = False


class CommunicationStore(Protocol):
    async def enqueue(
        self,
        message: InterAgentMessage,
        audit: CommunicationAuditRecord,
        *,
        delegation_max_messages: int | None = None,
    ) -> CommunicationStoreResult:
        """Atomically consume replay/delegation state, audit, and enqueue."""

    async def append_audit(self, record: CommunicationAuditRecord) -> None:
        """Append a minimized communication audit record."""

    async def lease_messages(
        self,
        tenant_id: str,
        recipient_agent_id: str,
        *,
        limit: int,
        lease_duration: timedelta,
        request_id: str = "",
    ) -> tuple[MessageLease, ...]:
        """Atomically lease pending messages and audit each delivery."""

    async def acknowledge(
        self,
        tenant_id: str,
        recipient_agent_id: str,
        message_id: str,
        lease_id: str,
        *,
        request_id: str = "",
    ) -> CommunicationStoreResult:
        """Acknowledge a current lease and scrub delivered content."""

    async def health(self) -> bool:
        """Return whether authoritative communication state is writable."""

    async def purge_expired(
        self,
        *,
        retention: timedelta = timedelta(days=7),
    ) -> int:
        """Delete expired mailbox/replay rows older than the retention window."""


class SQLiteCommunicationStore:
    """Single-node reference communication state with transactional audit."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout: float = 5.0,
        now=None,
    ) -> None:
        self.path = str(Path(path).expanduser().resolve())
        self.busy_timeout = float(busy_timeout)
        if self.busy_timeout <= 0:
            raise ValueError("busy_timeout must be positive")
        self._now = now or (lambda: datetime.now(timezone.utc))
        _initialize_database(self.path, self.busy_timeout)

    async def enqueue(
        self,
        message: InterAgentMessage,
        audit: CommunicationAuditRecord,
        *,
        delegation_max_messages: int | None = None,
    ) -> CommunicationStoreResult:
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
        connection = _connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            if expires_at <= now:
                denial = _audit_with_outcome(
                    audit,
                    outcome="denied",
                    reason_code="communication_message_expired",
                )
                _insert_audit(connection, denial)
                connection.commit()
                return CommunicationStoreResult(
                    False,
                    "communication_message_expired",
                    "The communication message has expired.",
                )
            connection.execute(
                "DELETE FROM communication_replay WHERE expires_at <= ?",
                (_timestamp(now),),
            )
            replay = connection.execute(
                """
                INSERT OR IGNORE INTO communication_replay
                    (message_fingerprint, consumed_at, expires_at)
                VALUES (?, ?, ?)
                """,
                (
                    message.message_fingerprint,
                    _timestamp(now),
                    _timestamp(expires_at),
                ),
            )
            if replay.rowcount != 1:
                denial = _audit_with_outcome(
                    audit,
                    outcome="denied",
                    reason_code="communication_message_replayed",
                )
                _insert_audit(connection, denial)
                connection.commit()
                return CommunicationStoreResult(
                    False,
                    "communication_message_replayed",
                    "The communication message ID was already used.",
                )

            if delegation_max_messages is not None:
                updated = connection.execute(
                    """
                    INSERT INTO communication_delegation_usage
                        (tenant_id, delegation_id, used_messages, updated_at)
                    VALUES (?, ?, 1, ?)
                    ON CONFLICT(tenant_id, delegation_id) DO UPDATE SET
                        used_messages = used_messages + 1,
                        updated_at = excluded.updated_at
                    WHERE used_messages < ?
                    """,
                    (
                        message.tenant_id,
                        message.delegation_id,
                        _timestamp(now),
                        delegation_max_messages,
                    ),
                )
                if updated.rowcount != 1:
                    denial = _audit_with_outcome(
                        audit,
                        outcome="denied",
                        reason_code="delegation_message_limit_exceeded",
                    )
                    _insert_audit(connection, denial)
                    connection.commit()
                    return CommunicationStoreResult(
                        False,
                        "delegation_message_limit_exceeded",
                        "The delegation message limit has been exhausted.",
                    )

            connection.execute(
                """
                INSERT INTO communication_messages (
                    message_id, message_fingerprint, tenant_id, sender_agent_id,
                    recipient_agent_id, session_id, run_id, trace_id, message_kind,
                    content, content_sha256, correlation_id, parent_message_id,
                    delegation_id, requested_capabilities_json, metadata_json,
                    created_at, expires_at, state, lease_id, lease_until,
                    delivery_attempt, acknowledged_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'pending', '', NULL, 0, NULL)
                """,
                _message_row(message),
            )
            _insert_audit(connection, audit)
            connection.commit()
            return CommunicationStoreResult(True)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def append_audit(self, record: CommunicationAuditRecord) -> None:
        await asyncio.to_thread(self._append_audit, record)

    def _append_audit(self, record: CommunicationAuditRecord) -> None:
        connection = _connect(self.path, self.busy_timeout)
        try:
            _insert_audit(connection, record)
            connection.commit()
        finally:
            connection.close()

    async def lease_messages(
        self,
        tenant_id: str,
        recipient_agent_id: str,
        *,
        limit: int,
        lease_duration: timedelta,
        request_id: str = "",
    ) -> tuple[MessageLease, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("message lease limit must be between 1 and 100")
        if not timedelta(seconds=1) <= lease_duration <= timedelta(minutes=10):
            raise ValueError("message lease duration must be between 1 and 600 seconds")
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
        connection = _connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT * FROM communication_messages
                WHERE tenant_id = ? AND recipient_agent_id = ?
                  AND expires_at > ?
                  AND (
                      state = 'pending'
                      OR (state = 'leased' AND lease_until <= ?)
                  )
                ORDER BY created_at, message_id
                LIMIT ?
                """,
                (
                    tenant_id,
                    recipient_agent_id,
                    _timestamp(now),
                    _timestamp(now),
                    limit,
                ),
            ).fetchall()
            leases = []
            for row in rows:
                lease_id = str(uuid4())
                attempt = int(row["delivery_attempt"]) + 1
                connection.execute(
                    """
                    UPDATE communication_messages
                    SET state = 'leased', lease_id = ?, lease_until = ?,
                        delivery_attempt = ?
                    WHERE message_id = ?
                    """,
                    (
                        lease_id,
                        _timestamp(lease_until),
                        attempt,
                        row["message_id"],
                    ),
                )
                message = _message_from_row(row)
                _insert_audit(
                    connection,
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
        finally:
            connection.close()

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
        connection = _connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM communication_messages
                WHERE tenant_id = ? AND recipient_agent_id = ? AND message_id = ?
                """,
                (tenant_id, recipient_agent_id, message_id),
            ).fetchone()
            if row is None:
                _insert_audit(
                    connection,
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
            if row["lease_id"] != lease_id:
                _insert_audit(
                    connection,
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
                    connection,
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
                    connection,
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
            connection.execute(
                """
                UPDATE communication_messages
                SET state = 'acknowledged', acknowledged_at = ?, content = '',
                    metadata_json = '{}', requested_capabilities_json = '[]'
                WHERE message_id = ?
                """,
                (_timestamp(now), message_id),
            )
            _insert_audit(
                connection,
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
        finally:
            connection.close()

    async def health(self) -> bool:
        return await asyncio.to_thread(self._health)

    def _health(self) -> bool:
        connection = _connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR REPLACE INTO communication_health_probe(probe_id) VALUES (1)"
            )
            connection.rollback()
            return True
        except Exception:
            connection.rollback()
            return False
        finally:
            connection.close()

    async def purge_expired(
        self,
        *,
        retention: timedelta = timedelta(days=7),
    ) -> int:
        if not timedelta(hours=1) <= retention <= timedelta(days=90):
            raise ValueError("retention must be between 1 hour and 90 days")
        return await asyncio.to_thread(self._purge_expired, retention)

    def _purge_expired(self, retention: timedelta) -> int:
        cutoff = _normalize_time(self._now()) - retention
        connection = _connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            deleted = connection.execute(
                "DELETE FROM communication_messages WHERE expires_at <= ?",
                (_timestamp(cutoff),),
            ).rowcount
            connection.execute(
                "DELETE FROM communication_replay WHERE expires_at <= ?",
                (_timestamp(cutoff),),
            )
            connection.commit()
            return max(int(deleted), 0)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def query_audit(self, *, limit: int = 100) -> list[dict]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        return await asyncio.to_thread(self._query_audit, limit)

    def _query_audit(self, limit: int) -> list[dict]:
        connection = _connect(self.path, self.busy_timeout)
        try:
            rows = connection.execute(
                "SELECT * FROM communication_audit ORDER BY audit_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            output = []
            for row in rows:
                item = dict(row)
                item["details"] = json.loads(item.pop("details_json"))
                output.append(item)
            return output
        finally:
            connection.close()

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
        connection = _connect(self.path, self.busy_timeout)
        try:
            if after is None:
                rows = connection.execute(
                    """
                    SELECT * FROM communication_audit
                    ORDER BY occurred_at, record_id
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                timestamp = _timestamp(after.occurred_at)
                rows = connection.execute(
                    """
                    SELECT * FROM communication_audit
                    WHERE occurred_at > ? OR (occurred_at = ? AND record_id > ?)
                    ORDER BY occurred_at, record_id
                    LIMIT ?
                    """,
                    (timestamp, timestamp, after.record_id, limit),
                ).fetchall()
            output = []
            for row in rows:
                item = dict(row)
                item.pop("audit_id", None)
                item["details"] = json.loads(item.pop("details_json"))
                output.append(item)
            return output
        finally:
            connection.close()


def _initialize_database(path: str, busy_timeout: float) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = _connect(path, busy_timeout)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS communication_schema (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL
            )
            """
        )
        schema = connection.execute(
            """
            SELECT version FROM communication_schema
            WHERE component = 'agent_communication_gateway'
            """
        ).fetchone()
        if schema is not None and int(schema["version"]) != _SCHEMA_VERSION:
            raise RuntimeError(
                "unsupported Agent Communication Gateway schema version: "
                f"expected {_SCHEMA_VERSION}, found {schema['version']}"
            )
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS communication_replay (
                message_fingerprint TEXT PRIMARY KEY,
                consumed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_communication_replay_expiry
                ON communication_replay(expires_at);

            CREATE TABLE IF NOT EXISTS communication_delegation_usage (
                tenant_id TEXT NOT NULL,
                delegation_id TEXT NOT NULL,
                used_messages INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(tenant_id, delegation_id)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS communication_messages (
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
                requested_capabilities_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending', 'leased', 'acknowledged')),
                lease_id TEXT NOT NULL,
                lease_until TEXT,
                delivery_attempt INTEGER NOT NULL,
                acknowledged_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_communication_mailbox
                ON communication_messages(
                    tenant_id, recipient_agent_id, state, created_at
                );

            CREATE TABLE IF NOT EXISTS communication_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL UNIQUE,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
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
                details_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_communication_audit_tenant_time
                ON communication_audit(tenant_id, occurred_at DESC);

            CREATE INDEX IF NOT EXISTS idx_communication_audit_export
                ON communication_audit(occurred_at, record_id);

            CREATE TRIGGER IF NOT EXISTS communication_audit_no_update
            BEFORE UPDATE ON communication_audit
            BEGIN
                SELECT RAISE(ABORT, 'SafeHarness communication audit is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS communication_audit_no_delete
            BEFORE DELETE ON communication_audit
            BEGIN
                SELECT RAISE(ABORT, 'SafeHarness communication audit is append-only');
            END;

            CREATE TABLE IF NOT EXISTS communication_health_probe (
                probe_id INTEGER PRIMARY KEY CHECK(probe_id = 1)
            );
            """
        )
        connection.execute(
            """
            INSERT INTO communication_schema(component, version)
            VALUES ('agent_communication_gateway', ?)
            ON CONFLICT(component) DO NOTHING
            """,
            (_SCHEMA_VERSION,),
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
    return connection


def _message_row(message: InterAgentMessage) -> tuple:
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


def _message_from_row(row: sqlite3.Row) -> InterAgentMessage:
    return InterAgentMessage(
        tenant_id=row["tenant_id"],
        sender_agent_id=row["sender_agent_id"],
        recipient_agent_id=row["recipient_agent_id"],
        session_id=row["session_id"],
        run_id=row["run_id"],
        trace_id=row["trace_id"],
        kind=MessageKind(row["message_kind"]),
        content=row["content"],
        correlation_id=row["correlation_id"],
        parent_message_id=row["parent_message_id"],
        delegation_id=row["delegation_id"],
        requested_capabilities=frozenset(
            json.loads(row["requested_capabilities_json"])
        ),
        metadata=json.loads(row["metadata_json"]),
        message_id=row["message_id"],
        created_at=_parse_time(row["created_at"]),
        expires_at=_parse_time(row["expires_at"]),
    )


def _insert_audit(
    connection: sqlite3.Connection,
    record: CommunicationAuditRecord,
) -> None:
    connection.execute(
        """
        INSERT INTO communication_audit (
            record_id, action, outcome, occurred_at, tenant_id,
            sender_agent_id, recipient_agent_id, message_fingerprint,
            message_kind, content_sha256, content_length,
            delegation_fingerprint, reason_code, request_id, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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


def _ack_audit(
    *,
    row: sqlite3.Row | None,
    tenant_id: str,
    recipient_agent_id: str,
    message_id: str,
    lease_id: str,
    outcome: str,
    reason_code: str,
    request_id: str,
) -> CommunicationAuditRecord:
    details = {"lease_fingerprint": _fingerprint(lease_id)}
    if row is not None:
        details["delivery_attempt"] = int(row["delivery_attempt"])
    return CommunicationAuditRecord(
        action="message_acknowledge",
        outcome=outcome,
        tenant_id=tenant_id,
        sender_agent_id=str(row["sender_agent_id"]) if row is not None else "",
        recipient_agent_id=recipient_agent_id,
        message_fingerprint=(
            str(row["message_fingerprint"])
            if row is not None
            else _fingerprint(message_id)
        ),
        message_kind=str(row["message_kind"]) if row is not None else "",
        content_sha256=str(row["content_sha256"]) if row is not None else "",
        content_length=len(str(row["content"])) if row is not None else 0,
        delegation_fingerprint=(
            _fingerprint(str(row["delegation_id"])) if row is not None else ""
        ),
        reason_code=reason_code,
        request_id=request_id,
        details=details,
    )


def _audit_with_outcome(
    record: CommunicationAuditRecord,
    *,
    outcome: str,
    reason_code: str,
) -> CommunicationAuditRecord:
    return CommunicationAuditRecord(
        action=record.action,
        outcome=outcome,
        tenant_id=record.tenant_id,
        sender_agent_id=record.sender_agent_id,
        recipient_agent_id=record.recipient_agent_id,
        message_fingerprint=record.message_fingerprint,
        message_kind=record.message_kind,
        content_sha256=record.content_sha256,
        content_length=record.content_length,
        delegation_fingerprint=record.delegation_fingerprint,
        reason_code=reason_code,
        request_id=record.request_id,
        details=record.details,
    )


def _normalize_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("communication timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return _normalize_time(value).isoformat()


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    return _normalize_time(datetime.fromisoformat(value))


def _fingerprint(value: str) -> str:
    from safeharness.communication.models import fingerprint_identifier

    return fingerprint_identifier(value)
