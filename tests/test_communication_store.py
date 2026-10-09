from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from safeharness.communication import (
    CommunicationAuditRecord,
    InterAgentMessage,
    MessageKind,
    SQLiteCommunicationStore,
)


NOW = datetime(2026, 7, 20, 8, 0, tzinfo=timezone.utc)


def _message(
    message_id: str,
    *,
    kind: MessageKind = MessageKind.QUERY,
    delegation_id: str = "",
) -> InterAgentMessage:
    capabilities = (
        frozenset({"nms:alarm:read"})
        if kind is MessageKind.DELEGATE
        else frozenset()
    )
    return InterAgentMessage(
        tenant_id="fiberhome",
        sender_agent_id="supervisor",
        recipient_agent_id="diagnosis",
        session_id="session-1",
        run_id="run-1",
        trace_id="trace-1",
        kind=kind,
        content="Inspect alarm ALM-1001.",
        delegation_id=delegation_id,
        requested_capabilities=capabilities,
        metadata={"safeharness_provenance": {"trust": "medium"}},
        message_id=message_id,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def _audit(message: InterAgentMessage, request_id: str = "request-1") -> CommunicationAuditRecord:
    return CommunicationAuditRecord(
        action="message_send",
        outcome="enqueued",
        tenant_id=message.tenant_id,
        sender_agent_id=message.sender_agent_id,
        recipient_agent_id=message.recipient_agent_id,
        message_fingerprint=message.message_fingerprint,
        message_kind=message.kind.value,
        content_sha256=message.content_sha256,
        content_length=len(message.content),
        delegation_fingerprint=(
            hashlib.sha256(message.delegation_id.encode("utf-8")).hexdigest()
            if message.delegation_id
            else ""
        ),
        request_id=request_id,
        details={"password": "must-not-be-stored", "route": "noc"},
    )


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


class SQLiteCommunicationStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_message_lifecycle_is_persistent_audited_and_scrubbed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            store = SQLiteCommunicationStore(path, now=lambda: NOW)
            message = _message("message-lifecycle")

            enqueued = await store.enqueue(message, _audit(message))
            leases = await store.lease_messages(
                "fiberhome",
                "diagnosis",
                limit=10,
                lease_duration=timedelta(seconds=30),
                request_id="receive-1",
            )
            lease = leases[0]
            mismatch = await store.acknowledge(
                "fiberhome",
                "diagnosis",
                message.message_id,
                "wrong-lease",
                request_id="ack-wrong",
            )
            acknowledged = await store.acknowledge(
                "fiberhome",
                "diagnosis",
                message.message_id,
                lease.lease_id,
                request_id="ack-1",
            )
            repeated = await store.acknowledge(
                "fiberhome",
                "diagnosis",
                message.message_id,
                lease.lease_id,
                request_id="ack-2",
            )

            self.assertTrue(enqueued.allowed)
            self.assertEqual(len(leases), 1)
            self.assertEqual(lease.message.content, message.content)
            self.assertEqual(mismatch.reason_code, "communication_lease_mismatch")
            self.assertTrue(acknowledged.allowed)
            self.assertTrue(repeated.allowed)
            self.assertTrue(repeated.idempotent)

            connection = _connect(path)
            try:
                row = connection.execute(
                    "SELECT * FROM communication_messages WHERE message_id = ?",
                    (message.message_id,),
                ).fetchone()
                self.assertEqual(row["state"], "acknowledged")
                self.assertEqual(row["content"], "")
                self.assertEqual(row["metadata_json"], "{}")
                self.assertEqual(row["requested_capabilities_json"], "[]")
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("DELETE FROM communication_audit")
            finally:
                connection.close()

            audits = await store.query_audit(limit=20)
            serialized = json.dumps(audits)
            self.assertEqual(
                {row["outcome"] for row in audits},
                {"enqueued", "leased", "denied", "acknowledged", "idempotent"},
            )
            self.assertNotIn("must-not-be-stored", serialized)
            self.assertNotIn("wrong-lease", serialized)

    async def test_replay_and_delegation_limit_are_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            store = SQLiteCommunicationStore(path, now=lambda: NOW)
            first = _message(
                "delegation-message-1",
                kind=MessageKind.DELEGATE,
                delegation_id="delegation-1",
            )
            second = _message(
                "delegation-message-2",
                kind=MessageKind.DELEGATE,
                delegation_id="delegation-1",
            )

            accepted = await store.enqueue(
                first,
                _audit(first),
                delegation_max_messages=1,
            )
            exhausted = await store.enqueue(
                second,
                _audit(second),
                delegation_max_messages=1,
            )
            replayed = await store.enqueue(
                second,
                _audit(second),
                delegation_max_messages=1,
            )

            self.assertTrue(accepted.allowed)
            self.assertEqual(exhausted.reason_code, "delegation_message_limit_exceeded")
            self.assertEqual(replayed.reason_code, "communication_message_replayed")

            connection = _connect(path)
            try:
                counts = {
                    table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in (
                        "communication_messages",
                        "communication_replay",
                        "communication_delegation_usage",
                    )
                }
                usage = connection.execute(
                    "SELECT used_messages FROM communication_delegation_usage"
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(counts["communication_messages"], 1)
            self.assertEqual(counts["communication_replay"], 2)
            self.assertEqual(counts["communication_delegation_usage"], 1)
            self.assertEqual(usage, 1)

    async def test_normalized_expiry_rejects_without_consuming_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            store = SQLiteCommunicationStore(path, now=lambda: NOW)
            message = _message(
                "subsecond-message",
                kind=MessageKind.DELEGATE,
                delegation_id="delegation-subsecond",
            )
            object.__setattr__(
                message,
                "expires_at",
                NOW + timedelta(milliseconds=500),
            )

            result = await store.enqueue(
                message,
                _audit(message),
                delegation_max_messages=1,
            )

            self.assertFalse(result.allowed)
            self.assertEqual(result.reason_code, "communication_message_expired")
            connection = _connect(path)
            try:
                counts = {
                    table: connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in (
                        "communication_messages",
                        "communication_replay",
                        "communication_delegation_usage",
                    )
                }
                audit = connection.execute(
                    "SELECT outcome, reason_code FROM communication_audit"
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(set(counts.values()), {0})
            self.assertEqual(
                tuple(audit),
                ("denied", "communication_message_expired"),
            )

    async def test_concurrent_replay_and_mailbox_claim_have_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            stores = [SQLiteCommunicationStore(path, now=lambda: NOW) for _ in range(8)]
            message = _message("concurrent-message")
            results = await asyncio.gather(
                *(store.enqueue(message, _audit(message)) for store in stores)
            )

            self.assertEqual(sum(result.allowed for result in results), 1)
            self.assertEqual(
                sum(result.reason_code == "communication_message_replayed" for result in results),
                7,
            )

            leases = await asyncio.gather(
                *(
                    store.lease_messages(
                        "fiberhome",
                        "diagnosis",
                        limit=1,
                        lease_duration=timedelta(seconds=30),
                    )
                    for store in stores
                )
            )
            self.assertEqual(sum(len(batch) for batch in leases), 1)

    async def test_enqueue_audit_failure_rolls_back_all_authoritative_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            store = SQLiteCommunicationStore(path, now=lambda: NOW)
            message = _message(
                "rollback-message",
                kind=MessageKind.DELEGATE,
                delegation_id="delegation-rollback",
            )
            connection = _connect(path)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER fail_communication_audit
                    BEFORE INSERT ON communication_audit
                    BEGIN
                        SELECT RAISE(ABORT, 'simulated audit failure');
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(sqlite3.IntegrityError):
                await store.enqueue(
                    message,
                    _audit(message),
                    delegation_max_messages=1,
                )

            connection = _connect(path)
            try:
                for table in (
                    "communication_messages",
                    "communication_replay",
                    "communication_delegation_usage",
                    "communication_audit",
                ):
                    count = connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    self.assertEqual(count, 0, table)
            finally:
                connection.close()

    async def test_receive_and_ack_audit_failures_roll_back_mailbox_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            store = SQLiteCommunicationStore(path, now=lambda: NOW)
            message = _message("delivery-rollback")
            await store.enqueue(message, _audit(message))

            connection = _connect(path)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER fail_receive_audit
                    BEFORE INSERT ON communication_audit
                    WHEN NEW.action = 'message_receive'
                    BEGIN
                        SELECT RAISE(ABORT, 'simulated receive audit failure');
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(sqlite3.IntegrityError):
                await store.lease_messages(
                    "fiberhome",
                    "diagnosis",
                    limit=1,
                    lease_duration=timedelta(seconds=30),
                )

            connection = _connect(path)
            try:
                row = connection.execute(
                    "SELECT state, delivery_attempt FROM communication_messages"
                ).fetchone()
                self.assertEqual((row["state"], row["delivery_attempt"]), ("pending", 0))
                connection.execute("DROP TRIGGER fail_receive_audit")
                connection.commit()
            finally:
                connection.close()

            lease = (
                await store.lease_messages(
                    "fiberhome",
                    "diagnosis",
                    limit=1,
                    lease_duration=timedelta(seconds=30),
                )
            )[0]
            connection = _connect(path)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER fail_ack_audit
                    BEFORE INSERT ON communication_audit
                    WHEN NEW.action = 'message_acknowledge'
                    BEGIN
                        SELECT RAISE(ABORT, 'simulated ack audit failure');
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(sqlite3.IntegrityError):
                await store.acknowledge(
                    "fiberhome",
                    "diagnosis",
                    message.message_id,
                    lease.lease_id,
                )

            connection = _connect(path)
            try:
                row = connection.execute(
                    "SELECT state, content FROM communication_messages"
                ).fetchone()
                self.assertEqual(row["state"], "leased")
                self.assertEqual(row["content"], message.content)
            finally:
                connection.close()

    async def test_incompatible_schema_version_is_rejected_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            connection = _connect(path)
            try:
                connection.execute(
                    "CREATE TABLE communication_schema(component TEXT PRIMARY KEY, version INTEGER)"
                )
                connection.execute(
                    "INSERT INTO communication_schema VALUES (?, ?)",
                    ("agent_communication_gateway", 999),
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaisesRegex(RuntimeError, "expected 1, found 999"):
                SQLiteCommunicationStore(path)

            connection = _connect(path)
            try:
                version = connection.execute(
                    "SELECT version FROM communication_schema"
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(version, 999)


if __name__ == "__main__":
    unittest.main()
