from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from safeharness.communication import (
    AuditCursor,
    AuditCursorFile,
    CommunicationAuditRecord,
    CommunicationMaintenance,
    HTTPSAuditExporter,
    InterAgentMessage,
    MessageKind,
    RedisFixedWindowRateLimiter,
    SQLiteCommunicationStore,
)
from safeharness.communication.rate_limit import (
    communication_rate_limiter_from_environment,
)


NOW = datetime(2026, 7, 22, 8, 0, tzinfo=timezone.utc)


class CommunicationRateLimiterTests(unittest.TestCase):
    def test_limit_is_shared_and_bucket_identity_is_hashed(self) -> None:
        client = _FakeRedis()
        first = RedisFixedWindowRateLimiter(
            client=client,
            requests=2,
            window_seconds=60,
            now=lambda: NOW,
        )
        second = RedisFixedWindowRateLimiter(
            client=client,
            requests=2,
            window_seconds=60,
            now=lambda: NOW,
        )

        self.assertTrue(first.allow("agent:fiberhome:supervisor"))
        self.assertTrue(second.allow("agent:fiberhome:supervisor"))
        self.assertFalse(first.allow("agent:fiberhome:supervisor"))

        key = next(iter(client.counts))
        self.assertTrue(key.startswith("safeharness:communication-rate:"))
        self.assertNotIn("fiberhome", key)
        window_ms = 60_000
        expected_expiry = (int(NOW.timestamp() * 1000) // window_ms + 2) * window_ms
        self.assertEqual(client.expirations[key], expected_expiry)

    def test_next_window_uses_a_fresh_counter(self) -> None:
        client = _FakeRedis()
        clock = [NOW]
        limiter = RedisFixedWindowRateLimiter(
            client=client,
            requests=1,
            window_seconds=60,
            now=lambda: clock[0],
        )

        self.assertTrue(limiter.allow("agent:fiberhome:supervisor"))
        self.assertFalse(limiter.allow("agent:fiberhome:supervisor"))
        clock[0] += timedelta(seconds=60)
        self.assertTrue(limiter.allow("agent:fiberhome:supervisor"))
        self.assertEqual(len(client.counts), 2)

    def test_environment_is_opt_in_and_builds_a_redis_client(self) -> None:
        self.assertIsNone(communication_rate_limiter_from_environment({}))
        client = _FakeRedis()
        with patch(
            "safeharness.communication.rate_limit._redis_client",
            return_value=client,
        ) as factory:
            limiter = communication_rate_limiter_from_environment(
                {
                    "SAFEHARNESS_COMMUNICATION_RATE_LIMIT_REDIS_URL": "redis://local/0",
                    "SAFEHARNESS_COMMUNICATION_RATE_LIMIT_REQUESTS": "7",
                    "SAFEHARNESS_COMMUNICATION_RATE_LIMIT_WINDOW_SECONDS": "15",
                }
            )

        self.assertIsNotNone(limiter)
        assert limiter is not None
        self.assertEqual(limiter.requests, 7)
        self.assertEqual(limiter.window_seconds, 15)
        factory.assert_called_once_with("redis://local/0", 2.0)


class CommunicationMaintenanceTests(unittest.TestCase):
    def test_export_advances_cursor_only_after_each_successful_batch(self) -> None:
        records = [_audit_record("a", 0), _audit_record("b", 0), _audit_record("c", 1)]
        retention = _RetentionStore(4)
        reader = _AuditReader(records)
        exporter = _AuditExporter()
        with tempfile.TemporaryDirectory() as directory:
            cursor_file = AuditCursorFile(Path(directory) / "cursor.json")
            maintenance = CommunicationMaintenance(
                retention,
                audit_reader=reader,
                exporter=exporter,
                cursor_file=cursor_file,
                batch_size=2,
            )

            result = asyncio.run(maintenance.run_once())

            self.assertEqual(result.purged_rows, 4)
            self.assertEqual(result.exported_records, 3)
            self.assertEqual([[item["record_id"] for item in batch] for batch in exporter.batches], [["a", "b"], ["c"]])
            self.assertEqual(cursor_file.load(), AuditCursor(NOW + timedelta(seconds=1), "c"))

    def test_failed_export_does_not_create_or_advance_cursor(self) -> None:
        records = [_audit_record("a", 0)]
        with tempfile.TemporaryDirectory() as directory:
            cursor_file = AuditCursorFile(Path(directory) / "cursor.json")
            maintenance = CommunicationMaintenance(
                _RetentionStore(0),
                audit_reader=_AuditReader(records),
                exporter=_AuditExporter(fail=True),
                cursor_file=cursor_file,
            )

            with self.assertRaisesRegex(RuntimeError, "receiver unavailable"):
                asyncio.run(maintenance.run_once())

            self.assertIsNone(cursor_file.load())

    def test_cursor_file_accepts_utc_z_and_rejects_naive_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cursor.json"
            path.write_text(
                json.dumps({"occurred_at": "2026-07-22T08:00:00Z", "record_id": "a"}),
                encoding="utf-8",
            )
            self.assertEqual(AuditCursorFile(path).load(), AuditCursor(NOW, "a"))
            path.write_text(
                json.dumps({"occurred_at": "2026-07-22T08:00:00", "record_id": "a"}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "timezone-aware"):
                AuditCursorFile(path).load()

    def test_https_export_is_authenticated_idempotent_and_content_minimized(self) -> None:
        opener = _Opener(status=202)
        exporter = HTTPSAuditExporter(
            "https://audit.internal/v1/communication",
            "t" * 32,
            opener=opener,
        )

        asyncio.run(exporter.export((_audit_record("a", 0),)))

        request = opener.requests[0]
        payload = json.loads(request.data)
        self.assertEqual(payload["schema"], "safeharness.communication-audit.v1")
        self.assertEqual(payload["records"][0]["record_id"], "a")
        self.assertEqual(request.get_header("Authorization"), f"Bearer {'t' * 32}")
        self.assertEqual(len(request.get_header("Idempotency-key")), 64)
        self.assertEqual(opener.kwargs[0]["timeout"], 10.0)
        self.assertIn("context", opener.kwargs[0])

    def test_https_export_rejects_insecure_endpoint_and_non_success_response(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be HTTPS"):
            HTTPSAuditExporter("http://audit.internal", "t" * 32)
        exporter = HTTPSAuditExporter(
            "https://audit.internal/v1/communication",
            "t" * 32,
            opener=_Opener(status=503),
        )
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            asyncio.run(exporter.export((_audit_record("a", 0),)))


class SQLiteCommunicationMaintenanceTests(unittest.TestCase):
    def test_purge_removes_only_rows_older_than_retention_cutoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            historical_store = SQLiteCommunicationStore(
                path,
                now=lambda: NOW - timedelta(days=20),
            )
            old = _message("old", NOW - timedelta(days=10), NOW - timedelta(days=8))
            recent = _message("recent", NOW - timedelta(days=7), NOW - timedelta(days=6))
            asyncio.run(historical_store.enqueue(old, _message_audit(old)))
            asyncio.run(historical_store.enqueue(recent, _message_audit(recent)))
            store = SQLiteCommunicationStore(path, now=lambda: NOW)

            purged = asyncio.run(store.purge_expired(retention=timedelta(days=7)))

            self.assertEqual(purged, 1)
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM communication_messages").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM communication_replay").fetchone()[0],
                    1,
                )

    def test_audit_scan_uses_timestamp_and_record_id_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteCommunicationStore(Path(directory) / "communication.sqlite3")
            for record_id, offset in (("b", 0), ("a", 0), ("c", 1)):
                asyncio.run(
                    store.append_audit(
                        CommunicationAuditRecord(
                            action="gateway_request",
                            outcome="rejected",
                            tenant_id="fiberhome",
                            record_id=record_id,
                            occurred_at=NOW + timedelta(seconds=offset),
                        )
                    )
                )

            first = asyncio.run(store.scan_audit(limit=2))
            remaining = asyncio.run(
                store.scan_audit(after=AuditCursor(NOW, "b"), limit=2)
            )

            self.assertEqual([item["record_id"] for item in first], ["a", "b"])
            self.assertEqual([item["record_id"] for item in remaining], ["c"])


class _FakePipeline:
    def __init__(self, client: _FakeRedis) -> None:
        self.client = client
        self.key = ""
        self.expires_at = 0

    def incr(self, key: str) -> None:
        self.key = key

    def pexpireat(self, key: str, expires_at: int) -> None:
        if key != self.key:
            raise AssertionError("pipeline key changed")
        self.expires_at = expires_at

    def execute(self) -> list[int | bool]:
        self.client.counts[self.key] = self.client.counts.get(self.key, 0) + 1
        self.client.expirations[self.key] = self.expires_at
        return [self.client.counts[self.key], True]


class _FakeRedis:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.expirations: dict[str, int] = {}
        self.closed = False

    def pipeline(self, *, transaction: bool) -> _FakePipeline:
        if transaction is not True:
            raise AssertionError("rate limit update must be transactional")
        return _FakePipeline(self)

    def close(self) -> None:
        self.closed = True


class _RetentionStore:
    def __init__(self, purged: int) -> None:
        self.purged = purged

    async def purge_expired(self, *, retention: timedelta) -> int:
        self.retention = retention
        return self.purged


class _AuditReader:
    def __init__(self, records: list[dict]) -> None:
        self.records = records

    async def scan_audit(
        self,
        *,
        after: AuditCursor | None = None,
        limit: int = 500,
    ) -> list[dict]:
        start = 0
        if after is not None:
            keys = [
                (datetime.fromisoformat(item["occurred_at"]), item["record_id"])
                for item in self.records
            ]
            start = next(index for index, key in enumerate(keys) if key > (after.occurred_at, after.record_id))
        return self.records[start : start + limit]


class _AuditExporter:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.batches: list[list[dict]] = []

    async def export(self, records) -> None:
        if self.fail:
            raise RuntimeError("receiver unavailable")
        self.batches.append(list(records))


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None


class _Opener:
    def __init__(self, *, status: int) -> None:
        self.status = status
        self.requests = []
        self.kwargs = []

    def __call__(self, request, **kwargs):
        self.requests.append(request)
        self.kwargs.append(kwargs)
        return _Response(self.status)


def _audit_record(record_id: str, offset: int) -> dict:
    return {
        "record_id": record_id,
        "occurred_at": (NOW + timedelta(seconds=offset)).isoformat(),
        "action": "gateway_request",
        "outcome": "rejected",
        "tenant_id": "fiberhome",
        "details": {},
    }


def _message(message_id: str, created_at: datetime, expires_at: datetime) -> InterAgentMessage:
    return InterAgentMessage(
        tenant_id="fiberhome",
        sender_agent_id="supervisor",
        recipient_agent_id="diagnosis",
        session_id="session-1",
        run_id="run-1",
        trace_id="trace-1",
        kind=MessageKind.QUERY,
        content="Inspect alarm ALM-1001.",
        message_id=message_id,
        created_at=created_at,
        expires_at=expires_at,
    )


def _message_audit(message: InterAgentMessage) -> CommunicationAuditRecord:
    return CommunicationAuditRecord(
        action="message_send",
        outcome="enqueued",
        tenant_id=message.tenant_id,
        sender_agent_id=message.sender_agent_id,
        recipient_agent_id=message.recipient_agent_id,
        occurred_at=message.created_at,
    )


if __name__ == "__main__":
    unittest.main()
