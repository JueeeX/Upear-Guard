"""Exercise the shared PostgreSQL Agent communication store.

The script intentionally prints only aggregate outcomes.  Connection strings
and database exceptions are never echoed because they may contain credentials.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from safeharness.communication import (
    CommunicationAuditRecord,
    InterAgentMessage,
    MessageKind,
    PostgreSQLCommunicationStore,
)


async def main() -> None:
    writer_dsn = _required("SAFEHARNESS_COMMUNICATION_POSTGRES_DSN")
    reader_dsn = _required("SAFEHARNESS_COMMUNICATION_READER_DSN")
    retention_dsn = _required("SAFEHARNESS_COMMUNICATION_RETENTION_DSN")
    message_count = _message_count()
    tenant_id = f"fiberhome-postgres-smoke-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    writer_a = PostgreSQLCommunicationStore(writer_dsn, now=lambda: now)
    writer_b = PostgreSQLCommunicationStore(writer_dsn, now=lambda: now)
    reader = PostgreSQLCommunicationStore(reader_dsn, now=lambda: now)
    retention = PostgreSQLCommunicationStore(retention_dsn, now=lambda: now)

    writer_ready = await writer_a.health()
    if not writer_ready:
        raise RuntimeError(
            "shared communication PostgreSQL store is not ready "
            f"(writer={writer_ready})"
        )

    started = time.perf_counter()
    messages = [
        _message(f"shared-{uuid4()}", now=now, tenant_id=tenant_id)
        for _ in range(message_count)
    ]
    enqueue_results = await asyncio.gather(
        *(writer_a.enqueue(message, _audit(message)) for message in messages)
    )
    if not all(result.allowed for result in enqueue_results):
        raise AssertionError("shared PostgreSQL enqueue was denied")

    leases = []
    while len(leases) < len(messages):
        remaining = len(messages) - len(leases)
        first, second = await asyncio.gather(
            writer_a.lease_messages(
                tenant_id,
                "diagnosis",
                limit=min(100, remaining),
                lease_duration=timedelta(seconds=30),
                request_id="postgres-replica-a",
            ),
            writer_b.lease_messages(
                tenant_id,
                "diagnosis",
                limit=min(100, remaining),
                lease_duration=timedelta(seconds=30),
                request_id="postgres-replica-b",
            ),
        )
        batch = [*first, *second]
        if not batch:
            raise AssertionError("PostgreSQL replicas did not lease pending messages")
        leases.extend(batch)
    lease_ids = [lease.message.message_id for lease in leases]
    if len(lease_ids) != len(set(lease_ids)) or set(lease_ids) != {
        message.message_id for message in messages
    }:
        raise AssertionError("PostgreSQL replicas claimed duplicate or missing messages")
    ack_results = await asyncio.gather(
        *(
            writer_a.acknowledge(
                tenant_id,
                "diagnosis",
                lease.message.message_id,
                lease.lease_id,
                request_id="postgres-ack",
            )
            for lease in leases
        )
    )
    if not all(result.allowed for result in ack_results):
        raise AssertionError("shared PostgreSQL ACK was denied")

    delegated = _message(
        f"delegated-{uuid4()}",
        now=now,
        tenant_id=tenant_id,
        kind=MessageKind.DELEGATE,
        delegation_id=f"delegation-{uuid4()}",
    )
    accepted = await writer_a.enqueue(
        delegated,
        _audit(delegated),
        delegation_max_messages=1,
    )
    repeated = _message(
        f"delegated-{uuid4()}",
        now=now,
        tenant_id=tenant_id,
        kind=MessageKind.DELEGATE,
        delegation_id=delegated.delegation_id,
    )
    exhausted = await writer_b.enqueue(
        repeated,
        _audit(repeated),
        delegation_max_messages=1,
    )
    if not accepted.allowed or exhausted.reason_code != "delegation_message_limit_exceeded":
        raise AssertionError("shared delegation counter was not atomic")

    await retention.purge_expired(retention=timedelta(days=7))
    audit = await reader.query_audit(limit=100)
    if any("Inspect alarm" in str(row) for row in audit):
        raise AssertionError("raw communication content reached PostgreSQL audit")
    elapsed = max(time.perf_counter() - started, 0.000001)
    print(
        "SafeHarness PostgreSQL communication smoke passed: "
        f"{len(leases)} disjoint leases, delegation counter, ACK scrubbing, and audit minimization; "
        f"batch={message_count}, elapsed_seconds={elapsed:.3f}, "
        f"message_ops_per_second={message_count / elapsed:.1f}."
    )


def _message(
    message_id: str,
    *,
    now: datetime,
    tenant_id: str,
    kind: MessageKind = MessageKind.QUERY,
    delegation_id: str = "",
) -> InterAgentMessage:
    return InterAgentMessage(
        tenant_id=tenant_id,
        sender_agent_id="supervisor",
        recipient_agent_id="diagnosis",
        session_id="postgres-smoke-session",
        run_id="postgres-smoke-run",
        trace_id="postgres-smoke-trace",
        kind=kind,
        content="Inspect alarm ALM-POSTGRES-1.",
        expires_at=now + timedelta(minutes=5),
        delegation_id=delegation_id,
        requested_capabilities=(
            frozenset({"nms:alarm:read"})
            if kind is MessageKind.DELEGATE
            else frozenset()
        ),
        message_id=message_id,
        created_at=now,
    )


def _audit(message: InterAgentMessage) -> CommunicationAuditRecord:
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
        delegation_fingerprint="",
        request_id="postgres-smoke",
        details={"source": "postgres-smoke"},
    )


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _message_count() -> int:
    raw = os.environ.get("SAFEHARNESS_COMMUNICATION_SMOKE_MESSAGE_COUNT", "4")
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(
            "SAFEHARNESS_COMMUNICATION_SMOKE_MESSAGE_COUNT must be an integer"
        ) from exc
    if not 1 <= value <= 1_000:
        raise RuntimeError(
            "SAFEHARNESS_COMMUNICATION_SMOKE_MESSAGE_COUNT must be between 1 and 1000"
        )
    return value


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except RuntimeError as exc:
        message = str(exc)
        if message.startswith(
            ("shared communication PostgreSQL store is not ready", "SAFEHARNESS_")
        ):
            raise SystemExit(f"communication PostgreSQL smoke failed: {message}")
        raise SystemExit(
            f"communication PostgreSQL smoke failed ({type(exc).__name__})"
        )
    except Exception as exc:
        raise SystemExit(f"communication PostgreSQL smoke failed ({type(exc).__name__})")
