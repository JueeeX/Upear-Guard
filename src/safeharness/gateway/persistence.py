"""Composition helpers for persistent Tool Security Gateway backends."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safeharness.backends import (
    PostgreSQLAuditSink,
    RedisCapabilityReplayStore,
    RedisEnforcementReceiptReplayStore,
    SQLiteAuditSink,
    SQLiteCapabilityReplayStore,
    SQLiteEnforcementReceiptReplayStore,
)
from safeharness.ports import (
    CapabilityReplayStore,
    EnforcementReceiptReplayStore,
    GatewayAuditSink,
)


@dataclass(frozen=True, slots=True)
class GatewayPersistence:
    replay_store: CapabilityReplayStore
    receipt_replay_store: EnforcementReceiptReplayStore
    audit_sink: GatewayAuditSink
    readiness_checks: tuple[Callable[[], Any], ...]
    replay_backend: str
    audit_backend: str


def build_gateway_persistence(
    *,
    replay_backend: str,
    audit_backend: str,
    sqlite_path: str | Path | None = None,
    redis_url: str | None = None,
    postgres_dsn: str | None = None,
    postgres_table: str = "safeharness_audit_records",
    redis_key_prefix: str = "safeharness:capability-replay:",
    redis_receipt_key_prefix: str = "safeharness:receipt-replay:",
) -> GatewayPersistence:
    """Build independently selectable replay and audit backends."""

    replay_name = replay_backend.strip().lower()
    audit_name = audit_backend.strip().lower()
    if replay_name == "sqlite":
        if sqlite_path is None:
            raise ValueError("sqlite_path is required for SQLite replay protection")
        replay_store = SQLiteCapabilityReplayStore(sqlite_path)
        receipt_replay_store = SQLiteEnforcementReceiptReplayStore(sqlite_path)
    elif replay_name == "redis":
        if not redis_url:
            raise ValueError("redis_url is required for Redis replay protection")
        replay_store = RedisCapabilityReplayStore(
            redis_url,
            key_prefix=redis_key_prefix,
        )
        receipt_replay_store = RedisEnforcementReceiptReplayStore(
            redis_url,
            key_prefix=redis_receipt_key_prefix,
        )
    else:
        raise ValueError("replay_backend must be 'sqlite' or 'redis'")

    if audit_name == "sqlite":
        if sqlite_path is None:
            raise ValueError("sqlite_path is required for SQLite audit")
        audit_sink = SQLiteAuditSink(sqlite_path)
    elif audit_name == "postgres":
        if not postgres_dsn:
            raise ValueError("postgres_dsn is required for PostgreSQL audit")
        audit_sink = PostgreSQLAuditSink(
            postgres_dsn,
            table=postgres_table,
        )
    else:
        raise ValueError("audit_backend must be 'sqlite' or 'postgres'")

    readiness_checks = tuple(
        check
        for backend in (replay_store, receipt_replay_store, audit_sink)
        if callable(check := getattr(backend, "health", None))
    )
    return GatewayPersistence(
        replay_store=replay_store,
        receipt_replay_store=receipt_replay_store,
        audit_sink=audit_sink,
        readiness_checks=readiness_checks,
        replay_backend=replay_name,
        audit_backend=audit_name,
    )
