"""Durable, integrity-checked coordination control-plane state.

The communication mailbox and the coordination policy are deliberately separate
stores.  This module persists only policy metadata: Agent registrations,
topology, delegations, revocations, and quarantine state.  API keys, prompts,
message bodies, and tool credentials never enter the coordination database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from safeharness.communication.control import (
    CoordinationControlPlane,
    CoordinationSnapshot,
)
from safeharness.communication.models import (
    AgentRegistration,
    DelegationGrant,
    MessageKind,
    TopologyRule,
)


_SCHEMA_VERSION = 1
_SCHEMA_COMPONENT = "agent_coordination_control_plane"
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_OPERATION = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{0,127}\Z")


class CoordinationPersistenceError(RuntimeError):
    """Base class for durable control-plane failures."""


class CoordinationIntegrityError(CoordinationPersistenceError):
    """The durable state failed schema, signature, or referential checks."""


class CoordinationConflict(CoordinationPersistenceError):
    """Another administrator committed a newer state first."""


@dataclass(frozen=True, slots=True)
class CoordinationState:
    """One verified version of the coordination policy."""

    snapshot: CoordinationSnapshot
    version: int
    signature: str
    occurred_at: datetime
    operation: str
    actor: str

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or self.version < 1:
            raise ValueError("coordination state version must be positive")
        if not isinstance(self.signature, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.signature
        ):
            raise ValueError("coordination state signature is invalid")
        _timestamp(self.occurred_at)
        _identifier(self.operation, "operation", pattern=_OPERATION)
        _identifier(self.actor, "actor", pattern=_ACTOR)


class CoordinationStateStore(Protocol):
    """Synchronous persistence port used by the policy control plane."""

    def load(self) -> CoordinationState | None:
        """Load and verify the current state, or return ``None`` when empty."""

    def initialize(
        self,
        snapshot: CoordinationSnapshot,
        *,
        actor: str = "bootstrap",
    ) -> CoordinationState:
        """Create version one atomically."""

    def commit(
        self,
        expected_version: int,
        snapshot: CoordinationSnapshot,
        *,
        operation: str,
        actor: str,
    ) -> CoordinationState:
        """Commit one optimistic-concurrency-protected state transition."""

    def health(self) -> bool:
        """Return whether the store is readable, writable, and integrity-valid."""


def snapshot_to_payload(snapshot: CoordinationSnapshot) -> dict[str, Any]:
    """Convert a snapshot into a deterministic, strict-JSON-safe mapping."""

    _validate_snapshot(snapshot)
    return {
        "agents": [
            {
                "tenant_id": agent.tenant_id,
                "agent_id": agent.agent_id,
                "roles": sorted(agent.roles),
                "delegable_capabilities": sorted(agent.delegable_capabilities),
                "accepted_capabilities": sorted(agent.accepted_capabilities),
                "active": agent.active,
            }
            for agent in sorted(
                snapshot.agents,
                key=lambda item: (item.tenant_id, item.agent_id),
            )
        ],
        "topology": [
            {
                "tenant_id": rule.tenant_id,
                "source_agent_id": rule.source_agent_id,
                "target_agent_id": rule.target_agent_id,
                "allowed_kinds": sorted(kind.value for kind in rule.allowed_kinds),
            }
            for rule in sorted(
                snapshot.topology,
                key=lambda item: (
                    item.tenant_id,
                    item.source_agent_id,
                    item.target_agent_id,
                ),
            )
        ],
        "delegations": [
            {
                "tenant_id": grant.tenant_id,
                "grantor_agent_id": grant.grantor_agent_id,
                "grantee_agent_id": grant.grantee_agent_id,
                "capabilities": sorted(grant.capabilities),
                "expires_at": _timestamp(grant.expires_at).isoformat(),
                "session_id": grant.session_id,
                "run_id": grant.run_id,
                "max_messages": grant.max_messages,
                "delegation_id": grant.delegation_id,
            }
            for grant in sorted(
                snapshot.delegations,
                key=lambda item: (item.tenant_id, item.delegation_id),
            )
        ],
        "quarantined": [
            [tenant_id, agent_id]
            for tenant_id, agent_id in sorted(snapshot.quarantined)
        ],
        "revoked_delegations": [
            [tenant_id, delegation_id]
            for tenant_id, delegation_id in sorted(snapshot.revoked_delegations)
        ],
    }


def snapshot_from_payload(value: Any) -> CoordinationSnapshot:
    """Parse and validate a persisted snapshot without accepting extensions."""

    payload = _object(value, "coordination snapshot")
    _exact_keys(
        payload,
        {"agents", "topology", "delegations", "quarantined", "revoked_delegations"},
        "coordination snapshot",
    )
    agents = tuple(_agent_from_payload(item) for item in _array(payload["agents"], "agents"))
    topology = tuple(
        _topology_from_payload(item) for item in _array(payload["topology"], "topology")
    )
    delegations = tuple(
        _delegation_from_payload(item)
        for item in _array(payload["delegations"], "delegations")
    )
    quarantined = _pair_set(payload["quarantined"], "quarantined")
    revoked = _pair_set(payload["revoked_delegations"], "revoked_delegations")
    snapshot = CoordinationSnapshot(
        agents=agents,
        topology=topology,
        delegations=delegations,
        quarantined=quarantined,
        revoked_delegations=revoked,
    )
    _validate_snapshot(snapshot)
    return snapshot


def _validate_snapshot(snapshot: CoordinationSnapshot) -> None:
    if not isinstance(snapshot, CoordinationSnapshot):
        raise ValueError("coordination state must be a CoordinationSnapshot")
    try:
        candidate = CoordinationControlPlane(
            snapshot.agents,
            snapshot.topology,
            snapshot.delegations,
            revoked_delegations=snapshot.revoked_delegations,
        )
    except (TypeError, ValueError) as exc:
        raise CoordinationIntegrityError("coordination snapshot failed validation") from exc
    if not snapshot.quarantined <= candidate.principals:
        raise CoordinationIntegrityError(
            "quarantine state references an unregistered Agent"
        )
    delegation_keys = {
        (grant.tenant_id, grant.delegation_id) for grant in snapshot.delegations
    }
    if not snapshot.revoked_delegations <= delegation_keys:
        raise CoordinationIntegrityError(
            "revocation state references an unknown delegation"
        )


def _validate_mutation_snapshot(snapshot: CoordinationSnapshot) -> None:
    """Validate administrator-produced state while preserving client errors."""

    if not isinstance(snapshot, CoordinationSnapshot):
        raise ValueError("coordination state must be a CoordinationSnapshot")
    try:
        candidate = CoordinationControlPlane(
            snapshot.agents,
            snapshot.topology,
            snapshot.delegations,
            revoked_delegations=snapshot.revoked_delegations,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    if not snapshot.quarantined <= candidate.principals:
        raise ValueError("quarantine state references an unknown Agent")
    delegation_keys = {
        (grant.tenant_id, grant.delegation_id) for grant in snapshot.delegations
    }
    if not snapshot.revoked_delegations <= delegation_keys:
        raise ValueError("revocation state references an unknown delegation")


def _canonical_payload(snapshot: CoordinationSnapshot) -> str:
    return json.dumps(
        snapshot_to_payload(snapshot),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _validate_signing_key(signing_key: bytes) -> bytes:
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise ValueError("coordination signing_key must contain at least 32 bytes")
    return bytes(signing_key)


def _signature(
    signing_key: bytes,
    *,
    version: int,
    previous_signature: str,
    operation: str,
    actor: str,
    occurred_at: datetime,
    payload_json: str,
) -> str:
    material = json.dumps(
        {
            "version": version,
            "previous_signature": previous_signature,
            "operation": operation,
            "actor": actor,
            "occurred_at": _timestamp(occurred_at).isoformat(),
            "payload": payload_json,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(signing_key, material, hashlib.sha256).hexdigest()


def _state_from_parts(
    signing_key: bytes,
    *,
    version: int,
    previous_signature: str,
    operation: str,
    actor: str,
    occurred_at: datetime,
    payload_json: str,
) -> CoordinationState:
    try:
        snapshot = snapshot_from_payload(json.loads(payload_json))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, CoordinationPersistenceError):
            raise
        raise CoordinationIntegrityError("coordination payload is invalid JSON") from exc
    expected = _signature(
        signing_key,
        version=version,
        previous_signature=previous_signature,
        operation=operation,
        actor=actor,
        occurred_at=occurred_at,
        payload_json=payload_json,
    )
    return CoordinationState(
        snapshot=snapshot,
        version=version,
        signature=expected,
        occurred_at=occurred_at,
        operation=operation,
        actor=actor,
    )


def _verify_chain(
    signing_key: bytes,
    rows: list[Mapping[str, Any]],
    state_row: Mapping[str, Any] | None,
) -> CoordinationState | None:
    if state_row is None:
        if rows:
            raise CoordinationIntegrityError("coordination mutation log has no state row")
        return None
    if not rows:
        raise CoordinationIntegrityError("coordination state has no mutation record")
    previous = ""
    last: CoordinationState | None = None
    for expected_version, row in enumerate(rows, start=1):
        try:
            version = int(row["version"])
        except (TypeError, ValueError) as exc:
            raise CoordinationIntegrityError("coordination mutation version is invalid") from exc
        if version != expected_version:
            raise CoordinationIntegrityError("coordination mutation versions are not contiguous")
        row_previous = str(row["previous_signature"])
        if row_previous != previous:
            raise CoordinationIntegrityError("coordination signature chain is broken")
        occurred_at = _parse_timestamp(row["occurred_at"])
        payload_json = _payload_text(row["payload_json"])
        try:
            candidate = _state_from_parts(
                signing_key,
                version=version,
                previous_signature=row_previous,
                operation=str(row["operation"]),
                actor=str(row["actor"]),
                occurred_at=occurred_at,
                payload_json=payload_json,
            )
        except CoordinationPersistenceError:
            raise
        except Exception as exc:
            raise CoordinationIntegrityError("coordination mutation metadata is invalid") from exc
        supplied = str(row["signature"])
        if not hmac.compare_digest(candidate.signature, supplied):
            raise CoordinationIntegrityError("coordination mutation signature is invalid")
        previous = supplied
        last = candidate
    assert last is not None
    try:
        state_version = int(state_row["version"])
    except (TypeError, ValueError) as exc:
        raise CoordinationIntegrityError("coordination state version is invalid") from exc
    if state_version != last.version:
        raise CoordinationIntegrityError("coordination state version does not match mutation log")
    if not hmac.compare_digest(str(state_row["signature"]), last.signature):
        raise CoordinationIntegrityError("coordination state signature does not match mutation log")
    if _payload_text(state_row["payload_json"]) != _canonical_payload(last.snapshot):
        raise CoordinationIntegrityError("coordination state payload does not match mutation log")
    if str(state_row["previous_signature"]) != str(rows[-1]["previous_signature"]):
        raise CoordinationIntegrityError("coordination state previous signature is inconsistent")
    if str(state_row["operation"]) != last.operation or str(state_row["actor"]) != last.actor:
        raise CoordinationIntegrityError("coordination state metadata does not match mutation log")
    if _parse_timestamp(state_row["occurred_at"]) != last.occurred_at:
        raise CoordinationIntegrityError("coordination state timestamp does not match mutation log")
    return last


def _payload_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _timestamp(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("coordination timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _timestamp(value)
    if not isinstance(value, str):
        raise CoordinationIntegrityError("coordination timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoordinationIntegrityError("coordination timestamp is invalid") from exc
    try:
        return _timestamp(parsed)
    except ValueError as exc:
        raise CoordinationIntegrityError("coordination timestamp is invalid") from exc


def _identifier(value: Any, name: str, *, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")
    return value


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CoordinationIntegrityError(f"{name} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise CoordinationIntegrityError(f"{name} has unexpected fields")


def _array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise CoordinationIntegrityError(f"{name} must be an array")
    return value


def _strings(value: Any, name: str) -> frozenset[str]:
    items = _array(value, name)
    if any(not isinstance(item, str) for item in items) or len(set(items)) != len(items):
        raise CoordinationIntegrityError(f"{name} must contain unique strings")
    return frozenset(items)


def _agent_from_payload(value: Any) -> AgentRegistration:
    payload = _object(value, "agent")
    _exact_keys(
        payload,
        {
            "tenant_id",
            "agent_id",
            "roles",
            "delegable_capabilities",
            "accepted_capabilities",
            "active",
        },
        "agent",
    )
    if not isinstance(payload["active"], bool):
        raise CoordinationIntegrityError("agent.active must be boolean")
    try:
        return AgentRegistration(
            tenant_id=_identifier(payload["tenant_id"], "tenant_id", pattern=_ACTOR),
            agent_id=_identifier(payload["agent_id"], "agent_id", pattern=_ACTOR),
            roles=_strings(payload["roles"], "agent.roles"),
            delegable_capabilities=_strings(
                payload["delegable_capabilities"], "agent.delegable_capabilities"
            ),
            accepted_capabilities=_strings(
                payload["accepted_capabilities"], "agent.accepted_capabilities"
            ),
            active=payload["active"],
        )
    except (TypeError, ValueError) as exc:
        raise CoordinationIntegrityError("persisted Agent registration is invalid") from exc


def _topology_from_payload(value: Any) -> TopologyRule:
    payload = _object(value, "topology rule")
    _exact_keys(
        payload,
        {"tenant_id", "source_agent_id", "target_agent_id", "allowed_kinds"},
        "topology rule",
    )
    try:
        kinds = _strings(payload["allowed_kinds"], "topology.allowed_kinds")
        return TopologyRule(
            tenant_id=_identifier(payload["tenant_id"], "tenant_id", pattern=_ACTOR),
            source_agent_id=_identifier(
                payload["source_agent_id"], "source_agent_id", pattern=_ACTOR
            ),
            target_agent_id=_identifier(
                payload["target_agent_id"], "target_agent_id", pattern=_ACTOR
            ),
            allowed_kinds=frozenset(MessageKind(item) for item in kinds),
        )
    except (TypeError, ValueError) as exc:
        raise CoordinationIntegrityError("persisted topology rule is invalid") from exc


def _delegation_from_payload(value: Any) -> DelegationGrant:
    payload = _object(value, "delegation")
    _exact_keys(
        payload,
        {
            "tenant_id",
            "grantor_agent_id",
            "grantee_agent_id",
            "capabilities",
            "expires_at",
            "session_id",
            "run_id",
            "max_messages",
            "delegation_id",
        },
        "delegation",
    )
    if isinstance(payload["max_messages"], bool):
        raise CoordinationIntegrityError("delegation.max_messages must be an integer")
    try:
        return DelegationGrant(
            tenant_id=_identifier(payload["tenant_id"], "tenant_id", pattern=_ACTOR),
            grantor_agent_id=_identifier(
                payload["grantor_agent_id"], "grantor_agent_id", pattern=_ACTOR
            ),
            grantee_agent_id=_identifier(
                payload["grantee_agent_id"], "grantee_agent_id", pattern=_ACTOR
            ),
            capabilities=_strings(payload["capabilities"], "delegation.capabilities"),
            expires_at=_parse_timestamp(payload["expires_at"]),
            session_id=_identifier(payload["session_id"], "session_id", pattern=_ACTOR)
            if payload["session_id"]
            else "",
            run_id=_identifier(payload["run_id"], "run_id", pattern=_ACTOR)
            if payload["run_id"]
            else "",
            max_messages=payload["max_messages"],
            delegation_id=_identifier(
                payload["delegation_id"], "delegation_id", pattern=_ACTOR
            ),
        )
    except (TypeError, ValueError) as exc:
        raise CoordinationIntegrityError("persisted delegation is invalid") from exc


def _pair_set(value: Any, name: str) -> frozenset[tuple[str, str]]:
    pairs = _array(value, name)
    output: list[tuple[str, str]] = []
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            raise CoordinationIntegrityError(f"{name} must contain two-item arrays")
        output.append(
            (
                _identifier(pair[0], f"{name}.tenant_id", pattern=_ACTOR),
                _identifier(pair[1], f"{name}.value", pattern=_ACTOR),
            )
        )
    if len(set(output)) != len(output):
        raise CoordinationIntegrityError(f"{name} must not contain duplicates")
    return frozenset(output)


class SQLiteCoordinationStore:
    """Restart-persistent single-node coordination state with signed mutations."""

    def __init__(
        self,
        path: str | Path,
        signing_key: bytes,
        *,
        busy_timeout: float = 5.0,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = str(Path(path).expanduser().resolve())
        self.signing_key = _validate_signing_key(signing_key)
        self.busy_timeout = float(busy_timeout)
        if self.busy_timeout <= 0:
            raise ValueError("busy_timeout must be positive")
        self._now = now or (lambda: datetime.now(timezone.utc))
        _initialize_sqlite(self.path, self.busy_timeout)

    def load(self) -> CoordinationState | None:
        connection = _sqlite_connect(self.path, self.busy_timeout)
        try:
            return _sqlite_load(connection, self.signing_key)
        finally:
            connection.close()

    def initialize(
        self,
        snapshot: CoordinationSnapshot,
        *,
        actor: str = "bootstrap",
    ) -> CoordinationState:
        return self.commit(0, snapshot, operation="initialize", actor=actor)

    def commit(
        self,
        expected_version: int,
        snapshot: CoordinationSnapshot,
        *,
        operation: str,
        actor: str,
    ) -> CoordinationState:
        if not isinstance(expected_version, int) or expected_version < 0:
            raise ValueError("expected_version must be non-negative")
        _validate_snapshot(snapshot)
        _identifier(operation, "operation", pattern=_OPERATION)
        _identifier(actor, "actor", pattern=_ACTOR)
        occurred_at = _timestamp(self._now())
        payload_json = _canonical_payload(snapshot)
        connection = _sqlite_connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = _sqlite_load(connection, self.signing_key)
            current_version = 0 if current is None else current.version
            if current_version != expected_version:
                raise CoordinationConflict(
                    f"coordination state changed from expected version {expected_version}"
                )
            version = expected_version + 1
            previous_signature = "" if current is None else current.signature
            signature = _signature(
                self.signing_key,
                version=version,
                previous_signature=previous_signature,
                operation=operation,
                actor=actor,
                occurred_at=occurred_at,
                payload_json=payload_json,
            )
            values = (
                version,
                operation,
                actor,
                _timestamp(occurred_at).isoformat(),
                payload_json,
                previous_signature,
                signature,
            )
            connection.execute(
                """
                INSERT INTO safeharness_coordination_mutations (
                    version, operation, actor, occurred_at, payload_json,
                    previous_signature, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            connection.execute(
                """
                INSERT INTO safeharness_coordination_state (
                    component, version, payload_json, previous_signature,
                    signature, occurred_at, operation, actor
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(component) DO UPDATE SET
                    version = excluded.version,
                    payload_json = excluded.payload_json,
                    previous_signature = excluded.previous_signature,
                    signature = excluded.signature,
                    occurred_at = excluded.occurred_at,
                    operation = excluded.operation,
                    actor = excluded.actor
                """,
                (
                    _SCHEMA_COMPONENT,
                    *values[0:1],
                    payload_json,
                    previous_signature,
                    signature,
                    _timestamp(occurred_at).isoformat(),
                    operation,
                    actor,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return CoordinationState(
            snapshot=snapshot,
            version=version,
            signature=signature,
            occurred_at=occurred_at,
            operation=operation,
            actor=actor,
        )

    def health(self) -> bool:
        connection = _sqlite_connect(self.path, self.busy_timeout)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _sqlite_load(connection, self.signing_key)
            connection.rollback()
            return True
        except Exception:
            connection.rollback()
            return False
        finally:
            connection.close()

    def query_mutations(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        connection = _sqlite_connect(self.path, self.busy_timeout)
        try:
            rows = connection.execute(
                """
                SELECT version, operation, actor, occurred_at, signature
                FROM safeharness_coordination_mutations
                ORDER BY version DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [
                {
                    "version": int(row["version"]),
                    "operation": str(row["operation"]),
                    "actor": str(row["actor"]),
                    "occurred_at": str(row["occurred_at"]),
                    "signature": str(row["signature"]),
                }
                for row in rows
            ]
        finally:
            connection.close()


def _initialize_sqlite(path: str, busy_timeout: float) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = _sqlite_connect(path, busy_timeout)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS safeharness_coordination_schema (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS safeharness_coordination_state (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                previous_signature TEXT NOT NULL,
                signature TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                operation TEXT NOT NULL,
                actor TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS safeharness_coordination_mutations (
                version INTEGER PRIMARY KEY,
                operation TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_signature TEXT NOT NULL,
                signature TEXT NOT NULL UNIQUE
            );

            CREATE TRIGGER IF NOT EXISTS safeharness_coordination_mutations_no_update
            BEFORE UPDATE ON safeharness_coordination_mutations
            BEGIN
                SELECT RAISE(ABORT, 'SafeHarness coordination mutations are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS safeharness_coordination_mutations_no_delete
            BEFORE DELETE ON safeharness_coordination_mutations
            BEGIN
                SELECT RAISE(ABORT, 'SafeHarness coordination mutations are append-only');
            END;
            """
        )
        row = connection.execute(
            "SELECT version FROM safeharness_coordination_schema WHERE component = ?",
            (_SCHEMA_COMPONENT,),
        ).fetchone()
        if row is not None and int(row[0]) != _SCHEMA_VERSION:
            raise RuntimeError(
                "unsupported SafeHarness coordination schema version: "
                f"expected {_SCHEMA_VERSION}, found {row[0]}"
            )
        connection.execute(
            """
            INSERT INTO safeharness_coordination_schema(component, version)
            VALUES (?, ?)
            ON CONFLICT(component) DO NOTHING
            """,
            (_SCHEMA_COMPONENT, _SCHEMA_VERSION),
        )
        connection.commit()
    finally:
        connection.close()


def _sqlite_connect(path: str, busy_timeout: float) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=busy_timeout, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout * 1000)}")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _sqlite_load(
    connection: sqlite3.Connection,
    signing_key: bytes,
) -> CoordinationState | None:
    schema = connection.execute(
        "SELECT version FROM safeharness_coordination_schema WHERE component = ?",
        (_SCHEMA_COMPONENT,),
    ).fetchone()
    if schema is None or int(schema[0]) != _SCHEMA_VERSION:
        found = None if schema is None else schema[0]
        raise CoordinationIntegrityError(
            "unsupported SafeHarness coordination schema version: "
            f"expected {_SCHEMA_VERSION}, found {found}"
        )
    state_row = connection.execute(
        """
        SELECT version, payload_json, previous_signature, signature,
               occurred_at, operation, actor
        FROM safeharness_coordination_state
        WHERE component = ?
        """,
        (_SCHEMA_COMPONENT,),
    ).fetchone()
    rows = connection.execute(
        """
        SELECT version, operation, actor, occurred_at, payload_json,
               previous_signature, signature
        FROM safeharness_coordination_mutations
        ORDER BY version
        """
    ).fetchall()
    return _verify_chain(
        signing_key,
        [dict(row) for row in rows],
        None if state_row is None else dict(state_row),
    )


class PostgreSQLCoordinationStore:
    """PostgreSQL coordination state for a shared administrative control plane."""

    def __init__(
        self,
        signing_key: bytes,
        dsn: str | None = None,
        *,
        connect: Callable[[], Any] | None = None,
        initialize: bool = False,
    ) -> None:
        if (dsn is None) == (connect is None):
            raise ValueError("provide exactly one PostgreSQL DSN or connection factory")
        self.signing_key = _validate_signing_key(signing_key)
        self._connect = connect or _psycopg_connect(dsn or "")
        if initialize:
            self.initialize_schema()

    def load(self) -> CoordinationState | None:
        with closing(self._connect()) as connection:
            with closing(connection.cursor()) as cursor:
                return _postgres_load(cursor, self.signing_key)

    def initialize(
        self,
        snapshot: CoordinationSnapshot,
        *,
        actor: str = "bootstrap",
    ) -> CoordinationState:
        return self.commit(0, snapshot, operation="initialize", actor=actor)

    def commit(
        self,
        expected_version: int,
        snapshot: CoordinationSnapshot,
        *,
        operation: str,
        actor: str,
    ) -> CoordinationState:
        if not isinstance(expected_version, int) or expected_version < 0:
            raise ValueError("expected_version must be non-negative")
        _validate_snapshot(snapshot)
        _identifier(operation, "operation", pattern=_OPERATION)
        _identifier(actor, "actor", pattern=_ACTOR)
        occurred_at = datetime.now(timezone.utc)
        payload_json = _canonical_payload(snapshot)
        with closing(self._connect()) as connection:
            try:
                with closing(connection.cursor()) as cursor:
                    current = _postgres_load(
                        cursor,
                        self.signing_key,
                        for_update=True,
                    )
                    current_version = 0 if current is None else current.version
                    if current_version != expected_version:
                        raise CoordinationConflict(
                            f"coordination state changed from expected version {expected_version}"
                        )
                    version = expected_version + 1
                    previous_signature = "" if current is None else current.signature
                    signature = _signature(
                        self.signing_key,
                        version=version,
                        previous_signature=previous_signature,
                        operation=operation,
                        actor=actor,
                        occurred_at=occurred_at,
                        payload_json=payload_json,
                    )
                    occurred_text = _timestamp(occurred_at).isoformat()
                    cursor.execute(
                        """
                        INSERT INTO safeharness_coordination_mutations (
                            version, operation, actor, occurred_at, payload_json,
                            previous_signature, signature
                        ) VALUES (%s, %s, %s, CAST(%s AS timestamptz),
                                  CAST(%s AS jsonb), %s, %s)
                        """,
                        (
                            version,
                            operation,
                            actor,
                            occurred_text,
                            payload_json,
                            previous_signature,
                            signature,
                        ),
                    )
                    cursor.execute(
                        """
                        INSERT INTO safeharness_coordination_state (
                            component, version, payload_json, previous_signature,
                            signature, occurred_at, operation, actor
                        ) VALUES (%s, %s, CAST(%s AS jsonb), %s, %s,
                                  CAST(%s AS timestamptz), %s, %s)
                        ON CONFLICT(component) DO UPDATE SET
                            version = excluded.version,
                            payload_json = excluded.payload_json,
                            previous_signature = excluded.previous_signature,
                            signature = excluded.signature,
                            occurred_at = excluded.occurred_at,
                            operation = excluded.operation,
                            actor = excluded.actor
                        """,
                        (
                            _SCHEMA_COMPONENT,
                            version,
                            payload_json,
                            previous_signature,
                            signature,
                            occurred_text,
                            operation,
                            actor,
                        ),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return CoordinationState(
            snapshot=snapshot,
            version=version,
            signature=signature,
            occurred_at=occurred_at,
            operation=operation,
            actor=actor,
        )

    def initialize_schema(
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
                    for statement in _postgres_schema_statements():
                        cursor.execute(statement)
                    cursor.execute(
                        """
                        INSERT INTO safeharness_coordination_schema(component, version)
                        VALUES (%s, %s)
                        ON CONFLICT(component) DO NOTHING
                        """,
                        (_SCHEMA_COMPONENT, _SCHEMA_VERSION),
                    )
                    cursor.execute(
                        """
                        SELECT version FROM safeharness_coordination_schema
                        WHERE component = %s
                        """,
                        (_SCHEMA_COMPONENT,),
                    )
                    row = cursor.fetchone()
                    if row is None or int(row[0]) != _SCHEMA_VERSION:
                        found = None if row is None else row[0]
                        raise RuntimeError(
                            "unsupported SafeHarness coordination schema version: "
                            f"{found}"
                        )
                    for statement in _postgres_role_grants(
                        runtime_role=runtime,
                        reader_role=reader,
                    ):
                        cursor.execute(statement)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def health(self) -> bool:
        try:
            with closing(self._connect()) as connection:
                with closing(connection.cursor()) as cursor:
                    cursor.execute(
                        """
                        SELECT EXISTS (
                            SELECT 1 FROM safeharness_coordination_schema
                            WHERE component = %s AND version = %s
                        )
                        AND to_regclass('safeharness_coordination_state') IS NOT NULL
                        AND has_table_privilege(
                            current_user,
                            'safeharness_coordination_state',
                            'SELECT'
                        )
                        """,
                        (_SCHEMA_COMPONENT, _SCHEMA_VERSION),
                    )
                    row = cursor.fetchone()
                connection.rollback()
            if row is None or row[0] is not True:
                return False
            self.load()
            return True
        except Exception:
            return False

    def query_mutations(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with closing(self._connect()) as connection:
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT version, operation, actor, occurred_at, signature
                    FROM safeharness_coordination_mutations
                    ORDER BY version DESC LIMIT %s
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
        return [
            {
                "version": int(row[0]),
                "operation": str(row[1]),
                "actor": str(row[2]),
                "occurred_at": _parse_timestamp(row[3]).isoformat(),
                "signature": str(row[4]),
            }
            for row in rows
        ]


def _postgres_load(
    cursor: Any,
    signing_key: bytes,
    *,
    for_update: bool = False,
) -> CoordinationState | None:
    cursor.execute(
        """
        SELECT version FROM safeharness_coordination_schema
        WHERE component = %s
        """,
        (_SCHEMA_COMPONENT,),
    )
    schema = cursor.fetchone()
    if schema is None or int(schema[0]) != _SCHEMA_VERSION:
        found = None if schema is None else schema[0]
        raise CoordinationIntegrityError(
            "unsupported SafeHarness coordination schema version: "
            f"expected {_SCHEMA_VERSION}, found {found}"
        )
    suffix = " FOR UPDATE" if for_update else ""
    cursor.execute(
        """
        SELECT version, payload_json, previous_signature, signature,
               occurred_at, operation, actor
        FROM safeharness_coordination_state
        WHERE component = %s
        """ + suffix,
        (_SCHEMA_COMPONENT,),
    )
    raw_state = cursor.fetchone()
    cursor.execute(
        """
        SELECT version, operation, actor, occurred_at, payload_json,
               previous_signature, signature
        FROM safeharness_coordination_mutations
        ORDER BY version
        """
    )
    raw_rows = cursor.fetchall()
    state_row = None
    if raw_state is not None:
        state_row = {
            "version": raw_state[0],
            "payload_json": raw_state[1],
            "previous_signature": raw_state[2],
            "signature": raw_state[3],
            "occurred_at": raw_state[4],
            "operation": raw_state[5],
            "actor": raw_state[6],
        }
    rows = [
        {
            "version": row[0],
            "operation": row[1],
            "actor": row[2],
            "occurred_at": row[3],
            "payload_json": row[4],
            "previous_signature": row[5],
            "signature": row[6],
        }
        for row in raw_rows
    ]
    return _verify_chain(signing_key, rows, state_row)


def _psycopg_connect(dsn: str) -> Callable[[], Any]:
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL coordination state requires: "
            "pip install 'safeharness[production]'"
        ) from exc

    def connect() -> Any:
        return psycopg.connect(dsn, autocommit=False)

    return connect


def _role_identifier(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,62}", value
    ) is None:
        raise ValueError("PostgreSQL role must be an unquoted identifier")
    return value


def _postgres_schema_statements() -> tuple[str, ...]:
    return (
        """
        CREATE TABLE IF NOT EXISTS safeharness_coordination_schema (
            component TEXT PRIMARY KEY,
            version INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS safeharness_coordination_state (
            component TEXT PRIMARY KEY,
            version BIGINT NOT NULL,
            payload_json JSONB NOT NULL,
            previous_signature TEXT NOT NULL,
            signature TEXT NOT NULL,
            occurred_at TIMESTAMPTZ NOT NULL,
            operation TEXT NOT NULL,
            actor TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS safeharness_coordination_mutations (
            version BIGINT PRIMARY KEY,
            operation TEXT NOT NULL,
            actor TEXT NOT NULL,
            occurred_at TIMESTAMPTZ NOT NULL,
            payload_json JSONB NOT NULL,
            previous_signature TEXT NOT NULL,
            signature TEXT NOT NULL UNIQUE
        )
        """,
        """
        CREATE OR REPLACE FUNCTION safeharness_reject_coordination_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'SafeHarness coordination mutations are append-only';
        END;
        $$
        """,
        """
        DROP TRIGGER IF EXISTS safeharness_coordination_mutations_no_update
            ON safeharness_coordination_mutations
        """,
        """
        CREATE TRIGGER safeharness_coordination_mutations_no_update
        BEFORE UPDATE OR DELETE ON safeharness_coordination_mutations
        FOR EACH ROW EXECUTE FUNCTION safeharness_reject_coordination_mutation()
        """,
    )


def _postgres_role_grants(
    *,
    runtime_role: str | None,
    reader_role: str | None,
) -> tuple[str, ...]:
    if runtime_role is None and reader_role is None:
        return ()
    tables = (
        "safeharness_coordination_schema",
        "safeharness_coordination_state",
        "safeharness_coordination_mutations",
    )
    statements = [*(f"REVOKE ALL ON TABLE {table} FROM PUBLIC" for table in tables)]
    if runtime_role is not None:
        statements.extend(
            (
                f"GRANT SELECT ON TABLE safeharness_coordination_schema "
                f"TO {runtime_role}",
                f"GRANT SELECT, INSERT ON TABLE safeharness_coordination_mutations "
                f"TO {runtime_role}",
                f"GRANT SELECT, INSERT, UPDATE ON TABLE "
                f"safeharness_coordination_state TO {runtime_role}",
                f"REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE "
                f"safeharness_coordination_state FROM {runtime_role}",
                f"REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE "
                f"safeharness_coordination_mutations FROM {runtime_role}",
            )
        )
    if reader_role is not None:
        statements.append(
            f"GRANT SELECT ON TABLE {', '.join(tables)} TO {reader_role}"
        )
        statements.append(
            f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE "
            f"{', '.join(tables)} FROM {reader_role}"
        )
    return tuple(statements)


class PersistentCoordinationControlPlane(CoordinationControlPlane):
    """Control plane backed by a signed state store.

    Authorization refreshes the verified snapshot before evaluating a message,
    so a revocation committed by another gateway process takes effect without
    waiting for a process restart.  A store failure raises and is handled by the
    communication application as an unavailable policy dependency (fail closed).
    """

    def __init__(
        self,
        store: CoordinationStateStore,
        *,
        agents=(),
        topology=(),
        delegations=(),
        now: Callable[[], datetime] | None = None,
        bootstrap_actor: str = "bootstrap",
    ) -> None:
        self._coordination_store = store
        self._coordination_now = now or (lambda: datetime.now(timezone.utc))
        state = store.load()
        if state is None:
            initial = CoordinationSnapshot(
                agents=tuple(agents),
                topology=tuple(topology),
                delegations=tuple(delegations),
            )
            _validate_snapshot(initial)
            state = store.initialize(initial, actor=bootstrap_actor)
        super().__init__(
            state.snapshot.agents,
            state.snapshot.topology,
            state.snapshot.delegations,
            revoked_delegations=state.snapshot.revoked_delegations,
            now=self._coordination_now,
        )
        self._replace_snapshot(state.snapshot)
        self._coordination_version = state.version
        self._coordination_signature = state.signature

    @property
    def coordination_version(self) -> int:
        return self._coordination_version

    @property
    def coordination_signature(self) -> str:
        return self._coordination_signature

    @property
    def state_store(self) -> CoordinationStateStore:
        return self._coordination_store

    def refresh(self) -> CoordinationState:
        state = self._coordination_store.load()
        if state is None:
            raise CoordinationIntegrityError("coordination state unexpectedly disappeared")
        if state.version < self._coordination_version:
            raise CoordinationIntegrityError("coordination state moved backwards")
        if state.version != self._coordination_version:
            self._replace_snapshot(state.snapshot)
            self._coordination_version = state.version
            self._coordination_signature = state.signature
        return state

    def authorize_sender(self, message):
        self.refresh()
        return super().authorize_sender(message)

    def authorize_recipient(self, tenant_id: str, recipient_agent_id: str):
        self.refresh()
        return super().authorize_recipient(tenant_id, recipient_agent_id)

    def register_agent(self, agent: AgentRegistration, *, actor: str = "admin") -> None:
        self._mutate(
            "register_agent",
            actor,
            lambda snapshot: CoordinationSnapshot(
                agents=snapshot.agents + (agent,),
                topology=snapshot.topology,
                delegations=snapshot.delegations,
                quarantined=snapshot.quarantined,
                revoked_delegations=snapshot.revoked_delegations,
            ),
        )

    def set_agent_active(
        self,
        tenant_id: str,
        agent_id: str,
        active: bool,
        *,
        actor: str = "admin",
    ) -> None:
        def mutate(snapshot: CoordinationSnapshot) -> CoordinationSnapshot:
            updated = []
            found = False
            for agent in snapshot.agents:
                if (agent.tenant_id, agent.agent_id) == (tenant_id, agent_id):
                    updated.append(
                        AgentRegistration(
                            tenant_id=agent.tenant_id,
                            agent_id=agent.agent_id,
                            roles=agent.roles,
                            delegable_capabilities=agent.delegable_capabilities,
                            accepted_capabilities=agent.accepted_capabilities,
                            active=active,
                        )
                    )
                    found = True
                else:
                    updated.append(agent)
            if not found:
                raise KeyError("unknown Agent")
            return CoordinationSnapshot(
                agents=tuple(updated),
                topology=snapshot.topology,
                delegations=snapshot.delegations,
                quarantined=snapshot.quarantined,
                revoked_delegations=snapshot.revoked_delegations,
            )

        self._mutate("set_agent_active", actor, mutate)

    def upsert_topology(self, rule: TopologyRule, *, actor: str = "admin") -> None:
        def mutate(snapshot: CoordinationSnapshot) -> CoordinationSnapshot:
            filtered = tuple(
                item
                for item in snapshot.topology
                if (
                    item.tenant_id,
                    item.source_agent_id,
                    item.target_agent_id,
                )
                != (rule.tenant_id, rule.source_agent_id, rule.target_agent_id)
            )
            return CoordinationSnapshot(
                agents=snapshot.agents,
                topology=filtered + (rule,),
                delegations=snapshot.delegations,
                quarantined=snapshot.quarantined,
                revoked_delegations=snapshot.revoked_delegations,
            )

        self._mutate("upsert_topology", actor, mutate)

    def remove_topology(
        self,
        tenant_id: str,
        source_agent_id: str,
        target_agent_id: str,
        *,
        actor: str = "admin",
    ) -> bool:
        removed = False

        def mutate(snapshot: CoordinationSnapshot) -> CoordinationSnapshot:
            nonlocal removed
            kept = tuple(
                item
                for item in snapshot.topology
                if not (
                    item.tenant_id == tenant_id
                    and item.source_agent_id == source_agent_id
                    and item.target_agent_id == target_agent_id
                )
            )
            removed = len(kept) != len(snapshot.topology)
            return CoordinationSnapshot(
                agents=snapshot.agents,
                topology=kept,
                delegations=snapshot.delegations,
                quarantined=snapshot.quarantined,
                revoked_delegations=snapshot.revoked_delegations,
            )

        self._mutate("remove_topology", actor, mutate)
        return removed

    def add_delegation(self, grant: DelegationGrant, *, actor: str = "admin") -> None:
        self._mutate(
            "add_delegation",
            actor,
            lambda snapshot: CoordinationSnapshot(
                agents=snapshot.agents,
                topology=snapshot.topology,
                delegations=snapshot.delegations + (grant,),
                quarantined=snapshot.quarantined,
                revoked_delegations=snapshot.revoked_delegations,
            ),
        )

    def quarantine_agent(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        actor: str = "admin",
    ) -> None:
        self._mutate(
            "quarantine_agent",
            actor,
            lambda snapshot: CoordinationSnapshot(
                agents=snapshot.agents,
                topology=snapshot.topology,
                delegations=snapshot.delegations,
                quarantined=snapshot.quarantined | {(tenant_id, agent_id)},
                revoked_delegations=snapshot.revoked_delegations,
            ),
        )

    def restore_agent(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        actor: str = "admin",
    ) -> None:
        self._mutate(
            "restore_agent",
            actor,
            lambda snapshot: CoordinationSnapshot(
                agents=snapshot.agents,
                topology=snapshot.topology,
                delegations=snapshot.delegations,
                quarantined=snapshot.quarantined - {(tenant_id, agent_id)},
                revoked_delegations=snapshot.revoked_delegations,
            ),
        )

    def revoke_delegation(
        self,
        tenant_id: str,
        delegation_id: str,
        *,
        actor: str = "admin",
    ) -> None:
        self._mutate(
            "revoke_delegation",
            actor,
            lambda snapshot: CoordinationSnapshot(
                agents=snapshot.agents,
                topology=snapshot.topology,
                delegations=snapshot.delegations,
                quarantined=snapshot.quarantined,
                revoked_delegations=snapshot.revoked_delegations
                | {(tenant_id, delegation_id)},
            ),
        )

    def _mutate(
        self,
        operation: str,
        actor: str,
        mutate: Callable[[CoordinationSnapshot], CoordinationSnapshot],
    ) -> None:
        self.refresh()
        candidate = mutate(self.snapshot())
        _validate_mutation_snapshot(candidate)
        try:
            state = self._coordination_store.commit(
                self._coordination_version,
                candidate,
                operation=operation,
                actor=actor,
            )
        except CoordinationConflict:
            self.refresh()
            raise
        self._replace_snapshot(state.snapshot)
        self._coordination_version = state.version
        self._coordination_signature = state.signature


class SQLiteCoordinationControlPlane(PersistentCoordinationControlPlane):
    """Convenience composition for local demos and single-node deployments."""

    def __init__(
        self,
        path: str | Path,
        signing_key: bytes,
        *,
        agents=(),
        topology=(),
        delegations=(),
        busy_timeout: float = 5.0,
        now: Callable[[], datetime] | None = None,
        bootstrap_actor: str = "bootstrap",
    ) -> None:
        store = SQLiteCoordinationStore(
            path,
            signing_key,
            busy_timeout=busy_timeout,
            now=now,
        )
        super().__init__(
            store,
            agents=agents,
            topology=topology,
            delegations=delegations,
            now=now,
            bootstrap_actor=bootstrap_actor,
        )


class PostgreSQLCoordinationControlPlane(PersistentCoordinationControlPlane):
    """Convenience composition for a shared PostgreSQL control plane."""

    def __init__(
        self,
        signing_key: bytes,
        dsn: str | None = None,
        *,
        connect: Callable[[], Any] | None = None,
        agents=(),
        topology=(),
        delegations=(),
        now: Callable[[], datetime] | None = None,
        bootstrap_actor: str = "bootstrap",
    ) -> None:
        store = PostgreSQLCoordinationStore(
            signing_key,
            dsn,
            connect=connect,
        )
        super().__init__(
            store,
            agents=agents,
            topology=topology,
            delegations=delegations,
            now=now,
            bootstrap_actor=bootstrap_actor,
        )
