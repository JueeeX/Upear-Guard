"""Small, authenticated administration surface for durable coordination state."""

from __future__ import annotations

from datetime import datetime
from http import HTTPStatus
from typing import Any

from safeharness.communication.models import (
    AgentRegistration,
    DelegationGrant,
    MessageKind,
    TopologyRule,
)
from safeharness.communication.persistence import (
    CoordinationConflict,
    CoordinationIntegrityError,
    CoordinationPersistenceError,
    PersistentCoordinationControlPlane,
    snapshot_to_payload,
)


_ID_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@-")
_CAPABILITY_CHARS = _ID_CHARS | {"*"}


class CoordinationAdminApplication:
    """Validated management operations over a persistent coordination plane."""

    def __init__(self, control_plane: PersistentCoordinationControlPlane) -> None:
        if not isinstance(control_plane, PersistentCoordinationControlPlane):
            raise TypeError("coordination administration requires a persistent control plane")
        self.control_plane = control_plane

    def snapshot(self) -> dict[str, Any]:
        state = self.control_plane.refresh()
        return {
            "version": state.version,
            "signature": state.signature,
            "occurred_at": state.occurred_at.isoformat(),
            "operation": state.operation,
            "actor": state.actor,
            "state": snapshot_to_payload(state.snapshot),
        }

    def mutate(self, route: str, payload: Any, *, actor: str) -> dict[str, Any]:
        if not isinstance(actor, str) or not actor or not _valid_identifier(actor):
            raise ValueError("admin actor is invalid")
        data = _object(payload)
        if route == "/v1/admin/agents/register":
            _exact(data, {
                "tenant_id", "agent_id", "roles", "delegable_capabilities",
                "accepted_capabilities", "active",
            })
            self.control_plane.register_agent(_agent(data), actor=actor)
        elif route == "/v1/admin/agents/active":
            _exact(data, {"tenant_id", "agent_id", "active"})
            self.control_plane.set_agent_active(
                _id(data["tenant_id"]),
                _id(data["agent_id"]),
                _boolean(data["active"], "active"),
                actor=actor,
            )
        elif route == "/v1/admin/topology":
            _exact(data, {"tenant_id", "source_agent_id", "target_agent_id", "allowed_kinds"})
            self.control_plane.upsert_topology(_topology(data), actor=actor)
        elif route == "/v1/admin/topology/remove":
            _exact(data, {"tenant_id", "source_agent_id", "target_agent_id"})
            self.control_plane.remove_topology(
                _id(data["tenant_id"]),
                _id(data["source_agent_id"]),
                _id(data["target_agent_id"]),
                actor=actor,
            )
        elif route == "/v1/admin/delegations":
            _exact(data, {
                "tenant_id", "grantor_agent_id", "grantee_agent_id", "capabilities",
                "expires_at", "session_id", "run_id", "max_messages", "delegation_id",
            })
            self.control_plane.add_delegation(_delegation(data), actor=actor)
        elif route == "/v1/admin/agents/quarantine":
            operator = _controlled_mutation(
                data, action="agent.quarantine", target_field="agent_id",
                resource_kind="agent", effect="deny_agent_communication",
            )
            self.control_plane.quarantine_agent(
                _id(data["tenant_id"]), _id(data["agent_id"]), actor=operator
            )
        elif route == "/v1/admin/agents/restore":
            operator = _controlled_mutation(
                data, action="agent.restore", target_field="agent_id",
                resource_kind="agent", effect="restore_agent_communication",
            )
            self.control_plane.restore_agent(
                _id(data["tenant_id"]), _id(data["agent_id"]), actor=operator
            )
        elif route == "/v1/admin/delegations/revoke":
            operator = _controlled_mutation(
                data, action="delegation.revoke", target_field="delegation_id",
                resource_kind="delegation", effect="revoke_delegated_authority",
            )
            self.control_plane.revoke_delegation(
                _id(data["tenant_id"]), _id(data["delegation_id"]), actor=operator
            )
        else:
            raise LookupError("unknown administration route")
        return self.snapshot()

    @staticmethod
    def error_status(exc: Exception) -> int:
        if isinstance(exc, (TypeError, ValueError)):
            return int(HTTPStatus.BAD_REQUEST)
        if isinstance(exc, KeyError):
            return int(HTTPStatus.NOT_FOUND)
        if isinstance(exc, CoordinationConflict):
            return int(HTTPStatus.CONFLICT)
        if isinstance(exc, (CoordinationIntegrityError, CoordinationPersistenceError, OSError)):
            return int(HTTPStatus.SERVICE_UNAVAILABLE)
        return int(HTTPStatus.INTERNAL_SERVER_ERROR)


def _agent(data: dict[str, Any]) -> AgentRegistration:
    return AgentRegistration(
        tenant_id=_id(data["tenant_id"]),
        agent_id=_id(data["agent_id"]),
        roles=_strings(data["roles"], "roles"),
        delegable_capabilities=_capabilities(
            data["delegable_capabilities"], "delegable_capabilities"
        ),
        accepted_capabilities=_capabilities(
            data["accepted_capabilities"], "accepted_capabilities"
        ),
        active=_boolean(data["active"], "active"),
    )


def _controlled_mutation(
    data: dict[str, Any], *, action: str, target_field: str, resource_kind: str, effect: str
) -> str:
    _exact(data, {
        "schema_version", "action", "tenant_id", target_field, "resource", "effect",
        "operator_id", "reason", "decision_id", "approval_id", "policy_version",
        "idempotency_key",
    })
    tenant_id = _id(data["tenant_id"])
    target_id = _id(data[target_field])
    operator = _id(data["operator_id"])
    if data["schema_version"] != "1.0" or data["action"] != action:
        raise ValueError("controlled mutation action is invalid")
    if data["resource"] != f"tenant/{tenant_id}/{resource_kind}/{target_id}":
        raise ValueError("controlled mutation resource is invalid")
    if data["effect"] != effect:
        raise ValueError("controlled mutation effect is invalid")
    for name in ("decision_id", "approval_id", "policy_version", "idempotency_key"):
        _id(data[name])
    reason = data["reason"]
    if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 500:
        raise ValueError("controlled mutation reason is invalid")
    return operator


def _topology(data: dict[str, Any]) -> TopologyRule:
    kinds = _strings(data["allowed_kinds"], "allowed_kinds")
    try:
        parsed = frozenset(MessageKind(item) for item in kinds)
    except ValueError as exc:
        raise ValueError("allowed_kinds contains an unknown message kind") from exc
    return TopologyRule(
        tenant_id=_id(data["tenant_id"]),
        source_agent_id=_id(data["source_agent_id"]),
        target_agent_id=_id(data["target_agent_id"]),
        allowed_kinds=parsed,
    )


def _delegation(data: dict[str, Any]) -> DelegationGrant:
    raw_expiry = data["expires_at"]
    if not isinstance(raw_expiry, str):
        raise ValueError("expires_at must be an ISO-8601 timestamp")
    try:
        expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("expires_at must be an ISO-8601 timestamp") from exc
    return DelegationGrant(
        tenant_id=_id(data["tenant_id"]),
        grantor_agent_id=_id(data["grantor_agent_id"]),
        grantee_agent_id=_id(data["grantee_agent_id"]),
        capabilities=_capabilities(data["capabilities"], "capabilities"),
        expires_at=expiry,
        session_id=_optional_id(data["session_id"], "session_id"),
        run_id=_optional_id(data["run_id"], "run_id"),
        max_messages=_integer(data["max_messages"], "max_messages", 1, 10000),
        delegation_id=_id(data["delegation_id"]),
    )


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("administration payload must be a JSON object")
    return value


def _exact(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("administration payload contains invalid fields")


def _id(value: Any) -> str:
    if not isinstance(value, str) or not _valid_identifier(value):
        raise ValueError("identifier is invalid")
    return value


def _optional_id(value: Any, name: str) -> str:
    if value == "":
        return ""
    if not isinstance(value, str) or not _valid_identifier(value):
        raise ValueError(f"{name} is invalid")
    return value


def _valid_identifier(value: str) -> bool:
    return bool(value) and len(value) <= 256 and all(char in _ID_CHARS for char in value)


def _strings(value: Any, name: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    if len(set(value)) != len(value):
        raise ValueError(f"{name} must not contain duplicates")
    return frozenset(_id(item) for item in value)


def _capabilities(value: Any, name: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    if len(set(value)) != len(value):
        raise ValueError(f"{name} must not contain duplicates")
    if any(
        not item
        or len(item) > 256
        or any(char not in _CAPABILITY_CHARS for char in item)
        for item in value
    ):
        raise ValueError(f"{name} contains an invalid capability")
    return frozenset(value)


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside the allowed range")
    return value
