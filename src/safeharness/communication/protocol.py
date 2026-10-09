"""Strict JSON wire protocol for the Agent Communication Gateway."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from safeharness.api._mapping import json_safe
from safeharness.communication.models import InterAgentMessage, MessageKind, MessageLease
from safeharness.communication.store import CommunicationStoreResult


PROTOCOL_VERSION = "safeharness-agent-communication.v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")


def strict_json_loads(value: bytes | str) -> Any:
    """Parse JSON while rejecting duplicate keys and non-standard constants."""

    if isinstance(value, bytes):
        value = value.decode("utf-8")

    def object_pairs(pairs):
        output: dict[str, Any] = {}
        for key, item in pairs:
            if key in output:
                raise ValueError(f"duplicate JSON key: {key}")
            output[key] = item
        return output

    def reject_constant(constant: str) -> None:
        raise ValueError(f"non-standard JSON constant: {constant}")

    return json.loads(
        value,
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )


def message_to_wire(message: InterAgentMessage) -> dict[str, Any]:
    return {
        "tenant_id": message.tenant_id,
        "sender_agent_id": message.sender_agent_id,
        "recipient_agent_id": message.recipient_agent_id,
        "session_id": message.session_id,
        "run_id": message.run_id,
        "trace_id": message.trace_id,
        "kind": message.kind.value,
        "content": message.content,
        "correlation_id": message.correlation_id,
        "parent_message_id": message.parent_message_id,
        "delegation_id": message.delegation_id,
        "requested_capabilities": sorted(message.requested_capabilities),
        "metadata": _strict_json_value(message.metadata, "message.metadata"),
        "message_id": message.message_id,
        "created_at": message.created_at.isoformat(),
        "expires_at": message.expires_at.isoformat(),
    }


def message_from_wire(value: Any) -> InterAgentMessage:
    payload = _object(value, "message")
    _exact_keys(
        payload,
        {
            "tenant_id",
            "sender_agent_id",
            "recipient_agent_id",
            "session_id",
            "run_id",
            "trace_id",
            "kind",
            "content",
            "correlation_id",
            "parent_message_id",
            "delegation_id",
            "requested_capabilities",
            "metadata",
            "message_id",
            "created_at",
            "expires_at",
        },
        "message",
    )
    try:
        kind = MessageKind(_string(payload["kind"], "message.kind"))
    except ValueError as exc:
        raise ValueError("message.kind is unknown") from exc
    return InterAgentMessage(
        tenant_id=_identifier(payload["tenant_id"], "message.tenant_id"),
        sender_agent_id=_identifier(
            payload["sender_agent_id"], "message.sender_agent_id"
        ),
        recipient_agent_id=_identifier(
            payload["recipient_agent_id"], "message.recipient_agent_id"
        ),
        session_id=_identifier(payload["session_id"], "message.session_id"),
        run_id=_identifier(payload["run_id"], "message.run_id"),
        trace_id=_optional_identifier(payload["trace_id"], "message.trace_id"),
        kind=kind,
        content=_string(payload["content"], "message.content"),
        correlation_id=_optional_identifier(
            payload["correlation_id"], "message.correlation_id"
        ),
        parent_message_id=_optional_identifier(
            payload["parent_message_id"], "message.parent_message_id"
        ),
        delegation_id=_optional_identifier(
            payload["delegation_id"], "message.delegation_id"
        ),
        requested_capabilities=_unique_strings(
            payload["requested_capabilities"],
            "message.requested_capabilities",
        ),
        metadata=_object(payload["metadata"], "message.metadata"),
        message_id=_identifier(payload["message_id"], "message.message_id"),
        created_at=_timestamp(payload["created_at"], "message.created_at"),
        expires_at=_timestamp(payload["expires_at"], "message.expires_at"),
    )


def lease_to_wire(lease: MessageLease) -> dict[str, Any]:
    return {
        "message": message_to_wire(lease.message),
        "lease_id": lease.lease_id,
        "lease_until": lease.lease_until.isoformat(),
        "delivery_attempt": lease.delivery_attempt,
    }


def lease_from_wire(value: Any) -> MessageLease:
    payload = _object(value, "lease")
    _exact_keys(
        payload,
        {"message", "lease_id", "lease_until", "delivery_attempt"},
        "lease",
    )
    return MessageLease(
        message=message_from_wire(payload["message"]),
        lease_id=_identifier(payload["lease_id"], "lease.lease_id"),
        lease_until=_timestamp(payload["lease_until"], "lease.lease_until"),
        delivery_attempt=_integer(
            payload["delivery_attempt"],
            "lease.delivery_attempt",
            minimum=1,
        ),
    )


def send_request_to_wire(message: InterAgentMessage) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_VERSION,
        "message": message_to_wire(message),
    }


def parse_send_request(value: Any) -> InterAgentMessage:
    payload = _request(value, {"protocol", "message"})
    return message_from_wire(payload["message"])


def receive_request_to_wire(
    *,
    limit: int,
    lease_duration: timedelta,
) -> dict[str, Any]:
    seconds = lease_duration.total_seconds()
    if not seconds.is_integer():
        raise ValueError("lease_duration must contain whole seconds")
    return {
        "protocol": PROTOCOL_VERSION,
        "limit": limit,
        "lease_duration_seconds": int(seconds),
    }


def parse_receive_request(value: Any) -> tuple[int, timedelta]:
    payload = _request(
        value,
        {"protocol", "limit", "lease_duration_seconds"},
    )
    limit = _integer(payload["limit"], "request.limit", minimum=1, maximum=100)
    seconds = _integer(
        payload["lease_duration_seconds"],
        "request.lease_duration_seconds",
        minimum=1,
        maximum=600,
    )
    return limit, timedelta(seconds=seconds)


def ack_request_to_wire(message_id: str, lease_id: str) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_VERSION,
        "message_id": _identifier(message_id, "message_id"),
        "lease_id": _identifier(lease_id, "lease_id"),
    }


def parse_ack_request(value: Any) -> tuple[str, str]:
    payload = _request(value, {"protocol", "message_id", "lease_id"})
    return (
        _identifier(payload["message_id"], "request.message_id"),
        _identifier(payload["lease_id"], "request.lease_id"),
    )


def store_result_to_wire(result: CommunicationStoreResult) -> dict[str, Any]:
    return {
        "accepted": result.allowed,
        "reason_code": result.reason_code,
        "reason": result.reason,
        "idempotent": result.idempotent,
    }


def store_result_from_wire(value: Any) -> CommunicationStoreResult:
    payload = _object(value, "result")
    _exact_keys(
        payload,
        {"accepted", "reason_code", "reason", "idempotent"},
        "result",
    )
    if not isinstance(payload["accepted"], bool):
        raise ValueError("result.accepted must be a boolean")
    if not isinstance(payload["idempotent"], bool):
        raise ValueError("result.idempotent must be a boolean")
    return CommunicationStoreResult(
        allowed=payload["accepted"],
        reason_code=_string(
            payload["reason_code"],
            "result.reason_code",
            allow_empty=True,
        ),
        reason=_string(payload["reason"], "result.reason", allow_empty=True),
        idempotent=payload["idempotent"],
    )


def success_response(**values: Any) -> dict[str, Any]:
    return {"protocol": PROTOCOL_VERSION, "ok": True, **values}


def error_response(code: str, message: str) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_VERSION,
        "ok": False,
        "error": {"code": code, "message": message},
    }


def parse_response(value: Any) -> Mapping[str, Any]:
    payload = _object(value, "response")
    if payload.get("protocol") != PROTOCOL_VERSION:
        raise ValueError("unsupported communication protocol")
    if not isinstance(payload.get("ok"), bool):
        raise ValueError("response.ok must be a boolean")
    if payload["ok"] and "error" in payload:
        raise ValueError("successful response must not contain an error")
    if not payload["ok"]:
        _exact_keys(payload, {"protocol", "ok", "error"}, "response")
        error = _object(payload["error"], "response.error")
        _exact_keys(error, {"code", "message"}, "response.error")
        _string(error["code"], "response.error.code")
        _string(error["message"], "response.error.message")
    return payload


def _request(value: Any, expected: set[str]) -> dict[str, Any]:
    payload = _object(value, "request")
    _exact_keys(payload, expected, "request")
    if payload["protocol"] != PROTOCOL_VERSION:
        raise ValueError("unsupported communication protocol")
    return payload


def _strict_json_value(value: Any, name: str) -> Any:
    safe = json_safe(value)
    if safe is None or isinstance(safe, (bool, int, float, str)):
        return safe
    if isinstance(safe, Mapping):
        return {
            str(key): _strict_json_value(item, f"{name}.{key}")
            for key, item in safe.items()
        }
    if isinstance(safe, (list, tuple)):
        return [
            _strict_json_value(item, f"{name}[{index}]")
            for index, item in enumerate(safe)
        ]
    raise ValueError(f"{name} must contain only JSON-compatible values")


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} keys must be strings")
    return value


def _string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ValueError(f"{name} must be {qualifier}")
    return value


def _identifier(value: Any, name: str) -> str:
    output = _string(value, name)
    if _IDENTIFIER.fullmatch(output) is None:
        raise ValueError(f"{name} is invalid")
    return output


def _optional_identifier(value: Any, name: str) -> str:
    output = _string(value, name, allow_empty=True)
    return _identifier(output, name) if output else ""


def _integer(
    value: Any,
    name: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} is below the minimum")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} exceeds the maximum")
    return value


def _unique_strings(value: Any, name: str) -> frozenset[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    output = []
    for index, item in enumerate(value):
        output.append(_identifier(item, f"{name}[{index}]"))
    if len(set(output)) != len(output):
        raise ValueError(f"{name} must not contain duplicates")
    return frozenset(output)


def _timestamp(value: Any, name: str) -> datetime:
    raw = _string(value, name)
    try:
        timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return timestamp


def _exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    missing = expected - set(value)
    unexpected = set(value) - expected
    if missing or unexpected:
        raise ValueError(
            f"{name} has invalid fields (missing={sorted(missing)}, "
            f"unexpected={sorted(unexpected)})"
        )
