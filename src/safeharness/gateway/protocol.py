"""Strict JSON wire representations for the Tool Security Gateway."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import json
from typing import Any

from safeharness.api._mapping import json_safe
from safeharness.api.context import SessionContext
from safeharness.api.decisions import Obligation, ObligationKind
from safeharness.api.tools import ToolInvocation
from safeharness.ports import AuthorizationResult, CapabilityGrant


PROTOCOL_VERSION = "safeharness-tool-gateway.v1"


def strict_json_loads(value: bytes | str) -> Any:
    """Parse RFC-style JSON while rejecting duplicate keys and NaN values."""

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


def context_to_wire(context: SessionContext) -> dict[str, Any]:
    return {
        "tenant_id": context.tenant_id,
        "agent_id": context.agent_id,
        "session_id": context.session_id,
        "run_id": context.run_id,
        "framework": context.framework,
        "trace_id": context.trace_id,
        "parent_session_id": context.parent_session_id,
        "metadata": _strict_json_value(context.metadata, "context.metadata"),
    }


def context_from_wire(value: Any) -> SessionContext:
    payload = _object(value, "context")
    _exact_keys(
        payload,
        {
            "tenant_id",
            "agent_id",
            "session_id",
            "run_id",
            "framework",
            "trace_id",
            "parent_session_id",
            "metadata",
        },
        "context",
    )
    parent = payload["parent_session_id"]
    if parent is not None:
        parent = _string(parent, "context.parent_session_id")
    metadata = _object(payload["metadata"], "context.metadata")
    return SessionContext(
        tenant_id=_string(payload["tenant_id"], "context.tenant_id"),
        agent_id=_string(payload["agent_id"], "context.agent_id"),
        session_id=_string(payload["session_id"], "context.session_id"),
        run_id=_string(payload["run_id"], "context.run_id"),
        framework=_string(payload["framework"], "context.framework"),
        trace_id=_string(payload["trace_id"], "context.trace_id"),
        parent_session_id=parent,
        metadata=metadata,
    )


def invocation_to_wire(invocation: ToolInvocation) -> dict[str, Any]:
    payload = {
        "tool_name": invocation.tool_name,
        "arguments": _strict_json_value(invocation.arguments, "invocation.arguments"),
        "call_id": invocation.call_id,
        "tool_version": invocation.tool_version,
        "resource": invocation.resource,
        "capability_token": invocation.capability_token,
        "intent_digest": invocation.intent_digest,
    }
    if invocation.enforcement_receipt is not None:
        payload["enforcement_receipt"] = invocation.enforcement_receipt
    return payload


def invocation_from_wire(value: Any) -> ToolInvocation:
    payload = _object(value, "invocation")
    _exact_keys(
        payload,
        {
            "tool_name",
            "arguments",
            "call_id",
            "tool_version",
            "resource",
            "capability_token",
            "intent_digest",
            "enforcement_receipt",
        },
        "invocation",
        optional={"enforcement_receipt"},
    )
    return ToolInvocation(
        tool_name=_string(payload["tool_name"], "invocation.tool_name"),
        arguments=_object(payload["arguments"], "invocation.arguments"),
        call_id=_string(payload["call_id"], "invocation.call_id"),
        tool_version=_optional_string(payload["tool_version"], "invocation.tool_version"),
        resource=_optional_string(payload["resource"], "invocation.resource"),
        capability_token=_optional_string(
            payload["capability_token"], "invocation.capability_token"
        ),
        intent_digest=_optional_string(payload["intent_digest"], "invocation.intent_digest"),
        enforcement_receipt=_optional_string(
            payload.get("enforcement_receipt"), "invocation.enforcement_receipt"
        ),
    )


def grant_to_wire(grant: CapabilityGrant) -> dict[str, Any]:
    return {
        "token": grant.token,
        "token_id": grant.token_id,
        "expires_at": grant.expires_at.isoformat(),
        "subject": grant.subject,
        "tenant_id": grant.tenant_id,
        "session_id": grant.session_id,
        "run_id": grant.run_id,
        "tool_name": grant.tool_name,
        "tool_version": grant.tool_version,
        "tool_integrity_digest": grant.tool_integrity_digest,
        "invocation_digest": grant.invocation_digest,
    }


def grant_from_wire(value: Any) -> CapabilityGrant:
    payload = _object(value, "grant")
    _exact_keys(
        payload,
        {
            "token",
            "token_id",
            "expires_at",
            "subject",
            "tenant_id",
            "session_id",
            "run_id",
            "tool_name",
            "tool_version",
            "tool_integrity_digest",
            "invocation_digest",
        },
        "grant",
    )
    try:
        expires_at = datetime.fromisoformat(
            _string(payload["expires_at"], "grant.expires_at").replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("grant.expires_at must be an ISO-8601 timestamp") from exc
    if expires_at.tzinfo is None:
        raise ValueError("grant.expires_at must include a timezone")
    return CapabilityGrant(
        token=_string(payload["token"], "grant.token"),
        token_id=_string(payload["token_id"], "grant.token_id"),
        expires_at=expires_at,
        subject=_string(payload["subject"], "grant.subject"),
        tenant_id=_string(payload["tenant_id"], "grant.tenant_id"),
        session_id=_string(payload["session_id"], "grant.session_id"),
        run_id=_string(payload["run_id"], "grant.run_id"),
        tool_name=_string(payload["tool_name"], "grant.tool_name"),
        tool_version=_string(payload["tool_version"], "grant.tool_version"),
        tool_integrity_digest=_string(
            payload["tool_integrity_digest"], "grant.tool_integrity_digest"
        ),
        invocation_digest=_string(
            payload["invocation_digest"], "grant.invocation_digest"
        ),
    )


def authorization_to_wire(result: AuthorizationResult) -> dict[str, Any]:
    return {
        "allowed": result.allowed,
        "reason": result.reason,
        "reason_code": result.reason_code,
        "obligations": [
            {"kind": obligation.kind.value, "parameters": json_safe(obligation.parameters)}
            for obligation in result.obligations
        ],
        "claims": json_safe(result.claims),
    }


def authorization_from_wire(value: Any) -> AuthorizationResult:
    payload = _object(value, "authorization")
    _exact_keys(
        payload,
        {"allowed", "reason", "reason_code", "obligations", "claims"},
        "authorization",
    )
    if not isinstance(payload["allowed"], bool):
        raise ValueError("authorization.allowed must be a boolean")
    obligations_value = payload["obligations"]
    if not isinstance(obligations_value, list):
        raise ValueError("authorization.obligations must be an array")
    obligations = []
    for index, item in enumerate(obligations_value):
        obligation = _object(item, f"authorization.obligations[{index}]")
        _exact_keys(
            obligation,
            {"kind", "parameters"},
            f"authorization.obligations[{index}]",
        )
        try:
            kind = ObligationKind(
                _string(obligation["kind"], f"authorization.obligations[{index}].kind")
            )
        except ValueError as exc:
            raise ValueError("authorization contains an unknown obligation") from exc
        obligations.append(
            Obligation(
                kind,
                _object(
                    obligation["parameters"],
                    f"authorization.obligations[{index}].parameters",
                ),
            )
        )
    return AuthorizationResult(
        allowed=payload["allowed"],
        reason=_string(payload["reason"], "authorization.reason", allow_empty=True),
        reason_code=_string(
            payload["reason_code"], "authorization.reason_code", allow_empty=True
        ),
        obligations=tuple(obligations),
        claims=_object(payload["claims"], "authorization.claims"),
    )


def request_to_wire(
    context: SessionContext,
    invocation: ToolInvocation,
    *,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "protocol": PROTOCOL_VERSION,
        "context": context_to_wire(context),
        "invocation": invocation_to_wire(invocation),
    }
    if expires_at is not None:
        if expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        payload["expires_at"] = expires_at.isoformat()
    return payload


def parse_request(value: Any, *, allow_expiry: bool = False) -> tuple[
    SessionContext, ToolInvocation, datetime | None
]:
    payload = _object(value, "request")
    expected = {"protocol", "context", "invocation"}
    if allow_expiry:
        expected.add("expires_at")
    _exact_keys(payload, expected, "request", optional={"expires_at"})
    if payload["protocol"] != PROTOCOL_VERSION:
        raise ValueError("unsupported gateway protocol")
    expiry_value = payload.get("expires_at")
    expiry = None
    if expiry_value is not None:
        try:
            expiry = datetime.fromisoformat(
                _string(expiry_value, "request.expires_at").replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("request.expires_at must be an ISO-8601 timestamp") from exc
        if expiry.tzinfo is None:
            raise ValueError("request.expires_at must include a timezone")
    return context_from_wire(payload["context"]), invocation_from_wire(
        payload["invocation"]
    ), expiry


def success_response(**values: Any) -> dict[str, Any]:
    return {"protocol": PROTOCOL_VERSION, "ok": True, **values}


def _strict_json_value(value: Any, name: str) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        output = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{name} keys must be strings")
            output[key] = _strict_json_value(item, f"{name}.{key}")
        return output
    if isinstance(value, (list, tuple)):
        return [
            _strict_json_value(item, f"{name}[{index}]")
            for index, item in enumerate(value)
        ]
    raise ValueError(f"{name} must contain only JSON-compatible values")


def error_response(code: str, message: str) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_VERSION,
        "ok": False,
        "error": {"code": code, "message": message},
    }


def parse_response(value: Any) -> Mapping[str, Any]:
    payload = _object(value, "response")
    if payload.get("protocol") != PROTOCOL_VERSION:
        raise ValueError("unsupported gateway protocol")
    if not isinstance(payload.get("ok"), bool):
        raise ValueError("response.ok must be a boolean")
    if payload["ok"] and "error" in payload:
        raise ValueError("successful response must not contain an error")
    if not payload["ok"]:
        if set(payload) != {"protocol", "ok", "error"}:
            raise ValueError("error response has invalid fields")
        error = _object(payload["error"], "response.error")
        _exact_keys(error, {"code", "message"}, "response.error")
        _string(error["code"], "response.error.code")
        _string(error["message"], "response.error.message")
    return payload


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} keys must be strings")
    return value


def _string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _exact_keys(
    value: Mapping[str, Any],
    expected: set[str],
    name: str,
    *,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = expected - optional - set(value)
    unexpected = set(value) - expected
    if missing or unexpected:
        raise ValueError(
            f"{name} has invalid fields (missing={sorted(missing)}, "
            f"unexpected={sorted(unexpected)})"
        )
