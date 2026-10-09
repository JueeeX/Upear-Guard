"""Default audit minimization for potentially sensitive agent events."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from safeharness.api.decisions import Decision
from safeharness.api.events import SecurityEvent


_SENSITIVE_KEY_FRAGMENTS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)
_CONTENT_KEYS = frozenset({"arguments", "content", "result"})


def minimize_event(event: SecurityEvent) -> SecurityEvent:
    """Return an audit-safe event copy without raw content or tool results."""

    payload = {
        str(key): _minimize(value, str(key))
        for key, value in event.payload.items()
    }
    return event.with_payload(payload)


def minimize_decision(decision: Decision) -> Decision:
    """Return a decision copy whose event and evidence are safe to persist."""

    reasons = tuple(
        replace(
            reason,
            message=_minimize_reason_message(reason.message),
            evidence={
                str(key): _minimize(value, str(key))
                for key, value in reason.evidence.items()
            },
        )
        for reason in decision.reasons
    )
    obligations = tuple(
        replace(
            obligation,
            parameters={
                str(key): _minimize(value, str(key))
                for key, value in obligation.parameters.items()
            },
        )
        for obligation in decision.obligations
    )
    return replace(
        decision,
        effective_event=minimize_event(decision.effective_event),
        reasons=reasons,
        obligations=obligations,
    )


def minimize_value(value: Any, key: str = "") -> Any:
    """Return an audit-safe JSON-like copy of an arbitrary value."""

    return _minimize(value, key)


def _minimize(value: Any, key: str = "") -> Any:
    normalized_key = key.lower().replace("-", "_")
    if normalized_key in _CONTENT_KEYS:
        return _content_summary(value)
    if any(fragment in normalized_key for fragment in _SENSITIVE_KEY_FRAGMENTS):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): _minimize(v, str(k)) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_minimize(item) for item in value]
    return value


def _content_summary(value: Any) -> dict[str, Any]:
    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", errors="replace")
    return {
        "redacted": True,
        "type": type(value).__name__,
        "length": len(value) if hasattr(value, "__len__") else None,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _minimize_reason_message(message: str) -> str:
    """Avoid persisting verbose provider output or embedded user content."""

    if len(message) <= 256:
        return message
    raw = message.encode("utf-8", errors="replace")
    return f"[REDACTED LONG REASON sha256={hashlib.sha256(raw).hexdigest()}]"
