"""Shared sanitization and row encoding for persistent audit backends."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from safeharness.api._mapping import json_safe
from safeharness.ports import AuditRecord, GatewayAuditRecord
from safeharness.runtime.redaction import minimize_decision, minimize_event, minimize_value


AUDIT_COLUMNS = (
    "record_id",
    "source",
    "record_type",
    "action",
    "outcome",
    "occurred_at",
    "tenant_id",
    "agent_id",
    "session_id",
    "run_id",
    "trace_id",
    "event_id",
    "sequence",
    "tool_name",
    "tool_version",
    "tool_integrity_digest",
    "invocation_digest",
    "capability_fingerprint",
    "decision_id",
    "receipt_id",
    "disposition",
    "reason_code",
    "request_id",
    "payload_json",
)


def agent_audit_row(record: AuditRecord) -> dict[str, Any]:
    event = minimize_event(record.event)
    decision = minimize_decision(record.decision) if record.decision else None
    receipt = record.receipt
    payload = {
        "event": event.to_dict(),
        "decision": decision.to_dict() if decision else None,
        "receipt": _receipt_to_dict(receipt) if receipt else None,
        "details": json_safe(minimize_value(record.details)),
    }
    reason_code = decision.reasons[-1].code if decision and decision.reasons else ""
    event_payload = event.payload
    return {
        "record_id": _agent_record_id(record),
        "source": "agent",
        "record_type": record.record_type,
        "action": event.kind.value,
        "outcome": decision.disposition.value if decision else "observed",
        "occurred_at": timestamp_text(event.meta.timestamp),
        "tenant_id": event.meta.tenant_id,
        "agent_id": event.meta.agent_id,
        "session_id": event.meta.session_id,
        "run_id": event.meta.run_id,
        "trace_id": event.meta.trace_id,
        "event_id": event.meta.event_id,
        "sequence": event.meta.sequence,
        "tool_name": str(event_payload.get("tool_name", "")),
        "tool_version": str(event_payload.get("tool_version") or ""),
        "tool_integrity_digest": "",
        "invocation_digest": str(event_payload.get("invocation_digest") or ""),
        "capability_fingerprint": "",
        "decision_id": decision.decision_id if decision else "",
        "receipt_id": receipt.receipt_id if receipt else "",
        "disposition": decision.disposition.value if decision else "",
        "reason_code": reason_code,
        "request_id": "",
        "payload_json": json_text(payload),
    }


def gateway_audit_row(record: GatewayAuditRecord) -> dict[str, Any]:
    payload = {
        "action": record.action,
        "outcome": record.outcome,
        "reason_code": record.reason_code,
        "details": json_safe(minimize_value(record.details)),
    }
    return {
        "record_id": record.record_id,
        "source": "gateway",
        "record_type": "gateway",
        "action": record.action,
        "outcome": record.outcome,
        "occurred_at": timestamp_text(record.occurred_at),
        "tenant_id": record.tenant_id,
        "agent_id": record.agent_id,
        "session_id": record.session_id,
        "run_id": record.run_id,
        "trace_id": record.trace_id,
        "event_id": "",
        "sequence": 0,
        "tool_name": record.tool_name,
        "tool_version": record.tool_version,
        "tool_integrity_digest": record.tool_integrity_digest,
        "invocation_digest": record.invocation_digest,
        "capability_fingerprint": record.capability_fingerprint,
        "decision_id": "",
        "receipt_id": "",
        "disposition": "",
        "reason_code": record.reason_code,
        "request_id": record.request_id,
        "payload_json": json_text(payload),
    }


def json_text(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def timestamp_text(value: datetime) -> str:
    return normalize_time(value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def normalize_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _receipt_to_dict(receipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "decision_id": receipt.decision_id,
        "event_id": receipt.event_id,
        "disposition": receipt.disposition.value,
        "enforced": receipt.enforced,
        "adapter": receipt.adapter,
        "details": json_safe(minimize_value(receipt.details)),
        "enforced_at": receipt.enforced_at.isoformat(),
    }


def _agent_record_id(record: AuditRecord) -> str:
    if record.receipt is not None:
        return record.receipt.receipt_id
    if record.decision is not None:
        return record.decision.decision_id
    return record.event.meta.event_id
