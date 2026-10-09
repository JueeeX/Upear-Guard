"""Injected backend services shared by otherwise stateless runtime objects."""

from __future__ import annotations

from dataclasses import dataclass

from safeharness.ports import (
    ApprovalBroker,
    AuditSink,
    CapabilityAuthority,
    EnforcementReceiptIssuer,
    CompensationProvider,
    JudgeProvider,
    StateBackend,
    ToolCatalog,
)


@dataclass(frozen=True, slots=True)
class RuntimeServices:
    tool_catalog: ToolCatalog | None = None
    capability_authority: CapabilityAuthority | None = None
    enforcement_receipt_issuer: EnforcementReceiptIssuer | None = None
    judge_provider: JudgeProvider | None = None
    state_backend: StateBackend | None = None
    compensation_provider: CompensationProvider | None = None
    approval_broker: ApprovalBroker | None = None
    audit_sink: AuditSink | None = None
