"""Stable service-provider interfaces for framework and backend integrations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, runtime_checkable
from uuid import uuid4

from safeharness.api._mapping import frozen_mapping
from safeharness.api.context import SessionContext
from safeharness.api.decisions import Decision, EnforcementReceipt, Obligation
from safeharness.api.events import SecurityEvent
from safeharness.api.tools import ToolDescriptor, ToolInvocation


@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    allowed: bool
    reason: str = ""
    reason_code: str = "capability_denied"
    obligations: tuple[Obligation, ...] = ()
    claims: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "claims", frozen_mapping(self.claims))


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    """An authority-issued, signed claim for exactly one tool invocation."""

    token: str
    token_id: str
    expires_at: datetime
    subject: str
    tenant_id: str
    session_id: str
    run_id: str
    tool_name: str
    tool_version: str
    tool_integrity_digest: str
    invocation_digest: str


@runtime_checkable
class CapabilityIssuer(Protocol):
    async def issue(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        *,
        expires_at: datetime | None = None,
    ) -> CapabilityGrant:
        """Issue a narrowly bound capability claim for a concrete invocation."""


@runtime_checkable
class EnforcementReceiptIssuer(Protocol):
    async def issue(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        *,
        decision_id: str,
        event_id: str,
        policy_version: str,
        expires_at: datetime | None = None,
        workload_id: str = "",
    ) -> str:
        """Issue a signed proof that policy allowed this exact invocation."""


@runtime_checkable
class EnforcementReceiptSignatureSigner(Protocol):
    @property
    def algorithm(self) -> str:
        """Return the signed-envelope algorithm identifier."""

    @property
    def key_id(self) -> str:
        """Return the non-secret verification-key identifier."""

    async def sign(self, message: bytes) -> bytes:
        """Sign an exact receipt-envelope message through a private-key boundary."""


@runtime_checkable
class EnforcementReceiptSignatureVerifier(Protocol):
    @property
    def algorithm(self) -> str:
        """Return the only accepted signed-envelope algorithm identifier."""

    @property
    def key_id(self) -> str:
        """Return the verification-key identifier selected by the envelope."""

    async def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify an exact receipt-envelope message without signing authority."""


@runtime_checkable
class CapabilityReplayStore(Protocol):
    async def consume(self, token_id: str, expires_at: datetime) -> bool:
        """Atomically mark a capability token as used, returning ``False`` on replay."""


@dataclass(frozen=True, slots=True)
class EnforcementReceiptVerification:
    """Sanitized result of verifying a control-plane enforcement proof."""

    allowed: bool
    reason: str = ""
    reason_code: str = "enforcement_receipt_invalid"
    claims: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "claims", frozen_mapping(self.claims))


@runtime_checkable
class EnforcementReceiptReplayStore(Protocol):
    async def consume(self, receipt_id: str, expires_at: datetime) -> bool:
        """Atomically mark a receipt ID as consumed, returning ``False`` on replay."""


@runtime_checkable
class EnforcementReceiptVerifier(Protocol):
    async def verify(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        receipt: str | None,
        *,
        consume: bool = False,
        expected_decision_id: str | None = None,
        expected_event_id: str | None = None,
        expected_policy_version: str | None = None,
        workload_id: str | None = None,
    ) -> EnforcementReceiptVerification:
        """Verify a receipt and optionally consume its replay identity."""


@dataclass(frozen=True, slots=True)
class JudgeRequest:
    purpose: str
    content: Mapping[str, Any]
    risk_hint: float = 0.0
    data_classifications: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", frozen_mapping(self.content))


@dataclass(frozen=True, slots=True)
class JudgeResult:
    label: str
    confidence: float
    reason: str = ""
    provider: str = ""
    model: str = ""
    judge_status: str = "ok"
    judge_calls: int = 1
    judge_result_class: str = "unspecified"

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("judge confidence must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class CheckpointRef:
    checkpoint_id: str
    backend: str
    scope: str


@dataclass(frozen=True, slots=True)
class RestoreReceipt:
    checkpoint_id: str
    restored: bool
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", frozen_mapping(self.details))


@dataclass(frozen=True, slots=True)
class CompensationReceipt:
    compensation_id: str
    compensated: bool
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", frozen_mapping(self.details))


@dataclass(frozen=True, slots=True)
class ApprovalResult:
    approved: bool
    approver: str = ""
    reason: str = ""
    approval_id: str = ""


@dataclass(frozen=True, slots=True)
class AuditRecord:
    record_type: str
    event: SecurityEvent
    decision: Decision | None = None
    receipt: EnforcementReceipt | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", frozen_mapping(self.details))


class ToolCatalog(Protocol):
    async def resolve(self, tool_name: str, version: str | None = None) -> ToolDescriptor | None:
        """Return the canonical descriptor for a tool, or ``None`` if unknown."""


@runtime_checkable
class CapabilityAuthority(Protocol):
    async def authorize(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
    ) -> AuthorizationResult:
        """Authorize a concrete invocation after arguments are normalized."""


@runtime_checkable
class JudgeProvider(Protocol):
    async def judge(self, request: JudgeRequest) -> JudgeResult:
        """Perform optional semantic or contextual verification."""


@runtime_checkable
class StateBackend(Protocol):
    async def capture(
        self, context: SessionContext, invocation: ToolInvocation
    ) -> CheckpointRef:
        """Capture recoverable agent or environment state before execution."""

    async def restore(self, checkpoint: CheckpointRef) -> RestoreReceipt:
        """Restore a previously captured state snapshot."""


@runtime_checkable
class CompensationProvider(Protocol):
    async def compensate(
        self,
        context: SessionContext,
        invocation: ToolInvocation,
        result: Any,
        reason: str,
    ) -> CompensationReceipt:
        """Compensate an already committed external side effect."""


@runtime_checkable
class ApprovalBroker(Protocol):
    async def request(
        self, context: SessionContext, event: SecurityEvent, decision: Decision
    ) -> ApprovalResult:
        """Request an out-of-band approval for a proposed action."""


@runtime_checkable
class AuditSink(Protocol):
    async def write(self, record: AuditRecord) -> None:
        """Persist a structured, redacted audit record."""


@dataclass(frozen=True, slots=True)
class GatewayAuditRecord:
    """Sanitized audit fact emitted by the independent tool gateway."""

    action: str
    outcome: str
    tenant_id: str = ""
    agent_id: str = ""
    session_id: str = ""
    run_id: str = ""
    trace_id: str = ""
    tool_name: str = ""
    tool_version: str = ""
    tool_integrity_digest: str = ""
    invocation_digest: str = ""
    capability_fingerprint: str = ""
    reason_code: str = ""
    request_id: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)
    record_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.action or not self.outcome:
            raise ValueError("gateway audit action and outcome are required")
        if self.occurred_at.tzinfo is None:
            raise ValueError("gateway audit timestamps must be timezone-aware")
        object.__setattr__(self, "details", frozen_mapping(self.details))


@runtime_checkable
class GatewayAuditSink(Protocol):
    async def write_gateway(self, record: GatewayAuditRecord) -> None:
        """Persist a sanitized gateway security or execution record."""
