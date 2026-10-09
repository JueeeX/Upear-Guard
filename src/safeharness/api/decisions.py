"""Policy decisions and proof-of-enforcement records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from safeharness.api._mapping import frozen_mapping, json_safe
from safeharness.api.events import SecurityEvent


class Disposition(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    REQUIRE_APPROVAL = "require_approval"
    DEFER = "defer"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ObligationKind(str, Enum):
    CHECKPOINT = "checkpoint"
    REDACT = "redact"
    DEGRADE = "degrade"
    SANDBOX = "sandbox"
    REQUIRE_APPROVAL = "require_approval"
    ROLLBACK = "rollback"
    COMPENSATE = "compensate"
    AUDIT = "audit"


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: float = 0.0
    severity: Severity = Severity.INFO
    categories: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("risk score must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class Reason:
    code: str
    message: str
    policy_id: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", frozen_mapping(self.evidence))


@dataclass(frozen=True, slots=True)
class Obligation:
    kind: ObligationKind
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameters", frozen_mapping(self.parameters))


@dataclass(frozen=True, slots=True)
class Decision:
    disposition: Disposition
    effective_event: SecurityEvent
    risk: RiskAssessment = field(default_factory=RiskAssessment)
    reasons: tuple[Reason, ...] = ()
    obligations: tuple[Obligation, ...] = ()
    policy_version: str = "unversioned"
    decision_id: str = field(default_factory=lambda: str(uuid4()))
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def executable(self) -> bool:
        return self.disposition in (Disposition.ALLOW, Disposition.MODIFY)

    @property
    def blocked(self) -> bool:
        return not self.executable

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "disposition": self.disposition.value,
            "effective_event": self.effective_event.to_dict(),
            "risk": {
                "score": self.risk.score,
                "severity": self.risk.severity.value,
                "categories": list(self.risk.categories),
            },
            "reasons": [
                {
                    "code": reason.code,
                    "message": reason.message,
                    "policy_id": reason.policy_id,
                    "evidence": json_safe(reason.evidence),
                }
                for reason in self.reasons
            ],
            "obligations": [
                {
                    "kind": obligation.kind.value,
                    "parameters": json_safe(obligation.parameters),
                }
                for obligation in self.obligations
            ],
            "policy_version": self.policy_version,
            "decided_at": self.decided_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class EnforcementReceipt:
    decision_id: str
    event_id: str
    disposition: Disposition
    enforced: bool
    adapter: str
    details: Mapping[str, Any] = field(default_factory=dict)
    receipt_id: str = field(default_factory=lambda: str(uuid4()))
    enforced_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", frozen_mapping(self.details))
