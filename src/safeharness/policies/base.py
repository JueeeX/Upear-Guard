"""Policy contracts and partial votes aggregated by the policy engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, MutableMapping, Protocol, runtime_checkable

from safeharness.api._mapping import frozen_mapping
from safeharness.api.context import SessionContext
from safeharness.api.decisions import (
    Disposition,
    Obligation,
    Reason,
    RiskAssessment,
)
from safeharness.api.events import EventKind, SecurityEvent
from safeharness.runtime.services import RuntimeServices


class FailureMode(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DEFER = "defer"


@dataclass(slots=True)
class PolicyContext:
    session: SessionContext
    state: MutableMapping[str, Any]
    services: RuntimeServices


@dataclass(frozen=True, slots=True)
class PolicyVote:
    disposition: Disposition | None = None
    risk: RiskAssessment = field(default_factory=RiskAssessment)
    reasons: tuple[Reason, ...] = ()
    obligations: tuple[Obligation, ...] = ()
    replacement_payload: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.replacement_payload is not None:
            object.__setattr__(
                self, "replacement_payload", frozen_mapping(self.replacement_payload)
            )

    @classmethod
    def abstain(cls) -> "PolicyVote":
        return cls()

    @classmethod
    def allow(
        cls,
        *,
        risk: RiskAssessment | None = None,
        reasons: tuple[Reason, ...] = (),
        obligations: tuple[Obligation, ...] = (),
        replacement_payload: Mapping[str, Any] | None = None,
    ) -> "PolicyVote":
        return cls(
            Disposition.ALLOW,
            risk or RiskAssessment(),
            reasons,
            obligations,
            replacement_payload,
        )

    @classmethod
    def deny(
        cls,
        reason: Reason,
        *,
        risk: RiskAssessment | None = None,
        obligations: tuple[Obligation, ...] = (),
    ) -> "PolicyVote":
        return cls(
            Disposition.DENY,
            risk or RiskAssessment(score=1.0),
            (reason,),
            obligations,
        )

    @classmethod
    def modify(
        cls,
        payload: Mapping[str, Any],
        reason: Reason,
        *,
        risk: RiskAssessment | None = None,
        obligations: tuple[Obligation, ...] = (),
    ) -> "PolicyVote":
        return cls(
            Disposition.MODIFY,
            risk or RiskAssessment(),
            (reason,),
            obligations,
            payload,
        )


@runtime_checkable
class SecurityPolicy(Protocol):
    policy_id: str
    subscribed_events: frozenset[EventKind]

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        """Evaluate one canonical event without executing framework actions."""
