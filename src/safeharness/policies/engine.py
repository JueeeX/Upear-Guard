"""Deterministic aggregation of ordered policy votes."""

from __future__ import annotations

from safeharness.api.decisions import (
    Decision,
    Disposition,
    Reason,
    RiskAssessment,
    Severity,
)
from safeharness.api.events import SecurityEvent
from safeharness.policies.base import FailureMode, PolicyContext, PolicyVote, SecurityPolicy


_PRECEDENCE = {
    None: 0,
    Disposition.ALLOW: 1,
    Disposition.MODIFY: 2,
    Disposition.DEFER: 3,
    Disposition.REQUIRE_APPROVAL: 4,
    Disposition.DENY: 5,
}


class PolicyEngine:
    """Evaluate policies in a stable order and combine their decisions."""

    def __init__(
        self,
        policies: tuple[SecurityPolicy, ...] | list[SecurityPolicy] = (),
        *,
        policy_version: str = "unversioned",
        failure_mode: FailureMode = FailureMode.DENY,
    ) -> None:
        self._policies = tuple(policies)
        self.policy_version = policy_version
        self.failure_mode = failure_mode

    @property
    def policies(self) -> tuple[SecurityPolicy, ...]:
        return self._policies

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> Decision:
        current_event = event
        disposition: Disposition | None = None
        reasons = []
        obligations = []
        highest_risk = RiskAssessment()

        for policy in self._policies:
            if current_event.kind not in policy.subscribed_events:
                continue
            try:
                vote = await policy.evaluate(current_event, context)
            except Exception as exc:  # policy isolation boundary
                vote = self._failure_vote(policy.policy_id, exc)

            if vote.replacement_payload is not None:
                current_event = current_event.with_payload(vote.replacement_payload)
            if _PRECEDENCE[vote.disposition] > _PRECEDENCE[disposition]:
                disposition = vote.disposition
            reasons.extend(vote.reasons)
            for obligation in vote.obligations:
                if obligation not in obligations:
                    obligations.append(obligation)
            if vote.risk.score > highest_risk.score:
                highest_risk = vote.risk

            if vote.disposition is Disposition.DENY:
                break

        if disposition is None:
            disposition = Disposition.ALLOW

        return Decision(
            disposition=disposition,
            effective_event=current_event,
            risk=highest_risk,
            reasons=tuple(reasons),
            obligations=tuple(obligations),
            policy_version=self.policy_version,
        )

    def _failure_vote(self, policy_id: str, exc: Exception) -> PolicyVote:
        reason = Reason(
            code="policy_evaluation_failed",
            message="A security policy failed to produce a valid decision.",
            policy_id=policy_id,
            evidence={"exception_type": type(exc).__name__},
        )
        risk = RiskAssessment(1.0, Severity.HIGH, ("policy_failure",))
        if self.failure_mode is FailureMode.ALLOW:
            return PolicyVote.allow(risk=risk, reasons=(reason,))
        if self.failure_mode is FailureMode.DEFER:
            return PolicyVote(Disposition.DEFER, risk, (reason,))
        return PolicyVote.deny(reason, risk=risk)
