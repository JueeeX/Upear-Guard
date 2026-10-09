"""Tiered action verification independent of any agent framework."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from safeharness.api.decisions import (
    Disposition,
    Obligation,
    ObligationKind,
    Reason,
    RiskAssessment,
    Severity,
)
from safeharness.api.events import EventKind, SecurityEvent
from safeharness.api.tools import Reversibility
from safeharness.policies.base import PolicyContext, PolicyVote
from safeharness.ports import JudgeRequest


class VerifyPolicy:
    """Use deterministic risk signals before optionally invoking a judge.

    The judge never grants capabilities. It can only add scrutiny after the
    deterministic catalog and capability checks performed by ``ConstrainPolicy``.
    Sensitive argument keys are redacted before an external judge sees them.
    """

    policy_id = "safeharness.verify.tiered"
    subscribed_events = frozenset({EventKind.TOOL_CALL_PROPOSED})

    _sensitive_key_fragments = (
        "api_key",
        "authorization",
        "credential",
        "password",
        "secret",
        "token",
    )

    def __init__(
        self,
        *,
        judge_threshold: float = 0.3,
        approval_threshold: float = 0.8,
    ) -> None:
        if not 0.0 <= judge_threshold <= approval_threshold <= 1.0:
            raise ValueError(
                "expected 0 <= judge_threshold <= approval_threshold <= 1"
            )
        self.judge_threshold = judge_threshold
        self.approval_threshold = approval_threshold

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        catalog = context.services.tool_catalog
        if catalog is None:
            return PolicyVote.abstain()
        descriptor = await catalog.resolve(
            str(event.payload.get("tool_name", "")), event.payload.get("tool_version")
        )
        if descriptor is None:
            return PolicyVote.abstain()

        risk = self._risk_for(descriptor)
        if risk.score < self.judge_threshold:
            return PolicyVote.allow(risk=risk)

        judge = context.services.judge_provider
        if judge is None:
            if risk.score >= self.approval_threshold:
                return self._require_approval(
                    risk,
                    "judge_unavailable_for_high_risk_action",
                    "A high-risk action requires review because no judge is configured.",
                )
            return PolicyVote.allow(
                risk=risk,
                reasons=(
                    Reason(
                        "deterministic_verification_only",
                        "The action was evaluated without an optional semantic judge.",
                        self.policy_id,
                    ),
                ),
            )

        arguments = self._redact(event.payload.get("arguments", {}))
        result = await judge.judge(
            JudgeRequest(
                purpose="tool_action_safety",
                content={
                    "tool_name": descriptor.name,
                    "tool_version": descriptor.version,
                    "arguments": arguments,
                    "side_effects": sorted(descriptor.side_effects),
                    "reversibility": descriptor.reversibility.value,
                },
                risk_hint=risk.score,
                data_classifications=descriptor.data_classifications,
            )
        )
        label = result.label.strip().upper()
        judged_risk = RiskAssessment(
            max(risk.score, result.confidence if label == "UNSAFE" else risk.score),
            Severity.HIGH if label == "UNSAFE" else risk.severity,
            risk.categories + ("semantic_judge",),
        )
        if label == "SAFE":
            return PolicyVote.allow(
                risk=judged_risk,
                reasons=(Reason("judge_safe", result.reason, self.policy_id),),
            )
        if label == "UNSAFE":
            return PolicyVote.deny(
                Reason(
                    "judge_unsafe",
                    result.reason or "The semantic judge rejected the action.",
                    self.policy_id,
                    {"provider": result.provider, "model": result.model},
                ),
                risk=judged_risk,
            )
        return self._require_approval(
            judged_risk,
            "judge_uncertain",
            result.reason or "The semantic judge could not establish action safety.",
        )

    def _require_approval(
        self, risk: RiskAssessment, code: str, message: str
    ) -> PolicyVote:
        return PolicyVote(
            disposition=Disposition.REQUIRE_APPROVAL,
            risk=risk,
            reasons=(Reason(code, message, self.policy_id),),
            obligations=(Obligation(ObligationKind.REQUIRE_APPROVAL),),
        )

    @staticmethod
    def _risk_for(descriptor) -> RiskAssessment:
        score = 0.05
        categories: list[str] = []
        if descriptor.side_effects:
            score = max(score, 0.35)
            categories.append("side_effect")
        if descriptor.data_classifications:
            score = max(score, 0.65)
            categories.append("sensitive_data")
        if descriptor.sandbox_required:
            score = max(score, 0.7)
            categories.append("sandbox_required")
        reversibility_scores = {
            Reversibility.READ_ONLY: 0.05,
            Reversibility.TRANSACTIONAL: 0.5,
            Reversibility.COMPENSATABLE: 0.6,
            Reversibility.IRREVERSIBLE: 0.85,
        }
        score = max(score, reversibility_scores[descriptor.reversibility])
        if descriptor.reversibility is not Reversibility.READ_ONLY:
            categories.append(descriptor.reversibility.value)
        severity = (
            Severity.HIGH if score >= 0.8
            else Severity.MEDIUM if score >= 0.5
            else Severity.LOW
        )
        return RiskAssessment(score, severity, tuple(categories))

    @classmethod
    def _redact(cls, value: Any, key: str = "") -> Any:
        normalized_key = key.lower().replace("-", "_")
        if any(fragment in normalized_key for fragment in cls._sensitive_key_fragments):
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {str(k): cls._redact(v, str(k)) for k, v in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [cls._redact(item) for item in value]
        return value
