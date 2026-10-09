"""Bind external side effects to the latest inspected user intent."""

from __future__ import annotations

import hmac
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
from safeharness.api.intent import TRUSTED_USER_INTENT_STATE_KEY
from safeharness.api.tools import Reversibility
from safeharness.policies.base import PolicyContext, PolicyVote
from safeharness.ports import JudgeRequest


class IntentBindingPolicy:
    """Require high-risk tool calls to match a recently inspected user request.

    A semantic judge can reject or escalate an apparently bound call, but it
    cannot create an intent record or bypass deterministic digest matching.
    """

    policy_id = "safeharness.verify.intent_binding"
    subscribed_events = frozenset({EventKind.TOOL_CALL_PROPOSED})

    _sensitive_key_fragments = (
        "api_key",
        "authorization",
        "credential",
        "password",
        "secret",
        "token",
    )
    semantic_min_confidence = 0.5

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        catalog = context.services.tool_catalog
        if catalog is None:
            return PolicyVote.abstain()
        descriptor = await catalog.resolve(
            str(event.payload.get("tool_name", "")), event.payload.get("tool_version")
        )
        if descriptor is None or not self._requires_binding(descriptor):
            return PolicyVote.abstain()

        intent = context.state.get(TRUSTED_USER_INTENT_STATE_KEY)
        if not isinstance(intent, Mapping) or not intent.get("active"):
            return self._deny(
                "trusted_user_intent_required",
                "An external side effect requires a current, inspected user intent.",
            )
        expected_digest = intent.get("digest")
        supplied_digest = event.payload.get("intent_digest")
        if not isinstance(expected_digest, str) or not isinstance(supplied_digest, str):
            return self._deny(
                "tool_intent_binding_missing",
                "The tool call is not cryptographically bound to the current user intent.",
            )
        if not hmac.compare_digest(expected_digest, supplied_digest):
            return self._deny(
                "tool_intent_binding_mismatch",
                "The tool call is bound to a different or stale user intent.",
            )

        judge = context.services.judge_provider
        if judge is None:
            return PolicyVote(
                disposition=Disposition.REQUIRE_APPROVAL,
                risk=RiskAssessment(
                    0.75,
                    Severity.HIGH,
                    ("intent_alignment", "judge_unavailable"),
                ),
                reasons=(
                    Reason(
                        "judge_unavailable_for_intent_alignment",
                        "An effectful call requires approval because semantic intent "
                        "alignment is unavailable.",
                        self.policy_id,
                        {"intent_digest": expected_digest},
                    ),
                ),
                obligations=(Obligation(ObligationKind.REQUIRE_APPROVAL),),
            )

        result = await judge.judge(
            JudgeRequest(
                purpose="tool_intent_alignment",
                content={
                    "user_intent": str(intent.get("content", "")),
                    "intent_digest": expected_digest,
                    "tool_name": descriptor.name,
                    "tool_version": descriptor.version,
                    "arguments": self._redact(event.payload.get("arguments", {})),
                    "resource": event.payload.get("resource"),
                    "side_effects": sorted(descriptor.side_effects),
                    "reversibility": descriptor.reversibility.value,
                },
                risk_hint=0.85,
                data_classifications=descriptor.data_classifications,
            )
        )
        label = result.label.strip().upper()
        risk = RiskAssessment(
            max(0.85, result.confidence),
            Severity.HIGH,
            ("intent_alignment", "semantic_judge"),
        )
        if (
            label in {"SAFE", "ALIGNED", "LEGITIMATE"}
            and result.confidence >= self.semantic_min_confidence
        ):
            return PolicyVote.allow(
                risk=risk,
                reasons=(
                    Reason(
                        "tool_intent_aligned",
                        result.reason or "The judge found the call aligned with user intent.",
                        self.policy_id,
                        {
                            "intent_digest": expected_digest,
                            "provider": result.provider,
                            "model": result.model,
                        },
                    ),
                ),
            )
        if label in {"UNSAFE", "INJECTION", "MISALIGNED"}:
            return PolicyVote.deny(
                Reason(
                    "judge_unsafe",
                    result.reason or "The judge rejected alignment with user intent.",
                    self.policy_id,
                    {"provider": result.provider, "model": result.model},
                ),
                risk=risk,
            )
        return PolicyVote(
            disposition=Disposition.REQUIRE_APPROVAL,
            risk=risk,
            reasons=(
                Reason(
                    "judge_intent_uncertain",
                    result.reason or "Intent alignment could not be established.",
                    self.policy_id,
                    {"provider": result.provider, "model": result.model},
                ),
            ),
            obligations=(Obligation(ObligationKind.REQUIRE_APPROVAL),),
        )

    def _deny(self, code: str, message: str) -> PolicyVote:
        return PolicyVote.deny(
            Reason(code, message, self.policy_id),
            risk=RiskAssessment(1.0, Severity.HIGH, ("intent_binding",)),
        )

    @staticmethod
    def _requires_binding(descriptor) -> bool:
        return bool(descriptor.side_effects) or (
            descriptor.reversibility is not Reversibility.READ_ONLY
        )

    @classmethod
    def _redact(cls, value: Any, key: str = "") -> Any:
        normalized_key = key.lower().replace("-", "_")
        if any(fragment in normalized_key for fragment in cls._sensitive_key_fragments):
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {
                str(item_key): cls._redact(item, str(item_key))
                for item_key, item in value.items()
            }
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [cls._redact(item) for item in value]
        return value
