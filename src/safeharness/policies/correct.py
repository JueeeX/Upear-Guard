"""Recovery and irreversible-action obligations for tool calls."""

from __future__ import annotations

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


class CorrectPolicy:
    policy_id = "safeharness.correct.recovery"
    subscribed_events = frozenset({EventKind.TOOL_CALL_PROPOSED})

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        catalog = context.services.tool_catalog
        if catalog is None:
            return PolicyVote.abstain()
        descriptor = await catalog.resolve(
            str(event.payload.get("tool_name", "")), event.payload.get("tool_version")
        )
        if descriptor is None:
            return PolicyVote.abstain()

        obligations = []
        if descriptor.sandbox_required:
            obligations.append(Obligation(ObligationKind.SANDBOX))

        if descriptor.reversibility is Reversibility.IRREVERSIBLE:
            obligations.append(Obligation(ObligationKind.REQUIRE_APPROVAL))
            return PolicyVote(
                Disposition.REQUIRE_APPROVAL,
                RiskAssessment(0.85, Severity.HIGH, ("irreversible_action",)),
                (
                    Reason(
                        "irreversible_action_requires_approval",
                        "An irreversible action requires explicit approval.",
                        self.policy_id,
                    ),
                ),
                tuple(obligations),
            )

        if descriptor.reversibility is Reversibility.TRANSACTIONAL:
            obligations.append(
                Obligation(
                    ObligationKind.CHECKPOINT,
                    {"reversibility": descriptor.reversibility.value},
                )
            )
        elif descriptor.reversibility is Reversibility.COMPENSATABLE:
            obligations.append(
                Obligation(
                    ObligationKind.COMPENSATE,
                    {
                        "reversibility": descriptor.reversibility.value,
                        "compensator": descriptor.compensator or "",
                    },
                )
            )
        return PolicyVote.allow(obligations=tuple(obligations))
