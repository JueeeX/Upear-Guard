"""Deterministic limits for explicit memory and sub-Agent adapter boundaries."""

from __future__ import annotations

from collections.abc import Sequence

from safeharness.api.decisions import Reason, RiskAssessment, Severity
from safeharness.api.events import EventKind, SecurityEvent
from safeharness.policies.base import PolicyContext, PolicyVote


class LifecycleBoundaryPolicy:
    policy_id = "safeharness.lifecycle.boundaries"
    subscribed_events = frozenset(
        {
            EventKind.MEMORY_WRITE_PROPOSED,
            EventKind.SUBAGENT_CREATION_PROPOSED,
        }
    )

    def __init__(
        self,
        *,
        max_memory_write_bytes: int = 256 * 1024,
        max_subagent_depth: int = 4,
    ) -> None:
        if not 1 <= max_memory_write_bytes <= 16 * 1024 * 1024:
            raise ValueError("max_memory_write_bytes must be between 1 byte and 16 MiB")
        if not 1 <= max_subagent_depth <= 32:
            raise ValueError("max_subagent_depth must be between 1 and 32")
        self.max_memory_write_bytes = int(max_memory_write_bytes)
        self.max_subagent_depth = int(max_subagent_depth)

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        if event.kind is EventKind.MEMORY_WRITE_PROPOSED:
            return self._memory_vote(event)
        if event.kind is EventKind.SUBAGENT_CREATION_PROPOSED:
            return self._subagent_vote(event)
        return PolicyVote.abstain()

    def _memory_vote(self, event: SecurityEvent) -> PolicyVote:
        size = event.payload.get("serialized_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            return self._deny(
                "memory_write_size_invalid",
                "The adapter did not provide a valid memory-write size.",
                "memory",
            )
        if size > self.max_memory_write_bytes:
            return self._deny(
                "memory_write_too_large",
                "The proposed memory value exceeds the configured size limit.",
                "memory",
            )
        return PolicyVote.allow()

    def _subagent_vote(self, event: SecurityEvent) -> PolicyVote:
        if event.payload.get("constraint_allowed") is not True:
            reason = str(event.payload.get("constraint_reason", ""))
            allowed_reasons = {
                "subagent_capability_escalation",
                "subagent_depth_exceeded",
                "subagent_target_denied",
            }
            code = reason if reason in allowed_reasons else "subagent_creation_denied"
            return self._deny(
                code,
                "The sub-Agent request violates the adapter's trusted constraints.",
                "subagent",
            )
        depth = event.payload.get("depth")
        if not isinstance(depth, int) or isinstance(depth, bool) or depth < 1:
            return self._deny(
                "subagent_depth_invalid",
                "The adapter did not provide a valid sub-Agent depth.",
                "subagent",
            )
        if depth > self.max_subagent_depth:
            return self._deny(
                "subagent_depth_exceeded",
                "The sub-Agent nesting depth exceeds the runtime ceiling.",
                "subagent",
            )
        requested = event.payload.get("requested_capabilities", ())
        delegated = event.payload.get("delegated_capabilities", ())
        if not self._string_sequence(requested) or not self._string_sequence(delegated):
            return self._deny(
                "subagent_capabilities_invalid",
                "The adapter provided invalid sub-Agent capability metadata.",
                "subagent",
            )
        if not set(requested).issubset(delegated):
            return self._deny(
                "subagent_capability_escalation",
                "The sub-Agent requested capabilities not delegated by its parent.",
                "subagent",
            )
        return PolicyVote.allow()

    @staticmethod
    def _string_sequence(value: object) -> bool:
        return isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ) and all(isinstance(item, str) and item for item in value)

    def _deny(self, code: str, message: str, category: str) -> PolicyVote:
        return PolicyVote.deny(
            Reason(code, message, self.policy_id),
            risk=RiskAssessment(0.9, Severity.HIGH, (category,)),
        )
