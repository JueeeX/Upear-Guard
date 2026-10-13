"""Session-trajectory policy: cross-tool chain rules, repeated-attempt
pressure, and high-entropy payload detection.

AgentGuard-inspired capabilities, rebuilt natively on the SafeHarness policy
contract (no external code). Strictly additive:

- **Off by default**: with no chain rules and both thresholds at ``0`` the
  policy abstains on every event — installing it changes nothing.
- **Deny-only**: like the supplementary regex layer, this policy can only
  block, never un-block what another policy or capability gate denies.
- **Session-scoped state**: the trajectory lives in ``PolicyContext.state``
  under one namespaced key, so it dies with the session (no cross-session
  leakage, no policy-instance growth).
- **No raw payloads in evidence**: entropy findings record the parameter
  name, length, and entropy value — never the payload itself.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping

from safeharness.api.decisions import Disposition, Reason, RiskAssessment, Severity
from safeharness.api.events import EventKind, SecurityEvent
from safeharness.policies.base import PolicyContext, PolicyVote

_TRAJECTORY_STATE_KEY = "safeharness.trajectory.v1"
_SEQUENCE_CAP = 64
_MAX_CHAIN_TAGS = 16


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _normalize_tags(tags: tuple[str, ...], field: str) -> tuple[str, ...]:
    if len(tags) > _MAX_CHAIN_TAGS:
        raise ValueError(f"{field} accepts at most {_MAX_CHAIN_TAGS} tags")
    normalized: list[str] = []
    for tag in tags:
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError(f"{field} entries must be non-empty strings")
        normalized.append(tag.strip())
    return tuple(dict.fromkeys(normalized))


def _endpoint_matches(name: str, tags: tuple[str, ...], pattern: str, rule_tags: tuple[str, ...]) -> bool:
    # Callers guarantee at least one non-empty condition (ChainRule __post_init__).
    if pattern and not re.search(pattern, name, re.IGNORECASE):
        return False
    if rule_tags and not (set(tags) & set(rule_tags)):
        return False
    return True


@dataclass(frozen=True)
class ChainRule:
    """`first` ... (up to ``max_gap`` calls, 0 = any distance) ... `then`.

    Each endpoint may match on tool-name regex, on descriptor tags, or both
    (both given = AND). An empty condition list on an endpoint is a
    configuration error: at least one match condition per side is required.
    """

    name: str
    first: str = ""
    then: str = ""
    severity: str = "high"
    category: str = "trajectory_chain"
    reason: str = ""
    max_gap: int = 0
    first_tags: tuple[str, ...] = ()
    then_tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        first_tags = _normalize_tags(self.first_tags, "first_tags")
        then_tags = _normalize_tags(self.then_tags, "then_tags")
        object.__setattr__(self, "first_tags", first_tags)
        object.__setattr__(self, "then_tags", then_tags)
        try:
            if self.first:
                re.compile(self.first, re.IGNORECASE)
            if self.then:
                re.compile(self.then, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid chain regex: {exc}") from exc
        if self.max_gap < 0:
            raise ValueError("max_gap must be >= 0")
        if not self.first and not first_tags:
            raise ValueError(f"chain rule '{self.name}': endpoint 'first' needs a regex or tags")
        if not self.then and not then_tags:
            raise ValueError(f"chain rule '{self.name}': endpoint 'then' needs a regex or tags")


class TrajectoryPolicy:
    """Cross-tool behaviour checks over the per-session tool-call sequence."""

    policy_id = "safeharness.trajectory"
    subscribed_events = frozenset(
        {
            EventKind.TOOL_CALL_PROPOSED,
            EventKind.TOOL_CALL_SUCCEEDED,
            EventKind.TOOL_CALL_FAILED,
        }
    )

    def __init__(
        self,
        chain_rules: tuple[ChainRule, ...] | list[ChainRule] = (),
        *,
        repeated_attempt_threshold: int = 0,
        entropy_threshold: float = 0.0,
        entropy_min_length: int = 48,
    ) -> None:
        self._chains = tuple(chain_rules)
        for rule in self._chains:
            if not isinstance(rule, ChainRule):
                raise TypeError("chain_rules must contain ChainRule instances")
        if repeated_attempt_threshold < 0:
            raise ValueError("repeated_attempt_threshold must be >= 0")
        if not 0.0 <= entropy_threshold <= 8.0:
            raise ValueError("entropy_threshold must be within [0, 8]")
        self.repeated_attempt_threshold = repeated_attempt_threshold
        self.entropy_threshold = entropy_threshold
        self.entropy_min_length = max(1, entropy_min_length)

    @property
    def configured(self) -> bool:
        """False when the policy is a no-op (every check off)."""
        return bool(self._chains) or self.repeated_attempt_threshold > 0 or self.entropy_threshold > 0

    @staticmethod
    def _trajectory(state: Mapping[str, Any]) -> dict[str, Any]:
        # PolicyContext.state is the session's mutable mapping (see
        # session._evaluate_unlocked); store one namespaced blob per session.
        trajectory = state.get(_TRAJECTORY_STATE_KEY)
        if not isinstance(trajectory, dict):
            trajectory = {"sequence": [], "denials": {}}
            state[_TRAJECTORY_STATE_KEY] = trajectory
        return trajectory

    def _record(
        self,
        trajectory: dict[str, Any],
        tool_name: str,
        outcome: str,
        tags: tuple[str, ...] = (),
    ) -> None:
        sequence = trajectory["sequence"]
        if outcome != "proposed":
            for entry in reversed(sequence):
                if entry[0] == tool_name and entry[1] == "proposed":
                    entry[1] = outcome
                    break
            else:
                sequence.append([tool_name, outcome, list(tags)])
        else:
            sequence.append([tool_name, outcome, list(tags)])
        if len(sequence) > _SEQUENCE_CAP:
            del sequence[: len(sequence) - _SEQUENCE_CAP]

    @staticmethod
    async def _descriptor_tags(
        event: SecurityEvent, context: PolicyContext, tool_name: str
    ) -> tuple[str, ...]:
        """Resolve descriptor tags for the proposed tool.

        No catalog (or unknown tool) yields no tags: tag conditions then simply
        cannot match while name-regex chains keep working. Resolution only
        happens when at least one chain rule actually uses tags, so policies
        without tag rules keep their previous failure surface exactly.
        """
        services = context.services
        catalog = services.tool_catalog if services is not None else None
        if catalog is None:
            return ()
        raw_version = event.payload.get("tool_version")
        version = raw_version if isinstance(raw_version, str) and raw_version else None
        descriptor = await catalog.resolve(tool_name, version)
        if descriptor is None:
            return ()
        return tuple(sorted(str(tag) for tag in descriptor.tags))

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        trajectory = self._trajectory(context.state)
        tool_name = str(event.payload.get("tool_name", ""))
        kind = event.kind

        needs_tags = any(rule.first_tags or rule.then_tags for rule in self._chains)
        current_tags: tuple[str, ...] = ()
        if needs_tags:
            current_tags = await self._descriptor_tags(event, context, tool_name)

        if kind is EventKind.TOOL_CALL_SUCCEEDED:
            self._record(trajectory, tool_name, "succeeded", current_tags)
            trajectory["denials"].pop(tool_name, None)  # success resets pressure
            return PolicyVote.abstain()
        if kind is EventKind.TOOL_CALL_FAILED:
            self._record(trajectory, tool_name, "failed", current_tags)
            trajectory["denials"][tool_name] = trajectory["denials"].get(tool_name, 0) + 1
            return PolicyVote.abstain()

        # ---- TOOL_CALL_PROPOSED: record, then run the pre-execution checks.
        self._record(trajectory, tool_name, "proposed", current_tags)
        sequence = trajectory["sequence"]

        for rule in self._chains:
            if not _endpoint_matches(tool_name, current_tags, rule.then, rule.then_tags):
                continue
            gap = 0
            for entry in reversed(sequence[:-1]):
                if rule.max_gap and gap >= rule.max_gap:
                    break
                entry_tags = tuple(entry[2]) if len(entry) > 2 else ()
                if _endpoint_matches(str(entry[0]), entry_tags, rule.first, rule.first_tags):
                    return PolicyVote.deny(
                        Reason(
                            code="trajectory_chain_rule",
                            message=rule.reason
                            or f"Tool '{tool_name}' matches chain rule '{rule.name}' "
                            f"after '{entry[0]}'.",
                            policy_id=self.policy_id,
                            evidence={
                                "chain_rule": rule.name,
                                "first_tool": str(entry[0]),
                                "then_tool": tool_name,
                                "gap": gap,
                                "first_tags": list(rule.first_tags),
                                "then_tags": list(rule.then_tags),
                            },
                        ),
                        risk=RiskAssessment(1.0, Severity(rule.severity.lower()), (rule.category,)),
                    )
                gap += 1

        if self.repeated_attempt_threshold > 0:
            denials = int(trajectory["denials"].get(tool_name, 0))
            if denials >= self.repeated_attempt_threshold:
                return PolicyVote.deny(
                    Reason(
                        code="trajectory_repeated_attempts",
                        message=f"Tool '{tool_name}' was already denied {denials} times "
                        f"in this session (threshold {self.repeated_attempt_threshold}).",
                        policy_id=self.policy_id,
                        evidence={"tool": tool_name, "denials": denials},
                    ),
                    risk=RiskAssessment(0.9, Severity.HIGH, ("repeated_attempts",)),
                )

        if self.entropy_threshold > 0:
            arguments = event.payload.get("arguments")
            if isinstance(arguments, Mapping):
                for key, value in arguments.items():
                    if not isinstance(value, str) or len(value) < self.entropy_min_length:
                        continue
                    entropy = _shannon_entropy(value)
                    if entropy >= self.entropy_threshold:
                        return PolicyVote.deny(
                            Reason(
                                code="trajectory_high_entropy_payload",
                                message=f"Argument '{key}' looks like encoded/obfuscated "
                                f"payload (entropy {entropy:.2f}).",
                                policy_id=self.policy_id,
                                evidence={
                                    "argument": str(key)[:80],
                                    "length": len(value),
                                    "entropy": round(entropy, 3),
                                },
                            ),
                            risk=RiskAssessment(0.8, Severity.HIGH, ("high_entropy",)),
                        )

        return PolicyVote.abstain()


__all__ = ["ChainRule", "TrajectoryPolicy"]
