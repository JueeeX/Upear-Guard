"""
SafeHarness unified security pipeline — composes all four layers into
a single ``check_action`` interface consumed by harness implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.safety.layer1_privilege import PrivilegeSeparationLayer
from src.safety.layer2_filtering import AdversarialContextFilter
from src.safety.layer3_verification import CausalSafetyVerifier
from src.safety.layer4_rollback import RollbackLayer
from src.safety.memory_protection import ProtectedMemory, EntropyMonitor
from src.tools.registry import ToolRegistry
from src.tools.simulated_tools import SimulatedEnvironment


@dataclass
class SecurityDecision:
    blocked: bool
    reason: str = ""
    layer: str = ""
    risk_score: float = 0.0


class SecurityPipeline:
    """Runs every tool call through Layers 1-3 and manages Layer 4 state."""

    def __init__(self, registry: ToolRegistry,
                 config: dict[str, Any] | None = None,
                 judge_model: str | None = None):
        cfg = config or {}
        self.l1 = PrivilegeSeparationLayer(
            registry,
            max_allowed_tier="network",
            config=cfg.get("layer1", {}),
        )
        self.l2 = AdversarialContextFilter(
            config=cfg.get("layer2", {}),
            judge_model=judge_model,
        )
        self.l3 = CausalSafetyVerifier(
            config=cfg.get("layer3", {}),
            judge_model=judge_model,
        )
        self.l4 = RollbackLayer(config=cfg.get("layer4", {}))
        self.memory = ProtectedMemory()
        self.entropy = EntropyMonitor()
        self._step = 0

    def filter_context(self, text: str, source: str = "user_input") -> str:
        """Pass content through Layer 2 before it enters the agent."""
        result = self.l2.filter(text, source_type=source)
        if result.injection_detected:
            self.entropy.record_action(violated=True)
        return result.cleaned

    def check_action(self, tool_name: str, arguments: dict[str, Any],
                     env: SimulatedEnvironment) -> SecurityDecision:
        """Called by the harness before each tool execution."""
        self._step += 1
        self.l4.maybe_checkpoint(self._step, env)

        # Apply degradation ceiling
        self.l1.max_allowed_tier = self.l4.max_allowed_tier()

        # Layer 1 — privilege check
        l1d = self.l1.check(tool_name, arguments)
        if not l1d.allowed:
            self.entropy.record_action(violated=True)
            return SecurityDecision(True, l1d.reason, "layer1")

        # Layer 3 — tiered verification
        context = " ".join(str(v) for v in arguments.values())
        l3d = self.l3.verify(tool_name, arguments, context)
        self.entropy.record_action(violated=(l3d.label == "UNSAFE"))

        if l3d.label == "UNSAFE":
            if l3d.is_attack:
                self.l4.rollback(env)
                self.l4.escalate_degradation()
            return SecurityDecision(True, l3d.feedback, f"layer3_tier{l3d.tier_triggered}",
                                    l3d.risk_score)

        self.memory.write(
            f"action_{self._step}",
            f"{tool_name}({arguments})",
            source_type="agent",
        )
        return SecurityDecision(False, risk_score=l3d.risk_score)


class BoltOnPipeline:
    """Simplified bolt-on defence (pattern check + Tier-1 rules only).
    Represents the 'external module' baseline."""

    def __init__(self, registry: ToolRegistry,
                 config: dict[str, Any] | None = None,
                 judge_model: str | None = None):
        cfg = config or {}
        self.l2 = AdversarialContextFilter(
            config=cfg.get("layer2", {}), judge_model=None)
        self.l3 = CausalSafetyVerifier(
            config=cfg.get("layer3", {}), judge_model=None)

    def filter_context(self, text: str, source: str = "user_input") -> str:
        return self.l2.filter(text, source_type=source).cleaned

    def check_action(self, tool_name: str, arguments: dict[str, Any],
                     env: SimulatedEnvironment) -> SecurityDecision:
        v = self.l3.verify(tool_name, arguments)
        if v.label == "UNSAFE":
            return SecurityDecision(True, v.feedback, "bolt_on")
        return SecurityDecision(False, risk_score=v.risk_score)
