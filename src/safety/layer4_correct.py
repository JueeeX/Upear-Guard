"""
Layer 4 — Safe Rollback & Recovery  (CORRECT)

  * State checkpointing at configurable intervals
  * Attack-triggered rollback to last safe checkpoint
  * Graceful degradation (reduce tool privileges progressively, 5 levels)
  * Adaptive recovery (restore one privilege level after sustained safe actions)
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from src.tools.simulated_tools import SimulatedEnvironment

if TYPE_CHECKING:
    from src.safety.memory_protection import MemorySnapshot


@dataclass
class Checkpoint:
    step: int
    filesystem_snapshot: dict[str, str]
    history_length: int
    memory_snapshot: MemorySnapshot | None = None


class RollbackLayer:
    """Manages state checkpoints, rollback, and adaptive degradation/recovery
    (L4 — Correct)."""

    def __init__(self, config: dict[str, Any] | None = None,
                 enabled: bool = True):
        self.config = config or {}
        self.enabled = enabled
        self.interval = self.config.get("checkpoint_interval", 3)
        self.max_degradation = self.config.get("max_degradation_level", 4)
        self.recovery_window = self.config.get("recovery_window", 5)
        self._checkpoints: list[Checkpoint] = []
        self._degradation_level = 0
        self._consecutive_safe = 0

    @property
    def degradation_level(self) -> int:
        return self._degradation_level

    def maybe_checkpoint(self, step: int, env: SimulatedEnvironment,
                         memory_snapshot: MemorySnapshot | None = None):
        if not self.enabled:
            return
        if step % self.interval == 0:
            cp = Checkpoint(
                step=step,
                filesystem_snapshot=copy.deepcopy(env.filesystem),
                history_length=len(env.history),
                memory_snapshot=memory_snapshot,
            )
            self._checkpoints.append(cp)

    def rollback(self, env: SimulatedEnvironment) -> Checkpoint | None:
        """Restore env to the last checkpoint. Returns the checkpoint used,
        or None if rollback was not possible."""
        if not self.enabled or not self._checkpoints:
            return None
        cp = self._checkpoints[-1]
        env.filesystem = copy.deepcopy(cp.filesystem_snapshot)
        env.history = env.history[:cp.history_length]
        self._consecutive_safe = 0
        return cp

    def escalate_degradation(self) -> int:
        """Increase degradation level (reduce L3 Constrain tier ceiling).

          0 = normal (all tiers available)
          1 = destructive tools disabled
          2 = network tools disabled
          3 = execute tools disabled
          4 = write tools disabled (read_only only)

        Actual maximum is capped by ``max_degradation_level`` in config.
        """
        if not self.enabled:
            return 0
        self._degradation_level = min(
            self._degradation_level + 1, self.max_degradation
        )
        self._consecutive_safe = 0
        return self._degradation_level

    def maybe_recover(self):
        """Adaptive recovery: after ``recovery_window`` consecutive safe
        actions, restore one level of privilege."""
        if not self.enabled or self._degradation_level == 0:
            return
        self._consecutive_safe += 1
        if self._consecutive_safe >= self.recovery_window:
            self._degradation_level = max(0, self._degradation_level - 1)
            self._consecutive_safe = 0

    def max_allowed_tier(self) -> str:
        if not self.enabled:
            return "destructive"
        mapping = {
            0: "destructive",
            1: "network",
            2: "execute",
            3: "write",
            4: "read_only",
        }
        return mapping.get(self._degradation_level, "read_only")
