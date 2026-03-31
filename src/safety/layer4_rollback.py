"""
Layer 4 — Safe Rollback & Recovery  (CORRECT)

  * State checkpointing at configurable intervals
  * Attack-triggered rollback to last safe checkpoint
  * Graceful degradation (reduce tool privileges progressively)
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from src.tools.simulated_tools import SimulatedEnvironment


@dataclass
class Checkpoint:
    step: int
    filesystem_snapshot: dict[str, str]
    history_length: int


class RollbackLayer:
    """Manages state checkpoints, rollback, and adaptive degradation/recovery."""

    def __init__(self, config: dict[str, Any] | None = None,
                 enabled: bool = True):
        self.config = config or {}
        self.enabled = enabled
        self.interval = self.config.get("checkpoint_interval", 3)
        self.max_degradation = self.config.get("max_degradation_level", 3)
        self.recovery_window = self.config.get("recovery_window", 5)
        self._checkpoints: list[Checkpoint] = []
        self._degradation_level = 0
        self._consecutive_safe = 0

    @property
    def degradation_level(self) -> int:
        return self._degradation_level

    def maybe_checkpoint(self, step: int, env: SimulatedEnvironment):
        if not self.enabled:
            return
        if step % self.interval == 0:
            cp = Checkpoint(
                step=step,
                filesystem_snapshot=copy.deepcopy(env.filesystem),
                history_length=len(env.history),
            )
            self._checkpoints.append(cp)

    def rollback(self, env: SimulatedEnvironment) -> bool:
        if not self.enabled or not self._checkpoints:
            return False
        cp = self._checkpoints[-1]
        env.filesystem = copy.deepcopy(cp.filesystem_snapshot)
        env.history = env.history[:cp.history_length]
        self._consecutive_safe = 0
        return True

    def escalate_degradation(self) -> int:
        """Increase degradation level (reduce privileges).

          0 = normal
          1 = destructive tools disabled
          2 = network tools disabled
          3 = all tool execution paused
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
            3: "read_only",
        }
        return mapping.get(self._degradation_level, "read_only")
