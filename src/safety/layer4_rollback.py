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
    """Manages state checkpoints and rollback / degradation."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.interval = self.config.get("checkpoint_interval", 3)
        self.max_degradation = self.config.get("max_degradation_level", 3)
        self._checkpoints: list[Checkpoint] = []
        self._degradation_level = 0

    @property
    def degradation_level(self) -> int:
        return self._degradation_level

    def maybe_checkpoint(self, step: int, env: SimulatedEnvironment):
        """Save a checkpoint if we've reached the interval."""
        if step % self.interval == 0:
            cp = Checkpoint(
                step=step,
                filesystem_snapshot=copy.deepcopy(env.filesystem),
                history_length=len(env.history),
            )
            self._checkpoints.append(cp)

    def rollback(self, env: SimulatedEnvironment) -> bool:
        """Roll back environment to the most recent checkpoint.
        Returns True on success."""
        if not self._checkpoints:
            return False
        cp = self._checkpoints[-1]
        env.filesystem = copy.deepcopy(cp.filesystem_snapshot)
        env.history = env.history[:cp.history_length]
        return True

    def escalate_degradation(self) -> int:
        """Move one level deeper in graceful degradation.

        Returns the new degradation level:
          0 = normal
          1 = destructive tools disabled
          2 = network tools disabled
          3 = all tool execution paused
        """
        self._degradation_level = min(
            self._degradation_level + 1, self.max_degradation
        )
        return self._degradation_level

    def max_allowed_tier(self) -> str:
        """Translate current degradation level to a max-allowed tool tier."""
        mapping = {
            0: "destructive",
            1: "network",
            2: "execute",
            3: "read_only",
        }
        return mapping.get(self._degradation_level, "read_only")
