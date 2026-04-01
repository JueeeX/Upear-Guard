"""
Cross-Layer — Memory Protection & Entropy Monitoring

  * Provenance-tagged persistent memory
  * Anomaly detection on memory writes
  * Sliding-window entropy drift scoring
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class MemoryEntry:
    key: str
    value: str
    source_type: str  # user | tool | agent | system
    source_agent: str = ""
    timestamp: str = ""
    hash: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.hash:
            self.hash = hashlib.sha256(self.value.encode()).hexdigest()[:16]


@dataclass
class MemorySnapshot:
    store: dict[str, MemoryEntry]
    history_length: int


class ProtectedMemory:
    """Append-only memory store with provenance tracking."""

    def __init__(self):
        self._store: dict[str, MemoryEntry] = {}
        self._history: list[MemoryEntry] = []

    def write(self, key: str, value: str,
              source_type: str = "agent", source_agent: str = ""):
        entry = MemoryEntry(key=key, value=value,
                            source_type=source_type,
                            source_agent=source_agent)
        self._store[key] = entry
        self._history.append(entry)

    def read(self, key: str) -> MemoryEntry | None:
        return self._store.get(key)

    def snapshot(self) -> MemorySnapshot:
        """Capture current memory state for checkpoint/rollback."""
        return MemorySnapshot(
            store=dict(self._store),
            history_length=len(self._history),
        )

    def restore(self, snap: MemorySnapshot):
        """Restore memory to a previous snapshot, discarding later writes."""
        self._store = dict(snap.store)
        self._history = self._history[:snap.history_length]

    def detect_anomalies(self) -> list[str]:
        """Simple anomaly checks on the memory history."""
        issues: list[str] = []
        seen_hashes: dict[str, str] = {}
        for entry in self._history:
            if entry.key in seen_hashes:
                if entry.hash != seen_hashes[entry.key]:
                    issues.append(
                        f"Memory key '{entry.key}' mutated "
                        f"(prev={seen_hashes[entry.key][:8]}, "
                        f"new={entry.hash[:8]})."
                    )
            seen_hashes[entry.key] = entry.hash

        untrusted_writes = sum(
            1 for e in self._history if e.source_type not in ("system", "user")
        )
        if untrusted_writes > len(self._history) * 0.8 and len(self._history) > 3:
            issues.append(
                f"High ratio of non-system memory writes "
                f"({untrusted_writes}/{len(self._history)})."
            )
        return issues


class EntropyMonitor:
    """Sliding-window entropy monitor that tracks the violation rate
    over the most recent *window_size* actions, making it sensitive
    to short-term bursts of anomalous activity."""

    def __init__(self, window_size: int = 20, threshold: float = 0.3):
        self._window: deque[bool] = deque(maxlen=window_size)
        self._threshold = threshold
        self.total_actions = 0
        self.constraint_violations = 0

    def record_action(self, violated: bool = False):
        self.total_actions += 1
        if violated:
            self.constraint_violations += 1
        self._window.append(violated)

    def entropy_score(self) -> float:
        """Violation rate within the sliding window."""
        if not self._window:
            return 0.0
        return sum(self._window) / len(self._window)

    def is_drifting(self, threshold: float | None = None) -> bool:
        return self.entropy_score() > (threshold if threshold is not None
                                       else self._threshold)
