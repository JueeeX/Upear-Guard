"""
Cross-Layer — Memory Protection & Entropy Monitoring

  * Provenance-tagged persistent memory
  * Anomaly detection on memory writes
  * Entropy drift scoring
"""

from __future__ import annotations

import hashlib
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
    """Tracks coarse entropy metrics over the execution lifetime."""

    def __init__(self):
        self.constraint_violations = 0
        self.total_actions = 0

    def record_action(self, violated: bool = False):
        self.total_actions += 1
        if violated:
            self.constraint_violations += 1

    def entropy_score(self) -> float:
        if self.total_actions == 0:
            return 0.0
        return self.constraint_violations / self.total_actions

    def is_drifting(self, threshold: float = 0.3) -> bool:
        return self.entropy_score() > threshold
