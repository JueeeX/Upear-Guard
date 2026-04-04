"""
Archival Memory — unbounded persistent store with keyword retrieval.

Inspired by MemGPT's "archival storage": the agent can explicitly
store facts and later retrieve them by keyword query.  Uses simple
word-overlap scoring to keep the framework dependency-free (no
external vector DB or embedding model required).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ArchivalEntry:
    content: str
    step: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


def _tokenise(text: str) -> set[str]:
    return set(re.findall(r"\w+", text.lower()))


class ArchivalMemory:
    """Append-only archival store with keyword-overlap retrieval."""

    def __init__(self):
        self._entries: list[ArchivalEntry] = []
        self._retrieve_count = 0

    def store(self, content: str, step: int = 0,
              metadata: dict[str, Any] | None = None) -> None:
        self._entries.append(ArchivalEntry(
            content=content, step=step, metadata=metadata or {},
        ))

    def retrieve(self, query: str, k: int = 3) -> list[ArchivalEntry]:
        """Return the *k* entries whose content has highest word overlap
        with *query*.  Ties are broken by recency (later entries first)."""
        self._retrieve_count += 1
        if not self._entries:
            return []
        q_tokens = _tokenise(query)
        if not q_tokens:
            return list(reversed(self._entries[-k:]))

        scored: list[tuple[float, int, ArchivalEntry]] = []
        for idx, entry in enumerate(self._entries):
            e_tokens = _tokenise(entry.content)
            overlap = len(q_tokens & e_tokens)
            scored.append((overlap, idx, entry))

        scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
        return [entry for _, _, entry in scored[:k]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "archival_entries": len(self._entries),
            "archival_retrieves": self._retrieve_count,
        }

    def __len__(self) -> int:
        return len(self._entries)
