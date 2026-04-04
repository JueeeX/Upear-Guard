"""
Working Memory — fixed-capacity structured memory always present in prompt.

Inspired by MemGPT's "main context" block: a bounded set of entries
that the agent can read every step and explicitly update via tools.
Oldest entries are evicted FIFO when capacity is exceeded.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WMEntry:
    content: str
    source: str  # task | tool_output | agent | user
    step: int = 0


class WorkingMemory:
    """Bounded FIFO working memory that is serialised into the system prompt."""

    def __init__(self, capacity: int = 5):
        self._capacity = capacity
        self._entries: deque[WMEntry] = deque(maxlen=capacity)
        self._update_count = 0

    def update(self, content: str, source: str = "agent", step: int = 0) -> None:
        self._entries.append(WMEntry(content=content, source=source, step=step))
        self._update_count += 1

    def to_prompt_string(self) -> str:
        if not self._entries:
            return "[WORKING MEMORY]\n  (empty)\n[END WORKING MEMORY]"
        lines = ["[WORKING MEMORY]"]
        for e in self._entries:
            lines.append(f"  [{e.source.upper()} step={e.step}] {e.content}")
        lines.append("[END WORKING MEMORY]")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "working_memory_entries": len(self._entries),
            "working_memory_updates": self._update_count,
            "working_memory_capacity": self._capacity,
        }

    def __len__(self) -> int:
        return len(self._entries)
