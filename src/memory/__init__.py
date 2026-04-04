"""
Agent memory module for the MemoryHarness.

Provides MemGPT-style hierarchical memory: a bounded WorkingMemory
(always in prompt) and an unbounded ArchivalMemory (keyword retrieval).
"""

from src.memory.working_memory import WorkingMemory
from src.memory.archival_memory import ArchivalMemory

__all__ = ["WorkingMemory", "ArchivalMemory"]
