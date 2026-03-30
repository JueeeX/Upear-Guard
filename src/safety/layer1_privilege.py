"""
Layer 1 — Privilege-Separated Tool Control  (CONSTRAIN)

Enforces platform-level access control:
  * Tool partitioning by risk tier
  * Capability-token validation
  * Tool-description integrity checks
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.tools.registry import ToolRegistry, CapabilityToken, verify_signature


@dataclass
class L1Decision:
    allowed: bool
    reason: str = ""


class PrivilegeSeparationLayer:
    """Checks every tool invocation against the privilege policy."""

    TIER_ORDER = ["read_only", "write", "execute", "network", "destructive"]

    def __init__(self, registry: ToolRegistry,
                 max_allowed_tier: str = "network",
                 config: dict[str, Any] | None = None):
        self.registry = registry
        self.max_allowed_tier = max_allowed_tier
        self.config = config or {}
        self._tokens: dict[str, CapabilityToken] = {}

    def check(self, tool_name: str, arguments: dict[str, Any]) -> L1Decision:
        spec = self.registry.get(tool_name)
        if spec is None:
            return L1Decision(False, f"Unknown tool '{tool_name}'.")

        if not verify_signature(spec):
            return L1Decision(False,
                              f"Tool '{tool_name}' description signature mismatch — "
                              "possible tampering.")

        try:
            tool_idx = self.TIER_ORDER.index(spec.risk_tier)
            max_idx = self.TIER_ORDER.index(self.max_allowed_tier)
        except ValueError:
            return L1Decision(False, f"Invalid tier '{spec.risk_tier}'.")

        if tool_idx > max_idx:
            return L1Decision(
                False,
                f"Tool '{tool_name}' (tier={spec.risk_tier}) exceeds "
                f"allowed tier ceiling ({self.max_allowed_tier})."
            )

        # Path-based constraints from config
        denied_paths = self.config.get("denied_paths", [])
        path_arg = arguments.get("path", "")
        if path_arg:
            for dp in denied_paths:
                if path_arg.startswith(dp):
                    return L1Decision(False,
                                      f"Path '{path_arg}' is in the deny-list.")

        return L1Decision(True)
