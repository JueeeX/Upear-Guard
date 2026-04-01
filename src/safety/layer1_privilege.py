"""
Layer 1 — Privilege-Separated Tool Control  (CONSTRAIN)

Enforces platform-level access control:
  * Tool partitioning by risk tier
  * Capability-token validation (time-limited, invocation-capped)
  * Tool-description integrity checks (HMAC signature)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from src.tools.registry import ToolRegistry, CapabilityToken, verify_signature, verify_token_signature


@dataclass
class L1Decision:
    allowed: bool
    reason: str = ""


class PrivilegeSeparationLayer:
    """Checks every tool invocation against the privilege policy."""

    TIER_ORDER = ["read_only", "write", "execute", "network", "destructive"]

    def __init__(self, registry: ToolRegistry,
                 max_allowed_tier: str = "network",
                 config: dict[str, Any] | None = None,
                 enabled: bool = True):
        self.registry = registry
        self.max_allowed_tier = max_allowed_tier
        self.config = config or {}
        self.enabled = enabled
        self._tokens: dict[str, CapabilityToken] = {}

    def issue_session_tokens(self, agent_id: str = "primary"):
        """Issue capability tokens for all registered tools, respecting
        the current tier ceiling.  Called once per harness execution."""
        for spec in self.registry.list_tools(self.max_allowed_tier):
            token = self.registry.issue_token(
                spec.name, agent_id,
                ttl_seconds=self.config.get("token_ttl", 600),
                max_invocations=self.config.get("token_max_invocations", 50),
            )
            self._tokens[spec.name] = token

    def check(self, tool_name: str, arguments: dict[str, Any]) -> L1Decision:
        if not self.enabled:
            return L1Decision(True)

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

        # Capability-token validation (signature + expiry + invocation cap)
        token = self._tokens.get(tool_name)
        if token is not None:
            if not verify_token_signature(token):
                return L1Decision(
                    False,
                    f"Capability token for '{tool_name}' has invalid signature "
                    "— possible token forgery."
                )
            if not token.is_valid():
                return L1Decision(
                    False,
                    f"Capability token for '{tool_name}' expired or exhausted "
                    f"(used {token.invocations_used}/{token.max_invocations})."
                )
            token.consume()

        # Path-based constraints from config
        denied_paths = self.config.get("denied_paths", [])
        path_arg = arguments.get("path", "")
        if path_arg:
            if ".." in path_arg:
                return L1Decision(
                    False,
                    f"Path '{path_arg}' contains traversal components.")
            normalised = os.path.normpath(path_arg)
            for dp in denied_paths:
                dp_norm = os.path.normpath(dp)
                if normalised == dp_norm or normalised.startswith(dp_norm + os.sep):
                    return L1Decision(False,
                                      f"Path '{path_arg}' is in the deny-list.")

        return L1Decision(True)
