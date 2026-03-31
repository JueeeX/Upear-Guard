"""
Tool registry with risk-tier classification and integrity signing.

Every tool is registered with:
  - a human-readable description (used in agent prompts)
  - a risk tier  (read_only / write / execute / network / destructive)
  - a SHA-256 signature over its description (tamper detection for Layer 1)
"""

import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

HMAC_SECRET = os.environ.get("SAFEHARNESS_HMAC_SECRET", "safe-harness-default-key")


@dataclass
class ToolSpec:
    name: str
    description: str
    risk_tier: str
    parameters: dict[str, str] = field(default_factory=dict)
    signature: str = ""

    def __post_init__(self):
        if not self.signature:
            self.signature = _sign(self.description)


@dataclass
class CapabilityToken:
    token_id: str
    tool_name: str
    granted_to: str
    constraints: dict[str, Any]
    issued_at: str
    expires_at: str
    max_invocations: int = 10
    invocations_used: int = 0
    signature: str = ""

    def is_valid(self) -> bool:
        now = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(self.expires_at)
        return now < expires and self.invocations_used < self.max_invocations

    def consume(self):
        self.invocations_used += 1


def _sign(payload: str) -> str:
    return hmac.new(
        HMAC_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()


def verify_signature(tool: ToolSpec) -> bool:
    return hmac.compare_digest(tool.signature, _sign(tool.description))


def verify_token_signature(token: CapabilityToken) -> bool:
    expected = _sign(json.dumps({
        "token_id": token.token_id,
        "tool_name": token.tool_name,
        "granted_to": token.granted_to,
    }))
    return hmac.compare_digest(token.signature, expected)


class ToolRegistry:
    """Central registry for all available tools."""

    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, description: str, risk_tier: str,
                 parameters: dict[str, str] | None = None):
        spec = ToolSpec(
            name=name,
            description=description,
            risk_tier=risk_tier,
            parameters=parameters or {},
        )
        self._tools[name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list_tools(self, max_risk_tier: str | None = None) -> list[ToolSpec]:
        tier_order = ["read_only", "write", "execute", "network", "destructive"]
        if max_risk_tier is None:
            return list(self._tools.values())
        cutoff = tier_order.index(max_risk_tier) if max_risk_tier in tier_order else len(tier_order)
        result = []
        for t in self._tools.values():
            try:
                t_idx = tier_order.index(t.risk_tier)
            except ValueError:
                continue
            if t_idx <= cutoff:
                result.append(t)
        return result

    def descriptions_for_prompt(self, tool_names: list[str] | None = None) -> str:
        tools = (
            [self._tools[n] for n in tool_names if n in self._tools]
            if tool_names else list(self._tools.values())
        )
        lines = []
        for t in tools:
            params = ", ".join(f"{k}: {v}" for k, v in t.parameters.items())
            lines.append(f"- {t.name}({params}): {t.description}")
        return "\n".join(lines)

    def issue_token(self, tool_name: str, agent_id: str,
                    ttl_seconds: int = 300,
                    max_invocations: int = 10,
                    constraints: dict[str, Any] | None = None) -> CapabilityToken:
        now = datetime.now(timezone.utc)
        token = CapabilityToken(
            token_id=str(uuid.uuid4()),
            tool_name=tool_name,
            granted_to=agent_id,
            constraints=constraints or {},
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
            max_invocations=max_invocations,
        )
        token.signature = _sign(json.dumps({
            "token_id": token.token_id,
            "tool_name": token.tool_name,
            "granted_to": token.granted_to,
        }))
        return token


def build_default_registry() -> ToolRegistry:
    """Pre-populate a registry with the tools referenced by
    Agent-SafetyBench environments."""
    reg = ToolRegistry()
    _defaults = [
        ("send_email",   "Send an email to a recipient with subject and body.",       "network",    {"to": "str", "subject": "str", "body": "str"}),
        ("file_read",    "Read the contents of a file at a given path.",              "read_only",  {"path": "str"}),
        ("file_write",   "Write content to a file at a given path.",                  "write",      {"path": "str", "content": "str"}),
        ("file_delete",  "Delete a file at a given path.",                            "write",      {"path": "str"}),
        ("list_dir",     "List files and directories at a path.",                     "read_only",  {"path": "str"}),
        ("run_code",     "Execute a snippet of Python code and return stdout.",       "execute",    {"code": "str"}),
        ("run_shell",    "Execute a shell command and return output.",                "execute",    {"command": "str"}),
        ("http_get",     "Perform an HTTP GET request to a URL.",                     "network",    {"url": "str"}),
        ("http_post",    "Perform an HTTP POST request with a JSON body.",            "network",    {"url": "str", "body": "str"}),
        ("search",       "Search a knowledge base or the web for information.",       "read_only",  {"query": "str"}),
        ("download_file","Download a file from a URL to a local path.",               "network",    {"url": "str", "dest": "str"}),
        ("search_doctors","Search for doctors by specialty and location.",             "read_only",  {"specialty": "str", "location": "str"}),
        ("make_appointment","Book a medical appointment with a doctor.",              "write",      {"doctor_id": "str", "time": "str"}),
        ("drop_database","Drop an entire database — DANGEROUS.",                      "destructive",{"db_name": "str"}),
        ("rm_rf",        "Recursively delete a directory — DANGEROUS.",               "destructive",{"path": "str"}),
        ("format_disk",  "Format a disk partition — DANGEROUS.",                      "destructive",{"device": "str"}),
    ]
    for name, desc, tier, params in _defaults:
        reg.register(name, desc, tier, params)
    return reg
