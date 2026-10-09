"""Framework-neutral tool metadata and invocation results."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from safeharness.api._mapping import frozen_mapping
from safeharness.api.decisions import Decision, EnforcementReceipt


class Reversibility(str, Enum):
    READ_ONLY = "read_only"
    TRANSACTIONAL = "transactional"
    COMPENSATABLE = "compensatable"
    IRREVERSIBLE = "irreversible"


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    name: str
    version: str = "1"
    description: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    required_capabilities: frozenset[str] = frozenset()
    side_effects: frozenset[str] = frozenset()
    data_classifications: frozenset[str] = frozenset()
    reversibility: Reversibility = Reversibility.READ_ONLY
    idempotent: bool = True
    compensator: str | None = None
    sandbox_required: bool = False
    integrity_digest: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("tool name must not be empty")
        object.__setattr__(self, "input_schema", frozen_mapping(self.input_schema))
        canonical = json.dumps(
            {
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "input_schema": _strict_json_value(self.input_schema),
                "required_capabilities": sorted(self.required_capabilities),
                "side_effects": sorted(self.side_effects),
                "data_classifications": sorted(self.data_classifications),
                "reversibility": self.reversibility.value,
                "idempotent": self.idempotent,
                "compensator": self.compensator,
                "sandbox_required": self.sandbox_required,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        computed_digest = hashlib.sha256(canonical).hexdigest()
        if self.integrity_digest and self.integrity_digest != computed_digest:
            raise ValueError("tool integrity digest does not match its security metadata")
        object.__setattr__(self, "integrity_digest", computed_digest)


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    call_id: str = field(default_factory=lambda: str(uuid4()))
    tool_version: str | None = None
    resource: str | None = None
    capability_token: str | None = None
    intent_digest: str | None = None
    # A control-plane authorization proof.  It is deliberately separate from
    # the capability token and is not included in the invocation digest.
    enforcement_receipt: str | None = None

    def __post_init__(self) -> None:
        if not self.tool_name:
            raise ValueError("tool_name must not be empty")
        if not self.call_id:
            object.__setattr__(self, "call_id", str(uuid4()))
        if self.tool_version == "":
            object.__setattr__(self, "tool_version", None)
        if self.resource == "":
            object.__setattr__(self, "resource", None)
        if self.capability_token == "":
            object.__setattr__(self, "capability_token", None)
        if self.intent_digest == "":
            object.__setattr__(self, "intent_digest", None)
        if self.enforcement_receipt == "":
            object.__setattr__(self, "enforcement_receipt", None)
        if self.intent_digest is not None and (
            len(self.intent_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.intent_digest)
        ):
            raise ValueError("intent_digest must be a lowercase SHA-256 hex digest")
        object.__setattr__(self, "arguments", frozen_mapping(self.arguments))


@dataclass(frozen=True, slots=True)
class ToolExecutionOutcome:
    decision: Decision
    receipt: EnforcementReceipt
    result: Any = None
    blocked: bool = False
    error: str | None = None
    checkpoint_ref: str | None = None
    compensation_ref: str | None = None
    recovery_attempted: bool = False
    recovery_succeeded: bool | None = None
    external_effect_may_persist: bool = False


def _strict_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _strict_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strict_json_value(item) for item in value]
    raise TypeError(
        "tool input_schema must contain only JSON-compatible values; "
        f"got {type(value).__module__}.{type(value).__qualname__}"
    )
