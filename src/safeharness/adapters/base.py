"""Coverage declarations shared by framework-specific adapters."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum


class Coverage(str, Enum):
    NONE = "none"
    OBSERVE = "observe"
    ENFORCE = "enforce"


BASELINE_REQUIRED_CAPABILITIES = frozenset(
    {
        "input_filter",
        "final_output_filter",
    }
)

PRODUCTION_REQUIRED_CAPABILITIES = frozenset(
    {
        "input_filter",
        "pre_tool_enforcement",
        "tool_argument_rewrite",
        "post_tool_filter",
        "final_output_filter",
        "message_interception",
        "memory_interception",
        "handoff_tracking",
        "subagent_creation",
        "state_checkpoint",
        "checkpoint_rehydration",
    }
)

ADAPTER_LIFECYCLE_CAPABILITIES = PRODUCTION_REQUIRED_CAPABILITIES


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    input_filter: Coverage = Coverage.NONE
    pre_tool_enforcement: Coverage = Coverage.NONE
    tool_argument_rewrite: Coverage = Coverage.NONE
    post_tool_filter: Coverage = Coverage.NONE
    final_output_filter: Coverage = Coverage.NONE
    message_interception: Coverage = Coverage.NONE
    memory_interception: Coverage = Coverage.NONE
    handoff_tracking: Coverage = Coverage.NONE
    subagent_creation: Coverage = Coverage.NONE
    state_checkpoint: Coverage = Coverage.NONE
    checkpoint_rehydration: Coverage = Coverage.NONE
    arbitrary_code_isolation: Coverage = Coverage.NONE

    def to_dict(self) -> dict[str, str]:
        """Return a stable, machine-readable coverage report."""

        return {item.name: getattr(self, item.name).value for item in fields(self)}

    def missing_enforcement(self, required: frozenset[str]) -> frozenset[str]:
        """Return requested capabilities that are not enforceable by this adapter."""

        known = {item.name for item in fields(self)}
        unknown = required - known
        missing = {
            name
            for name in required & known
            if getattr(self, name) is not Coverage.ENFORCE
        }
        return frozenset(unknown | missing)

    @property
    def adapter_lifecycle_complete(self) -> bool:
        """Whether every in-framework lifecycle boundary is enforceable.

        This deliberately excludes process, network, filesystem, and credential
        isolation. Those are deployment controls, not Adapter capabilities.
        """

        return not self.missing_enforcement(ADAPTER_LIFECYCLE_CAPABILITIES)


@dataclass(frozen=True, slots=True)
class DeclaredDeploymentControls:
    """Caller-declared controls that an in-process Adapter cannot verify."""

    process_isolation: Coverage = Coverage.NONE
    network_egress_enforcement: Coverage = Coverage.NONE
    filesystem_enforcement: Coverage = Coverage.NONE
    credential_isolation: Coverage = Coverage.NONE

    def to_dict(self) -> dict[str, str]:
        return {item.name: getattr(self, item.name).value for item in fields(self)}

    @property
    def declared_complete(self) -> bool:
        return all(getattr(self, item.name) is Coverage.ENFORCE for item in fields(self))

    @property
    def complete(self) -> bool:
        """Compatibility alias; completeness is declared, not attested."""

        return self.declared_complete


DeploymentControls = DeclaredDeploymentControls
