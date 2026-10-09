"""Stateless runtime factory for isolated security sessions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from safeharness.api.context import SessionContext
from safeharness.policies import (
    ConstrainPolicy,
    CorrectPolicy,
    FailureMode,
    InformPolicy,
    IntentBindingPolicy,
    LifecycleBoundaryPolicy,
    PolicyEngine,
    SecurityPolicy,
    SqlGuardPolicy,
    VerifyPolicy,
)
from safeharness.runtime.services import RuntimeServices

if TYPE_CHECKING:
    from safeharness.runtime.session import SecuritySession


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    policy_version: str = "unversioned"
    policy_failure_mode: FailureMode = FailureMode.DENY
    auto_start_sessions: bool = True
    allow_empty_policy_set: bool = False


class SafeHarnessRuntime:
    """Reusable runtime containing only immutable policy and backend references."""

    def __init__(
        self,
        policies: tuple[SecurityPolicy, ...] | list[SecurityPolicy] | None = None,
        *,
        services: RuntimeServices | None = None,
        config: RuntimeConfig | None = None,
    ) -> None:
        self.config = config or RuntimeConfig()
        configured_services = services or RuntimeServices()
        self.services = configured_services
        active_policies: tuple[SecurityPolicy, ...] | list[SecurityPolicy]
        if policies is None:
            active_policies = (
                InformPolicy(),
                LifecycleBoundaryPolicy(),
                ConstrainPolicy(),
                SqlGuardPolicy(),
                IntentBindingPolicy(),
                VerifyPolicy(),
                CorrectPolicy(),
            )
        else:
            active_policies = policies
        if not active_policies and not self.config.allow_empty_policy_set:
            raise ValueError(
                "an empty policy set disables all protection; set "
                "RuntimeConfig(allow_empty_policy_set=True) only for tests or "
                "explicit unprotected evaluation"
            )
        self.policy_engine = PolicyEngine(
            active_policies,
            policy_version=self.config.policy_version,
            failure_mode=self.config.policy_failure_mode,
        )

    def session(self, context: SessionContext) -> "SecuritySession":
        """Create a fresh mutable security boundary for exactly one run."""

        from safeharness.runtime.session import SecuritySession

        return SecuritySession(self, context)
