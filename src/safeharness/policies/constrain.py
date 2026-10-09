"""Tool-catalog and capability enforcement policy."""

from __future__ import annotations

from safeharness.api.decisions import Reason, RiskAssessment, Severity
from safeharness.api.events import EventKind, SecurityEvent
from safeharness.api.tools import ToolInvocation
from safeharness.policies._schema import validate_arguments
from safeharness.policies.base import PolicyContext, PolicyVote


class ConstrainPolicy:
    policy_id = "safeharness.constrain.capabilities"
    subscribed_events = frozenset({EventKind.TOOL_CALL_PROPOSED})

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        catalog = context.services.tool_catalog
        authority = context.services.capability_authority
        if catalog is None or authority is None:
            return PolicyVote.deny(
                Reason(
                    "authorization_backend_unavailable",
                    "Tool authorization is not configured; denying by default.",
                    self.policy_id,
                ),
                risk=RiskAssessment(1.0, Severity.HIGH, ("authorization",)),
            )

        invocation = ToolInvocation(
            tool_name=str(event.payload.get("tool_name", "")),
            arguments=event.payload.get("arguments", {}),
            call_id=str(event.payload.get("call_id", "")),
            tool_version=event.payload.get("tool_version"),
            resource=event.payload.get("resource"),
            capability_token=event.payload.get("capability_token"),
            intent_digest=event.payload.get("intent_digest"),
            enforcement_receipt=event.payload.get("enforcement_receipt"),
        )
        descriptor = await catalog.resolve(invocation.tool_name, invocation.tool_version)
        if descriptor is None:
            return PolicyVote.deny(
                Reason(
                    "unknown_tool",
                    "The requested tool is not present in the trusted catalog.",
                    self.policy_id,
                    {"tool_name": invocation.tool_name},
                ),
                risk=RiskAssessment(1.0, Severity.HIGH, ("unknown_tool",)),
            )

        schema_errors = validate_arguments(invocation.arguments, descriptor.input_schema)
        if schema_errors:
            return PolicyVote.deny(
                Reason(
                    "invalid_tool_arguments",
                    "Tool arguments do not satisfy the trusted input schema.",
                    self.policy_id,
                    {"errors": schema_errors[:10]},
                ),
                risk=RiskAssessment(0.8, Severity.HIGH, ("schema_violation",)),
            )

        result = await authority.authorize(context.session, descriptor, invocation)
        if not result.allowed:
            return PolicyVote.deny(
                Reason(
                    result.reason_code,
                    result.reason or "The capability authority denied this tool call.",
                    self.policy_id,
                ),
                risk=RiskAssessment(0.9, Severity.HIGH, ("capability",)),
                obligations=result.obligations,
            )
        return PolicyVote.allow(
            reasons=(
                Reason(
                    "capability_authorized",
                    "The trusted capability authority authorized this tool call.",
                    self.policy_id,
                    {
                        "tool_integrity_digest": descriptor.integrity_digest,
                        "tool_version": descriptor.version,
                        "idempotent": descriptor.idempotent,
                        "claims": dict(result.claims),
                    },
                ),
            ),
            obligations=result.obligations,
        )
