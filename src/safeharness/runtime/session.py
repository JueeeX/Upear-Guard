"""Per-run event sequencing, policy evaluation, and tool enforcement."""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Mapping

from safeharness.api.context import SessionContext
from safeharness.api.decisions import (
    Decision,
    Disposition,
    EnforcementReceipt,
    ObligationKind,
    Reason,
    RiskAssessment,
    Severity,
)
from safeharness.api.events import ContentSource, EventKind, EventMeta, SecurityEvent
from safeharness.api.intent import TRUSTED_USER_INTENT_STATE_KEY, user_intent_digest
from safeharness.api.tools import Reversibility, ToolExecutionOutcome, ToolInvocation
from safeharness.policies import PolicyContext
from safeharness.ports import AuditRecord, CheckpointRef
from safeharness.runtime.redaction import minimize_decision, minimize_event


ToolExecutor = Callable[[ToolInvocation], Any | Awaitable[Any]]

if TYPE_CHECKING:
    from safeharness.runtime.runtime import SafeHarnessRuntime


_RUNTIME_ENFORCED_OBLIGATIONS = frozenset(
    {
        ObligationKind.AUDIT,
        ObligationKind.CHECKPOINT,
        ObligationKind.COMPENSATE,
        ObligationKind.REQUIRE_APPROVAL,
    }
)


class SecuritySession:
    """An isolated, serialized security state machine for one agent run."""

    def __init__(self, runtime: "SafeHarnessRuntime", context: SessionContext) -> None:
        self.runtime = runtime
        self.context = context
        self._sequence = 0
        self._state: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._tool_lock = asyncio.Lock()
        self._started = False
        self._closed = False
        self._start_decision: Decision | None = None

    @property
    def state(self) -> Mapping[str, Any]:
        return dict(self._state)

    @property
    def current_intent_digest(self) -> str | None:
        intent = self._state.get(TRUSTED_USER_INTENT_STATE_KEY)
        if not isinstance(intent, Mapping) or not intent.get("active"):
            return None
        digest = intent.get("digest")
        return digest if isinstance(digest, str) else None

    def bind_invocation(self, invocation: ToolInvocation) -> ToolInvocation:
        """Bind a proposed call to the current inspected user intent, if any."""

        if invocation.enforcement_receipt is not None:
            raise ValueError(
                "enforcement receipts are issued internally after policy approval"
            )
        if invocation.intent_digest is not None:
            return invocation
        digest = self.current_intent_digest
        if digest is None:
            return invocation
        return ToolInvocation(
            tool_name=invocation.tool_name,
            arguments=invocation.arguments,
            call_id=invocation.call_id,
            tool_version=invocation.tool_version,
            resource=invocation.resource,
            capability_token=invocation.capability_token,
            intent_digest=digest,
            enforcement_receipt=invocation.enforcement_receipt,
        )

    async def __aenter__(self) -> "SecuritySession":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.close(error=type(exc).__name__ if exc is not None else None)

    async def start(self) -> Decision:
        async with self._lock:
            if self._closed:
                raise RuntimeError("security session is already closed")
            if self._start_decision is not None:
                return self._start_decision
            self._started = True
            self._start_decision = await self._evaluate_unlocked(EventKind.RUN_STARTED, {})
            return self._start_decision

    async def close(self, *, error: str | None = None) -> Decision | None:
        # Closing waits for any in-flight tool wrapper to reach a terminal event.
        async with self._tool_lock:
            async with self._lock:
                if self._closed:
                    return None
                if not self._started:
                    self._started = True
                    self._start_decision = await self._evaluate_unlocked(
                        EventKind.RUN_STARTED, {}
                    )
                decision = await self._evaluate_unlocked(
                    EventKind.RUN_FINISHED, {"error_type": error}
                )
                self._closed = True
                return decision

    async def evaluate(
        self, kind: EventKind, payload: Mapping[str, Any] | None = None
    ) -> Decision:
        if not self._started and self.runtime.config.auto_start_sessions:
            await self.start()
        elif not self._started:
            raise RuntimeError("security session has not been started")
        async with self._lock:
            if self._closed:
                raise RuntimeError("security session is already closed")
            return await self._evaluate_unlocked(kind, payload or {})

    async def inspect_content(
        self,
        content: str,
        *,
        source: ContentSource | str = ContentSource.USER_INPUT,
        attributes: Mapping[str, Any] | None = None,
    ) -> Decision:
        return await self.evaluate(
            EventKind.CONTENT_RECEIVED,
            {
                "content": content,
                "source": source.value if isinstance(source, ContentSource) else source,
                "attributes": dict(attributes or {}),
            },
        )

    async def record_model_response(self, content: str) -> Decision:
        return await self.evaluate(EventKind.MODEL_RESPONDED, {"content": content})

    async def inspect_final_output(self, content: str) -> Decision:
        return await self.evaluate(
            EventKind.FINAL_OUTPUT_PROPOSED,
            {"content": content, "source": ContentSource.AGENT_OUTPUT.value},
        )

    async def around_tool(
        self,
        invocation: ToolInvocation,
        executor: ToolExecutor,
        *,
        adapter: str = "generic",
        enforced_obligations: frozenset[ObligationKind] = frozenset(),
    ) -> ToolExecutionOutcome:
        """Enforce pre- and post-tool policies around one native executor."""

        async with self._tool_lock:
            return await self._around_tool_serialized(
                invocation,
                executor,
                adapter=adapter,
                enforced_obligations=enforced_obligations,
            )

    async def _around_tool_serialized(
        self,
        invocation: ToolInvocation,
        executor: ToolExecutor,
        *,
        adapter: str,
        enforced_obligations: frozenset[ObligationKind],
    ) -> ToolExecutionOutcome:

        invocation = self.bind_invocation(invocation)
        pre_decision = await self.evaluate(
            EventKind.TOOL_CALL_PROPOSED, self._invocation_payload(invocation)
        )

        approval_details: dict[str, Any] = {}
        if pre_decision.disposition is Disposition.REQUIRE_APPROVAL:
            broker = self.runtime.services.approval_broker
            if broker is None:
                pre_decision = self._deny(
                    pre_decision,
                    "approval_backend_unavailable",
                    "Approval is required but no approval broker is configured.",
                )
            else:
                try:
                    approval = await broker.request(
                        self.context, pre_decision.effective_event, pre_decision
                    )
                except Exception as exc:
                    pre_decision = self._deny(
                        pre_decision,
                        "approval_backend_failed",
                        f"The approval backend failed ({type(exc).__name__}).",
                    )
                else:
                    approval_details = {
                        "approval_id": approval.approval_id,
                        "approver": approval.approver,
                    }
                    if approval.approved and approval.approval_id and approval.approver:
                        pre_decision = self._approval_granted(
                            pre_decision, approval.reason
                        )
                    elif approval.approved:
                        pre_decision = self._deny(
                            pre_decision,
                            "invalid_approval_receipt",
                            "Approved actions require an approval ID and approver identity.",
                        )
                    else:
                        pre_decision = self._deny(
                            pre_decision,
                            "approval_denied",
                            approval.reason or "The requested action was not approved.",
                        )

        if pre_decision.blocked:
            return await self._blocked_outcome(
                pre_decision, adapter, {"phase": "pre_tool", **approval_details}
            )

        effective_invocation = self._effective_invocation(pre_decision, invocation)
        unsupported = {
            obligation.kind
            for obligation in pre_decision.obligations
            if obligation.kind not in _RUNTIME_ENFORCED_OBLIGATIONS
            and obligation.kind not in enforced_obligations
        }
        if unsupported:
            pre_decision = self._deny(
                pre_decision,
                "adapter_cannot_enforce_obligation",
                "The active adapter cannot enforce a required sandbox obligation.",
            )
            return await self._blocked_outcome(
                pre_decision,
                adapter,
                {"unsupported_obligations": sorted(item.value for item in unsupported)},
            )

        try:
            checkpoint = await self._capture_checkpoint_if_required(
                pre_decision, effective_invocation
            )
        except Exception as exc:
            pre_decision = self._deny(
                pre_decision,
                "checkpoint_backend_failed",
                f"The checkpoint backend failed ({type(exc).__name__}).",
            )
            return await self._blocked_outcome(
                pre_decision, adapter, {"phase": "pre_tool"}
            )
        if self._requires_checkpoint(pre_decision) and checkpoint is None:
            pre_decision = self._deny(
                pre_decision,
                "checkpoint_backend_unavailable",
                "The action requires recoverable state but no checkpoint was created.",
            )
            return await self._blocked_outcome(pre_decision, adapter, {"phase": "pre_tool"})

        if self._requires_compensation(pre_decision):
            if self.runtime.services.compensation_provider is None:
                pre_decision = self._deny(
                    pre_decision,
                    "compensation_backend_unavailable",
                    "The action requires compensation support but none is configured.",
                )
                return await self._blocked_outcome(
                    pre_decision, adapter, {"phase": "pre_tool"}
                )

        pre_receipt = EnforcementReceipt(
            decision_id=pre_decision.decision_id,
            event_id=pre_decision.effective_event.meta.event_id,
            disposition=pre_decision.disposition,
            enforced=True,
            adapter=adapter,
            details={"phase": "pre_tool", **approval_details},
        )
        await self._audit_receipt(pre_decision, pre_receipt)
        try:
            effective_invocation = await self._attach_enforcement_receipt(
                pre_decision, effective_invocation
            )
        except Exception as exc:
            pre_decision = self._deny(
                pre_decision,
                "enforcement_receipt_issuance_failed",
                f"The enforcement receipt issuer failed ({type(exc).__name__}).",
            )
            return await self._blocked_outcome(
                pre_decision, adapter, {"phase": "pre_tool"}
            )
        await self.evaluate(
            EventKind.TOOL_CALL_STARTED, self._invocation_payload(effective_invocation)
        )

        try:
            value = executor(effective_invocation)
            result = await value if inspect.isawaitable(value) else value
        except Exception as exc:
            await self.evaluate(
                EventKind.TOOL_CALL_FAILED,
                {
                    **self._invocation_payload(effective_invocation),
                    "exception_type": type(exc).__name__,
                },
            )
            restored_ref, compensation_ref = await self._recover(
                checkpoint,
                effective_invocation,
                None,
                f"executor_failed:{type(exc).__name__}",
            )
            recovery_attempted = checkpoint is not None or self._requires_compensation(
                pre_decision
            )
            recovery_succeeded = (
                bool(restored_ref or compensation_ref) if recovery_attempted else None
            )
            external_effect_may_persist = await self._external_effect_may_persist(
                effective_invocation, recovery_succeeded
            )
            receipt = EnforcementReceipt(
                decision_id=pre_decision.decision_id,
                event_id=pre_decision.effective_event.meta.event_id,
                disposition=pre_decision.disposition,
                enforced=True,
                adapter=adapter,
                details={"phase": "tool_execution", "failed": True},
            )
            await self._audit_receipt(pre_decision, receipt)
            return ToolExecutionOutcome(
                decision=pre_decision,
                receipt=receipt,
                error=type(exc).__name__,
                checkpoint_ref=checkpoint.checkpoint_id if checkpoint else None,
                compensation_ref=compensation_ref,
                recovery_attempted=recovery_attempted,
                recovery_succeeded=recovery_succeeded,
                external_effect_may_persist=external_effect_may_persist,
            )

        post_decision = await self.evaluate(
            EventKind.TOOL_CALL_SUCCEEDED,
            {
                **self._invocation_payload(effective_invocation),
                "result": result,
                "source": ContentSource.TOOL_OUTPUT.value,
            },
        )
        if post_decision.blocked:
            restored_ref, compensation_ref = await self._recover(
                checkpoint,
                effective_invocation,
                result,
                "post_tool_policy_denied",
            )
            recovery_attempted = checkpoint is not None or self._requires_compensation(
                pre_decision
            )
            recovery_succeeded = (
                bool(restored_ref or compensation_ref)
                if recovery_attempted
                else None
            )
            external_effect_may_persist = await self._external_effect_may_persist(
                effective_invocation, recovery_succeeded
            )
            outcome = await self._blocked_outcome(
                post_decision,
                adapter,
                {
                    "phase": "post_tool",
                    "recovery_attempted": recovery_attempted,
                    "recovery_succeeded": recovery_succeeded,
                    "external_effect_may_persist": external_effect_may_persist,
                },
            )
            return replace(
                outcome,
                checkpoint_ref=checkpoint.checkpoint_id if checkpoint else None,
                compensation_ref=compensation_ref,
                recovery_attempted=recovery_attempted,
                recovery_succeeded=recovery_succeeded,
                external_effect_may_persist=external_effect_may_persist,
            )

        effective_result = post_decision.effective_event.payload.get("result", result)
        receipt = EnforcementReceipt(
            decision_id=post_decision.decision_id,
            event_id=post_decision.effective_event.meta.event_id,
            disposition=post_decision.disposition,
            enforced=True,
            adapter=adapter,
            details={"phase": "post_tool", **approval_details},
        )
        await self._audit_receipt(post_decision, receipt)
        return ToolExecutionOutcome(
            decision=post_decision,
            receipt=receipt,
            result=effective_result,
            checkpoint_ref=checkpoint.checkpoint_id if checkpoint else None,
        )

    async def _evaluate_unlocked(
        self, kind: EventKind, payload: Mapping[str, Any]
    ) -> Decision:
        self._sequence += 1
        meta = EventMeta(
            tenant_id=self.context.tenant_id,
            session_id=self.context.session_id,
            run_id=self.context.run_id,
            agent_id=self.context.agent_id,
            sequence=self._sequence,
            framework=self.context.framework,
            trace_id=self.context.trace_id,
        )
        event = SecurityEvent(kind, meta, payload)
        is_user_input = self._is_user_input(event)
        if is_user_input:
            self._state.pop(TRUSTED_USER_INTENT_STATE_KEY, None)
        policy_context = PolicyContext(
            session=self.context,
            state=self._state,
            services=self.runtime.services,
        )
        decision = await self.runtime.policy_engine.evaluate(event, policy_context)
        if is_user_input and isinstance(
            decision.effective_event.payload.get("provenance"), Mapping
        ):
            self._update_user_intent(decision)
        sink = self.runtime.services.audit_sink
        if sink is not None:
            await sink.write(
                AuditRecord(
                    "decision",
                    minimize_event(event),
                    decision=minimize_decision(decision),
                )
            )
        return decision

    @staticmethod
    def _is_user_input(event: SecurityEvent) -> bool:
        if event.kind is not EventKind.CONTENT_RECEIVED:
            return False
        source = event.payload.get("source")
        return source in (ContentSource.USER_INPUT, ContentSource.USER_INPUT.value)

    def _update_user_intent(self, decision: Decision) -> None:
        payload = decision.effective_event.payload
        provenance = payload.get("provenance")
        if not decision.executable or (
            isinstance(provenance, Mapping)
            and str(provenance.get("trust", "")).lower() == "untrusted"
        ):
            self._state[TRUSTED_USER_INTENT_STATE_KEY] = {
                "active": False,
                "event_id": decision.effective_event.meta.event_id,
                "sequence": decision.effective_event.meta.sequence,
            }
            return
        content = payload.get("content")
        if not isinstance(content, str):
            return
        self._state[TRUSTED_USER_INTENT_STATE_KEY] = {
            "active": True,
            "content": content,
            "digest": user_intent_digest(content),
            "event_id": decision.effective_event.meta.event_id,
            "sequence": decision.effective_event.meta.sequence,
        }

    async def _blocked_outcome(
        self, decision: Decision, adapter: str, details: Mapping[str, Any]
    ) -> ToolExecutionOutcome:
        receipt = EnforcementReceipt(
            decision_id=decision.decision_id,
            event_id=decision.effective_event.meta.event_id,
            disposition=decision.disposition,
            enforced=True,
            adapter=adapter,
            details=details,
        )
        await self._audit_receipt(decision, receipt)
        return ToolExecutionOutcome(decision, receipt, blocked=True)

    async def _audit_receipt(
        self, decision: Decision, receipt: EnforcementReceipt
    ) -> None:
        sink = self.runtime.services.audit_sink
        if sink is not None:
            audit_decision = minimize_decision(decision)
            await sink.write(
                AuditRecord(
                    "enforcement",
                    audit_decision.effective_event,
                    decision=audit_decision,
                    receipt=receipt,
                )
            )

    async def _attach_enforcement_receipt(
        self,
        decision: Decision,
        invocation: ToolInvocation,
    ) -> ToolInvocation:
        """Ask the configured control plane to sign the final allowed call."""

        issuer = self.runtime.services.enforcement_receipt_issuer
        if issuer is None or invocation.enforcement_receipt is not None:
            return invocation
        catalog = self.runtime.services.tool_catalog
        if catalog is None:
            return invocation
        descriptor = await catalog.resolve(invocation.tool_name, invocation.tool_version)
        if descriptor is None:
            raise RuntimeError("cannot sign an enforcement receipt for an unknown tool")
        receipt = await issuer.issue(
            self.context,
            descriptor,
            invocation,
            decision_id=decision.decision_id,
            event_id=decision.effective_event.meta.event_id,
            policy_version=decision.policy_version,
            workload_id=str(self.context.metadata.get("workload_id", "")),
        )
        return ToolInvocation(
            tool_name=invocation.tool_name,
            arguments=invocation.arguments,
            call_id=invocation.call_id,
            tool_version=invocation.tool_version,
            resource=invocation.resource,
            capability_token=invocation.capability_token,
            intent_digest=invocation.intent_digest,
            enforcement_receipt=receipt,
        )

    async def _capture_checkpoint_if_required(
        self, decision: Decision, invocation: ToolInvocation
    ) -> CheckpointRef | None:
        if not self._requires_checkpoint(decision):
            return None
        backend = self.runtime.services.state_backend
        if backend is None:
            return None
        checkpoint = await backend.capture(self.context, invocation)
        await self.evaluate(
            EventKind.CHECKPOINT_CREATED,
            {
                "checkpoint_id": checkpoint.checkpoint_id,
                "backend": checkpoint.backend,
                "scope": checkpoint.scope,
                "call_id": invocation.call_id,
            },
        )
        return checkpoint

    async def _recover(
        self,
        checkpoint: CheckpointRef | None,
        invocation: ToolInvocation,
        result: Any,
        reason: str,
    ) -> tuple[str | None, str | None]:
        restored_checkpoint: str | None = None
        if checkpoint is not None and self.runtime.services.state_backend is not None:
            await self.evaluate(
                EventKind.ROLLBACK_REQUESTED,
                {"checkpoint_id": checkpoint.checkpoint_id, "reason": reason},
            )
            restore_error: str | None = None
            try:
                restore = await self.runtime.services.state_backend.restore(checkpoint)
                restored = restore.restored
            except Exception as exc:
                restored = False
                restore_error = type(exc).__name__
            await self.evaluate(
                EventKind.ROLLBACK_COMPLETED,
                {
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "restored": restored,
                    "error_type": restore_error,
                },
            )
            if restored:
                restored_checkpoint = checkpoint.checkpoint_id
                return restored_checkpoint, None

        catalog = self.runtime.services.tool_catalog
        compensator = self.runtime.services.compensation_provider
        if catalog is not None and compensator is not None:
            descriptor = await catalog.resolve(invocation.tool_name, invocation.tool_version)
            if descriptor and descriptor.reversibility is Reversibility.COMPENSATABLE:
                try:
                    receipt = await compensator.compensate(
                        self.context, invocation, result, reason
                    )
                except Exception:
                    return restored_checkpoint, None
                if receipt.compensated:
                    return restored_checkpoint, receipt.compensation_id
        return restored_checkpoint, None

    @staticmethod
    def _requires_checkpoint(decision: Decision) -> bool:
        return any(
            obligation.kind is ObligationKind.CHECKPOINT
            for obligation in decision.obligations
        )

    @staticmethod
    def _requires_compensation(decision: Decision) -> bool:
        return any(
            obligation.kind is ObligationKind.COMPENSATE
            for obligation in decision.obligations
        )

    async def _external_effect_may_persist(
        self,
        invocation: ToolInvocation,
        recovery_succeeded: bool | None,
    ) -> bool:
        catalog = self.runtime.services.tool_catalog
        if catalog is None:
            return True
        try:
            descriptor = await catalog.resolve(
                invocation.tool_name, invocation.tool_version
            )
        except Exception:
            return True
        if descriptor is None:
            return True
        has_external_effect = bool(descriptor.side_effects) or (
            descriptor.reversibility is not Reversibility.READ_ONLY
        )
        return has_external_effect and recovery_succeeded is not True

    @staticmethod
    def _invocation_payload(invocation: ToolInvocation) -> dict[str, Any]:
        return {
            "tool_name": invocation.tool_name,
            "arguments": dict(invocation.arguments),
            "call_id": invocation.call_id,
            "tool_version": invocation.tool_version,
            "resource": invocation.resource,
            "capability_token": invocation.capability_token,
            "intent_digest": invocation.intent_digest,
        }

    @staticmethod
    def _effective_invocation(
        decision: Decision, original: ToolInvocation
    ) -> ToolInvocation:
        payload = decision.effective_event.payload
        return ToolInvocation(
            tool_name=str(payload.get("tool_name", original.tool_name)),
            arguments=payload.get("arguments", original.arguments),
            call_id=str(payload.get("call_id", original.call_id)),
            tool_version=payload.get("tool_version", original.tool_version),
            resource=payload.get("resource", original.resource),
            capability_token=payload.get("capability_token", original.capability_token),
            intent_digest=payload.get("intent_digest", original.intent_digest),
            enforcement_receipt=payload.get(
                "enforcement_receipt", original.enforcement_receipt
            ),
        )

    @staticmethod
    def _deny(decision: Decision, code: str, message: str) -> Decision:
        return Decision(
            disposition=Disposition.DENY,
            effective_event=decision.effective_event,
            risk=RiskAssessment(1.0, Severity.HIGH, (code,)),
            reasons=decision.reasons + (Reason(code, message, "safeharness.runtime"),),
            obligations=decision.obligations,
            policy_version=decision.policy_version,
        )

    @staticmethod
    def _approval_granted(decision: Decision, reason: str = "") -> Decision:
        return Decision(
            disposition=Disposition.ALLOW,
            effective_event=decision.effective_event,
            risk=decision.risk,
            reasons=decision.reasons
            + (
                Reason(
                    "approval_granted",
                    reason or "The required approval was granted.",
                    "safeharness.runtime",
                ),
            ),
            obligations=decision.obligations,
            policy_version=decision.policy_version,
        )
