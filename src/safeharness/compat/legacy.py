"""Expose the new runtime through the legacy ``filter_context/check_action`` API."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Any

from safeharness.api.context import SessionContext
from safeharness.api.decisions import ObligationKind
from safeharness.api.events import ContentSource, EventKind
from safeharness.runtime import SafeHarnessRuntime


@dataclass(slots=True)
class LegacySecurityDecision:
    blocked: bool
    reason: str = ""
    layer: str = "safeharness-core"
    risk_score: float = 0.0


class LegacyPipelineFacade:
    """Migration bridge for existing synchronous paper harnesses.

    Tool-argument modifications are denied because the legacy contract cannot return
    modified arguments to the caller. New integrations should use ``around_tool``.
    """

    def __init__(
        self,
        runtime: SafeHarnessRuntime,
        context: SessionContext,
        *,
        blocked_content: str = "[Content blocked by SafeHarness]",
    ) -> None:
        self.runtime = runtime
        self.session = runtime.session(context)
        self.blocked_content = blocked_content
        self._lock = threading.RLock()
        self._closed = False
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"safeharness-legacy-{context.session_id[:8]}",
            daemon=True,
        )
        self._thread.start()
        self._ready.wait()
        self.l2 = self  # compatibility with harnesses calling pipeline.l2.record_reasoning

    def filter_context(self, text: str, source: str = "user_input") -> str:
        try:
            content_source: ContentSource | str = ContentSource(source)
        except ValueError:
            content_source = source
        decision = self._run(self.session.inspect_content(text, source=content_source))
        if decision.blocked:
            return self.blocked_content
        return str(decision.effective_event.payload.get("content", text))

    def check_action(
        self, tool_name: str, arguments: dict[str, Any], env: Any = None
    ) -> LegacySecurityDecision:
        decision = self._run(
            self.session.evaluate(
                EventKind.TOOL_CALL_PROPOSED,
                {"tool_name": tool_name, "arguments": dict(arguments)},
            )
        )
        effective_arguments = decision.effective_event.payload.get("arguments", arguments)
        modified = dict(effective_arguments) != dict(arguments)
        unsupported = {
            obligation.kind
            for obligation in decision.obligations
            if obligation.kind
            in {
                ObligationKind.CHECKPOINT,
                ObligationKind.COMPENSATE,
                ObligationKind.REQUIRE_APPROVAL,
                ObligationKind.SANDBOX,
            }
        }
        blocked = decision.blocked or modified or bool(unsupported)
        if unsupported and not decision.blocked:
            names = ", ".join(sorted(item.value for item in unsupported))
            reason = f"Legacy adapter cannot enforce required obligations: {names}."
        elif modified and not decision.blocked:
            reason = "Legacy adapter cannot enforce modified tool arguments safely."
        else:
            reason = decision.reasons[-1].message if decision.reasons else ""
        return LegacySecurityDecision(
            blocked,
            reason,
            risk_score=decision.risk.score,
        )

    def record_reasoning(self, step_text: str) -> None:
        self._run(self.session.record_model_response(step_text))

    def run_awaitable(self, awaitable):
        """Run one SafeHarness awaitable on this facade's dedicated event loop."""

        return self._run(awaitable)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._submit(self.session.close())
            self._closed = True
            assert self._loop is not None
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()

    def __enter__(self) -> "LegacyPipelineFacade":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def _run(self, awaitable):
        with self._lock:
            if self._closed:
                awaitable.close()
                raise RuntimeError("legacy pipeline facade is closed")
            return self._submit(awaitable)

    def _submit(self, awaitable):
        assert self._loop is not None
        future = asyncio.run_coroutine_threadsafe(awaitable, self._loop)
        return future.result()

    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()
