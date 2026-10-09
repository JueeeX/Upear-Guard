"""Deterministic local latency gate for SafeHarness SDK hot paths."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import gc
import json
import math
import statistics
import sys
import time
import tracemalloc
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from safeharness import SafeHarnessRuntime, SessionContext, ToolDescriptor, ToolInvocation
from safeharness.adapters import (
    ExplicitLifecycleAdapter,
    HmacIntegrityCipher,
    SubagentConstraints,
    execute_invocation,
)
from safeharness.backends import (
    InMemoryAuditSink,
    OpenAICompatibleJudge,
    SignedCapabilityGateway,
    StaticCapabilityAuthority,
    StaticToolCatalog,
)
from safeharness.ports import JudgeRequest
from safeharness.runtime import RuntimeServices


@dataclass(frozen=True, slots=True)
class Budget:
    p95_overhead_ms: float
    p99_overhead_ms: float


BUDGETS = {
    "input_filter": Budget(1.0, 2.0),
    "final_output_filter": Budget(1.0, 2.0),
    "tool_round_trip": Budget(2.0, 4.0),
    "memory_read": Budget(3.0, 6.0),
    "memory_write": Budget(2.0, 4.0),
    "subagent_handoff": Budget(5.0, 10.0),
    "checkpoint_integrity_4k": Budget(1.0, 2.0),
    "signed_gateway_local": Budget(3.0, 6.0),
    "semantic_judge_adapter_local": Budget(5.0, 10.0),
}


async def measure(
    operation: Callable[[], Awaitable[Any]],
    *,
    samples: int,
    warmup: int,
) -> dict[str, float]:
    for _ in range(warmup):
        await operation()
    values = []
    wall_started = time.perf_counter_ns()
    cpu_started = time.process_time_ns()
    for _ in range(samples):
        started = time.perf_counter_ns()
        await operation()
        values.append((time.perf_counter_ns() - started) / 1_000_000)
    cpu_elapsed = time.process_time_ns() - cpu_started
    wall_elapsed = time.perf_counter_ns() - wall_started
    values.sort()
    peak_allocated_bytes = await _measure_peak_allocation(
        operation,
        samples=min(samples, 50),
        warmup=min(warmup, 10),
    )
    return {
        "p50_ms": statistics.median(values),
        "median_ms": statistics.median(values),
        "p95_ms": values[math.ceil(len(values) * 0.95) - 1],
        "p99_ms": values[math.ceil(len(values) * 0.99) - 1],
        "mean_ms": statistics.fmean(values),
        "cpu_mean_ms": cpu_elapsed / samples / 1_000_000,
        "sequential_throughput_ops_per_second": samples / (wall_elapsed / 1_000_000_000),
        "peak_allocated_bytes": peak_allocated_bytes,
    }


async def _measure_peak_allocation(
    operation: Callable[[], Awaitable[Any]],
    *,
    samples: int,
    warmup: int,
) -> float:
    gc.collect()
    tracemalloc.start(1)
    try:
        for _ in range(warmup):
            await operation()
        values = []
        for _ in range(samples):
            current, _ = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            await operation()
            _, peak = tracemalloc.get_traced_memory()
            values.append(max(0, peak - current))
        values.sort()
        return float(values[math.ceil(len(values) * 0.95) - 1])
    finally:
        tracemalloc.stop()


async def run_benchmarks(*, samples: int, warmup: int) -> dict[str, dict[str, float]]:
    audit = InMemoryAuditSink()
    descriptor = ToolDescriptor(
        "lookup_alarm",
        input_schema={
            "type": "object",
            "properties": {"alarm_id": {"type": "string"}},
            "required": ["alarm_id"],
            "additionalProperties": False,
        },
        required_capabilities=frozenset({"alarm:read"}),
    )
    runtime = SafeHarnessRuntime(
        services=RuntimeServices(
            tool_catalog=StaticToolCatalog((descriptor,)),
            capability_authority=StaticCapabilityAuthority(
                {"performance-agent": {"alarm:read"}}
            ),
            audit_sink=audit,
        )
    )
    session = runtime.session(
        SessionContext(
            tenant_id="performance",
            agent_id="performance-agent",
            framework="performance-gate",
        )
    )
    await session.start()
    invocation = ToolInvocation("lookup_alarm", {"alarm_id": "ALM-1001"})
    lifecycle = ExplicitLifecycleAdapter(
        session,
        adapter_name="performance-gate",
        subagent_constraints=SubagentConstraints(
            allowed_agent_ids=frozenset({"diagnosis"}),
        ),
    )
    memory = {"incident": {"alarm_id": "ALM-1001", "status": "active"}}
    checkpoint_payload = b"x" * 4096
    checkpoint_cipher = HmacIntegrityCipher(b"c" * 32)
    gateway = SignedCapabilityGateway(
        b"gateway-performance-signing-key-32b",
        {"performance-agent": {"alarm:read"}},
    )
    judge = OpenAICompatibleJudge(
        lambda _messages, _model: json.dumps(
            {"label": "SAFE", "confidence": 1.0, "reason": "local regression"}
        ),
        model="local-regression",
    )
    judge_request = JudgeRequest(
        purpose="prompt_injection_detection",
        content={"source": "tool_output", "content": "Alarm ALM-1001 is active."},
    )

    async def no_guard_input() -> str:
        return "Inspect alarm ALM-1001."

    async def no_guard_output() -> str:
        return "Alarm ALM-1001 is active."

    async def no_guard_tool() -> str:
        return "active"

    async def tool_round_trip() -> Any:
        return await execute_invocation(session, invocation, lambda _effective: "active")

    async def no_guard_memory_read() -> Any:
        return memory["incident"]

    async def memory_read() -> Any:
        outcome = await lifecycle.read_memory(
            "incident",
            lambda: memory["incident"],
            namespace=("performance",),
        )
        return outcome.value

    def write_memory(value: Any) -> None:
        memory["incident"] = value

    async def no_guard_memory_write() -> None:
        write_memory({"alarm_id": "ALM-1001", "status": "active"})

    async def memory_write() -> Any:
        return await lifecycle.write_memory(
            "incident",
            {"alarm_id": "ALM-1001", "status": "active"},
            write_memory,
            namespace=("performance",),
        )

    async def no_guard_handoff() -> str:
        return "diagnosis"

    async def subagent_handoff() -> Any:
        return await lifecycle.create_subagent(
            "diagnosis",
            "Inspect alarm ALM-1001.",
            lambda _context, _task: "diagnosis",
        )

    async def no_guard_checkpoint() -> bytes:
        return checkpoint_payload

    async def checkpoint_integrity() -> bytes:
        ciphername, authenticated = checkpoint_cipher.encrypt(checkpoint_payload)
        return checkpoint_cipher.decrypt(ciphername, authenticated)

    async def no_guard_gateway() -> bool:
        return True

    async def signed_gateway_local() -> Any:
        proposed = ToolInvocation(
            "lookup_alarm",
            {"alarm_id": "ALM-1001"},
            tool_version=descriptor.version,
        )
        grant = await gateway.issue(session.context, descriptor, proposed)
        result = await gateway.authorize(
            session.context,
            descriptor,
            dataclasses.replace(proposed, capability_token=grant.token),
        )
        if not result.allowed:
            raise RuntimeError("local signed gateway rejected its fresh capability")
        return result

    async def no_guard_judge() -> str:
        return "SAFE"

    async def semantic_judge_adapter_local() -> Any:
        return await judge.judge(judge_request)

    baseline_operations = {
        "input_filter": no_guard_input,
        "final_output_filter": no_guard_output,
        "tool_round_trip": no_guard_tool,
        "memory_read": no_guard_memory_read,
        "memory_write": no_guard_memory_write,
        "subagent_handoff": no_guard_handoff,
        "checkpoint_integrity_4k": no_guard_checkpoint,
        "signed_gateway_local": no_guard_gateway,
        "semantic_judge_adapter_local": no_guard_judge,
    }
    guarded_operations = {
        "input_filter": lambda: session.inspect_content("Inspect alarm ALM-1001."),
        "final_output_filter": lambda: session.inspect_final_output(
            "Alarm ALM-1001 is active."
        ),
        "tool_round_trip": tool_round_trip,
        "memory_read": memory_read,
        "memory_write": memory_write,
        "subagent_handoff": subagent_handoff,
        "checkpoint_integrity_4k": checkpoint_integrity,
        "signed_gateway_local": signed_gateway_local,
        "semantic_judge_adapter_local": semantic_judge_adapter_local,
    }

    try:
        baselines = {
            name: await measure(operation, samples=samples, warmup=warmup)
            for name, operation in baseline_operations.items()
        }
        guarded = {
            name: await measure(operation, samples=samples, warmup=warmup)
            for name, operation in guarded_operations.items()
        }
    finally:
        await session.close()
    if not audit.records:
        raise RuntimeError("performance gate must exercise audit enforcement")
    return {
        name: {
            "baseline_p50_ms": baselines[name]["p50_ms"],
            "baseline_p95_ms": baselines[name]["p95_ms"],
            "baseline_p99_ms": baselines[name]["p99_ms"],
            "guarded_p50_ms": metrics["p50_ms"],
            "guarded_median_ms": metrics["median_ms"],
            "guarded_p95_ms": metrics["p95_ms"],
            "guarded_p99_ms": metrics["p99_ms"],
            "p50_overhead_ms": max(
                0.0, metrics["p50_ms"] - baselines[name]["p50_ms"]
            ),
            "p95_overhead_ms": max(0.0, metrics["p95_ms"] - baselines[name]["p95_ms"]),
            "p99_overhead_ms": max(
                0.0, metrics["p99_ms"] - baselines[name]["p99_ms"]
            ),
            "guarded_cpu_mean_ms": metrics["cpu_mean_ms"],
            "cpu_overhead_mean_ms": max(
                0.0, metrics["cpu_mean_ms"] - baselines[name]["cpu_mean_ms"]
            ),
            "guarded_sequential_throughput_ops_per_second": metrics[
                "sequential_throughput_ops_per_second"
            ],
            "guarded_peak_allocated_bytes": metrics["peak_allocated_bytes"],
            "peak_allocated_overhead_bytes": max(
                0.0,
                metrics["peak_allocated_bytes"]
                - baselines[name]["peak_allocated_bytes"],
            ),
        }
        for name, metrics in guarded.items()
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure local SafeHarness overhead and enforce p95 budgets."
    )
    parser.add_argument("--samples", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--no-fail", action="store_true")
    args = parser.parse_args(argv)
    if args.samples < 20 or args.warmup < 0:
        parser.error("samples must be >= 20 and warmup must be >= 0")

    results = asyncio.run(run_benchmarks(samples=args.samples, warmup=args.warmup))
    failed = []
    output = {}
    for name, metrics in results.items():
        budget = BUDGETS[name]
        passed = (
            metrics["p95_overhead_ms"] <= budget.p95_overhead_ms
            and metrics["p99_overhead_ms"] <= budget.p99_overhead_ms
        )
        output[name] = {
            **metrics,
            "budget_p95_overhead_ms": budget.p95_overhead_ms,
            "budget_p99_overhead_ms": budget.p99_overhead_ms,
            "passed": passed,
        }
        if not passed:
            failed.append(name)
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if args.no_fail or not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
