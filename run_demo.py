#!/usr/bin/env python3
"""
Quick demo — runs 3 tasks through ALL harness × security combinations
**in parallel** and prints a summary table + saves JSON output.

Usage:
    python run_demo.py
    python run_demo.py --tasks 5
    python run_demo.py --workers 12
    python run_demo.py --harness direct react --security unprotected safe_harness
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.data_loader import load_subset, download_dataset
from src.tools.registry import build_default_registry, ToolRegistry
from src.tools.simulated_tools import SimulatedEnvironment
from src.harness.direct import DirectHarness
from src.harness.react import ReactHarness
from src.harness.multi_agent import MultiAgentHarness
from src.harness.map_reduce import MapReduceHarness
from src.safety import SecurityPipeline, BoltOnPipeline
from src.attacks import context_poisoning
from src.evaluation import rule_checker, llm_judge
from src.evaluation.metrics import compute_metrics

HARNESS_MAP = {
    "direct": DirectHarness,
    "react": ReactHarness,
    "multi_agent": MultiAgentHarness,
    "map_reduce": MapReduceHarness,
}


@dataclass
class Job:
    task: dict[str, Any]
    harness_type: str
    security_mode: str
    attack: str | None          # None = clean run
    attack_fn: Callable | None  # function to apply to task


@dataclass
class Record:
    model: str
    harness: str
    security_mode: str
    attack: str | None
    task_id: int
    risks: list[str]
    judge_label: int
    judge_reasoning: str
    rule_unsafe: bool
    rule_details: str
    blocked_count: int
    elapsed_s: float


def load_config(path: str = "config/experiment.yaml") -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_security_pipeline(mode: str, registry: ToolRegistry,
                            cfg: dict, judge_model: str):
    if mode == "safe_harness":
        return SecurityPipeline(registry, cfg.get("safety", {}), judge_model)
    if mode == "bolt_on":
        return BoltOnPipeline(registry, cfg.get("safety", {}), judge_model)
    return None


def _run_job(job: Job, registry: ToolRegistry, cfg: dict,
             model_name: str, judge_model: str) -> Record:
    """Execute a single (task, harness, security, attack) combination.

    Each invocation creates its own mutable state (env, pipeline) so
    that jobs are fully independent and thread-safe.
    """
    harness_cfg = {**cfg["harness"], "security_mode": job.security_mode}
    harness = HARNESS_MAP[job.harness_type](model_name, registry, harness_cfg)
    pipeline = build_security_pipeline(job.security_mode, registry, cfg, judge_model)
    env = SimulatedEnvironment()

    task = job.attack_fn(job.task, seed=job.task["id"]) if job.attack_fn else job.task

    t0 = time.time()
    hr = harness.execute(task, env, pipeline)
    rr = rule_checker.check(hr)
    jr = llm_judge.evaluate(hr, task, judge_model=judge_model)
    elapsed = time.time() - t0

    return Record(
        model=model_name,
        harness=job.harness_type,
        security_mode=job.security_mode,
        attack=job.attack,
        task_id=job.task["id"],
        risks=job.task.get("risks", []),
        judge_label=jr.label,
        judge_reasoning=jr.reasoning[:300],
        rule_unsafe=rr.is_unsafe,
        rule_details=rr.details,
        blocked_count=len(hr.blocked_actions),
        elapsed_s=round(elapsed, 2),
    )


def main():
    parser = argparse.ArgumentParser(description="SafeHarness Demo (parallel)")
    parser.add_argument("--tasks", type=int, default=3)
    parser.add_argument("--harness", nargs="*", default=None)
    parser.add_argument("--security", nargs="*", default=None)
    parser.add_argument("--workers", type=int, default=None,
                        help="Parallel threads (default: from config)")
    parser.add_argument("--config", default="config/experiment.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    judge_model = cfg["models"]["judge_model"]
    model_name = cfg["models"]["agent_models"][0]
    max_workers = args.workers or cfg.get("parallel", {}).get("max_workers", 8)

    harness_types = args.harness or cfg["harness"]["types"]
    security_modes = args.security or cfg["security_modes"]

    print("=" * 65)
    print("  SafeHarness Demo (parallel)")
    print(f"  Model: {model_name}  |  Judge: {judge_model}")
    print(f"  Harnesses: {harness_types}")
    print(f"  Security modes: {security_modes}")
    print(f"  Workers: {max_workers}")
    print("=" * 65)

    # ── 1. Download & load data ────────────────────────────────
    print("\n[1/4] Downloading dataset …")
    download_dataset()
    tasks = load_subset(args.tasks)
    print(f"  Loaded {len(tasks)} tasks:")
    for t in tasks:
        print(f"    id={t['id']}  risks={t['risks']}")
        print(f"    instruction: {t['instruction'][:100]}…")

    registry = build_default_registry()

    # ── 2. Build job list ──────────────────────────────────────
    jobs: list[Job] = []
    for h_type in harness_types:
        for s_mode in security_modes:
            for task in tasks:
                jobs.append(Job(task, h_type, s_mode, None, None))
                jobs.append(Job(task, h_type, s_mode,
                                "context_poisoning", context_poisoning.inject))

    total = len(jobs)
    print(f"\n[2/4] Running {total} jobs with {max_workers} workers …\n")

    # ── 3. Execute in parallel ─────────────────────────────────
    results: list[Record] = []
    counter = {"done": 0}
    lock = threading.Lock()

    def _submit_and_log(job: Job) -> Record:
        rec = _run_job(job, registry, cfg, model_name, judge_model)
        with lock:
            counter["done"] += 1
            _log_record(rec, counter["done"], total)
        return rec

    t_start = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_submit_and_log, job) for job in jobs]
        for future in as_completed(futures):
            results.append(future.result())

    wall_time = time.time() - t_start
    serial_time = sum(r.elapsed_s for r in results)
    print(f"\n  Wall time: {wall_time:.1f}s  |  Sum of job times: {serial_time:.1f}s  "
          f"|  Speedup: {serial_time / wall_time:.1f}x")

    # ── 4. Aggregate metrics per (harness, security) ───────────
    print("\n[3/4] Summary Table")
    print("-" * 90)
    hdr = (f"{'Harness':<14} {'Security':<14} {'UBR':>6} {'ASR':>6} "
           f"{'TCR':>6} {'UA':>6} {'NNH':>6} {'Blocked':>8}")
    print(hdr)
    print("-" * 90)

    summary_table: list[dict] = []
    for h_type in harness_types:
        for s_mode in security_modes:
            group = [r for r in results
                     if r.harness == h_type and r.security_mode == s_mode]
            batch = _records_to_metric_tuples(group, tasks)
            m = compute_metrics(batch)
            row = {"harness": h_type, "security": s_mode, **m.summary_dict()}
            summary_table.append(row)
            nnh_str = f"{row['NNH']}" if row["NNH"] != "inf" else "  inf"
            print(f"{row['harness']:<14} {row['security']:<14} "
                  f"{row['UBR']:>6.2%} {row['ASR']:>6.2%} "
                  f"{row['TCR']:>6.2%} {row['UA']:>6.2%} "
                  f"{nnh_str:>6} {row['blocked_count']:>8}")

    print("-" * 90)

    # ── 5. Save results ────────────────────────────────────────
    output_dir = Path(cfg["project"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "demo_results.json"

    all_records = sorted(
        [_record_to_dict(r) for r in results],
        key=lambda x: (x["harness"], x["security_mode"], x["task_id"], x["attack"] or ""),
    )

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "config": {
                "model": model_name,
                "harness_types": harness_types,
                "security_modes": security_modes,
                "num_tasks": len(tasks),
                "workers": max_workers,
                "wall_time_s": round(wall_time, 2),
            },
            "records": all_records,
            "summary": summary_table,
        }, f, ensure_ascii=False, indent=2)
    print(f"\n[4/4] Results saved → {out_file}")
    print("\nDone!")


# ── helpers ────────────────────────────────────────────────────

def _log_record(r: Record, done: int, total: int):
    lmap = {-1: "FAIL", 0: "SAFE", 1: "PART", 2: "UNSAFE"}
    jl = lmap.get(r.judge_label, "?")
    atk = r.attack or "clean"
    rule_flag = "RULE!" if r.rule_unsafe else "ok"
    print(f"  [{done:>3}/{total}] {r.harness:<12} {r.security_mode:<14} "
          f"task={r.task_id:<4} {atk:<14} "
          f"judge={jl:<7} rule={rule_flag:<6} blocked={r.blocked_count} "
          f"({r.elapsed_s:.1f}s)")


def _record_to_dict(r: Record) -> dict:
    return {
        "model": r.model,
        "harness": r.harness,
        "security_mode": r.security_mode,
        "attack": r.attack,
        "task_id": r.task_id,
        "risks": r.risks,
        "judge_label": r.judge_label,
        "judge_reasoning": r.judge_reasoning,
        "rule_unsafe": r.rule_unsafe,
        "rule_details": r.rule_details,
        "blocked_count": r.blocked_count,
        "elapsed_s": r.elapsed_s,
    }


def _records_to_metric_tuples(records: list[Record], tasks: list[dict]):
    """Convert Record list into the (task, hr, jr, rr) tuples that
    compute_metrics expects, using lightweight stub objects."""
    from src.harness.base import HarnessResult
    from src.evaluation.llm_judge import JudgeResult
    from src.evaluation.rule_checker import RuleCheckResult

    tuples = []
    task_map = {t["id"]: t for t in tasks}
    for r in records:
        task = task_map.get(r.task_id, {"id": r.task_id})
        if r.attack:
            task = dict(task, _attack=r.attack)
        hr = HarnessResult(
            task_id=r.task_id, harness_type=r.harness,
            security_mode=r.security_mode, final_response="",
            blocked_actions=[None] * r.blocked_count,
        )
        jr = JudgeResult(label=r.judge_label, reasoning=r.judge_reasoning)
        rr = RuleCheckResult(is_unsafe=r.rule_unsafe,
                             triggered_rules=[], details=r.rule_details)
        tuples.append((task, hr, jr, rr))
    return tuples


if __name__ == "__main__":
    main()
