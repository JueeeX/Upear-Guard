#!/usr/bin/env python3
"""
Full SafeHarness experiment runner — **parallel** execution.

Usage:
    python run_experiment.py                       # full matrix
    python run_experiment.py --subset 10           # quick run with N samples
    python run_experiment.py --workers 16          # control concurrency
    python run_experiment.py --config config/experiment.yaml
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

from src.data_loader import load_subset, load_dataset_local, download_dataset
from src.tools.registry import build_default_registry, ToolRegistry
from src.tools.simulated_tools import SimulatedEnvironment
from src.harness.direct import DirectHarness
from src.harness.react import ReactHarness
from src.harness.multi_agent import MultiAgentHarness
from src.harness.map_reduce import MapReduceHarness
from src.safety import SecurityPipeline, BoltOnPipeline
from src.attacks import context_poisoning, tool_tampering, memory_injection
from src.evaluation import rule_checker, llm_judge
from src.evaluation.metrics import compute_metrics

HARNESS_MAP = {
    "direct": DirectHarness,
    "react": ReactHarness,
    "multi_agent": MultiAgentHarness,
    "map_reduce": MapReduceHarness,
}

ATTACK_MAP: dict[str, Callable] = {
    "context_poisoning": context_poisoning.inject,
    "tool_tampering": tool_tampering.inject,
    "memory_injection": memory_injection.inject,
}


@dataclass
class Job:
    task: dict[str, Any]
    model_name: str
    harness_type: str
    security_mode: str
    attack: str | None
    attack_fn: Callable | None


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


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_security_pipeline(mode, registry, config, judge_model):
    if mode == "safe_harness":
        return SecurityPipeline(registry, config.get("safety", {}), judge_model)
    if mode == "bolt_on":
        return BoltOnPipeline(registry, config.get("safety", {}), judge_model)
    return None


def _run_job(job: Job, registry: ToolRegistry, cfg: dict,
             judge_model: str) -> Record:
    """Execute a single experiment job — fully independent, thread-safe."""
    harness_cfg = {**cfg["harness"], "security_mode": job.security_mode}
    harness = HARNESS_MAP[job.harness_type](job.model_name, registry, harness_cfg)
    pipeline = build_security_pipeline(job.security_mode, registry, cfg, judge_model)
    env = SimulatedEnvironment()

    task = job.attack_fn(job.task, seed=job.task["id"]) if job.attack_fn else job.task

    t0 = time.time()
    hr = harness.execute(task, env, pipeline)
    rr = rule_checker.check(hr)
    jr = llm_judge.evaluate(hr, task, judge_model=judge_model)
    elapsed = time.time() - t0

    return Record(
        model=job.model_name,
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
    parser = argparse.ArgumentParser(description="SafeHarness Experiment (parallel)")
    parser.add_argument("--config", default="config/experiment.yaml")
    parser.add_argument("--subset", type=int, default=0,
                        help="Run on N samples (0 = use config default)")
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    output_dir = Path(args.output or cfg["project"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    max_workers = args.workers or cfg.get("parallel", {}).get("max_workers", 8)

    print("[*] Downloading / loading dataset …")
    download_dataset()
    subset_size = args.subset or cfg["data"]["demo_subset_size"]
    tasks = load_subset(subset_size)
    print(f"[*] Loaded {len(tasks)} tasks.")

    registry = build_default_registry()
    agent_models = cfg["models"]["agent_models"]
    judge_model = cfg["models"]["judge_model"]
    harness_types = cfg["harness"]["types"]
    security_modes = cfg["security_modes"]
    attack_types = cfg["attacks"]["types"]

    # ── Build flat job list ────────────────────────────────────
    jobs: list[Job] = []
    for model_name in agent_models:
        for h_type in harness_types:
            for s_mode in security_modes:
                for task in tasks:
                    jobs.append(Job(task, model_name, h_type, s_mode, None, None))
                    for atk_type in attack_types:
                        jobs.append(Job(task, model_name, h_type, s_mode,
                                        atk_type, ATTACK_MAP[atk_type]))

    total = len(jobs)
    print(f"[*] {total} jobs to run with {max_workers} workers.\n")

    # ── Execute in parallel ────────────────────────────────────
    results: list[Record] = []
    counter = {"done": 0}
    lock = threading.Lock()

    def _submit(job: Job) -> Record:
        rec = _run_job(job, registry, cfg, judge_model)
        with lock:
            counter["done"] += 1
            _print_row(rec, counter["done"], total)
        return rec

    t_start = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_submit, job) for job in jobs]
        for future in as_completed(futures):
            results.append(future.result())

    wall_time = time.time() - t_start
    serial_time = sum(r.elapsed_s for r in results)
    print(f"\n[*] Wall: {wall_time:.1f}s  |  Serial sum: {serial_time:.1f}s  "
          f"|  Speedup: {serial_time / wall_time:.1f}x")

    # ── Per-group metrics ──────────────────────────────────────
    from src.harness.base import HarnessResult
    from src.evaluation.llm_judge import JudgeResult
    from src.evaluation.rule_checker import RuleCheckResult

    for model_name in agent_models:
        for h_type in harness_types:
            for s_mode in security_modes:
                group = [r for r in results
                         if r.model == model_name
                         and r.harness == h_type
                         and r.security_mode == s_mode]
                batch = _to_metric_tuples(group, tasks)
                m = compute_metrics(batch)
                print(f"\n  {model_name} / {h_type} / {s_mode}")
                print(f"  {m}")

    # ── Save ───────────────────────────────────────────────────
    all_dicts = sorted(
        [_rec_dict(r) for r in results],
        key=lambda x: (x["model"], x["harness"], x["security_mode"],
                        x["task_id"], x["attack"] or ""),
    )
    out_file = output_dir / "experiment_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_dicts, f, ensure_ascii=False, indent=2)
    print(f"\n[*] Results saved → {out_file}")


def _print_row(r: Record, done: int, total: int):
    lmap = {-1: "FAIL", 0: "SAFE", 1: "PART", 2: "UNSAFE"}
    label = lmap.get(r.judge_label, "?")
    atk = r.attack or "clean"
    rule = "RULE!" if r.rule_unsafe else "ok"
    print(f"  [{done:>4}/{total}] {r.model:<16} {r.harness:<12} "
          f"{r.security_mode:<14} task={r.task_id:<4} {atk:<20} "
          f"judge={label:<7} {rule:<6} blocked={r.blocked_count} "
          f"({r.elapsed_s:.1f}s)")


def _rec_dict(r: Record) -> dict:
    return {
        "model": r.model, "harness": r.harness,
        "security_mode": r.security_mode, "attack": r.attack,
        "task_id": r.task_id, "risks": r.risks,
        "judge_label": r.judge_label,
        "judge_reasoning": r.judge_reasoning,
        "rule_unsafe": r.rule_unsafe, "rule_details": r.rule_details,
        "blocked_count": r.blocked_count, "elapsed_s": r.elapsed_s,
    }


def _to_metric_tuples(records, tasks):
    from src.harness.base import HarnessResult
    from src.evaluation.llm_judge import JudgeResult
    from src.evaluation.rule_checker import RuleCheckResult
    task_map = {t["id"]: t for t in tasks}
    tuples = []
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
