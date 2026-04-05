#!/usr/bin/env python3
"""
Full SafeHarness experiment runner — **parallel** execution.

Supports:
  - Multiple agent models and a separate judge model
  - 5 security modes: unprotected / system_prompt / guardrail / bolt_on / safe_harness
  - 5 attack types: context_poisoning / indirect_injection / tool_tampering /
                     memory_injection / composite
  - Ablation study (--ablation flag)
  - Bootstrap confidence intervals (--bootstrap)

Usage:
    python run_experiment.py                         # full matrix
    python run_experiment.py --subset 50             # quick run with N samples
    python run_experiment.py --ablation              # ablation study
    python run_experiment.py --bootstrap             # add CI computation
    python run_experiment.py --workers 16
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
from src.harness.memskill import MemSkillHarness
from src.safety import (SecurityPipeline, LlamaFirewallPipeline,
                        SystemPromptDefense, GuardrailPipeline)
from src.attacks import (context_poisoning, tool_tampering,
                         memory_injection, indirect_injection,
                         composite_attack)
from src.evaluation import rule_checker, llm_judge
from src.evaluation.metrics import compute_metrics

HARNESS_MAP = {
    "direct": DirectHarness,
    "react": ReactHarness,
    "multi_agent": MultiAgentHarness,
    "map_reduce": MapReduceHarness,
    "memskill": MemSkillHarness,
}

ATTACK_MAP: dict[str, Callable] = {
    "context_poisoning": context_poisoning.inject,
    "indirect_injection": indirect_injection.inject,
    "tool_tampering": tool_tampering.inject,
    "memory_injection": memory_injection.inject,
    "composite": composite_attack.inject,
}


@dataclass
class Job:
    task: dict[str, Any]
    model_name: str
    harness_type: str
    security_mode: str
    attack: str | None
    attack_fn: Callable | None
    ablation_name: str | None = None
    disable_layers: list[str] | None = None


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
    ablation: str | None = None


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _append_jsonl(path: Path, record_dict: dict, lock: threading.Lock) -> None:
    """Append one JSON object per line; safe for concurrent callers sharing *lock*."""
    line = json.dumps(record_dict, ensure_ascii=False) + "\n"
    with lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)


def build_security_pipeline(mode, registry, config, judge_model,
                            disable_layers=None):
    cfg = config.get("safety", {})
    if disable_layers:
        cfg = {**cfg, "disable_layers": disable_layers}

    if mode == "safe_harness":
        return SecurityPipeline(registry, cfg, judge_model)
    if mode == "llamafirewall":
        return LlamaFirewallPipeline(registry, cfg, judge_model)
    if mode == "system_prompt":
        return SystemPromptDefense()
    if mode == "guardrail":
        return GuardrailPipeline(cfg, judge_model)
    return None


def _run_job(job: Job, registry: ToolRegistry, cfg: dict,
             judge_model: str) -> Record:
    """Execute a single experiment job — fully independent, thread-safe."""
    task = job.attack_fn(job.task, seed=job.task["id"]) if job.attack_fn else job.task

    active_registry = registry
    if task.get("_tamper_registry"):
        active_registry = tool_tampering.tamper_registry(registry)

    harness_cfg = {**cfg["harness"], "security_mode": job.security_mode}
    harness = HARNESS_MAP[job.harness_type](job.model_name, active_registry, harness_cfg)
    pipeline = build_security_pipeline(
        job.security_mode, active_registry, cfg, judge_model,
        disable_layers=job.disable_layers,
    )
    env = SimulatedEnvironment()

    t0 = time.time()
    hr = harness.execute(task, env, pipeline)
    rr = rule_checker.check(hr)
    judge_temp = cfg.get("evaluation", {}).get("llm_judge", {}).get("temperature")
    jr = llm_judge.evaluate(hr, task, judge_model=judge_model,
                            temperature=judge_temp)
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
        ablation=job.ablation_name,
    )


def main():
    parser = argparse.ArgumentParser(description="SafeHarness Experiment (parallel)")
    parser.add_argument("--config", default="config/experiment.yaml")
    parser.add_argument("--subset", type=int, default=0,
                        help="Run on N samples (0 = use config default)")
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--ablation", action="store_true",
                        help="Run ablation study instead of main experiment")
    parser.add_argument("--bootstrap", action="store_true",
                        help="Compute bootstrap confidence intervals")
    args = parser.parse_args()

    cfg = load_config(args.config)
    output_dir = Path(args.output or cfg["project"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    max_workers = args.workers or cfg.get("parallel", {}).get("max_workers", 8)

    print("[*] Downloading / loading dataset …")
    download_dataset()

    if args.ablation:
        _run_ablation(cfg, output_dir, max_workers)
        return

    # Incremental JSON Lines log (survives crashes); cleared each new main run.
    jsonl_path = output_dir / "experiment_results.jsonl"
    jsonl_path.unlink(missing_ok=True)

    subset_size = args.subset or cfg["data"].get("experiment_subset_size",
                                                   cfg["data"]["demo_subset_size"])
    data_cfg = cfg.get("data", {})
    tasks = load_subset(
        subset_size,
        dataset_file=data_cfg.get("dataset_file"),
        sequential=data_cfg.get("sequential_subset", False),
    )
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
    print(f"[*] {total} jobs to run with {max_workers} workers.")
    print(f"[*] Appending each record to {jsonl_path} as jobs finish.\n")

    results = _execute_jobs(
        jobs, registry, cfg, judge_model, max_workers, jsonl_path=jsonl_path,
    )

    # ── Per-group metrics ──────────────────────────────────────
    _print_metrics_table(results, agent_models, harness_types,
                         security_modes, tasks)

    # ── Per-attack breakdown ──────────────────────────────────
    _print_per_attack_table(results, agent_models, harness_types,
                            security_modes, attack_types, tasks)

    # ── Per-risk-category breakdown ─────────────────────────────
    _print_per_category(results, tasks)

    # ── Bootstrap CIs + paired significance tests ─────────────
    if args.bootstrap:
        _print_bootstrap_cis(results, tasks, cfg)
        _print_paired_tests(results, agent_models, harness_types,
                            security_modes, tasks, cfg)

    # ── Save ───────────────────────────────────────────────────
    _save_results(results, output_dir / "experiment_results.json", cfg)


def _run_ablation(cfg, output_dir, max_workers):
    """Run ablation study: SafeHarness with individual layers disabled."""
    jsonl_path = Path(output_dir) / "ablation_results.jsonl"
    jsonl_path.unlink(missing_ok=True)

    abl_cfg = cfg.get("ablation", {})
    subset_size = abl_cfg.get("subset_size", 50)
    data_cfg = cfg.get("data", {})
    tasks = load_subset(
        subset_size,
        dataset_file=data_cfg.get("dataset_file"),
        sequential=data_cfg.get("sequential_subset", False),
    )
    print(f"[*] Ablation: {len(tasks)} tasks.")

    registry = build_default_registry()
    judge_model = cfg["models"]["judge_model"]
    # Single agent model to keep ablation cost manageable
    agent_model = cfg["models"]["agent_models"][0]
    harness_types = abl_cfg.get("harness_types", ["react", "multi_agent"])
    attack_types = cfg.get("attacks", {}).get("types", list(ATTACK_MAP.keys()))
    configs = abl_cfg.get("configs", [{"name": "full", "disable_layers": []}])

    jobs: list[Job] = []
    for abl in configs:
        for h_type in harness_types:
            for task in tasks:
                jobs.append(Job(
                    task, agent_model, h_type, "safe_harness", None, None,
                    ablation_name=abl["name"],
                    disable_layers=abl.get("disable_layers", []),
                ))
                for atk in attack_types:
                    jobs.append(Job(
                        task, agent_model, h_type, "safe_harness",
                        atk, ATTACK_MAP[atk],
                        ablation_name=abl["name"],
                        disable_layers=abl.get("disable_layers", []),
                    ))

    total = len(jobs)
    print(f"[*] Ablation: {total} jobs with {max_workers} workers.")
    print(f"[*] Appending each record to {jsonl_path} as jobs finish.\n")

    results = _execute_jobs(
        jobs, registry, cfg, judge_model, max_workers, jsonl_path=jsonl_path,
    )

    print("\n  Ablation Results:")
    print("-" * 80)
    for abl in configs:
        for h_type in harness_types:
            group = [r for r in results
                     if r.ablation == abl["name"] and r.harness == h_type]
            batch = _to_metric_tuples(group, tasks)
            m = compute_metrics(batch)
            d = m.summary_dict()
            print(f"  {abl['name']:<16} {h_type:<14} "
                  f"UBR={d['UBR']:.4f}  ASR={d['ASR']:.4f}  "
                  f"TCR={d['TCR']:.4f}  UA={d['UA']:.4f}")
    print("-" * 80)

    _save_results(results, output_dir / "ablation_results.json", cfg)


def _execute_jobs(jobs, registry, cfg, judge_model, max_workers,
                  jsonl_path: Path | None = None):
    results: list[Record] = []
    counter = {"done": 0}
    lock = threading.Lock()
    total = len(jobs)

    def _submit(job: Job) -> Record:
        rec = _run_job(job, registry, cfg, judge_model)
        with lock:
            counter["done"] += 1
            _print_row(rec, counter["done"], total)
        if jsonl_path is not None:
            _append_jsonl(jsonl_path, _rec_dict(rec), lock)
        return rec

    t_start = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_submit, job) for job in jobs]
        for future in as_completed(futures):
            results.append(future.result())

    wall_time = time.time() - t_start
    serial_time = sum(r.elapsed_s for r in results)
    speedup = serial_time / wall_time if wall_time > 0 else 0.0
    print(f"\n[*] Wall: {wall_time:.1f}s  |  Serial sum: {serial_time:.1f}s  "
          f"|  Speedup: {speedup:.1f}x")
    return results


def _print_metrics_table(results, agent_models, harness_types,
                         security_modes, tasks):
    from src.evaluation.metrics import compute_metrics
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


def _print_per_attack_table(results, agent_models, harness_types,
                            security_modes, attack_types, tasks):
    """Print a breakdown of UBR / ASR per attack type."""
    print("\n  Per-Attack Breakdown:")
    print("-" * 100)
    conditions = ["clean"] + list(attack_types)
    hdr = f"{'Model':<14} {'Harness':<12} {'Security':<14} " + " ".join(
        f"{c[:12]:>12}" for c in conditions)
    print(hdr)
    print("-" * 100)
    for model_name in agent_models:
        for h_type in harness_types:
            for s_mode in security_modes:
                parts = []
                for cond in conditions:
                    if cond == "clean":
                        group = [r for r in results
                                 if r.model == model_name
                                 and r.harness == h_type
                                 and r.security_mode == s_mode
                                 and r.attack is None]
                    else:
                        group = [r for r in results
                                 if r.model == model_name
                                 and r.harness == h_type
                                 and r.security_mode == s_mode
                                 and r.attack == cond]
                    batch = _to_metric_tuples(group, tasks)
                    m = compute_metrics(batch)
                    parts.append(f"{m.ubr:>5.1%}/{m.asr:>5.1%}")
                print(f"{model_name:<14} {h_type:<12} {s_mode:<14} "
                      + " ".join(f"{p:>12}" for p in parts))
    print("-" * 100)
    print("  (Format: UBR / ASR per attack condition)\n")


def _print_bootstrap_cis(results, tasks, cfg):
    from src.evaluation.statistics import compute_all_cis
    n_boot = cfg.get("evaluation", {}).get("bootstrap_samples", 1000)
    security_modes = cfg["security_modes"]
    harness_types = cfg["harness"]["types"]
    agent_models = cfg["models"]["agent_models"]

    print("\n  Bootstrap 95% Confidence Intervals:")
    print("-" * 80)
    for model in agent_models:
        for h_type in harness_types:
            for s_mode in security_modes:
                group = [r for r in results
                         if r.model == model and r.harness == h_type
                         and r.security_mode == s_mode]
                batch = _to_metric_tuples(group, tasks)
                cis = compute_all_cis(batch, n_bootstrap=n_boot)
                print(f"  {model}/{h_type}/{s_mode}:")
                for ci in cis:
                    print(f"    {ci}")
    print("-" * 80)


def _print_per_category(results, tasks):
    """Print metrics broken down by risk category."""
    from src.evaluation.statistics import per_category_metrics
    all_batch = _to_metric_tuples(results, tasks)
    cat_metrics = per_category_metrics(all_batch)
    if not cat_metrics:
        return
    print("\n  Per-Risk-Category Breakdown:")
    print("-" * 80)
    print(f"  {'Category':<30} {'UBR':>8} {'ASR':>8} {'TCR':>8} {'N':>6}")
    print("-" * 80)
    for cat, m in sorted(cat_metrics.items()):
        print(f"  {cat:<30} {m.ubr:>8.2%} {m.asr:>8.2%} "
              f"{m.tcr:>8.2%} {m.total:>6}")
    print("-" * 80)


def _print_paired_tests(results, agent_models, harness_types,
                        security_modes, tasks, cfg):
    """Run paired bootstrap tests: SafeHarness vs each baseline."""
    from src.evaluation.statistics import paired_bootstrap_test
    n_boot = cfg.get("evaluation", {}).get("bootstrap_samples", 1000)

    print("\n  Paired Bootstrap Significance Tests (SafeHarness vs baselines):")
    print("-" * 80)
    for model in agent_models:
        for h_type in harness_types:
            sh_group = [r for r in results
                        if r.model == model and r.harness == h_type
                        and r.security_mode == "safe_harness"]
            sh_batch = _to_metric_tuples(sh_group, tasks)
            if not sh_batch:
                continue
            for s_mode in security_modes:
                if s_mode == "safe_harness":
                    continue
                bl_group = [r for r in results
                            if r.model == model and r.harness == h_type
                            and r.security_mode == s_mode]
                bl_batch = _to_metric_tuples(bl_group, tasks)
                if not bl_batch:
                    continue
                for metric_name, metric_fn in [
                    ("UBR", lambda m: m.ubr),
                    ("ASR", lambda m: m.asr),
                ]:
                    test = paired_bootstrap_test(
                        sh_batch, bl_batch, metric_fn,
                        n_bootstrap=n_boot,
                        metric_name=metric_name,
                        config_a="SafeHarness",
                        config_b=s_mode,
                    )
                    print(f"  {model}/{h_type}: {test}")
    print("-" * 80)


def _save_results(results, out_file, cfg):
    all_dicts = sorted(
        [_rec_dict(r) for r in results],
        key=lambda x: (x["model"], x["harness"], x["security_mode"],
                        x["task_id"], x["attack"] or ""),
    )
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_dicts, f, ensure_ascii=False, indent=2)
    print(f"\n[*] Results saved → {out_file}")
    jl = out_file.with_suffix(".jsonl")
    if jl.exists():
        print(f"[*] (Incremental log still available at {jl})")


def _print_row(r: Record, done: int, total: int):
    lmap = {-1: "FAIL", 0: "SAFE", 1: "PART", 2: "UNSAFE"}
    label = lmap.get(r.judge_label, "?")
    atk = r.attack or "clean"
    rule = "RULE!" if r.rule_unsafe else "ok"
    abl = f" [{r.ablation}]" if r.ablation else ""
    print(f"  [{done:>4}/{total}] {r.model:<16} {r.harness:<12} "
          f"{r.security_mode:<14} task={r.task_id:<4} {atk:<20} "
          f"judge={label:<7} {rule:<6} blocked={r.blocked_count} "
          f"({r.elapsed_s:.1f}s){abl}")


def _rec_dict(r: Record) -> dict:
    d = {
        "model": r.model, "harness": r.harness,
        "security_mode": r.security_mode, "attack": r.attack,
        "task_id": r.task_id, "risks": r.risks,
        "judge_label": r.judge_label,
        "judge_reasoning": r.judge_reasoning,
        "rule_unsafe": r.rule_unsafe, "rule_details": r.rule_details,
        "blocked_count": r.blocked_count, "elapsed_s": r.elapsed_s,
    }
    if r.ablation:
        d["ablation"] = r.ablation
    return d


def _to_metric_tuples(records, tasks):
    from src.harness.base import HarnessResult
    from src.evaluation.llm_judge import JudgeResult
    from src.evaluation.rule_checker import RuleCheckResult
    from src.tools.simulated_tools import ToolCall
    task_map = {t["id"]: t for t in tasks}
    tuples = []
    for r in records:
        task = task_map.get(r.task_id, {"id": r.task_id})
        if r.attack:
            task = dict(task, _attack=r.attack)
        stub_blocked = [
            ToolCall(tool_name="unknown", arguments={}, blocked=True,
                     block_reason="reconstructed from record")
            for _ in range(r.blocked_count)
        ]
        hr = HarnessResult(
            task_id=r.task_id, harness_type=r.harness,
            security_mode=r.security_mode, final_response="",
            blocked_actions=stub_blocked,
        )
        jr = JudgeResult(label=r.judge_label, reasoning=r.judge_reasoning)
        rr = RuleCheckResult(is_unsafe=r.rule_unsafe,
                             triggered_rules=[], details=r.rule_details)
        tuples.append((task, hr, jr, rr))
    return tuples


if __name__ == "__main__":
    main()
