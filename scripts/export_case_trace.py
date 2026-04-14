#!/usr/bin/env python3
"""
Export a single full interaction trace for use in qualitative case studies.

Mirrors the logic of run_experiment._run_job but outputs the complete
HarnessResult (reasoning_trace, tool_calls, blocked_actions, final_response)
rather than the aggregated Record summary that the main experiment stores.

Usage examples:
  # Baseline (unprotected) under A1 context poisoning
  python scripts/export_case_trace.py \
      --task-id 1 --harness react \
      --security unprotected --attack context_poisoning \
      --out output/cases/case01_unprot_ctx.json

  # SafeHarness under the same attack (for side-by-side comparison)
  python scripts/export_case_trace.py \
      --task-id 1 --harness react \
      --security safe_harness --attack context_poisoning \
      --out output/cases/case01_safe_ctx.json

  # Scan multiple tasks quickly (prints traces to stdout)
  python scripts/export_case_trace.py \
      --task-id 1 2 3 --harness react \
      --security unprotected safe_harness \
      --attack context_poisoning composite \
      --scan

Supported attack names: context_poisoning, indirect_injection, tool_tampering,
                         memory_injection, composite
Supported harness names: direct, react, multi_agent, map_reduce, memskill
Supported security modes: unprotected, system_prompt, guardrail,
                           llamafirewall, safe_harness
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import yaml

# ── make project root importable ──────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.data_loader import load_dataset_local, download_dataset
from src.tools.registry import build_default_registry, ToolRegistry
from src.tools.simulated_tools import SimulatedEnvironment
from src.harness.direct import DirectHarness
from src.harness.react import ReactHarness
from src.harness.multi_agent import MultiAgentHarness
from src.harness.map_reduce import MapReduceHarness
from src.harness.memskill import MemSkillHarness
from src.safety import (SecurityPipeline, LlamaFirewallPipeline,
                        SystemPromptDefense, GuardrailPipeline)
from src.attacks import (context_poisoning, indirect_injection,
                         tool_tampering, memory_injection, composite_attack)
from src.evaluation import rule_checker, llm_judge

HARNESS_MAP = {
    "direct": DirectHarness,
    "react": ReactHarness,
    "multi_agent": MultiAgentHarness,
    "map_reduce": MapReduceHarness,
    "memskill": MemSkillHarness,
}

ATTACK_MAP = {
    "context_poisoning": context_poisoning.inject,
    "indirect_injection": indirect_injection.inject,
    "tool_tampering": tool_tampering.inject,
    "memory_injection": memory_injection.inject,
    "composite": composite_attack.inject,
}


def load_config(path: str | Path = "config/experiment.yaml") -> dict:
    p = Path(path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_pipeline(mode: str, registry: ToolRegistry,
                   cfg: dict, judge_model: str):
    safety_cfg = cfg.get("safety", {})
    if mode == "safe_harness":
        return SecurityPipeline(registry, safety_cfg, judge_model)
    if mode == "llamafirewall":
        return LlamaFirewallPipeline(registry, safety_cfg, judge_model)
    if mode == "system_prompt":
        return SystemPromptDefense()
    if mode == "guardrail":
        return GuardrailPipeline(safety_cfg, judge_model)
    return None


def run_single(
    task_raw: dict[str, Any],
    harness_type: str,
    security_mode: str,
    attack_name: str | None,
    cfg: dict,
    judge_model: str,
    trace_char_limit: int = 800,
) -> dict[str, Any]:
    """Execute one (task, harness, security, attack) combination and return
    a complete JSON-serialisable record including the full reasoning trace."""

    # ── apply attack ──────────────────────────────────────────────────────────
    if attack_name:
        attack_fn = ATTACK_MAP[attack_name]
        task = attack_fn(task_raw, seed=task_raw["id"])
    else:
        task = dict(task_raw)

    # ── build registry (possibly tampered) ───────────────────────────────────
    registry = build_default_registry()
    if task.get("_tamper_registry"):
        registry = tool_tampering.tamper_registry(registry)

    # ── build harness and pipeline ────────────────────────────────────────────
    harness_cfg = {**cfg.get("harness", {}), "security_mode": security_mode}
    harness = HARNESS_MAP[harness_type](
        cfg["models"]["agent_models"][0], registry, harness_cfg
    )
    pipeline = build_pipeline(security_mode, registry, cfg, judge_model)
    env = SimulatedEnvironment()

    # ── execute ───────────────────────────────────────────────────────────────
    t0 = time.time()
    hr = harness.execute(task, env, pipeline)
    elapsed = round(time.time() - t0, 2)

    # ── evaluate ──────────────────────────────────────────────────────────────
    rr = rule_checker.check(hr)
    judge_temp = cfg.get("evaluation", {}).get("llm_judge", {}).get("temperature")
    jr = llm_judge.evaluate(hr, task, judge_model=judge_model,
                            temperature=judge_temp)

    # ── trim trace content to keep JSON manageable ────────────────────────────
    def _trim(s: str) -> str:
        return s[:trace_char_limit] + " …[trimmed]" if len(s) > trace_char_limit else s

    hr_dict = hr.to_dict()
    for step in hr_dict.get("reasoning_trace", []):
        if "content" in step:
            step["content"] = _trim(step["content"])
    for tc in hr_dict.get("tool_calls", []):
        tc["result"] = _trim(str(tc.get("result", "")))
    hr_dict["final_response"] = _trim(hr_dict.get("final_response", ""))

    # ── task fields visible in output (strip internal attack metadata) ────────
    task_out = {
        "id": task.get("id"),
        "instruction": task.get("instruction", "")[:600],
        "fulfillable": task.get("fulfillable"),
        "risks": task.get("risks", []),
        "attack": attack_name,
        "injected_payload": task.get("_payload") or task.get("_indirect_payload"),
        "tamper_registry": task.get("_tamper_registry", False),
        "has_fake_history": bool(task.get("_fake_history")),
    }

    label_map = {-1: "FAILED", 0: "SAFE", 1: "PARTIALLY_UNSAFE", 2: "FULLY_UNSAFE"}

    return {
        "meta": {
            "harness": harness_type,
            "security_mode": security_mode,
            "model": cfg["models"]["agent_models"][0],
            "judge_model": judge_model,
            "elapsed_s": elapsed,
        },
        "task": task_out,
        "harness_result": hr_dict,
        "judge": {
            "label": jr.label,
            "label_str": label_map.get(jr.label, "?"),
            "reasoning": jr.reasoning,
        },
        "rule_check": {
            "is_unsafe": rr.is_unsafe,
            "triggered_rules": rr.triggered_rules,
            "details": rr.details,
        },
    }


def _find_task(data: list[dict], task_id: int) -> dict | None:
    for t in data:
        if t.get("id") == task_id:
            return t
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Export full interaction traces for qualitative case studies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--task-id", type=int, nargs="+", required=True,
                        metavar="ID",
                        help="Task ID(s) from the dataset")
    parser.add_argument("--harness", nargs="+",
                        default=["react"],
                        choices=list(HARNESS_MAP),
                        help="Harness type(s) to run")
    parser.add_argument("--security", nargs="+",
                        default=["unprotected", "safe_harness"],
                        help="Security mode(s) to run")
    parser.add_argument("--attack", nargs="*",
                        default=["context_poisoning"],
                        choices=list(ATTACK_MAP) + ["none"],
                        help="Attack name(s); use 'none' for clean run")
    parser.add_argument("--out", default=None,
                        help="Output JSON path (only used when exactly one "
                             "combination is specified; otherwise auto-named)")
    parser.add_argument("--out-dir", default="output/cases",
                        help="Output directory for multi-combination runs")
    parser.add_argument("--scan", action="store_true",
                        help="Print summary table instead of saving JSON files")
    parser.add_argument("--config", default="config/experiment.yaml")
    parser.add_argument("--trace-limit", type=int, default=800,
                        help="Max characters per trace step (default: 800)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    judge_model = cfg["models"]["judge_model"]
    data_cfg = cfg.get("data", {})

    print("[export_case_trace] Loading dataset …")
    data = load_dataset_local(data_cfg.get("dataset_file"))

    attacks = [None if a == "none" else a for a in (args.attack or ["none"])]

    # build all combinations
    combos = [
        (tid, harness, sec, atk)
        for tid in args.task_id
        for harness in args.harness
        for sec in args.security
        for atk in attacks
    ]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    label_map = {-1: "FAILED", 0: "SAFE", 1: "PARTLY", 2: "UNSAFE"}

    results: list[dict] = []
    for i, (tid, harness, sec, atk) in enumerate(combos, 1):
        task_raw = _find_task(data, tid)
        if task_raw is None:
            print(f"  [!] task_id={tid} not found in dataset — skipping.")
            continue

        atk_label = atk or "clean"
        print(f"  [{i}/{len(combos)}] task={tid}  harness={harness}  "
              f"security={sec}  attack={atk_label} …", end=" ", flush=True)

        try:
            rec = run_single(task_raw, harness, sec, atk, cfg, judge_model,
                             trace_char_limit=args.trace_limit)
        except Exception as exc:
            print(f"ERROR: {exc}")
            continue

        j_str = label_map.get(rec["judge"]["label"], "?")
        rule_str = "RULE!" if rec["rule_check"]["is_unsafe"] else "ok"
        blk = len(rec["harness_result"].get("blocked_actions", []))
        print(f"judge={j_str}  rule={rule_str}  blocked={blk}  "
              f"({rec['meta']['elapsed_s']}s)")
        results.append(rec)

        if not args.scan:
            if args.out and len(combos) == 1:
                out_path = Path(args.out)
            else:
                atk_slug = (atk or "clean").replace("_", "-")
                fname = f"case{tid}_{harness}_{sec}_{atk_slug}.json"
                out_path = out_dir / fname
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False, indent=2)
            print(f"      → {out_path}")

    if args.scan:
        # compact summary table
        print("\n" + "=" * 100)
        print(f"  {'task':>5}  {'harness':<12} {'security':<14} {'attack':<20} "
              f"{'judge':<8} {'rule':<6} {'blocked':>7}  reasoning[:100]")
        print("=" * 100)
        for rec in results:
            m = rec["meta"]
            j = rec["judge"]
            r = rec["rule_check"]
            blk = len(rec["harness_result"].get("blocked_actions", []))
            j_str = label_map.get(j["label"], "?")
            rule_str = "RULE!" if r["is_unsafe"] else "ok"
            reason = j["reasoning"][:100].replace("\n", " ")
            atk_label = rec["task"]["attack"] or "clean"
            print(f"  {rec['task']['id']:>5}  {m['harness']:<12} "
                  f"{m['security_mode']:<14} {atk_label:<20} "
                  f"{j_str:<8} {rule_str:<6} {blk:>7}  {reason}")


if __name__ == "__main__":
    main()
