#!/usr/bin/env python3
"""
从 demo_results.json / experiment_results.json（或 .jsonl）重建指标，
按「攻击方式」分组打印与 run_experiment / run_demo 一致的聚合指标。

用法:
  python results.py
  python results.py --path output/demo_results.json
  python results.py --path output/demo_results.jsonl
  python results.py --path output/experiment_results.json
  python results.py --path output/experiment_results.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# 与 run_experiment / run_demo 一致，从仓库根目录解析 src
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.evaluation.metrics import compute_metrics


def load_records(path: Path) -> list[dict[str, Any]]:
    """支持: { "records": [...] }、顶层 JSON 数组、JSON Lines。"""
    if path.suffix.lower() == ".jsonl":
        rows: list[dict[str, Any]] = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
        return rows

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "records" in data:
        return data["records"]
    raise ValueError(
        f"无法解析 {path}: 需要 JSON 数组、或包含 \"records\" 的对象、或 .jsonl"
    )


def records_to_metric_tuples(records: list[dict[str, Any]]) -> list[tuple]:
    """与 run_demo._records_to_metric_tuples / run_experiment._to_metric_tuples 等价逻辑。"""
    from src.harness.base import HarnessResult
    from src.evaluation.llm_judge import JudgeResult
    from src.evaluation.rule_checker import RuleCheckResult
    from src.tools.simulated_tools import ToolCall

    tuples: list[tuple] = []
    for r in records:
        task: dict[str, Any] = {
            "id": r["task_id"],
            "risks": r.get("risks", []),
            "fulfillable": r.get("fulfillable", 1),
        }
        if r.get("attack"):
            task = dict(task, _attack=r["attack"])
        stub_blocked = [
            ToolCall(
                tool_name="unknown",
                arguments={},
                blocked=True,
                block_reason="reconstructed from record",
            )
            for _ in range(r.get("blocked_count", 0))
        ]
        hr = HarnessResult(
            task_id=r["task_id"],
            harness_type=r["harness"],
            security_mode=r["security_mode"],
            final_response="",
            blocked_actions=stub_blocked,
        )
        jr = JudgeResult(
            label=r["judge_label"],
            reasoning=r.get("judge_reasoning", ""),
        )
        rr = RuleCheckResult(
            is_unsafe=r.get("rule_unsafe", False),
            triggered_rules=[],
            details=r.get("rule_details", ""),
        )
        tuples.append((task, hr, jr, rr))
    return tuples


def _attack_label(r: dict[str, Any]) -> str:
    a = r.get("attack")
    return "clean" if a is None else str(a)


def _sorted_attack_conditions(records: list[dict[str, Any]]) -> list[str]:
    labels = {_attack_label(r) for r in records}
    # clean 放最前，其余按字典序
    out = []
    if "clean" in labels:
        out.append("clean")
        labels.discard("clean")
    out.extend(sorted(labels))
    return out


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted(set(values))


def print_metrics_table(
    title: str,
    records: list[dict[str, Any]],
    models: list[str],
    harnesses: list[str],
    security_modes: list[str],
) -> None:
    """与 run_demo 摘要表同列: UBR ASR TCR UA NNH Blocked；另附 total 与 ORR。"""
    print(f"\n{title}")
    print("-" * 110)
    hdr = (
        f"{'Model':<16} {'Harness':<14} {'Security':<14} "
        f"{'UBR':>7} {'ASR':>7} {'TCR':>7} {'UA':>7} {'NNH':>7} "
        f"{'ORR':>7} {'Blk':>6} {'N':>5}"
    )
    print(hdr)
    print("-" * 110)

    for model in models:
        for h in harnesses:
            for sm in security_modes:
                group = [
                    r
                    for r in records
                    if r.get("model") == model
                    and r.get("harness") == h
                    and r.get("security_mode") == sm
                ]
                if not group:
                    continue
                m = compute_metrics(records_to_metric_tuples(group))
                d = m.summary_dict()
                nnh_str = f"{d['NNH']}" if d["NNH"] != "inf" else " inf"
                print(
                    f"{model:<16} {h:<14} {sm:<14} "
                    f"{d['UBR']:>6.2%} {d['ASR']:>6.2%} {d['TCR']:>6.2%} "
                    f"{d['UA']:>6.2%} {nnh_str:>7} {d['ORR']:>6.2%} "
                    f"{d['blocked_count']:>6} {d['total']:>5}"
                )
    print("-" * 110)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="按攻击方式汇总 SafeHarness 实验指标（与 run_experiment / run_demo 一致）"
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=_ROOT / "output" / "demo_results.json",
        help="结果 JSON 或 JSONL（默认: output/demo_results.json）",
    )
    parser.add_argument(
        "--merged",
        action="store_true",
        help="额外打印不分攻击方式的合并表（等同实验主摘要）",
    )
    args = parser.parse_args()

    path: Path = args.path
    if not path.is_file():
        print(f"文件不存在: {path}", file=sys.stderr)
        sys.exit(1)

    records = load_records(path)
    if not records:
        print("无记录。")
        return

    models = _unique_sorted([str(r["model"]) for r in records])
    harnesses = _unique_sorted([str(r["harness"]) for r in records])
    security_modes = _unique_sorted([str(r["security_mode"]) for r in records])
    attacks = _sorted_attack_conditions(records)

    print(f"[*] 载入 {len(records)} 条记录 ← {path}")
    print(f"    models={models}")
    print(f"    harnesses={harnesses}")
    print(f"    security_modes={security_modes}")
    print(f"    攻击条件顺序={attacks}")

    if args.merged:
        print_metrics_table(
            "[合并] 全部攻击混在一起（与 run_experiment 主表一致）",
            records,
            models,
            harnesses,
            security_modes,
        )

    for atk in attacks:
        if atk == "clean":
            sub = [r for r in records if r.get("attack") is None]
        else:
            sub = [r for r in records if r.get("attack") == atk]
        print_metrics_table(
            f"[攻击方式] {atk}  (N={len(sub)})",
            sub,
            models,
            harnesses,
            security_modes,
        )

    print(
        "\n说明: UBR/ASR/TCR/UA/NNH/ORR 定义见 src/evaluation/metrics.py；"
        "clean 场景下 ASR/UA 分母为 0 时指标为 0。"
    )


if __name__ == "__main__":
    main()
