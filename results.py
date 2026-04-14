#!/usr/bin/env python3
"""
从 demo_results.json / experiment_results.json（或 .jsonl）重建指标。

输出顺序（与 run_demo 一致）：
  1. 全部攻击合并的主摘要表（clean + 各攻击一并聚合）；
  2. 再按「攻击方式」分别输出各子表。

支持消融结果：当记录含 ``ablation`` 字段且 ``--ablation`` 为 auto/on 时，输出
「对比表」——同一 Model×Harness×Security 下 **full / w/o_L1 / … 各占一行**，
便于与 full 对照（与 ``run_experiment.py --ablation`` 的 jsonl 一致）。

消融名称与论文层号对应：
  w/o_L1 = 禁用 L1 Inform（对抗性上下文过滤）
  w/o_L2 = 禁用 L2 Verify（因果安全验证）
  w/o_L3 = 禁用 L3 Constrain（特权分离工具控制）
  w/o_L4 = 禁用 L4 Correct（安全回滚与恢复）

用法:
  python results.py
  python results.py --path output/demo_results.json
  python results.py --path output/demo_results.jsonl
  python results.py --path output/experiment_results.json
  python results.py --path output/experiment_results.jsonl
  python results.py -o output/my_summary.txt
  python results.py --path output/ablation_results.jsonl --ablation auto
  python results.py --path output/ablation_results.jsonl --ablation on \\
      --ablation-order full,w/o_L1,w/o_L2,w/o_L3,w/o_L4,w/o_memory
  # --ablation off 时仍为主实验式「按行聚合」单表（消融配置会混在一起）
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

# 与 run_experiment / run_demo 一致，从仓库根目录解析 src
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.evaluation.metrics import compute_metrics

# 打印 / 制表顺序与 README.md「实验矩阵」及 config/experiment.yaml 一致
HARNESS_ORDER = ["react", "multi_agent", "memskill", "direct", "map_reduce"]
SECURITY_MODE_ORDER = [
    "unprotected",
    "system_prompt",
    "guardrail",
    "llamafirewall",
    "safe_harness",
]
# clean 优先，其余与 attacks.types 一致
ATTACK_ORDER = [
    "clean",
    "context_poisoning",
    "indirect_injection",
    "tool_tampering",
    "memory_injection",
    "composite",
]
# 与 config/experiment.yaml ablation.configs 的 name 顺序一致（便于对比论文表）
ABLATION_ORDER = [
    "full",
    "w/o_L1",
    "w/o_L2",
    "w/o_L3",
    "w/o_L4",
    "w/o_memory",
]


def _order_strings_present(canonical: list[str], present: set[str]) -> list[str]:
    """按 canonical 顺序列出 present 中存在的项；其余（未知键）按字典序接在末尾。"""
    ordered = [x for x in canonical if x in present]
    rest = sorted(present - set(ordered))
    return ordered + rest


def write_metrics_legend(write: Callable[[str], None]) -> None:
    """在汇总表最前说明各列含义及优劣方向（与 src/evaluation/metrics.py 一致）。"""
    write("=" * 72)
    write("指标说明（定义详见 src/evaluation/metrics.py）")
    write("-" * 72)
    write(
        "  UBR  不安全行为率：在「未整体判失败」的样本中，不安全行为占比。"
        "越低越好。"
    )
    write(
        "  ASR  攻击成功率：在「带攻击」的样本中，攻击仍导致不安全结果的占比。"
        "越低越好。"
    )
    write(
        "  TCR  任务完成率：未被判为整体失败（法官标签 ≠ FAILED）的样本占比。"
        "越高越好。"
    )
    write(
        "  UA   攻击下效用：在「带攻击」的样本中，既完成又安全的占比。"
        "越高越好。"
    )
    write(
        "  NNH  害处所需样本数：NNH = 1/UBR（UBR>0 时）；可理解为平均多少次才遇一次不安全。"
        "越高越好（与 UBR 反向）。"
    )
    write(
        "  ORR  过度拒绝率：在标注为可完成（fulfillable）的任务中，被判失败（拒绝）的占比。"
        "越低越好。"
    )
    write(
        "  Blk  拦截次数：安全管线拦截的动作总次数；需结合 UBR/TCR/ORR 解读，"
        "并非单纯越高或越低越好。"
    )
    write(
        "  N    样本条数：参与该单元格聚合的记录数；为规模信息，不表示优劣。"
    )
    write(
        "  表头符号：↓ 越低越好；↑ 越高越好；· 无单一优劣方向（Blk / N）。"
    )
    write("=" * 72)
    write()


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


def _ordered_attack_conditions(records: list[dict[str, Any]]) -> list[str]:
    labels = {_attack_label(r) for r in records}
    return _order_strings_present(ATTACK_ORDER, labels)


def _parse_csv_names(raw: str | None) -> list[str] | None:
    if not raw or not raw.strip():
        return None
    return [x.strip() for x in raw.split(",") if x.strip()]


def _partition_by_ablation(
    records: list[dict[str, Any]],
    mode: str,
    order_hint: list[str] | None,
) -> list[tuple[str | None, list[dict[str, Any]]]]:
    """返回 (段落标签, 子记录列表)。标签为 None 表示不打印消融前缀（整文件一份表）。"""
    has_field = any("ablation" in r for r in records)
    if mode == "off" or (mode == "auto" and not has_field):
        return [(None, records)]

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in records:
        name = r.get("ablation", "<no_ablation>")
        if not isinstance(name, str):
            name = str(name)
        groups[name].append(r)

    present = set(groups.keys())
    if order_hint:
        ordered = [x for x in order_hint if x in present]
        tail = sorted(present - set(ordered))
        names = ordered + tail
    else:
        names = _order_strings_present(ABLATION_ORDER, present)

    return [(n, groups[n]) for n in names]


def _slice_for_cell(
    chunk: list[dict[str, Any]],
    model: str,
    harness: str,
    security_mode: str,
    *,
    attack_scope: str | None,
) -> list[dict[str, Any]]:
    """attack_scope=None 表示该单元格与主「合并」表一致（不筛 attack）；否则为 ``clean`` 或具体攻击名。"""
    g = [
        r
        for r in chunk
        if r.get("model") == model
        and r.get("harness") == harness
        and r.get("security_mode") == security_mode
    ]
    if attack_scope is None:
        return g
    if attack_scope == "clean":
        return [r for r in g if r.get("attack") is None]
    return [r for r in g if r.get("attack") == attack_scope]


def print_ablation_comparison_block(
    title: str,
    sections: list[tuple[str, list[dict[str, Any]]]],
    models: list[str],
    harnesses: list[str],
    security_modes: list[str],
    *,
    attack_scope: str | None,
    write: Callable[[str], None],
) -> None:
    """同一 (model, harness, security) 下，各消融配置占一行，便于横向对比指标。"""
    abl_w = max(len("Ablation"), max((len(n) for n, _ in sections), default=8))
    abl_w = min(abl_w, 22)

    hdr = (
        f"{'Ablation':<{abl_w}} "
        f"{'UBR↓':>7} {'ASR↓':>7} {'TCR↑':>7} {'UA↑':>7} {'NNH↑':>7} "
        f"{'ORR↓':>7} {'Blk·':>6} {'N·':>5}"
    )
    rule = "-" * max(96, len(hdr))

    atk_note = "全部攻击合并" if attack_scope is None else (
        "clean (无攻击)" if attack_scope == "clean" else str(attack_scope)
    )

    for model in models:
        for h in harnesses:
            for sm in security_modes:
                nonempty = False
                for _, chunk in sections:
                    if _slice_for_cell(
                        chunk, model, h, sm, attack_scope=attack_scope
                    ):
                        nonempty = True
                        break
                if not nonempty:
                    continue

                write(f"\n{title}")
                write(f"    Model={model}  Harness={h}  Security={sm}  |  {atk_note}")
                write(rule)
                write(hdr)
                write(rule)
                for abl_name, chunk in sections:
                    group = _slice_for_cell(
                        chunk, model, h, sm, attack_scope=attack_scope
                    )
                    if not group:
                        continue
                    m = compute_metrics(records_to_metric_tuples(group))
                    d = m.summary_dict()
                    nnh_str = f"{d['NNH']}" if d["NNH"] != "inf" else " inf"
                    write(
                        f"{abl_name:<{abl_w}} "
                        f"{d['UBR']:>6.2%} {d['ASR']:>6.2%} {d['TCR']:>6.2%} "
                        f"{d['UA']:>6.2%} {nnh_str:>7} {d['ORR']:>6.2%} "
                        f"{d['blocked_count']:>6} {d['total']:>5}"
                    )
                write(rule)


def print_metrics_table(
    title: str,
    records: list[dict[str, Any]],
    models: list[str],
    harnesses: list[str],
    security_modes: list[str],
    write: Callable[[str], None],
) -> None:
    """与 run_demo 摘要表同列: UBR ASR TCR UA NNH Blocked；另附 total 与 ORR。"""
    write(f"\n{title}")
    hdr = (
        f"{'Model':<16} {'Harness':<14} {'Security':<14} "
        f"{'UBR↓':>7} {'ASR↓':>7} {'TCR↑':>7} {'UA↑':>7} {'NNH↑':>7} "
        f"{'ORR↓':>7} {'Blk·':>6} {'N·':>5}"
    )
    _rule = "-" * max(110, len(hdr))
    write(_rule)
    write(hdr)
    write(_rule)

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
                write(
                    f"{model:<16} {h:<14} {sm:<14} "
                    f"{d['UBR']:>6.2%} {d['ASR']:>6.2%} {d['TCR']:>6.2%} "
                    f"{d['UA']:>6.2%} {nnh_str:>7} {d['ORR']:>6.2%} "
                    f"{d['blocked_count']:>6} {d['total']:>5}"
                )
    write(_rule)


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
        "--output",
        "-o",
        type=Path,
        default=None,
        help="汇总输出 txt（默认: 与输入同目录、同主文件名 .txt，例如 demo_results.json → demo_results.txt）",
    )
    parser.add_argument(
        "--ablation",
        choices=("auto", "on", "off"),
        default="auto",
        help="消融分段: auto=仅当记录含 ablation 字段时按配置分表; on=始终按 ablation 分表"
        "（缺字段归入 <no_ablation>）; off=不区分消融（与旧版一致，适合主实验结果）。",
    )
    parser.add_argument(
        "--ablation-order",
        type=str,
        default=None,
        metavar="NAMES",
        help="消融配置名顺序，逗号分隔；未列出的名称按字典序排在后面。默认与 config/experiment.yaml 中 ablation.configs 一致。",
    )
    parser.add_argument(
        "--no-legend",
        action="store_true",
        help="不打印指标含义说明块。",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="不向 stdout 打印报表，仅写入 --output 指定文件。",
    )
    args = parser.parse_args()

    path: Path = args.path
    if not path.is_file():
        print(f"文件不存在: {path}", file=sys.stderr)
        sys.exit(1)

    out_txt: Path = args.output if args.output is not None else path.with_suffix(".txt")

    records = load_records(path)
    if not records:
        print("无记录。")
        return

    ablation_order = _parse_csv_names(args.ablation_order)
    sections = _partition_by_ablation(records, args.ablation, ablation_order)

    lines: list[str] = []

    def write(line: str = "") -> None:
        lines.append(line)
        if not args.quiet:
            print(line)

    if not args.no_legend:
        write_metrics_legend(write)

    write(f"[*] 载入 {len(records)} 条记录 ← {path}")
    write(f"    --ablation={args.ablation}  消融配置数={len(sections)}")
    if ablation_order:
        write(f"    --ablation-order 已指定: {ablation_order}")

    use_ablation_compare = sections[0][0] is not None

    if use_ablation_compare:
        models = sorted({str(r["model"]) for r in records})
        harnesses = _order_strings_present(
            HARNESS_ORDER,
            {str(r["harness"]) for r in records},
        )
        security_modes = _order_strings_present(
            SECURITY_MODE_ORDER,
            {str(r["security_mode"]) for r in records},
        )
        attacks = _ordered_attack_conditions(records)
        write("")
        write(
            "[*] 消融结果采用「对比表」：每个 Model×Harness×Security 子块中，"
            "行为各 ablation 配置（full / w/o_L* / …），列为指标，便于与 full 对照。"
        )
        write(f"    models={models}")
        write(f"    harnesses={harnesses}")
        write(f"    security_modes={security_modes}")
        write(f"    攻击条件顺序={attacks}")

        print_ablation_comparison_block(
            "[合并·消融对比]  (每子表内各行为一种消融配置)",
            sections,
            models,
            harnesses,
            security_modes,
            attack_scope=None,
            write=write,
        )

        for atk in attacks:
            scope = "clean" if atk == "clean" else atk
            print_ablation_comparison_block(
                f"[攻击方式·消融对比] {atk}  (末列 N· 为该单元格样本数)",
                sections,
                models,
                harnesses,
                security_modes,
                attack_scope=scope,
                write=write,
            )
    else:
        for abl_label, chunk in sections:
            models = sorted({str(r["model"]) for r in chunk})
            harnesses = _order_strings_present(
                HARNESS_ORDER,
                {str(r["harness"]) for r in chunk},
            )
            security_modes = _order_strings_present(
                SECURITY_MODE_ORDER,
                {str(r["security_mode"]) for r in chunk},
            )
            attacks = _ordered_attack_conditions(chunk)

            write(f"    models={models}")
            write(f"    harnesses={harnesses}")
            write(f"    security_modes={security_modes}")
            write(f"    攻击条件顺序={attacks}")

            prefix = f"[{abl_label}] " if abl_label is not None else ""
            print_metrics_table(
                f"{prefix}[合并] 全部攻击（与 run_demo 主摘要一致）  (N={len(chunk)})",
                chunk,
                models,
                harnesses,
                security_modes,
                write=write,
            )

            for atk in attacks:
                if atk == "clean":
                    sub = [r for r in chunk if r.get("attack") is None]
                else:
                    sub = [r for r in chunk if r.get("attack") == atk]
                print_metrics_table(
                    f"{prefix}[攻击方式] {atk}  (N={len(sub)})",
                    sub,
                    models,
                    harnesses,
                    security_modes,
                    write=write,
                )

    write(
        "\n说明: UBR/ASR/TCR/UA/NNH/ORR 定义见 src/evaluation/metrics.py；"
        "clean 场景下 ASR/UA 分母为 0 时指标为 0。"
    )

    out_txt.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines) + "\n"
    out_txt.write_text(text, encoding="utf-8")
    print(f"\n[*] 已写入: {out_txt.resolve()}", file=sys.stderr)


if __name__ == "__main__":
    main()
