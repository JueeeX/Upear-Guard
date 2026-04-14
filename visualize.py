#!/usr/bin/env python3
"""从 SafeHarness ``output/`` 下的主实验结果（JSON / JSONL）生成图表。

默认从 ``output/`` 自动选取结果文件（跳过文件名含 ablation 的消融结果）。
消融结果暂不绘图；若显式传入 ablation 文件将提示并退出。

用法:
  python visualize.py
  python visualize.py output/ds_chat_experiment_results.jsonl
  python visualize.py output/ds_r1_experiment_results.jsonl
  python visualize.py --input output/experiment_results.jsonl --output-dir output/figures_run1
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from collections import defaultdict
from typing import Any

import matplotlib
from matplotlib import colors as mcolors

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from results import load_records, records_to_metric_tuples  # noqa: E402
from src.evaluation.metrics import compute_metrics  # noqa: E402

# ---------- palette & style（与 config/experiment.yaml 矩阵对齐）----------

SECURITY_COLORS = {
    "unprotected": "#E74C3C",
    "system_prompt": "#9B59B6",
    "guardrail": "#1ABC9C",
    "llamafirewall": "#3498DB",
    "safe_harness": "#2ECC71",
}
SECURITY_LABELS = {
    "unprotected": "Unprotected",
    "system_prompt": "System Prompt",
    "guardrail": "Guardrail",
    "llamafirewall": "LlamaFirewall",
    "safe_harness": "SafeHarness",
}
SECURITY_ORDER = [
    "unprotected",
    "system_prompt",
    "guardrail",
    "llamafirewall",
    "safe_harness",
]

HARNESS_ORDER = ["direct", "react", "multi_agent", "map_reduce", "memskill"]
HARNESS_LABELS = {
    "direct": "Direct",
    "react": "ReAct",
    "multi_agent": "Multi-Agent",
    "map_reduce": "Map-Reduce",
    "memskill": "Self-Evolving",
}

ATTACK_COLORS = {
    "clean": "#95A5A6",
    "context_poisoning": "#E67E22",
    "indirect_injection": "#D35400",
    "tool_tampering": "#8E44AD",
    "memory_injection": "#C0392B",
    "composite": "#16A085",
}
ATTACK_LABELS = {
    "clean": "Clean",
    "context_poisoning": "Context Poisoning",
    "indirect_injection": "Indirect Injection",
    "tool_tampering": "Tool Tampering",
    "memory_injection": "Memory Injection",
    "composite": "Composite",
}
ATTACK_ORDER = [
    "clean",
    "context_poisoning",
    "indirect_injection",
    "tool_tampering",
    "memory_injection",
    "composite",
]

LABEL_COLORS = {
    -1: "#BDC3C7",
    0: "#27AE60",
    1: "#F39C12",
    2: "#C0392B",
}
LABEL_NAMES = {
    -1: "Failed (-1)",
    0: "Safe (0)",
    1: "Partial Unsafe (1)",
    2: "Fully Unsafe (2)",
}

plt.rcParams.update(
    {
        "font.family": "Times New Roman",
        "axes.unicode_minus": False,
        "xtick.direction": "in",
        "ytick.direction": "in",
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.labelsize": 11,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "figure.dpi": 150,
    }
)


TECH_PURPLE = "#6B5BFF"
TECH_PURPLE_DARK = "#3E37B3"
TECH_TEXT = "#222230"


def _harnesses_present(records: list[dict[str, Any]]) -> list[str]:
    present = {str(r["harness"]) for r in records}
    return [h for h in HARNESS_ORDER if h in present] + sorted(
        present - set(HARNESS_ORDER)
    )


def _security_present(records: list[dict[str, Any]]) -> list[str]:
    present = {str(r["security_mode"]) for r in records}
    return [s for s in SECURITY_ORDER if s in present] + sorted(
        present - set(SECURITY_ORDER)
    )


def _attacks_present(records: list[dict[str, Any]]) -> list[str]:
    labels: set[str] = set()
    for r in records:
        labels.add("clean" if r.get("attack") in (None, "") else str(r["attack"]))
    ordered = [a for a in ATTACK_ORDER if a in labels]
    ordered += sorted(labels - set(ordered))
    return ordered


def _sec_color(sec: str) -> str:
    return SECURITY_COLORS.get(sec, "#7F8C8D")


def _atk_color(atk: str) -> str:
    return ATTACK_COLORS.get(atk, "#34495E")


def _gray_hex(index: int, total: int, start: float = 0.90, end: float = 0.38) -> str:
    if total <= 1:
        shade = (start + end) / 2.0
    else:
        shade = start - index * ((start - end) / (total - 1))
    channel = max(0, min(255, int(round(shade * 255))))
    return f"#{channel:02X}{channel:02X}{channel:02X}"


def _security_style(sec: str, securities: list[str]) -> tuple[str, str, str | None, float]:
    other_secs = [name for name in securities if name != "safe_harness"]
    if sec == "safe_harness":
        return TECH_PURPLE, TECH_PURPLE_DARK, "///", 0.0
    idx = other_secs.index(sec) if sec in other_secs else 0
    return _gray_hex(idx, max(len(other_secs), 1), start=0.88, end=0.40), "none", None, 0.0


def _attack_style(atk: str, attacks: list[str]) -> str:
    non_composite = [name for name in attacks if name != "composite"]
    if atk == "composite":
        return _gray_hex(0, 1, start=0.26, end=0.26)
    n = max(len(non_composite), 1)
    idx = non_composite.index(atk) if atk in non_composite else 0
    return _gray_hex(idx, n, start=0.90, end=0.50)


def _style_axis_text(ax: plt.Axes, x_size: int, y_size: int) -> None:
    ax.tick_params(axis="x", labelsize=x_size, width=1.1)
    ax.tick_params(axis="y", labelsize=y_size, width=1.1)
    for label in ax.get_xticklabels() + ax.get_yticklabels():
        label.set_fontweight("bold")
        label.set_color(TECH_TEXT)


def filter_main_experiment_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """去掉消融行（含 ``ablation`` 字段的记录），主实验结果不受影响。"""
    return [r for r in records if "ablation" not in r]


def build_summary(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """按 (harness, security_mode) 聚合，生成与旧 ``demo_results.summary`` 兼容的列表。"""
    harnesses = _harnesses_present(records)
    security_modes = _security_present(records)
    summary: list[dict[str, Any]] = []
    for h in harnesses:
        for sm in security_modes:
            group = [
                r
                for r in records
                if str(r.get("harness")) == h and str(r.get("security_mode")) == sm
            ]
            if not group:
                continue
            m = compute_metrics(records_to_metric_tuples(group))
            d = m.summary_dict()
            nnh = d["NNH"]
            nnh_f = float("inf") if nnh == "inf" else float(nnh)
            summary.append(
                {
                    "harness": h,
                    "security": sm,
                    "UBR": float(d["UBR"]),
                    "ASR": float(d["ASR"]),
                    "TCR": float(d["TCR"]),
                    "UA": float(d["UA"]),
                    "NNH": nnh_f,
                    "ORR": float(d["ORR"]),
                    "total": int(d["total"]),
                }
            )
    return summary


def pick_results_file(output_dir: Path) -> Path | None:
    """在 ``output/`` 下挑选主实验结果文件；跳过文件名含 ``ablation`` 的项。"""
    if not output_dir.is_dir():
        return None
    candidates: list[Path] = []
    for p in output_dir.iterdir():
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".json", ".jsonl"):
            continue
        if "ablation" in p.name.lower():
            continue
        candidates.append(p)

    for preferred in ("experiment_results.jsonl", "experiment_results.json"):
        hit = output_dir / preferred
        if hit in candidates:
            return hit

    exp_like = [
        p
        for p in candidates
        if "experiment" in p.name.lower() and "results" in p.name.lower()
    ]
    if exp_like:
        exp_like.sort(key=lambda x: (x.suffix.lower() != ".jsonl", x.name))
        return exp_like[0]

    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def load_demo_style(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """返回 (records, summary)。若为旧版 ``{records, summary}`` JSON 则直接使用 summary。"""
    if path.suffix.lower() == ".jsonl":
        records = load_records(path)
        return records, build_summary(records)

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "records" in data and "summary" in data:
        rec = data["records"]
        summ = data["summary"]
        if isinstance(rec, list) and isinstance(summ, list):
            return rec, summ

    if isinstance(data, list):
        return data, build_summary(data)

    raise ValueError(
        f"无法解析 {path}: 需要 JSONL、顶层数组、或包含 records/summary 的对象"
    )


# ===================================================================
# Figure 1 – UBR grouped bar chart (Harness x Security)
# ===================================================================
def fig1_ubr_bar(summary: list[dict[str, Any]], harnesses: list[str], securities: list[str], out_dir: Path):
    fig, ax = plt.subplots(figsize=(max(10, len(harnesses) * 2.0), 6.6))
    x = np.arange(len(harnesses))
    n_sec = len(securities)
    pitch = min(0.84 / max(n_sec, 1), 0.18)
    bar_width = pitch * 0.92

    lookup = {(s["harness"], s["security"]): s for s in summary}
    other_secs = [sec for sec in securities if sec != "safe_harness"]

    for i, sec in enumerate(securities):
        offset = (i - (n_sec - 1) / 2.0) * pitch
        vals = [lookup.get((h, sec), {}).get("UBR", 0.0) for h in harnesses]
        if sec == "safe_harness":
            color = "#6B5BFF"
            edgecolor = "#3E37B3"
            hatch = "///"
            linewidth = 0.0
        else:
            idx = other_secs.index(sec) if sec in other_secs else 0
            if len(other_secs) <= 1:
                shade = 0.72
            else:
                shade = 0.88 - idx * (0.50 / (len(other_secs) - 1))
            channel = max(0, min(255, int(round(shade * 255))))
            color = f"#{channel:02X}{channel:02X}{channel:02X}"
            edgecolor = "none"
            hatch = None
            linewidth = 0.0
        bars = ax.bar(
            x + offset,
            vals,
            bar_width,
            label=SECURITY_LABELS.get(sec, sec),
            color=color,
            edgecolor=edgecolor,
            linewidth=linewidth,
            hatch=hatch,
            zorder=3,
        )
        for bar, v in zip(bars, vals):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.015,
                f"{v:.1%}",
                ha="center",
                va="bottom",
                fontsize=10,
                fontweight="bold",
            )

    ax.set_xticks(x)
    ax.set_xticklabels(
        [HARNESS_LABELS.get(h, h) for h in harnesses],
        fontsize=20,
        fontweight="bold",
    )
    ax.set_ylabel("UBR (Unsafe Behavior Rate)", fontsize=24, fontweight="bold")
    ax.set_title(
        "Unsafe Behavior Rate: Harness x Security Mode",
        fontsize=26,
        fontweight="bold",
        pad=18,
    )
    ax.set_ylim(0, 1.08)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    ax.tick_params(axis="y", labelsize=20, width=1.1)
    for label in ax.get_yticklabels():
        label.set_fontweight("bold")
    ax.grid(axis="y", linestyle="--", linewidth=0.8, alpha=0.25, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(
        loc="upper right",
        ncol=min(3, n_sec),
        frameon=False,
        prop={"size": 19, "weight": "bold"},
    )
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines["left"].set_linewidth(1.1)
    ax.spines["bottom"].set_linewidth(1.1)

    path = out_dir / "fig1_ubr_bar.pdf"
    fig.tight_layout()
    fig.savefig(path, dpi=1200)
    plt.close(fig)
    return path


# ===================================================================
# Figure 2 – ASR heatmap
# ===================================================================
def fig2_asr_heatmap(
    summary: list[dict[str, Any]], harnesses: list[str], securities: list[str], out_dir: Path
):
    lookup = {(s["harness"], s["security"]): s for s in summary}
    matrix = np.array(
        [
            [lookup.get((h, sec), {}).get("ASR", 0.0) for sec in securities]
            for h in harnesses
        ]
    )

    fig_w = max(9.0, len(securities) * 1.6)
    fig_h = max(5.8, len(harnesses) * 1.1)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    cmap = mcolors.LinearSegmentedColormap.from_list(
        "tech_purple_heat",
        ["#F4F4F8", "#DBDBE4", "#BBBBCA", "#8B80FF", "#221A78"],
    )
    im = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(len(securities)))
    ax.set_xticklabels(
        [SECURITY_LABELS.get(s, s) for s in securities],
        rotation=18,
        ha="right",
        fontsize=18,
        fontweight="bold",
    )
    ax.set_yticks(range(len(harnesses)))
    ax.set_yticklabels(
        [HARNESS_LABELS.get(h, h) for h in harnesses],
        fontsize=18,
        fontweight="bold",
    )
    ax.set_xticks(np.arange(-0.5, len(securities), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(harnesses), 1), minor=True)
    ax.grid(which="minor", color="white", linestyle="-", linewidth=2.0)
    ax.tick_params(which="minor", bottom=False, left=False)

    for i in range(len(harnesses)):
        for j in range(len(securities)):
            val = matrix[i, j]
            color = "white" if val > 0.55 else TECH_TEXT
            ax.text(
                j,
                i,
                f"{val:.2%}",
                ha="center",
                va="center",
                fontsize=15,
                fontweight="bold",
                color=color,
            )

    ax.set_title("Attack Success Rate Heatmap (ASR)", fontsize=26, fontweight="bold", pad=18)
    _style_axis_text(ax, x_size=18, y_size=18)
    for spine in ax.spines.values():
        spine.set_visible(False)
    cbar = fig.colorbar(im, ax=ax, label="ASR", shrink=0.84)
    cbar.ax.tick_params(labelsize=16, width=1.0)
    for label in cbar.ax.get_yticklabels():
        label.set_fontweight("bold")
        label.set_color(TECH_TEXT)
    cbar.set_label("ASR", fontsize=18, fontweight="bold")

    path = out_dir / "fig2_asr_heatmap.pdf"
    fig.tight_layout()
    fig.savefig(path, dpi=1200)
    plt.close(fig)
    return path


# ===================================================================
# Figure 3 – Attack effectiveness (Harness x Attack type)
# ===================================================================
def fig3_attack_effectiveness(
    records: list[dict[str, Any]], harnesses: list[str], attacks: list[str], out_dir: Path
):
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"unsafe": 0, "total": 0}
    )
    for r in records:
        atk = "clean" if not r.get("attack") else str(r["attack"])
        key = (str(r["harness"]), atk)
        counts[key]["total"] += 1
        if r.get("judge_label") in (1, 2):
            counts[key]["unsafe"] += 1

    n_atk = len(attacks)
    fig_w = max(11.0, len(harnesses) * 2.0)
    fig, ax = plt.subplots(figsize=(fig_w, 6.4))
    x = np.arange(len(harnesses))
    pitch = min(0.84 / max(n_atk, 1), 0.15)
    bar_width = pitch * 0.92

    for i, atk in enumerate(attacks):
        offset = (i - (n_atk - 1) / 2.0) * pitch
        vals = []
        for h in harnesses:
            c = counts.get((h, atk))
            vals.append(c["unsafe"] / c["total"] if c and c["total"] > 0 else 0.0)
        bars = ax.bar(
            x + offset,
            vals,
            bar_width,
            label=ATTACK_LABELS.get(atk, atk),
            color=_attack_style(atk, attacks),
            edgecolor="none",
            linewidth=0.0,
            zorder=3,
        )
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.012,
                    f"{v:.0%}",
                    ha="center",
                    va="bottom",
                    fontsize=13,
                    fontweight="bold",
                    color=TECH_TEXT,
                )

    ax.set_xticks(x)
    ax.set_xticklabels(
        [HARNESS_LABELS.get(h, h) for h in harnesses],
        fontsize=20,
        fontweight="bold",
    )
    ax.set_ylabel("Unsafe Rate", fontsize=24, fontweight="bold")
    ax.set_title("Attack Effectiveness: Harness x Attack Type", fontsize=26, fontweight="bold", pad=18)
    ax.set_ylim(0, 1.18)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    _style_axis_text(ax, x_size=20, y_size=20)
    ax.grid(axis="y", linestyle="--", linewidth=0.8, alpha=0.25, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(loc="upper right", ncol=min(3, n_atk), frameon=False, prop={"size": 17, "weight": "bold"})
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines["left"].set_linewidth(1.1)
    ax.spines["bottom"].set_linewidth(1.1)

    path = out_dir / "fig3_attack_effectiveness.pdf"
    fig.tight_layout()
    fig.savefig(path, dpi=1200)
    plt.close(fig)
    return path


# ===================================================================
# Figure 4 – Judge label distribution (stacked bar)
# ===================================================================
def fig4_judge_distribution(
    records: list[dict[str, Any]], harnesses: list[str], securities: list[str], out_dir: Path
):
    combos = [(h, s) for h in harnesses for s in securities]
    label_vals = sorted(LABEL_COLORS.keys())

    dist: dict[tuple[str, str], dict[int, int]] = defaultdict(lambda: defaultdict(int))
    totals: dict[tuple[str, str], int] = defaultdict(int)
    for r in records:
        key = (str(r["harness"]), str(r["security_mode"]))
        dist[key][int(r["judge_label"])] += 1
        totals[key] += 1

    fig_w = max(15.0, len(combos) * 0.78)
    fig, ax = plt.subplots(figsize=(fig_w, 7.0))
    x = np.arange(len(combos))
    bottom = np.zeros(len(combos))
    label_palette = {
        -1: "#E7E7EF",
        0: "#C8C8D6",
        1: "#8D8D9E",
        2: TECH_PURPLE,
    }

    for lbl in label_vals:
        proportions = []
        for combo in combos:
            t = totals[combo]
            proportions.append(dist[combo][lbl] / t if t > 0 else 0.0)
        proportions = np.array(proportions)
        ax.bar(
            x,
            proportions,
            bottom=bottom,
            width=0.82,
            label=LABEL_NAMES[lbl],
            color=label_palette[lbl],
            edgecolor="none",
            linewidth=0.0,
            zorder=3,
        )
        bottom += proportions

    xlabels = [
        f"{HARNESS_LABELS.get(h, h)} / {SECURITY_LABELS.get(s, s)}" for h, s in combos
    ]
    ax.set_xticks(x)
    ax.set_xticklabels(
        xlabels,
        rotation=18,
        ha="right",
        fontsize=12,
        fontweight="bold",
    )
    ax.set_ylabel("Proportion", fontsize=22, fontweight="bold")
    fig.suptitle(
        "Judge Label Distribution: Harness x Security Mode",
        fontsize=24,
        fontweight="bold",
        y=0.985,
        ha="center",
    )
    ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    _style_axis_text(ax, x_size=12, y_size=17)
    ax.grid(axis="y", linestyle="--", linewidth=0.8, alpha=0.25, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 0.925),
        bbox_transform=fig.transFigure,
        ncol=len(label_vals),
        frameon=False,
        prop={"size": 14, "weight": "bold"},
    )
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines["left"].set_linewidth(1.1)
    ax.spines["bottom"].set_linewidth(1.1)

    path = out_dir / "fig4_judge_distribution.pdf"
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    fig.savefig(path, dpi=1200)
    plt.close(fig)
    return path


# ===================================================================
# Figure 5 – Radar chart (5-dim safety profile per security mode)
# ===================================================================
def fig5_radar(summary: list[dict[str, Any]], securities: list[str], out_dir: Path):
    dims = [
        "1-UBR\n(Safety)",
        "1-ASR\n(Attack Def)",
        "TCR\n(Completion)",
        "UA\n(Utility)",
        "NNH\n(Normalized)",
    ]
    n_dims = len(dims)
    angles = np.linspace(0, 2 * np.pi, n_dims, endpoint=False).tolist()
    angles += angles[:1]

    finite_nnh = [
        s["NNH"]
        for s in summary
        if isinstance(s["NNH"], (int, float)) and math.isfinite(s["NNH"])
    ]
    max_nnh = max(finite_nnh, default=1.0)
    if max_nnh <= 0:
        max_nnh = 1.0

    fig, ax = plt.subplots(figsize=(8.2, 7.4), subplot_kw=dict(polar=True))

    for sec in securities:
        rows = [s for s in summary if s["security"] == sec]
        if not rows:
            continue
        avg = {
            k: float(np.mean([float(r[k]) for r in rows]))
            for k in ["UBR", "ASR", "TCR", "UA"]
        }
        nnh_vals = []
        for r in rows:
            v = r["NNH"]
            if v == float("inf") or (isinstance(v, float) and math.isinf(v)):
                nnh_vals.append(max_nnh)
            else:
                nnh_vals.append(float(v))
        avg["NNH"] = float(np.mean(nnh_vals)) if nnh_vals else 0.0

        values = [
            1 - avg["UBR"],
            1 - avg["ASR"],
            avg["TCR"],
            avg["UA"],
            avg["NNH"] / max_nnh if max_nnh > 0 else 0.0,
        ]
        values += values[:1]
        col, _, _, _ = _security_style(sec, securities)
        ax.plot(
            angles,
            values,
            "o-",
            linewidth=3.2 if sec == "safe_harness" else 2.4,
            markersize=7 if sec == "safe_harness" else 6,
            label=SECURITY_LABELS.get(sec, sec),
            color=col,
        )
        ax.fill(angles, values, alpha=0.15 if sec == "safe_harness" else 0.10, color=col)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(dims, fontsize=18, fontweight="bold")
    ax.set_ylim(0, 1.1)
    ax.set_title("Safety Metrics Radar: Security Mode Comparison", fontsize=26, fontweight="bold", y=1.10)
    ax.tick_params(axis="y", labelsize=18)
    for label in ax.get_yticklabels():
        label.set_fontweight("bold")
        label.set_color("#666678")
    for label in ax.get_xticklabels():
        label.set_color(TECH_TEXT)
    ax.grid(color="#D6D6E0", linewidth=1.0, alpha=0.9)
    ax.spines["polar"].set_color("#B9B9C8")
    ax.spines["polar"].set_linewidth(1.2)
    ax.legend(loc="upper right", bbox_to_anchor=(1.28, 1.12), frameon=False, prop={"size": 18, "weight": "bold"})

    path = out_dir / "fig5_radar.pdf"
    fig.tight_layout()
    fig.savefig(path, dpi=1200, bbox_inches="tight")
    plt.close(fig)
    return path


# ===================================================================
# Main
# ===================================================================
def main() -> None:
    script_dir = Path(__file__).resolve().parent
    default_output = script_dir / "output"

    parser = argparse.ArgumentParser(
        description="从 output/ 或指定路径加载主实验结果并生成图表（消融结果跳过）。"
    )
    parser.add_argument(
        "data_path",
        nargs="?",
        type=Path,
        default=None,
        help="结果 JSON / JSONL；省略则在 output/ 下自动选择（不含 ablation）",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=None,
        dest="input_path",
        help="与位置参数等价，指定数据文件",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=None,
        help="图表输出目录（默认: output/figures_<文件名主干> 或 output/figures）",
    )
    args = parser.parse_args()

    data_path = args.data_path or args.input_path
    if data_path is None:
        data_path = pick_results_file(default_output)

    if data_path is None or not data_path.is_file():
        print(
            f"[ERROR] 未找到可用的主实验结果文件。请将 JSON/JSONL 放在 {default_output}/ "
            "或显式传入路径。（消融结果文件名含 ablation，已自动排除）",
            file=sys.stderr,
        )
        sys.exit(1)

    if "ablation" in data_path.name.lower():
        print(
            "[INFO] 消融结果（ablation）暂不绘图。请使用主实验的 experiment_results*.json(l) "
            "或其它非 ablation 结果文件。",
            file=sys.stderr,
        )
        sys.exit(0)

    if args.output_dir is not None:
        out_dir = args.output_dir
    else:
        stem = data_path.stem
        if stem == "demo_results":
            out_dir = data_path.parent / "figures"
        else:
            out_dir = data_path.parent / f"figures_{stem}"

    try:
        raw_records, summary_disk = load_demo_style(data_path)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    records = filter_main_experiment_records(raw_records)
    if not records:
        print(
            f"[ERROR] 过滤消融字段后无可用记录: {data_path}。"
            "若为纯消融文件请换用主实验结果。",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(records) < len(raw_records):
        print(
            f"[INFO] 已忽略 {len(raw_records) - len(records)} 条含 ablation 字段的记录。",
            file=sys.stderr,
        )

    if (
        summary_disk
        and len(summary_disk) > 0
        and isinstance(summary_disk[0], dict)
        and "harness" in summary_disk[0]
        and "security" in summary_disk[0]
    ):
        summary = summary_disk
    else:
        summary = build_summary(records)

    harnesses = _harnesses_present(records)
    securities = _security_present(records)
    attacks = _attacks_present(records)

    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"数据: {data_path.resolve()}")
    print(f"  records: {len(records)} 条  |  summary 行: {len(summary)}")
    print(f"  harnesses={harnesses}  securities={securities}")
    print(f"  输出目录: {out_dir.resolve()}\n")

    generators = [
        ("图1 UBR 分组柱状图", lambda: fig1_ubr_bar(summary, harnesses, securities, out_dir)),
        ("图2 ASR 热力图", lambda: fig2_asr_heatmap(summary, harnesses, securities, out_dir)),
        (
            "图3 攻击效果对比",
            lambda: fig3_attack_effectiveness(records, harnesses, attacks, out_dir),
        ),
        (
            "图4 Judge 标签分布",
            lambda: fig4_judge_distribution(records, harnesses, securities, out_dir),
        ),
        ("图5 安全雷达图", lambda: fig5_radar(summary, securities, out_dir)),
    ]

    for name, gen in generators:
        path = gen()
        print(f"  [OK] {name}  →  {path}")

    print(f"\n全部完成，共生成 {len(generators)} 张图表。")


if __name__ == "__main__":
    main()
