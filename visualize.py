#!/usr/bin/env python3
"""Visualize SafeHarness experiment results from demo_results.json."""

import json
import os
import sys
from pathlib import Path
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

# ---------- palette & style ----------

SECURITY_COLORS = {
    "unprotected": "#E74C3C",
    "llamafirewall": "#3498DB",
    "safe_harness":"#2ECC71",
}
SECURITY_LABELS = {
    "unprotected": "Unprotected",
    "llamafirewall": "LlamaFirewall",
    "safe_harness":"SafeHarness",
}
HARNESS_ORDER = ["direct", "react", "multi_agent", "map_reduce", "memory"]
HARNESS_LABELS = {
    "direct":      "Direct",
    "react":       "ReAct",
    "multi_agent": "Multi-Agent",
    "map_reduce":  "Map-Reduce",
    "memory":      "Memory",
}
SECURITY_ORDER = ["unprotected", "llamafirewall", "safe_harness"]

ATTACK_COLORS = {
    "clean":             "#95A5A6",
    "context_poisoning": "#E67E22",
    "tool_tampering":    "#8E44AD",
    "memory_injection":  "#C0392B",
}
ATTACK_LABELS = {
    "clean":             "Clean",
    "context_poisoning": "Context Poisoning",
    "tool_tampering":    "Tool Tampering",
    "memory_injection":  "Memory Injection",
}
ATTACK_ORDER = ["clean", "context_poisoning", "tool_tampering", "memory_injection"]

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

plt.rcParams.update({
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.dpi": 150,
})


def load_data(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ===================================================================
# Figure 1 – UBR grouped bar chart (Harness x Security)
# ===================================================================
def fig1_ubr_bar(summary, out_dir: Path):
    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(HARNESS_ORDER))
    width = 0.22

    lookup = {(s["harness"], s["security"]): s for s in summary}

    for i, sec in enumerate(SECURITY_ORDER):
        vals = [lookup.get((h, sec), {}).get("UBR", 0) for h in HARNESS_ORDER]
        bars = ax.bar(x + (i - 1) * width, vals, width,
                      label=SECURITY_LABELS[sec],
                      color=SECURITY_COLORS[sec], edgecolor="white", linewidth=0.5)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{v:.2f}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels([HARNESS_LABELS[h] for h in HARNESS_ORDER])
    ax.set_ylabel("UBR (Unsafe Behavior Rate)")
    ax.set_title("Unsafe Behavior Rate: Harness x Security Mode")
    ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    ax.legend(loc="upper right")
    ax.spines[["top", "right"]].set_visible(False)

    path = out_dir / "fig1_ubr_bar.png"
    fig.tight_layout()
    fig.savefig(path, dpi=300)
    plt.close(fig)
    return path


# ===================================================================
# Figure 2 – ASR heatmap
# ===================================================================
def fig2_asr_heatmap(summary, out_dir: Path):
    lookup = {(s["harness"], s["security"]): s for s in summary}
    matrix = np.array([
        [lookup.get((h, sec), {}).get("ASR", 0) for sec in SECURITY_ORDER]
        for h in HARNESS_ORDER
    ])

    fig, ax = plt.subplots(figsize=(6, 4.5))
    im = ax.imshow(matrix, cmap="YlOrRd", vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(len(SECURITY_ORDER)))
    ax.set_xticklabels([SECURITY_LABELS[s] for s in SECURITY_ORDER])
    ax.set_yticks(range(len(HARNESS_ORDER)))
    ax.set_yticklabels([HARNESS_LABELS[h] for h in HARNESS_ORDER])

    for i in range(len(HARNESS_ORDER)):
        for j in range(len(SECURITY_ORDER)):
            val = matrix[i, j]
            color = "white" if val > 0.6 else "black"
            ax.text(j, i, f"{val:.2%}", ha="center", va="center",
                    fontsize=11, fontweight="bold", color=color)

    ax.set_title("Attack Success Rate Heatmap (ASR)")
    fig.colorbar(im, ax=ax, label="ASR", shrink=0.8)

    path = out_dir / "fig2_asr_heatmap.png"
    fig.tight_layout()
    fig.savefig(path, dpi=300)
    plt.close(fig)
    return path


# ===================================================================
# Figure 3 – Attack effectiveness (Harness x Attack type)
# ===================================================================
def fig3_attack_effectiveness(records, out_dir: Path):
    counts = defaultdict(lambda: {"unsafe": 0, "total": 0})
    for r in records:
        atk = r["attack"] if r["attack"] else "clean"
        key = (r["harness"], atk)
        counts[key]["total"] += 1
        if r["judge_label"] in (1, 2):
            counts[key]["unsafe"] += 1

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(HARNESS_ORDER))
    width = 0.18

    for i, atk in enumerate(ATTACK_ORDER):
        vals = []
        for h in HARNESS_ORDER:
            c = counts.get((h, atk))
            vals.append(c["unsafe"] / c["total"] if c and c["total"] > 0 else 0)
        bars = ax.bar(x + (i - 1.5) * width, vals, width,
                      label=ATTACK_LABELS[atk], color=ATTACK_COLORS[atk],
                      edgecolor="white", linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                        f"{v:.0%}", ha="center", va="bottom", fontsize=7)

    ax.set_xticks(x)
    ax.set_xticklabels([HARNESS_LABELS[h] for h in HARNESS_ORDER])
    ax.set_ylabel("Unsafe Rate")
    ax.set_title("Attack Effectiveness: Harness x Attack Type")
    ax.set_ylim(0, 1.15)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    ax.legend(loc="upper right", ncol=2)
    ax.spines[["top", "right"]].set_visible(False)

    path = out_dir / "fig3_attack_effectiveness.png"
    fig.tight_layout()
    fig.savefig(path, dpi=300)
    plt.close(fig)
    return path


# ===================================================================
# Figure 4 – Judge label distribution (stacked bar)
# ===================================================================
def fig4_judge_distribution(records, out_dir: Path):
    combos = [(h, s) for h in HARNESS_ORDER for s in SECURITY_ORDER]
    label_vals = sorted(LABEL_COLORS.keys())

    dist = defaultdict(lambda: defaultdict(int))
    totals = defaultdict(int)
    for r in records:
        key = (r["harness"], r["security_mode"])
        dist[key][r["judge_label"]] += 1
        totals[key] += 1

    fig, ax = plt.subplots(figsize=(11, 5))
    x = np.arange(len(combos))
    bottom = np.zeros(len(combos))

    for lbl in label_vals:
        proportions = []
        for combo in combos:
            t = totals[combo]
            proportions.append(dist[combo][lbl] / t if t > 0 else 0)
        proportions = np.array(proportions)
        ax.bar(x, proportions, bottom=bottom, width=0.7,
               label=LABEL_NAMES[lbl], color=LABEL_COLORS[lbl],
               edgecolor="white", linewidth=0.3)
        bottom += proportions

    xlabels = [f"{HARNESS_LABELS[h]}\n{SECURITY_LABELS[s]}" for h, s in combos]
    ax.set_xticks(x)
    ax.set_xticklabels(xlabels, fontsize=7)
    ax.set_ylabel("Proportion")
    ax.set_title("Judge Label Distribution: Harness x Security Mode")
    ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    ax.legend(loc="upper right", ncol=2)
    ax.spines[["top", "right"]].set_visible(False)

    path = out_dir / "fig4_judge_distribution.png"
    fig.tight_layout()
    fig.savefig(path, dpi=300)
    plt.close(fig)
    return path


# ===================================================================
# Figure 5 – Radar chart (5-dim safety profile per security mode)
# ===================================================================
def fig5_radar(summary, out_dir: Path):
    dims = ["1-UBR\n(Safety)", "1-ASR\n(Attack Def)", "TCR\n(Completion)",
            "UA\n(Utility)", "NNH\n(Normalized)"]
    n_dims = len(dims)
    angles = np.linspace(0, 2 * np.pi, n_dims, endpoint=False).tolist()
    angles += angles[:1]

    max_nnh = max((s["NNH"] for s in summary), default=1)

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))

    for sec in SECURITY_ORDER:
        rows = [s for s in summary if s["security"] == sec]
        if not rows:
            continue
        avg = {k: np.mean([r[k] for r in rows])
               for k in ["UBR", "ASR", "TCR", "UA", "NNH"]}
        values = [
            1 - avg["UBR"],
            1 - avg["ASR"],
            avg["TCR"],
            avg["UA"],
            avg["NNH"] / max_nnh if max_nnh > 0 else 0,
        ]
        values += values[:1]
        ax.plot(angles, values, "o-", linewidth=2, markersize=5,
                label=SECURITY_LABELS[sec], color=SECURITY_COLORS[sec])
        ax.fill(angles, values, alpha=0.12, color=SECURITY_COLORS[sec])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(dims, fontsize=9)
    ax.set_ylim(0, 1.1)
    ax.set_title("Safety Metrics Radar: Security Mode Comparison", y=1.08)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1))

    path = out_dir / "fig5_radar.png"
    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return path


# ===================================================================
# Main
# ===================================================================
def main():
    script_dir = Path(__file__).resolve().parent
    data_path = script_dir / "output" / "demo_results.json"

    if len(sys.argv) > 1:
        data_path = Path(sys.argv[1])

    if not data_path.exists():
        print(f"[ERROR] 数据文件不存在: {data_path}")
        sys.exit(1)

    data = load_data(str(data_path))
    records = data["records"]
    summary = data["summary"]

    out_dir = data_path.parent / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"数据: {data_path}")
    print(f"  records: {len(records)} 条  |  summary: {len(summary)} 组")
    print(f"输出目录: {out_dir}\n")

    generators = [
        ("图1 UBR 分组柱状图",    lambda: fig1_ubr_bar(summary, out_dir)),
        ("图2 ASR 热力图",        lambda: fig2_asr_heatmap(summary, out_dir)),
        ("图3 攻击效果对比",       lambda: fig3_attack_effectiveness(records, out_dir)),
        ("图4 Judge 标签分布",    lambda: fig4_judge_distribution(records, out_dir)),
        ("图5 安全雷达图",        lambda: fig5_radar(summary, out_dir)),
    ]

    for name, gen in generators:
        path = gen()
        print(f"  [OK] {name}  →  {path}")

    print(f"\n全部完成，共生成 {len(generators)} 张图表。")


if __name__ == "__main__":
    main()
