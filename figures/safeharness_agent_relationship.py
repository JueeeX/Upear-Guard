"""Nature-style schematic of the relationship between an Agent and SafeHarness.

Figure contract
---------------
Core conclusion: SafeHarness does not replace Agent reasoning; it enforces
security decisions at lifecycle boundaries around the Agent's task loop.
Archetype: schematic-led composite with a responsibility sidebar.
Target: Nature-family, double-column width (183 mm), editable vector output.
Backend: Python / matplotlib only.
Panel a: lifecycle coupling between the Agent task plane and SafeHarness.
Panel b: explicit ownership split and the current-versus-production boundary.
Reviewer risk: do not imply that the current in-process alpha is a hard security
boundary or that observation-only multi-agent handoffs are enforced.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle


# Mandatory publication and editable-SVG settings.
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
plt.rcParams["svg.fonttype"] = "none"

plt.rcParams.update(
    {
        "font.sans-serif": [
            "Microsoft YaHei",
            "Arial",
            "SimHei",
            "DejaVu Sans",
            "Liberation Sans",
        ],
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "font.size": 7,
        "axes.linewidth": 0.8,
        "legend.frameon": False,
        "savefig.facecolor": "white",
    }
)


INK = "#272727"
MUTED = "#66707A"
LINE = "#BFC6CC"
LINE_LIGHT = "#DCE1E5"
AGENT = "#0F4D92"
AGENT_SOFT = "#E7F0F8"
SAFE = "#7C6CCF"
SAFE_SOFT = "#EEEAF8"
TOOLS = "#42949E"
TOOLS_SOFT = "#E0F0F0"
ALLOW = "#2E9E44"
MODIFY = "#D99B2B"
DENY = "#B64342"
NEUTRAL_SOFT = "#F3F5F6"


def add_box(
    ax,
    x: float,
    y: float,
    width: float,
    height: float,
    title: str,
    subtitle: str,
    *,
    facecolor: str,
    edgecolor: str,
    title_color: str = INK,
    title_size: float = 7.0,
    subtitle_size: float = 5.4,
    linewidth: float = 0.9,
    linestyle: str = "-",
    zorder: int = 3,
) -> None:
    patch = FancyBboxPatch(
        (x, y),
        width,
        height,
        boxstyle="round,pad=0.005,rounding_size=0.008",
        transform=ax.transAxes,
        facecolor=facecolor,
        edgecolor=edgecolor,
        linewidth=linewidth,
        linestyle=linestyle,
        zorder=zorder,
    )
    ax.add_patch(patch)
    ax.text(
        x + width / 2,
        y + height * 0.64,
        title,
        transform=ax.transAxes,
        ha="center",
        va="center",
        color=title_color,
        fontsize=title_size,
        fontweight="bold",
        zorder=zorder + 1,
    )
    ax.text(
        x + width / 2,
        y + height * 0.30,
        subtitle,
        transform=ax.transAxes,
        ha="center",
        va="center",
        color=MUTED,
        fontsize=subtitle_size,
        linespacing=1.15,
        zorder=zorder + 1,
    )


def add_arrow(
    ax,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    color: str = INK,
    linewidth: float = 1.0,
    arrowstyle: str = "-|>",
    mutation_scale: float = 8,
    linestyle: str = "-",
    connectionstyle: str = "arc3,rad=0",
    zorder: int = 2,
) -> None:
    arrow = FancyArrowPatch(
        start,
        end,
        transform=ax.transAxes,
        arrowstyle=arrowstyle,
        mutation_scale=mutation_scale,
        linewidth=linewidth,
        color=color,
        linestyle=linestyle,
        connectionstyle=connectionstyle,
        shrinkA=0,
        shrinkB=0,
        zorder=zorder,
    )
    ax.add_patch(arrow)


def add_section_text(
    ax,
    x: float,
    y: float,
    heading: str,
    body: str,
    color: str,
) -> None:
    ax.add_patch(
        Rectangle(
            (x, y - 0.005),
            0.008,
            0.125,
            transform=ax.transAxes,
            facecolor=color,
            edgecolor="none",
            zorder=2,
        )
    )
    ax.text(
        x + 0.018,
        y + 0.105,
        heading,
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=7.0,
        fontweight="bold",
        color=color,
    )
    ax.text(
        x + 0.018,
        y + 0.075,
        body,
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=5.8,
        color=INK,
        linespacing=1.40,
    )


def build_figure():
    fig = plt.figure(figsize=(7.2, 5.3), facecolor="white")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(
        0.035,
        0.957,
        "SafeHarness 在智能体执行过程中提供安全能力",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=11.0,
        fontweight="bold",
        color=INK,
    )
    ax.text(
        0.035,
        0.914,
        "智能体负责理解、推理与规划；SafeHarness 在关键边界检查、授权、阻断、审计与恢复。",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=6.5,
        color=MUTED,
    )

    # Panel a: concrete runtime sequence.
    ax.text(0.025, 0.848, "a", transform=ax.transAxes, fontsize=8, fontweight="bold")
    ax.text(
        0.050,
        0.848,
        "智能体运行时安全注入路径",
        transform=ax.transAxes,
        fontsize=7.4,
        fontweight="bold",
        color=INK,
        va="center",
    )

    ax.add_patch(
        Rectangle(
            (0.035, 0.585),
            0.930,
            0.195,
            transform=ax.transAxes,
            facecolor="#F8FAFC",
            edgecolor="none",
            zorder=0,
        )
    )
    ax.text(
        0.045,
        0.758,
        "从输入到响应的完整执行时序",
        transform=ax.transAxes,
        fontsize=5.6,
        fontweight="bold",
        color=INK,
        va="center",
    )
    ax.plot([0.215, 0.950], [0.758, 0.758], transform=ax.transAxes, color=LINE_LIGHT, lw=0.7)

    runtime_boxes = [
        (0.045, 0.085, "输入上下文", "用户 / RAG\n记忆"),
        (0.145, 0.090, "输入防护", "注入检测\n清洗与溯源"),
        (0.250, 0.105, "智能体推理", "LLM / 规划器"),
        (0.370, 0.105, "工具前防护", "意图对齐\nSchema / 令牌"),
        (0.490, 0.105, "NMS / 工具", "查询或\n外部副作用"),
        (0.610, 0.105, "工具后防护", "结果扫描\n补偿 / 恢复"),
        (0.730, 0.095, "继续推理", "观察 → 决策"),
        (0.840, 0.095, "输出防护", "最终响应检查"),
    ]
    for index, (x, width, title, subtitle) in enumerate(runtime_boxes, start=1):
        is_guard = "防护" in title
        is_tool = title == "NMS / 工具"
        facecolor = SAFE_SOFT if is_guard else TOOLS_SOFT if is_tool else AGENT_SOFT
        edgecolor = SAFE if is_guard else TOOLS if is_tool else AGENT
        title_color = SAFE if is_guard else TOOLS if is_tool else AGENT
        add_box(
            ax,
            x,
            0.630,
            width,
            0.100,
            title,
            subtitle,
            facecolor=facecolor,
            edgecolor=edgecolor,
            title_color=title_color,
            title_size=6.4,
            subtitle_size=4.8,
        )
        ax.text(
            x + width / 2,
            0.742,
            str(index),
            transform=ax.transAxes,
            ha="center",
            va="center",
            fontsize=4.8,
            fontweight="bold",
            color=title_color,
        )

    arrow_pairs = [
        (0.132, 0.142),
        (0.237, 0.247),
        (0.357, 0.367),
        (0.477, 0.487),
        (0.597, 0.607),
        (0.717, 0.727),
        (0.827, 0.837),
    ]
    for start_x, end_x in arrow_pairs:
        add_arrow(ax, (start_x, 0.680), (end_x, 0.680), color=MUTED, linewidth=0.9)
    add_arrow(ax, (0.937, 0.680), (0.968, 0.680), color=MUTED, linewidth=0.9)
    ax.text(
        0.941,
        0.704,
        "最终响应",
        transform=ax.transAxes,
        fontsize=4.9,
        color=MUTED,
        ha="left",
    )

    ax.add_patch(
        Rectangle(
            (0.135, 0.370),
            0.795,
            0.145,
            transform=ax.transAxes,
            facecolor="#FBFAFD",
            edgecolor=LINE_LIGHT,
            linewidth=0.7,
            zorder=0,
        )
    )
    ax.text(
        0.158,
        0.490,
        "SafeHarness SecuritySession",
        transform=ax.transAxes,
        fontsize=6.7,
        fontweight="bold",
        color=SAFE,
        va="center",
    )
    ax.text(
        0.158,
        0.453,
        "策略引擎：Inform  →  Verify  →  Constrain  →  Correct",
        transform=ax.transAxes,
        fontsize=5.7,
        color=INK,
        va="center",
    )
    ax.text(
        0.158,
        0.414,
        "会话身份  ·  可信用户意图  ·  provenance  ·  调用 ID  ·  fail-closed 状态",
        transform=ax.transAxes,
        fontsize=5.2,
        color=MUTED,
        va="center",
    )

    outcome_specs = [
        (0.590, "允许", ALLOW),
        (0.664, "修改", MODIFY),
        (0.738, "拒绝", DENY),
        (0.812, "审批", SAFE),
    ]
    ax.text(
        0.590,
        0.486,
        "返回决策与执行义务",
        transform=ax.transAxes,
        fontsize=5.2,
        fontweight="bold",
        color=INK,
        va="center",
    )
    for x, label, color in outcome_specs:
        ax.plot([x, x + 0.015], [0.448, 0.448], transform=ax.transAxes, color=color, lw=2.0)
        ax.text(
            x + 0.020,
            0.448,
            label,
            transform=ax.transAxes,
            fontsize=4.8,
            color=color,
            va="center",
        )

    # Guard nodes emit typed events and receive decisions/obligations.
    for x in (0.190, 0.422, 0.662, 0.887):
        add_arrow(
            ax,
            (x, 0.627),
            (x, 0.518),
            color=LINE,
            linewidth=0.8,
            arrowstyle="<->",
            mutation_scale=6,
            linestyle="--",
            zorder=1,
        )

    ax.text(
        0.510,
        0.548,
        "生命周期事件  ↓        ↑  决策 / obligation",
        transform=ax.transAxes,
        fontsize=4.8,
        color=MUTED,
        va="center",
        ha="center",
    )

    # Panel b: pluggable security services.
    ax.text(0.025, 0.315, "b", transform=ax.transAxes, fontsize=8, fontweight="bold")
    ax.text(
        0.050,
        0.315,
        "安全能力由可插拔服务支撑",
        transform=ax.transAxes,
        fontsize=7.4,
        fontweight="bold",
        color=INK,
        va="center",
    )
    services = [
        (0.045, 0.215, "语义 Judge", "注入与意图对齐"),
        (0.225, 0.215, "工具目录", "可信描述与 Schema"),
        (0.405, 0.215, "签名能力授权", "单次令牌 / 防重放"),
        (0.045, 0.120, "人工审批", "高风险动作确认"),
        (0.225, 0.120, "审计后端", "最小化事件与回执"),
        (0.405, 0.120, "状态 / 补偿", "检查点与恢复语义"),
    ]
    for x, y, title, subtitle in services:
        add_box(
            ax,
            x,
            y,
            0.160,
            0.067,
            title,
            subtitle,
            facecolor=NEUTRAL_SOFT,
            edgecolor=LINE,
            title_color=INK,
            title_size=5.7,
            subtitle_size=4.5,
            linewidth=0.7,
        )
    ax.text(
        0.045,
        0.078,
        "当前 Demo 多为内存实现；生产环境需外置网关、密钥隔离与持久化后端。",
        transform=ax.transAxes,
        fontsize=4.9,
        color=MUTED,
        va="center",
    )

    # Panel c: responsibility and deployment boundary.
    ax.plot([0.605, 0.605], [0.065, 0.325], transform=ax.transAxes, color=LINE_LIGHT, lw=0.8)
    ax.text(0.625, 0.315, "c", transform=ax.transAxes, fontsize=8, fontweight="bold")
    ax.text(
        0.650,
        0.315,
        "职责与安全边界",
        transform=ax.transAxes,
        fontsize=7.4,
        fontweight="bold",
        color=INK,
        va="center",
    )
    add_section_text(
        ax,
        0.630,
        0.195,
        "智能体：决定“做什么”",
        "理解任务 · 推理规划\n选择工具 · 生成回答",
        AGENT,
    )
    add_section_text(
        ax,
        0.810,
        0.195,
        "SafeHarness：执行安全裁决",
        "决定能否及如何执行\n检查 · 授权 · 阻断 · 审计 · 恢复",
        SAFE,
    )
    boundary = FancyBboxPatch(
        (0.630, 0.067),
        0.335,
        0.075,
        boxstyle="round,pad=0.006,rounding_size=0.008",
        transform=ax.transAxes,
        facecolor="white",
        edgecolor=MUTED,
        linewidth=0.8,
        linestyle="--",
        zorder=2,
    )
    ax.add_patch(boundary)
    ax.text(
        0.647,
        0.124,
        "部署边界",
        transform=ax.transAxes,
        fontsize=5.8,
        fontweight="bold",
        color=INK,
        va="top",
    )
    ax.text(
        0.647,
        0.096,
        "当前 Alpha：进程内控制   |   生产：独立工具网关 + 持久化审计 / 状态",
        transform=ax.transAxes,
        fontsize=4.6,
        color=MUTED,
        va="top",
        linespacing=1.25,
    )

    return fig


def main() -> None:
    output_dir = Path(__file__).resolve().parent
    output_base = output_dir / "safeharness_agent_relationship_nature"
    fig = build_figure()
    fig.savefig(output_base.with_suffix(".svg"), bbox_inches="tight", pad_inches=0.04)
    fig.savefig(output_base.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.04)
    fig.savefig(
        output_base.with_suffix(".png"),
        dpi=600,
        bbox_inches="tight",
        pad_inches=0.04,
    )
    fig.savefig(
        output_base.with_suffix(".tiff"),
        dpi=600,
        bbox_inches="tight",
        pad_inches=0.04,
    )
    plt.close(fig)
    for suffix in (".svg", ".pdf", ".png", ".tiff"):
        print(output_base.with_suffix(suffix))


if __name__ == "__main__":
    main()
