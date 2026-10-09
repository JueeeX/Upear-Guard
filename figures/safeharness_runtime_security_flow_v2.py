"""Nature-style V2 schematic of SafeHarness runtime security enforcement.

Core conclusion: the Agent owns task reasoning, while SafeHarness intercepts
four lifecycle boundaries and returns an explicit allow, modify, approval,
deny, or correction outcome before execution continues.

The schematic intentionally uses one horizontal execution path, one vertical
event path, and one outcome path so arrows never cross.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon, Rectangle


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
        "savefig.facecolor": "white",
    }
)


INK = "#272727"
MUTED = "#68727D"
LINE = "#B8C0C7"
LINE_LIGHT = "#DDE2E6"
AGENT = "#0F4D92"
AGENT_SOFT = "#E7F0F8"
SAFE = "#7867CF"
SAFE_SOFT = "#F0EDFA"
TOOL = "#3F99A4"
TOOL_SOFT = "#E2F1F2"
ALLOW = "#2E9E44"
ALLOW_SOFT = "#EFF8F1"
MODIFY = "#D99B2B"
MODIFY_SOFT = "#FFF7E6"
DENY = "#B64342"
DENY_SOFT = "#FBEDED"
CORRECT = "#277E86"
CORRECT_SOFT = "#EDF7F7"
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
    subtitle_color: str = MUTED,
    title_size: float = 6.2,
    subtitle_size: float = 4.7,
    linewidth: float = 0.9,
    radius: float = 0.007,
    zorder: int = 3,
) -> None:
    patch = FancyBboxPatch(
        (x, y),
        width,
        height,
        boxstyle=f"round,pad=0.005,rounding_size={radius}",
        transform=ax.transAxes,
        facecolor=facecolor,
        edgecolor=edgecolor,
        linewidth=linewidth,
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
        fontsize=title_size,
        fontweight="bold",
        color=title_color,
        zorder=zorder + 1,
    )
    ax.text(
        x + width / 2,
        y + height * 0.27,
        subtitle,
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=subtitle_size,
        color=subtitle_color,
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
    ax.add_patch(
        FancyArrowPatch(
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
    )


def add_outcome_row(
    ax,
    y: float,
    label: str,
    detail: str,
    *,
    color: str,
    facecolor: str,
) -> None:
    x = 0.535
    width = 0.425
    height = 0.044
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            width,
            height,
            boxstyle="round,pad=0.003,rounding_size=0.005",
            transform=ax.transAxes,
            facecolor=facecolor,
            edgecolor="none",
            zorder=2,
        )
    )
    ax.add_patch(
        Rectangle(
            (x, y),
            0.007,
            height,
            transform=ax.transAxes,
            facecolor=color,
            edgecolor="none",
            zorder=3,
        )
    )
    ax.text(
        x + 0.016,
        y + height / 2,
        label,
        transform=ax.transAxes,
        ha="left",
        va="center",
        fontsize=5.4,
        fontweight="bold",
        color=color,
        zorder=4,
    )
    ax.text(
        x + 0.083,
        y + height / 2,
        detail,
        transform=ax.transAxes,
        ha="left",
        va="center",
        fontsize=5.1,
        color=INK,
        zorder=4,
    )


def build_figure():
    fig = plt.figure(figsize=(7.2, 4.9), facecolor="white")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(
        0.035,
        0.958,
        "SafeHarness 通过生命周期 Gate 控制智能体执行",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=11.0,
        fontweight="bold",
        color=INK,
    )
    ax.text(
        0.035,
        0.913,
        "智能体产生计划与动作；SafeHarness 将边界事件送入统一 SecuritySession，并把裁决反馈到原执行点。",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=6.4,
        color=MUTED,
    )

    ax.text(
        0.040,
        0.845,
        "1   智能体主执行路径",
        transform=ax.transAxes,
        fontsize=7.2,
        fontweight="bold",
        color=INK,
        va="center",
    )
    ax.add_patch(
        Rectangle(
            (0.035, 0.640),
            0.930,
            0.165,
            transform=ax.transAxes,
            facecolor="#F8FAFC",
            edgecolor="none",
            zorder=0,
        )
    )

    nodes = [
        (0.045, 0.090, "外部上下文", "用户 · RAG\n记忆", NEUTRAL_SOFT, LINE, INK, MUTED),
        (0.145, 0.065, "输入 Gate", "注入 · 溯源", SAFE, SAFE, "white", "white"),
        (0.225, 0.120, "智能体", "推理 · 规划", AGENT_SOFT, AGENT, AGENT, MUTED),
        (0.360, 0.075, "工具 Gate", "意图 · 权限", SAFE, SAFE, "white", "white"),
        (0.450, 0.105, "NMS / 工具", "查询 · 副作用", TOOL_SOFT, TOOL, TOOL, MUTED),
        (0.570, 0.075, "结果 Gate", "扫描 · 恢复", SAFE, SAFE, "white", "white"),
        (0.660, 0.120, "智能体", "观察 · 再推理", AGENT_SOFT, AGENT, AGENT, MUTED),
        (0.795, 0.075, "输出 Gate", "最终检查", SAFE, SAFE, "white", "white"),
        (0.885, 0.075, "响应", "返回用户", NEUTRAL_SOFT, LINE, INK, MUTED),
    ]
    for x, width, title, subtitle, face, edge, title_color, subtitle_color in nodes:
        add_box(
            ax,
            x,
            0.675,
            width,
            0.090,
            title,
            subtitle,
            facecolor=face,
            edgecolor=edge,
            title_color=title_color,
            subtitle_color=subtitle_color,
            title_size=5.8,
            subtitle_size=4.4,
        )

    for start_x, end_x in [
        (0.137, 0.142),
        (0.212, 0.222),
        (0.347, 0.357),
        (0.437, 0.447),
        (0.557, 0.567),
        (0.647, 0.657),
        (0.782, 0.792),
        (0.872, 0.882),
    ]:
        add_arrow(ax, (start_x, 0.720), (end_x, 0.720), color=MUTED, linewidth=0.85)

    # Four SafeHarness gates emit events into one shared security bus.
    gate_centers = (0.1775, 0.3975, 0.6075, 0.8325)
    for x in gate_centers:
        add_arrow(
            ax,
            (x, 0.672),
            (x, 0.595),
            color=SAFE,
            linewidth=0.9,
            mutation_scale=7,
        )

    bus = FancyBboxPatch(
        (0.120, 0.485),
        0.770,
        0.105,
        boxstyle="round,pad=0.006,rounding_size=0.009",
        transform=ax.transAxes,
        facecolor=SAFE_SOFT,
        edgecolor=SAFE,
        linewidth=1.0,
        zorder=2,
    )
    ax.add_patch(bus)
    ax.text(
        0.505,
        0.558,
        "SafeHarness 生命周期安全总线（SecuritySession）",
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=6.6,
        fontweight="bold",
        color=SAFE,
    )
    ax.text(
        0.505,
        0.518,
        "规范化事件 · 会话身份 · provenance · 可信用户意图 · 调用 ID · fail-closed",
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=5.0,
        color=MUTED,
    )

    ax.text(
        0.040,
        0.420,
        "2   SafeHarness 风险裁决与处置",
        transform=ax.transAxes,
        fontsize=7.2,
        fontweight="bold",
        color=INK,
        va="center",
    )

    add_box(
        ax,
        0.055,
        0.155,
        0.305,
        0.185,
        "策略引擎",
        "Inform → Verify → Constrain → Correct\n\n规则检测 + 语义 Judge\n工具目录 + 签名能力 + 人工审批\n审计 + 状态 / 补偿",
        facecolor=SAFE_SOFT,
        edgecolor=SAFE,
        title_color=SAFE,
        subtitle_color=INK,
        title_size=7.0,
        subtitle_size=5.1,
        linewidth=1.0,
    )
    add_arrow(ax, (0.225, 0.482), (0.225, 0.345), color=SAFE, linewidth=1.0)
    ax.text(
        0.238,
        0.400,
        "事件进入策略引擎",
        transform=ax.transAxes,
        fontsize=4.8,
        color=MUTED,
        va="center",
    )

    diamond = Polygon(
        [(0.440, 0.320), (0.495, 0.250), (0.440, 0.180), (0.385, 0.250)],
        closed=True,
        transform=ax.transAxes,
        facecolor="white",
        edgecolor=SAFE,
        linewidth=1.1,
        zorder=3,
    )
    ax.add_patch(diamond)
    ax.text(
        0.440,
        0.250,
        "风险\n裁决",
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=6.1,
        fontweight="bold",
        color=SAFE,
        linespacing=1.05,
        zorder=4,
    )
    add_arrow(ax, (0.363, 0.250), (0.382, 0.250), color=SAFE, linewidth=1.0)
    add_arrow(ax, (0.498, 0.250), (0.528, 0.250), color=SAFE, linewidth=1.0)

    add_outcome_row(
        ax,
        0.330,
        "安全",
        "ALLOW：继续原流程",
        color=ALLOW,
        facecolor=ALLOW_SOFT,
    )
    add_outcome_row(
        ax,
        0.277,
        "可修复",
        "MODIFY：清洗 / 改写后重新评估",
        color=MODIFY,
        facecolor=MODIFY_SOFT,
    )
    add_outcome_row(
        ax,
        0.224,
        "高风险",
        "APPROVAL：暂停执行，等待人工审批",
        color=SAFE,
        facecolor=SAFE_SOFT,
    )
    add_outcome_row(
        ax,
        0.171,
        "危险",
        "DENY：立即阻断，旧意图失效并审计",
        color=DENY,
        facecolor=DENY_SOFT,
    )
    add_outcome_row(
        ax,
        0.118,
        "事后风险",
        "CORRECT：补偿 / 恢复；不可逆则标记残余影响",
        color=CORRECT,
        facecolor=CORRECT_SOFT,
    )

    # A single, non-crossing feedback path returns the outcome to the gate.
    add_arrow(ax, (0.905, 0.382), (0.905, 0.482), color=SAFE, linewidth=1.0)
    ax.text(
        0.917,
        0.432,
        "裁决回写 Gate",
        transform=ax.transAxes,
        fontsize=4.8,
        color=SAFE,
        va="center",
        ha="left",
    )

    ax.plot([0.040, 0.960], [0.085, 0.085], transform=ax.transAxes, color=LINE_LIGHT, lw=0.7)
    ax.text(
        0.040,
        0.058,
        "SafeHarness 特点：统一 SecuritySession · 可信意图绑定 · 单次签名能力 · 失败关闭 · 最小化审计 · 明确恢复语义",
        transform=ax.transAxes,
        fontsize=5.0,
        color=INK,
        va="center",
    )
    ax.text(
        0.040,
        0.028,
        "当前 Alpha 强制覆盖输入、工具前、工具后与输出边界；生产环境需独立工具网关及持久化审计 / 状态后端。",
        transform=ax.transAxes,
        fontsize=4.7,
        color=MUTED,
        va="center",
    )

    return fig


def main() -> None:
    output_dir = Path(__file__).resolve().parent
    output_base = output_dir / "safeharness_runtime_security_flow_v2"
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
