# SafeHarness — 面向 Agent 安全的 Harness 架构设计框架

> **SafeHarness: Security-Aware Harness Architecture for Safe AI Agent Deployment**

本项目实现了论文中提出的 SafeHarness 框架——一个将安全机制原生嵌入 Agent Harness 执行生命周期的统一安全架构。

---

## 设计动机

### 问题背景：Agent 任务与安全决策绑在执行形态上

面向工具的 Agent 往往在**多轮推理、工具调用、环境状态与记忆读写**中完成任务；同一类「不安全行为」可能出现在用户指令、检索内容、工具返回值、跨步推理或持久状态中。若把安全看成「进模型前拦一次、出模型后查一次」，会默认攻击面主要落在自然语言接口两端——这与真实 Agent 的**长链路、可观测中间态**并不一致。

### 外挂式（bolt-on）方案为何不够

业界常见做法是在模型调用前后叠加独立模块（输入过滤、输出审核、外挂护栏等）。这类设计在本项目所针对的场景下存在三类结构性不足：

1. **与执行范式脱钩**：不同 Harness（如 Direct、ReAct、Multi-Agent、Map-Reduce、MemSkill 等）在**推理轨迹、角色分工、子任务并行与记忆构建**上的行为差异很大；安全模块若停留在「黑盒外侧」，难以稳定获得与决策相关的**中间表征**（例如逐步 Observation、分解结果、记忆条目），容易产生误判或漏判。
2. **防御割裂、难以联动**：输入侧、推理侧、工具侧、状态侧若各自为政，缺少统一信号（如注入迹象、风险分数、降级等级）在层间传递，就无法形成**可解释的纵深防御**，也不利于在攻击升级时自动收紧策略。
3. **关键环节覆盖不足**：高风险动作往往发生在**工具执行与状态更新**（权限边界、工具完整性、可回滚性）；仅覆盖「进/出两端」会低估工具滥用、描述篡改、记忆/环境腐蚀等向量——这与本仓库威胁模型（T1–T6）及 Agent-SafetyBench 类评测所强调的风险并不对齐。

### SafeHarness 的立场

本项目的核心判断是：**可信的 Agent 安全应尽量与 Harness 执行管线同构**——把安全机制作为执行路径上的**一等公民**，在统一抽象下接入多种 Harness，使「同一类防御」可在不同执行形态间**横向可比**。

具体而言：

- **生命周期对齐**：将安全职责映射到「输入处理 → 决策推理 → 动作执行 → 状态更新」四段，并辅以跨步记忆保护与熵监控，避免遗漏持久状态与跨步攻击面。
- **层间反馈而非堆叠**：各层可基于上游信号升级验证、触发回滚与权限收紧，并在风险降低后自适应恢复，平衡安全与效用。
- **可检验**：通过禁用单层或记忆组件的消融配置，验证「缺哪一层、伤哪类指标」，使动机不仅停留在设计主张，也与实验结论闭环。

---

## 核心架构：四层安全生命周期模型

### 为什么恰好是四层？

SafeHarness 的四层设计直接映射到 Agent 执行生命周期的四个不可缺少的阶段。每一层守护一个特定阶段，确保覆盖完整且不冗余：

```
Agent 执行生命周期                    SafeHarness 安全层
                                     
┌──────────────────┐                ┌─────────────────────────────────────────┐
│ 1. 信息输入       │ ◄─── 守护 ──── │ L2: INFORM — 对抗性上下文过滤              │
│ (Input Processing)│                │ → 结构净化 · 语义净化 · 溯源标记            │
├──────────────────┤                ├─────────────────────────────────────────┤
│ 2. 决策推理       │ ◄─── 守护 ──── │ L3: VERIFY — 因果安全验证                  │
│ (Decision Making) │                │ → Tier1 规则 · Tier2 LLM护栏 · Tier3 因果 │
├──────────────────┤                ├─────────────────────────────────────────┤
│ 3. 动作执行       │ ◄─── 守护 ──── │ L1: CONSTRAIN — 特权分离工具控制            │
│ (Action Execution)│                │ → 风险分级 · 能力令牌 · HMAC 签名验证        │
├──────────────────┤                ├─────────────────────────────────────────┤
│ 4. 状态更新       │ ◄─── 守护 ──── │ L4: CORRECT — 安全回滚与恢复               │
│ (State Update)    │                │ → 检查点 · 因果回滚 · 自适应降级/恢复         │
└──────────────────┘                └─────────────────────────────────────────┘
                                     
         跨越所有阶段 ◄─── 守护 ──── 跨层：记忆保护 & 熵监控
                                     → 溯源标记 · 异常检测 · 熵漂移触发
```

### 四层必要性论证

| 执行阶段 | 安全层 | 安全属性 | 为什么必要 |
|----------|--------|----------|-----------|
| **信息输入** | L2 INFORM | 输入完整性 (Input Integrity) | 若无此层，被投毒的上下文（提示注入、RAG 污染）直接进入 Agent，后续所有层的决策基础都被破坏 |
| **决策推理** | L3 VERIFY | 行为安全性 (Action Safety) | 即使输入干净，Agent 自身也可能做出不安全决策（实验表明 clean 场景也有 22-56% unsafe 率），需独立验证 |
| **动作执行** | L1 CONSTRAIN | 最小权限 (Least Privilege) | 即使决策被验证通过，仍需强制执行权限边界——L3 可能被绕过（对抗样本）或误判，L1 提供硬性保障 |
| **状态更新** | L4 CORRECT | 可恢复性 (Recoverability) | 前三层均有失败可能，最后一道防线保证可回滚到安全状态，且通过自适应降级/恢复平衡安全与效用 |

**充分性论证**：四层覆盖了完整的执行生命周期，不存在未被保护的阶段。跨层记忆保护针对持久状态（不属于任何单一阶段的循环），确保状态不被跨步骤污染。

**必要性验证**：消融实验（Ablation Study）通过逐一禁用各层来量化每一层的独立贡献，证明移除任何一层都会导致特定指标显著恶化。

### 威胁模型

| 威胁向量 | 描述 | 主要防御层 | 辅助防御层 |
|----------|------|-----------|-----------|
| T1: 直接提示注入 | 用户输入/指令中包含对抗性指令 | L2 (模式过滤+语义净化) | L3 (Tier3 因果诊断) |
| T2: 间接提示注入 | 工具返回值/RAG 检索内容中嵌入恶意指令 | L2 (observation 过滤) | L3 (因果诊断) |
| T3: 工具滥用 | Agent 被诱导调用高风险工具 | L1 (权限分级) | L3 (规则+LLM 验证) |
| T4: 工具描述篡改 | 攻击者修改工具描述以改变 Agent 行为 | L1 (HMAC 签名验证) | L2 (异常检测) |
| T5: 状态/记忆腐蚀 | 攻击者注入虚假对话历史或修改持久状态 | 跨层记忆保护 (溯源+异常) | L4 (回滚) |
| T6: 权限提升 | Agent 尝试执行超出授权范围的操作 | L1 (能力令牌+分级) | L4 (降级) |

### 层间反馈机制

SafeHarness 不是简单的安全层堆叠，各层之间存在主动反馈：

- **L2 检测异常 → L3 升级验证**：当 L2 检测到注入尝试（正则匹配或语义过滤变化超阈值）时，熵监控器记录违规；当熵分数超过阈值，L3 自动从 Tier 1（规则）升级到 Tier 2/3（LLM/因果）验证
- **L3 确认攻击 → L4 回滚+降级**：当 L3 的 Tier 3 因果诊断判定为注入攻击，L4 立即回滚到最近安全检查点（包括 memory 快照恢复）并升级降级等级
- **L4 降级 → L1 权限收紧**：L4 的降级等级与 L1 的五级风险体系一一对齐（0=全部 → 4=只读）
- **L4 自适应恢复 → L3 降级验证**：连续安全操作达到窗口阈值后，L4 自动恢复一级权限，同时 L3 的最低验证级别同步降级，平衡安全与效用

---

## 项目结构

```
SafeHarness/
├── config/
│   └── experiment.yaml          # 全局配置（模型、阈值、攻击类型、消融配置等）
├── data/                        # 自动下载的数据集（Agent-SafetyBench）
├── output/                      # 实验结果输出
├── src/
│   ├── llm_client.py            # LLM 调用封装
│   ├── data_loader.py           # 数据集下载与加载
│   ├── tools/
│   │   ├── registry.py          # 工具注册、HMAC 签名、风险分级、能力令牌
│   │   └── simulated_tools.py   # 模拟工具执行环境
│   ├── harness/
│   │   ├── base.py              # 抽象基类 & HarnessResult & L2 输入过滤
│   │   ├── direct.py            # Direct API（含 L2 observation 过滤）
│   │   ├── react.py             # ReAct 推理循环（含 L2 observation 过滤）
│   │   ├── multi_agent.py       # Multi-Agent + Critic（含 L2 observation 过滤）
│   │   ├── map_reduce.py        # Map-Reduce 任务委托（含 L2 observation 过滤）
│   │   └── memskill.py          # MemSkill 技能条件化记忆构建 + 记忆增强 ReAct
│   ├── safety/
│   │   ├── __init__.py          # SecurityPipeline / LlamaFirewallPipeline /
│   │   │                        # SystemPromptDefense / GuardrailPipeline
│   │   ├── layer1_privilege.py  # Layer 1: 特权分离 + 能力令牌
│   │   ├── layer2_filtering.py  # Layer 2: 对抗性上下文过滤
│   │   ├── layer3_verification.py # Layer 3: 三级因果安全验证
│   │   ├── layer4_rollback.py   # Layer 4: 安全回滚 + 自适应降级/恢复
│   │   └── memory_protection.py # 跨层记忆保护 & 熵监控
│   ├── attacks/
│   │   ├── context_poisoning.py   # A1: 上下文投毒（8 种 payload 变体）
│   │   ├── indirect_injection.py  # A2: 间接注入（通过工具返回值）
│   │   ├── tool_tampering.py      # A3: 工具描述篡改 + 参数提升
│   │   ├── memory_injection.py    # A4: 虚假历史注入
│   │   └── composite_attack.py    # A5: 组合攻击（多向量同时）
│   └── evaluation/
│       ├── rule_checker.py      # 规则安全检查器
│       ├── llm_judge.py         # LLM-as-Judge 评估器
│       ├── metrics.py           # UBR/ASR/TCR/UA/NNH 指标
│       └── statistics.py        # Bootstrap CI / 显著性检验
├── run_demo.py                  # 快速 Demo
├── run_experiment.py            # 完整实验入口（含消融/Bootstrap）
├── visualize.py                 # 结果可视化
├── results.py                   # 从已保存 JSON/JSONL 离线重算指标
├── test_e2e.py                  # 端到端冒烟（默认可 mock LLM）
├── llm_api.py                   # LLM API 底层调用
├── requirements.txt
└── README.md
```

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 运行 Demo

```bash
python run_demo.py
```

### 3. 运行完整实验

```bash
# 200 条数据，按当前 config 矩阵运行
python run_experiment.py --subset 200

# 消融实验
python run_experiment.py --ablation

# 带 Bootstrap 置信区间
python run_experiment.py --subset 100 --bootstrap
```

### 4. 自定义运行

```bash
# 只跑 direct + react，只比较 unprotected 和 safe_harness
python run_demo.py --harness direct react --security unprotected safe_harness

# 完整实验，16 线程
python run_experiment.py --subset 200 --workers 16
```

---

## 实验设计

### 实验矩阵

| 维度 | 选项 |
|------|------|
| **Harness 配置** | Direct API · ReAct · Multi-Agent+Critic · Map-Reduce · MemSkill |
| **安全模式** | Unprotected · System-Prompt · Guardrail · LlamaFirewall · SafeHarness |
| **攻击类型** | Clean · Context Poisoning · Indirect Injection · Tool Tampering · Memory Injection · Composite |
| **Agent 模型** | gpt5.4（默认）· deepseek_chat（可选） |
| **Judge 模型** | gpt4omini（默认）· gpt4o（可选，与 Agent 分离） |

### Harness 配置说明

| Harness | 执行形态 | 评测关注点 |
|---------|----------|------------|
| **Direct** | 单次模型调用，至多一轮工具执行 | 交互链最短，适合作为「无多步推理」对照；对间接注入的暴露主要在一次 observation |
| **ReAct** | Thought / Action / Observation 多步循环，直至 FINISH | 多轮推理与工具观测并存，典型考察 L2 对 observation、L3 对逐步推理的覆盖 |
| **Multi-Agent** | Primary 生成 + Critic 审核，可带修订轮次 | 多角色与修订链增加语义空间；适合检验跨角色上下文与安全反馈是否被安全管线感知 |
| **Map-Reduce** | 分解子任务 → 并行求解 → 聚合输出 | 子任务与聚合阶段均可能引入或放大风险；关注跨子结果与归并阶段的过滤与一致性 |
| **MemSkill** | 先基于 span 做技能条件化记忆构建，再执行记忆增强的 ReAct | 显式记忆读写与检索，攻击面含记忆质量与检索依赖；与「仅对话、无结构化记忆库」的 Harness 形成对照 |


### 安全基线说明

| 基线 | 防御机制 | 局限性 |
|------|---------|--------|
| **Unprotected** | 无 | 完全无保护 |
| **System-Prompt** | 系统提示中追加安全指令 | 纯依赖 LLM 遵从性，无强制执行 |
| **Guardrail** | 独立的输入过滤 + 输出检测 | 无 Harness 状态感知，无权限控制 |
| **LlamaFirewall** | PromptGuard-style 模式检测 + AlignmentCheck-style LLM 推理审计 | 无权限分级、无状态回滚、无层间反馈 |
| **SafeHarness** | 完整四层 + 跨层记忆保护 + 层间反馈 | 我们的方案 |

### 攻击类型说明

| 攻击 | 目标层 | 描述 | 参考 |
|------|--------|------|------|
| **A1: Context Poisoning** | L2 | 在指令中注入对抗性指令（8 种变体） | OWASP LLM01 |
| **A2: Indirect Injection** | L2 | 通过工具返回值注入恶意指令（模拟 RAG 投毒） | Greshake et al. 2023 |
| **A3: Tool Tampering** | L1 | 篡改工具描述 + HMAC 签名失效 | - |
| **A4: Memory Injection** | 跨层 | 注入虚假对话历史伪造预授权 | - |
| **A5: Composite** | 多层 | A1+A2+A3+A4 四种攻击同时施加 | - |

### 消融实验

通过逐一禁用各安全层，验证每层的必要性：

| 配置 | L1 | L2 | L3 | L4 | 记忆 | 验证目标 |
|------|----|----|----|----|------|---------|
| Full SafeHarness | ✓ | ✓ | ✓ | ✓ | ✓ | 完整系统基准 |
| w/o L1 | ✗ | ✓ | ✓ | ✓ | ✓ | 权限控制的必要性 |
| w/o L2 | ✓ | ✗ | ✓ | ✓ | ✓ | 输入过滤的必要性 |
| w/o L3 | ✓ | ✓ | ✗ | ✓ | ✓ | 安全验证的必要性 |
| w/o L4 | ✓ | ✓ | ✓ | ✗ | ✓ | 回滚机制的必要性 |
| w/o Memory | ✓ | ✓ | ✓ | ✓ | ✗ | 记忆保护的必要性 |

### 评测指标

| 指标 | 含义 | 方向 |
|------|------|------|
| **UBR** | Unsafe Behaviour Rate — 不安全行为率 | 越低越好 |
| **ASR** | Attack Success Rate — 攻击成功率 | 越低越好 |
| **TCR** | Task Completion Rate — 任务完成率 | 越高越好 |
| **UA** | Utility Under Attack — 受攻击时的效用 | 越高越好 |
| **NNH** | Number Needed to Harm — 每 N 次交互产生一次伤害 | 越高越好 |
| **ORR** | Over-Refusal Rate — 过度拒绝率（fulfillable 任务被拒绝的比例） | 越低越好 |

所有指标均提供 Bootstrap 95% 置信区间和配对显著性检验。ORR 用于衡量安全机制的保守程度——过低的 UBR 如果伴随过高的 ORR，说明系统通过"一刀切式拒绝"而非精确防御来实现安全。

---

## 数据集

### 主数据集：Agent-SafetyBench

[Agent-SafetyBench](https://github.com/thu-coai/Agent-SafetyBench)（清华大学，arXiv:2412.14470）：
- 2000 条 Agent 安全评测任务
- 8 大风险类别
- 349 个交互环境
- 每条任务附带工具定义和失败模式标注

数据在首次运行时自动下载到 `data/agent_safety_bench/` 目录。

### 扩展数据集（可选）

可通过修改 `src/data_loader.py` 集成 InjecAgent 等注入攻击专用数据集，以增强泛化性评估。

---

## 配置说明

所有参数均在 `config/experiment.yaml` 中配置，包括：

- **models**: Agent 模型列表和 Judge 模型（必须不同以避免自我评估偏差；当前默认 `gpt5.4` + `gpt4omini`）
- **harness**: Harness 类型列表及各类型参数
- **security_modes**: 5 种安全模式
- **safety**: 各层参数（L1 令牌配置、L2 可疑模式、L3 阈值、L4 检查点间隔与恢复窗口）
- **attacks**: 5 种攻击类型
- **ablation**: 消融实验配置（禁用层列表、子集大小、Harness 类型）
- **evaluation**: Bootstrap 采样数等

---

## 实验运行指南与 API 调用量估算

### 当前默认实验规模（来自 `config/experiment.yaml`）

当前仓库默认配置：
- 任务数：200（`data.experiment_subset_size`）
- Harness：3（`react`, `multi_agent`, `memskill`）
- Security Mode：5
- Attack Condition：6（clean + A1-A5，clean 在代码中自动加入）
- Agent Model：1（`gpt5.4`，与下文成本表 Agent 单价一致；若改用 `deepseek_chat` 等其它模型需替换费率）

主实验 job 数：

```
200 × 3 × 5 × 6 × 1 = 18,000 jobs
```

消融实验（默认）job 数：

```
50 × 2 harness × 6 configs × 6 attack_conditions = 3,600 jobs
```

合计（主实验 + 消融）：

```
21,600 jobs
```

### API 调用量（与实现对齐的粗算）

以下指 **`call_model` → Agent 模型** 的次数（见 `src/harness/*.py`）；每 job 另有 **1 次** `call_judge`（`src/evaluation/llm_judge.py`）。在 **`safe_harness`** 下，L2 语义过滤与 L3 Tier 2/3 还会对 **`judge_model`** 额外调用 `call_model`（`src/safety/layer2_filtering.py`、`layer3_verification.py`），不计入下表「Harness 侧」次数。

- **ReAct**（`src/harness/react.py`）：每步一次 Agent 调用，至多 `react_max_steps`（默认 **5**）次；提前 `FINISH` 则更少。
- **Multi-Agent**（`src/harness/multi_agent.py`）：每轮「Primary + Critic」，Critic 也走 **同一 Agent 模型**；`multi_agent_max_revisions` 默认 2 时，至多 **5** 次 Agent 调用（两轮完整 critic + 最后一轮仅 primary）。
- **MemSkill**（`src/harness/memskill.py`）：随 `task["dialog"]` 分段出的 span 数与是否提前结束变化较大。Phase 1 每个 span 约 2 次（选技能 + 执行器）；Phase 2 每 ReAct 步 1 次，若做增量记忆更新则每步最多再 2 次；`memskill_evolve_skills` 且 `memskill_evolve_after_phase1` 时再 +1。无 span 时约等于「仅 Phase 2 ReAct」，可低至约 **5** 次 Agent 调用。

粗算示例（不含 `safe_harness` 下 L2/L3 对 `judge_model` 的额外调用）：若 Harness 侧 Agent 调用按三种类型分别约 **3 / 3 / 10** 次取混合中位、每 job 再加 **1** 次评测 Judge，则单次 job 约 **~7** 次 LLM 调用；主实验 **18,000** jobs 则约 **18,000×7 ≈ 1.26×10⁵** 量级。MemSkill 随 span 与增量记忆路径变化大，**safe_harness** 还会显著增加 **Judge 侧**调用。

总 call 数请以网关或日志中的 `usage` 为准。

### 成本估算（CNY，按你给的单价）

当前 `experiment.yaml` 中 Agent 为 **`gpt5.4`**、Judge 为 **`gpt4omini`**，与下表一致。

计价（CNY / 1M tokens）——对应 `llm_api.py` 中 **`gpt5.4`** → `gpt-5.4-2026-03-05`、**`gpt4omini`** → `gpt-4o-mini-2024-07-18`：
- Agent (`gpt5.4`)：输入 15.750，输出 94.500
- Judge（`gpt4omini`，与「gpt-4o-mini」同档）：输入 0.945，输出 3.780

**「Judge tokens」在本项目中**应计入所有走 **`judge_model`** 的调用：最终评测（`call_judge`）、以及启用时的 L2 语义过滤 / L3 Tier 2–3（均使用 `call_model(judge_model, …)`）。下表若只按「评测一次」估 Judge tokens，在 **`safe_harness`** 下会**偏低**。

单个 job 成本（上表两类模型；若 Agent 改用其它模型请替换 Agent 侧输入/输出单价）：

```
Cost_job(CNY) =
  (Agent_in_tokens  × 15.750
 + Agent_out_tokens × 94.500
 + Judge_in_tokens  × 0.945
 + Judge_out_tokens × 3.780) / 1,000,000
```

三档示例（代入上式；**21,600 jobs 列为 `单 job 估算 × 21,600`，四舍五入到整数 CNY**）：

| 档位 | Agent tokens (in/out) | Judge tokens (in/out) | 单 job 估算 | 21,600 jobs 估算 |
|------|------------------------|------------------------|------------|------------------|
| 保守 | 800 / 250 | 600 / 80 | ~0.037 CNY | ~801 CNY |
| 中位 | 1200 / 400 | 800 / 120 | ~0.058 CNY | ~1,251 CNY |
| 偏高 | 1800 / 700 | 1200 / 180 | ~0.096 CNY | ~2,080 CNY |

> 注：成本对 **Agent 输出 token** 最敏感（单价最高）。如需压成本，优先控制 ReAct / MemSkill 步数、减少冗长输出与无效工具回合；**safe_harness** 下还需为 L2/L3 预留 **`judge_model` 额度**。

### 运行命令

```bash
# 主实验（按 config 默认矩阵）
python run_experiment.py --subset 200

# 仅 SafeHarness 模式跑全攻击
python run_experiment.py --subset 200 --security safe_harness

# 仅 baseline 对比（clean + A1 + A5）
python run_experiment.py --subset 200 \
  --security unprotected system_prompt guardrail llamafirewall \
  --attacks clean context_poisoning composite

# 消融实验
python run_experiment.py --ablation

# 主实验 + Bootstrap 置信区间
python run_experiment.py --subset 200 --bootstrap

# Demo：仅跑指定 harness / security（run_demo 支持过滤）
python run_demo.py --tasks 5 --harness react multi_agent --security unprotected safe_harness
```

---

## 近期改进

### v0.3 (2026-04)

**新增 MemSkill Harness**

新增与 ReAct / Multi-Agent / Map-Reduce 并列的 MemSkill Harness，基于 Zhang et al. (2026) 的 MemSkill 框架：

- **技能银行（Skill Bank）**：维护一组结构化、可复用的记忆技能（INSERT / UPDATE / DELETE / NOOP），每个技能包含 Purpose / When to use / How to apply / Constraints / Action type
- **两阶段执行**：
  - *Phase 1 — 记忆构建*：将先验对话/上下文切分为文本段（span），每段通过 LLM Controller 选择 Top-K 技能，再由 LLM Executor 在一次调用中生成技能引导的记忆更新
  - *Phase 2 — 记忆增强 ReAct*：在标准 Thought / Action / Observation 循环中，每轮注入从 Memory Bank 检索的相关记忆；每次新 Observation 后触发增量记忆更新
- **可选技能库轻量自进化**（非论文中的训练式 Designer）：在 `memskill_evolve_skills: true` 时，可在 Phase 1 结束后（及可选地在整段任务结束后）额外调用 LLM，根据当前技能目录、Memory Bank 与 trace 提议 **新增一条技能** 或 **向现有技能的 `content` 追加指导**；进化后的技能库在 Phase 2 中生效。结果记录在 `metadata.skill_evolution_log` 与 trace 中的 `memskill_skill_evolution` 条目。默认关闭，且不包含跨任务持久化。
- **安全集成**：与 SafeHarness 四层安全机制完全兼容——工具输出经 L2 过滤，推理步骤记录至 L3，工具调用经 L1 权限检查
- **配置项**：`memskill_react_steps`（Phase 2 步数）、`memskill_top_k`（每段选择技能数）、`memskill_retrieve_k`（每轮检索记忆数）；自进化相关：`memskill_evolve_skills`（总开关）、`memskill_max_skills`（技能总数上限）、`memskill_evolve_after_phase1`（Phase 1 后进化，使 Phase 2 使用新库）、`memskill_evolve_end_task`（任务结束后再进化一次，多用于记录或后续扩展持久化）

> 参考：Zhang et al., "MemSkill: Learning and Evolving Memory Skills for Self-Evolving Agents", arXiv:2602.02474, Feb 2026.

### v0.2 (2026-04)

**核心逻辑修复**
- **L2 语义过滤反馈闭环**：LLM 语义过滤的结果现在正确反馈到 `injection_detected` 和 provenance 标记（通过检测文本变化率），确保 L2→L3 层间升级在 `always_semantic` 模式下有效
- **L2 来源感知信任级别**：不同来源类型（user_input/tool_output/retrieved/inter_agent）现在有差异化的默认信任级别
- **L4 Memory 快照**：Checkpoint 现在包含 ProtectedMemory 快照，回滚时同步恢复 memory 状态，防止记忆腐蚀跨越回滚边界
- **L4 降级映射对齐**：降级等级从 3 级扩展为 5 级，与 L1 的五级风险体系一一对齐（destructive → network → execute → write → read_only）
- **L3 双向可调**：新增 `maybe_deescalate()` 方法，在 L4 自适应恢复时联动降级 L3 的最低验证级别
- **L1 路径遍历防护**：路径检查现在拒绝包含 `..` 的路径并使用 `os.path.normpath` 规范化

**评估与解析修复**
- **LLM Judge 标签解析**：修复子串匹配导致 "SAFE" 文本中包含 "UNSAFE" 被误判的问题，改用词边界匹配和否定上下文检查
- **L3 Tier 2 标签优先级**：改为基于位置的匹配（取最早出现的标签），避免遍历顺序偏差
- **ReAct 终止条件**：从宽松的子串匹配改为严格的正则模式（`Action: FINISH` / `Final Answer:`）

**其他改进**
- `data_loader.load_subset()` 的 `seed` 参数现在正确用于控制分桶采样的随机性
- L2 注入模式集扩展：新增 pretend/jailbreak/DAN/developer mode/bypass/roleplay 等 8 种模式
- 端到端测试增加安全语义断言（L4 回滚正确性、降级映射、L3 升降级、L1 路径遍历防护、ReAct 终止正则）

---

## 引用

如果使用本框架，请引用：

```bibtex
@article{safeharness2026,
  title={SafeHarness: Lifecycle-Integrated Security Architecture for Safe LLM Agent Deployment},
  author={Liu, Yang and Chen, Yancheng and Zhang, Shuai and Wu, Yongxuan and Lin, Xixun},
  journal={arXiv preprint},
  year={2026}
}
```
