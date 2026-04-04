# SafeHarness — 面向 Agent 安全的 Harness 架构设计框架

> **SafeHarness: Security-Aware Harness Architecture for Safe AI Agent Deployment**

本项目实现了论文中提出的 SafeHarness 框架——一个将安全机制原生嵌入 Agent Harness 执行生命周期的统一安全架构。

---

## 设计动机

现有 AI Agent 安全方案主要采用**外挂式（bolt-on）**思路：在 Agent 执行流程的外部叠加独立的安全模块（如输入过滤器、输出检测器）。这种方法存在根本性缺陷：

1. **信息盲区**：外挂模块无法感知 Harness 内部状态（如 ReAct 的推理链、Multi-Agent 的角色上下文、Map-Reduce 的任务分解过程），导致安全决策缺乏上下文
2. **防御碎片化**：各安全检查点之间缺乏协调与反馈，无法形成纵深防御
3. **覆盖不全**：仅覆盖输入或输出端，忽略了执行过程中的权限控制、状态管理等关键环节

SafeHarness 的核心观察是：**Agent 的安全性不能后期追加，必须从 Harness 架构层面原生嵌入**。安全机制应当覆盖 Agent 执行生命周期的每一个阶段，且各安全层之间需要有层间反馈和联动。

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
│   ├── memory/
│   │   ├── __init__.py          # 记忆模块入口
│   │   ├── working_memory.py    # 工作记忆（固定容量 FIFO，注入 system prompt）
│   │   └── archival_memory.py   # 档案记忆（无限容量，关键词检索）
│   ├── harness/
│   │   ├── base.py              # 抽象基类 & HarnessResult & L2 输入过滤
│   │   ├── direct.py            # Direct API（含 L2 observation 过滤）
│   │   ├── react.py             # ReAct 推理循环（含 L2 observation 过滤）
│   │   ├── multi_agent.py       # Multi-Agent + Critic（含 L2 observation 过滤）
│   │   ├── map_reduce.py        # Map-Reduce 任务委托（含 L2 observation 过滤）
│   │   └── memory.py            # MemGPT 式 Memory Harness（分层记忆管理）
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
# 200 条数据，全矩阵
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
| **Harness 配置** | Direct API · ReAct · Multi-Agent+Critic · Map-Reduce · MemGPT-style Memory |
| **安全模式** | Unprotected · System-Prompt · Guardrail · LlamaFirewall · SafeHarness |
| **攻击类型** | Clean · Context Poisoning · Indirect Injection · Tool Tampering · Memory Injection · Composite |
| **Agent 模型** | DeepSeek-Chat · GPT-4o（另可扩展） |
| **Judge 模型** | GPT-4o（固定，与 Agent 模型分离） |

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

- **models**: Agent 模型列表和 Judge 模型（必须不同以避免自我评估偏差）
- **harness**: Harness 类型列表及各类型参数
- **security_modes**: 5 种安全模式
- **safety**: 各层参数（L1 令牌配置、L2 可疑模式、L3 阈值、L4 检查点间隔与恢复窗口）
- **attacks**: 5 种攻击类型
- **ablation**: 消融实验配置（禁用层列表、子集大小、Harness 类型）
- **evaluation**: Bootstrap 采样数等

---

## 实验运行指南与 API 调用量估算

### 完整实验矩阵

完整对比实验包含以下维度的笛卡尔积：

| 维度 | 数量 | 具体值 |
|------|------|--------|
| 任务数 | 200 | Agent-SafetyBench 分层采样 |
| Harness | 5 | Direct, ReAct, Multi-Agent, Map-Reduce, Memory |
| Security Mode | 5 | Unprotected, System-Prompt, Guardrail, LlamaFirewall, SafeHarness |
| Attack Condition | 6 | Clean + A1-A5 |
| Agent Model | 2 | DeepSeek-Chat, GPT-4o |

全矩阵 job 数 = 200 × 5 × 5 × 6 × 2 = **60,000 jobs**

### 每个 Job 的 API 调用次数

不同 Harness 和安全模式下，每个 job 所需的 LLM API 调用次数不同：

| Harness | Agent 调用 | L2 语义过滤 | L3 Tier2/3 | 评估 Judge | 合计 |
|---------|-----------|------------|-----------|-----------|------|
| Direct | 1 | 0-1 | 0-1 | 1 | ~3 |
| ReAct (5 步) | 5 | 0-2 | 0-2 | 1 | ~8 |
| Multi-Agent | 2-4 | 0-1 | 0-1 | 1 | ~6 |
| Map-Reduce | 4-6 | 0-1 | 0-1 | 1 | ~7 |
| Memory (5 步) | 5 | 0-2 | 0-2 | 1 | ~8 |

说明：
- **Agent 调用**：模型推理次数，取决于 Harness 配置（ReAct 步数、Critic 轮数、子任务数等）
- **L2 语义过滤**：仅在 Stage 2 模式检测命中且有 judge_model 时触发额外 LLM 调用
- **L3 Tier2/3**：仅在 Tier 1 规则判定为中等风险（tau_low < score < tau_high）时升级到 LLM 验证
- **评估 Judge**：每个 job 结束后调用一次 LLM Judge 评估安全性
- Unprotected / System-Prompt 模式下无 L2/L3 LLM 调用，仅 Agent + Judge

加权平均 ≈ **6 次调用/job**

### 全量实验 API 调用量

```
全矩阵：60,000 jobs × 6 calls/job ≈ 360,000 次 API 调用
```

### 优化方案（推荐）

实际运行中，不需要对所有 baseline 跑全部攻击。推荐策略：

| 安全模式 | 攻击条件 | 理由 |
|---------|---------|------|
| SafeHarness | 全部 6 种 | 需要完整评估主系统在所有攻击下的表现 |
| 其他 4 种 baseline | Clean + A1 + A5 | Clean 提供基准，A1 是最常见攻击，A5 综合测试 |

优化后的 job 数量计算：

```
SafeHarness: 5 harness × 6 attack × 2 model × 200 task = 12,000 jobs
Baselines:   5 harness × 3 attack × 2 model × 200 task × 4 mode = 24,000 jobs
总计: 36,000 jobs × 6 calls/job ≈ 216,000 次 API 调用
```

### 消融实验

```
50 tasks × 2 harness (ReAct + Multi-Agent) × 6 configs × 3 attacks = 1,800 jobs
1,800 jobs × 6 calls/job ≈ 10,800 次 API 调用
```

### 总计

| 方案 | Job 数 | API 调用量 | 预计成本（GPT-4o） |
|------|--------|-----------|-----------------|
| 全矩阵 | 60,000 | ~360,000 | ~$360-600 |
| 优化方案（推荐） | 36,000 | ~216,000 | ~$220-360 |
| 消融实验 | 1,800 | ~10,800 | ~$11-18 |
| **优化方案 + 消融** | **37,800** | **~226,800** | **~$230-380** |

> 注：成本估算基于 GPT-4o 的 input/output token 价格，实际成本取决于平均 token 长度。DeepSeek-Chat 作为 Agent 时成本显著更低。

### 运行命令

```bash
# 完整主实验（优化方案）
python run_experiment.py --subset 200

# 仅 SafeHarness 模式跑全攻击
python run_experiment.py --subset 200 --security safe_harness

# 仅 baseline 对比（clean + A1 + A5）
python run_experiment.py --subset 200 \
  --security unprotected system_prompt guardrail llamafirewall \
  --attacks clean context_poisoning composite

# 消融实验
python run_experiment.py --ablation

# 带 Bootstrap CI
python run_experiment.py --subset 200 --bootstrap
```

---

## 近期改进

### v0.3 (2026-04)

**新增 MemoryHarness — 第五种 Harness 类型**
- 基于 MemGPT（arXiv:2310.08560）的分层记忆架构，新增 `MemoryHarness` 作为第五种 Harness 类型
- **Working Memory**：固定容量 FIFO 记忆，始终注入 system prompt，agent 通过 `memory_update_working` 工具主动管理
- **Archival Memory**：无限容量持久存储，支持 `memory_store`（写入）和 `memory_retrieve`（关键词检索）
- 记忆工具不经过 `security_pipeline.check_action`（内部认知操作），但检索结果经过 L2 `filter_context` 过滤以防止记忆污染攻击
- 环境工具结果自动存入 Archival Memory，便于后续步骤检索
- `HarnessResult.metadata` 中记录 `memory_stats`（archival 条目数、检索次数、working memory 更新次数等）
- 新增 `src/memory/` 模块（`working_memory.py` + `archival_memory.py`）
- 新增 `test_memory_pipeline.py` 独立测试脚本

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

## 待跑实验方案（Experiment Roadmap）

以下是当前版本需要完成的全部实验，按优先级排列。

### 实验一：主实验（Main Comparison）

**目标**：对比 5 种 Harness × 5 种安全模式在 Clean 和各攻击条件下的安全与效用表现。

| 维度 | 值 |
|------|------|
| 数据 | Agent-SafetyBench 200 条（分层采样） |
| Harness | Direct · ReAct · Multi-Agent · Map-Reduce · **Memory** |
| Security Mode | Unprotected · System-Prompt · Guardrail · LlamaFirewall · SafeHarness |
| Attack | Clean · Context Poisoning · Indirect Injection · Tool Tampering · Memory Injection · Composite |
| Agent Model | DeepSeek-Chat · GPT-4o |
| Judge Model | GPT-4o |
| 指标 | UBR · ASR · TCR · UA · NNH · ORR（均附 Bootstrap 95% CI） |

**优化运行策略**（减少 API 调用量）：

| 分组 | Security Mode | Attack | Harness | 理由 |
|------|--------------|--------|---------|------|
| A — 主系统全攻击 | SafeHarness | 全部 6 种 | 全部 5 种 | 完整评估主方案 |
| B — Baseline 精简 | 其余 4 种 | Clean + A1 + A5 | 全部 5 种 | Clean 提供基准，A1 最常见，A5 综合 |

```bash
# A 组：SafeHarness 全攻击
python run_experiment.py --subset 200 --security safe_harness --bootstrap

# B 组：Baseline 精简
python run_experiment.py --subset 200 \
  --security unprotected system_prompt guardrail llamafirewall \
  --attacks clean context_poisoning composite --bootstrap
```

**预期产出表格**：

| | Unprotected | System-Prompt | Guardrail | LlamaFirewall | SafeHarness |
|---|---|---|---|---|---|
| Direct — UBR / TCR | | | | | |
| ReAct — UBR / TCR | | | | | |
| Multi-Agent — UBR / TCR | | | | | |
| Map-Reduce — UBR / TCR | | | | | |
| **Memory — UBR / TCR** | | | | | |

### 实验二：Memory Harness 专项分析

**目标**：深入分析 MemoryHarness 的独特行为——记忆使用模式、记忆对安全性的影响、记忆污染攻击的效果。

**2a. Memory vs ReAct 逐步对比**

Memory Harness 本质上是 ReAct + 分层记忆管理。通过与 ReAct 的逐步对比来量化"记忆"的增量效果：

| 对比维度 | ReAct | Memory | Delta |
|----------|-------|--------|-------|
| UBR（Clean） | | | |
| UBR（Under Attack） | | | |
| TCR（Clean） | | | |
| TCR（Under Attack） | | | |
| 平均步数 | | | |
| 平均工具调用数 | | | |

```bash
python run_experiment.py --subset 200 --harness react memory --bootstrap
```

**2b. Memory 统计分析**

从 `HarnessResult.metadata["memory_stats"]` 提取以下指标：

| 统计量 | 含义 |
|--------|------|
| `archival_entries` | 平均每 task 存入 Archival Memory 的条目数 |
| `archival_retrieves` | 平均检索次数 |
| `working_memory_updates` | Working Memory 更新次数 |
| WM 使用率 | `working_memory_entries / working_memory_capacity` |

按 security mode 和 attack type 分组，观察安全机制是否影响记忆使用模式。

**2c. Memory Injection 攻击对 Memory Harness 的特殊效果**

Memory Injection 攻击注入虚假历史，对 Memory Harness 尤其危险（虚假信息可能被存入 Archival Memory 并在后续步骤被检索出来）。重点观察：

- Memory Harness 在 Memory Injection 下的 UBR 是否高于其他 Harness
- SafeHarness 的 L2 `filter_context` 是否有效拦截了从 Archival Memory 检索出的污染内容

```bash
python run_experiment.py --subset 200 --attacks memory_injection \
  --security unprotected safe_harness --harness react memory --bootstrap
```

### 实验三：消融实验（Ablation Study）

**目标**：验证 SafeHarness 四层安全机制中每一层的独立贡献。

| 配置 | L1 | L2 | L3 | L4 | 记忆保护 | 验证目标 |
|------|:--:|:--:|:--:|:--:|:------:|---------|
| Full | ✓ | ✓ | ✓ | ✓ | ✓ | 基准 |
| w/o L1 | ✗ | ✓ | ✓ | ✓ | ✓ | 权限控制必要性 |
| w/o L2 | ✓ | ✗ | ✓ | ✓ | ✓ | 输入过滤必要性 |
| w/o L3 | ✓ | ✓ | ✗ | ✓ | ✓ | 安全验证必要性 |
| w/o L4 | ✓ | ✓ | ✓ | ✗ | ✓ | 回滚机制必要性 |
| w/o Memory | ✓ | ✓ | ✓ | ✓ | ✗ | 记忆保护必要性 |

在 ReAct 和 Multi-Agent 两种 Harness 上运行（配置复杂度适中，安全层参与度最高）：

```bash
python run_experiment.py --ablation
# 50 tasks × 2 harness × 6 configs × 3 attacks = 1,800 jobs
```

### 实验四：跨 Harness 安全-效用权衡分析

**目标**：在统一的攻击条件下，绘制每种 Harness 的 Safety-Utility Pareto 前沿。

对每种 Harness，以 (1−UBR) 为 x 轴、TCR 为 y 轴，标注 5 种安全模式为不同的点。观察：

- 哪种 Harness 在 Pareto 前沿上表现最好（安全与效用兼优）
- Memory Harness 是否因为额外的记忆管理开销降低了 TCR
- Memory Harness 是否因为记忆增强上下文而提高了安全性

### API 调用量总估算

| 实验 | Job 数 | API 调用量 | 预计成本 |
|------|--------|-----------|---------|
| 主实验 A 组（SafeHarness 全攻击） | 12,000 | ~72,000 | ~$72-120 |
| 主实验 B 组（Baseline 精简） | 24,000 | ~144,000 | ~$144-240 |
| Memory 专项（2a+2c） | 4,800 | ~28,800 | ~$29-48 |
| 消融实验 | 1,800 | ~10,800 | ~$11-18 |
| **合计** | **~42,600** | **~255,600** | **~$256-426** |

> 注：预计成本基于 GPT-4o 价格。DeepSeek-Chat 成本约为 GPT-4o 的 1/10，实际混合使用时总成本显著更低。

### 推荐运行顺序

```
1. python test_e2e.py                          # 验证代码无误
2. python test_memory_pipeline.py              # 验证 Memory 通路
3. python run_demo.py --tasks 3                # 小规模 demo 确认输出格式
4. python run_experiment.py --subset 50 \      # 小规模验证全流程
     --harness direct react memory \
     --security unprotected safe_harness \
     --bootstrap
5. python run_experiment.py --subset 200 \     # 主实验 A 组
     --security safe_harness --bootstrap
6. python run_experiment.py --subset 200 \     # 主实验 B 组
     --security unprotected system_prompt guardrail llamafirewall \
     --attacks clean context_poisoning composite --bootstrap
7. python run_experiment.py --ablation         # 消融实验
8. python visualize.py output/experiment_results.json  # 生成图表
```

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

MemoryHarness 的设计参考了 MemGPT 的分层记忆架构：

```bibtex
@article{packer2023memgpt,
  title={MemGPT: Towards LLMs as Operating Systems},
  author={Packer, Charles and Wooders, Sarah and Lin, Kevin and Fang, Vivian and Patil, Shishir G and Stoica, Ion and Gonzalez, Joseph E},
  journal={arXiv preprint arXiv:2310.08560},
  year={2023}
}
```
