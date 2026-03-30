# SafeHarness — 面向 Agent 安全的 Harness 架构设计框架

> **SafeHarness: Security-Aware Harness Architecture for Safe AI Agent Deployment**

本项目实现了论文中提出的 SafeHarness 框架——一个将安全机制原生嵌入 Agent Harness 四大功能层（约束-告知-验证-纠正）的统一安全架构。

---

## 项目结构

```
agent/code/
├── config/
│   └── experiment.yaml          # 全局配置（模型、阈值、攻击类型等）
├── data/                        # 自动下载的数据集（Agent-SafetyBench）
├── output/                      # 实验结果输出
├── src/
│   ├── llm_client.py            # LLM 调用封装（复用 llm_api_openai.py）
│   ├── data_loader.py           # 数据集下载与加载
│   ├── tools/
│   │   ├── registry.py          # 工具注册、签名、分级
│   │   └── simulated_tools.py   # 模拟工具执行环境
│   ├── harness/
│   │   ├── base.py              # 抽象基类 & HarnessResult
│   │   ├── direct.py            # Direct API（无 harness 基线）
│   │   ├── react.py             # ReAct 推理循环
│   │   ├── multi_agent.py       # Multi-Agent + Critic
│   │   └── map_reduce.py        # Map-Reduce 任务委托
│   ├── safety/
│   │   ├── __init__.py          # SecurityPipeline 统一入口
│   │   ├── layer1_privilege.py  # Layer 1: 特权分离工具控制
│   │   ├── layer2_filtering.py  # Layer 2: 对抗性上下文过滤
│   │   ├── layer3_verification.py # Layer 3: 因果安全验证
│   │   ├── layer4_rollback.py   # Layer 4: 安全回滚与恢复
│   │   └── memory_protection.py # 跨层记忆保护 & 熵监控
│   ├── attacks/
│   │   ├── context_poisoning.py # A1: 上下文投毒
│   │   ├── tool_tampering.py    # A3: 工具编排篡改
│   │   └── memory_injection.py  # A4: 记忆操纵
│   └── evaluation/
│       ├── rule_checker.py      # 规则安全检查器
│       ├── llm_judge.py         # LLM-as-Judge 评估器
│       └── metrics.py           # UBR/ASR/TCR/UA/NNH 指标
├── run_demo.py                  # 快速 Demo（3 条数据）
├── run_experiment.py            # 完整实验入口
├── requirements.txt
└── README.md
```

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 运行 Demo（3 条数据，端到端）

```bash
cd agent/code
python run_demo.py
```

这会：
1. 自动从 HuggingFace 下载 Agent-SafetyBench 数据集（2000 条）
2. 选取 3 条覆盖不同风险类别的样本
3. 对每条样本 × 4 种 Harness × 3 种安全模式运行实验
4. 对每条样本同时注入上下文投毒攻击进行对比
5. 使用 LLM-as-Judge + 规则检查器联合评估
6. 打印汇总表格并保存到 `output/demo_results.json`

### 3. 自定义运行

```bash
# 只跑 direct + react harness，只比较 unprotected 和 safe_harness
python run_demo.py --harness direct react --security unprotected safe_harness

# 跑 5 条数据
python run_demo.py --tasks 5

# 完整实验（所有模型 × 所有配置）
python run_experiment.py --subset 10
```

---

## 核心架构

### SafeHarness 四层安全架构

```
┌───────────────────────────────────────────────────────────┐
│  Layer 4: Safe Rollback & Recovery       (CORRECT)        │
│  → 状态检查点 · 因果回滚 · 优雅降级                        │
├───────────────────────────────────────────────────────────┤
│  Layer 3: Causal Safety Verification     (VERIFY)         │
│  → Tier1 规则检查 · Tier2 LLM 护栏 · Tier3 因果诊断       │
├───────────────────────────────────────────────────────────┤
│  Layer 2: Adversarial Context Filtering  (INFORM)         │
│  → 结构化净化 · 语义净化 · 溯源追踪                        │
├───────────────────────────────────────────────────────────┤
│  Layer 1: Privilege-Separated Tool Control (CONSTRAIN)    │
│  → 工具分级 · 能力令牌 · 描述签名                          │
├───────────────────────────────────────────────────────────┤
│  Cross-Layer: Memory Protection & Entropy Monitoring      │
│  → 溯源标记 · 异常检测 · 熵漂移监控                        │
└───────────────────────────────────────────────────────────┘
```

### 实验矩阵

| 维度 | 选项 |
|------|------|
| Harness 配置 | Direct API · ReAct · Multi-Agent+Critic · Map-Reduce |
| 安全模式 | Unprotected · Bolt-On · SafeHarness |
| 攻击类型 | 上下文投毒 · 工具篡改 · 记忆注入 |

### 评测指标

| 指标 | 含义 |
|------|------|
| **UBR** | Unsafe Behaviour Rate — 不安全行为率 |
| **ASR** | Attack Success Rate — 攻击成功率 |
| **TCR** | Task Completion Rate — 任务完成率 |
| **UA** | Utility Under Attack — 受攻击时的效用 |
| **NNH** | Number Needed to Harm — 每 N 次交互产生一次伤害 |

---

## 配置说明

所有参数均在 `config/experiment.yaml` 中配置，包括：

- **models**: 使用的 Agent 模型和 Judge 模型（key 对应 `llm_api_openai.py` 中的 `MODEL_FUNC_MAP`）
- **harness**: Harness 类型列表及各类型参数
- **security_modes**: 安全模式列表
- **safety**: Layer 3 阈值（tau_low / tau_high）、工具风险分级、可疑模式列表等
- **attacks**: 启用的攻击类型

---

## 数据集

使用 [Agent-SafetyBench](https://github.com/thu-coai/Agent-SafetyBench)（清华大学，arXiv:2412.14470），包含：

- 2000 条 Agent 安全评测任务
- 8 大风险类别
- 349 个交互环境
- 每条任务附带工具定义和失败模式标注

数据在首次运行时自动下载到 `data/agent_safety_bench/` 目录。

---

## 输出示例

运行 `run_demo.py` 后会输出类似：

```
Summary Table
----------------------------------------------------------------------------------
Harness        Security       UBR    ASR    TCR     UA    NNH  Blocked
----------------------------------------------------------------------------------
direct         unprotected   66.67% 66.67% 100.00% 33.33%  1.50       0
direct         bolt_on       33.33% 33.33% 100.00% 66.67%  3.00       1
direct         safe_harness  16.67% 16.67%  83.33% 83.33%  6.00       2
react          unprotected   50.00% 50.00% 100.00% 50.00%  2.00       0
...
```

详细结果保存为 `output/demo_results.json`。

---

## 引用

如果使用本框架，请引用：

```bibtex
@article{safeharness2026,
  title={SafeHarness: Security-Aware Harness Architecture for Safe AI Agent Deployment},
  year={2026}
}
```
