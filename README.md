# Upear Guard

> 面向 LLM 智能体的**生命周期安全框架**与**多智能体规划平台**。
> 安全机制原生嵌入智能体执行生命周期：输入防线、能力授权、强制回执、工具网关、审计脱敏、运行监督与人工复核，配合「LLM 提案 + 确定性编译 + 人工确认」的 FSM 多智能体规划。

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Status](https://img.shields.io/badge/Status-Engineering%20Alpha-orange)

> **来源与范围**：Upear Guard 由两部分构成——① **Upear Guard 安全框架**（基于 SafeHarness 论文[官方实现](https://github.com/liu-yang-maker/SafeHarness)提出的框架，并做了生产化改造与优化，架构出处见文末[致谢](#-致谢)）；② **Upear 平台**（受保护对话链、FSM 规划、安全运营前端等工程扩展），平台后端基于 [HugAgentOS](https://github.com/ZJU-REAL/HugAgentOS) 基座构建，我们在其上叠加了全部安全能力。本仓库自身的贡献见「[本项目的原创与扩展](#本项目的原创与扩展)」。

---

## 为什么是 Upear Guard

工具型智能体在**多轮推理、工具调用、环境状态与记忆读写**中完成任务，不安全行为可能出现在任何一环。把安全做成「进模型前拦一次、出模型后查一次」的外挂护栏，会漏掉工具滥用、间接注入、记忆腐蚀等关键攻击面。

Upear Guard 的核心判断（源自 SafeHarness 论文并在此实现）：**可信的智能体安全应与 Harness 执行管线同构**——安全机制作为执行路径上的一等公民，在统一抽象下接入多种执行形态（ReAct、多智能体、Map-Reduce 等），使同一类防御横向可比。

本项目包含两部分：

- **Upear Guard 安全框架**（`src/safeharness`，独立 pip 包；fork 自 SafeHarness 论文官方实现）：与执行生命周期对齐的四层安全模型、能力令牌与强制回执、工具安全网关、审计与监督；
- **Upear 平台**：基于该框架的多智能体产品化平台——受保护对话链、FSM 多智能体规划、外部智能体桥、安全运营前端（平台后端基于 [HugAgentOS](https://github.com/ZJU-REAL/HugAgentOS) 构建，见[致谢](#-致谢)）。

### 本项目的原创与扩展

平台基座（对话、会话、编排基础设施）来自 HugAgentOS；**以下安全能力为本项目原创设计与实现**：

| 能力 | 说明 |
|---|---|
| 受保护对话链 | 结构防线（毫秒级、零模型调用）→ 语义 Judge（fail-closed）→ 分流，全程审计落账 |
| Tool Security Gateway | capability 签发/原子消费 + 强制回执（HMAC 会签）+ 网关侧独立审计账本 |
| 策略中心 | 补充注入规则层：文件 + 运行时双通道热生效、链式规则（支持工具标签）、版本回滚、人工闸门 |
| AI 辅助规则起草 | LLM 起草 → 服务端确定性校验 → 样本自测 → 人工确认（草稿绝不自动生效） |
| MCP 通道守卫 | 全部 MCP 工具的描述注入扫描 + 策略评估中间件（env 门控默认关） |
| 轨迹链与工具标签 | 跨工具链式规则（名称正则/描述符标签）、被拒重试压力、熵载荷检测 |
| 运行监督 | 步数/循环/输出/预算四类触发 + 重试压力第五触发 → 语义复核 → 人工复核队列 |
| FSM 规划安全守卫 | 规划输入逐条语义验证；LLM 只提案，执行权在确定性编译的代码 |

总体关系：

![Upear 总体架构：Upear Guard 安全层 × 平台基座](figures/upear-overview-zh.svg)

平台分层细节见 [Upear-Backend 仓库 README](https://github.com/JueeeX/Upear-Backend)（含安全增强架构图）。

---

## 安全能力

### 四层安全生命周期模型

```
智能体执行生命周期                SafeHarness 安全层
┌──────────────────┐           ┌─────────────────────────────────────────┐
│ 1. 信息输入       │ ◄─ 守护 ─ │ L1 INFORM — 对抗性上下文过滤              │
│ (Input)          │           │   结构净化 · 模式检测 · 语义过滤 · 溯源标记 │
├──────────────────┤           ├─────────────────────────────────────────┤
│ 2. 决策推理       │ ◄─ 守护 ─ │ L2 VERIFY — 分级安全验证                  │
│ (Decision)       │           │   规则 → LLM 护栏 → 因果诊断              │
├──────────────────┤           ├─────────────────────────────────────────┤
│ 3. 动作执行       │ ◄─ 守护 ─ │ L3 CONSTRAIN — 特权分离工具控制           │
│ (Action)         │           │   风险分级 · 能力令牌 · HMAC 签名验证     │
├──────────────────┤           ├─────────────────────────────────────────┤
│ 4. 状态更新       │ ◄─ 守护 ─ │ L4 CORRECT — 安全回滚与恢复               │
│ (State)          │           │   检查点 · 因果回滚 · 自适应降级/恢复      │
└──────────────────┘           └─────────────────────────────────────────┘
        跨越所有阶段 ◄─ 守护 ─ 跨层：记忆保护 & 熵监控
```

层间不是简单堆叠，而是主动反馈：L1 检出注入会抬高 L2 验证等级；L2 确认攻击触发 L4 回滚与降级；L4 降级同步收紧 L3 权限；连续安全后自适应恢复。

### 威胁模型

| 威胁向量 | 描述 | 主要防御层 |
|---|---|---|
| T1 直接提示注入 | 用户输入中包含对抗性指令 | L1（模式过滤+语义净化） |
| T2 间接提示注入 | 工具返回值 / RAG 内容中嵌入恶意指令 | L1（observation 过滤） |
| T3 工具滥用 | 智能体被诱导调用高风险工具 | L3（权限分级） |
| T4 工具描述篡改 | 攻击者修改工具描述改变智能体行为 | L3（HMAC 签名验证） |
| T5 状态/记忆腐蚀 | 注入虚假历史或修改持久状态 | 跨层记忆保护 |
| T6 权限提升 | 智能体尝试执行超授权操作 | L3（能力令牌+分级） |

### 平台安全机制

- **受保护对话链**：结构防线（正则注入检测 + SQL 形状分类器，毫秒级、零模型调用）→ 语义 Judge（fail-closed，不确定即拦截）→ 分流执行，全程审计落账。
- **Tool Security Gateway**：集中式工具授权网关——capability 签发/验证/原子消费（防重放）、强制回执（agent 侧签名、网关同钥验证）、网关侧独立审计账本。工具执行产生 `capability_issue → capability_inspect → dispatched → succeeded/denied` 四行完整审计闭环。
- **强制回执（Enforcement Receipt）**：本地 runtime 决策 allow 后对 invocation countersign，网关验证签名后才执行；token 永不落入智能体侧审计。
- **审计链与脱敏**：SQLite WAL 审计（16KB 截断、90 天/20 万行轮转），可选脱敏模式——正文键做摘要化（redacted+sha256），敏感键（api_key/token/secret 等）替换为 `[REDACTED]`，攻击原文不落账。
- **运行监督**：步数超限 / 循环检测 / 输出超长 / 预算超支四类触发 → 语义复核（fail-closed）→ 结构化拦截 → 进入人工复核队列，复核结案留痕。
- **通信网关**：租户/智能体身份强制、默认拒绝通信拓扑、有界委托、注水式消息检查、限速与租约投递。

### 内部红队基线（参考）

> 以下为内部 red-team 回归的初步结果，仅说明测试方法有效性与当前防线的相对水位，**不构成任何生产环境安全承诺**。攻击效果判定均经人工复核；裸模型基线受采样方差影响，报区间不报单点。

| 测试集 | 受保护链路 | 裸模型参照 |
|---|---|---|
| 本地注入基线（30 条） | **30/30 防住，ASR 0%** | — |
| 公开攻击套件（104 条） | triage 后 **1.0%** | glm-4 系列 18–26% |
| 外部智能体桥（104×3 框架） | autogen 1.0% / openai-agents 3.9% / smolagents 1.0% | 同上 |

---

## 多智能体规划能力

### FSM 多智能体规划：LLM 提案 + 确定性编译

![FSM 多智能体规划：从任务到受控执行](figures/fsm-planning-zh.svg)

规划权在 LLM，执行权在代码：

1. 用户任务经 SafeHarness 输入检查（逐条语义验证）；
2. **LLM 只提案**——选择能力与顺序；
3. `fsm_builder` **纯代码确定性编译**：依赖扩展、输入绑定、failure 路径、高危动作强制人工审批；
4. `validate_fsm` 校验 + `plan_hash`/`registry_hash` 锁定计划与能力注册表；
5. PlanCard 预览 → **人工确认** → SSE 流式执行，全程可追踪、可审计。

监督者是代码不是模型：计划一旦确认，执行路径不再由模型自由发挥。

### 多智能体调度

- `platform-supervisor`（纯规则调度身份，零 LLM 调用）按消息分类分流：运维诊断 / 知识问答 / 联网搜索 / 通用对话（`main_agent`）；
- 子智能体委派、@ 提及单轮委派、`/` 斜杠命令四段选择（智能体/插件/技能/MCP 工具）。

### 外部智能体桥

统一接入三个主流框架的智能体，**零新增凭据**（统一走平台模型链）：

| 框架 | 形态 |
|---|---|
| AutoGen（Microsoft） | AssistantAgent |
| OpenAI Agents SDK | ReAct Agent |
| smolagents（HuggingFace） | CodeAgent |

每个外部智能体均获得与主链一致的：输入守卫（注入检测 fail-closed）、网关工具（全证明链：本地回执签名 → capability 签发 → 双证明执行）、记忆配置（窗口截取 + mem0 长期记忆读写）、运行监督（四触发 + 语义复核）。运行回执带 `evidence`：步数、记忆状态机、工具调用链 `receipt=verified` 徽章、监督干预警告。

---

## 仓库结构

```
Upear/
├── src/safeharness/            # SafeHarness 安全框架本体（独立 pip 包）
│   ├── policies/               #   输入防线：inform(正则+语义) / sql_guard / constrain(能力门)
│   ├── runtime/                #   会话决策 / 回执 / 审批生命周期 / 审计脱敏
│   ├── backends/               #   SignedCapabilityGateway / 回执 / replay / SQLite 审计
│   ├── gateway/                #   网关客户端与服务端（HTTP）
│   ├── evolution/              #   物化内容闸门 + 语义复查
│   └── adapters/               #   LangGraph 受保护聊天适配器
├── src/harness|safety|attacks|evaluation/   # 论文复现代码（四层实现 / 攻击套件 / 评测指标）
├── Upear UI/                   # 平台前端（React + Vite + TypeScript）
├── examples/
│   ├── langgraph_noc/          #   LangGraph NOC 安全运维 Demo（守卫节点 + 签名能力）
│   └── product_demo/           #   一键五进程产品 Demo（见下）
├── tools/agentprobe/           # 注入攻击扫描套件、结果汇总与 triage 工具
├── deploy/                     # 生产化部署拓扑（PostgreSQL/Redis/Grafana/备份）
├── tests/                      # 框架测试（核心 / 回执 / SQL 守卫 / 受保护桥接）
├── docs/                       # 架构与运维文档（威胁模型 / 网关 / 通信网关 / LLM 配置）
├── config/                     # 实验配置与组件 env 模板
├── run_experiment.py           # 论文实验入口（含消融 / Bootstrap）
├── run_demo.py                 # 论文快速 Demo
└── pyproject.toml              # safeharness 包定义（safeharness-audit 等 CLI）
```

平台后端（受保护对话、FSM 规划编译器、外部智能体桥、审计与复核服务）基于 [HugAgentOS](https://github.com/ZJU-REAL/HugAgentOS) 构建，单独仓库托管。

## 快速开始

### 1. 框架安装

```bash
pip install -r requirements.txt   # 或: pip install -e .
```

模型配置：复制 `config/llm.env.example` 为 `config/llm.env`，填入任意 OpenAI 兼容端点：

```dotenv
SAFEHARNESS_LLM_BASE_URL=https://your-provider.example/v1
SAFEHARNESS_LLM_API_KEY=your-api-key
SAFEHARNESS_LLM_MODEL=your-model-id
SAFEHARNESS_JUDGE_MODEL=your-judge-model-id   # 可选：独立语义 Judge 模型
```

### 2. 框架最小用例

```python
from safeharness import Guard, LangGraphAgent, LangGraphTool

def lookup_alarm(alarm_id: str) -> dict:
    """Look up one alarm."""
    return {"alarm_id": alarm_id, "status": "active"}

tool = LangGraphTool.from_callable(
    lookup_alarm,
    required_capabilities={"alarm:read"},
    resource_parameter="alarm_id",
)

async with Guard(tenant_id="local", agent_id="assistant") as guard:
    graph = guard.attach(LangGraphAgent(model=model, tools=(tool,)))
    result = await graph.ainvoke({"messages": messages})
```

`Guard.attach()` 默认生产安全契约：仅接受覆盖全部生命周期边界的 Adapter，未知智能体**拒绝接入而非静默降级**。

### 3. 论文复现实验

```bash
python run_demo.py                                 # 快速 Demo
python run_experiment.py --subset 200              # 完整实验
python run_experiment.py --ablation                # 消融实验
python run_experiment.py --subset 100 --bootstrap  # Bootstrap 置信区间
```

### 4. 产品 Demo（五进程）

完整平台体验需要同时获取平台后端（Upear-Backend，基于 HugAgentOS 构建）与前端（本仓库 `Upear UI/`）。五进程拓扑：

| 端口 | 进程 |
|---|---|
| 3001 | 平台后端 BFF（uvicorn） |
| 3002 | 前端（Vite） |
| 38200 | 智能体通信网关 |
| 38308 | SafeHarness Admin UI |
| 38310 | Tool Security Gateway |

```powershell
powershell -ExecutionPolicy Bypass -File examples\product_demo\run.ps1
```

登录 `admin / admin123`（本地演示账号）。启动器不读取仓库真实 `.env`，后端从隔离临时目录启动；Demo 攻击场景使用真实 SafeHarness runtime。详细说明见 [examples/product_demo/README.md](examples/product_demo/README.md)。

## 文档

- [威胁模型](docs/threat-model.md)
- [框架工程说明](docs/engineering.md)
- [Tool Security Gateway](docs/tool-security-gateway.md)
- [Agent Communication Gateway](docs/agent-communication-gateway.md)
- [LLM 配置](docs/llm-configuration.md)
- [Admin Console](docs/admin-console.md)
- [提示注入演示指南](docs/prompt-injection-demo-guide.md)
- [后端测试手册](docs/backend-test-manual.md) / [前端测试手册](docs/frontend-test-manual.md)

## 测试

```bash
# 框架全套
python -m pytest --noconftest -q tests/test_core.py tests/test_legacy.py tests/test_sql_guard.py \
  tests/test_plan_judge_contract.py tests/test_protected_chat_bridge.py \
  tests/test_enforcement_receipts.py tests/test_receipt_configuration.py

# 论文代码端到端冒烟（可 mock LLM）
python test_e2e.py
```

---

## 🙏 致谢

本项目站在众多开源项目的肩膀上构建。特别说明：`src/safeharness` 安全框架 **fork 自 SafeHarness 论文（arXiv:2604.13630）的官方实现**，本项目在其上做了生产化改造与大规模扩展（受保护对话链、策略中心、MCP 守卫、运行监督等，见[本项目的原创与扩展](#本项目的原创与扩展)）；架构权利归原论文作者，感谢以下项目与社区的贡献：

| 项目 | 本项目中的用途 |
|---|---|
| [SafeHarness（论文 · arXiv:2604.13630）](https://arxiv.org/abs/2604.13630) | **本框架的架构出处**：`src/safeharness` fork 自其[官方实现](https://github.com/liu-yang-maker/SafeHarness)（四层安全生命周期模型、能力令牌与强制回执、工具网关等），本项目在此之上做了生产化改造与扩展 |
| [HugAgentOS (ZJU-REAL)](https://github.com/ZJU-REAL/HugAgentOS) | 平台后端的基座：多智能体对话、会话与编排基础设施。Upear Guard 平台侧能力（受保护对话链、外部智能体桥、审计复核等）在其上扩展构建 |
| [LangGraph](https://github.com/langchain-ai/langgraph) | 智能体执行框架与受保护图适配（`safeharness/adapters`、`examples/langgraph_noc`） |
| [mem0](https://github.com/mem0ai/mem0) | 外部智能体长期记忆读写 |
| [AutoGen](https://github.com/microsoft/autogen) / [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) / [smolagents](https://github.com/huggingface/smolagents) | 外部智能体桥接的三种执行框架 |
| [AgentProbe](https://www.npmjs.com/package/@alexmelges/agentprobe) | 提示注入攻击套件与红队扫描方法（`tools/agentprobe`） |
| [Agent-SafetyBench](https://github.com/thu-coai/Agent-SafetyBench) | 论文实验评测数据集 |
| [LlamaFirewall](https://github.com/meta-llama/PurpleLlama) | 论文中的基线防御对比 |
| [AgentScope](https://github.com/modelscope/agentscope) | 产品 Demo 运行时依赖 |
| [FastAPI](https://github.com/fastapi/fastapi) / [React](https://github.com/facebook/react) / [Vite](https://github.com/vitejs/vite) | 前后端工程基础设施 |

上述项目均以其自身许可证发布，使用本仓库时请同时遵循各上游项目的许可证条款。

## 许可证

[Apache-2.0](LICENSE)
