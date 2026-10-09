# Upear 后端测试手册

本手册面向后端开发、集成测试和故障定位人员。所有命令使用 Windows PowerShell，项目完整目录是 `F:\AgentSecurity\Upear`。

## 1. 后端边界

项目包含两个测试入口：

- 根目录 SafeHarness runtime、Gateway、Admin UI、适配器和通信控制面。
- `SUMC` 目录中的 BFF、数据库、Agent API、模型 API、FSM 编排和 SafeHarness 路由。

`F:\AgentSecurity\SafeHarness` 是残留旧 checkout，本手册不以它作为当前项目根目录。

后端测试必须区分：

- 确定性离线安全行为。
- API/BFF 合约。
- 真实模型 Live E2E。
- 生产部署验收。

前三者均不能自动推出第四者成立。

## 2. 一键 Demo 启动和停止

```powershell
Set-Location F:\AgentSecurity\Upear
powershell -ExecutionPolicy Bypass -File examples\product_demo\run.ps1
```

脚本会依次执行：

1. `examples.langgraph_noc.security_demo --scenario all`。
2. 父仓聚焦测试：`test_protected_chat_bridge.py`、`test_admin_ui.py`、`test_coordination_admin_http.py`。
3. SUMC 聚焦测试：`test_safeharness_capability_contract.py`、`test_safeharness_application_mutations.py`、`test_safeharness_bootstrap.py`。
4. `npm.cmd run check:safeharness`。
5. Gateway、SafeHarness Admin UI、SUMC BFF、Upear UI readiness 检查。

当前脚本中的测试数量标签可能与实际依赖版本或测试收集结果变化；以 pytest 实际输出为准，不要硬编码历史数量。

就绪地址和账号：

```text
UI: http://127.0.0.1:3002
Backend health: http://127.0.0.1:3001/live
Gateway health: http://127.0.0.1:38200/health
Admin UI overview: http://127.0.0.1:38308/api/overview
账号：admin
密码：admin123
```

按 `Ctrl+C` 停止。运行目录、日志和 SQLite 文件保留。

## 3. 环境检查

```powershell
Set-Location F:\AgentSecurity\Upear
python --version
node --version
npm.cmd --version
Test-Path .venv\Scripts\python.exe
Test-Path 'Upear UI\node_modules'
```

若使用启动器，根 `.venv`、Node 和前端依赖必须已存在。启动器会在 `%LOCALAPPDATA%\SUMC\product-demo\venv` 准备隔离 Demo 环境。

## 4. 确定性 SafeHarness 场景

不需要真实模型、URL 或 API key：

```powershell
Set-Location F:\AgentSecurity\Upear
$env:PYTHONPATH = "$PWD\src;$PWD"
python -m examples.langgraph_noc.security_demo --scenario all
```

预期包含四个场景：

```text
input-injection
nested-tool-result
restored-tool-call
restored-history
```

每个场景必须是 `PASS`。失败时检查：

- 输入阻断后模型调用数是否为 0。
- 恶意工具调用是否在执行前被清除。
- 恶意工具结果是否进入模型上下文。
- 恢复历史是否被重新检查。
- attachment report 是否显示 LangGraph adapter 和 checkpoint enforce。
- 输出是否泄露原始攻击文本、工具结果、key 或 capability token。

生成脱敏 JSON 报告：

```powershell
python -m examples.langgraph_noc.security_demo `
  --scenario all `
  --json-output "$env:TEMP\safeharness-security-report.json"
Get-Content "$env:TEMP\safeharness-security-report.json" -Raw
```

只允许查看脱敏报告；不要把包含密钥或完整 payload 的本地文件上传或提交。

## 5. 根仓测试

运行全部根测试：

```powershell
Set-Location F:\AgentSecurity\Upear
$env:PYTHONPATH = "$PWD\src;$PWD"
python -m pytest tests -q
```

先运行一键脚本使用的聚焦测试：

```powershell
python -m pytest `
  tests\test_protected_chat_bridge.py `
  tests\test_admin_ui.py `
  tests\test_coordination_admin_http.py -q
```

按功能运行：

```powershell
python -m pytest tests\test_guard_facade.py tests\test_enforcement_receipts.py -q
python -m pytest tests\test_langgraph_adapter.py tests\test_langgraph_integration.py -q
python -m pytest tests\test_agent_communication.py tests\test_communication_gateway.py -q
python -m pytest tests\test_sqlite_backends.py tests\test_production_backends.py -q
```

## 6. SUMC 后端测试

### 6.1 聚焦 SafeHarness 合约

```powershell
Set-Location F:\AgentSecurity\Upear\SUMC
$env:DATABASE_URL = 'sqlite:///:memory:'
$env:PYTHONPATH = 'F:\AgentSecurity\Upear\SUMC\src\backend;F:\AgentSecurity\Upear\src;F:\AgentSecurity\Upear'
$env:PYTHON_DOTENV_DISABLED = '1'

python -m pytest `
  src\backend\tests\test_safeharness_capability_contract.py `
  src\backend\tests\test_safeharness_application_mutations.py `
  src\backend\tests\test_safeharness_bootstrap.py -q
```

### 6.2 全部 SUMC 测试

```powershell
python -m pytest src\backend\tests -q
```

若环境使用启动器创建的 Demo Python：

```powershell
$demoPython = Join-Path $env:LOCALAPPDATA 'SUMC\product-demo\venv\Scripts\python.exe'
& $demoPython -m pytest src\backend\tests -q
```

### 6.3 相关功能测试

```powershell
python -m pytest `
  src\backend\tests\test_add_agent_permission.py `
  src\backend\tests\test_ce_agent_visibility.py `
  src\backend\tests\test_user_agent_resources.py -q

python -m pytest `
  src\backend\tests\test_safeharness_dispatch.py `
  src\backend\tests\test_safeharness_capability_read_model.py -q
```

## 7. API 健康和认证检查

启动 Demo 后，未认证请求必须被拒绝：

```powershell
try {
  Invoke-WebRequest 'http://127.0.0.1:3001/v1/safeharness/overview' -UseBasicParsing
} catch {
  [int]$_.Exception.Response.StatusCode
}
```

预期输出：

```text
401
```

不要从启动日志中复制内部 key。浏览器登录后由 session cookie 完成 BFF 认证。

策略查询和模拟应通过同源 BFF 或已认证浏览器执行。后端接口语义：

```text
GET  /v1/safeharness/overview
GET  /v1/safeharness/audit
GET  /v1/safeharness/policies
POST /v1/safeharness/policies/simulate
POST /v1/safeharness/mutations
POST /v1/safeharness/mutations/{approval_id}/decision
```

策略模拟请求体示例：

```json
{
  "schema_version": "1.0",
  "package_id": "safeharness.default.v1",
  "operation": "internet_search"
}
```

后端必须返回 `deterministic_read_only`，不能执行工具或写入控制面。

## 8. AgentCard 和 FSM 合约测试

当前 AgentCard 由 `SUMC/src/backend/orchestration/subagents/fsm_contracts.py` 定义，版本为 `agent-card.v1`。AgentCard 在用户 Agent 中的存储位置是：

```text
extra_config.agent_card
```

合法最小样例：

```json
{
  "schema_version": "agent-card.v1",
  "agent_id": "alarm-agent",
  "runtime": "langgraph",
  "capabilities": [
    {
      "capability_id": "alarm.read",
      "description": "读取告警摘要",
      "input_schema": {"type": "object"},
      "output_schema": {"type": "object"},
      "required_capabilities": [],
      "risk_level": "low",
      "side_effects": [],
      "reversibility": "read_only",
      "idempotent": true,
      "timeout_seconds": 30,
      "max_retries": 1,
      "outcomes": ["success", "denied"]
    }
  ]
}
```

必须拒绝或脱敏：

```json
{
  "api_key": "secret",
  "endpoint": "https://internal.example",
  "handler": "internal_handler",
  "system_prompt": "private prompt",
  "token": "secret-token"
}
```

重点检查：

- schema version 不正确。
- capability ID 重复。
- risk level 不在 `low/medium/high/critical`。
- reversibility 不在允许枚举。
- timeout 不在 `1..3600`。
- max retries 不在 `0..5`。
- 数组、对象、字符串超过大小限制。
- FSM state 引用不存在的 Agent 或 capability。
- FSM transition 超过限制。

推荐直接运行现有合约测试，而不是在终端手写内部对象：

```powershell
Set-Location F:\AgentSecurity\Upear\SUMC
$env:PYTHONPATH = 'F:\AgentSecurity\Upear\SUMC\src\backend;F:\AgentSecurity\Upear\src;F:\AgentSecurity\Upear'
python -m pytest src\backend\tests\test_safeharness_capability_contract.py -q
```

## 9. 受控 mutation 测试

必须验证以下顺序：

1. 正确租户和操作员。
2. re-auth 成功。
3. prepare mutation。
4. 一次性审批 allow 或 deny。
5. 幂等键一致。
6. 后端生成并校验 receipt。
7. 重复、错配、过期请求被拒绝。

运行：

```powershell
Set-Location F:\AgentSecurity\Upear\SUMC
python -m pytest src\backend\tests\test_safeharness_application_mutations.py -q
```

预期错误语义：

| 情况 | 预期 code/status |
|---|---|
| 未认证 | `401` |
| 租户不匹配 | `safeharness_cross_tenant` / `403` |
| re-auth 失败 | `safeharness_reauth_failed` / `403` |
| 幂等键冲突 | `safeharness_idempotency_conflict` / `409` |
| 审批缺失或过期 | `safeharness_approval_unavailable` / `410` |
| 已在处理中 | `safeharness_mutation_conflict` / `409` |
| 结果不确定 | `safeharness_mutation_indeterminate` / `409` 或 `503` |

不允许把 indeterminate 当成成功，也不允许自动重试未知结果。

## 10. 真实模型配置和 Live E2E

先在前端“设置 -> 模型服务”配置，或在专用测试环境通过后端配置。API key 不要写入 PowerShell 命令、测试文本、日志或文档。

必须填写部署真实上下文窗口：

```text
ModelProvider.extra_config.context_length = 实际部署支持的上下文窗口
```

不要使用猜测值。模型连通性测试成功后，再执行：

1. 普通聊天。
2. 规划任务。
3. FSM 合法结构生成。
4. FSM 非法结构拒绝。
5. 输入注入阻断。
6. 需要审批后继续。
7. 拒绝审批。
8. 新 SQLAlchemy session 下恢复/重放。

Live E2E 通过的含义是“本次部署、模型、配置和输入下观察到预期结果”，不代表生产安全验收。需要单独记录模型名、部署版本、上下文窗口、时间、测试输入摘要、reason code 和脱敏 trace ID。

## 11. 前端合约和构建检查

```powershell
Set-Location 'F:\AgentSecurity\Upear\Upear UI'
npm.cmd run check:i18n
npm.cmd run check:fsm-graph
npm.cmd run check:safeharness
npx tsc -b --pretty false
npm.cmd run build
```

这些检查不能代替后端 pytest；两者都通过才可称为本地集成检查通过。

## 12. 故障定位顺序

按以下顺序缩小范围：

1. 端口和进程是否存在。
2. Gateway `/health`。
3. Admin UI `/api/overview`。
4. BFF `/live` 和 session 认证。
5. 数据库/SQLite 路径和 schema。
6. SafeHarness route、策略和审计响应。
7. AgentCard/FSM 合约校验。
8. 模型服务连通性和 context length。
9. SSE 事件是否完整。
10. 前端错误映射和渲染。

日志位置由启动器最后输出的 run directory 决定：

```powershell
Get-ChildItem 'C:\Users\<用户名>\AppData\Local\Temp\sumc-demo' -Recurse -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 30 FullName
```

不要先修改 SafeHarness 判定阈值来“修复”规划失败。先根据 `reason_code` 区分安全阻断、Judge 不可用、模型 JSON 错误、FSM 校验错误和服务故障。

## 13. 前端化配置中心边界

当前已可前端编辑：

- 用户级 Agent 基础字段。
- `extra_config` 中的安全、非敏感配置。
- 模型服务配置和连通性测试。
- 用户级能力、插件和服务配置。

当前只读：

- SafeHarness runtime 状态。
- policy package 当前版本。
- audit receipt、Gateway health、coordination snapshot。
- production readiness。

### 测试中心接口

```text
GET  /v1/safeharness/test-scenarios
POST /v1/safeharness/test-runs
GET  /v1/safeharness/test-runs/{run_id}
GET  /v1/safeharness/test-runs/{run_id}/events
```

`POST /test-runs` 的 `scenario_id` 可填 `all`、`input-injection`、`nested-tool-result`、`restored-tool-call` 或 `restored-history`。后端使用确定性 SafeHarness 适配器，结果只返回场景名、阻断阶段、通过状态和有限 evidence；不返回原始输入、密钥、完整提示词或模型上下文。

禁止前端编辑或返回：

- API key、mutation key、admin key、signing key、数据库凭据。
- Judge 逻辑和 fail-closed 阈值。
- 内部 handler、endpoint、系统提示词和部署控制。

已实现配置流程：

```text
前端草稿 -> 后端 schema/安全校验 -> Diff -> 权限审批 -> 发布 -> 版本审计 -> 可回滚
```

当前配置中心只发布用户 Agent 的 `agent_card` 和 `planning` 两个命名空间。`agent_card` 复用 `normalize_agent_card`；planning 只允许 `enabled`、`mode`、`max_retries`、`approval_required` 和 `fsm`，存在 FSM 时复用 `normalize_fsm`。后端检查敏感字段、Agent 所属用户、`base_version`、审批状态和发布前版本冲突。能力目录、插件、MCP 和生产策略仍保持只读或走已有 SafeHarness 受控 mutation。

### 配置中心接口

```text
GET  /v1/config-center/catalog
GET  /v1/config-center/state
POST /v1/config-center/validate
POST /v1/config-center/drafts
GET  /v1/config-center/drafts/{draft_id}
POST /v1/config-center/drafts/{draft_id}/submit
POST /v1/config-center/drafts/{draft_id}/approve
POST /v1/config-center/drafts/{draft_id}/publish
GET  /v1/config-center/history
POST /v1/config-center/rollback?version_id={version_id}
```

## 14. 测试结论模板

```text
测试时间：
测试人员：
代码版本：
Python/Node 版本：
运行目录：
测试命令：
场景：
预期：
实际：
reason_code：
model_calls：
tool_calls：
trace/correlation ID：
日志路径：
结论：PASS / FAIL / UNKNOWN
```

任何缺少关键证据的结果都标记为 `UNKNOWN`，不要用“看起来正常”替代测试通过。
