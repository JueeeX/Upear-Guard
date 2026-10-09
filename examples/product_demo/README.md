# Upear 离线产品 Demo

面向技术评审。真实链路为：

```text
Upear UI -> SUMC BFF -> SafeHarness Admin UI
  -> Agent Communication Gateway -> SQLite coordination state
```

NOC Agent 和外部系统为模拟组件；攻击场景使用真实 SafeHarness/LangGraph
runtime 与脚本模型。结果只证明 Alpha/reference 本地边界，不证明真实模型安全效果、
生产 Gateway 验收或 production readiness。

Demo 产品名为 `Upear`（智能管控中枢预览版），登录页和主界面首次打开默认使用中文；
用户主动切换后的语言偏好仍保存在浏览器本地。

## 前置条件

- Windows PowerShell。
- 根目录 `.venv` 已安装 Upear Demo 依赖。
- Python 3.11+ 可创建虚拟环境。
- Node.js、`npm.cmd` 和 `Upear UI/node_modules` 已存在。
- `38200`、`38308`、`3001`、`3002` 端口空闲。

启动器首次在 `%LOCALAPPDATA%\SUMC\product-demo\venv` 创建专用环境并安装 SafeHarness、
SUMC 及 `agentscope==2.0.0` 等声明依赖；依赖文件哈希未变化时直接复用。安装失败会在启动服务前退出。

启动器不读取仓库真实 `.env`：后端从隔离临时目录启动并设置
`PYTHON_DOTENV_DISABLED=1`；Demo Vite 配置使用 `envDir: false`。

## 一键启动

在 `F:\AgentSecurity\Upear` 运行：

```powershell
powershell -ExecutionPolicy Bypass -File examples\product_demo\run.ps1
```

启动器依次执行：

1. 四个确定性注入防护场景。
2. 父仓 Admin UI、coordination、protected-chat bridge 聚焦测试。
3. SUMC capability、mutation、bootstrap 聚焦测试。
4. 前端 SafeHarness 契约检查。
5. 隔离身份初始化和四层服务启动。

预期验证结果：4 个攻击场景 `PASS`、父仓 `20 passed`、SUMC `62 passed`、
`npm.cmd run check:safeharness` 成功；随后依次看到 `gateway`、`admin-ui`、`backend`、
`frontend` readiness。任一端口占用或依赖缺失都会 fail-fast，不自动换端口。

全部就绪后自动打开 `http://127.0.0.1:3002`。登录账号为 `admin`，密码为 `admin123`；
密码也用于受控 mutation 的 re-auth。浏览器不获得 coordination admin key、mutation
key 或数据库凭据。

## 界面边界

- `http://127.0.0.1:3002` 是 `Upear` 主界面；普通工作台与仅 `super_admin`
  可用的“安全运营”管理模块共用同一 shell。
- `http://127.0.0.1:38308` 是 SafeHarness loopback recovery console，仅供本机恢复和
  诊断，不是面向用户的独立管理产品，也不向浏览器发放其 UI token。
- 当前没有独立、完整的管理者门户；`/admin` 和 `/config` 商业管理台源码不在本 CE 树中。

## 现场演示

### 1. 认证与总览

1. 使用 `admin` / `admin123` 登录。
2. 打开左侧“安全运营”。
3. 确认总览包含 `noc-supervisor-agent`、`noc-diagnosis-agent`、允许拓扑和有效委派。

数据通过 UI、BFF、Admin UI、coordination HTTP 链路读取，不是前端静态假数据。

### 2. 策略与能力边界

1. 打开“策略中心”。
2. 查看 `safeharness.default.v1` 和 `safeharness.mutations.v1`。
3. 运行 deterministic read-only simulation。
4. 确认候选 diff、publish、rollback 为 unavailable。
5. 在能力中心确认 `internet_search` 为 `approval_required`、
   `production_ready=false`；不要执行联网搜索。

protected chat 保持 disabled：离线 Demo 没有伪造 main-agent 模型配置。

### 3. Fail-closed re-auth

1. 在 Agent 页选择隔离 `noc-diagnosis-agent`。
2. 输入错误密码并提交。
3. 预期返回 `safeharness_reauth_failed`；Agent 仍为 active。

### 4. 一次性审批、隔离与恢复

1. 再次选择隔离，输入正确密码 `admin123`。
2. 第一次操作 prepare mutation。
3. 第二次明确点击“允许并执行”。
4. 确认 Agent 进入 quarantine，并显示签名 coordination mutation log receipt reference。
5. 对同一 Agent 执行恢复，重复 re-auth 和 one-shot allow，确认状态恢复 active。

receipt 是 Alpha coordination mutation log 引用，不是 Tool Gateway receipt，也不是最终
执行结果的不可变生产审计。approval 绑定 operator、tenant、target 和 idempotency digest；
重复或错配审批不会再次执行。

## 停止与复核

在启动终端按 `Ctrl+C`。脚本只停止本轮记录的四个子进程，不删除运行数据。日志和
SQLite 文件保留在终端打印的 `%TEMP%\safeharness-demo\<run-id>`。

确认不再需要后，先核对完整路径确属本轮运行目录，再显式删除：

```powershell
$demoRun = 'C:\Users\<user>\AppData\Local\Temp\safeharness-demo\<exact-run-id>'
Resolve-Path -LiteralPath $demoRun
Remove-Item -LiteralPath $demoRun -Recurse
```

禁止对 `%TEMP%`、`safeharness-demo` 根目录或通配路径执行递归删除。

## 故障排查

- `Required demo port ... is already in use`：停止占用固定端口的进程后重试。
- Python import 失败：使用当前仓库既有环境补齐依赖；启动器不会自动安装或改环境。
- 服务 readiness 超时：查看本轮运行目录 `logs/*.err.log`。
- `/login` 空白或不停刷新：确认使用 Demo Vite 配置，并检查启动输出包含
  `Backend login form ready: http://127.0.0.1:3002/login`。
- UI 显示 unavailable：先确认 `gateway`、`admin-ui`、`backend` 三个进程仍存活。
- 不要通过启用真实模型、读取 `.env` 或弱化 fail-closed 校验绕过失败。
