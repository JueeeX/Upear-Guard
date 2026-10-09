# SafeHarness 管理控制台（V1）

safeharness-admin-ui 是一个不依赖前端框架的蓝白 recovery/control console。它默认只监听
127.0.0.1:38308；浏览器只读，服务端 mutation channel 仅代理精确白名单写操作。

界面包含：

- 控制面总览：Agent、隔离、拓扑和委派统计；
- Agent 清单；隔离/恢复按钮只提示前往 SUMC Console；
- 显式允许的通信拓扑与有效委派；
- 可选的只读 SQLite 审计查询。

## 运行

推荐将控制台的全部运行设置放在专用文件中。先复制模板（目标文件已被 Git 忽略）：

~~~powershell
Copy-Item config\admin-ui.env.example config\admin-ui.env
~~~

在 `config/admin-ui.env` 中替换管理员密钥和浏览器访问令牌后，直接启动：

~~~powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m safeharness.admin_ui.server
~~~

默认读取当前工作目录的 `config/admin-ui.env`。也可以指定一个其他路径：

~~~powershell
.\.venv\Scripts\python.exe -m safeharness.admin_ui.server --config C:\secure\safeharness-admin-ui.env
~~~

只允许文件设置 `SAFEHARNESS_ADMIN_UI_*` 变量；它不会执行 shell 内容或展开变量。进程
环境变量优先于文件，方便容器、CI 和密钥管理器覆盖。不要把密钥写入 HTML、JavaScript、
文档或浏览器本地存储。

如果不使用配置文件，仍可由部署方在进程环境中提供以下变量：

~~~powershell
$env:PYTHONPATH = "src"
$env:SAFEHARNESS_ADMIN_UI_UPSTREAM_URL = "https://communication-admin.example"
$env:SAFEHARNESS_ADMIN_UI_ADMIN_KEY = "<coordination admin key>"
$env:SAFEHARNESS_ADMIN_UI_ACCESS_TOKEN = "<at-least-32-character operator session token>"
$env:SAFEHARNESS_ADMIN_UI_MUTATION_KEY = "<at-least-32-character server mutation key>"
$env:SAFEHARNESS_ADMIN_UI_AUDIT_DATABASE = "data\tool-gateway.sqlite3" # optional
.\.venv\Scripts\python.exe -m safeharness.admin_ui.server
~~~

也可以在安装后运行：

~~~powershell
safeharness-admin-ui
~~~

浏览器打开 http://127.0.0.1:38308，输入 SAFEHARNESS_ADMIN_UI_ACCESS_TOKEN。
该令牌只保存在当前标签页的 sessionStorage。协调管理 key 和 mutation key 只保留在
Python 代理/BFF 进程。Recovery console 只读；受控写操作必须经 SUMC Console
完成 re-auth 和一次性审批。

## 安全边界

- 不配置完整 upstream、admin key 和 UI access token 时，页面可以显示但所有管理 API
  都会拒绝；
- 前端只代理白名单操作，不能把它当成通用 HTTP 转发器；
- 隔离、恢复和委派撤销必须在 SUMC Console 完成 re-auth、目标绑定一次性审批和明确 allow；
- 审计接口只使用 SQLiteAuditReader 的只读模式，不初始化、迁移或修改数据库；
- 面向非 loopback 部署时，应在 UI 前放置 TLS 终止、企业 IAM/RBAC 和独立管理网络。
  本 V1 的单一浏览器访问令牌不是企业 IAM 的替代品。
