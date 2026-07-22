# Project Guardrails

Fill this file during project initialization. Keep only project-specific rules; generic workflow rules live in `.agent/INDEX.md`.

## Required project facts

- Product and users: 本仓库是 Agent Workflow Template 母模板，面向将规则安装到软件项目中的维护者与 AI 编程 Agent。
- Technology and architecture: Python 3.9+ 控制脚本、Markdown/JSON 规则与状态、模板渲染器，以及独立的可选 Node.js pxpipe 插件；`.agent/state/TASK.json` 为任务权威状态，`.agent/state/CONTEXT.json` 为有完整性绑定的有界上下文胶囊。
- Writable and read-only areas: 工作区根目录可写；正常任务只修改需求契约、显式选定的交付物和 `.agent/state` 受控状态。审计任务对实现、模板、技能、策略和插件源文件只读。
- Security, privacy, compliance and performance red lines: 不伪造 provider/human/orchestrator 证明，不绕过测试、环境、预算、完整性或运行时清理门禁；不读取工作区外私密数据；不留下后台进程、端口或容器；不得把 Agent 自签内容提升为外部事实。
- Build, test and lint commands: `python3 .agent/scripts/agentctl.py validate` 做结构校验；`python3 .agent/scripts/self_test_*.py` 运行核心自测；pxpipe 插件仅在其能力被明确选定时运行自己的 Node.js 自测。
- Deployment authority and rollback owner: 模板仓库不授权部署；任何 test/production/deploy 路由必须由配置的 provider-owned 决策适配器和人类负责人批准。模板维护者拥有本地规则变更的回滚责任。

## Universal project constraints

- Start every request with `clarify-task`; no unresolved material decision enters design or implementation.
- AI inference is labeled and never promoted to business fact without approval.
- Use the smallest applicable mode and load only selected Skills/templates.
- Register and clean every local runtime; zero residual state is mandatory.
- Test and production use separate branches, credentials, artifacts, approvals and rollback plans.
- Preserve one current state and one current context capsule; remove superseded drafts and temporary evidence.
