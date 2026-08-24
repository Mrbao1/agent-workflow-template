# Agent Workflow Template

可复用的 AI Coding 工作流模板。通过 `install.py` 一键安装到任意项目，提供结构化的任务管理、上下文预算控制、Agent 编排和验收流程。

## 这是什么

一个 `.agent` 规则集模板，为 AI 辅助开发提供开箱即用的工作流骨架：

- **任务驱动** — 每个任务从需求澄清开始，经过设计、实现、审查到验收
- **三级模式** — `fast`（小修小改）、`standard`（常规功能/Bug）、`release`（跨系统、数据、安全、部署）
- **Token 预算** — 统一追踪 root 用量、引用开销和子 Agent 消耗
- **Agent 编排** — 子 Agent 的 payload、身份、审查链全程受控
- **上下文管理** — 上下文 checkpoint 绑定策略摘要，策略漂移自动失效
- **运行时清理** — 本地 server、容器、浏览器等资源生命周期管理
- **证据留存** — 可验证的 hash 链式证据归档

## 快速开始

```bash
# 安装到新项目
python3 install.py /path/to/project --project-name my-project
cd /path/to/project

# 完成 guardrails 文档后初始化
cp .agent/policies/PROJECT_GUARDRAILS.md project-guardrails.md
# 编辑 project-guardrails.md，填写产品、用户、技术栈、安全红线等信息
python3 .agent/scripts/agentctl.py project-init --guardrails-file project-guardrails.md

# 验证并开始第一个任务
python3 .agent/scripts/agentctl.py validate
python3 .agent/scripts/agentctl.py bootstrap-check
python3 .agent/scripts/agentctl.py start --title '第一个需求' --mode auto
```

新安装的项目会显示 `BOOTSTRAP NOT READY`，这是预期行为——必须先通过 `project-init` 完成 guardrails 绑定。

## 三种工作模式

| 模式 | 场景 | Token 上限 | 子 Agent | 测试时间 |
|------|------|-----------|---------|---------|
| `fast` | 文案修改、常量调整、微型修复 | 12k | 0 | 5 分钟 |
| `standard` | 常规功能、Bug、重构 | 24k | 0-1 | 15 分钟 |
| `release` | 跨系统、数据、安全、部署 | 48k | ≤2 | 45 分钟 |

当范围、可逆性、数据风险或不确定性超出当前模式时，应向上 escalate。永远不要为了绕过 gate 而降级。

## 更新工作流

```bash
# 检查更新
python3 install.py /path/to/project --check

# 预览更新
python3 install.py /path/to/project --update --dry-run

# 执行更新
python3 install.py /path/to/project --update
```

更新会保留项目的私有状态（config、task、context、证据），只升级 managed 部分。

## 项目结构

```
.agent/
├── INDEX.md              # 编排入口
├── config.json            # 路由配置、模式定义
├── scripts/               # agentctl, workflowctl, evidencectl 等
├── skills/                # 按需加载的 Skill
├── workflows/             # 工作流定义和质量门
├── templates/             # 模式专用模板
├── capabilities/          # 可选能力注册
├── policies/              # 项目 guardrails（用户填写）
├── state/                 # TASK, CONTEXT, agents, evidence 等
├── knowledge/             # 人工沉淀的知识
└── assets/                # fresh-state 种子数据
```

## 可选插件

### pxpipe-context

提供 Codex Local 的请求上下文压缩能力（通过 loopback proxy），以及可选的冷文件 MCP 辅助。详见 `plugins/pxpipe-context/`。

## 清理

每次工作结束后：

```bash
python3 .agent/scripts/agentctl.py cleanup
python3 .agent/scripts/agentctl.py assert-clean
```

## 要求

Python 3.9+
