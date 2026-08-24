# Agent Workflow Template

可安装到任意 Git 项目的通用 `.agent/` 开发工作流。它提供需求澄清、设计、开发、审查、验收、CI、知识治理和安全更新控制，但**不替用户选择技术栈或架构**。

项目地址：`user-growth/agent-workflow-template`。

## 核心原则

1. **用户先设计**：目标、架构、技术选择、能力、约束、验收、项目命令和 Git provider 都由用户输入。
2. **确认后适配**：`.agent/project/BLUEPRINT.json` 未被用户确认前，不允许发现、评分、安装或激活项目 Skill。
3. **Skill 不固化**：内置 Skill 只负责通用控制面；语言、框架、设计、测试、基础设施和业务 Skill 根据当前项目蓝图从 GitHub 动态选择。
4. **发现不等于信任**：外部 Skill 是不可信 prompt/供应链输入。硬门禁先于评分，评分只给合格候选排序。
5. **证据可复现**：安装绑定用户蓝图、policy、推荐报告、完整 40 位 commit、license、文件 SHA-256、CAS bundle 和 exact lock。
6. **迭代只提案**：低质量 Skill 可被提议试用、替换、弃用或退役；不能自动放宽 policy、删验收、合并或部署。

## 能力

- `fast / standard / release` 三级任务状态机
- 用户确认的 project blueprint 和无 shell 的 argv 命令执行
- GitHub Skill 发现、解释评分、锁定、内容级安装、校验、更新、回滚、隔离和退役
- 项目知识 registry、owner 映射、catalog digest 和 changed-path 计划
- GitHub/GitLab Issue、PR/MR 和 CI 模板生成
- 设计 → 开发 → 独立审查 → 验收 → CI → 复盘的证据链
- 上下文预算、子 Agent ledger、本地 runtime 清理、环境交付与 installer migration
- 低敏 outcome 驱动的自我迭代提案

## 安装

```bash
python3 install.py /path/to/project --project-name my-project
cd /path/to/project

# 填写项目 guardrails 后初始化
cp .agent/policies/PROJECT_GUARDRAILS.md project-guardrails.md
# 编辑 project-guardrails.md，只写用户/团队已决定的边界
python3 .agent/scripts/agentctl.py project-init --guardrails-file project-guardrails.md
python3 .agent/scripts/agentctl.py bootstrap-check
```

安装与项目初始化分离。fresh install 显示 `BOOTSTRAP NOT READY` 是预期行为。

## 第一步：由用户填写并确认设计

```bash
python3 .agent/scripts/blueprintctl.py init
# 编辑 .agent/project/BLUEPRINT.json
python3 .agent/scripts/blueprintctl.py check
python3 .agent/scripts/blueprintctl.py confirm \
  --source 'user:已确认目标、架构、技术选择、能力、验收和命令'
```

蓝图从空白开始，不带默认技术栈：

```json
{
  "schema": "agent-project-blueprint/v1",
  "status": "draft",
  "design": {
    "goals": [],
    "architecture": [],
    "technology_choices": [],
    "capabilities": [],
    "constraints": [],
    "acceptance": [],
    "commands": [],
    "providers": []
  },
  "suggestions": [],
  "confirmation": null
}
```

- `technology_choices` 的每项必须包含用户选择和原因，也可以明确选择空列表。
- `capabilities` 是稳定的 `{id, description}`，可由用户明确留空；`acceptance` 是稳定的 `{id, criterion, method?}`，其中 `method` 可为 `executable`、`evidence` 或 `manual`。
- `commands` 是 `{id, argv, stage, timeout_seconds, covers, environment}`；只有 `executable` acceptance 必须被 acceptance/CI 命令完整覆盖。研究、写作、政策、设计等项目可以明确使用 evidence/manual 验收并令 commands 为空。命令使用 `shell=False`、独立进程组和最小环境执行，只有用户列入 `environment` 的变量会从宿主继承。
- `providers` 也是用户设计：GitHub 明确 runner（支持 label 数组）/container，GitLab 明确 image/tags；container/image 必须固定为 `@sha256:<digest>`，模板不替用户固定 CI 环境。
- Agent 可以把仓库观察写成 suggestion 供讨论，但 suggestion 不参与 Skill 匹配，也不能代替用户确认。
- 设计变化时运行 `blueprintctl.py reopen --source 'user:<原因>'`，修改后重新确认；旧 Skill lock 会变 stale。

## 第二步：动态选择 GitHub Skill

在线发现（可选 `GITHUB_TOKEN`，只读且不落盘）：

```bash
python3 .agent/scripts/skillctl.py discover \
  --output .agent/project/skill-candidates.json
```

发现会为每个已确认 capability/technology choice 保留一个确定性 query unit，并按 query 轮询候选仓库，避免前面的热门结果饿死后面的用户选择。如果 bounded search 结果无法在 `--max-repositories` 内覆盖每个 query unit，它会在内容 inspection 前显式失败；如果 GitHub request budget 无法覆盖全部 query 与有界内容检查，则在任何网络请求前失败。两者都不会静默丢弃设计项。

也可以向 `score` 提供用户/组织审核过的离线 `agent-skill-candidates/v1` catalog。catalog 必须绑定 confirmed blueprint、候选集合 SHA-256、时间和 `offline-user-reviewed` provenance；无法验证的仓库维护/trust 元数据只使用中性先验并显示 warning：

```bash
python3 .agent/scripts/skillctl.py score \
  --candidates .agent/project/skill-candidates.json \
  --output .agent/project/skill-recommendation.json
```

默认评分：

`100 × (35% relevance + 15% quality + 15% maintenance + 20% security + 10% trust + 5% license) × (0.70 + 0.30 × evidence confidence)`

其中 relevance **只读取用户确认的设计**。stars 只是 trust 中受限的小信号，不能覆盖相关性、安全和许可证门禁。

安装前先查看候选、hard failures、breakdown、confidence 和 `recommendation_sha256`：

```bash
# 先生成不修改状态的 candidate-specific action（绑定 report、bundle、当前 lock 和 expiry）
python3 .agent/scripts/skillctl.py install \
  --candidates .agent/project/skill-candidates.json \
  --report .agent/project/skill-recommendation.json --candidate <id> \
  --covers-capability <confirmed-capability-id> --plan
# 用户确认完整 payload 后执行；非第一名合格候选需额外 --rationale
python3 .agent/scripts/skillctl.py install \
  --candidates .agent/project/skill-candidates.json \
  --report .agent/project/skill-recommendation.json --candidate <id> \
  --covers-capability <confirmed-capability-id> \
  --source 'user:<decision>' --approve-digest <approval_sha256>
python3 .agent/scripts/skillctl.py verify
```

安全边界：

- 只从 pinned Git tree 读取普通 UTF-8 `SKILL.md` 和 license 文本；
- 拒绝短 SHA、路径逃逸、symlink/gitlink、binary、未知 license、archived repo、超限内容和阻断级危险模式；
- 安装期不 checkout、不运行 hook/script/postinstall、不加载凭据；
- CAS、active 目录和 lock 每次使用前 exact-set 重验；
- Skill/CAS/lock/lifecycle 多文件变更使用共享 mutation lock 和 digest-bound crash journal；中断后运行 `skillctl.py recover` 确定性回滚，未恢复时只读验证 fail closed；
- 系统、组织、项目 guardrails、用户决定始终高于外部 Skill。

## 知识库模板

```bash
python3 .agent/scripts/knowledgectl.py init
# 新增小而权威的 Markdown，并在 .agent/knowledge/registry.json 登记 owner/source_globs
python3 .agent/scripts/knowledgectl.py check
python3 .agent/scripts/knowledgectl.py build          # 仅由维护者显式更新 catalog
python3 .agent/scripts/knowledgectl.py verify-catalog # CI 只读验证，不自动 bless drift
python3 .agent/scripts/knowledgectl.py plan --changed src/example other/path
```

registry 不固化目录或领域；每个项目自行配置。未知 changed path 默认 fail closed。catalog 只生成 hash/索引，不覆盖人工语义。

## Issue/MR/CI 模板

在蓝图中明确选择 `github`、`gitlab` 或两者后生成：

```bash
python3 .agent/scripts/providerctl.py emit --provider gitlab --output-root .
python3 .agent/scripts/providerctl.py emit --provider github --output-root .
python3 .agent/scripts/providerctl.py verify --provider gitlab --output-root .
python3 .agent/scripts/providerctl.py verify --provider github --output-root .
# 上次 emit 被进程/主机中断时，先按 journal 确定性恢复
python3 .agent/scripts/providerctl.py recover
# 已有文件时先生成 exact overwrite action，再批准该 digest
python3 .agent/scripts/providerctl.py emit --provider gitlab --output-root . --force --plan-overwrite
python3 .agent/scripts/providerctl.py emit --provider gitlab --output-root . --force \
  --source 'user:<decision>' --approve-digest <approval_sha256>
```

生成内容包括：

- 用户设计、范围、验收、知识、安全和回滚字段；
- Skill 推荐/lock 证据字段；
- CI 中绑定 exact blueprint digest 的 Skill、只读 knowledge catalog 和可信 Git diff owner 检查；
- 仅由用户蓝图提供的 argv commands 和 CI runner/image/tags；
- `.agent/provider-design/<provider>.json`，逐字段保存完整 authoritative design，并证明 canonical digest 等于确认摘要；
- `.agent/provider-trace/<provider>.json`，绑定完整设计、provider 配置、命令、生成文件、前序 inventory 和 overwrite decision；覆盖已有输出必须先 plan，再通过 human-decision receipt 批准 exact action，verify 会拒绝剥离、拼接或跨 provider 重放决定。emit/plan 使用共享 mutation lock 和稳定的 no-follow 目录 descriptor；现有文件通过原子 exchange 检查实际被替换的 predecessor，缺失文件通过原子 no-replace 提交。每个多文件 emit 在首个 commit 前 fsync digest-bound crash journal；中断后运行 `providerctl.py recover`，只恢复仍属于本事务的字节并保留并发第三方内容。未恢复时 emit/verify fail closed。

模板不会自行加入 npm、Flutter、Gradle、Cargo、Go、数据库、云或任何框架命令。所有用户选择的 YAML runner/image/tag 都以显式字符串序列化，避免 `null`、`true` 等值被 YAML 改型。

## 通用验收权限

`executable` criteria 由蓝图 argv 命令产生证据，并在 receipt verify/release gate 中通过 canonical runner 重新执行；手写 zero-exit JSON 不能代替真实执行。`evidence`/`manual` criteria 由独立 integrator 的 `agent-blueprint-integrator-evidence/v1` 精确覆盖。release node 7 要求最终 live receipt 的 path/SHA-256/bytes 与已验证 selected integrator 的 marker-bound result evidence 完全相同，只有同名 ID 不算权限。`manual` criteria 还必须先运行 `blueprintacceptance.py run ... --plan`，由人批准绑定 blueprint、candidate、Skill lock、preflight、criterion 和 evidence 的 exact digest，再同时提交 `--manual-approve-digest`、`--manual-decision-source 'user:<decision>'` 和 `--manual-decision-receipt`。该 receipt 必须由仓库外、OS 保护的 host/provider adapter 验证；caller 自填 `user:` 文本即使在 local-release route 也会被拒绝。脱离 node 7 ledger binding 的 standalone receipt 不能作为 release 权限。

## 更新、弃用、退役和回滚

更新必须重新评分并批准新的 report：

```bash
python3 .agent/scripts/skillctl.py update \
  --candidates .agent/project/skill-candidates.json \
  --report .agent/project/skill-recommendation.json --candidate <id> \
  --covers-capability <confirmed-capability-id> --plan
python3 .agent/scripts/skillctl.py update \
  --candidates .agent/project/skill-candidates.json \
  --report .agent/project/skill-recommendation.json --candidate <id> \
  --covers-capability <confirmed-capability-id> \
  --source 'user:<decision>' --approve-digest <approval_sha256>
```

生命周期变化先生成只读 approval payload：

```bash
python3 .agent/scripts/skillctl.py plan-lifecycle \
  --action deprecate --id <old> --replacement <active-new> --reason '<reason>'
# 用户确认完整 payload 和 approval_sha256 后：
python3 .agent/scripts/skillctl.py deprecate \
  --id <old> --replacement <active-new> --reason '<reason>' \
  --source 'user:<decision>' --approve-digest <approval_sha256>
```

retire、quarantine 和 rollback 使用相同 plan → exact digest → explicit source 流程。正常 retire 要求先 deprecate 且 active replacement 覆盖全部锁定 requirement；quarantine 是安全撤销，不声称回滚外部副作用。

## 自我迭代

```bash
python3 .agent/scripts/evolutionctl.py record --skill <id> --outcome success \
  --run-id <stable-run-id> --evidence-sha256 <acceptance-evidence-sha256>
python3 .agent/scripts/evolutionctl.py record-workflow --component <control-component> --outcome failure \
  --run-id <stable-run-id> --evidence-sha256 <acceptance-evidence-sha256>
python3 .agent/scripts/evolutionctl.py plan \
  --report .agent/project/skill-recommendation.json \
  --output .agent/project/evolution-plan.json
```

- 最小观察窗不足时不下结论；
- 重复 task/run/evidence observation 被拒绝；每个 evolution action 有独立 digest，apply 一次只批准一个 action，并绑定 plan/report/blueprint/policy/当前 lock/expiry receipt；
- replace/deprecate/retire 都是 digest-bound proposal；
- 正常退役必须先安装、锁定并验证覆盖相同能力的 replacement；
- 安全撤销可 quarantine，但不声称回滚外部不可逆副作用；
- workflow 框架本身仍通过 installer 的 check → dry-run → reviewed update 更新。

```bash
python3 install.py /path/to/project --check
python3 install.py /path/to/project --update --dry-run
python3 install.py /path/to/project --update
```

项目私有的 blueprint、Skill CAS/lock、知识和 outcome 在模板升级中保留。

## 建议版本化的项目证据

为了让 fresh clone/CI 能离线复验，项目应审查后提交：

- 已确认的 `.agent/project/BLUEPRINT.json` 与自定义 `skill-policy.json`；
- 用于批准的 bounded candidate catalog、recommendation report、`skills.lock.json` 和 lock history；
- lock 引用的 `skill-cas/` 及 active `skills/` 精确文件；
- knowledge registry、人工 Markdown 和生成 catalog；
- provider 模板以及团队选择共享的 lifecycle/outcome 证据。

不得提交 `GITHUB_TOKEN`、其他凭据、未经检查的额外脚本/Hook、或供应链工具缓存。外部候选内容即使被提交，仍是低权限数据而不是项目规则。

## 任务模式

| 模式 | 场景 | Token 上限 | 子 Agent | 测试时间 |
|---|---|---:|---:|---:|
| `fast` | 微型、隔离、可逆 | 16k | 0 | 5 分钟 |
| `standard` | 常规功能、Bug、重构 | 48k | 0–1 | 15 分钟 |
| `release` | 跨系统、数据、安全、迁移、部署 | 96k | ≤2 | 45 分钟 |

范围或风险上升时只能 escalate，不能为绕过 gate 降级。

## 目录

```text
.agent/
├── INDEX.md
├── config.json
├── scripts/                  # control plane + blueprint/skill/knowledge/provider/evolution CLI
├── skills/                   # first-party generic control Skills
├── project/                  # project-private blueprint, dynamic Skill CAS/lock/outcomes
├── workflows/
├── templates/
├── capabilities/
├── policies/
├── state/
├── knowledge/                # project-private topics; only INDEX scaffold is managed
└── assets/                   # fresh state, schemas, default stack-neutral policy
```

## 验证

```bash
python3 .agent/scripts/self_test_adaptive_workflow.py
python3 tests/run_all.py --test-timeout 600
python3 tests/run_all.py --full --test-timeout 600
```

测试完全离线覆盖未确认拒绝、任意用户技术选择、公平 query coverage、评分、恶意候选、伪造 manual/zero-exit approval、commit/file lock、tamper、gitlink 知识 owner、provider 并发事务、双 provider CI 和 evolution proposal。

## 要求与限制

- Python 3.9+
- 在线 GitHub discovery 受 GitHub REST 限流；无 Token 时应使用小预算 discovery、组织 catalog 或已批准离线 CAS
- 自动评分不能可靠证明 prompt 无恶意、脚本所有行为、license 法律兼容、维护者未失陷或未来质量
- 本模板不自动 merge、生产部署、修改保护规则或执行第三方 Skill 代码
