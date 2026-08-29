# Agent Workflow Template

可安装到任意 Git 项目的通用 `.agent/` 开发工作流。它提供需求澄清、设计、开发、审查、验收、CI、知识治理和安全更新控制，但**不替用户选择技术栈或架构**。

权威仓库：[GitLab `user-growth/agent-workflow-template`](https://git.kuainiujinke.com/user-growth/agent-workflow-template)；[GitHub `Mrbao1/agent-workflow-template`](https://github.com/Mrbao1/agent-workflow-template) 是同 SHA 镜像。发布时先验证 GitLab `main`，再把同一 commit/tag 推送到 GitHub；禁止在镜像上产生独立提交、强推或只在单侧发布。

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

## 支持矩阵

| 边界 | 支持状态 |
|---|---|
| Python | CPython 3.9–3.13；只使用标准库 |
| 操作系统 | Linux、macOS；依赖 POSIX `fcntl`、进程组、文件 mode 和原子 rename |
| Windows | 原生 Windows 不支持并在前置检查中失败；WSL2 按 Linux 语义使用 |
| Provider / Git host | 保持空值或记录任意用户确认的 provider；GitHub/GitLab 仅是内置生成器，不是封闭枚举 |
| 技术栈/模型 | 无默认语言、框架、云、数据库或模型；以用户/host 已确认配置为准 |
| CI | GitHub/GitLab 有可选内置 emitter；任意其他 confirmed provider 生成 content-only contract，不猜测其语法。runner/platform/image/tags 由用户提供，容器镜像固定 digest |

可选 `pxpipe-context` 因缺少可复现的上游 commit/tree/lock/toolchain 证明和完整 transitive-license 清单而处于 **quarantined**：不透明的历史 runtime/proxy bundle 已删除，它不在 marketplace，installer/MCP fail closed，也不影响通用工作流。未来激活只接受绑定 version/migration、managed hash+mode、双 bootstrap、verified plugin map 与唯一 marketplace entry 的精确安装锚；退役兼容发布过的 v3/v4/v5 manifest metadata，并额外固定发布版 helper digest 对，任何 disabled、漂移或非真实 `plugins/pxpipe-context` 路径都拒绝。升级到默认 native 时，仅在旧 plugin tree 与 marketplace entry 都被精确证明为安装器所有时才删除并归档私有 retirement receipt；缺失、漂移或未归属状态一律保留并阻止升级。只有完成 v4 可复现重建、许可证清单和独立审查后才能重新发布。

## 安装

```bash
python3 install.py /path/to/project --project-name my-project
cd /path/to/project

# 填写项目 guardrails 后初始化
cp .agent/policies/PROJECT_GUARDRAILS.md project-guardrails.md
# 编辑 project-guardrails.md，只写用户/团队已决定的边界
python3 .agent/scripts/agentctl.py project-init \
  --guardrails-file project-guardrails.md
python3 .agent/scripts/agentctl.py bootstrap-check
# 每个任务启动时显式选择，不持久化 idle 默认值
python3 .agent/scripts/agentctl.py start --mode standard --model '<user-selected-provider/model-id>' --title '<task>'
```

安装与项目初始化分离。为使 POSIX rename/unlink 事务不受非协作用户的 namespace race 影响，目标父目录必须预先创建；该父目录和已有目标根必须归当前有效用户所有，且不得允许 group/other 写入；managed source 与已有私有 `.agent` 树也必须由当前用户或 root 持有且不可由 group/other 写。受信目录内的每个事务父路径都会逐段 `O_NOFOLLOW` 打开并复核。fresh seed 的 model 是 `null`，不会暗选模型或把占位符变成可调度 ID；`null` 在未开始任务的已初始化项目中仍然合法。idle/accepted 状态的 config 与 Agent ledger 必须保持 model 为 `null`；每次 `agentctl.py start --model <provider/model-id>` 都显式选择并原子绑定该 task generation，完成后只把模型保留在 terminal evidence，并清空 idle authority。`--default-model` 与 `select-model` 都会 fail closed。fresh install 显示 `BOOTSTRAP NOT READY` 是预期行为。


安全卸载只删除 manifest 精确拥有且未漂移的字节，保留 `.agent/state`、`.agent/project`、配置、未知私有文件和 bootstrap 区块外内容：

```bash
python3 install.py /path/to/project --uninstall
```

卸载复用独占 publication lock 与 descriptor-bound transaction journal；崩溃后重跑同一命令收敛，owned byte 漂移时不做部分删除。

## 第一步：由用户填写并确认设计

```bash
python3 .agent/scripts/blueprintctl.py init
# 编辑 .agent/project/BLUEPRINT.json
python3 .agent/scripts/blueprintctl.py check
python3 .agent/scripts/blueprintctl.py confirm \
  --source 'user:已确认目标、架构、技术选择、能力、验收和命令' \
  --human-decision-receipt .agent/state/evidence/<provider-receipt>.json
```

`confirm/reopen` 是权威状态变化，必须先由 host/operator 在仓库外配置 `.agent/config.json → agent_control.human_decision_observer.signed_adapter`。adapter 必须是绝对、canonical、仓库外、OS 管理且当前 Agent 不可写的专用可执行文件；旁边还必须有同样受保护的 `<adapter>.agent-workflow-adapter.json`，以 `agent-provider-adapter/v1` 精确绑定 executable SHA-256、`provider-verifiable-agent-control` purpose 和该 consumer 需要的 exact operation（human decision、scheduler、usage、host compaction、provider preflight 或 platform snapshot），防止把通用 shell/interpreter 冒充 adapter。默认值为 `null`，因此未接入可信 host 时确认会明确 fail closed；`user:*` 文本或 caller 自制 JSON 只算 advisory，不能授权。adapter/receipt 协议见 `.agent/scripts/humandecision.py`。每份 provider receipt 还绑定 canonical 绝对项目根、project/guardrail identity 与稳定 task generation；跨 checkout、跨项目或 task 变更后的 A/B 重放会被拒绝。可选 host scheduler 必须由 operator 在任务开始前同时配置 `agent_control.scheduler.signed_adapter`、`provider_project_id` 与 `provider_repository_id`（三者要么全部为 `null`，要么全部存在），随后通过 provider-approved `contextctl.py repair/approve-repair` 重新绑定 policy capsule；scheduler receipt 必须逐字匹配这两个 trusted ID 和当前 `task_generation_id`，不能从调用者环境或 receipt 自身反向建立信任。同一 receipt 只允许在完全相同的 project/task/gate/artifact/source/routing binding 上做确定性 revalidation（这是显式的 bounded reuse，不是可转移 bearer token）。安装器只在旧 authority 尚无当前 provider policy 或稳定 generation identity 时归档并撤销 gate authority；已处于当前 policy、具备合法 generation ID 的同版本/idempotent 更新原样保留可复验 authority。伪造 migration version 不能升级旧 authority，未知/非 `1` 的当前 policy 直接 fail closed。

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
- `providers` 也是用户设计：可为空；GitHub 明确 Linux/macOS POSIX runner（支持含显式 OS label 的数组）、default branch 与 container；GitLab 必须明确 `platform: linux|macos`、image/tags，macOS 禁止 container image。container/image 必须是小写 canonical digest reference（包括 `node@sha256:<digest>` 这种 registry shorthand，不接受 tag、大写 digest 或非规范形式）；其他 provider 使用有界的 `id/kind/configuration` 用户确认记录。configuration 只允许非敏感公开元数据，token/secret/password/auth/private-key 类设置必须由运行时 secret 注入。GitHub/GitLab 使用专用 emitter；其他 provider 只生成中性的 content-only contract（用户确认的公开配置、命令与验收覆盖），不猜测 provider 文件名、语法或执行语义。若需要 provider-specific 语法或集成能力，必须先把它建模为显式 capability，再选择并审核能够覆盖它的 Skill/生成器。
- Agent 可以把仓库观察写成 suggestion 供讨论，但 suggestion 不参与 Skill 匹配，也不能代替用户确认。
- 设计变化时运行 `blueprintctl.py reopen --source 'user:<原因>'`，修改后重新确认；旧 Skill lock 会变 stale。

## 第二步：动态选择内容型 Skill

在线发现（可选 `GITHUB_TOKEN`，只读且不落盘）：

```bash
python3 .agent/scripts/skillctl.py discover \
  --output .agent/project/skill-candidates.json
```

发现会为每个已确认 goal、architecture、capability、technology choice、constraint、acceptance 与 provider 保留确定性且去重的 query unit；非内置 provider 只有用户显式填写的公开 `discovery_aliases` 会发送给 GitHub，id/kind/config key/value 与 runner label 都留在本地。provider ID 只是本地 advisory discovery/matching unit，不产生 `provider:<id>` 锁定或覆盖义务；若确实需要某种 emitter/集成能力，用户必须把它建模为显式 capability，再由 `matched_capabilities` 覆盖该 capability。候选按 query 轮询仓库，避免前面的热门结果饿死后面的用户选择。同一仓库的多个 `SKILL.md` 会按设计相关性和稳定路径做跨仓库 round-robin，而不是截断成一个；candidate/request 上限仍严格生效。外部 Skill 只允许可独立工作的单文件说明；引用相对 links、scripts、references 或 assets 的不完整 bundle 会直接拒绝，任何外部脚本都不会安装或执行。如果 bounded search 无法在 `--max-repositories` 内覆盖每个 query unit，或基础 request budget 不足，会在内容 inspection 前显式失败。GitHub 请求仅对瞬时网络/5xx 做一次有界重试，同进程重复 URL 使用内存 cache，跨 origin redirect 被拒绝。

也可以向 `score` 提供用户/组织审核过的离线 `agent-skill-candidates/v2` content catalog。离线来源必须由项目 Skill policy 的 `offline_content_catalogs` 以 catalog ID 与候选 exact-set SHA-256 明确选择，provenance source 使用 `offline:<id>`，且每个候选 host 仍须属于 policy 的 `allowed_hosts`；未选入 catalog allowlist 的离线内容仍可使用中性先验评分，但不能激活。离线 catalog 不声称仓库 host authenticity，维护/trust 元数据只使用中性先验并显示 warning；激活仍要求用户审核 exact UTF-8 `SKILL.md`、完整适用 MIT/LICENSE/NOTICE 集合、空相对资产集合、exact two-file bundle digest 和 provider-backed human decision。它不会执行外部脚本，也不会把 catalog 自哈希升级为仓库权威：

```bash
python3 .agent/scripts/skillctl.py score \
  --candidates .agent/project/skill-candidates.json \
  --output .agent/project/skill-recommendation.json
```

默认评分：

`100 × (35% relevance + 15% quality + 15% maintenance + 20% security + 10% trust + 5% license) × (0.70 + 0.30 × evidence confidence)`

其中 relevance **只读取用户确认的设计**。technology、goal、architecture、provider 与 query routing unit 只提供 contextual/advisory 匹配，不产生安装义务；`required_coverage` 只来自用户明确确认的 capability。generic provider emitter 需求也必须建模为显式 capability，不能由 provider/technology 字段隐式强制外部 Skill；没有 capability 时推荐与 lock 选择可保持空。stars 只是 trust 中受限的小信号，不能覆盖相关性、安全和许可证门禁。所有 policy 阈值、权重、候选评分、report 与 lock 的 JSON 数字都必须是有限值；`NaN`、`Infinity`、`-Infinity` 在评分、canonical digest 或序列化前 fail closed。

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
  --reviewed-content-sha256 <skill_content_sha256> \
  --reviewed-license-sha256 <license_content_sha256> \
  --source 'user:<decision>' --approve-digest <approval_sha256> \
  --human-decision-receipt .agent/state/evidence/<provider-receipt>.json
python3 .agent/scripts/skillctl.py verify
```

安全边界：

- 从 pinned Git tree 读取普通 UTF-8 `SKILL.md`，并从 Skill 所在 package 目录逐级到仓库根，nearest-first 收集每一级直接适用的 `LICENSE`/`COPYING`/`NOTICE` exact set；同一级出现多个 license/COPYING 或多个 NOTICE 属于歧义并拒绝，不能按文件名挑第一个；
- 每个 LICENSE/COPYING 必须是完整、未附加条件的 MIT 文本；每个 NOTICE 都进入同一审查集合，出现其他许可证、field-of-use、non-commercial 或附加条件即拒绝。完整路径/角色/字节/SHA 集合绑定 candidate、immutable source pin、authenticated blob evidence、review payload、canonical `LICENSE.txt` CAS、lock 与 verify；GitHub 安装期独立从 immutable tree 重算集合，调用方遗漏 sibling/nearest NOTICE 不能获得认证；
- 拒绝短 SHA、路径逃逸、symlink/gitlink、binary、未知/歧义 license、archived repo、超限内容和阻断级危险模式；本 release 的 strict classifier 只正向识别完整 MIT 条款，默认 policy 也只能允许 `MIT`，Apache/BSD/ISC/MPL 等在加入同等严格的完整文本 validator 前均为 `NOASSERTION`，标题/README 中出现 “MIT” 不构成许可证证明；
- 动态 Skill 激活是 network-closed：候选不得包含外部 URI、下载/clone/fetch、package-manager 网络安装或稍后获取/执行 mutable tool/script/package 的指令；安装期不 checkout、不运行 hook/script/postinstall、不加载凭据，运行期也不因 Skill 获得网络获取权限；
- CAS、active 目录和 lock 每次使用前 exact-set 重验；完整法律集合启用 `agent-skill-candidates/v2`、`agent-skill-source-pin/v2`、`agent-skill-selection-action/v4` 与 `agent-skills-lock/v2`。旧 v1 lock 缺少 sibling/ancestor NOTICE/COPYING 证明，不能静默升级或继续激活；更新 installer 只在任务 idle 且旧 mutation journal 不存在时，把旧 lock、active、CAS、history 与 lifecycle exact bytes 移入不可激活的 digest-bound quarantine，随后要求重新 discover、完整审查并批准 v2 lock。活动任务或不完整 mutation 一律停止，不伪造迁移授权；
- `agentctl.py start` 在任何 task mutation 前验证 lock/CAS/active exact set、Blueprint/policy/approval/journal，随后把精确 `SKILL.md`/`LICENSE.txt` bytes、Skill IDs、bundle digests 与 lock digest 原子封装到 task-generation-bound `.agent/state/SKILL_ACTIVATION.json`；host 仅可在 `agentctl.py validate` 成功后加载该快照中嵌入的 `SKILL.md` bytes，禁止直接加载 mutable `.agent/project/skills/`；
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

registry 不固化目录或领域；每个项目自行配置。未知 changed path 默认 fail closed。catalog 只生成 hash/索引，不覆盖人工语义。`.agent/assets/schemas/*.schema.json` 是可执行的结构契约：标准库 validator 在 Blueprint、Skill policy/candidate 和 knowledge registry runtime loader 中先执行 schema，再执行跨字段/权限语义；差异 self-test 防止 schema 成为无人消费的装饰文件。

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
  --source 'user:<decision>' --approve-digest <approval_sha256> \
  --human-decision-receipt .agent/state/evidence/<provider-receipt>.json
```

GitLab 默认生成 `.gitlab/agent-workflow.yml`，**不会拥有或替换项目根 `.gitlab-ci.yml`**。项目 owner 按生成的 `.agent/provider-design/gitlab-include.yml` 把 `local: "/.gitlab/agent-workflow.yml"` 合入自己的 root CI；root 输出缺少该 include 时，默认路径上的 `providerctl verify` 会失败。component 使用内建 `.pre` stage，不覆盖项目 `stages`。verify 只接受恰好一个 canonical、顶层 block-style include；anchor/alias、flow syntax、quoted/duplicate include header 或把路径藏在其他 key 下都会被拒绝。该 `local` include 由 GitLab 在触发 pipeline 的同一 `$CI_COMMIT_SHA` checkout 解析，因此 pin identity 是该 pipeline 的完整 commit SHA 加 provider trace/design digest，而不是可漂移的 branch URL。

生成的 GitHub/GitLab workflow **只产生 candidate evidence，不能单独充当 protected required check**：候选分支可以修改自己的 workflow 或覆盖 GitLab include 中的 job。GitHub 必须把不可变外部 workflow/action 或 protected default-branch verifier 配成 required check；GitLab 必须由候选仓库外的 Pipeline Execution Policy/compliance pipeline 提供 authority，并向 verify 注入受保护的 authority mode、project ID、40 位 ref SHA、effective merged-config digest 与 collision-scan digest。任何缺失、候选 root 自填、reserved job collision 或可变 ref 都失败。带 OIDC 的 artifact publisher 只消费同次未授权 job 生成并校验的 exact archive/receipt，且不得 checkout 或执行候选命令/inline script。

生成内容包括：

- 用户设计、范围、验收、知识、安全和回滚字段；
- Skill 推荐/lock 证据字段；
- CI 中绑定 exact blueprint digest 的 Skill、只读 knowledge catalog 和可信 Git diff owner 检查；
- 仅由用户蓝图提供的 argv commands 和 CI runner/image/tags；
- `.agent/provider-design/<provider>.json` 只保存 provider ID、确认设计 digest、authority path 和明确的 `configuration_values_embedded: false`；
- `.agent/provider-trace/<provider>.json` 通过 digest 绑定设计、provider 配置和命令，并绑定生成文件、前序 inventory 和 overwrite decision；配置值与 argv 不复制到这些 artifact；覆盖已有输出必须先 plan，再通过 human-decision receipt 批准 exact action，verify 会拒绝剥离、拼接或跨 provider 重放决定。emit/plan 使用共享 mutation lock 和稳定的 no-follow 目录 descriptor；现有文件通过原子 exchange 检查实际被替换的 predecessor，缺失文件通过原子 no-replace 提交。每个多文件 emit 在首个 commit 前 fsync digest-bound crash journal；中断后运行 `providerctl.py recover`：prepared/committed 阶段只恢复仍属于本事务的字节并保留并发第三方内容；所有目标已提交后先持久化 `finalizing`，再幂等清理 predecessor stage，崩溃发生在 fsynced unlink 与 `cleaned` checkpoint 之间时会把“stage 已不存在且目标仍精确匹配 generated bytes”视为已完成，而不会永久卡死。未恢复时 emit/verify fail closed。

模板不会自行加入 npm、Flutter、Gradle、Cargo、Go、数据库、云或任何框架命令。所有用户选择的 YAML runner/image/tag 都以显式字符串序列化，避免 `null`、`true` 等值被 YAML 改型。

## 通用验收权限

`executable` criteria 由蓝图 argv 命令产生证据，并在 receipt verify/release gate 中通过 canonical runner 重新执行；手写 zero-exit JSON 不能代替真实执行。Node 6 的 `agent-node-implementation/v3` 必须提供 bounded、完整且无重复的 `candidate_snapshot`（每项精确绑定 relative path、SHA-256、bytes 与 canonical mode 420/493），`changes` 必须是其子集；Node 7 只在这些已捕获 bytes 的私有 materialization 中运行。preflight/run/replay 会重查 executable digest；直接脚本的 canonical absolute shebang interpreter 也进入绑定，`/usr/bin/env` 等运行时解析被拒绝；污染的 loader/runtime env 与成功后残留进程同样 fail closed。`evidence`/`manual` criteria 由独立 integrator 的 `agent-blueprint-integrator-evidence/v1` 精确覆盖。release node 7 要求最终 live receipt 的 path/SHA-256/bytes 与已验证 selected integrator 的 marker-bound result evidence 完全相同，只有同名 ID 不算权限。`manual` criteria 还必须先运行 `blueprintacceptance.py run ... --plan`，由人批准绑定 blueprint、candidate、Skill lock、preflight、criterion 和 evidence 的 exact digest，再同时提交 `--manual-approve-digest`、`--manual-decision-source 'user:<decision>'` 和 `--manual-decision-receipt`。该 receipt 必须由仓库外、OS 保护的 host/provider adapter 验证；caller 自填 `user:` 文本即使在 local-release route 也会被拒绝。脱离 node 7 ledger binding 的 standalone receipt 不能作为 release 权限。

私有 materialization 只提供待执行字节的完整性隔离，不是文件系统或网络 confinement，`hostile_command_containment` 明确为 `false`。Linux 使用 subreaper/进程身份清理；macOS 仅保留完整 resolved path chain 都由 root 持有且不可 group/world 写的外部 executable，其他已审核 native/interpreter bytes 都复制到私有 executable。每次启动前立即获取同用户 `libproc` 微秒 start-identity baseline；若启动后出现无法归属于已观察 launch 的持久新 process identity（即使其 parent/root 拓扑在观察期间变化），不盲目结束可能无关的进程，而是拒绝 cleanup assurance 和验收成功。

Fresh install 的 `scope.fingerprint_paths` 只列出安装器保证存在的 `.agent` 控制面路径，避免把模板仓库自身的 README、tests、installer 或可选 pxpipe 当作采用方前提；常见 manifest/source root 会自动发现。用户确认蓝图后，任何未被自动发现的自定义产品布局都必须把精确路径加入 `scope.fingerprint_paths`，路径缺失、越界、symlink 或空目录均 fail closed。

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
  --reviewed-content-sha256 <payload.content_review.skill_content_sha256> \
  --reviewed-license-sha256 <payload.content_review.license_content_sha256> \
  --source 'user:<decision>' --approve-digest <approval_sha256> \
  --human-decision-receipt .agent/state/evidence/<provider-receipt>.json
```

生命周期变化先生成只读 approval payload：

```bash
python3 .agent/scripts/skillctl.py plan-lifecycle \
  --action deprecate --id <old> --replacement <active-new> --reason '<reason>'
# 用户确认完整 payload 和 approval_sha256 后：
python3 .agent/scripts/skillctl.py deprecate \
  --id <old> --replacement <active-new> --reason '<reason>' \
  --source 'user:<decision>' --approve-digest <approval_sha256> \
  --human-decision-receipt .agent/state/evidence/<provider-receipt>.json
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
python3 tests/run_all.py --full --fail-on-skip --allow-skip .agent/skills/manage-local-runtime/scripts/self_test_docker_http.py --test-timeout 600
```

只有项目未提供受跟踪的 `compose.yaml` 时，上述精确 Docker HTTP 自测可作为审计后的 N/A；其他任何 exit 77 都由 `--fail-on-skip` 拒绝。

测试完全离线覆盖未确认拒绝、任意用户技术选择、公平 query coverage、评分、恶意候选、伪造 manual/zero-exit approval、commit/file lock、tamper、gitlink 知识 owner、provider 并发事务、双 provider CI 和 evolution proposal。

## 要求与限制

- Python 3.9+；Linux/macOS POSIX 文件语义（原生 Windows 不支持）
- 在线 GitHub discovery 受 GitHub REST 限流；无 Token 时应使用小预算 discovery、组织 catalog 或已批准离线 CAS
- 自动评分不能可靠证明 prompt 无恶意、脚本所有行为、license 法律兼容、维护者未失陷或未来质量
- 本模板不自动 merge、生产部署、修改保护规则或执行第三方 Skill 代码

## License

本项目使用 [MIT License](LICENSE)。安装到项目中的模板副本会保留同一许可证文本；动态 Skill 和 quarantined 第三方内容仍分别受其自身随附许可证约束。
