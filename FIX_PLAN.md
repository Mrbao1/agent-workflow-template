# 修复方案：agent-workflow-template 全量审查问题

来源：2026-07-30 全量审查（7 个方向：文档层、状态机、上下文子系统、证据清理、子代理生命周期、安装/模板、技能路由）。
编号约定：H = 高危，M = 中危，L = 低危/文档。每项给出：问题 → 修法 → 涉及文件 → 验证方式。

实施顺序：P0（测试基建，先行，否则后续修复无法回归）→ P1（默认配置死锁三角 + 状态机硬伤）→ P2（证据/记录清除）→ P3（安装/模板）→ P4（子代理生命周期）→ P5（需求推进与中危）→ P6（文档与低危）。

---

## P0. 测试基建（前置）

### P0-1 `tests/run_all.py` 可执行化
- 问题：串行跑 20 个自测 × 3 个安装上下文，单次 15–30+ 分钟，无分片无超时，CI 已移除，等于没有整体回归门禁。
- 修法：
  1. 增加 `--shard K/N`（按自测名单取模分片）与 `--only <name...>` 子集模式；三个上下文（idle/polluted/installed）中后两者仅在 `--full` 时运行，默认只跑 source 级 + idle。
  2. 每个自测加 `subprocess timeout=`（默认 120s，可配），超时记失败并杀进程组。
  3. 输出 JUnit 风格摘要（通过/失败/耗时清单）。
- 涉及：`tests/run_all.py:159-243`。
- 验证：`python3 tests/run_all.py` 在 5 分钟内完成默认集；`--full` 全量通过。

### P0-2 恢复最低限度 CI（或等效门禁）
- 修法：恢复一个 CI 工作流（或本地 `make check` 入口），跑 P0-1 默认分片；`assert_self_test_inventory` 保留为硬门禁。
- 涉及：新建 `.github/workflows/selftest.yml`（或仓库约定入口）。

---

## P1. 默认配置死锁三角 + 状态机硬伤

### P1-1（H1）`awaiting_host_compaction` 永久死锁
- 问题：`contextctl.py:956-962` 在该状态下拒绝一切 sync/repair；唯一出口要求 `signed_adapter`，默认配置为 null（`config.json:115-118`）；进入无门槛（`--request-host-compaction` 不查适配器，`contextctl.py:1005-1008`）。
- 修法：
  1. `sync --request-host-compaction` 在 `signed_adapter` 为 null 时直接拒绝，报错信息指明"未配置 host compaction 观察适配器，无法进入等待态"。
  2. 新增有界退出命令 `contextctl.py abort-host-compaction`：仅当状态为 `awaiting_host_compaction` 时可用，清除该状态、保留 checkpoint 原值、在 capsule `compaction` 块记录 `aborted` 事件；要求与 `repair` 同级的审批（本地任务走 v2 本地审批，见 P1-2）。
  3. 对存量已卡死状态：`repair --reset` 允许在 `awaiting_host_compaction` 下执行（把状态检查移到 repair 分支之后）。
- 涉及：`.agent/scripts/contextctl.py`（526-530、608-616、925-962、1005-1024）。
- 验证：新增自测——null 适配器下 request 被拒；构造卡死 CONTEXT，abort 后 sync 恢复；repair 在卡死态可用。

### P1-2（H2）`approve-repair` 在默认配置下不可批准
- 问题：`approve-repair` 无条件走 `humandecision.verify`（provider 适配器，`humandecision.py:173-175`），默认 null → capsule 任何损坏不可恢复；v2 本地审批机制从未被咨询。
- 修法：`approve-repair` 与需求/方案审批走同一路由：`decision_policy_version==2` 且任务属本地边界（fast/standard 非部署、或显式 opt-in 的本地 release）时接受 `local_approval`（`humandecision.py:92-99`），受保护路由仍强制 provider 适配器。与 `workflowctl.execution_gate` 的策略判定复用同一函数，避免第三套口径。
- 涉及：`.agent/scripts/contextctl.py:925-929`、`.agent/scripts/humandecision.py`。
- 验证：自测——默认配置下 capsule 损坏 → repair → 本地批准 → 恢复；release 受保护任务仍被拒。

### P1-3（H3）escalate-mode 触发策略 v2→v1 后任务永久卡死
- 问题：`agentctl.py:2384-2392` 重算策略版本但保留旧审批；升级后 `execution_gate` 按 v1 重验失败（`workflowctl.py:615-623`），恢复路径又需要 null 适配器。
- 修法：
  1. `escalate-mode` 提交前预检：用新策略重验现有需求审批，若将失败则**拒绝提交**并输出明确指引（"升级将使现有本地审批失效，请先以新策略重新批准需求"），而不是提交一个死状态。
  2. 提供组合命令 `escalate-mode --reapprove --source user:<text>`：在同一事务内完成策略切换 + 按新策略重录审批（v1 需 provider 回执；v2→v2 直接重录并绑定新 routing profile，见 P5-7）。
  3. scope gate 的提示语（`workflowctl.py:526-528`）改为指向上述安全命令。
- 涉及：`.agent/scripts/agentctl.py:2384-2392`、`.agent/scripts/workflowctl.py:526-528,615-623`、`.agent/scripts/humandecision.py`。
- 验证：自测覆盖 escalation + 策略翻转两条路径（当前 `self_test_control_gates.py` 未覆盖）。

### P1-4（H4）standard + lightweight 投影 → 任务不可完成
- 问题：`workflowctl.py:724-727` 对 `projection=="lightweight"` 从 node 2 投影到 node 6、跳过 solution gate；但 `workflow_validation_errors`（`:1194-1199`）和 complete 的 `required_records`（`:1172`）对 standard 无条件要求 node 4 审批与 1-7 全 artifact。
- 修法（二选一，推荐 A）：
  - A. 验证侧对齐投影：`workflow_validation_errors` 与 `complete-task` 读取 TASK 中由 route receipt 绑定的 `projection` 字段；为 `lightweight` 时 required_records 改为 `{1,2,6,7}` 并豁免 node 4 solution 审批（与 fast 模式同构）。projection 字段纳入 `TASK_INVARIANT_KEYS`，防止事后篡改。
  - B. 推进侧收窄：`command_advance` 的投影分支仅限 `mode=="fast"`，standard 一律走全节点（牺牲 lightweight 在 standard 的收益）。
- 涉及：`.agent/scripts/workflowctl.py:724-727,1144-1219`、`.agent/scripts/contextctl.py`（invariant keys）。
- 验证：自测——governance 类 standard 任务走投影路径可 complete；投影字段篡改后 route-resume fail-closed。

### P1-5（H5/M）三方文档与代码的 fail-closed 语义统一
- 问题：`INDEX.md:15` 称无适配器一律 fail closed；`QUALITY_GATES.md:26` 暗示 release 可人工比对；代码（`agentledger.py:1758-1761`）仅 release fail-closed，fast/standard 接受自写快照。
- 修法（推荐）：代码保持现状（release 强制签名），文档改口：
  1. `INDEX.md:15` 改为明确分级：release 无签名适配器 fail-closed；fast/standard 的快照为"编排方自我声明"，必须配合 node 7 人工比对真实工具记录，且 ledger 仅为协调记账、非活性证明。
  2. `QUALITY_GATES.md:26` 删除"release 可人工比对兜底"的暗示，与代码对齐。
  3. 配套补强（降低自我声明风险）见 P4-1/P4-3。
- 涉及：`.agent/INDEX.md`、`.agent/workflows/QUALITY_GATES.md`。

### P1-6（M）三振升级可绕过
- 问题：`command_return` 三振后置 `waiting_human`（`workflowctl.py:781-785`），但 `command_advance` 允许从 `waiting_human` 推进且无 gate 节点不查审批（`:728`）。
- 修法：`command_advance`/`submit-gate`/`approve-gate` 在 `status=="waiting_human"` 且 `next_action` 含三振标记时，要求存在针对该根因的人工决策记录（本地 v2 或 provider 回执）才允许继续；决策记录消费后清除标记。
- 涉及：`.agent/scripts/workflowctl.py:728,781-785`。
- 验证：自测——三振后直接 advance 被拒；录入决策后放行。

### P1-7（M）调度器 resume 回执可重放 + 无适配器时崩溃
- 问题：nonce 只查非空（`workflowctl.py:1233`）；未配置适配器时传 `--scheduler-receipt` 触发 `SystemExit` 且无 JSON 回执（`humandecision.py:174-175`）；`:1239` 对非 dict config 未防护。
- 修法：
  1. 新增已消费 nonce 注册表（`.agent/state/` 下私有文件，记录 nonce+cursor+过期时间，随 receipt TTL 清理）；同 nonce 重放拒绝。
  2. `--scheduler-receipt` 在无适配器时降级为 `scheduler_available=false` + 错误字段，**仍输出 JSON 回执**（保持"回执即终局裁决"契约）。
  3. 全部 config 读取加 isinstance 防护；`verified_scheduler_resume` 的异常统一转换为结构化回执字段而非 SystemExit。
- 涉及：`.agent/scripts/workflowctl.py:1222-1294`、`.agent/scripts/humandecision.py:170-180`。
- 验证：自测——重放同一回执被拒；无适配器传回执得到 JSON 错误回执而非 traceback。

### P1-8（M）TASK→CONTEXT 两文件提交无崩溃日志
- 问题：`contexttx.py:131-168` 在 TASK 与 CONTEXT 更新之间被 SIGKILL 则状态不一致，只能人工修复；project-init 有恢复日志（`agentctl.py:215-244`）而这里没有。
- 修法：参照 project-init 增加 transition journal：提交前写 journal（含 before/after 摘要与备份路径），提交完成后删除；`route-resume`/`bootstrap-check` 检测到残留 journal 时输出确定的恢复命令（重放或回滚），而非泛泛的 `repair-context-or-workflow-state`。回滚 `_restore` 改为先写齐 tmp 再统一 rename，缩短不一致窗口；rename 后 fsync 父目录。
- 涉及：`.agent/scripts/contexttx.py:70-171`、`.agent/scripts/workflowctl.py`（route-resume 恢复分支）。
- 验证：自测——注入 kill 点，验证 journal 恢复两方向。

### P1-9（M）`update_stage` 无锁非原子 + 提交后失败语义混乱
- 问题：`workflowctl.py:536` 裸 `write_text`，在事务锁释放后执行；写失败时变更已提交但操作者看到失败。
- 修法：STAGE_INDEX 写入纳入 `contexttx.transition_task` 事务（作为 side-effect 文件，带备份与回滚），使用 `atomic_write`（tmp+fsync+rename）。
- 涉及：`.agent/scripts/workflowctl.py:536,665,715,756,802,895`、`.agent/scripts/contexttx.py`。
- 验证：自测——并发 route-resume 不再观察到 stage 漂移；注入写失败验证回滚。

### P1-10（M）变异路径子进程无超时
- 问题：`workflowctl.py:642-645`（budget-gate）、`:866-876`（complete 的 validate/ledger/cleanup 链）无 `timeout=`。
- 修法：统一 120s 超时（与代码库其他调用一致）；`subprocess.TimeoutExpired` 全局捕获并转为结构化错误。`command_complete` 调整为先校验 ledger/clean 再执行 destructive cleanup。
- 涉及：`.agent/scripts/workflowctl.py:642-645,866-877,1212-1261`。
- 验证：自测——注入挂起的 budget-gate，验证 120s 后结构化失败。

### P1-11（M）`policy_bundle_sha256` 不绑定执行代码与 guardrails
- 问题：`contextctl.py:217-229` 只哈希 config/INDEX/manifest/workflows/主 SKILL.md；改 `workflowctl.py` 等脚本或 `PROJECT_GUARDRAILS.md` 不触发漂移。
- 修法：
  1. bundle 集合扩展为：现有项 + `.agent/scripts/**.py` + 主 skill 的 `scripts/**`、`references/**` + `policies/PROJECT_GUARDRAILS.md`（按 manifest 枚举，符号链接/缺失仍 fail-closed）。
  2. 版本迁移：bundle 计算函数带版本号（`policy-bundle/v2`），capsule 记录版本；旧 v1 capsule 一次性升级（复用 `legacy_usage_upgrade_allowed` 模式）。
  3. 同步更新 INDEX/CONTEXT/METHODOLOGY/QUALITY_GATES 对 bundle 覆盖面的描述。
- 涉及：`.agent/scripts/contextctl.py:217-258,360,774-886`、四个文档、install 迁移序列。
- 验证：自测——改任一脚本字节后 check 报漂移；旧 capsule 升级路径通过。

---

## P2. 证据与记录清除

### P2-1（H6）任务归档链使证据压缩永久失效
- 问题：`build_task_archive` 嵌入完整旧 TASK 文本（`agentctl.py:2455-2495`），`reachable_evidence` 文本传递闭包（`evidencectl.py:337-348`）使历史证据永远可达；活跃证据超 4MiB 后 compact 硬失败且无出口。
- 修法：
  1. task-archive 载荷改为结构化格式：归档 TASK 中引用证据的路径清单抽取为独立字段 `referenced_evidence`（存 sha256 摘要，**不存字面路径**），正文中的路径文本替换为摘要占位。
  2. `reachable_evidence` 对 `task-archives/` 只沿 `previous` 头链遍历，不再对归档载荷做文本扫描。
  3. 兼容：旧格式归档在首次 compact 时迁移重写（内容寻址，生成新头）。
  4. 增加 operator 出口：`evidencectl.py compact --include-task-history`（需人工决策记录），允许将任务历史整体 deep-archive 并修剪活跃引用。
- 涉及：`.agent/scripts/agentctl.py:2455-2619`、`.agent/scripts/evidencectl.py:274-482`。
- 验证：自测必须覆盖 task-archive 场景（当前完全缺失）——归档 N 个任务后历史证据可压缩、4MiB 上限可恢复。

### P2-2（H7）`deliveryctl init` 无防护抹除交付回执
- 问题：`deliveryctl.py:447-466` 每次 `agentctl start` 无条件重置 delivery.json；任务归档不含 delivery.json → 回执静默丢失、交付状态可随意"回滚"。
- 修法：
  1. `build_task_archive` 增加 delivery.json 字节（digest 绑定进归档头）。
  2. `command_init` 在非空状态下先生成归档回执（写入 evidence 并登记索引）再重置；无归档副作用时拒绝。
  3. delivery.json 增加 `epoch`/`previous_head` 链，与 task-archive 头对齐，`validate` 校验链完整。
- 涉及：`.agent/scripts/deliveryctl.py:447-466`、`.agent/scripts/agentctl.py:2470-2484,2576-2648`。
- 验证：自测——连续两个任务后首个任务的交付回执仍可验证；直接 init 篡改被 validate 发现。

### P2-3（M）rollback 归档链无深度上限
- 问题：`compact_rollback_state`（`workflowctl.py:153-189`）无 `max_rollback_archive_depth`、无 snapshot 合并，永驻活跃证据预算。
- 修法：移植 failure 链的 snapshot 合并逻辑（`:227-236` + `failure_archive_depth_limit` 配置模式）：超过深度阈值时将最老链段合并为单个 snapshot 文件，TASK 只保留新头。
- 涉及：`.agent/scripts/workflowctl.py:144-254`、`.agent/config.json`（新增 `rollback_archive_depth_limit`）。
- 验证：自测——超深度后链长恒定、历史可验证。

### P2-4（M）可达性根集合白名单遗漏
- 问题：`root_reference_files`（`evidencectl.py:305-326`）不含 `.agent/skills/**`、`templates/**`、`assets/**`、`scripts/**`、`plugins/**`、`CLAUDE.md` 等，而 skill 中确有字面证据路径。
- 修法：根集合改为 config 可配置（`evidence.reference_roots`），默认值补齐上述目录；匹配增加 digest 引用形式（sha256 命中亦保护）。
- 涉及：`.agent/scripts/evidencectl.py:274-326`、`.agent/config.json`。
- 验证：自测——仅被 skill 引用的证据不被压缩。

### P2-5（M-L）deep 验证未纳入常规 compact + restore 无锁 + 孤儿 GC
- 修法：
  1. `compact` 对它将依赖的每个归档执行 `manifest_from_archive(deep=True)`（而非仅浅验索引）；`agentctl cleanup` 定期挂 `verify --deep --quiet`（结果入 route-resume 警告字段）。
  2. `command_restore` 取 `.evidence.lock`。
  3. `verify` 增加未索引归档/临时文件报告；`compact` 提供 `--gc-orphans` 清理（列出后删除，需确认）；`contexttx` 授权残留纳入 `agentctl cleanup`。
- 涉及：`.agent/scripts/evidencectl.py:455-559`、`.agent/scripts/agentctl.py:1983-1992`、`.agent/scripts/contexttx.py:70-81`。
- 验证：自测覆盖三分支。

### P2-6（L）mtime 年龄保护可被 `cp -p` 绕过
- 修法：年龄判定增加 birth time（`st_birthtime`，macOS 可用）或回退为"索引登记时间"为准；至少在文档中声明限制。
- 涉及：`.agent/scripts/evidencectl.py:355-358`。

---

## P3. 安装 / 模板生命周期

### P3-1（H8）pxpipe 渲染在 v4 安装上硬坏
- 问题：`templatectl.py:360` 只接受 v2/v3 manifest；新安装均为 v4（`install.py:350`）；自测手工构造 v3 掩盖。
- 修法：
  1. `validate_context_transport_vars` 接受 v4，并为 v4 绑定 `claude_bootstrap` 字段（`:450` 的证明映射同步更新）。
  2. `TEMPLATE_ROUTING.md:30` 文案更新为 v2+。
  3. 新增测试：对真实 v4 安装跑完整 render 路径（当前测试空白）。
- 涉及：`.agent/scripts/templatectl.py:360,450`、`.agent/scripts/self_test_templatectl.py:503`、`.agent/workflows/TEMPLATE_ROUTING.md`。
- 验证：新自测通过；旧 v2/v3 项目回归通过。

### P3-2（H9）旧版 install.py 静默降级新版安装
- 问题：`install.py:1831` 只比 `!=`；目标为更新版本时文件落入直接覆盖分支（`:283-295`）。
- 修法：
  1. 版本比较改为语义化三元：target_newer / same / target_older。`--update` 遇到 target_newer 默认拒绝，提示使用更新版模板；`--allow-downgrade` 显式放行并输出警告。
  2. migration 序列按目标版本下限裁剪，拒绝执行 `migration_version` 回退。
  3. `--check` 输出已能显示版本方向，补充 exit code 区分。
- 涉及：`install.py:183-295,1831`。
- 验证：新增降级拒绝自测（当前空白）。

### P3-3（M-L）install 杂项
- `--update` 字节幂等：零写入时跳过 `migrate_private` 的 CONTEXT/STAGE_INDEX 重拷（`install.py:1705-1709`）；测试补 pin。
- 只读模式副作用：`--check`/`--dry-run` 不做 `mkdir`（`:1862,:1728` 移入写分支）。
- `--provider-preflight-adapter` 正向路径补测试（`:1264-1280`）。
- 涉及：`install.py`、两个生命周期自测。

---

## P4. 子代理生命周期

### P4-1（M）ledger 反向标记校验 + 完整性链
- 问题：`validate` 只对现存成员验终态标记（`agentledger.py:3825-3862`）；删除成员不可检测；agents.json 是无保护明文。
- 修法：
  1. `validate` 反向枚举 `agent-terminal-markers/<epoch>/`，存在无对应成员的标记即失败。
  2. agents.json 增加追加式 hash 链字段（每次 save 记录 `prev_sha256`），`validate` 验链；与平台快照的绑定保持现状。
- 涉及：`.agent/scripts/agentledger.py:107-117,3825-3975`。
- 验证：自测——删除成员/篡改历史均被 validate 发现。

### P4-2（M-H）`init --archive-existing` 前置条件不强制
- 问题：带活跃成员也可归档重置（`agentledger.py:1906-1908`），epoch 标记成孤儿。
- 修法：`--archive-existing` 要求全部成员终态；否则需 `--force` + 人工决策记录（v2 本地或 provider），并在归档头记录强制原因。
- 涉及：`.agent/scripts/agentledger.py:1896-1910`。
- 验证：自测两分支。

### P4-3（M）route-resume 的 terminal=true 不绑定 ledger/runtime
- 问题：`workflow_validation_errors`（`workflowctl.py:1144-1219`）不跑 `agentledger validate` / `assert-clean`；终局回执可与活跃子代理/泄漏运行时并存。
- 修法：route-resume 在 `status=="accepted"` 分支追加只读校验：`agentledger.py validate --require-empty`（或等效内联，带 30s 超时）与 `agentctl.py assert-clean --quiet`；失败则 `terminal=false` 并给出清理游标。直接改 agents.json 绕过场景由 P4-1 的链校验兜底。
- 涉及：`.agent/scripts/workflowctl.py:1273-1303`。
- 验证：自测——完成后注入活跃成员，route-resume 转非终态。

### P4-4（M）子代理 limbo：平台丢失无出口
- 问题：无 "lost" 终态转移（`agentledger.py:2949-2950,3049-3051`），成员永久 active，complete 不可达。
- 修法：新增 `finish --lost`：要求 (a) 连续 N 次（默认 3）新鲜快照均缺失该成员，或 (b) 人工决策记录；写入终态标记 `lost`，结算 token 预留为 released。`watchdog-plan` 对超时活跃成员输出 `finish --lost` 建议。
- 涉及：`.agent/scripts/agentledger.py`（finish/check/watchdog）。
- 验证：自测——丢失成员走 lost 后 complete 可达。

### P4-5（L-M）prepared 不过期 / tool-lease 监管缺口
- 修法：
  1. `validate` 对超 TTL 的 prepared 直接判失败并给出 `cancel-prepare` 游标（从劝告升级为强制）。
  2. tool-run 信号处理移到 `Popen` 之前（对齐 `managed-run`）；`cleanup_tool_leases` 增加 supervisor 活性检查，supervisor 死亡即回收；畸形 lease 记录保留并报告而非静默丢弃（`agentctl.py:3057-3059`）。
- 涉及：`.agent/scripts/agentledger.py:2240-2243,3954-3961,4011-4024`、`.agent/scripts/agentctl.py:2854-3061`。
- 验证：自测三分支。

### P4-6（L）cleanup/assert-clean 盲区
- 修法：docker 残留检查纳入 named volume（声明时 `compose down -v`）；baseline 捕获时机器已脏则警告并要求确认；cwd 逃逸限制写入 `manage-local-runtime` 文档声明。
- 涉及：`.agent/scripts/agentctl.py:621-628,762-819,1026-1040,3076-3119`。

---

## P5. 需求推进与路由（中危）

### P5-1（M）风险升级的诚实性标注 + 启发式补强
- 修法：
  1. `INDEX.md:27` 与 mode router 表明确标注：升级规则中仅"文件数、migration 子串、四类路径前缀、测试/生产/部署路由"为机械强制，其余（data_risk/security/irreversible 等）为流程判断，依赖申报。
  2. `actual_scope_gate` 增加安全敏感路径启发（`auth/`、`crypto/`、`security/`、`.pem`/`.key` 等）为**警告级**输出（不阻断，提醒人工确认模式选择）。
  3. 明确写出"拆任务规避 fast 限制"无机械防护，控制点是每次拆分都需新的需求审批。
- 涉及：`.agent/INDEX.md`、`.agent/scripts/workflowctl.py:516-524`。

### P5-2（M）回溯→知识沉淀死路
- 问题：`knowledge_candidates` 归档后永不被读（`workflowctl.py:878`）；无脚本写/验 `knowledge/INDEX.md`。
- 修法：
  1. `complete-task` 将候选写入 `.agent/state/knowledge-pending.json`（而非只进 TASK）。
  2. 扩展 `agentctl.py` 现有 `promote` 子命令（或新增 `promote-knowledge`）：从 pending 列表晋升，**实际写入** `knowledge/INDEX.md` 或 `capabilities/INDEX.md` 并记录晋升回执（要求人工来源）。
  3. `route-resume` 在新任务启动时提示未处理候选数。
- 涉及：`.agent/scripts/workflowctl.py:863-878`、`.agent/scripts/agentctl.py`、`knowledge/INDEX.md`。
- 验证：自测——完整走通 候选→晋升→索引落盘 链路。

### P5-3（L）node 0 无契约
- 修法：`node-contracts.md` 为 node 0 定义最小 gate（任务必填字段齐全 + 路由回执存在）；`agentctl start` 的自动接受（`:2614`）改为校验后接受，缺失字段直接拒绝 start。
- 涉及：`.agent/skills/run-ai-coding-pipeline/references/node-contracts.md:7`、`.agent/scripts/agentctl.py:2614`。

### P5-4（L）适配器 `implemented` 标志可变自声明
- 修法：`bootstrap-check` 增加探测：标记 implemented 的适配器若 runner 文件/宿主依赖（docker/xcodebuild）缺失则警告；node 4 检查（`workflowctl.py:569-573`）在 release 下要求一次轻量 preflight 证据而非仅布尔位。
- 涉及：`.agent/scripts/agentctl.py`（bootstrap-check）、`.agent/scripts/workflowctl.py:569-573`、`.agent/config.json:237-263`。

### P5-5（L）`workflow_validation_errors` 不重验 requirement gate
- 修法：validation 与 `execution_gate` 复用同一 requirement 校验函数，保证 route-resume 的 `action=continue` 与下一次 transition 判定一致。
- 涉及：`.agent/scripts/workflowctl.py:609-636,1144-1219`。

### P5-6（M）CONTEXT capsule 自哈希无密钥（记录为已知限制）
- 说明：无宿主密钥时无法根本解决（agent 可重写 capsule 并重算哈希）。修法为诚实降级 + 有适配器时增强：
  1. INDEX.md 第 14 条改为明确："无签名适配器时，capsule 完整性为流程约束而非脚本强制"。
  2. 配置适配器后，`sync`/`--transition` 要求回执签名覆盖 capsule 哈希（扩展现有 authorization receipt 机制）。
- 涉及：`.agent/INDEX.md`、`.agent/scripts/contextctl.py:253-320`。

### P5-7（L）v2 本地审批不绑定 routing profile
- 修法：`local_approval` 记录增加 `routing_profile_sha256`（mode/files/risks），与 provider 回执对齐；escalate-mode（v2→v2）时要求重录审批（与 P1-3 的组合命令配合）。
- 涉及：`.agent/scripts/humandecision.py:43-99`、`.agent/scripts/agentctl.py:2384-2392`。

---

## P6. 文档一致性与低危杂项

1. **hard_blocked 动作集统一**：INDEX.md:14 与 CONTEXT.md:4 统一为同一份清单（建议：cleanup、split、escalate、human decision），并注明 escalate 受模式上限约束。涉及：`.agent/INDEX.md`、`.agent/workflows/CONTEXT.md`。
2. **budget-policy.md 与脚本矛盾**：`:13` 改为与脚本一致——降估计必须走 `--host-compaction` 请求/回执握手；同时修正":7 compact 后继续"对累计账户无效的误导（明确 compact 只重置活跃窗口门，不清累计成本门）。涉及：`.agent/skills/manage-task-context/references/budget-policy.md`。
3. **AGENTS.md/CLAUDE.md 引导清单**补 `state/CONTEXT.json`；同步说明 guardrails 由 `project_initialization.guardrails_sha256` 绑定、bootstrap-check 验证。涉及：根 `AGENTS.md`、`CLAUDE.md`。
4. **`usage_receipt`/`usage_receipts` schema 漂移**：`budget.py:106` 改读复数列表（取最新一条），或删除死分支；补 `risk_flags` isinstance 防护（`workflowlib/state.py:23-24`）。
5. **`--request-host-compaction` 伪造 history**：`contextctl.py:526-530` 写入 `handoff_written` 前校验 handoff artifact 真实存在，否则拒绝。
6. **非 invariant TASK 字段绕过授权**：`contexttx.changed_fields` 对 invariant 之外的变更至少记录字段名清单进授权回执（不阻断，但可审计）；注释（`contextctl.py:42-43`）改为如实描述覆盖范围。
7. **`legacy_usage_upgrade_allowed` 疑似死代码**：确认旧 capsule 格式；若确实永不命中，修正比较基准（expected vs stored 的键集合对齐）并补一条迁移测试。
8. **`humandecision.local_approval_valid` 信任存储的策略版本**：release 下重查 config 的 `allow_current_chat_local_release`，配置收紧后旧本地 release 任务应失效并提示。
9. **config 收紧不追溯**问题统一原则：凡 config 中安全相关布尔位（allow_current_chat_local_release、adapter implemented）变更，bootstrap-check 输出影响提示。

---

## 验证总纲

- 每个 P1–P5 项必须带自测（新增 `self_test_*.py` 并登记进 `tests/run_all.py` 清单，或扩展现有对应套件）。
- 全部完成后：`python3 tests/run_all.py --full` 通过；`python3 install.py . --check` 通过；对一份 v4 全新安装手工演练：fast 任务全流程、standard lightweight 投影、capsule 损坏恢复、三振人工决策、子代理 lost、证据超上限压缩——六条路径均可走通。
- install.py 的 migration 序列追加一条新迁移（bundle v2、delivery epoch、rollback depth 配置默认值），保证存量项目 `--update` 平滑升级。

---

## P7. Token 账本校准（用户实测反馈）

实测症状：启动必读 ~5,238 tokens、进入澄清 ~6,716 tokens（fast 预算 12,000 的 56%）；`start` 默认 files=3/complexity=bounded 自动落入 standard；每次状态迁移虚构 +150/300/500；standard 子代理 16,000 payload + 3,000 margin = 19,000 > standard 硬阈值 21,600 前的 must_compact 线 18,000（一个子代理必入 must_compact）；child_system_tool_margin 仅 1,000；宿主 System Prompt 每轮重放完全不入账。

1. **P7-1 算术不变量**：配置校验强制 `最大允许子代理单次计费(payload上限+margins) + 基线开销 < hard_budget_ratio × 模式预算`——任何"合法操作必然越线"的配置在安装/校验期即拒绝。同步修正默认数值使其满足不变量。
2. **P7-2 迁移增量语义**：150/300/500 改为"每轮宿主开销估计"（含 System Prompt 重放 + 轮次成本），配置键改名/文档化；有 provider 实测回执时优先实测值（P6-4 已打通 `usage_receipts` 读取）。
3. **P7-3 margin 现实化**：`child_system_tool_margin_tokens` 默认提高到现实量级（≥4,000）并可按宿主校准；`inherited_turn_estimated_tokens` 对每次根轮次计费而不仅是 dispatch。
4. **P7-4 start 默认值**：默认 files/complexity 路由到 fast（最小声明），由 scope gate 事后纠偏，而不是默认落 standard。
5. **P7-5 账本覆盖**：宿主 System Prompt 放大纳入统一账本的估计模型并写入 budget-policy.md；INDEX/CONTEXT 文档同步数字。
