# 最终报告机器契约

最终报告必须是唯一权威版本。报告校验器只证明结构、文件和哈希自洽；Node 7 人工决定前使用 `--draft`，最终发布时仍要求 provider 认证的人工批准。真正发布门使用 adapter 的 `run/verify` 收据协议：integrator 的唯一一次 runtime helper 运行先进入报告，`run` 将它与 candidate/preflight 封装，Node 7 只调用只读 `verify`；不得为了“独立验证”再次启动 Docker、测试或 cleanup。

报告必须引用一个带 SHA-256 的 `Acceptance plan` JSON。它包含权威 requirements、受测 scope、11 条 lane、预先声明的 controlled adjacencies 和紧凑 agent ledger；具体字段由校验脚本强制。Requirement source 使用真实 `{file, anchor}`，file 必须属于 requirement_files，anchor 必须是精确 Markdown 标题或存在的 `L<行号>`。Scope 必须覆盖项目中存在的常规源码/测试根目录，每个 root 至少贡献一个文件；排除项必须真实存在，并有 path、reason 和 `user:` approver，且不能越出已声明 root。

Agent ledger 使用全局连续 sequence 的结构化事件。每个 phase 都包含 started/status_check/finished，并符合 candidate → adversarial → 可选 fix/adversarial-retest → cross → 可选 fix/cross-retest/adversarial-affected → integrator 状态机；interrupted 后最多重派一次。

## 顶层字段

严格使用脚本要求的字段名。版本指纹等于指纹清单文件自身的 SHA-256；清单以 `SHA-256␠␠相对路径` 列出本次受测源码、配置和 lockfile，校验器会重新计算每个文件。Agent 身份写为 `canonical-agent-id#task-id`，实现者、对抗审查者和交叉审查者必须不同。

人工批准必须同时记录：

```text
- Human decision: approved
- Human decision source: user:<可定位的用户决定>
```

AI 不得自行填写用户批准。

## 场景记录

每个必测场景只出现一次，并引用项目内真实、非符号链接的证据文件：

```text
- Case: CASE-001 | Requirement: REQ-001 | Status: Pass | Evidence: output/acceptance/latest/case-001.json | SHA-256: <64位小写哈希>
```

`Mandatory cases` 至少为 2，且与结构化 Case 行数量和 `Passed` 完全一致；唯一 Requirement ID 必须等于 Acceptance plan 的权威需求集合。每个 JSON 证据除基础字段外，还必须给出 lane、user_role、risk、review_type、observed_layers、data_flow_steps、execution_run_ids 和 scenario_vector；对抗证据使用受控 attack_types 并给出 fault_injection。交叉证据的 `derivation_source` 必须精确等于该 Case 对应 Requirement 的 `{file, anchor}`。Acceptance plan 必须预先声明两条 Case 的 adjacency；两条 Case 使用同键 `scenario_vector`，所有值必须是去除空白后仍非空的字符串，至少固定 `flow`、`state`、`input_shape` 三个不变量，只能有一个受控业务字段不同。受控字段限金额类别、输入变体、边界值、错误模式、状态转换或权限。运行 ID、环境、观察层和自由文本标签都不能用作业务邻接证明。至少覆盖两个用户角色。截图不能作为唯一证据。

## 干净复跑记录

恰好一次由 integrator 独占的 fresh-state 全链路证据：

```text
- Rerun: RUN-01 | Evidence: output/acceptance/latest/run-01.json | SHA-256: <64位小写哈希>
```

任何源码或配置变化都会使指纹和相关证据失效，必须重新生成和复跑。

该 Rerun 的 `cases` 必须按报告顺序精确等于全部 Mandatory Case ID，不能重复，并附带 64 位 `candidate_sha256`、image_digest、fresh-state token 和结构化 state_reset_evidence。它引用唯一 runtime helper JSON 及哈希；runtime helper 必须携带相同的 canonical `candidate_sha256`，其中容器、镜像、health、源码、真实 client command 和清理结果必须一致。Client command 必须引用 scope 与指纹中的真实测试文件，并输出 `acceptance-client/v1` JSON 回执；回执按相同顺序精确覆盖全部 Mandatory Case、fresh-state token 和归零结果且不能重复。每个 Case 恰好有一个带 `case_id`、去除空白后仍非空的 `name` 和 `passed:true` 的可定位断言。Runtime helper 要求客户端独立进程组已清理且 `process_cleanup.remaining=0`。外部门禁的 `run` 只封装这一证据，`verify` 只重验收据、候选、preflight 和当前 clean，不再执行 client 或 cleanup。
