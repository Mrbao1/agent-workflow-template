# Requirement Contract

- Goal: 全量核查真实任务推进错误日志与状态推进日志，修复预算状态、恢复路由和跨任务衔接不一致，使状态机闭环且不虚构 Token 节省。
- Users: 使用该模板推进本地开发、测试、交付和恢复流程的维护者与 Agent。
- Success: TASK、CONTEXT、route-resume 对同一检查点给出一致的有效预算状态；accepted 任务在必须压缩或切换会话时给出可执行且诚实的下一步；新任务不会在无压缩证明时把 must_compact 伪装成已验证 handoff；真实生命周期与针对性回归测试覆盖上述路径并通过。
- In scope: 审计现有任务链、失败/超时报告和恢复回执；修改 contextctl、agentctl、workflowctl 及必要的流程文档；新增真实跨任务生命周期和状态一致性测试；运行针对性与全量回归。
- Out of scope: 接入外部 host-compaction/provider adapter；执行生产部署；重写历史私有任务证据；把未观测 Token 使用伪装为已节省。
- Constraints: 保持现有哈希绑定、迁移兼容和 fail-closed 安全边界；活动窗口估计只有经签名 host compaction 才能下降；不使用 contexttx 桩替代真实事务完成验收；保留用户已有工作区改动。
- Data and permissions: 仅修改本仓库本地文件与测试临时目录；不触发外部发布、部署或不可逆操作。
- Target environment: local
- Context transport: native
- Acceptance: 复现日志矛盾并形成自动化断言；预算状态事实源在 TASK/CONTEXT/route receipt 间一致或字段语义明确且不误导；accepted+must_compact 的 next_action 指向新会话或经验证 host compaction；跨任务 start 和后续路由不宣称虚假压缩；context/bootstrap/workflow 校验通过；针对性套件和完整套件无真实失败。
- Provenance: user request: 仔细的全量的检查，根据任务推进的错误日志，整体状态推进的日志进行更改
- Production provider target: none
- Human decisions: user:仔细的全量的检查，根据任务推进的错误日志，整体状态推进的日志进行更改
- Clarified: true
