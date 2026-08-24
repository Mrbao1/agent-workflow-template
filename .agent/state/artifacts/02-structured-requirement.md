# Structured Requirement

- Background: 现有独立模板已有治理状态机，但项目能力与部分模板仍固定；需要改为用户确认蓝图驱动
- Goal: 用户确认需求、架构、技术选择和验收后，才允许按该蓝图选择外部 Skill
- Roles: 项目维护者负责蓝图与安装确认；Agent 负责候选发现、解释评分、验证和执行；CI 负责锁重验
- Flow: 创建蓝图草案→用户确认 digest→发现候选→硬门禁→可解释评分→用户批准推荐→锁定安装→设计开发验收 CI→演化提案
- Data sources: 用户确认蓝图为唯一选择权威；GitHub metadata、pinned SKILL.md、LICENSE 仅作不可信候选证据
- Inputs / outputs: 输入为用户蓝图和可选 GitHub catalog；输出为推荐报告、commit/file lock、受控 Skill、知识与 provider 模板
- Exceptions: 蓝图缺失或未确认、许可证未知、短 commit、危险内容、完整性漂移、评分不足、更新未批准均 fail closed
- Acceptance: 离线 fixture 覆盖确认门、评分、供应链、知识、Issue、双 CI、演化及安装升级生命周期
- Field provenance: 目标与设计原则来自用户；安全硬门禁来自现有项目治理与 Nova 抽取审计
- AI inferences requiring confirmation: 无；技术栈和架构不得由 Agent 推断后自动确认
