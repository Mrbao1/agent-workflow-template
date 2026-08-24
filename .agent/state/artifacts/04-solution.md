# Solution and Task Graph

- Architecture: 保留通用 first-party 控制面；新增项目私有、用户确认的 BLUEPRINT 作为 domain Skill 选择唯一权威；外部 Skill 经 quarantine→gate→score→approval→lock→install 生命周期
- Modules and data flow: blueprintctl 管理草案和确认 digest；skillctl 发现评分锁定安装验证更新退役；knowledgectl 管理 owner catalog；providerctl 生成 Issue MR 和 CI；evolutionctl 只产 digest 绑定提案
- Interfaces / configuration: Python 3.9 标准库 CLI、严格 JSON schema、环境中的可选 GITHUB_TOKEN、用户提供的 provider 和命令配置；不预设语言框架
- Risks and rollback: 恶意 Skill、评分偏差、网络限流、模板覆盖和 installer 漂移；默认不执行、硬门禁优先、原子写、旧锁留存、分支整体可回滚
- Parallel / serial dependencies: 先写离线测试；实现 blueprint 和共享安全库；再实现 skill lifecycle；随后知识 provider evolution；最后 installer manifest 文档 CI 和全量验证
- Allowed / forbidden files: 允许 .agent managed scripts skills workflows assets knowledge index、README、install.py、tests、GitHub GitLab CI；禁止 Nova 仓库、凭据、生产设置和现有私有用户知识
- Task ownership and integration: 根 Agent 唯一实现和集成；实现完成后独立 adversarial 与 cross reviewer 只读审查同一 digest
- Human solution decision: 用户已决定技术栈和架构必须由用户输入确认，Agent 不得自动固化或擅自替换
- Decision requested: 批准上述用户蓝图优先、外部 Skill 动态适配和安全生命周期方案
- Approval enables: 本地可逆实现、测试、文档、提交并推送用户明确指定的 GitLab feature branch
- Approval does not enable: 生产部署、自动 merge、执行第三方代码、降低安全门禁或替用户选择技术栈
