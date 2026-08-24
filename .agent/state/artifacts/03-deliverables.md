# Delivery Scope

- Business boundary: 通用 .agent 控制面，不包含任何项目专用业务实现或固定技术栈
- Deliver now: 用户蓝图门、动态 GitHub Skill 生命周期、知识 registry、Issue MR 与双 CI 模板、自迭代提案、文档测试安装迁移
- Explicit exclusions: 自动选栈、执行第三方脚本、自动发布合并部署、Nova 专用规则、在线真实 GitHub 依赖测试
- Later batches: 可选签名 registry、GitHub GitLab API 写适配器、组织级 TUF 与远程撤销服务
- Item acceptance mapping: 蓝图与 Skill 由自测覆盖；模板由生成与 exact content 检查覆盖；整体由 fresh install update 和全套测试覆盖
