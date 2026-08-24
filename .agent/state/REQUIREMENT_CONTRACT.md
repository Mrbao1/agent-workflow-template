# Requirement Contract

- Goal: 将现有独立 .agent 工作流完善为可安装到任意项目的通用开发模板；项目技术栈、架构与设计必须由用户输入并显式确认，确认后才按需求动态发现、评分、锁定和安装最合适的 GitHub Skill，并贯通设计、开发、验收、CI、知识与迭代。
- Users: 采用不同技术栈的软件项目维护者、开发者与 AI 编程 Agent。
- Success: 新鲜项目可先完成用户主导的需求/架构/技术栈确认，再生成确认摘要并据此动态选择外部 Skill；Skill 具备可解释评分、供应链硬门禁、完整 commit 与文件哈希锁、离线校验、更新/回滚/淘汰提案；知识库、Issue/MR、设计开发验收和 GitHub/GitLab CI 均为可配置模板；现有安装/升级生命周期和全量自测通过，变更推送到 user-growth/agent-workflow-template。
- In scope: 用户确认优先的项目蓝图；GitHub Skill 搜索/候选输入/评分/检查/锁定/安装/验证/更新/退役；通用知识 registry 与 changed-path owner 检查；GitHub/GitLab Issue/MR 模板；GitHub Actions 与 GitLab CI 模板；工作流自迭代提案；README、架构、安全文档、fresh install 与 update 迁移测试。
- Out of scope: 自动替用户决定技术栈或架构；把仓库现状探测结果提升为用户决定；自动执行第三方 Skill 脚本/Hook；自动合并、生产部署、修改保护规则；保证评分等同于安全或法律批准；复制 Nova 业务、路径、Runner、Bridge、Mars 或专用 AST 规则。
- Constraints: 用户确认的 project blueprint 是 Skill 选择唯一权威输入，仓库探测只能给出带证据的建议；外部 Skill 永远低于系统、组织、项目与用户规则；发现不等于信任，评分不能绕过许可证、路径、symlink、恶意指令、完整性和审批门禁；控制面保持 Python 3.9+ 标准库且不固定业务技术栈；所有网络、文件数、字节、分页、超时与输出有界；核心控制 Skill 可内置，项目/领域 Skill 不得固化。
- Data and permissions: 仅按需读取公开 GitHub repository metadata、pinned blob、LICENSE/NOTICE，可选 GITHUB_TOKEN 只从环境读取且不得输出或落盘；第三方内容进入 quarantine，默认只允许 UTF-8 Markdown 与许可证文本且绝不执行；GitLab 推送使用当前个人凭据和用户本轮明确授权，不处理生产凭据或真实业务数据。
- Target environment: local
- Context transport: native
- Acceptance: 使用完全离线的伪 GitHub fixture 验证用户未确认时拒绝 Skill 解析、确认后确定性评分、硬门禁、commit/file lock、原子安装、verify/update/retire；验证知识 owner/Issue 模板/双 CI 生成；运行新增定向测试、python3 tests/run_all.py、fresh install/check/update 生命周期、agentctl validate、运行时 cleanup/assert-clean，并检查最终 Git diff 与远端 push。
- Provenance: user request: 抽取通用 workflow、动态从 GitHub 拉取并评分 Skill、模板化知识/Issue/CI、支持自我迭代并推送到同一 GitLab group；user correction: 不固定技术栈，必须由用户自己选择设计并确认，随后才按其选择匹配 Skill。
- Production provider target: none
- Human decisions: user:不固定技术栈；由用户输入并确认设计后再选择最合适 Skill，完善独立通用模板并推送
- Clarified: true
