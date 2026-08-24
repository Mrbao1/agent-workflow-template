# Test and Acceptance Matrix

- Normal: 用户确认任意自选架构和技术选择后，候选按蓝图匹配并生成可解释推荐、锁和模板
- Abnormal: 未确认蓝图、GitHub 故障、未知许可证、危险内容、短 SHA、hash 漂移、低分和未批准更新均失败且不产生半安装
- Boundary: 空设计、重复 capability、最大文件字节分页、同分排序、离线缓存、原子替换和退役最后活跃版本
- Permissions / security / compliance: Token 不落盘；外部 Markdown 不执行；路径穿越、symlink、binary、prompt 注入和 shell 指令 hard reject 或隔离
- Performance / compatibility: 网络请求有页数和超时预算；Python 3.9+；无特定项目技术栈依赖；GitHub 与 GitLab 模板均可生成
- Regression: 现有 20 个自测、fresh install、polluted source、installed project、update migration 和 plugin 检查继续通过
- Human acceptance: 用户可看到确认蓝图、每项评分原因、hard gate、Skill 来源 commit/license/hash、演化 diff 和所需确认
- Failure return nodes: 需求变化回 node 1；蓝图和架构问题回 node 4；测试失败回 node 6；安全或供应链不确定停止
