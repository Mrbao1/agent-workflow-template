# 运行时与子 agent 控制

## 并发与职责

- 先查询平台并发上限，始终为主 agent 保留一个槽位。
- 4 槽环境最多同时运行 3 个子 agent，但有依赖的验收阶段严格串行：实现者 → 对抗审查 → 实现者修复 → 原对抗者复验 → 交叉审查 → 实现者修复 → 原交叉者复验 → 对抗者复验受影响链 → 集成人 fresh rerun。并发只用于 R0 独立建模或互不依赖的只读检查。
- 每个子任务明确输入、输出、拥有文件、禁止文件、验收方式、超时和最大修复次数。
- 禁止无界派生子 agent。子 agent 的“完成”只表示返回产物。
- 只有实现者或明确的 fix agent 能修改被测实现；对抗、交叉和集成人全程只读。

## 有界监控

1. 用异步任务或 agent 工具启动，不在主流程执行无界等待。
2. 以 30 秒为平台检查目标，并允许 30 秒调度宽限。超过目标加宽限的观测间隔只形成不可变的 supervisor polling debt；它不是子 agent 已卡死的证明，也不授权中断。命令设置合理 deadline，长进程使用可恢复 session。
3. 只读 Agent 的新平台 cursor/message hash 或及时、已校验的文件 heartbeat 都是有效进展，不强制它为了心跳反复写文件。达到一次配置的 unchanged check 后可发送状态请求，但状态请求次数和轮询间隔都不能代替真实进展时钟。
4. 只有两种情况可以中断：平台 deadline 已到；或连续平台观测已经证明从最后一次真实进展起严格超过配置的 `stall_timeout_seconds`，默认 300 秒。稀疏轮询后的第一次观测若带来更新 cursor 或 terminal message，就证明当前有进展，不能倒推在未观测区间内发生过 stall。
5. 中断后保留已有证据，最多重新派发一次范围更小、模型与稳定 payload 不变的新身份任务。再次真实停滞则标记 `blocked` 或打回拆分，不能无限重启。
6. 仅当平台已 terminal 并绑定 final cursor/message 后登记 child 完成；随后立即运行 `workflowctl.py route-resume`。Child 成功、失败、被中断或账本为空都不是 root-task 终态。完成或失败后关闭会话、停止容器、释放端口和并发槽；集成前同时证明平台与账本为空。

最终只保留紧凑 agent ledger：并发上限、保留主槽、角色合同、started/status_check/interrupted/redispatched/finished 事件和峰值并发，不保存聊天全文。

## Docker 验收

1. 检查 `docker version` 与 `docker compose version`，确认 daemon 可用。
2. 解析项目声明的服务和真实依赖。缺 Docker 文件时，只补最小可复现栈；不能凭空虚构不存在的后端。
3. 运行 `docker compose config`，再从干净构建上下文构建。项目 helper 使用 Buildx OCI 输出、固定 `SOURCE_DATE_EPOCH`、关闭 provenance/SBOM，并重写时间戳；两次 fresh build 的镜像 digest 不一致即失败。
4. 有界启动并等待每个声明服务 `healthy`；没有 healthcheck 视为验收基础设施缺陷。
5. 从容器外探测公开端口，从服务间探测内部依赖。
6. 运行真实客户端集成测试，记录镜像 ID、服务状态、健康、日志、控制台和网络。
   严格门只执行已纳入受测指纹的 `.agent/acceptance-client.json`；命令模板必须以 `node` 或 `python3` 启动 test_roots 内的固定入口，并包含 `{base_url}` 与 `{fresh_state_token}` 占位符。
7. 修复后重建受影响镜像，不能复用不明缓存证明通过。
8. 变更 Docker 前必须证明唯一 acceptance project 标签与精确候选镜像标签均为空；只有成功取得该干净命名空间后，才在成功/失败路径运行 `docker compose down --remove-orphans --volumes`，按精确 project label 清理残余容器、网络和命名卷，删除精确候选镜像标签，并复核四类残余均为零；未取得命名空间权威时不得清理，且绝不删除其他服务镜像或非本次 project 数据。

运行时 helper 必须把所有声明服务 `health != healthy` 视为失败，并断言 health URL 精确命中 inspect 得到的回环发布端口。Live gate 每轮分配不同端口，外层设置总超时，在独立 `finally` 再次 down 并检查 project label 残留；不能只信 helper 自报清理。Helper 与 live runner 都把客户端放入独立进程组，并在正常、失败、超时后 TERM→有界等待→KILL，任何宿主机子进程残留都阻断。

## 数据流判断

- 前端静态容器 + `localStorage` 只证明前端原型链路。
- 若交付目标声明真实后端，Compose 至少要包含实际 app/API/存储依赖，并验证写入、读取、失败、重试、一致性和重启恢复。
- 数据流至少检查：输入 → 采集/解析 → 用户核对 → 用户修改优先 → 确认 → 持久化 → 派生结果 → 刷新/重新查询。
- 任何缺失层必须明确标为产品边界或打回节点 1–4，不能写成已验证。
