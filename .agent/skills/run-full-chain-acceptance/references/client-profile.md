# 固定客户端 Profile

节点 5 必须生成真实测试入口，并在受测指纹中包含 `.agent/acceptance-client.json` 与入口文件。最小 profile：

```json
{
  "schema": "acceptance-client-profile/v1",
  "web_baseline": true,
  "command": [
    "node",
    "tests/full-chain.mjs",
    "--base-url",
    "{base_url}",
    "--fresh-state-token",
    "{fresh_state_token}"
  ]
}
```

限制：

- 解释器只能是 `node` 或 `python3`，不能是绝对路径、shell、`-c` 或下载型 runner。
- 第二个参数必须是 Acceptance plan `test_roots` 内、指纹清单中的测试文件。
- URL 与 token 只能由 live gate 注入；报告中的 argv 不会被执行。
- 测试必须清理该 origin 的浏览器存储、cookie、缓存和服务端测试数据，再执行全部 Case。
- stdout 只输出一个 JSON object：

```json
{
  "schema": "acceptance-client/v1",
  "passed": true,
  "fresh_state_token": "live-...",
  "state_reset": {"performed": true, "residual": 0},
  "case_ids": ["CASE-001", "CASE-002"],
  "assertions": [
    {"case_id": "CASE-001", "name": "用户修正值被持久化", "passed": true},
    {"case_id": "CASE-002", "name": "刷新后派生金额一致", "passed": true}
  ]
}
```

`case_ids` 必须精确等于所有 Mandatory Case；任何失败、缺失、额外 Case、token 不匹配或 residual 非零都阻断发布。
