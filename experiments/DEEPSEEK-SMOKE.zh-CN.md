# DeepSeek 服务器组件试跑

本轮暂停前端，直接由服务器 Python 驱动真实 Rust 合成实验。DeepSeek 只扮演
**Planner**，收到封闭 view（epoch、公开句柄、状态），不收到私密事实、执行
审计、根授权或实验 oracle。不能拿此接线把 ReviewView 发送到云端模型。

新增接口：

- `DeepSeekRelay(key).propose(payload)`：本机可信转发器，仅访问官方 HTTPS
  endpoint；密钥不写文件，异常不回显底层响应，不重试。`close()` 清除持有的
  引用，但不声称 Python 能保证物理内存归零。
- `one_trial(..., propose=async_callback)`：回调只收到已校验的 view 与公开
  任务规模/限制，不收到 effects。模型输出仍由原 Rust planner port 检查。
  不能同时传入旧 `model` 执行器配置。
- `python -m savana_bench.remote_smoke --driver ELF --output NEW_DIRECTORY`：
  在服务器运行两条固定合成任务，通过 stdio 的带编号请求/回复接模型。
  该进程不读取 API key。远端请求必须由可信本地 relay 验证后才能外发。

stdio 帧以 `SAVANA_RELAY_V1 ` 开头，后跟 base64 编码 JSON。`proposal` 帧只
包含 `call_id` 和封闭 payload。客户端回复一行 JSON，字段精确为
`call_id, decision, usage, model`。不允许把远端字符串当 shell 命令或 endpoint。
首次不确定结果会停止调用，不自动重发计费请求。此通道仅用于隔离合成实验，
不是向生产 Agent/MCP 提供的新授权接口。

2026-09-24 AWS 记录：`results/deepseek-aws-smoke-20260924/`。
两条任务完成，共 6 次实际 API 调用、1,652 tokens；另有一次 49-token 的
连通性测试。私密备注里的注入没有被披露给模型，所以**不报告模型 ASR**。
正式 AgentDojo 的任务编译、受授权观察/发布及配套 oracle 接线仍未完成。

这轮使用 `deepseek-flash` 服务别名，服务端权重快照不可固定、量化细节不可见，
没有假造模型 revision。结果只能作为接线试跑，不是可直接发表的模型对比表。
