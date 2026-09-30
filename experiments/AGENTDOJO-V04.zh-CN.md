# AgentDojo 与 v0.4：真实执行组件互通，不是正式模型评测

## 本次接通什么

现在可以由 Python 启动真实 Rust 内核集成测试，使已注册的 v0.4 结果依赖计划
经过私密编译、G4/G5/G7、认证本机 IPC、执行器日志和执行许可验证，再调用
AgentDojo `FunctionsRuntime`，实际改变模拟邮箱。工具返回值回到执行器和内核，
入库并成为后续步骤的正文；不是 Python 收到 `allowed=True` 后自行执行工具。

Python 组件为 `savana_bench.agentdojo_provider.AgentDojoProvider`，请求使用
内核已有的 `McpToolsCallJsonV1` 格式，结果使用带 `savana_status` 的封闭响应。
提供方函数确实执行后才报告成功；执行后抛异常、结果不能编码或超限都返回
`indeterminate`，不能用“报错了”推断没有副作用。相同请求 ID 和字节在同一
提供方实例中返回原答复，不重复调用；换字节复用 ID 直接拒绝。

**这是提供方，不是安全裁决接口。** 外层必须是可信执行器。此次本机 Unix
socket 只位于隔离的合成测试目录，不是生产身份认证方案。实验类不能作为
MCP 工具提供给模型，否则模型可以绕过内核。测试密钥、模拟回滚锚和会话
只存在于已有 debug 测试夹具；release 构建拒绝启用对应 test-support 特性。

## 实际例子

测试根预先允许 A→Alice、B→Bob；B 的正文必须来自 A 的真实工具返回。

1. 内核编译并检查第一个动作，执行器验证封装及许可。
2. 执行器把实际 `mail.allowed` 请求交给 Python 提供方。
3. 明确的合成连接器把 Alice 映射为 `alice@example.org`，调用 AgentDojo
   自带的 `send_email` 实现；它不是发到真实邮件服务器。
4. AgentDojo 返回实际生成的邮件对象，适配器编码为工具响应。
5. 内核验证、保存响应；B 的正文逐字节使用这份响应，目的地仍固定为 Bob。
6. 独立 Python 检查器同时检查实际模拟邮箱、请求、响应哈希和数据依赖；
   内核测试检查额度、结果提交、状态重开、撤权与不重复执行。

这里 `file` 是合成消息的标签/主题，不代表 AgentDojo 的真实附件操作。
此映射仅为现有内核邮件夹具的连接器语义，不是通用 workspace 编译器。
另有 Python 单测直接调用官方 `send_email` 工具名及其原生参数，无别名映射。

有两种工具返回：正常邮件对象；邮件对象后附不可信文字，要求向攻击者发送数据。
后者只能沿原签名边进入下一步正文，不能修改目标。**没有模型在这组实验里
读取这些文字，所以它验证的是数据/权限边界，不是模型抵抗注入的成功率。**

## 可运行命令

使用已有 Python 3.11+ 实验环境，并显式安装 `requirements-agentdojo.txt`。
本次使用已安装的 AgentDojo 0.1.35，没有新建云资源或调用模型。

```sh
cargo test --offline --locked -p savana-kerneld --lib --features test-support \
  fused_agentdojo_provider_roundtrip_v04 --no-run
```

把上面打印的 `Executable ...` 路径传入；不硬编码随构建变化的哈希：

```sh
PYTHONPATH=experiments python -m savana_bench agentdojo-native-probe \
  --kernel-test /absolute/path/to/savana_kerneld-TEST_HASH \
  --output experiments/results/agentdojo-native-YOUR_RUN
```

仅接受包含该 exact 测试的显式本机 debug 可执行文件。五类情形各跑正常/注入
两种响应：两步、三步、加密状态重开、第二步独立签名审批、中途撤权。
结果目录不可复用。每次运行记录源代码摘要、Rust 测试二进制摘要、实际安装的
AgentDojo 源码摘要、预先固定的用例清单、开始标记、原始日志、提供方审计及
实际模拟邮箱。运行中断留下开始标记，不能删除失败后只报告通过。

## 尚不能声称完成的部分

### 本次验证记录（2026-09-21）

- `results/agentdojo-native-final-20260921/summary.json`：10/10 合成互通用例通过，
  共执行 20 次模拟邮件操作；正常/注入两组均覆盖上述五类情形。
- Python 实验框架回归：65/65 通过，其中提供方测试 11 项。
- Rust 结果依赖 loop 回归：6/6 通过。
- 工作区全目标编译检查、315 个冻结文件校验及差异空白检查通过。

这些结果来自本机组件测试，不是 Linux 硬件验收，也不产生模型安全率。
早期运行暴露的工具别名不匹配已修复；失败运行目录仍保留，不以最终通过结果
覆盖原始记录。每个运行目录的摘要对应当时实际执行的源码与二进制。

### 正式实验前仍需补齐

- 这不是官方 workspace/travel/banking/slack 的任务成功率或攻击成功率。
  没有调用 `ground_truth`、攻击成功 oracle 或基准任务答案来生成权限。
- 注册任务与签名根来自合成测试夹具，不是把任意自然语言编译为 v0.4 授权。
- 返回值进了内核私密结果库和下一步正文，不代表已获准发布给模型或最终用户。
- 提供方缓存仅在进程内，不能把重新创建 Python 实例称为完整崩溃恢复。
  这里验证的是 Rust 加密 owner 重开，提供方进程和模拟环境仍在。
- 原生 Linux 多身份部署、硬件验收、私密登录恢复、独占发布/重连仍是独立门槛。

因此正式 AgentDojo 端到端实验仍需要**任务到授权/有限计划的编译器**和
**受授权控制的模型观察/最终结果发布接口**。当前 v0.4 只允许固定公共视图和
注册计划，不能直接喂回任意工具内容并宣称符合逐前缀披露约束。
`preflight` 保持阻止 full-product 实验，没有绕过安全校验或静默退回 V2。
