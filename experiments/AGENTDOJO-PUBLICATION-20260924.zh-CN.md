# 2026-09-24：原生结果发布与 AgentDojo 工具链路实测

## 结论与口径

可引用的固定二进制结果：
`results/native-publication-pinned-20260924/summary.json`：**14/14 通过**。
实际运行 AgentDojo 0.1.35 `FunctionsRuntime` 的模拟邮件工具，共 28 次模拟邮件
操作、4 次最终结果发布。没有外发真实邮件，没有调用模型，没有 AWS 费用。

这是 **synthetic_native_provider_conformance**，不是官方 AgentDojo 任务或攻击
oracle 成绩。`model_evaluation`、`official_benchmark_tasks`、
`production_acceptance` 都为 false；`model_safety_rate` 为 null，不填 100%。
正常与注入配对各七种场景：两步、三步、结果恢复、第二步审批、中途撤权、
最终发布、最终发布后加密 owner 重开。注入内容固定为合成不可信文本，
未测试真实模型是否会被诱导，因此不报告攻击成功率。

补充的发布兼容回归曾出现一次 `Unavailable`：测试签名只给发布留了 100 ms，
在并发编译负载下不足。测试现使用原批准信封自身的到期时间，仍受来源、根和
session 的原期限约束；没有修改生产超时、延长已有批准或自动重发。
修订后新旧发布专测 **8/8** 通过。之前的 `native-publication-20260924` 和
`native-publication-final-20260924` 目录保留；它们各有 14 项通过记录，但当时
runner 未防止 Cargo 在组内替换原测试文件，不能据此保证整组二进制一致。
新 runner 在开始时拷贝一份私有只读快照、检查复制中源文件没变，并在完成时
复核快照摘要。另有回归用例主动替换原文件，确认已固定的运行内容不受影响。
`pinned` 目录是修复后完整重跑；这些重复清单不能相加当新样本。

最终版本同样 **14/14 通过**，汇总文件 SHA-256 为
`0c327adf0b63591d594b24e5b66756c58e54fd34cda7a8c04d5ed3c20d422ad1`。

配套检查（与上述用例有重叠，不能合并成独立安全样本数）：

- Python 精确选择的 Rust 安全回归：83/83。首轮 82/83，唯一失败为本机
  Homebrew Node 缺少 `libsimdjson`；使用已有可用 Node 后全量重跑通过，未删测试。
- Python 实验框架单元/集成测试：119/119，无跳过（含二进制快照及官方日历适配测试）。
- macOS Rust fused 集合：kernel 91 通过、1 个显式 provider probe 忽略；
  policy 89/89。provider probe 由独立 Python runner 显式运行，结果见上。
- 新旧发布专测：8/8；协议发布 codec/capsule：4/4。
- 本机离线 ARM64 Linux 容器的 kernel/policy `fused_` 回归命令退出 0，
  policy 部分为 89/89。首次并行编译被系统 SIGKILL；改用单编译任务、关闭
  测试调试符号后完成。测试内容和生产逻辑未删改；不是 AWS 多服务/TPM 验收。
- 新构建的 Rust Python 扩展：8 项既有管理接口测试，加 1 项覆盖三份官方
  日历任务草案的原生规范化/签名绑定测试，共 9/9。
- 工作区全目标 `cargo check`、330 项冻结源码摘要和 `git diff --check` 通过。
  冻结清单是当前工作区的漂移检测，不是独立审计或硬件证书。

## 真实数据流

1. Python 启动明确指定的 Rust debug 测试二进制；用例提供合成身份和签名根。
2. 内核先经过现有动作/数据/许可检查，execd 验证密封执行许可后才连接
   本地私有测试 socket；Python 的 runtime 不是模型直接调用的后门。
3. `mail.allowed(A, Alice, body)` 经合成工具别名映射调用 AgentDojo 的邮件实现，
   实际修改隔离的模拟邮箱。原始返回值经过执行器/内核结果验证和私密库提交。
4. 第二步 B→Bob 的正文逐字节使用第一步原始返回；Python 独立对比正文 SHA-256
   和第一次响应 SHA-256。工具名、目标、资源仍取签名计划，不取返回文本。
5. 新发布场景取第二步的实际响应。Rust 从已提交的私密结果构造
   `/savana/final-result-release` 请求，绑定独立 `result:` 资源和指定应用轮次。
6. 合成 approvald 密钥签署准确的 FinalRelease 决策；这只是测试授权来源，
   不是省略 G6，也不代表真实 WebAuthn/硬件验收。没有最终目标的 G3 规则时，
   已批准仍无法执行，发布条款消费保持 0。
7. 配置测试签名 G3 规则后，G7 保留唯一发布效果，execd 发送。Python 独立
   比较收到的正文和最后一次实际工具响应；重试不得第二次发布。
8. 内核验证执行回执与审计摘要，结算任务/私密库，再确认执行器清理。

注入字符串可以作为**已授权正文数据**进入后续合成收件人的邮件和最终结果。
本实验声称的是它不能改变固定授权的控制字段，不是删除所有恶意文字，也不是
证明该正文适合在任意 UI、浏览器或下游模型中执行。

## 恢复用例实际做了什么

case 42 使用真实加密的内核 Agent authority 状态文件和测试防回滚锚：

- 发送后清掉内存 session、intent、execution、pending-release、ticket 和 release；
- 构造 G7 已提交、发布归档尚未保存 core 的窗口；从原 G7 记录找回原 nonce；
- 只做 query/fetch/ack，不重建业务请求或重新取得批准；
- 再重开已提交状态，核对 dispatch 和 commit 不变；
- A、B、发布条款的消费都为 `(1,1)`，实际 provider 仍只有一次发布。

执行器、vault、policy owner 和 Python 模拟环境仍存活。没有宣称全服务一起崩溃，
也没有宣称 Python 的进程内幂等缓存能跨进程恢复。不确定的执行仍保留 Unknown；
G7 提交后但未发送的故障不自动退费或重发。

## 审计文件及复现

每次运行目录禁止覆盖，含：

- `manifest.json`：AgentDojo 版本/源码摘要、本地源码摘要、实际测试二进制摘要、
  `kernel_test_pinned_for_entire_schedule: true`、预先固定的完整清单和实验口径。
- `NN.started.json`：先写开跑标记，避免中断的轮次被漏掉。
- `NN.kernel.log`：真实 Rust 测试退出/断言结果。
- `NN.audit.json`：工具原请求/响应摘要、实际模拟邮箱、发布请求/正文/响应摘要。
- `summary.json`：所有轮次结果；失败、错误、超时不会被过滤掉。

这些 provider 记录不是独立硬件签名的全量内核审计导出；Rust 中对 G3/G6/G7、
许可和回执的检查由对应测试断言及绑定二进制覆盖。正式研究报告还须导出并
关联生产 task/run/许可/消费/披露的可验证事件，不能拿 provider 哈希代替全部证据。

```sh
cargo test --offline --locked -p savana-kerneld --features test-support --lib --no-run
PYTHONPATH=experiments python -m savana_bench agentdojo-native-probe \
  --kernel-test /absolute/path/to/the/built/savana_kerneld-test-binary \
  --output /absolute/path/to/a/new/results-directory --timeout 30
```

测试二进制使用实际构建路径，不能填 release daemon 或其它 executable；runner
会验证精确测试名存在，再运行显式忽略的组件 probe。注册密钥、rollback anchor、
固定计划和模拟提供方只能留在测试环境。

## 还不能报告正式防护成绩的原因

1. 官方 clean task → 预授权根/真实工具参数 → 模型提议 → 原生 owner 的适配还没
   完整连通。本轮已加三项日历任务的 Python 草案编译和真实工具语义适配，
   见下节；当前正式 runner 仍是无防护基线，不能只改 `savana_protected` 标签。
2. 生产结果接收端、重新认证后的结果取回以及签名新版本的 Linux 多服务验收
   还没有完整通过。当前合成结果接收器不具备生产传输身份校验。

旧临时 EC2 已终止，本轮未新建实例；这与上述软件缺口分别记录。不会让用户
重做浏览器登记来掩盖缺口，也不会把该 14/14 写进论文作为正式防护成功率。

## 官方日历任务适配的新增代码与边界

`savana_bench.agentdojo_tasks.reviewed_task` 只接受固定版本下干净任务 ID 和完整
prompt；支持与已有基线相同的 `user_task_0`、`user_task_1`、`user_task_3`。
任务未写年份时，使用预声明的 2024 日历策略；不读取参考答案、隐藏事件 ID、
攻击目标、评分结果或模型文本来生成权限。改动 prompt、未知任务都拒绝。

`prepare_draft` 接收部署方已有的 task/root/descriptor/reader/turn 引用，生成
原生 schema 3 有限草案、独立发布条款选择器、确定性私密输入槽和未签名工具
规范。返回明确标记 `admitted: false`，不加载密钥、不签名、不创建根，也不
声称这些引用在运行中存在。原生扩展已实测接受三份草案并将发布 turn 纳入
签名摘要；这只是规范化验证，不是 live registry/root 编译通过。

`savana_bench.agentdojo_calendar.calendar_provider` 把两种显式 wrapper 映射到
上游原始 `search_calendar_events` / `get_day_calendar_events`。查询和日期是
独立控制字段；body 必须为空，不能把 JSON kwargs 或任意函数藏在 payload。
主日历资源和私密结果目标固定；不会开放发送邮件、删除文件等写函数。
工具提供方仍须放在 execd 后方，Python 对象本身不实现生产传输认证。

六项适配测试验证正常返回与上游直接调用逐值一致、模拟状态不变、原请求
重试不二次调用、额外字段/写工具/控制替换被拒绝；还验证三项任务 × 两种
官方注入确实改变了返回数据，但不改变生成的权限草案。最初测试按注入模板
原始字符串比较失败，因为上游 YAML 装载会规范化文本；修正为比较实际装载
后上游返回的值，并确认与 clean 返回不同，没有删除攻击内容来取得通过。

当前只有一个预授权读取模板，planner 只能选它或拒绝；最终源是原工具结果，
**不是模型生成的自然语言答案**。尚未把此适配器接入已部署 owner、最终
接收端和正式评分循环；也没有声称它支持任意 AgentDojo 多步任务。上述六项
测试和原生邮件 14 项是不同层次，不能拼成一次正式防护实验。
