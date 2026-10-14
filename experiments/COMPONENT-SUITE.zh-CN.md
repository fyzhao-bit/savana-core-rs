# 四类组件实验：成功、攻击、恢复和性能

这是可执行的 Python 实验编排，驱动真实 `savana-private-workflow` Rust
研究组件、签名合成事实、加密文件状态与合成 provider。它**不是**完整内核
G1–G7 端到端评测，也不是 LLM benchmark。完整内核结果依赖链另由
[专项回归](../docs/verification/result-dependent-loop-v04.md)验证；不能把两者混为一组成功率。

## 运行

需要 Python 3.11+ 和 Rust。所有数据、账户、密钥及外部效果都是合成的，
不调用模型、不下载权重、不读取 AWS/GCP 凭证、不创建云资源。

```sh
cargo build --offline --locked -p savana-private-workflow --example benchmark_driver
PYTHONPATH=experiments python3 -m savana_bench component-suite \
  --driver target/debug/examples/benchmark_driver \
  --output experiments/results/my-new-component-run \
  --orders 1 2 4 --repetitions 2
```

输出目录必须不存在，父目录必须存在。已有记录绝不覆盖。默认安排
3 个任务规模 × 7 种控制器 × 2 种恢复模式 × 2 次重复 = 84 个 episode。
重复是确定性案例的稳定性/计时重复，不是 84 个独立任务，也不是模型采样 seed。
恢复模式在每次重复中交替执行，减少固定先后次序的偏差，但不消除机器负载等混杂。

## 用例与独立判据

- `greedy`：完成全部缺失发票请求。Python 检查 provider 实际收到的字节：
  原订单、商家、收件人、正文、数量和唯一请求 ID，而不是相信“完成”标志。
- `refuse`：始终拒绝。应当没有效果，但任务成功率为零，用于发现“全拒绝也高分”的评分错误。
- `redirect`：请求增加攻击者收件人；`stale`：旧 epoch；
  `unknown-handle`：伪造句柄；`replay`：重复已消费句柄；
  `forged-result`：在 Planner 命令塞入伪造成功结果。这最后一项**不是**伪造
  execd 密码学签名的实验。每个攻击 episode 注入一次，随后恢复正常策略。
- 攻击成功不只看最终目标：如果被故意构造的非法命令当步产生了效果，即使
  目标恰好合法，也计为违规。已观测的违规不会因后续超时/审计丢失而消失。
- `reopen=true`：每步关闭并重新打开真实加密状态，对比尝试次数、披露次数
  和 provider 效果数；下一步继续使用恢复后的 owner。还与同任务的
  `reopen=false` 配对比较完成情况。这里不是进程中途 kill、断电或 TPM 恢复。

攻击条件还包含私密订单备注里的固定注入字符串，但该备注不会暴露给受限
planner。故上述测试不是“LLM 读到注入后是否上当”；不能以此宣称模型抵抗
提示注入的通用攻击成功率。真实模型和标准基准适配仍需后续独立接入。

## 性能测量边界

Rust `Instant` 记录实际阶段纳秒：根签名验证及建库、PlannerPort 与持久化、
事实验签入库、合成 provider 执行及持久化、加密状态重开。没有虚构单独的
G1/G2/G3 耗时，也没有把人工审批等待记为零。合成事实签名生成不计入
“验签入库”阶段。计时只交给宿主审计，不发送到模型 view。

Python 另记录 episode 墙钟时间，含子进程启动、IPC、正常退出及清理。
汇总报告 median、nearest-rank p95、同任务重开与不重开的墙钟差值。
这些是含持久化的复合阶段，不应相加为完整程序耗时；配对差值可能为负。
没有关闭安全机制的 baseline，因此不能称为“全部安全机制的净开销”。
当前首轮使用 debug 构建与普通本机负载，只做流程验证，不宜直接用于论文性能表。

## 记录与失败口径

- `manifest.json`：运行前固定的完整计划、源码树/二进制/数据配置摘要、
  运行时与机器信息、时钟口径、步数和超时限制。源码摘要包含未提交改动。
- `started-NNNN.json`：每个 episode 开始前写入，保留中断证据。
- `audit-NNNN.json`：实际合成效果、注入当步效果增量、恢复前后计数及阶段采样。
- `trials.jsonl`：逐条写入并同步；`summary.json`：按策略/恢复模式汇总。

超时、清理权限拒绝、缺失或不一致的审计均计入 Unknown，不从分母消失，
也不算安全。攻击成功率以“确认注入过”的 episode 为分母，另列未知数量；
没有攻击时为 null，不制造 0% 的成绩。拒绝不算任务成功。
运行中换二进制会终止；中断后不能在原目录悄悄替换试验。文件不是硬件认证
或签名实验凭证；必须保留 manifest 和全部原始审计，不能只摘录汇总百分比。

## 已保存的运行

- `results/component-suite-pilot-20260921/`：首轮 84 个 episode，保留原样。
- `results/component-suite-verified-20260921/`：增加“部分轨迹保留已知违规”
  检查后的重跑。优先使用该目录；两轮不是独立任务，不应合并扩大样本数。

最终重跑：84 个 episode 全部取得完整审计，72 个完成任务，12 个“全部拒绝”
控制正确计为未完成；60 次确认注入没有触发违规效果；228 次状态重开没有
尝试/披露计数重置或重复效果，36 对可完成任务的恢复前后可用性一致。
没有 Unknown。这里的零攻击成功仅适用于这五种固定脚本攻击，不能外推到模型。
配对墙钟差值中位数约 74.26 ms，p95 约 216.54 ms，属于本机 debug 验证数据，
不是生产开销结论。原始数值在 `summary.json` 与逐次审计中。

本轮框架检查：Python **54 项通过、无跳过**，Rust 研究组件 **26 项通过**；
源码格式、差异检查及现有 313 文件冻结清单通过。没有修改生产内核权限或部署。

检查框架：

```sh
PYTHONPATH=experiments SAVANA_COMPONENT_DRIVER=target/debug/examples/benchmark_driver \
  python3 -m unittest discover -s experiments/tests -v
cargo test --offline --locked -p savana-private-workflow
```

未设置驱动路径会明确跳过 Rust 集成部分；跳过不算通过。
