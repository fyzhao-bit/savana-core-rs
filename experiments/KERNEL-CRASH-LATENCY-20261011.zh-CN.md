# 崩溃矩阵与中介延迟（2026-10-11）

**问题：** 审稿意见要求两组数：(1) 崩溃矩阵——在持久化管线的每个关键点把进程杀掉，
重启后有没有"坏状态"（重复效果、丢失效果、卡住、无法恢复）；(2) 每次工具调用的中介开销，p99 应在几十毫秒量级，
并且相对模型推理只占小比例。

**结论：**

- **崩溃矩阵：461 次试验（460 次 SIGKILL），0 个坏状态。** 同一 execution nonce 的 provider 请求最多 1 次；
  崩溃后内核重发原派发、再重启一次，都没有再次触达 provider。
- 论文列出的执行器日志四步——attempt 记录落盘、effect-started 回执、首个 provider 字节、响应加密落盘——
  分别有 **53 / 42 / 28 / 60** 次试验，**全部 0 个坏状态**。
- **中介延迟：每次工具调用 p50 58.8 ms，p99 85.1 ms**（与评测主机相同的构建：opt-level 1、开调试断言），
  opt-level 3 下 p50 53.3 ms、p99 75.7 ms。同期 `deepseek-flash` 一次调用的中位数是 1.0–1.9 秒，
  所以中介开销的 p99 不到最快的一类模型调用中位数的 10%。
- 发现两处与论文描述不符，见"发现"一节：执行器把"尚未发出字节"的 attempt 也判为 Indeterminate（保守），
  论文写的"内核侧恢复状态机"在代码里没有接入。

## 一、崩溃矩阵

### 做法

每次试验在一个**子进程**里跑一次真实的 fused 派发：G4/G5/G7、密封信封、Suite-1 IPC、execd 加密日志、
worker 校验，与 `fused_private_g7_success_and_legacy_cache_isolation`（case 0）同一条路径。
执行器日志和它的回滚锚放在磁盘上的试验目录里，子进程在下列某一点被 **SIGKILL**（不跑析构、不刷缓冲）：

| 杀进程的位置 | 含义 |
| --- | --- |
| `before:n` | 第 n 次日志提交已落盘，回滚锚尚未前进 |
| `after:n` | 第 n 次日志提交和回滚锚都已落盘 |
| `provider` | provider 已收到请求（效果已发生，先 fsync 记一笔），执行器还没拿到响应 |
| `random` | 父进程在派发开始后的随机时刻杀子进程（splitmix64，可复现） |

父进程随后按守护进程的启动顺序重开日志：**先跑启动恢复**（`recover_prepared_with_connector_registry`），
再开始服务；然后把内核当时发出的那条派发**原样重发一次**（内核没收到回复时会这样做），再**重启一次**。
全程统计 provider 收到的请求数。

一次完整派发有 6 次日志提交（接收、attempt、effect-started、响应、完成、确认）。
每个提交点的 `before`/`after` 各 20 次，`provider` 20 次，`random` 200 次，另有 7 次枚举探针。

**坏状态**（运行前在测试里写定）：同一 nonce 的 provider 请求超过 1 次；崩溃后重发派发或再重启又触达 provider；
恢复后仍停在进行中状态；provider 已收到请求却记为"确定无效果"（FailedNoEffect）；
没有效果却记为完成；有效果却没有日志条目；条目多于一条；日志无法重开。

### 结果

| 重启时日志里的状态 | 对应步骤 | 试验数（杀的方式） | 恢复后 | provider 请求数 | 坏状态 |
| --- | --- | --- | --- | --- | --- |
| Prepared | 已接收，尚未开 attempt | 62（after 20、before 20、random 22） | 完成 62 | 1 次：62 | 0 |
| ProviderAttemptPrepared | **1. attempt 记录落盘** | 53（after 20、before 20、random 13） | 不确定 53 | 0 次：53 | 0 |
| EffectStarted | **2. effect-started 回执已存** | 42（after 20、before 20、random 2） | 不确定 42 | 0 次：42 | 0 |
| EffectStarted + 已发请求 | **3. 首个 provider 字节已发** | 28（provider 20、random 8） | 不确定 28 | 1 次：28 | 0 |
| ProviderResponseRetained | **4. 响应已加密落盘** | 60（after 20、before 20、random 20） | 完成 60 | 1 次：60 | 0 |
| CompletionAvailable | 完成已记录 | 84（after 20、before 20、random 44） | 完成 84 | 1 次：84 | 0 |
| Acknowledged | 内核已确认 | 41（after 21、before 20） | 已确认 41 | 1 次：41 | 0 |
| （无条目） | 执行器尚未接收 | 91（random 91） | 无条目 76、完成 15 | 0 次：76，1 次：15 | 0 |

读法：

- **尚未开 attempt 的派发**在恢复时继续执行，恰好一次——此前没有任何字节发出，所以这是安全的续跑，不是重试。
- **开了 attempt 以后、没有留存响应的**一律记为不确定（Indeterminate），**从不自动重试**。其中 28 次 provider 确实收到了请求，
  另外 95 次没有。
- **响应已落盘的**从留存的密文解码完成，不再联系 provider。
- **随机杀进程**的 200 次里有 91 次落在执行器接收之前：派发的大部分时间花在内核侧的 G6/G7。
  其中 15 次内核已经发出派发、执行器还没落盘；重发后执行器第一次执行它，provider 收到 1 次请求。
- `before:n` 与 `after:n` 的结果完全相同：日志比回滚锚多一步时，重开会按"序号 +1 且前驱摘要相同"的规则接受它。

### 发现

1. **"尚未发出字节"也被判为不确定。** attempt 记录已落盘、effect-started 回执还没写时，协议保证没有发出任何字节
   （回执先于首字节落盘），本可判为"确定无效果"并允许重新规划。执行器的恢复（`connector_runtime.rs`）
   把它和 EffectStarted 一样记为不确定。这不影响安全（不重试、不丢效果），但这类动作需要 owner 处理，是可用性代价。
2. **论文描述的"内核侧恢复状态机"没有接入。** `crates/savana-kerneld/src/v2_recovery.rs` 标了
   `#[allow(dead_code)]`，没有任何调用方。实际运行的恢复是：执行器启动时先恢复再服务，内核的 fused 恢复驱动
   按 execution nonce 查询执行器并对账（`restore_fused_execution_queries_v04`、`tick_fused_recovery_v04`），
   不会为同一条款重新签发 nonce。这段死代码与实际行为还有两处不一致：它把 ProviderAttemptPrepared 判为
   "执行前中止"（FailedNoEffect），而执行器判为不确定；（Prepared 或 Dispatching，执行器 EffectStarted）
   没有匹配分支，会返回 Contradiction。论文需按实际路径改写。

### 局限

- **进程被杀不等于断电。** 页缓存仍在，掉电下的 fsync 语义没有验证。
- provider、worker 和回滚锚是测试替身：锚是磁盘文件，不是 TPM。
- 内核与执行器在同一个子进程里一起被杀；内核自己的持久状态没有重开（fixture 不支持）。
  所以这个矩阵检验的是执行器的 P5（同一 nonce 至多一次 provider attempt）以及内核重发派发时的行为。
  内核侧的崩溃边界另有进程内的故障注入测试（G7Prepared、VaultCommitted、OutcomeCommitted、ResultCheckpointed），
  每个都断言 provider 请求恰好 1 次。
- debug 构建；这里只看正确性，与时序无关。

## 二、中介延迟

### 做法

同一条 case 0 路径，进程内运行，每个样本新建一份 fixture（预算是一次性的），只给四个内核调用计时：

| 阶段 | 包含 |
| --- | --- |
| `kernel.g4_prepare` | G4：匹配 owner 授权、选定七个控制面、加密持久提交 |
| `kernel.g5_evaluate` | G5：本体论、验证器、意图流下限、加密持久提交 |
| `kernel.g6_g7_dispatch` | G6 授权、G7 解密级检查、注册表同步、持久准备、密封、签名、Suite-1 IPC，**以及执行器的全部日志工作** |
| `kernel.reconcile_completion` | 取回完成、写结果库、提交结果、确认（含执行器的取回和确认） |

每次持久提交都加密整份状态并 fsync（临时文件 fsync → rename → 目录 fsync），文件在 ext4（`/dev/vda`）上，不是 tmpfs。
IPC 是同机 Unix socket 上的完整 Suite-1 握手。测试 fixture 的执行器服务器每 2 ms 轮询一次 accept，
一次调用有 4 次 IPC，平均约多算 4 ms；这是测试夹具的等待，我们没有扣除（该文件在冻结清单里，不改）。
provider 立即应答，不调用模型。1000 个样本，前 3 次预热不计。

两种构建：`integration`（评测主机上守护进程用的就是它：opt-level 1，保留调试断言和溢出检查）和
opt-level 3（同样保留调试断言；`test-support` 不允许关闭它）。

### 结果（毫秒）

| 阶段 | integration p50 | p90 | p99 | 最大 | opt-level 3 p50 | p90 | p99 | 最大 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| G4 准备 | 4.2 | 6.0 | 8.6 | 32.3 | 3.6 | 5.1 | 6.6 | 33.1 |
| G5 评估 | 3.5 | 4.9 | 6.2 | 224.9 | 3.0 | 4.3 | 5.8 | 19.5 |
| G6/G7 派发（含执行器） | 29.1 | 36.3 | 44.8 | 104.9 | 25.6 | 32.1 | 40.2 | 45.5 |
| 　其中执行器处理派发 | 11.7 | 14.8 | 21.4 | 88.5 | 11.0 | 13.9 | 20.0 | 33.5 |
| 完成对账（含执行器取回和确认） | 21.5 | 26.7 | 31.9 | 58.7 | 20.1 | 25.0 | 30.8 | 48.1 |
| **每次工具调用合计** | **58.8** | **71.3** | **85.1** | 298.4 | **53.3** | **65.1** | **75.7** | 90.4 |

integration 一列的最大值 298 ms 是单个样本：它的 G5 一步用了 225 ms，而 G5 其余 999 个样本都不超过 9.1 ms。合计第二大的样本是 134 ms。

**开销主要是持久提交，不是计算。** 从 opt-level 1 到 3 中位数只降了 9%。这台机器上一次原子替换
（64 KiB，fsync 文件 + rename + fsync 目录）中位数 1.06 ms、p99 2.25 ms；一次工具调用里，
执行器自己就有 6 次这样的提交，内核侧还有 G4、G5、G7 准备和对账的多次提交。

### 与模型推理对比

同期 CaMeL 在 AutoDojo 上的 6,172 次 `deepseek-flash` 请求（同一个模型、同一时段）：

| 调用 | 次数 | p50 | p90 | p99 |
| --- | ---: | ---: | ---: | ---: |
| 规划器大小的提示（约 36 KB） | 4,045 | 1.91 s | 3.57 s | 6.98 s |
| 小的抽取提示 | 2,127 | 1.01 s | 1.35 s | 2.08 s |

每次工具调用的中介开销 p99（85.1 ms）不到最快一类模型调用中位数（1.01 s）的 10%，中位数（58.8 ms）约 6%。

**这不是端到端延迟。** 部署后的一个回合还包括模型调用、owner 审批往返，以及内核驱动每秒最多推进一次的节流
（刻意的速率限制）。[此前的测量](KERNEL-PERF-20261001.zh-CN.md)里，一个"读 → 派生写 → 发布"回合约 17 秒，
主要花在这些地方，而不是中介本身。

### 局限

- 进程内测量：内核与执行器在同一进程，IPC 走本机 Unix socket。
- 回滚锚是内存替身。生产用 TPM 锚，每次提交还有一次 TPM 操作，没有计入；评测主机用的也是文件锚。
- 不含模型调用、审批等待和驱动节流。

## 证据与复现

运行目录 `experiments/results/crash-matrix-20261011/`（不入库）：

| 文件 | sha256 前 16 位 |
| --- | --- |
| `trials-boundaries-random.jsonl`（461 次试验） | `da20bd161e5356cc` |
| `mediation-latency-integration.json` | `0628c363eeea6de6` |
| `mediation-latency-opt3.json` | `32595efc82942950` |

```
# 崩溃矩阵（debug 构建即可；每次试验一个子进程）
SAVANA_CRASH_MATRIX_TRIALS=20 SAVANA_CRASH_MATRIX_RANDOM=200 \
SAVANA_CRASH_MATRIX_OUT=trials.jsonl \
  cargo test -p savana-kerneld --lib --features test-support -- \
  --ignored --exact v2_agent_authority::tests::fused_compiler_tests::fused_crash_matrix_v04
python -m analysis.crash_matrix trials.jsonl

# 中介延迟（与评测主机相同的 integration 构建）
SAVANA_LATENCY_SAMPLES=1000 SAVANA_LATENCY_OUT=latency.json \
  cargo test -p savana-kerneld --lib --features test-support --profile integration -- \
  --ignored --exact v2_agent_authority::tests::fused_compiler_tests::fused_mediation_latency_v04
```

代码：`crates/savana-kerneld/src/v04_fused_crash_matrix_tests.rs`、`v04_fused_latency_tests.rs`；
执行器侧的文件锚、崩溃点和按守护进程顺序先恢复再服务的重启在
`crates/savana-execd/src/intent_bound_test_support.rs`（仅调试构建）。
