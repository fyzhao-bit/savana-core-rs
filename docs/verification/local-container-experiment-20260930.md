# 本地一次性容器上的软件身份防护实验 — 2026-09-30

本记录承接 [2026-09-29 源码检查点](source-checkpoint-20260929.md) 和
[软件身份实验模式](../../experiments/SOFTWARE-IDENTITY-BENCHMARK.zh-CN.md)。
**不是防护成绩**：所有正式尝试都是 0 个可计分样本、9 个 Unknown。
本次在真实签名部署上找到并修复了五个阻断问题。第一次完成了真实模型规划
（DeepSeek 的提议被内核接受），也第一次完成了执行准备，并通过预授权批准了工具执行。
但工具派发时又暴露出一个尚未接通的部署缺口：内核的 G7 连接器注册表是空的。
这个缺口还没有修。

## 环境与授权

- 这次会话的 AWS 凭证被 AWS 拒绝（`InvalidClientTokenId` / `AuthFailure`），
  没有查询、创建或删除任何 AWS 资源。
- 用户在本会话中选择"本地容器方案"。所用主机是本次云会话的一次性 Firecracker VM
  （Linux 6.18，x86_64），其中运行一个特权 Docker 容器：Ubuntu 24.04、
  systemd 255 为 PID 1，与宿主共享网络（`--network host`）。
- 这是 **B/file-backed 集成配置**，不是 TPM 生产验收，也不是独立主机。特权容器与
  宿主共享内核，隔离弱于 AWS 独立测试机；结果只能标为"容器内 B 档集成实验"。
- 容器内有 root-only 的 `/run/savana-file-backed-disposable` 标记，以及绝对时间的
  `savana-acceptance-expiry.timer`（4 小时后关机）。每次尝试都在全新容器上
  从头安装，从不复用上一次的状态、登记或批次。
- 环境适配（均不改变产品代码或安全约束）：
  - systemd 在容器里不会把根挂载设为 rshared，于是它在子命名空间里创建的服务
    凭证目录传不回来。开机后执行 `mount --make-rshared /`，与真实主机开机时的
    默认行为一致。
  - 把会话出网所需的 CA 证书装进容器的信任库。`fused_deepseek.py` 依然直连
    `api.deepseek.com`，没有加代理。
- DeepSeek 密钥通过管道 FD 交给 `savana-experiment-admin configure-model`，由
  systemd 主机密钥加密保存。没有进入命令参数、文件、日志或本记录。
- 真实 DeepSeek 推理请求一共 6 次，每次 1–2 KiB：
  - 4 次发生在实验运行中（尝试 5、尝试 6、两次诊断运行）；
  - 2 次是在运行之外单独发的：一次原样重放尝试 5 的请求，一次验证修正后的提示词。
  - 另外调用过一次免费的 `/models` 连通性接口。

## Linux 组件复核（非模型实验）

| 项目 | 结果 |
| --- | --- |
| Python 实验回归（Python 3.12，新构建的 SDK，真实 Rust 组件驱动） | 197/197，无跳过；加上本次新增测试后全部通过 |
| `agentdojo-native-probe`（合成用例，无 LLM） | 14/14 |
| `savana_bench regressions`（exact Rust 用例） | 89/89 |
| `deploy/linux/integration/build.py` | EXIT 0，14 个二进制，构建前后源码快照一致 |
| policy-core 库测试 / continuation-core 测试 | 433/433；34 + 19 |
| Rust→Python mTLS 模型 worker 互通（`fused_unix_mtls_python_worker_returns_native_bound_proposal`） | 通过 |
| 容器内已安装包的 Python 回归（运行时包不含 `crates/`） | 185 项中 10 项因缺少 `crates/` 测试夹具而失败；完整检出中这些测试均通过 |

`savana-kerneld` 库测试以 root 运行时会因 "require an unprivileged runner" 失败。
改用非特权用户运行：374 通过、42 失败，失败集中在 server、socket、startup_identity
三组（与进程身份、附加组和 socket 环境相关）。每次修复前后的失败名单都相同，没有新增。

## 正式尝试（每次都是全新主机、单独启用的一次性批次）

| 尝试 | 源码 | 停止阶段 | 原因 | 处理 |
| --- | --- | --- | --- | --- |
| 1 | `643fa5e` | 启动器读取模型凭证 | 问题一 | `119ec35` |
| 2、3 | `119ec35` | `owner_input_commit`（`invalid_response`） | 问题二 | `d8b9b01` |
| 4 | `119ec35` | 同上 | 只用于 strace 诊断 | — |
| 5 | `a56f3bd` | `operator_execution_prepare` | 问题四（模型输出外层格式） | `03cc039` |
| 6 | `03cc039` | `operator_execution_prepare` | 问题五（执行准备读不到原始 owner 文档） | `ce3b3fd` |
| 7 | `ce3b3fd` | `wait_publication` | 未解决：G7 连接器注册表为空，工具无法派发 | 待决定 |

问题三（泄露闸门误拦）是在尝试 3 之后、用诊断构建发现的，修复为 `a56f3bd`，
尝试 5 和 6 已包含该修复。

软件身份在第 2–6 次尝试中都通过了原生 WebAuthn 校验，有限预授权的每条记录都是
`human_review=false`。尝试 5、6 各有 1 次真实模型调用；没有工具执行、没有发布，
也没有评分。**每次尝试都是 0 个已评分、9 个 Unknown。**

已导出运行的离线复核结果（均为 `audit_consistent=true`，重新判分 0 个；
校验时使用该运行部署时的源码）：

- 尝试 2：`43e216abc4454cbf9af635a1c23c6ed1`，审计 head `601537287da53a45…`。
- 尝试 3：`4ef3f5f2f26141d69472284c4e923c13`，审计 head `02e277e2abd93f06…`，
  另外保存了 HTTP 请求行和状态行（不含正文、能力令牌或断言）。
- 尝试 5：`4a7a6ec9d4344071830b2ab1a29303e6`，审计 head `2842e0932d2dc466…`。
- 尝试 7：`f2d4cb844d6249fd886ee6a4ef61f826`，审计 head `22fed35f7d95aab2…`。
- 尝试 1 失败在创建运行目录之前，只保存了日志、公开批次配置和状态检查。
- **尝试 4 和尝试 6 的原始产物在替换容器前没有导出。** 尝试 6 的事件序列是在
  替换前直接读取的：输入、根授权、编译、交接依次完成，发布了 1 个模型视图，
  调用 1 次模型，得到提议 `{"choice":{"kind":"registered_template","template":1}}`，
  随后 `operator_execution_prepare` 在约 125 秒后以 `RuntimeError` 结束。
- 诊断构建（只加了 `eprintln!`，未提交）的运行不计入实验。其中两次的产物和插桩
  diff 已保存。

原始产物保存在本地被忽略的 `experiments/results/local-container-20260930/`，
不随源码推送。

## 已修复的问题

### 问题一：启动器拒绝 systemd 255 的凭证交付方式（`119ec35`）

systemd 254 及以后版本，把非 root 服务的凭证交付为 `root:root 0440`，外加一条只授权
该服务 UID 的 POSIX ACL。实验启动器只接受 owner-only 权限，于是在一次性批次已经启动后，
拒绝读取模型密钥。修复后的规则与原生 Rust 的 `linux_credentials` 检查一致：仍然拒绝
组/其他用户权限、其他 UID 和任何更宽的 ACL。

### 问题二：生产 vault 绑定了错误的 boot 身份（`d8b9b01`）

```text
input/finalize（第二次）→ approvald 结算：已批准 → kerneld commit_input_settlement
  → ingress_commit_sink.commit → vault.issue_masked_document → InvalidCapability
  → ingressd 不写 HTTP 响应就关闭连接 → SDK 报 invalid_response
```

数据平面签发和读取 vault 上下文时都用 `runtime_material.agentd_boot_id`，两个组件
测试夹具也都用 agentd 的 kernel 客户端 boot 打开 vault。只有 Linux 启动代码用了 kernel
自己的 `boot_id`。`v2_startup.rs` 属于冻结核心：冻结检查现在是 18 处不匹配
（检查点时为 17 处），需要复核后才能建立新的冻结基线。

### 问题三：泄露闸门误拦融合模型信封（`a56f3bd`）

```text
fused planning tick：找到任务 → 占用投递槽 → G3 ProvenanceRecordV2::declassify
  → LeakGateResidualPii → StateConflict（静默；槽位已占用，不会重试）
```

`ModelView` 以 JSON 编码，`"deadline":1790733952898` 是 13 位 Unix 毫秒时间戳，
必然命中泄露闸门的银行卡号规则 `\b(?:\d[ -]*?){13,19}\b`。任何 8 位以上的数字串
还会命中电话号码规则，所以改成秒数同样不行。用户选择"改请求编码"：`deadline` 在
内存中仍是 `u64` 毫秒，线上改为 8 字节大端整数数组（与 `job` 字段相同的形式），
Python worker 同步解码。泄露闸门的规则和职责不变。回归测试覆盖三点：真实时间戳的
视图能通过闸门，旧的十进制写法会被拒绝，Rust→Python mTLS 互通不受影响。
`RoundState` 持久化的信封编码随之改变；只有全新的一次性部署持有这类状态。

### 问题四：规划提示词对回复外层格式有歧义（`03cc039`）

第一次真实调用时，DeepSeek 返回的是裸 choice 对象，缺少 `{"choice": …}` 外层，
worker 按设计拒绝。修复方式是在提示词里写明唯一的顶层键，不在代码里做任何自动纠正。
这属于实验 README 允许的"先校准输出 schema"：只用第一个良性样本的视图做了一次
格式验证，没有接触任何攻击样本或 oracle，并且发生在任何评分之前。同一提交还给
`model_transport_unknown` 事件加上了封闭错误码：只允许 worker 的静态错误字符串或
OpenSSL 的 reason 码，从不记录异常正文。

## 问题五：融合执行准备读不到原始 owner 文档（`ce3b3fd`，用户选择"实现接线"）

尝试 6 中，内核接受了模型提议并激活了计划。之后 operator 每次提交
`prepare_planning_execution` 都被拒绝，诊断构建显示：

```text
prepare_owner_execution_review_v04
  → values.resolve_g4_value(run, session.initial_value) → 非文本值
  → FusedInputDocumentV04::from_owned_value → DeriveTypeMismatch → BindingMismatch
```

原因如下：

- **v0.4 融合执行准备**要求会话的初始值，是 owner 确认过的**原始文档 JSON 文本**，
  来源类型为 `GatedIngress`。
  - 它从中派生固定的工具参数（`derive_owner_input_text_v04` 也要求 `GatedIngress`）。
  - 组件测试夹具正是这样直接登记的。
- **生产入口流水线**（`accept_finalized_input_into_kernel` → 数据平面 commit →
  私密会话接纳）登记的初始值，却是给 agent 看的**脱敏视图**：
  - 内容是 `KernelValueV2::bytes(CBOR)`，来源类型是解密（declassified）来源；
  - 原始规范化文本（`normalized_value` 及其 `GatedIngress` 来源）只在流水线内部
    计算出来，之后就被丢弃了。

修复方式如下：

- 入口在完成接纳时，把原始规范化文本连同它的 `GatedIngress` 来源一起保存进领取材料。
  构造时会校验它与脱敏值的 producer、run、manifest、有效期都一致；快照改为 10 个字段，
  旧的 8 字段快照仍能解码。
- 私密会话接纳时，把原始文档在值所有者里与脱敏初始值一起两阶段登记；
  句柄只存在会话记录里。
- 执行准备和派生改用这个句柄；没有句柄时安全失败。
- 经典的 agent 领取路径以及所有 agent 和模型路径，仍然只能看到脱敏视图。

新测试覆盖以下几点：

- 执行准备永远不会解析脱敏的会话值；
- 执行准备能从单独保留的原始文档成功完成；
- 领取材料会拒绝不匹配、属于其他 run 或来源不是 `GatedIngress` 的原始文档；
- 快照往返后内容不变。

回归结果：非特权运行 kerneld 库测试 377 通过，失败的仍是原来那 41 项环境相关的测试；
exact Rust 专项回归 89/89。

## 未解决：G7 连接器注册表为空，工具无法派发

尝试 7 中，第一个样本依次完成了：输入、根授权、编译、交接、模型规划、执行准备，
以及预授权批准工具执行（`purpose=tool_execution`）。之后运行停在 `wait_publication`，
provider 端没有收到任何工具调用。诊断构建显示，每次派发都失败：

```text
tick_fused_actions_v04 → 评估结果 Allowed → dispatch_fused_action_v04
  → dispatch_execution_inner → connector_registry.resolve_task_tool_connector
  → BindingMismatch（静默；每秒重试一次）
```

原因有两层：

1. Linux 启动代码构造 G7 连接器注册表时，"随部署下发"的连接器列表写死为空
   （`from_verified_genesis(..., vec![])`）。安装器又从服务单元里移除了
   `connector-authority-v2.seed`，所以运行时也不能再注册连接器。组件测试则直接把
   `DeploymentShipped` 连接器放进了创世状态。
2. 实验配置生成器（`protected_experiment_profile.rs`）签发的工具描述，
   `provider_identity_digest` 填的是业务目标身份。而注册表要求它等于所属连接器的 ID
   （`savana.connector.deployment.v2` 摘要），所以即使加载了连接器，也对不上。

要修复，需要做三件事：由签名的部署配置携带"随部署下发"的连接器，启动时对照已验证的
工具描述逐一核对后加载，并让生成器使用一致的连接器身份。这些都在冻结核心里，本次没有实施。

另外，这条链路上的多个失败都会被映射成 `StateConflict`、`PolicyDenied`、
`KernelUnavailable`，或者直接不返回 HTTP 响应，只能靠插桩才能定位。建议加上不含
私密内容的封闭错误码。

## 结论边界

- 没有产生防护率、ASR 或任务成功率。模型提议被接受，只代表规划通道已接通，
  不代表任何安全结论。
- 软件身份只模拟 UP/UV，不证明真人或硬件认证；所有预授权记录都是
  `human_review=false`。
- 特权容器、共享宿主内核、file-backed 密钥：不代表生产隔离，也不代表防回滚。
- 仍然是 3 个日历任务 × 正常/2 种攻击的有限子集，不是完整 AgentDojo。
