# 本地一次性容器上的软件身份防护实验 — 2026-09-30

本记录承接 [2026-09-29 源码检查点](source-checkpoint-20260929.md) 和
[软件身份实验模式](../../experiments/SOFTWARE-IDENTITY-BENCHMARK.zh-CN.md)。
**不是防护成绩**：所有正式尝试都是 0 次模型调用、0 个可计分样本、9 个 Unknown。
本次的产出是 Linux 组件复核，以及在真实签名部署上找到并修复的两个阻断缺陷；
第三个阻断缺陷已定位，但修法涉及协议或签名策略，尚待决定。

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
  systemd 主机密钥加密保存。没有进入命令参数、文件、日志或本记录。本次只调用过
  一次免费的 `/models` 连通性接口，没有发出任何计费的推理请求。

## Linux 组件复核（非模型实验）

| 项目 | 结果 |
| --- | --- |
| Python 实验回归（Python 3.12，新构建的 SDK，真实 Rust 组件驱动） | 197/197，无跳过；加上本次新增测试为 198/198 |
| `agentdojo-native-probe`（合成用例，无 LLM） | 14/14 |
| `savana_bench regressions`（exact Rust 用例） | 89/89 |
| `deploy/linux/integration/build.py` | EXIT 0，14 个二进制，498 个源文件快照，构建前后一致 |
| 容器内已安装包的 Python 回归（运行时包不含 `crates/`） | 185 项中 10 项因缺少 `crates/` 测试夹具而失败；完整检出中这些测试均通过 |

`savana-kerneld` 库测试以 root 运行时会因 "require an unprivileged runner" 失败。
改用非特权用户运行：374 通过、42 失败，失败集中在 server、socket、startup_identity
三组（与进程身份、附加组和 socket 环境相关）。父提交与修复后的失败名单完全相同。

## 正式尝试（每次都是全新主机、单独启用的一次性批次）

| 尝试 | 停止阶段 | 原因 | 处理 |
| --- | --- | --- | --- |
| 1 | 启动器读取模型凭证 | systemd 255 以 `root:root 0440` 加精确 ACL 交付凭证，启动器只接受 owner-only 权限 | `119ec35`：规则与原生 Rust 凭证检查对齐 |
| 2、3 | `owner_input_commit`（`invalid_response`） | 见下文"缺陷二" | `d8b9b01` |
| 4 | 同上 | 只用于 strace 诊断 | 容器替换前未导出 |

软件身份在第 2–4 次尝试中都通过了原生 WebAuthn 校验，有限预授权批准了输入
（`human_review=false`）。之后的失败都发生在任何模型调用和工具执行之前。
**每次尝试均为 0 次模型调用、0 个已评分、9 个 Unknown。** 已导出运行的离线复核结果
（`audit_consistent=true`，重新判分 0 个）：

- 尝试 2：`43e216abc4454cbf9af635a1c23c6ed1`，审计 head `601537287da53a45…`。
- 尝试 3：`4ef3f5f2f26141d69472284c4e923c13`，审计 head `02e277e2abd93f06…`，
  另外保存了 HTTP 请求行和状态行（不含正文、能力令牌或断言）。
- 尝试 1 失败在创建运行目录之前，只保存了日志、公开批次配置和状态检查。

原始产物保存在本地被忽略的 `experiments/results/local-container-20260930/`，
不随源码推送。

## 缺陷二：生产 vault 绑定了错误的 boot 身份

诊断用 `strace` 跟踪了 ingressd、approvald、kerneld 之间的 IPC（只记录长度和时序），
并用一个只加了 `eprintln!` 的诊断构建（未提交）确认：

```text
input/finalize（第二次）→ approvald 结算：已批准 → kerneld commit_input_settlement
  → ingress_commit_sink.commit → vault.issue_masked_document → InvalidCapability
  → ingressd 不写 HTTP 响应就关闭连接 → SDK 报 invalid_response
```

数据平面签发和读取 vault 上下文时，用的都是 `runtime_material.agentd_boot_id`，
两个组件测试夹具也都用 agentd 的 kernel 客户端 boot 打开 vault。只有 Linux 启动代码
用 kernel 自己的 `boot_id` 打开 vault，于是 `validate_context` 必然拒绝。修复后，
同一流程通过了输入提交、根授权、operator 编译和私密会话交接。
`v2_startup.rs` 属于冻结核心：冻结检查现在是 18 处不匹配（检查点时为 17 处），
需要复核后才能建立新的冻结基线。

## 缺陷三（未修复）：泄露闸门误拦融合模型信封

修复缺陷二之后，运行停在 `operator_execution_prepare`，operator 等待 115 秒后超时，
模型调用仍为 0。诊断构建显示：

```text
fused planning tick：找到任务 → 占用投递槽 → G3 ProvenanceRecordV2::declassify
  → LeakGateResidualPii → StateConflict（静默；槽位已占用，不会重试）
```

`ModelView` 以 JSON 编码，其中 `"deadline":1790733952898` 是 13 位 Unix 毫秒时间戳。
`savana-leak-gate` 的银行卡号规则 `\b(?:\d[ -]*?){13,19}\b` 不做 Luhn 校验，
所以按设计扫描信封字节时**每次都会命中**（被替换成 `[银行卡号]`）。解码后的
`public_view` 明文检查（`BlocklistAndNoResidualPii`）是通过的。测试用的截止时间是
小整数，所以没有覆盖到这一点。结论：在现有代码下，生产部署的融合模型通道发不出
任何一次请求。

可选修法（尚未实施，需要维护者决定）：

1. **协议修正（推荐）**：`ModelView` 线上编码里不能出现 8 位以上的连续数字。
   电话号码规则 `\(?\d{2,4}\)?[- ]?\d{2,4}[- ]?\d{4,10}` 会命中任何 8 位以上的数字串，
   所以简单改成秒数（10 位）同样会被拦。可以像 `job` 字段那样，把 `deadline`
   编码成字节整数数组（例如 8 字节大端）。需要同步修改 continuation-core、
   Python `fused_worker` 及其测试；泄露闸门职责不变。
2. **策略修正**：把 `FusedModelCall` 规则的闸门职责降为只做黑名单检查，PII 检查
   依赖代码里对解码后 `public_view` 的显式检查。改动小，但属于放宽签名部署里的
   安全约束。

另外，这条路径上的多个失败都会被映射成 `StateConflict`、`KernelUnavailable` 或
不返回 HTTP 响应，只能靠插桩才能定位。建议给这条链路加上不含私密内容的封闭错误码。

## 结论边界

- 没有产生防护率、ASR 或任务成功率。
- 软件身份只模拟 UP/UV，不证明真人或硬件认证；所有预授权记录都是
  `human_review=false`。
- 特权容器、共享宿主内核、file-backed 密钥：不代表生产隔离，也不代表防回滚。
- 仍然是 3 个日历任务 × 正常/2 种攻击的有限子集，不是完整 AgentDojo。
