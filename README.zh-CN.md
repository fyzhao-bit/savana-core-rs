# savana-core-rs

[English](README.md)

Savana 的 Rust 安全内核工作区。生产安全路径默认禁止 `unsafe Rust`；
只有 `savana-platform-identity` 中经过审计的 Linux systemd、Landlock /
seccomp、macOS CoreFoundation / Security.framework 和 Seatbelt 原生边界
允许局部 `unsafe`，每个不安全操作都必须单独标注。

## 组成

生产工作区固定为十一个 crate：

- `savana-kernel-protocol`：V1/V2 隔离的规范 CBOR、有限帧、稳定错误码、
  opaque handle 和资源上限；
- `savana-policy-core`：签名策略和发布验证、反回滚状态、部署身份及
  G3-G7 策略核心；
- `savana-vault`：由内核权威持有的敏感数据存储；
- `savana-input-runtime`：Rust 持有的 G1/G2 输入处理；
- `savana-leak-gate`：masker 与内核去密级验证共用的确定性 blocklist 和
  PII 检测器；
- `savana-platform-identity`：进程、可执行文件、对端凭据及
  systemd/launchd listener 的原生测量；
- `savana-agentd`：JARVIS 控制入口和 agent session 边界；
- `savana-kerneld`：V2 启动验证、服务认证、策略执行、状态 owner、
  审计和 fail-closed 主内核；
- `savana-ingressd`：本机输入和文档解析入口；
- `savana-approvald`：WebAuthn、审批、身份验证和管理员边界；
- `savana-execd`：隔离、带 fence 的执行器边界。

`libsavana-ner` 和 `savana-core-py` 仍保留在仓库中，但不是生产工作区
成员，也不位于 V2 安全路径上。

## V2 安全模型

生产 `run()` 只进入 V2 启动门，不监听、不解码、也不回退到 V1。
V1 仅作为 debug `test-support` 下的冻结兼容和回归证据。

内核持有并执行 G1-G7：

- G1/G2：输入规范化、注入/secret/PII 检查、受保护片段 tokenization，
  以及不含原始敏感内容的 planner envelope；
- G3：label、provenance、不可改善派生、不含 handle 的语义摘要，以及
  manifest pin 锁定的签名去密级规则；
- G4：绑定存储、descriptor/registry 激活、action intent 去重和
  ontology projection；
- G5：只允许内核内部选择的 validator dispatch；
- G6：WebAuthn 验证、按用途分离的签名 settlement、计数器、重放消费、
  加密和反回滚；
- G7：tool/final release dispatch、审批和 quota 精确绑定、唯一持久
  execution nonce、签名执行回执及恢复对账。

五个会扩大可读范围的交接必须经过同一个去密级入口：masked agent
view、planner envelope、approval display、executor handoff 和 final
release。内核检查实际出站字节、生成 provenance 节点、校验 reader class
及精确 executor/sink（适用时），并把节点摘要绑定进签名交接对象。

每个 daemon 的可变安全状态由一个有界 owner 线程独占。请求有固定
deadline 和有界队列；owner panic、审计失败、身份变化、回滚或不确定
提交都会 fail closed。agentd 和 execd 的 EffectGate 在 planner/effect
状态转换期间持有同一个经测量的 OS 锁，fence 开始后禁止新的持有者。

服务间传输使用 Suite-1：临时 X25519、Ed25519 transcript 身份验证、
HKDF-SHA-256、双向 HMAC confirmation 和 ChaCha20-Poly1305。每条连接
只允许一个加密请求和一个加密响应。

## 对外接口

V2 只有一个产品集成边界：

```text
JARVIS / Python → agentd → Rust 内核服务图
```

Python server 不直接连接 `kerneld`、`ingressd`、`approvald`、`execd`、
vault 或某个 G1-G7 状态机。Python 包可以封装 agent-control 协议，
无需修改 Rust 内核，但 Python 进程必须通过本机进程身份和部署 manifest
校验。

### JARVIS / Python 控制 IPC

生产入口：

```text
/run/savana/agentd/jarvis/control.sock
```

该 Unix socket 使用 Suite-1 双向认证、规范 CBOR、opaque handle、
固定 deadline 和有界消息。完整操作只有四个：

| Tag | 操作 | 用途 |
| ---: | --- | --- |
| 0 | `Health` | 返回公共服务状态，并验证 kerneld 是否可认证、可用 |
| 10 | `PrepareIngress` | 创建 task，返回 opaque task handle 和一次性浏览器 bootstrap action |
| 11 | `GetTaskStatus` | 通过 opaque handle 查询 task 的公共状态 |
| 12 | `CancelTask` | 使用与 task 绑定的取消权威请求取消 |

这里没有通用 `execute`、原始策略求值、vault read、key export、socket
选择、role 选择或任意 operation 接口。

### 签名去密级接口

去密级是 Rust 内部策略边界，不是 Python 控制 API。`kerneld` 启动时
加载规范 CBOR `DeclassificationRuleSetV2`，通过用途为
`DeclassificationAuthority` 的 operational trust root 验证 Ed25519
签名，并要求规则集 signed digest 与 deployment manifest pin 完全一致。
唯一能生成去密级节点的入口是：

```rust
ProvenanceRecordV2::declassify(
    value, context, transition, verified_rule_set, purpose_digest,
    token_set_digest, final_release_settlement, parents, effects, now,
)
```

封闭 transition 只有 `MaskTokenizeAndLeakCheck`、
`BuildPlannerEnvelope`、`BuildApprovalDisplay`、
`BuildExecutionEnvelope` 和 `BuildFinalRelease`。`judge_handoff` 返回
`Admits`、`Refuses` 或 `Unproven`，只有 `Admits` 可以跨服务边界。
agent view、planner ticket、approval envelope 和 sealed execution payload
都会携带对应的去密级 provenance digest；最终释放还必须具有 fresh、
精确绑定、single-use 的审批 settlement，以及非空 value scope。

### 浏览器 localhost HTTP

浏览器接口只绑定 localhost，校验精确 Host/Origin，拒绝 Cookie、
Authorization、CORS 和未登记路径，使用固定 CSP，并将 body 限制为
1 MiB。

| Origin | 固定路由 |
| --- | --- |
| `http://localhost:8765` | `GET /v2/shell`；`GET /v2/bootstrap/{ingress\|approval\|agent}/{selector}`；`POST /v2/bootstrap/continue` |
| `http://localhost:8766` | `GET /v2/enrollment/bootstrap`；`POST /v2/ui-auth/{accept\|begin\|finish}`；`POST /v2/approval/display`；`POST /v2/approval/decision/{begin\|finish}`；`POST /v2/webauthn/enroll/{begin\|finish}` |
| `http://localhost:8767` | `POST /v2/bootstrap/accept`；`POST /v2/ui-auth/complete`；`POST /v2/input/{begin\|chunk\|finalize\|abort}` |
| `http://localhost:8768` | `POST /v2/ui-auth/complete`；`POST /v2/agent/view`；`POST /v2/agent/action` |

四个 origin 都提供 `GET /v2/savana-ui.js`。bootstrap selector、tab
capability、document reference 和 authentication transfer 都是一次性或
单用途 opaque capability，不是通用 bearer API。

### 内部认证 IPC

以下接口只开放给被 manifest、进程身份、可执行文件测量和角色共同锁定
的本机服务对端。它们不是 Python 或普通应用接口。

| 角色 | 生产 endpoint | 允许的操作 |
| --- | --- | --- |
| `AgentKernel` | `/run/savana/kerneld/agentd/kerneld.sock` | `Health`, `ClaimAgentSession`, `PrepareFollowupIngress`, `GetAgentSessionStatus`, `PreparePlannerCall`, `CommitPlannerValue`, `DeriveValue`, `ProposeToolCall`, `EvaluateToolCall`, `AuthorizeToolCall`, `DispatchExecution`, `GetExecutionStatus`, `ReadAgentView`, `PrepareRelease`, `AuthorizeRelease`, `DispatchRelease`, `GetReleaseStatus`, `RevokeVault`, `CloseAgentSession`, `PrepareNewIngress`, `PrepareAgentUiAuthentication`, `AuthenticateAgentUi`, `GetKernelTaskStatus`, `CancelKernelTask`, `ResumeCommittedAgentAuthentication` |
| `IngressKernel` | `/run/savana/kerneld/ingressd/kerneld.sock` | `Health`, `BeginInput`, `AppendInputChunk`, `FinalizeInput`, `CommitInputSettlement`, `AbortInput`, `GetInputStatus`, `PrepareIngressUiAuthentication`, `AuthenticateIngressUi`, `RegisterParserWorkerJob`, `AppendParserWorkerPageFrame`, `CommitParserWorkerResult` |
| `KernelExecutor` | `/run/savana/execd/kerneld/execd.sock` | `Health`, `Dispatch`, `QueryByExecutionNonce`, `AcknowledgeCommittedCompletion`, `FetchCompletion` |
| `AgentApproval` | `/run/savana/approvald/agentd/approvald.sock` | `AgentHealth`, `RegisterAgentApproval`, `GetAgentApprovalSettlement`, `RegisterAgentUiAuthentication`, `ConsumeAgentUiAuthenticationSettlement`, `CloseAgentAuthenticationAttempt` |
| `IngressApproval` | `/run/savana/approvald/ingressd/approvald.sock` | `IngressHealth`, `RegisterIngressApproval`, `GetIngressApprovalSettlement`, `RegisterIngressUiAuthentication`, `ConsumeIngressUiAuthenticationSettlement` |
| `ApprovalAdmin` | `/run/savana/approvald/admin/approvald.sock` | `AdminHealth`, `CreateEnrollmentCode`, `RevokeCredential` |

`ApprovalAdmin` socket 只允许 root，由私有 `savana-approvalctl` 使用。
macOS 开发部署使用相同 listener 名和 operation set，socket 位于
`/Library/Application Support/Savana/Development/run/` 下；这不是另一套
API。

### Rust 启动和协议 API

daemon 的嵌入入口固定为：

```rust
savana_kerneld::run(config_path)
savana_agentd::run(config_path)
savana_ingressd::run(config_path)
savana_approvald::run(config_path)
savana_execd::run(config_path)
```

daemon 只接受编译固定的生产路径或显式 gated 的开发路径，listener
必须从 systemd 或 launchd 继承，调用者不能指定任意 socket。
`savana-kernel-protocol` 对授权客户端公开有限的 V2 wire type 和规范
encoder/decoder；能够构造协议对象并不代表获得了 capability。

### 明确不暴露

生产环境不暴露：

- V1 listener 或 V1 fallback；
- 原始 G1-G7 控制接口；
- vault 明文、原始输入、plaintext secret；
- 私钥、签名 seed、peer credential 或 handshake state；
- executor nonce、内部 owner thread 或任意 capability 构造器；
- 调用方选择 handler、service role、socket 或策略 generation 的能力。

`savana-development-audit-bridge`、parser worker 和 connector-codec worker
是固定部署辅助进程，不是服务 API。

## macOS 开发部署

macOS 开发包使用 launchd socket activation、独立低权限账户、固定 IPC
edge group、本机开发代码签名证书和单独固定的 WebAuthn attestation
root。只信任该本机开发证书不会关闭内核的 manifest、进程身份、
Suite-1、策略、vault、反回滚或 G1-G7 校验。

开发审计桥只读取 kerneld 的固定 FIFO，并写入 mode `0600` 的私有审计
日志。它没有内核 socket group、opaque handle、签名材料、TLS 材料或
Python/server credential，因此不是第七个产品服务。

## 当前平台限制

Rust 协议和服务图已经实现，但生产发布仍要求目标平台提供并验证：

- 不可导出的 Linux/macOS keystore adapter；
- 硬件支持的 monotonic rollback authority；
- 消费这些 handle 的原生 apply/recovery 操作；
- 目标 Linux 的发行版、架构、HSM/PKCS#11 参数，或 macOS 的 Team ID、
  bundle ID、签名 requirement、provisioning 和 entitlement。

在这些目标适配器进入 sealed platform boundary 前，仓库不声称
`PlatformComplete` 或 `ProductComplete`。V2 固定使用 Ed25519；只有
P-256 的硬件目标必须升级协议，不能静默替换算法。

## 构建和验证

使用 Rust 1.82：

```bash
rustup run 1.82.0 cargo fmt --all -- --check
rustup run 1.82.0 cargo clippy --workspace --all-targets --all-features \
  --locked -- -D warnings
rustup run 1.82.0 cargo test --workspace --all-targets --all-features --locked
rustup run 1.82.0 cargo doc --workspace --all-features --no-deps --locked
rustup run 1.82.0 cargo build --workspace --release --locked
```

release build 故意不使用 `--all-features` 和 `--all-targets`，因为测试和
示例 target 会启用生产 release 明确拒绝的 `test-support` authority。

生产 Unix socket 测试需要允许创建本地 socket 的宿主环境。受限沙箱
可能先报 `IdentitySocketPermissions`，随后因进程级测试锁 poison 产生
连锁失败；这种情况必须在宿主重新运行，不能当作产品通过或产品失败。

V2 权威接口定义位于
[`crates/savana-kernel-protocol/src/v2`](crates/savana-kernel-protocol/src/v2)。
冻结 V1 兼容协议见 [`docs/protocol-v1.md`](docs/protocol-v1.md)，跨语言
fixture 和确定性生成命令见
[`vectors/kerneld/README.md`](vectors/kerneld/README.md)。
