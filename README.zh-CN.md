# savana-core-rs

[English](README.md)

## 当前源码快照 — 2026-09-29

本分支包含 Linux/v0.4 内核、Python SDK、部署工具与
[有限 AgentDojo 实验驱动](experiments/AGENTDOJO-PROTECTED-RUNNER.zh-CN.md)。
新增[软件身份实验模式](experiments/SOFTWARE-IDENTITY-BENCHMARK.zh-CN.md)：显式启用
测试身份和有限预授权，不代表真人验证或硬件认证，生产默认仍为交互式认证。
该新模式尚未部署，也没有产生防护成绩。原始实验产物和运行日志保留在本地
被忽略的 `experiments/results/` 下；历史报告中的部分链接指向这些未公开文件。

提交前 71 项 Python 专项测试及 macOS 工作区 `cargo check` 通过；冻结清单检查
仍有 **17 处源码/摘要不一致**，没有为让检查通过而直接重算冻结基线。
这是开发快照，不是验收通过的发布版。见[本次检查记录](docs/verification/source-checkpoint-20260929.md)。

下文及带日期的记录描述不同阶段的实现，不表示完整产品或真实硬件验收已经完成。

## v0.4 实现记录（面向 Linux）

新增独立[通行密钥认证档位](docs/verification/passkey-assurance-v04.md)：由部署配置
选择，支持同步凭证和零计数器，保留原硬件认证档位。档位写入签名回执与加密
恢复状态；重启不重置已消费的挑战，登录不代替动作审批。通行密钥不承诺
硬件不可复制性。Python API 不变，真实登记与 AWS 整机验通仍未完成。

本轮修复了多步执行中“已完成步骤的额度耗尽，导致后续合法步骤也无法准备”的问题。
六个合成集成用例覆盖依赖执行、临时执行句柄丢失、逆序依赖、撤销授权，以及
第二步独立审批后由下一次内核调度续行。测试实际经过 G4–G7、本机认证 IPC、
执行日志和结果入库，但会话、密钥和外部服务使用测试夹具。
现已接通依赖真实上一步结果的有界 loop：两步、三步传值，加密恢复、独立审批、
撤销和 Unknown 停止都有实际内核测试。结果仅能进入已签名的正文槽，不能改目标
或扩大额度。见[结果依赖循环及限制](docs/verification/result-dependent-loop-v04.md)。
原生安装启动、私密会话恢复、独占发布重连仍未全部接通；不能把组件回归当作整机验收。

已新增 TPM P-256/ECDSA-SHA256 签名套件：独立 V3 信封、固定 TPM 对象核验
和 Linux 设备适配。V2 Ed25519 保持不变，软件 TPM 互操作已通过。
已补签名登记验证、TPM 内部 PCR 门控、独立授权服务和 NV 完整状态头恢复，
并接入 Linux 的 Vault／Agent／G4／Connector 持久状态路径。
新增了[登记包离线制作与验证工具](docs/verification/tpm-enrollment-authoring-v3.md)，
不接触私钥或激活硬件。另可运行 [Python 驱动的真实 Rust 组件实验](experiments/COMPONENT-LOOP.zh-CN.md)，
含实际请求评分与本地模型 stdio 接口，不是完整产品实验。
新增[TPM 首次准备与签名后激活](docs/verification/tpm-first-install-v3.md)的原生入口，
软件 TPM 链路通过；已有槽位、旧状态和消费记录不能被重置。
**仍未完整上线**：旧部署记录迁移、续期与真实硬件部署验收尚未完成；
没有修改现有部署。见[当前 TPM 接入边界](docs/verification/tpm-authority-v3.md)。
新增独立的 [V3 部署记录与恢复日志](docs/verification/deployment-records-v3.md)，
绑定完整签名记录，并校验验证证据、提交证据两类材料。
另已补不可覆盖的历史归档、账本状态转换与真实证据链绑定；
这不代表原生部署执行器全部接通，安装器和启动门禁仍不能跳过。
Linux [原生安装前检查](docs/verification/linux-staging-v3.md)现已核对实际文件、
六类部署计划与 V3 历史上的交易授权；检查结果本身不能安装、启动或解除执行限制。
另已核对签名发布清单中的全部 35 个载荷和 29 个版本历史域，拒绝降版、
同版本替换内容及密钥时期回退；复用清单时重新检查有效期，普通升级不能替换启动信任基础。

已接上私密会话的首次登录和任务级审批交接：可信输入页发起，审批服务进行
独立硬件身份验证，内核消费专用签名回执，待审批动作只交给对应私密页面。
已登记私密任务不能通过旧 Agent 登录、领取会话、查询状态或取消。
见[私密会话及限制](docs/verification/private-session-v04.md)。
Python 现有独立的 `savana.private_v04.connect` 入口，接私密认证与工具审批交接，
不经旧 Agent 会话；见[实际接口与边界](docs/verification/python-private-v04.md)。
新增 `poll_publication` / `wait_publication` 和原生发布回执，Python 实验侧可核对
真实发布结果并记录审计摘要；审批通过不等于发布完成。见[接口与数据流](docs/verification/private-publication-sdk-v04.md)。
这尚不是正式 AgentDojo 防护组成绩，也不补足生产接收端与重连。
这不是整机验收完成：原生安装启动、私密会话重启恢复、独占发布/重连和
任意动态规划的通用循环仍未完成；已注册步骤的结果依赖循环已接通。
完整产品实验门槛保持关闭。

当前新增了有界续行检查器、加密持久的稳定消费与 pin/freeze 状态、G7
原子资源扣费，以及第一个 Rust 管理的私密对象源。改名、更新内容不换
对象 ID；删除保留身份墓碑和消费记录。原始执行输入现已随 G7 原子保存，
后续更新、删除或重放不改变该快照。五个私有资源管理方法加一个执行快照
读取方法见[资源适配器验证说明](docs/verification/managed-resources-v04.md)及
[执行快照说明](docs/verification/execution-input-snapshots-v04.md)，它们不是
新增的 Agent、MCP 或公开 HTTP 接口。独立的 Linux 管理 SDK 可以提交
签名管理命令，但不直接暴露这些 owner 方法。
现已在内核工具发送路径增加签名许可的 UTF-8 投影检查：逐字节核对原始
快照，保留现有 G3、加密信封及 execd 验证。已登记任务的请求现由内核
自动绑定资源证明，使用可选的 Linux 独立签名密钥，不接受模型提供可信
事实；任务登记和资源导入界面仍待接通。详见[发送边界](docs/verification/managed-handoff-v04.md)
及[准入与配置限制](docs/verification/managed-admission-v04.md)。
另已补充签名管理命令后端：资源导入、修改和原子任务登记均保存持久重试
回执。现已增加默认关闭的 Linux 本机 root 管理通道，以及 Rust/Python
`managed_admin.submit_signed` 薄封装，交给同一内核状态线程执行。Agent 和
内核进程都不持有管理员私钥。签名工作流、面向普通用户的审批界面及真实
Linux 部署验收仍待完成，详见[管理边界](docs/verification/managed-admin-v04.md)。

已新增 V2/v0.4 融合协议后端：审核视图、一次性建议采纳、持久发件箱、
登记模板编译与 V2 计划转换。现已把签名确认的具体操作与真实 G7 事务绑定，
受限重规划保留旧执行编号；模型交换入口先持久扣除投递次数，再通过绑定
具体接收方的新 G3 规则。现已增加签名投递时间槽和持久调度游标，恢复后不补发
错过的槽。后台定时器现已接入同一个内核状态线程，交换期间锁定当前部署策略，
已保存但尚未激活的候选可恢复而不重发。云端适配器仍禁用，
详见[主机接线](docs/verification/fused-host-v04.md)。另已接入内核内部的执行绑定：
对已经冻结、精确签名批准的动作，按活动计划选择下一步，并保留旧执行的重放身份；
G7 提交时再次核对。它还不是候选到动作的编译器，也没有新增 Agent/Python 接口。
现另有内核内部的候选草稿编译器：复用原 G4 检查，将活动步骤和本地值编译成
真实动作材料；不签发句柄或执行许可，尚未接入运行中的业务流程。真实任务关联和
审批展示可能随重编译变化，旧动作签名不能自动沿用，具体限制见上述主机接线说明。
现已新增独立的配方证据：先重建并核对每个真实 G4 参数，再计算稳定配方摘要。
重排可保持同一配方，但来源或值身份变化不能混用；它不是审批，不转移旧审批，
独立签名的配方清单现已接入私有管理事务及加密恢复（schema 14），原请求重试
返回原回执。编译器按当前配方、部署代次和有效期核对。
G7 持久事务现已校验当前动作的配方证据、活动步骤、根授权和部署代次，
执行凭证不得超过配方审批有效期；schema 15 原子保存核验回执，恢复时保留
原执行编号和消费记录。G5/G6、依赖和配额检查仍保留。
本地已验证输入现可一次性固定到加密状态（schema 16）；恢复时换新的进程
句柄，但保留原值身份、原始内容和溯源，不能换来源或延长有效期。
编译器与 G7 均核对固定输入。私有编排现由内核选择下一未预约步骤，只使用
固定输入生成持久 G4 动作，并复用 G5 及 G6 审批信封/精确回执验证。
旧 Agent 入口拒绝这些内部句柄，包括执行缓存和状态查询。私有 G7/execd
发送与结果核对现已接通既有加密信封、签名回执和 vault；丢响应保留原执行身份，
暂时未知继续占用预算、允许迟到成功入账，不重新发送。Schema 17 现把原始
结果身份与 G7 一起保存，并在执行器清理前记录 vault 结果引用；即使旧会话、
动作和票据丢失，也能恢复私有查询/结果句柄，保留原身份、溯源和有效期。
生产内核定时调度现已自动发现历史执行，逐个核对并重试原结果的清理确认；
不重新执行，也不在检查点之后重新获取明文。恢复、规划、新动作轮流运行；
新动作要求有效会话授权、生效计划、固定输入和精确签名规则，并重走 G4–G7。
拒绝或需要用户审批时暂停，执行规则不能替代 G6；同一任务等待上一动作入账
后才推进。单项故障保留原预约，持久状态损坏则停止。私有待审批信封和已验证
回执现已进入加密、防回滚的状态恢复；重新绑定须匹配原 G4、当前根授权和计划，
重验 G5、审批披露及 G6，不更新挑战或有效期，不恢复登录或自行执行。
面向用户的输入、会话恢复，以及可信审批交付和页面仍待接通。
审批接收端已持久绑定交付角色和展示信封，缓存重试也重验签名、配对和时效；
重启或重新登记不能更换展示挑战、重置决定。新增独立 `KernelApproval` 身份，
支持加密提交／查询，内核调度器已接入 G6 回执处理，不借用 Agent／Ingress 身份。
Linux 启动装配现已接入：在签名配置和专用凭据齐备时安装客户端，审批服务核验
专用监听及内核进程身份；附有按需启用的 systemd 和目录权限配置。
**可信用户审批页面路由仍未接通**，也未修改本机已安装的服务；未配置时继续停在待审批。
见 [Linux 审批部署契约](docs/verification/kernel-approval-linux-v04.md)。
登记后旧聊天规划和最终发布入口
仍拒绝回退，用户输入/审批、统一发布及 UI 接线尚未完成，不应在真实任务上启用。
详见[融合协议](docs/verification/fused-planning-v04.md)及
[执行与模型出站验证范围](docs/verification/fused-execution-and-egress-v04.md)。

**尚未完成整个 v0.4 产品**：通用编译器与残余契约替换、独占发布、具体
provider 效果执行、SDK/UI，以及原生 Linux 硬件与沙箱验收仍待完成。
Google Cloud / DeepSeek 仍为禁用占位符。
[实施计划与验证记录](docs/research/v04-product-implementation.md)。

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

客户端 SDK 将 `savana-client` 和 `savana-core-py` 加入工作区，使 Rust
实现和 Python binding 能一起检查；它们没有加入冻结的生产部署核心。
旧的 `libsavana-ner` 也作为 Python wheel 的依赖加入工作区，但仍不位于
V2 安全路径上。

另有**实验性研究 crate** [`savana-private-workflow`](crates/savana-private-workflow/README.md)：
实现证据驱动的运行时订单发现、动态实例授权和受控披露的闭环规划。
模型仅有 `Observe`、`Discover`、`RequestInvoice` 三种命令。
它不是新增的生产 RPC、Python SDK 接口或执行凭据；当前部署与 G1–G7 不变。
可运行的离线示例、信任假设和仍需完成的生产桥接见该 README。

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

### OpenClaw 正式运行时

本仓库还包含固定版本、仅文本的 OpenClaw 适配器：
[`integrations/openclaw-savana-runtime`](integrations/openclaw-savana-runtime/README.md)。
它只兼容 `openclaw@2026.7.1-2`，只注册一个 provider（`savana`）、一个
model（`agent`）和一个 harness（`savana`），不向 OpenClaw 注册任何 tool
或 MCP server。OpenClaw 上游只是只读兼容依赖；适配器源码、测试和文档
全部保留在本 `savana-core-rs` 仓库，不会向 OpenClaw 仓库提交或推送。

适配器只把当前用户输入的精确文本交给公开 Python SDK。私有的有界 agent
loop、G1-G7 和审批仍由 Savana 执行。只有 execd 经固定回环 TLS 1.3/mTLS
接收器送达、并被唯一 release reservation 持久认领的 payload，才能成为
OpenClaw assistant 文本。安装、固定端口 release connector、证书格式、
FD 3 产品认证 broker、model-scoped 配置、`savana.runtime` doctor、恢复流程
和真实 transcript 隐私边界见适配器 README。

JARVIS 仍是可信控制集成，并通过带外方式提供一次性 session bootstrap。
随后 V2 客户端 SDK 只使用三个面向应用的 loopback 服务：Agent、Ingress
和 Approval。JARVIS 不是第四个 SDK 服务。Python 应用和 SDK 都不直接
连接 `kerneld`、`execd`、vault 或某个 G1-G7 状态机。

### V2 客户端 SDK

异步 Python facade 由 Rust 持有的 `savana-client` 状态机及
`savana-core-py` binding 实现。固定网络拓扑如下：

| 服务 | 固定 endpoint | SDK 职责 |
| --- | --- | --- |
| Agent | `http://localhost:8768` | 已认证 session 操作、masked view、planning、execution、release 和 connector workflow |
| Ingress | `http://localhost:8767` | 有界文本/文件输入以及 committed completion |
| Approval | `http://localhost:8766` | WebAuthn 和人工审批 ceremony |

二十个 business method 只统计三个 workflow owner：

| Owner | Business method |
| --- | --- |
| `Identity` | `load(path)` |
| `Client` | `session(identity, bootstrap, webauthn, approval)`、`enroll(enrollment_token, code, webauthn, identity_path)` |
| `Session` | `ingest_text`、`ingest_file`、`task_authorization_context`、`establish_task_authorization`、`approve_task_authorization`、`revoke_task_authorization`、`recover_task_authorization`、`read_view`、`run_planner`、`execute`、`run_agent`、`release`、`register_connector`、`remove_connector`、`list_connectors`、`revoke`、`close` |

二十一个产品类型如下：

| 分类 | 类型 |
| --- | --- |
| 连接和生命周期 | `Identity`、`Client`、`Session` |
| opaque 及投影值 | `Handle`、`MaskedView`、`Plan`、`PlanStep`、`ApprovalRequest`、`ExecutionResult`、`ConnectorDescriptor` |
| 任务合同数据与回执 | `TaskAuthorizationContext`、`TaskAuthorizationDraft`、`TaskAuthorizationReceipt` |
| 选择项 | `IntentPrivacy`、`ContentKind` |
| loop 控制 | `RunLimits`、`AgentEvent` |
| 错误 | `SavanaError`、`AuthError`、`ApprovalDenied`、`PolicyRefused` |

`TaskAuthorizationContext.tools_json()`、`TaskAuthorizationContext.draft(id, clauses_json)`、
`TaskAuthorizationDraft.from_canonical_bytes(bytes)`、`ConnectorDescriptor.load(path)` 和 `RunLimits.cancel()` 是 supporting value
operation，不是额外 business workflow。`Handle` 不暴露原始 bytes，也不能
retag；`PlanStep` 只暴露 opaque step handle，不虚构 `kind`、`reads` 或
`effect`。输入方法只返回 committed completion（Python 中为 `None`），
不会伪造 document handle。因此 `run_planner(intent_privacy)` 没有 `goal`
或 `inputs` 参数；调用 planning 或 `run_agent` 之前，必须先用
`ingest_text` 提交 goal，并用 `ingest_file` 提交文件。

当前 intent-bound 分支中，输入提交成功不等于允许规划：还必须先建立精确的
任务合同。五个任务方法走已认证的 Ingress，任务审批用途为独立的
`task_authorization`。草稿只是非可信数据，回执只是观察结果，不是执行票据；
Python 无法签名或构造可信证据。新建授权缺少已完成的认证输入时直接拒绝。
`recover_task_authorization(request_digest, approval)` 会重新认证同一用户和任务，
只恢复已有的持久化签发记录，不上传替代输入、不重新签发授权、不重置额度。
请保留已观察到的签发请求摘要用于恢复；待批准草稿仍需独立任务审批，
失效或过期的记录直接拒绝。`task_authorization_context()` 返回内核确认的任务与
输入摘要、当前生效的签名工具配置和可恢复请求 ID，不签发授权，也不泄露旧合同
中的控制值。Ingress 编辑器可填写完整备选动作、额度及前置条件，并打开独立审批。
没有已审阅业务配置的工具不会自动放行。部署配置和完整链路验证仍在完成中，
本分支暂不可部署。

传给 `Client.session` 的 callback 会收到每一个真实的 ingress 审批 display，
并且必须返回严格的 `bool`；ingress 永远不会自动批准。`read_view` 只接受
精确的初始 document 或 opaque 的 `MaskedView.continuation` handle，在不暴露
cursor bytes、也不增加 business method 的前提下保留分页。

公开发布必须显式调用 `release(document, approval)`。`ApprovalRequest` 只有
`display` 与 `purpose`。Connector 注册先加载 canonical、unsigned 的部署
artifact 并在 Rust 中校验，再经过 approval 和 kernel authorization 生成
已签名 registry delta。有界 agent loop 只会在精确的
`failed_no_effect` 结果后重新 planning；不确定 effect 或
`effect_succeeded_output_quarantined` 结果绝不会自动重试。

bootstrap、WebAuthn callback contract、完整方法表、经检查的异步示例、
错误语义和验证命令见 [`docs/client-sdk-v2.md`](docs/client-sdk-v2.md)。

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

### 私有 mapper 与结构化 planner

planner 隐私链全部实现在 `savana-agentd`；内核的 planner operation 以及
`PlannerEnvelopeV2`、`PlannerPlanV2`、`PlannerStepV2` 的规范 wire 编码
保持不变。两个外部模型接口都是封闭的 mTLS CBOR endpoint：

| 接收方 | 精确接口 | 可接收内容 |
| --- | --- | --- |
| 私有 mapper | `POST /savana.mapper.v2/map` | 不含 nonce 的 intent projection，以及 active tool 与本机 semantic catalog 的交集 |
| 结构化 planner | `POST /savana.planner.v2/plan` | 每次重新生成 ID 的封闭结构节点、边和固定的 dataflow 排序目标 |

浏览器 agent action tag `2` 是 fail-safe 的私有 mapper 路径。tag `16`
是逐 task 明确选择“与已配置第三方 mapper 共享 intent”的操作；只有经测量
的 deployment ceiling 允许时才会执行。开发部署固定为 `PrivateOnly`，并
为 mapper 与 planner 测量不同的 server identity、SPKI pin 和仅 agentd
可读的 mTLS client credential。

TLS identity 与网络路由被明确分开：endpoint host 只用于 SNI、SAN 校验和
HTTP `Host`；签名 bootstrap 另外携带有界、规范化、已排序的 connect-address
list。agentd 只连接这些已测量 socket address，不会回退到 DNS。开发部署的
planner 与 mapper 分别连接 `127.0.0.1:9443` 和 `127.0.0.1:9445`，同时保留
不同的 `.invalid` TLS name。

Linux 必须安装 deployment-specific systemd 网络 drop-in。基础 unit 只有
`IPAddressDeny=any`，没有 allow；`ExecStartPre` 会在固定、root-owned 的
drop-in 与签名 bootstrap 不完全一致时拒绝启动。root 安装流程为：

```sh
install -d -o root -g root -m 0755 /etc/systemd/system/savana-agentd.service.d
/usr/libexec/savana/savana-systemd-agentd-network-policy-v2 install /etc/savana/agentd-bootstrap-v2.json
/usr/libexec/savana/savana-systemd-agentd-network-policy-v2 validate /etc/savana/agentd-bootstrap-v2.json
systemctl daemon-reload
systemctl restart savana-agentd.service
```

生成器只会原子安装 root:root、`0444` 的
`20-measured-network.conf`，并且仅允许已测量 endpoint list 中的唯一 IP；
端口和 server identity 仍由 typed config 与 pinned mTLS 强制执行。

semantic catalog 是 agentd 本机的加密、反回滚存储；Linux 生产路径为
`/var/lib/savana/agentd/planner-catalog-state-v2.cbor`，macOS 开发部署位于
固定 agentd state 目录。随部署提供的 row 必须经过测量；用户注册的 row
由已批准的签名 connector descriptor 投影而来；只有与内核 active
tool/action 精确匹配的 row 能进入 mapper request。decode table 与内核
envelope nonce 始终留在本机，decode 只做确定性表查找。
用户注册的精确 fail-closed 顺序是：内核授权已批准的 pending descriptor →
目录持久化提交 → 内核 apply。pending、denied、expired 以及被拒绝的
descriptor 都不会占用目录容量。

这里有不可回避的结构形状下限：planner 为了排序，仍会看到节点数量、
粗粒度 role/effect 和 dataflow topology；它看不到业务语义或可跨任务复用
的 tool identifier。若连 topology 也必须隐藏，需要本机 planner 或固定
template selection，而不是远程结构化规划模式。

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
