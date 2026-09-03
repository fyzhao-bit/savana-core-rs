# Savana Core 学术总结：面向大语言模型智能体的能力与信息流安全内核

**文档性质**：基于源码的学术总结（code-grounded academic summary）
**对应版本**：`main` 分支 commit `bee2ed3`（2026-09-02，PR #6 合并后）
**撰写日期**：2026-09-03
**与既有文档的关系**：`docs/technical-report.md` 与 `docs/paper-draft.md`（2026-08-01，修订 1.0）描述的是一个月前的评估分支。本文以当前工作树为准，重新度量全部数据，并在 §7 逐条说明此后关闭了哪些当时报告的缺口。所有数字均为本次直接测量所得，测量方法见附录 A。

---

## 摘要

让大语言模型（LLM）代表用户执行动作的系统面临一个结构性安全问题：模型既是解释不可信输入的部件，又是决定"做什么"的部件。提示注入（prompt injection）因此不是可以修补的缺陷，而是这种架构的必然后果。Savana Core 采取的立场是把安全边界从模型中整体移出：模型只是一个**不可信的提议者**（untrusted proposer），它可以请求动作，但不持有任何执行能力；所有能力由一个用 Rust 实现的多进程安全内核持有和裁决。

本文总结该内核当前的实现状态。其核心机制包括：(i) 一个四维安全标签模型 ⟨integrity, confidentiality, readers, effects⟩，派生只会收窄读者集合与效果集合，并在每次 join 之后重新施加"不可信数据的效果上限只有 READ"这一不变式；(ii) 系统中**唯一**能扩大读者范围的操作——去密级（declassification）——被封闭为五个显式过渡，每个过渡由签名规则集授权、由内核内部的确定性泄漏门（leak gate）在真实出站字节上验证、生成不可变的溯源节点，并在面向单一接收者的过渡里把接收者身份绑定进过渡本身；(iii) 一条以安装者/MDM 密钥为根、按用途分离、哈希链接、规范 CBOR 编码的签名策略供应链；(iv) 一条在效果发生之前先持久化、能在任意崩溃点恢复并诚实标注"恢复所得"溯源的动作管线；(v) 面向远程规划模型的三层隐私（值、形状、意图）设计；(vi) 通过哈希链注册表实现、不削弱内核不变式的连接器自助注册。

实现规模为 295,615 行 Rust（16 个 crate，其中 11 个构成被哈希清单冻结的生产核心）、6,622 行 Python 与 3,565 行 TypeScript 的应用侧集成，含 1,568 个 Rust 测试函数、6,427 条泄漏门差分向量、以及对抗矩阵、崩溃矩阵与启动矩阵。与 2026-08-01 报告最重要的差异是：当时"已建成但无生产调用者"的去密级门，现在已接入全部五条生产路径并由签名规则集约束（§4.3、§7）。本文同样明确列出尚未取得的证据：没有性能评估、没有第三方审计、没有形式化验证、硬件根信任适配器尚未接入，因此仓库自身也不宣称 `PlatformComplete` 或 `ProductComplete`。

---

## 1. 研究问题与设计立场

### 1.1 问题

一个智能体系统把 LLM 放进"读取内容 → 决定动作 → 系统执行"的循环里。在几乎所有真实部署中，模型读取的内容（网页、文档、邮件、工具返回值）都受攻击者影响，而这些内容与指令共用同一条信道。业界主流缓解手段——系统提示加固、输入输出分类器、工具沙箱、人在回路——都把安全边界放在模型之内或模型之上，因而对能控制模型输入的自适应攻击者不成立：

| 方法 | 边界所在 | 在 A1/A2（§2）下的失效方式 |
|---|---|---|
| 系统提示指令 | 模型的服从 | 指令对攻击者同样能指令的模型只是建议 |
| 输入/输出分类器 | 统计过滤器 | 对新表述开放失败，没有不动点的军备竞赛 |
| 工具沙箱 | 进程隔离 | 隔离的是代码而不是权威：被攻击者选参调用的沙箱工具仍执行攻击者的动作 |
| 仅人在回路 | 人的注意力 | 随量退化；用户批准的是被展示的内容，而展示内容由被攻陷部件选择 |

### 1.2 立场

Savana 的设计命题可以概括为一句话：**模型提议，内核裁决（the model proposes; the kernel disposes）**。具体地：

- 智能体守护进程 `savana-agentd` 不持有任何能力：它读不到保险库（vault）中的值，调不了工具，释放不了数据；它只能向内核发送请求，并接收内核选择返回的东西。
- 每个值都带安全标签；标签传播只会收窄；唯一能扩大受众的操作是显式的、可审计的去密级过渡。
- 每个有副作用的动作都需要来自签名策略的决定，且决定所依据的证据模型无法伪造。
- 所有失败都拒绝（fail closed）：没有任何失败模式会扩大权威。

这与 CaMeL 一系工作（控制流/数据流分离、能力附着于值）共享架构论点。本项目的区别性贡献在于**工程完备性**：签名的、可撤销的策略供应链；先记日志后动作的持久化与崩溃恢复；真实的进程间认证传输；对抗测试矩阵；以及在"值"之上的"形状"与"意图"两层隐私（§4.7）。

---

## 2. 威胁模型与安全目标

以下内容综合自 `docs/superpowers/specs/2026-07-27-savana-secure-kernel-v2-design.md` §4 与代码中实际执行的检查。

### 2.1 攻击者

| 编号 | 攻击者 | 假定能力 |
|---|---|---|
| A1 | 内容型提示注入 | 完全控制智能体读取的文本：网页、文档、邮件、工具结果 |
| A2 | 被攻陷的模型/模型提供方 | 规划器返回任意攻击者选择的输出，含恶意远程模型端点 |
| A3 | 被攻陷的智能体进程 | 在 agentd 中任意代码执行，可发出 agent 角色被允许的任何协议消息 |
| A4 | 恶意连接器/工具 | 已注册的工具或 MCP 服务器返回敌意结果并试图借此提权 |
| A5 | 网络攻击者 | 完全控制守护进程之间以及执行器与外部服务之间的网络 |
| A6 | 崩溃/部分失败 | 在任意点（包括状态变更与日志写入之间）终止进程；非恶意但时机对抗性 |

### 2.2 可信计算基

内核进程 `savana-kerneld` 及其内存完整性；安装者/MDM 签名密钥及其传递性授权的部署、激活、回滚、去密级权威；平台密码原语与操作系统进程/IPC 边界；以及——仅对其被展示的、摘要绑定的那个具体内容而言——人类审批者。

### 2.3 安全目标

- **S1 无未授权效果**：没有签名策略推导出的、基于模型无法伪造的证据的决定，就不发生副作用。
- **S2 无未授权披露**：机密值不到达其授权读者集合之外的任何读者。
- **S3 不可信数据不能授权**：外部来源的数据可读可分析，但永远不能携带引发效果的权威。
- **S4 可归因**：每个值的谱系被记录且可重放；每个决定可由记录的输入复现。
- **S5 失败即关闭**。

### 2.4 明确的非目标

设计文档 §4.3 明示不防御：root、内核、虚拟机监控器、调试器、浏览器或物理内存被攻陷；Rust 数据面进程在处理其被授权的表示时被攻陷；可信签名密钥、平台密钥库或签名策略被攻陷；恶意外部规划器对抽象信封的滥用（它只能拿到抽象信封）；正确授权释放之后恶意目的地的行为；以及所有时序、流量、CPU、内存与内核缓冲区侧信道。

---

## 3. 系统架构

### 3.1 进程分解

Savana 是一个多守护进程系统，角色之间通过窄的、双向认证的、规范 CBOR 帧化的协议通信。隔离由**进程边界**而非模块边界提供：一个角色被攻陷不能冒充另一个角色，因为它不持有对方的密钥或套接字凭据。

```text
JARVIS 控制壳 ── TaskHandle/状态/bootstrap ──► savana-agentd（不可信设计）
浏览器 ── bootstrap ──► savana-approvald（WebAuthn UI 认证、审批 settlement）
浏览器 ── 原始输入 ──► savana-ingressd（帧化、沙箱解析 worker）
                                 │
                                 ▼
                          savana-kerneld（TCB：G1–G7、标签、溯源、去密级、vault）
                            │                    │
                 抽象规划信封 ◄──┘（经 agentd）     │ 密封执行信封
                                                  ▼
                                           savana-execd（连接器运行时、HPKE 解封、效果日志）
                                                  │
                                                  ▼
                                            外部世界（MCP / HTTPS / stdio）
```

七条 IPC 边各自使用不同的客户端密钥、服务端密钥、对端规则、端点角色与操作枚举：JARVIS→agentd 控制、agentd→kerneld、ingressd→kerneld、kerneld→execd、agentd→approvald、ingressd→approvald、approvalctl→approvald 管理。不存在 JARVIS→kerneld、JARVIS→execd、agentd→execd 等数据面边。

### 3.2 工作区与冻结核心

| crate | 行数 | 冻结 | 职责 |
|---|---:|:---:|---|
| `savana-policy-core` | 85,589 | ✓ | 标签代数、溯源、去密级规则、策略引擎、部署清单/账本/事务、配额、验证器 |
| `savana-kerneld` | 62,857 | ✓ | 内核守护进程：启动验证、权威状态机、数据面、恢复、传输所有者 |
| `savana-kernel-protocol` | 43,644 | ✓ | 封闭线缆词汇：消息、句柄、签名对象、Suite-1 传输、规范 CBOR、硬上限 |
| `savana-agentd` | 22,806 | ✓ | 智能体会话、规划器隐私链、私有 mapper/planner 传输 |
| `savana-execd` | 17,791 | ✓ | 执行器：连接器运行时、provider 传输、效果门、沙箱 worker、日志 |
| `libsavana-ner` | 15,301 | – | 遗留 NER/解释器（Python 差分移植，不在 V2 安全路径上） |
| `savana-approvald` | 12,711 | ✓ | WebAuthn、按用途分离的签名 settlement、持久状态 |
| `savana-client` | 8,933 | – | Rust 客户端 SDK 状态机 |
| `savana-ingressd` | 8,594 | ✓ | 输入帧化、解析 worker 监督 |
| `savana-platform-identity` | 4,993 | ✓ | 原生对端/进程/可执行文件测量；Landlock/seccomp 与 Seatbelt 沙箱 |
| `savana-vault` | 4,004 | ✓ | 加密、防回滚的敏感值托管与释放材料 |
| `savana-core-py` | 2,691 | – | PyO3 绑定与异步 Python facade、OpenClaw 桥 |
| `savana-leak-gate` | 1,745 | ✓ | "何为敏感"的唯一定义：blocklist + PII 检测 |
| `savana-openclaw-release` | 1,722 | – | OpenClaw 最终释放接收器（TLS 1.3/mTLS、持久预留） |
| `savana-input-runtime` | 1,466 | ✓ | G1/G2：规范化、注入/凭据/PII 门、受保护片段 token 化 |
| `savana-development-audit-bridge` | 312 | – | 开发审计桥（独立工作区） |
| **合计** | **295,615** | 11/16 | |

生产核心由 `deploy/frozen-v2-core.files`（164 个路径）与 `deploy/frozen-v2-core.sha256` 冻结；CI 首先运行 `tools/check-frozen-v2-core.sh` 验证清单自身的规范性（排序、去重、无绝对路径、无 `..`、非符号链接）和每个文件的 SHA-256。工作区级 `unsafe_code = "forbid"`；只有 `savana-platform-identity` 降为 `deny`，并在四个原生边界模块（Linux systemd 描述符接管、Linux Landlock/seccomp 启动器、macOS CoreFoundation/Security.framework FFI、macOS Seatbelt 启动器）中逐处 `allow`。

### 3.3 G1–G7 门链

内核以七个门（gate）组织策略执行，每个门有唯一的 Rust 所有者：

| 门 | 所有者 | 行为 |
|---|---|---|
| G1 | input-runtime / kerneld | Unicode 规范化、间接提示注入策略、PII/凭据检测、token 化、拒绝 |
| G2 | input-runtime / kerneld | 签名的本地抽取模型、封闭语法/模式、白名单、抽象意图与槽位构造 |
| G3 | policy-core | 来源、父节点、根证据、标签、读者、摘要、溯源传播；任何计算或去密级都不提升完整性 |
| G4 | policy-core | 策略 × 注册表活动集、封闭本体、尝试类别、配额与动作意图去重 |
| G5 | policy-core | 仅清单绑定的内部验证器；外部或调用方提供的验证器证明被禁用 |
| G6 | kerneld / approvald | 守护进程签名的展示与精确的、WebAuthn 支持的一次性 settlement |
| G7 | kerneld / execd | 完全绑定的持久动作意图、原子派发准备、OS 效果门租约/围栏纪元、执行 nonce、结果回流、审计、无自动重放 |

### 3.4 传输：Suite-1

所有守护进程间边使用协议 `2.0`、`SUITE_ID = 1` 的认证传输（`savana-kernel-protocol/src/v2/transport.rs`）：固定握手前缀 `SAVANA2\0`、临时 X25519、Ed25519 签名的握手转录（28 字段）、HKDF-SHA-256 派生的方向密钥与 IV、双向 HMAC 确认、ChaCha20-Poly1305 记录、握手体上限 16 KiB、记录明文上限 8 MiB，以及**每条连接一个加密请求与一个加密响应**。握手转录绑定服务端与客户端的进程启动 ID（boot ID）、观测到的 OS 对端/代码身份和声明的客户端启动，因此所有启动绑定的 UI、重放、规划器与效果记录都以此为认证来源。kerneld 把握手签名密钥、待完成握手、nonce 重放表与已测量进程的启动绑定保存在一个专用的有界所有者线程上。

### 3.5 状态所有权与效果门

每个守护进程的可变安全状态由**一个有界所有者线程**独占（`v2_state_owner.rs`）：请求有绝对截止时间和有界队列；所有者 panic、审计失败、身份变化、回滚检测或提交结果不确定都导致 fail-stop。agentd 与 execd 各有一个进程级 `EffectGate` 协调器（`effect_gate.rs`），它在规划器/效果状态转换期间持有同一个经测量的 OS 共享锁（`flock` 于固定 inode），并读取已认证的账本投影以证明 `effects_fenced = false` 和精确的清单/世代/纪元；部署助手独占该锁后，新的持有者被拒绝。这把"部署切换"和"进行中的效果"之间的竞争条件变成一个 OS 级别可证明的互斥。

---

## 4. 核心机制

### 4.1 四维安全标签与不可信效果上限

每个内核值携带 `SecurityLabelV2`（`savana-policy-core/src/v2/labels.rs`）：

| 维度 | 代数结构 | 取值 |
|---|---|---|
| integrity | 三点全序，join = max | `KernelTrusted` < `UserAuthorized` < `ExternalUntrusted` |
| confidentiality | 四点格 | `Public` ⊑ {`PlannerAbstract`, `AgentMasked`} ⊑ `VaultBound`；`PlannerAbstract ⊔ AgentMasked = VaultBound` |
| readers | 封闭位集（7 位） | `KERNEL`、`AGENT`、`INGRESS`、`APPROVAL_DISPLAY`、`EXECUTOR`、`EXTERNAL_PLANNER`、`EXTERNAL_SINK` |
| effects | 封闭位集（7 位） | `READ`、`CREATE`、`UPDATE`、`DELETE`、`SEND`、`EXECUTE`、`FINAL_RELEASE` |

机密性格被刻意设计成非线性：`PlannerAbstract` 与 `AgentMasked` 不可比，其 join 是 `VaultBound`。由"规划器可见的东西"与"智能体可见的东西"派生出的值，两者都不可读——这是代数给出的安全结论，不是特判。

派生（`derive_normal`）对 integrity 与 confidentiality 向上 join，对 readers 与 effects 取**交集**，再与策略允许的效果集取交集。因此派生永远不会扩大受众，去密级成为系统中唯一有趣的操作。

代码中最承重的单条不变式是：

```rust
pub const UNTRUSTED_EFFECT_CEILING_V2: EffectSetV2 = EffectSetV2::READ;
// integrity == ExternalUntrusted  ⇒  effects ⊆ {READ}
```

它在每次构造、每次派生**以及每次 join 之后**重新施加。后者是关键：一个由可信父节点与不可信父节点派生出的值，其完整性经 join 后变为 `ExternalUntrusted`，必须随之失去可信父节点带来的授权效果。若没有这一步重施加，不变式在构造时逐点成立，却恰好在最重要的那次派生中被违反——我们称之为**效果洗白**（effect laundering）：从网页取回的攻击者收件人地址与用户授权的文档句柄合并后，继承 `SEND` 效果而通过基于效果的约束。G3 的来源初始化是封闭的：签名策略常量起于 `KernelTrusted`，经批准的输入起于 `UserAuthorized`，规划器输出、工具结果与恢复所得的执行结果**永远**是 `ExternalUntrusted`。

### 4.2 溯源 DAG

每个值伴随一个 `ProvenanceRecordV2`，记录其来源类型 `SourceKindV2`（8 个变体：`GatedIngress`、`KernelExtraction`、`PolicyConstant`、`PlannerOutput`、`ToolResult`、`Derived`、`KernelDeclassification`、`RecoveredExecution`）、父节点、根证据摘要、标签、生产者身份、运行 ID、活动状态清单摘要与过期时间。父节点数不超过 256，根证据不超过 64 条；跨运行或跨清单的父节点被拒绝（`CrossRunParent`、`CrossManifestParent`）；父值摘要与父溯源记录不一致被拒绝。这些编译期上限保证敌意谱系不能耗尽内核。`RecoveredExecution` 变体的存在，使得"在崩溃后才得知结果的动作所产生的值"携带诚实的溯源，而不与新鲜结果无法区分。

### 4.3 去密级：唯一的扩宽操作

#### 4.3.1 五个过渡与按接收者划分的职责

内核只定义五个去密级过渡（`provenance.rs`，`DeclassificationTransitionV2`）：

| 过渡 | 标签 | 目标 (confidentiality, readers) | 泄漏门职责 |
|---|---:|---|---|
| `MaskTokenizeAndLeakCheck` | 1 | (`AgentMasked`, `AGENT`) | blocklist **且** 无残留 PII |
| `BuildPlannerEnvelope` | 2 | (`PlannerAbstract`, `EXTERNAL_PLANNER`) | blocklist **且** 无残留 PII |
| `BuildApprovalDisplay` | 3 | (`AgentMasked`, `APPROVAL_DISPLAY`) | 仅 blocklist |
| `BuildExecutionEnvelope { executor_identity_digest }` | 4 | (`VaultBound`, `EXECUTOR`) | 仅 blocklist |
| `BuildFinalRelease { sink_identity_digest }` | 5 | (`VaultBound`, `EXTERNAL_SINK`) | 仅 blocklist |

职责的划分依据是**谁读取结果**，而不是机密性下降了多远。语言模型是唯一不能被信任持有个人数据的接收者——数据会变成提示上下文、训练输入或出站请求——因此两个面向 LLM 的过渡必须无残留 PII。人类审批者与执行器都需要真实的值才能完成工作；对它们做遮蔽不是更严格的门，而是坏掉的门（没有人能有意义地批准"把 `[电话号码]` 发给 `[邮箱]`"）。而 blocklist（注入指令）对所有接收者一律适用。

#### 4.3.2 精确接收者绑定

面向单一接收者的两个过渡把接收者的身份摘要放在**枚举变体内部**，使得"命名这个过渡"与"命名它的读者"不可分离。读者类只能表达"某个外部 sink 可以读"，无法区分用户要求的释放与释放到攻击者选择的目的地——而在出口边界，这个区别就是全部安全属性。全零身份被拒绝。

#### 4.3.3 检查者计算自己的证据

去密级构造器 `kernel_declassification` 是私有函数，它自己运行泄漏门并从实际观测计算证据摘要：

```rust
let leak_gate_digest =
    enforce_for_declassification(value, transition.leak_gate_duty().strictest(duty_floor))?;
```

`leak_gate_digest` **不是参数**。从调用方接受它，等于允许调用方断言一次内核无法核实的检查，而这恰恰发生在内核放弃机密性保证的那一点。构造器同时拒绝全零的规则、实现、token 集与用途摘要："授权自一条什么都不指的规则"的记录什么都不绑定。

#### 4.3.4 签名规则集与规则检查的内核入口

2026-08-01 之后新增的 `savana-policy-core/src/v2/declassification.rs` 提供了规则的**指称对象**：

- `DeclassificationRuleSetV2`：规范 CBOR 编码，签名标签 29，携带产品族摘要、序列号、前驱签名摘要（哈希链）、有效窗口和信任根集摘要；由用途为 `DeclassificationAuthority`（`OperationalTrustRootPurposeV2 = 5`）的操作信任根签名；其签名摘要必须等于部署清单中的 `declassification_rule_set_digest`（`deployment_manifest.rs:92`），验证通过但未被 pin 的规则集被拒绝。编译硬上限：每集最多 64 条规则，每条规则最多 16 个读者身份。
- `DeclassificationRuleV2`：绑定过渡标签、封闭用途（`ClosedDeclassificationPurposeV2`：`AgentIngressMasking`、`PlannerCall`、`ApprovalDisplay`、`ExecutionHandoff`、`FinalRelease`）、实现摘要、职责下限（duty floor）、可选的读者身份列表、可选的同意最大年龄（上限 300,000 ms）与有效窗口。
- 唯一的公开入口 `ProvenanceRecordV2::declassify(...)`（`provenance.rs:967`）依次检查：规则集窗口 → 存在授权该 (过渡, 用途) 的规则 → 规则窗口 → 规则的实现摘要等于该过渡**编译进内核**的实现摘要 → 精确读者身份在规则的读者列表内 → 若规则要求同意，则必须提供一个 `VerifiedFinalReleaseSettlementV2`，并对目的地、token 集、活动清单、签发时间与最大年龄做纯函数验证。全部通过后才调用私有构造器运行泄漏门。对最终释放（标签 5）还额外拒绝空的 token 集。
- `judge_handoff(transition, rule_set)` 返回三值判定：`Admits` / `Refuses` / `Unproven`。只有节点来源是 `KernelDeclassification` 且规则可在活动集中找到时才可能 `Admits`；标签的 confidentiality 与 readers 必须等于该过渡的目标，精确读者身份必须同时出现在规则和节点的根证据中。`Unproven` 与 `Refuses` 一样不能跨越服务边界。

#### 4.3.5 五条生产路径

这是与 2026-08-01 报告最大的差异：当时的 §8 明确写道构造器"没有生产调用者"。当前代码中五个过渡全部在 kerneld 生产路径上被实例化，并且 `judge_handoff != Admits` 即拒绝：

| 过渡 | 生产调用位置 | 结果去向 |
|---|---|---|
| `MaskTokenizeAndLeakCheck` | `savana-kerneld/src/v2_runtime.rs:294` | 去密级溯源摘要写入 `ReadAgentViewResponseV2` 和 vault 输入材料 |
| `BuildPlannerEnvelope` | `savana-kerneld/src/v2_agent_authority.rs:2556` | 规划器 ticket 携带去密级溯源摘要 |
| `BuildApprovalDisplay` | `v2_agent_authority.rs:3281, 4204, 5342`；`v2_ingress_authority.rs:643` | 签名审批信封携带精确展示字节与节点摘要 |
| `BuildExecutionEnvelope { executor }` | `v2_agent_authority.rs:3618` | 持久预封摘要绑定精确明文与节点摘要 |
| `BuildFinalRelease { sink }` | `v2_agent_authority.rs:4530` | 同上，且必须携带新鲜、精确、一次性的审批 settlement |

两个封装函数 `gate_execution_before_durable_prepare` 与 `gate_final_release_before_durable_prepare`（`v2_agent_authority.rs:267-298`）保证**门先于持久化准备**：门失败时持久准备闭包不可达，派发状态保持 `Authorized`，预留配额保持为零。持久预封摘要 = H(精确明文 ‖ 去密级节点摘要)，使恢复过程不能把同一字节别名到不同溯源。

#### 4.3.6 规则集的原子换代

`savana-kerneld/src/v2_declassification_policy.rs` 的 `ActiveDeclassificationRuleSetV2` 持有已验证信任根与一个 `Arc<RwLock<Arc<DeclassificationRuleSetV2>>>` 活动快照。候选字节经完整规范解码、摘要/签名/窗口/根验证，再在写锁下用 `validate_predecessor(Some(active))` 校验链接（序列连续、前驱摘要相等、产品族一致）后做一次原子指针交换；任何失败都保持旧活动集不变。去密级信任根也被绑进部署事务的 `ExpectedPreStateV2`，因此完整部署信任的闭包包含第四条信任链。

### 4.4 确定性泄漏门：一个谓词，一个实现

`savana-leak-gate` 是独立 crate，理由是依赖图：遮蔽发生在 `savana-input-runtime`（ingress），验证发生在 `savana-policy-core`（去密级），两者是只依赖协议 crate 的兄弟，谁都不能拥有定义而不反转依赖。历史上二者曾各自携带 PII 定义（一侧五类手写字节扫描器，另一侧 17 条模式），"两个定义不能靠检视达成一致，而遮蔽方与裁决方不一致正是值在仍携带敏感数据时被去密级的方式"。现在两侧调用同一组函数，`pii_spans` 取模式表与字节扫描器的**并集**，`pattern_set_digest` 折叠进每个门摘要。

实现细节上有一个值得记录的"正则引擎之墙"：blocklist 是从 Python `re` 移植的 21 条安全模式，Python 与 Rust `regex` crate 在 `\b`、`\s`、`\d`、`\w` 上语义不同，且 `\w` 的差异处于绕过方向（2,461 个标记/连接符在引擎里是词字符、在 Python 里不是）。因此所有字符类都改写为从 CPython 15.0.0 数据固定 vendored 的显式类，`\b` 改写为其两侧字面定义（需要环视，故用 `fancy-regex`），回溯有界，任何引擎运行时错误**按命中处理**——敌意输入只能造成过度阻断，不能造成漏检。`unicode-normalization` 被精确锁定在 `=0.1.22`（Unicode 15.0.0），因为升级会静默改变规范化结果。

差分语料：427 条手工向量（17 个行为组，如 `security_match` 107 条、`redact_pii` 30 条）加 6,000 条模糊向量（4,000 blocklist + 2,000 redaction），共 6,427 条，断言单向蕴含 `masked(x) ⇒ gate_passes(masked(x))`。这把一个架构假设变成可检查的属性：今天让遮蔽路径过门的误阻断代价为零；将来两半漂移之日，门会拒绝、ingress fail closed——是响亮的生产错误而非静默泄漏。

### 4.5 签名策略供应链与部署事务

内核中没有"配置"，只有**签名**。

**分层权威。** 安装者/MDM 密钥签发 `OperationalTrustRootSetV2`：规范编码、域分离、按 (序列, 前驱签名摘要) 哈希链接，成员按用途（`DeploymentAuthorization`、`RollbackAuthorization`、`InstallationActivation`、`InstallerOrMdm`、`DeclassificationAuthority`）分离，每个成员有嵌套在集合窗口内的有效窗口，按 (用途, key id, epoch) 排序去重，绑定摘要在解码时重算比对。其上依次是签名的部署清单与声明（发布身份、二进制与投影 pin、去密级规则集 pin）、由活动状态清单认证发布者密钥的签名工具描述符注册表（G4）、以及绑进每次派发的 G7 执行器材料（执行器身份、密钥 ID、密封公钥、连接器注册表摘要，类型层面拒绝零值）。

**验证纪律。** 三条性质在每个签名对象上反复出现：(1) **持有即已验证**——`OperationalTrustRootSetV2`、`VerifiedToolRegistryV2` 等类型字段私有、只有一个验证构造器，下游代码没有东西可以忘记重检；(2) **规范重编码相等**——解码、重编码、与输入字节比较，任何非规范编码（被改的字节、不同整数宽度、不定长容器）一律拒绝，整个工作区有 461 个互不相同的 NUL 结尾域分离字符串防止跨协议签名重用；(3) **链接而不修补**——撤销通过发布后继集合表达，前驱校验强制序列连续、摘要链接与族身份，没有墓碑也没有部分更新。

**部署事务。** `deployment_ledger.rs` 与 `deployment_transaction.rs` 实现一个双槽签名账本、29 个封闭安全域（`ClosedSecurityDomainV2`，从 `BinaryRelease` 到 `DeclassificationTrustRootSet`）的"历史最高"向量与摘要、单条记录 4 MiB 上限、固定 25 步/8 类证据语言的签名事务头（1 MiB 上限，≤ 4,096 条证据引用）、按 head-first/ledger-CAS 的类型化转换存储、固定 inode 的跨进程部署互斥、原生单调计数器推进与"持久后继槽和计数器推进之间"那一个崩溃窗口的恢复。`ABORTED → IDLE` 的压缩需要域 13 签名的 `EvidenceGcCheckpointV2`，而检查点由域 22 的 `InstallationEvidenceEnvelopeV2` 主机哈希链承载。转换崩溃矩阵覆盖每个 head、账本、原生计数器与最终重载的持久性边界。生产的 `savana-deploy` 与 `savana-deploy-watchdog` 在目标原生不可导出签名权威缺席时**故意退出为不可用**（§9）。

**fail-closed 启动。** 缺失、过期、错签或未 pin 的策略材料产生的是一个运行着但拒绝服务的内核，而不是一个宽松运行的内核。生产状态机测试要求损坏的引导材料下**没有任何套接字被绑定**——守护进程不提供降级服务。启动的路由完备性门证明全部 25 个 AgentKernel 与 12 个 IngressKernel 操作各有唯一封闭处理器后才发布 Ready。

### 4.6 审批与效果管线

**G6：两次不同的仪式。** 对 ingress、工具与最终释放审批，approvald 在一次新鲜的 `ApprovalDisplay` WebAuthn 认证建立起 approvald 源、主体、任务、信封、清单与标签页绑定的内存内 `ApprovalTabSessionCapabilityV2` 之前不返回任何展示内容；用户随后执行第二个、不同的 WebAuthn 决定仪式。展示认证与决定使用不同的签名类型、域、挑战、nonce、一次性状态与重放条目：展示认证永远不能批准，决定断言不能创建或恢复展示会话。approvald 持有按用途分离的 settlement 签名密钥（UI 认证、ingress、tool、release，以及连接器注册用途 4），用途替换在签名域层面失败。签名审批信封携带有界的**精确展示字节**与展示去密级节点摘要，approvald 与浏览器视图都重算并校验它们；因此人批准的正是被门过的那些字节。硬件 WebAuthn 注册要求 packed 直接证明、pin 的 AAGUID 与证明根，并拒绝可备份凭据。

**G7：先持久化，后效果。** 在向执行器写任何字节之前，kerneld 提交一个原子的效果准备事务：验证恰好一个封闭的 `DispatchSubjectV2` 变体（`ToolExecution` 绑定持久动作意图、描述符、完整参数绑定、溯源集与尝试类别；`FinalRelease` 绑定独立的持久释放 ID、vault 段、证据、token 集、展示/目的地投影与释放策略），消费执行/释放 ticket 与精确的审批 settlement，把配额从可用移到预留，锁定主体的每个字段与精确执行器和活动清单，创建**唯一**的执行 nonce，存储密封的主体专属信封、AEAD 密封的精确重放胶囊与 `Prepared` WAL 条目，并把该派发绑定到当前单调 `effect_fence_epoch`。配额按分支类型化：工具执行按 (持久运行, 尝试类别) 桶，最终释放按 (持久运行, 释放配额主体摘要) 桶，两者的计数器、键与解码器不能别名。

execd 的日志是外部字节边界的持久真相：`ProviderAttemptPrepared` → 签名的 `EffectStarted` 回执（fsync）→ 第一个 provider 字节 → `ProviderResponseRetained`（加密 fsync）→（最终释放另需 `ReleaseEvidencePrepared` 与签名最终回执）→ `CompletionAvailable`。回执与日志记录构成有向哈希 DAG。kerneld 侧的恢复状态机（`v2_recovery.rs`）把结果归入 `Prepared`/`Dispatching`/`EffectStarted`/`CompletionCommitted`/`FailedNoEffect`/`Indeterminate`，只有被证明的 `failed_no_effect` 可以重新规划，不确定效果与"效果成功但输出被隔离"永不自动重试。

**密码栈**（版本精确锁定）：Ed25519（`ed25519-dalek`，弱密钥拒绝）签名；SHA-256 域分离摘要；X25519 + HKDF + ChaCha20-Poly1305/AES-GCM 做信封密封与持久记录；`minicbor` 规范 CBOR；`getrandom` 熵源并对生成的 nonce 做显式零检查。

### 4.7 规划器隐私：值、形状、意图

`docs/planner-privacy-v2.md`（已实现，v1.2）指出遮蔽只保护第一层泄漏。使用远程规划模型的系统还泄漏两样东西：**形状**（计划结构：多少步、哪些能力类别、以何种数据流顺序到何种 sink）与**意图**（用户想做什么，它住在任务的动词里而不是值里）。实现在 `savana-agentd/src/planner_privacy.rs`，不改内核：

1. **mapperd（意图 LLM，位于用户的意图信任域）**：接收不含 nonce 的意图投影与活动工具 ∩ 本地语义目录，输出结构图。
2. **plannerd（规划 LLM，可为第三方）**：只看到封闭的结构图——每次运行重新铸造的节点 ID（域 `SAVANA_STRUCTURAL_NODE_ID_V2`）、`SOURCE|TRANSFORM|SINK` 角色、粗粒度效果类别、边与固定的"数据流排序"目标；节点上限 256，边上限 4,096。
3. **decode（确定性，非模型）**：把有序结构计划映射回 `tool_class` 步骤与本地 nonce。这里**必须不是模型**：一个会幻觉的 LLM 解码器可以选到另一个工具，这是安全缺陷而非优化问题。内核的 `resolve_class` 随后照旧完成授权。

意图暴露是一个显式旋钮：部署天花板 `PrivateOnly | UserMayUseThirdParty`，用户按任务选择，fail-safe 到私有；浏览器动作标签 2 是私有 mapper 路径，标签 16 是显式的第三方共享。TLS 身份与网络路由被分离：端点主机只用于 SNI/SAN/`Host`，签名 bootstrap 另携带有界、规范化、已排序的连接地址列表，agentd 无 DNS 回退；Linux 基础 unit `IPAddressDeny=any`，root 拥有的生成 drop-in 只放行已测量的唯一 IP。设计明示一个信息论下界：**谁生成计划，谁就知道计划的形状**；形状可以去语义化，但不能对规划者完全隐藏。

### 4.8 连接器自助注册

`docs/connector-registration-v2.md`（v1.2）的原则是"注册动词只存在于签名信道，运行时只做验证"。实现（`savana-policy-core/src/v2/connector_registry.rs` 及 kerneld/execd 侧）把连接器注册表变成一个**哈希链状态**：创世摘要与更新权威由部署信道 pin，自助注册只延长链，永不逃出链；kerneld 与 execd **独立**验证同一条链并收敛，链头分歧使派发像今天摘要不匹配那样失败。连接器有层级（`DeploymentShipped = 1`、`UserRegistered = 2`），层级是能力天花板：用户注册的连接器在结构上不能成为出口 sink（"registered ≠ releasable"），用户层受主机白名单约束，两层使用不同的标识符命名空间；每个描述符签入结构角色 `Source|Transform|Sink`，供 §4.7 的语义目录投影。注册提议只能从已认证的 8768 源标签页的描述符专属动作进入，kerneld 铸造一次性的、绑定精确描述符字节、当前注册表头、会话、主体、任务、运行、源、调用方启动、清单与世代的授权；被接受的提议生成用途 4 的审批信封，其人类展示包含层级、完整 URL/TLS pin 或 stdio 包摘要、每个工具的名称/效果/完整规范语义与完整规范描述符，并经真实的标签 3 去密级释放。硬上限：每安装最多 16 个用户连接器。

### 4.9 平台身份与沙箱

`savana-platform-identity` 提供对端、进程、可执行文件与服务管理器监听器的原生测量，以及 worker 沙箱启动器。Linux 使用 Landlock（路径规则）+ seccomp-BPF（`SECCOMP_RET_KILL_PROCESS` 默认）+ 描述符关闭 + 资源限制；macOS 使用默认拒绝的 Seatbelt profile、描述符关闭、CPU/文件/进程限制，并由固定父监督者在子进程超过测量物理内存足迹时终止它。解析（ingressd）与连接器编解码（execd）worker 是**一次一作业**、通过匿名继承管道通信的子进程：环境被清空，转录与输出有界，畸形或复用的作业被杀死并回收，缺失或改变的沙箱包装器/profile 使系统 fail closed。示例 profile（`deploy/sandbox/parser-profile-v2.example.json`）：1 GiB 内存、120 s CPU、16 个打开文件、1 个进程、拒绝全部网络。监听器必须从 systemd/launchd 继承，调用者不能指定任意套接字。

### 4.10 应用层集成

**V2 客户端 SDK**（`savana-client` + `savana-core-py`）：Rust 状态机拥有固定 HTTP 帧化、规范 CBOR、请求 nonce、能力类型、会话绑定、状态转换、截止时间、取消与响应校验；Python 不构造协议请求、不解码线缆响应、不签署审批、不选择内核操作。拓扑固定为三个回环服务（Agent 8768、Ingress 8767、Approval 8766），JARVIS 带外提供一次性 bootstrap 而非第四个服务。业务方法恰 15 个、产品类型恰 18 个；句柄不暴露原始字节也不能重标；输入返回"已提交完成"而非伪造的文档句柄；有界智能体循环只在精确的 `failed_no_effect` 后重新规划。

**OpenClaw 生产运行时**（`integrations/openclaw-savana-runtime` + `savana-openclaw-release`）：针对 `openclaw@2026.7.1-2` 精确 pin 的纯文本适配器，注册恰一个 provider、一个 model、一个 harness，**零** OpenClaw 工具、**零** MCP 服务器。一个被接受的回合是：当前入站文本 → 有界 NDJSON 桥 → Python 公开 SDK → `ingest_text` → `run_agent(PRIVATE, 有界限制)` → 每次工具调用（含只读调用）一个通过继承的 FD 3 产品认证 broker 的可信 UI `approval.decide` → 最终释放的又一次决定 → execd 按已验证的 `FinalRelease` 派发种类选择独立 pin 的释放传输（`split-final-release` 路由模式，两套 rustls mTLS 传输、两份私钥凭据）→ 固定的 127.0.0.1 TLS 1.3/mTLS 接收器 → 持久的单飞释放日志预留 → 一条 `turn.released` 文本 → 一条 assistant 消息。聊天文本永远不是审批信号；OpenClaw 只收到 `approval_required` 生命周期事件，看不到展示文本或审批 ID；状态类结果不能变成 assistant 文本；释放超时、桥或接收器崩溃、重复或跨回合投递、隔离输出与不确定效果都密封该回合。`docs/openclaw-deployment-acceptance-gate.md` 明确区分**源码级证据**（路由测试、桥毒化测试、doctor 重算 SPKI/证书摘要）与**尚待记录的现场验收证据**（真实 execd 派发与硬件 WebAuthn 序列）。

---

## 5. 工程方法论与可迁移的设计原则

以下原则中，前三条在 2026-08-01 的论文草稿中已从真实缺陷抽取；其余由本次阅读当前代码补充。它们是本项目最可迁移的部分。

| 编号 | 原则 | 代码中的体现 |
|---|---|---|
| P1 | **持有即已验证** | 已验证类型字段私有、单一验证构造器；65 处 `compile_fail` 文档测试把"不能构造/不能克隆/不能取种子"作为可编译检查的负向 API 契约（`savana-kerneld/src/lib.rs`） |
| P2 | **规范重编码相等** | 每个签名对象解码后重编码比对；461 个域分离字符串 |
| P3 | **链接而不修补** | 信任根集、规则集、连接器注册表、部署账本全部哈希链接；撤销 = 发布后继 |
| P4 | **检查者计算自己的证据** | `leak_gate_digest` 在私有构造器内由门产生，不从调用方接受（§4.3.3） |
| P5 | **一个谓词，一个实现，并机械化其一致性** | `savana-leak-gate` + 6,427 条差分向量 + `pattern_set_digest`（§4.4） |
| P6 | **空绑定必须在构造时拒绝** | 全零规则/实现/token 集/用途摘要与全零读者身份被拒；执行器材料的零摘要在类型层拒绝 |
| P7 | **门先于持久化准备** | 两个 `gate_*_before_durable_prepare` 顺序边界，门失败不触碰派发与配额 |
| P8 | **三值判定，未证明即拒绝** | `HandoffJudgmentV2::Unproven` 与验证器的 admit/refuse/unproven |
| P9 | **按接收者而非按机密性落差分配职责** | `LeakGateDutyV2` 的两档职责与规则的 duty floor 取最严 |
| P10 | **冻结的生产核心** | 164 文件 SHA-256 清单 + 对清单检查器自身的对抗测试，作为 CI 第一步 |
| P11 | **按数据流而非按符号审计** | 2026-08 的评估曾因构造器无调用者而误判出口管线不存在；出口管线存在且精细，只是绕过了溯源系统 |
| P12 | **规格驱动 + RED/GREEN + 独立复审** | `docs/superpowers/specs`（12 份设计）、`plans`（21 份计划）与 `.superpowers/sdd` 报告记录每项发现的失败测试→修复→通过证据与独立安全复审结论 |

一个方法论层面的观察：仓库的文档量（32,039 行 Markdown，其中三份 V2 主规格分别为 1,885、8,576、6,792 行）与代码量处于同一数量级，且规格对"什么算完成"给出四级证据（源码、工件、平台、产品）。这使得"实现是否符合设计"本身成为可审计的对象。

---

## 6. 评估与证据

### 6.1 规模

| 度量 | 值 |
|---|---:|
| Rust 源码 | 295,615 行 / 421 文件 / 16 crate（11 个冻结） |
| Python | 6,622 行 / 26 文件 |
| TypeScript（OpenClaw 插件） | 2,447 行源码 + 1,118 行测试 |
| Markdown 文档 | 32,039 行 / 48 文件 |
| 提交 | 184 次（2026-07-20 至 2026-09-02），6 个已合并 PR |
| 内核操作 | AgentKernel 25、IngressKernel 12、KernelExecutor 5、JARVIS 控制 4、连接器控制 2（标签 70/71） |
| 编译硬上限表 | 32 项（`HARD_LIMIT_VALUES_V2`，规范 CBOR 摘要锁定） |

### 6.2 测试资产

| 类别 | 数量 |
|---|---:|
| Rust `#[test]` 函数 | 1,568（policy-core 403、kerneld 385、protocol 216、ner 166、agentd 126、client 85、execd 63、platform-identity 41、ingressd 26、approvald 17、openclaw-release 12、leak-gate 11、vault 7、input-runtime 5、audit-bridge 5） |
| 集成测试文件 | 92 |
| 单元测试模块 | 163 |
| `compile_fail` 文档测试 | 65 |
| Python 测试函数 | 39（对遗留 Python 实现的差分测试）+ 41（SDK、OpenClaw 桥与运行时） |
| TypeScript 测试 | 29 |
| 泄漏门差分/模糊向量 | 427 + 6,000 = 6,427 |
| 遗留 NER 差分向量（`vectors/differential`） | body_leak_gate 1,239、json_amount 479、body_should_compress 208 等 |
| 冻结的 V1 线缆金标向量 | 7 个文件（`vectors/kerneld`，附 SHA-256） |

值得单独指出的对抗性套件：`policy_attack_matrix.rs`（671 行：签名伪造、双花、过期与坏签名的拒绝优先级、跨启动与跨换代重放）、`production_state_machine.rs`（601 行：损坏/部分/熵故障的安装材料必须不绑定任何套接字）、`v2_crash_matrix.rs`、`v2_declassification_rules.rs`（821 行：规范形状与 EOF、独立重算的摘要、签名标签/域变异、未授权签名者、用途/过渡归属不匹配、非法读者与同意形状、零/重复/未排序值、窗口、前驱成功/缺失/回滚/分叉、编译上限、错误的信任根用途）、`anti_rollback.rs`，以及 execd 与 ingressd 的 `worker_isolation.rs`。

### 6.3 本次核验的运行结果

在本会话的 Linux x86_64 容器（4 vCPU，以 root 运行，Rust 1.82.0，`--locked`）中执行：

| 套件 | 结果 |
|---|---|
| `savana-leak-gate` | 11 / 11 通过（含差分蕴含属性） |
| `savana-kernel-protocol` | 197 / 197 通过（44 单元 + 153 集成，覆盖规范 CBOR、帧上限、V1 线缆、V2 各服务线缆、传输、操作矩阵） |
| `savana-policy-core`（库） | 191 / 191 通过 |
| `savana-policy-core`（二进制 `savana-systemd-agentd-network-policy-v2` 单元测试） | 1 失败：`metadata_contract_requires_root_owned_exact_modes_and_single_link` 断言临时目录**不是** root 拥有的合规 drop-in；以 root 运行时该前提不成立。属环境假设（测试预期非特权用户），非产品缺陷 |

CI 等价的全工作区运行（`--all-targets --all-features --no-fail-fast`，排除需要 ONNX Runtime 与 Python 解释器的 `libsavana-ner` 与 `savana-core-py`）的逐目标结果见附录 C。概括地说：13 个 crate 的全部库、集成与示例测试目标通过，其中包括 policy-core 的 26 个集成套件（去密级规则负向矩阵 9/9、部署控制 30/30、反回滚 4/4 等）、kerneld 的 V2 崩溃矩阵、并发、端到端与最终模式套件、execd 与 ingressd 的 worker 隔离套件、client 的 7 个工作流套件以及 openclaw-release 的 3 个套件。未通过的 8 个目标全部归因于两个环境前提：(a) kerneld 的 V1 `policy_*`、`production_state_machine` 与启动身份测试**显式要求非特权运行者**（`startup_identity_tests.rs:699` 断言 `daemon_uid != 0`；守护进程引导校验 uid/gid 所有权），以 root 运行时测试守护进程在引导阶段退出，随后进程级测试锁 poison 造成 47 例连锁 `PoisonError`——这正是 README"构建和验证"一节预先描述的失效模式；(b) `linux_worker_sandbox` 要求内核提供 Landlock，本容器（Firecracker 6.18 微内核）没有 `/sys/kernel/security/landlock`，包装器按设计 fail closed。本会话无法创建非特权用户重跑（操作被环境策略拒绝），因此 kerneld 的这些套件在本文中记为"未在本环境验证"，而非通过或失败。仓库 CI（`.github/workflows/ci.yml`）在 ubuntu 与 macos 上运行冻结核心检查、`fmt`、`clippy -D warnings`、全特性测试、macOS 原生沙箱强制测试、`cargo doc` 与 release 构建，Linux 上另做 `systemd-analyze verify`。

### 6.4 已获得的属性与尚未获得的证据

当前机械地强制执行的属性：

| 编号 | 属性 | 证据 |
|---|---|---|
| E1 | 不可信值只读 | `UNTRUSTED_EFFECT_CEILING_V2` 在构造、派生与 join 后施加 |
| E2 | 派生不扩大受众 | `derive_normal` 交集 |
| E3 | 门只能运行，不能断言 | 摘要在私有构造器内计算 |
| E4 | 去密级记录命名精确读者 | 身份在变体内；零身份拒绝 |
| E5 | 遮蔽者与验证者共享一个定义 | 单一 crate + 6,427 向量 |
| E6 | 签名对象要么规范验证要么拒绝 | 重编码相等 |
| E7 | 拒绝顺序确定 | 攻击矩阵的优先级测试 |
| E8 | 判定三值，未证明即拒绝 | `judge_handoff`、验证器 |
| E9 | **每条扩宽路径都经过签名规则授权的门**（新） | §4.3.5 五处生产调用 + 规则集负向矩阵 |
| E10 | **`confidentiality` 与 `readers` 维度承重**（新） | `judge_handoff` 比对目标标签与读者集 |
| E11 | **最终释放的同意是纯验证的、一次性的、绑定精确释放的** | `VerifiedFinalReleaseSettlementV2` + WAL 精确重放规则 |

尚未获得的证据（仓库自身如实陈述，本文照录）：

- **没有性能评估**：没有吞吐、延迟或开销数字；任何此类声明都将是编造的。
- **没有第三方安全审计或渗透测试**；**没有形式化验证**——不变式靠构造强制并测试，未被证明。
- **检测召回率是单模态的**：确定性模式 + 字节扫描器的召回低于测量过的 NER 模型；失效方向安全（过度阻断），但召回未达设计意图（§9）。
- **硬件根信任缺席**：`open_native_deployment_authority_handles_v2` 在当前树中返回 `NativePlatformAuthorityUnavailable`；部署二进制故意不可用；仓库不宣称 `PlatformComplete`/`ProductComplete`。
- **OpenClaw 的现场验收证据**（真实 execd 派发、硬件 WebAuthn 序列、doctor 零发现报告）尚待记录。
- 两份 2026-08-21 与 2026-09-01 批准的 macOS 设计（Secure Enclave 凭据、浏览器所有者认证）目前只有协议层的仪式状态类型落地（commit `9b48da6`），approvald 与启动器侧未实现。

---

## 7. 与 2026-08-01 报告的差异

| 当时的限制 | 当前状态 | 依据 |
|---|---|---|
| L1 去密级门无生产调用者 | **已关闭**：五个过渡全部接入（§4.3.5） | `v2_runtime.rs:294`、`v2_agent_authority.rs:2556/3281/3618/4530`、`v2_ingress_authority.rs:643` |
| L2 `confidentiality`/`readers` 被计算但无人读取 | **已关闭**：`judge_handoff` 比对二者并可拒绝 | `provenance.rs:1152` |
| L3 没有签名的去密级规则面 | **已关闭**：`DeclassificationRuleSetV2`、信任根用途 5、清单 pin、原子换代 | `declassification.rs`、`deployment_manifest.rs:92`、`v2_declassification_policy.rs` |
| L4 出口强但未过门 | **已关闭**：最终释放过 `BuildFinalRelease` 门，token 集非空，同意纯验证且一次性 | `.superpowers/sdd/.../final-fix-report.md` Finding 1 |
| L5 召回单模态 | 未变；设计 §12 预留"测量 worker 只能增加遮蔽"的接入方式 | `docs/declassification-v2.md` |
| L6 无审计/形式化/性能 | 未变 | — |
| 连接器注册需要部署换代 | **已关闭**：哈希链自助注册 + 层级天花板（§4.8） | commits `31bc148`…`6855d66` |
| 规划器信封硬编码单一意图 | **已关闭**：封闭 `PlannerPurposeV2`、签名策略与请求限制取分量最小 | final-fix-report Finding 2 |
| 规模 | 233,730 → 295,615 行 Rust；14 → 16 crate；1,165 → 1,568 测试函数 | 附录 A |
| 新增面 | 客户端 SDK、规划器隐私、OpenClaw 运行时与逐调用审批、拆分最终释放传输 | §4.7、§4.10 |

需要修正的一处既有表述：`README.md` 写"28-domain highest-ever vector"，代码常量 `HIGHEST_EVER_DOMAIN_COUNT_V2` 与 `ClosedSecurityDomainV2` 的变体数均为 29（第 29 个是 `DeclassificationTrustRootSet`）。

---

## 8. 相关工作

**信息流控制。** 标签模型承自格模型 IFC（Denning）、去中心化标签模型（Myers & Liskov）与 IFC 操作系统（Asbestos、HiStar、Flume），后者确立了进程粒度的流控制与"去密级是显式特权操作"。Savana 的贡献不在格本身，而在其应用：读者集是**系统角色与命名的外部身份**而非用户；去密级职责按接收者可信度——具体说，按接收者是否是语言模型——分配；精确接收者身份被绑进过渡。

**LLM 智能体安全。** CaMeL 一系确立了控制流/数据流分离与值上的能力，并在原型规模上证明可行。Savana 共享其架构论点，差异在工程完备性与三层隐私。基于检测与指令层级的提示注入防御是互补的，但在 Savana 迁走的那条边界之内运作。沙箱方法约束代码而非权威。

**机密计算与供应链。** 清单、信任根与密封信封纪律借鉴二进制透明性与 in-toto 式供应链完整性，但施加于**策略**而非工件。

**认证。** 审批依赖 WebAuthn 的用户存在/验证标志、硬件证明根与签名计数器；macOS 路线转向 Secure Enclave 平台凭据的设计已被批准但尚未实现。

---

## 9. 局限与未来工作

1. **平台适配器。** 需要一个被选定、被测试的不可导出 Linux/macOS 密钥库适配器、硬件单调回滚权威，以及消费这些句柄的原生 apply/recovery 操作。目标部署必须标识发行版、架构、HSM/PKCS#11 参数（Linux）或 Team ID、bundle ID、签名要求、provisioning 与 entitlement（macOS）。V2 固定 Ed25519；仅 P-256 的硬件目标需要显式协议修订而非静默算法替换。
2. **召回率。** 设计预留：一个测量过的 ONNX NER worker 可以**提议**片段，提议只能增加遮蔽，确定性并集仍是下限，门仍是唯一裁决者，worker 输出为 `ExternalUntrusted`；`pattern_set_digest` + 算法版本把召回改进变成可见的签名策略变更。
3. **形式化。** §4.1 与 §4.3.3 的不变式以散文陈述、以构造强制；用精化类型或证明助手对标签代数机械化是自然的下一步。
4. **评估。** 投稿所需而尚缺的测量：每过渡的门开销、端到端动作延迟对比无门基线、标签/溯源内存开销随 DAG 深度的函数、对已发表提示注入语料的"结构上不可能 vs 被检测"分类、带过度阻断率的 PII 召回测量、以及一个把拒绝追溯到标签状态的端到端案例研究。
5. **形状隐私下界。** 远程结构化规划模式下规划器仍看到节点数、粗粒度角色/效果与拓扑；若连拓扑也必须隐藏，需要本地规划器或固定模板选择。
6. **环境敏感的测试。** 生产 Unix 套接字测试需要允许创建本地套接字的宿主；受限沙箱可能先报 `IdentitySocketPermissions` 再因进程级测试锁 poison 连锁失败，README 要求在宿主重跑而不得作为产品通过或失败；本文 §6.3 观察到的 root 环境假设属于同一类。

---

## 10. 结论

Savana Core 是对智能体安全问题"正确架构"的一次严肃尝试：能力约束加信息流控制，由内核强制而非向模型请求。与一个月前相比，最重要的变化是它的中心机制从"安全因为从不扩宽"变成了"安全因为扩宽被治理"：每条扩大受众的路径都经过签名规则授权、内核内部运行、按接收者分配职责、命名精确读者、生成不可变溯源节点的去密级门，而 `confidentiality` 与 `readers` 两个维度第一次成为承重的判定输入。贯穿代码库的工程纪律——不能未经验证就构造的类型、规范编码、哈希链权威、默认拒绝、确定的拒绝顺序、作为一等溯源来源的崩溃恢复、门先于持久化——在成熟的系统安全工作之外并不常见。

它同样清楚自己没有的东西：硬件根信任、第三方审计、形式化证明、性能数字与现场验收记录。本文认为，第二类陈述的精确程度，正是第一类陈述得以被相信的前提。

---

## 附录 A：度量方法

所有数字于 2026-09-03 在 commit `bee2ed3` 的工作树上测得。

```sh
# 代码规模
find crates -name '*.rs' | xargs cat | wc -l                      # 295,615
for d in crates/*/; do find "$d" -name '*.rs' | xargs cat | wc -l; done
find . -name '*.py' -not -path './target/*' | xargs cat | wc -l    # 6,622
find . -name '*.md' -not -path './target/*' | xargs wc -l | tail -1 # 32,039
git log --oneline | wc -l                                          # 184

# 测试资产
grep -rE '^\s*#\[(test|tokio::test)\]' crates --include='*.rs' | wc -l   # 1,568
find crates -path '*/tests/*.rs' -not -path '*/support/*' | wc -l        # 92
grep -rl '#\[cfg(test)\]' crates --include='*.rs' | wc -l                # 163
grep -rc 'compile_fail' crates --include='*.rs' | awk -F: '{s+=$2} END {print s}'  # 65

# 域分离字符串（NUL 结尾字节串字面量，去重）
grep -rhoE 'b"[A-Za-z0-9_./:\-]+\\0"' crates --include='*.rs' | sort -u | wc -l  # 461

# 泄漏门向量
python3 -c "import json; v=json.load(open('crates/savana-leak-gate/src/vectors.json')); print(sum(map(len, v.values())))"        # 427
python3 -c "import json; v=json.load(open('crates/savana-leak-gate/src/fuzz_vectors.json')); print(sum(map(len, v.values())))"   # 6,000

# 去密级生产调用点
grep -rn 'ProvenanceRecordV2::declassify(' crates/savana-kerneld/src
```

## 附录 B：术语对照

| 术语 | 含义 |
|---|---|
| 去密级（declassification） | 唯一能扩大一个值的读者集合/降低机密性标签的内核操作；必须经签名规则授权与泄漏门验证 |
| 泄漏门（leak gate） | `savana-leak-gate` 中"何为敏感"的确定性定义：21 条内容 blocklist 模式 + 17 条 PII 模式 + 字节扫描器的并集 |
| settlement | approvald 对一次 WebAuthn 仪式结果的签名结论；按用途分离签名域，一次性消费 |
| 效果门（EffectGate） | agentd/execd 与部署助手共享的 OS 文件锁与账本投影，证明效果未被围栏 |
| 围栏纪元（effect_fence_epoch） | 部署事务推进的单调计数，绑进每次派发准备 |
| 冻结核心（frozen V2 core） | 164 个生产源文件的 SHA-256 清单，CI 第一步校验 |
| Suite-1 | 守护进程间的认证加密传输套件（X25519 + Ed25519 + HKDF-SHA-256 + HMAC + ChaCha20-Poly1305） |
| G1–G7 | 七个策略门，见 §3.3 |

## 附录 C：CI 等价测试运行的逐目标结果

命令：`cargo test --workspace --exclude libsavana-ner --exclude savana-core-py --all-targets --all-features --no-fail-fast --locked`
环境：Linux x86_64 容器（Firecracker 内核 6.18，无 Landlock），4 vCPU，**以 root 运行**，Rust 1.82.0。运行时间 2026-09-03 03:47–约 04:00 UTC。

| crate | 目标 | 结果 |
|---|---|---|
| savana-agentd | lib / main / macos_startup / planner_privacy_e2e | 120 + 1 + 0 + 4 通过 |
| savana-approvald | lib / bins / state_owner / macos_startup | 12 + 1 + 2 + 1 通过 |
| savana-client | lib + 7 个工作流套件 | 4 + 15 + 11 + 11 + 11 + 2 + 4 + 27 通过 |
| savana-execd | lib / main / v2_connector_registry / worker_isolation | 50 + 1 + 9 + 2 通过 |
| savana-ingressd | lib / main / state_owner / worker_isolation | 21 + 1 + 1 + 2 通过 |
| savana-input-runtime | lib | 5 通过 |
| savana-kernel-protocol | lib + 22 个集成套件 + 示例 | 44 + 153 + 19 通过 |
| savana-kerneld | lib | 244 通过，49 失败（环境：root 运行者，见 §6.3） |
| savana-kerneld | cli / deployment_units / v2_concurrency / v2_crash_matrix / v2_end_to_end / v2_final_mode | 2 + 4 + 1 + 3 + 1 + 1 通过 |
| savana-kerneld | policy_attack_matrix / policy_fail_stop / policy_protocol | 0/11、0/4、0/4（环境：测试守护进程在引导阶段以 `BootstrapFailed` 退出） |
| savana-kerneld | policy_rollover / production_state_machine | 10/19、1/6（同上） |
| savana-leak-gate | lib | 11 通过 |
| savana-openclaw-release | request / reservation / server | 4 + 5 + 3 通过 |
| savana-platform-identity | lib / native_peer | 13 + 4 通过 |
| savana-platform-identity | linux_worker_sandbox | 0/2（环境：内核无 Landlock，包装器 fail closed） |
| savana-policy-core | lib + 26 个集成套件 + 示例 | 191 + 196 + 13 通过 |
| savana-policy-core | bin `savana-systemd-agentd-network-policy-v2` 单元测试 | 0/1（环境：断言临时目录非 root 拥有） |
| savana-vault | lib | 7 通过 |

macOS 专属目标（`macos_*`）在 Linux 上为 0 个测试，属预期。两个 `policy-core` 库测试的 stderr 中出现的 `panicked at ledger.rs:584` 与 `rollover.rs:429` 是**注入的**子进程 panic（测试名含 `guard_aborts`），对应目标结果为通过。
