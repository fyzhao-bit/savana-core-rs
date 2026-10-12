# 五个组件的状态核对（2026-10-12）

对象是一张组件状态表（私密续行、残余数据契约、自动发布策略综合、结构化规划、连接器注册），
表本身不在仓库里。做法：把每一行拆成子说法，逐条对照源码、测试和既有记录，再抽查关键结论
（`7cd8c86`、`a56f3bd` 的提交内容，schema-3 观察测试，用户注册连接器的 SEND 测试，mapper 越界处理，
评测的替换次数）。本次只运行了 `savana-continuation-core` 的 `core` 测试（36 个通过，含新补的 2 个），
没有重跑其他测试，也没有核验正在运行的部署。

## 结论一览

| 组件 | 原表状态 | 核对结论 |
| --- | --- | --- |
| 私密续行 | 部分实现 | **写过头了**：(1)(3)(4) 已实现、在内核运行、被评测使用；(2)(5) 已过时 |
| 残余数据契约 | 理论方案，T1–T3 待证 | **准确**；C1–C6、K1–K6 也未实现，另有一个受限替换已接入内核 |
| 自动发布策略综合 | 有界验证原语，本身不签发授权 | **准确**；只在测试中使用，"按效用排序"实为公开给定的顺序 |
| 结构化规划 | 扩展 | **标签准确，描述有两处错**："本地 mapper 生成结构图"、"默认退回私有规划" |
| 连接器注册 | （未填） | **部分实现**；"永远不能成为外发接收方"没有作为规则实现，审批显示只部分渲染含义 |

## 一、私密续行

说法出自第 43 批记录（`docs/research/v04-product-implementation.md`、`result-dependent-loop-v04.md`），
运行在 fused v0.4 路径上；内核里没有单独的"私密续行模式"，`savana-private-workflow` 是没有守护进程依赖的研究原型。

| 子说法 | 结论 | 依据 |
| --- | --- | --- |
| (1) 内核持有结果，只准备下一个就绪操作 | 已实现，评测每步都走 | `fused_planning.rs`（`ExecutionBinding.result_value`、`next_operation`），`v04_fused_compiler.rs`、`v04_fused_actions.rs`，由 `tick_private_workflows_v04` 驱动；测试 `fused_private_loop_completes_two_dependent_clauses_without_repreparing_consumed_work` 等 |
| (2) 结果只能填文本 payload，不能填资源或目的地 | **已过时** | `7cd8c86`（2026-09-30）起，整段结果仍只进 payload，但按 JSON 路径取出的值可填资源/目的地/参数（`fused_task_compiler.rs`，测试 `compiler_allows_a_result_edge_into_a_nonpayload_field_structurally`）；G4 核对 owner 签名的规则，目的地由 G5 底线升级为审批（`063764c`）。评测的实际内容都在参数字段里，payload 是空占位 |
| (3) 执行器清理前原子、加密检查点 | 已实现，评测每步都走 | `v2_agent_authority.rs` `commit_tool_completion`：vault 提交 → 结果提交 → `record_fused_result_value_v04`（一次 AES-256-GCM、带防回滚锚的提交）→ 确认执行器；测试 `fused_private_g7_recovers_vault_outcome_and_checkpoint_crash_boundaries` 等 |
| (4) 恢复不续期权利 | 对已有执行的检查已实现；重启路径不完整 | 按原始准入时间核验、过期结果拒收、清理重试不重新派发（测试 `fused_result_loop_revocation_stops_downstream_without_resetting_consumption` 等）。但 kerneld 重启后私密会话不恢复，`v2_recovery.rs` 是未接入的代码，崩溃矩阵没有重开内核自己的状态，评测没有测重启 |
| (5) 模型线格式不变，不接收结果数据 | **一半对** | 模型回复不能携带结果数据（测试 `model_cannot_supply_result_bindings_or_result_bytes`）；但 schema-3 轮次里经 G3 发布的结果观察会进入规划器视图（测试 `fused_dynamic_observation_from_real_execution_through_g3_survives_reopen` 断言规划器看到 `"value":"succeeded"`），`a56f3bd` 也改了截止时间的编码。评测的规划轮没有观察，但抽取工具会收到整段结果 |

## 二、残余数据契约

- C1–C6、K1–K6、T1–T3 的定义在 `docs/research/savana-private-continuation-framework.zh-CN.md` §5；
  文档自称"待实现与证明"。
- 代码里没有残余契约的构造（找不到 `Residualize`、`ReplacementSpec`、`T_replace` 或 C1–C3、C6 的实现），
  没有 K2、K4（用于替换）、K6 的检查器，也没有 T1–T3 的证明（纸面或机器检查都没有）。
- 已有构件：多域、全有或全无的消费账本（`ledger.rs`，C5 依赖的原子预留）；观察槽 pin/freeze（`observation.rs`，C4 的一块）；
  有界双世界检查和商构造（`release.rs`、`quotient.rs`，只在测试中使用）。
- 受限替换已实现并接入内核：新计划只能重排剩余操作并保留已开始的前缀（`planning.rs` `PlanningState::activate`，
  `fused_planning.rs` `FusedPlanningUpdateV04::Activate`，kerneld `tick_fused_planning`），有 9 个测试。
  文档明确说它"不构成 C1–C6/K1–K6 的一般覆盖"。评测的每个任务 `max_replacements: 0`，从未替换计划。

## 三、自动发布策略综合

- `release.rs` `synthesize_release`：候选上限 64（字面量，超出返回 Unknown，不截断）；排序就是调用方传入的顺序
  （注释"Public order supplies utility ranking"），不计算效用分；双世界检查对同基线的初始状态对，公共命令同步执行、
  输出逐字节相同，私有步骤两侧独立穷举；证书是可达状态对集合，由 `verify_certificate` 独立重建后继复核；
  反例在新候选上具体重放，仍能区分就跳过该候选（不做泛化）。
- 与设计文档的差别：设计要求"无解"附可复核的排除证据，代码只返回 `NoSolutionInLibrary`；
  设计允许遇到未决候选继续往后试，代码遇到第一个 Unknown 即整体返回 Unknown。
- 没有被 crate 之外的任何代码调用；没有任何东西用它的结果授权或发布。
- 本次补了两个此前没有的测试（`3f486c8`）：超过 64 个候选返回 Unknown（64 个仍正常搜索）；
  已存反例通过重放淘汰后面一个泄露方式相同的候选，不做完整检查。

## 四、结构化规划

- 已实现并接入 agentd 守护进程（`planner_privacy.rs`、`mapper_client.rs`、`planner_client.rs`、`browser_authority.rs`），
  有十几项测试，包括固定证书 mTLS 的端到端测试；只连过测试替身，仓库里没有 mapper 或规划器的模型服务。
- mapper 是用户信任域内、经 mTLS 访问的模型服务（`POST /savana.mapper.v2/map`），不是 agentd 进程内的组件；
  它返回具体工具绑定，结构图由 agentd 的 `relabel` 构造。
- 规划器只收到 `[2, nodes, edges, goal]`：每次重新生成的 16 字节标识、Source/Transform/Sink 角色、效果位和边；
  确定性解码器按表映射回工具类并要求完整、合依赖的排列。
- 意图暴露开关：每次请求选私有（tag 2）或第三方（tag 16），部署上限 `PrivateOnly`/`UserMayUseThirdParty`。
  **没有"退回私有"**：越界或未配置第三方端点时，在任何网络调用之前返回 `BoundaryDenied`/`InvalidDeployment`。
- 评测没有使用：AgentDojo 的规划器（`deepseek-flash`）直接收到 owner 请求文本和工具说明，起草完整程序。

## 五、连接器注册

| 子说法 | 结论 | 依据 |
| --- | --- | --- |
| 哈希链注册表 | 已实现、有测试、已接入 | 链头 = H(上一链头 ‖ 签名增量摘要)；Ed25519 严格验签、序号 +1、前驱一致、规范编码；kerneld 与 execd 各自重放并交叉核对链头；状态加密并有防回滚锚（`connector_registry.rs`、`connector_store.rs`、`production.rs`、execd `connector_registry.rs`） |
| 用户注册的连接器有能力上限 | 部分 | 不能申请 FINAL_RELEASE；HTTPS 主机白名单（解码、应用增量、执行器连接三处检查）、数量上限、分层派生 ID。设计中的"更严配额档""逐次审批档"未实现 |
| 永远不能成为外发接收方 | **没有作为规则实现** | 用户注册的描述符可以申请 SEND、声明 Sink，测试明确接受（policy-core `tests/v2_connector_registry.rs` 的 READ\|SEND 用例）。目前实际发不出去，是因为内核只派发启动时签名的工具，"让用户注册的工具进入 G4"（设计 R4）尚未实现 |
| 每次注册经独立用途审批，显示完整描述符的含义 | 审批已实现；含义只部分渲染 | 用途 4 有独立的信封和结算域，绑定描述符摘要和上一链头，每次新增都要审批（删除按设计不需要）。显示中名称、URL、证书指纹、能力、角色、工具名可读；业务配置（含目的地字段和目标）、校验器、执行器、重试和有效期只以 base64 CBOR 附带 |

评测没有使用：部署的连接器授权密钥为零、白名单为空，只带两个部署自带连接器；评测的预同意回调拒绝注册请求。

## 改正后的表格

| 组件 | 描述 | 状态 |
| --- | --- | --- |
| 私密续行 | 内核持有私密结果，只准备下一个就绪的操作；整段结果只能填文本 payload，按固定 JSON 路径取出的值可以填资源、参数或目的地字段，但须与 owner 签名的规则一致，数据填的目的地升级为 owner 审批，都不能改额度；工具字节和来源在执行器清理前原子检查点、加密保存；恢复按原始准入时间核验，不续期权利；模型的回复不能携带结果数据，经 G3 发布的结果观察可以进入规划器视图 | 已实现并用于评测；内核重启后的私密会话恢复未接通 |
| 残余数据契约 | 任务中途换计划时，把旧计划未完成的义务、消费账本和披露状态压缩成"相对于接口的残余契约"，新计划只能在其中接续。构造规则 C1–C6，检查义务 K1–K6 | 理论方案：C1–C6、K1–K6 未实现，T1–T3 未证明；已实现的只有受限替换（只能重排剩余操作、保留已开始前缀，已接入内核，评测未使用）及消费账本、观察 pin/freeze 等构件 |
| 自动发布策略综合 | 从至多 64 个按公开给定顺序排列的候选发布策略里，找第一个通过严格双世界（关系式）检查的，并给出可独立复核的证书；不通过的给出具体反例，用重放剪掉后面的候选 | 有界验证原语，只在测试中使用，本身不签发授权；"无解"不带排除证据，遇到"未知"即整体中止 |
| 结构化规划 | 私有 mapper（用户信任域内经 mTLS 访问的模型服务）把工具绑定到不透明槽位，agentd 据此构造结构图；第三方规划器只看每次重新生成的标识、粗角色和边来排序；再由确定性解码器映射回工具类。是否向第三方暴露意图是每次请求的显式选择，默认和部署上限都是私有，越界请求直接拒绝 | 扩展：已实现并接入 agentd，未评测，仓库内没有 mapper/规划器模型服务 |
| 连接器注册 | 哈希链注册表，内核与执行器独立重放校验，状态加密并防回滚；用户注册的连接器不能申请最终发布，受主机白名单和数量限制；每次新增经独立用途的审批，显示名称、URL、证书指纹、能力和工具名 | 部分实现：已接入守护进程，评测未使用（自助注册关闭）；"不能成为外发接收方"尚无规则保证（用户注册的工具目前进不了派发），配额档与逐次审批档未实现，业务配置未渲染给人看 |

## 未完成部分的分类

**A. 不改冻结文件、本次已完成**

- `README.zh-CN.md` 中"结果仅能进入已签名的正文槽"的过时说法已改正；第 43 批的两份历史记录加了勘误，原文保留。
- 发布综合补了上限与重放剪枝两个测试（`3f486c8`）。
- `experiments/savana_bench/regressions.py` 中一个已改名的测试名已改正（`3f486c8`）。

**B. 要改冻结文件**（需要同意，并在最后统一复核、重新生成冻结清单）

| 组件 | 要做的事 | 涉及的冻结文件 |
| --- | --- | --- |
| 私密续行 | 内核重启后恢复私密会话；处理未接入的 `v2_recovery.rs` | kerneld `v2_startup.rs`、`v2_recovery.rs`、`lib.rs`、`v04_fused_recovery_driver.rs`；policy-core `durable.rs`、`fused_planning.rs` |
| 自动发布策略综合 | "无解"附排除证据；遇"未知"继续试后面的候选 | continuation-core `release.rs`（也可以放进新 crate，经公开接口实现，不改冻结文件） |
| 连接器注册 | 按层级禁止用户注册的连接器作为外发接收方；把业务配置渲染进审批显示；R4（用户注册工具进入 G4）；配额档与逐次审批档 | policy-core `connector_registry.rs`、`dispatch.rs`、`provenance.rs`；kerneld `v2_agent_authority.rs`、`v2_connector_authority.rs`、`v2_startup.rs` |
| 残余数据契约 | 把检查器接进换计划流程 | policy-core `fused_planning.rs`；continuation-core `planning.rs`；kerneld `v04_fused_host.rs` |

**C. 理论工作**

- 残余数据契约：C1–C6 构造与 K1–K6 检查可以先做成新 crate 里的有界检查器（不改冻结文件），
  对照完整检查器验证"增量接受必被完整检查接受"；T1–T3 需要写出明确假设和证明，
  有界测试不能替代参数化结论。
