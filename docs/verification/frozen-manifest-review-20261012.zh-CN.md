# 冻结清单变更审阅（2026-10-12）

冻结清单 `deploy/frozen-v2-core.files` / `.sha256` 列出 331 个核心文件及其 SHA-256，
CI（`.github/workflows/ci.yml`）每次运行 `tools/check-frozen-v2-core.sh` 校验。
清单最后一次生成于 2026-09-29（`643fa5e`）。

当前有 71 个文件与清单不一致：

- 26 个是本次会话（2026-10-12）在你同意修改冻结文件之后改的，逐一列在第一节；其中 20 个在本次之前就已漂移。
- 45 个是 2026-09-30 至 10-07 各批工作留下的，本次没有碰，列在第二节。
- 其中 `crates/savana-kerneld/src/v2_recovery.rs` 已删除，所以校验脚本在 `test -f` 一步就会失败。
  在本次之前，旧的漂移已经让这项检查不通过。

**清单尚未重新生成。** 等你审阅同意后再做（第四节）。重新生成会同时认可第二节的 45 处漂移。

## 一、本次会话改动的冻结文件

| 文件 | 提交 | 改了什么 | 为什么 | 测试 |
| --- | --- | --- | --- | --- |
| `crates/savana-continuation-core/src/release.rs` | `23e0364` | `Synthesis` 增加排除证据（`Exclusion`、`verify_exclusions`）；遇到未决候选记下并继续往后试 | 设计要求"无解"附可复核证据、未决不应中止搜索（F1） | continuation-core `core` 38 个 |
| `crates/savana-kerneld/src/lib.rs` | `648f5b6` | 删去 `v2_recovery` 模块声明 | 该状态机从未接入（F3） | `cargo check` |
| `crates/savana-kerneld/src/v2_recovery.rs` | `648f5b6` | 删除文件 | 同上；清单需移除此项 | — |
| `crates/savana-kerneld/src/v2_agent_authority.rs` | `07508b1` | 连接器注册审批显示里渲染每个工具的含义 | 审批者看得懂描述符（F2） | `connector_display_renders_what_each_tool_means` |
| 同上 | `be52a80` | 任务记录增加加密保存的重连材料；权限快照升到 schema 6；恢复时带材料的运行中任务保持运行；撤销时清除 | kerneld 重启后 owner 重新登录接续（F3） | 私密会话 4 个新测试、重启端到端测试 |
| 同上 | `aaf063b` | 保留部署工具表，按连接器链重算 G4；用户层工具每次调用都按"必须审批"评估 | 设计 R4 | `a_user_registered_tool_needs_the_owners_approval_for_every_call` 等 |
| `crates/savana-kerneld/src/v04_private_session.rs` | `be52a80` | 登录门：首次登录用已提交输入，重启后的登录只用同一 run 的保留副本 | F3 | `fused_private_login_gate_admits_first_input_or_kept_copy_never_both` 等 |
| 同上 | `d2249ce` | 登录门区分首次、重启后、过期后续登三种；续登时同一会话和 run 延到新登录的上限；只保留最新登录接收交接 | 本进程内登录过期后可再登录 | `fused_private_session_continues_the_same_run_after_its_login_expires_in_process`、`fused_result_loop_continues_after_the_owner_login_expires_in_process` |
| `crates/savana-kerneld/src/v2_value_owner.rs` | `d2249ce` | 新增 `extend_private_run_v04`：同一 run 的期限延到新登录上限，值的来源期限不变 | 同上 | 同上 |
| `crates/savana-kerneld/src/v2_core_services.rs` | `aaf063b` | 批准新增和删除连接器之后先重算 G4，再同步执行器 | R4 | `approved_user_connector_tools_join_g4_and_leave_on_removal` |
| `crates/savana-policy-core/src/v2/descriptor.rs` | `aaf063b` | 活动工具记录带层级；`with_user_registered` 组合；测试特性下的改层级辅助函数 | R4 | policy-core 455 个 |
| `crates/savana-policy-core/src/v2/mod.rs` | `aaf063b` | 导出 `USER_REGISTERED_TOOL_ORDINAL_V2` | R4 | 同上 |
| `crates/savana-policy-core/src/v2/connector_registry.rs` | `aaf063b` | 只加了测试（文件内 `tests` 模块） | R4 | `user_registered_tools_join_g4_tagged_once_and_leave_with_their_connector` |
| `crates/savana-policy-core/src/v2/provenance_tests.rs` | `07508b1` | 只加了测试 | 最终发布读者必须由部署规则点名（F2） | `final_release_to_a_sink_the_deployment_rule_does_not_name_is_refused` |
| `crates/savana-input-runtime/src/lib.rs` | `7ed61ba` | 脱敏改为反复进行：用占位符同形的替身遮盖后再查，查到的残留区域并入原区域，直到内核复核用的 `redact_pii(masked) == masked` 成立；8 轮内不收敛则拒绝 | 一次遮盖可能让剩下的字符落到新的词边界上又被识别（AgentDojo banking 15 的 IBAN 里 `13301240023` 被遮后，`1215421872` 被当成电话号码），内核以"残留 PII"拒绝，这条 owner 输入永远提交不了（历次运行 5/5 失败） | `masking_continues_until_the_verifier_finds_nothing_left`、`residual_regions_map_back_over_the_stand_ins_they_touch` |
| `crates/savana-kerneld/src/v2_runtime.rs` | `7ed61ba` | 只改了测试：把已有输入提交测试的准备步骤提成辅助函数，加一条端到端测试（不修上面的问题时以 `Provenance` 失败） | 同上 | `an_account_number_whose_masking_exposes_another_number_still_commits` |
| `crates/savana-kernel-protocol/src/v2/business_controls.rs` | `4e7c577` | 新增 `ResultCandidatesV2`（1–64 个成员、总计 ≤4 KiB、按字节严格升序、精确比较）；派生规则可带集合（只用于不计算的文本或文本列表），规范字节在 6 元素形式里写入集合，因此所有提交该规则的摘要都提交集合；不带集合的规则字节不变；解码上限相应放宽 | U7：owner 签名时给数据派生的目的地附一个候选集合，内核派生时逐字节检查成员资格 | `tests/result_candidates.rs` 5 个 |
| `crates/savana-kernel-protocol/src/v2/business_request.rs` | `4e7c577` | 导出新类型和常量 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-kernel-protocol/src/v2/mod.rs` | `4e7c577`、`b98a04a` | 导出新类型和常量；`b98a04a` 只是 rustfmt 重排导出顺序 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-kernel-protocol/src/v2/task_context.rs` | `4e7c577` | owner 草稿 JSON 的派生规则可带 `candidates`（排序后校验，重复则拒绝） | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-kernel-protocol/src/v2/task_draft.rs` | `4e7c577` | 根审批显示列出集合，并说明集合内的值视为 owner 的选择、其余值仍需批准；有集合时显示版本为 3，其余根的显示不变 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-kernel-protocol/src/v2/task_action_display.rs` | `4e7c577`、`b98a04a` | 单步审批显示列出集合和 `in_candidates`（具体值是否成员，列表逐项）；有集合时版本为 3；`b98a04a` 改为从请求自己的字段取值判断成员（原来到 JSON-RPC 外层去找，永远判为非成员，U7 的第一批主机运行因此全部被软件 owner 拒绝），并加了用真实请求渲染的测试 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-continuation-core/src/planning.rs` | `4e7c577` | `SlotBinding.result_candidates`（只能在不计算的路径边上，非空、严格升序、有界）；配方摘要按整个操作序列化，自动包含它 | U7：签名时附候选集合，内核逐字节检查成员 | continuation-core 全部 |
| `crates/savana-policy-core/src/v2/fused_task_compiler.rs` | `4e7c577` | 按绑定重建派生规则时带上集合，G4 在准备和派发时用摘要比对，绑定无法放宽或去掉集合 | U7：签名时附候选集合，内核逐字节检查成员 | `a_trusted_set_edge_is_matched_with_its_set_and_a_binding_cannot_widen_it` |
| `crates/savana-policy-core/src/v2/provenance.rs` | `4e7c577` | 新派生操作（标签 11）只记录集合摘要；只有 `result_candidate_member_v04` 能产生它：先按原路径取值，成员（列表逐项）才把不可信父值的完整性提为 `UserAuthorized`，保密性、读者、效果不变，根证据记入集合摘要；普通派生拒绝标签 11，代理接口没有入口 | U7：签名时附候选集合，内核逐字节检查成员 | `a_signed_candidate_member_is_endorsed_and_nothing_else_is` |
| `crates/savana-policy-core/src/v2/fused_inputs.rs` | `4e7c577` | 派生结果值时，带集合且取到成员就走背书，否则与普通边完全相同（仍为不可信，G5 照旧要求批准）；G7 用同一函数重算，因此集合也受 G7 约束 | U7：签名时附候选集合，内核逐字节检查成员 | `a_trusted_set_edge_endorses_only_a_member_and_g7_binds_the_set` |
| `crates/savana-policy-core/src/v2/fused_plan_adapter.rs` | `4e7c577` | 只改测试里的结构体字面值（新字段 `None`） | U7：签名时附候选集合，内核逐字节检查成员 | policy-core 458 个 |
| `crates/savana-policy-core/src/v2/fused_recipe_approval.rs` | `4e7c577` | 只改测试里的结构体字面值（新字段 `None`） | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-policy-core/src/v2/provenance_tests.rs` | `4e7c577`、`b98a04a` | 加 U7 测试；`b98a04a` 只是 rustfmt 换行 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-agentd/Cargo.toml` | `2b3d6e3` | 加一个 `[[example]]`：`structured_plan_eval`，`required-features = ["test-support"]` | 结构化规划评测（F5）调用 agentd 真实的私有规划管线；不改 agentd 库代码，不带该特性的构建不编译它 | `experiments/tests/test_structured_example.py` 等 61 个 |

残余数据契约（F4）计划放在新 crate 里，不改冻结文件；工作区根 `Cargo.toml` 不在清单里。

## 二、本次之前就已漂移、本次没有碰的 45 个文件

| 文件 | 改动它的提交（新→旧） |
| --- | --- |
| `crates/savana-agentd/src/daemon.rs` | f718f83 |
| `crates/savana-agentd/src/lib.rs` | f718f83 |
| `crates/savana-approvald/src/daemon.rs` |  |
| `crates/savana-approvald/src/protocol_service.rs` |  |
| `crates/savana-client/src/approval.rs` | f718f83 |
| `crates/savana-client/src/lib.rs` | f718f83 |
| `crates/savana-client/src/managed_admin.rs` | f718f83 |
| `crates/savana-client/src/task_authorization.rs` | f718f83 |
| `crates/savana-core-py/Cargo.toml` | 55149f8 |
| `crates/savana-core-py/src/client.rs` | f718f83 |
| `crates/savana-core-py/src/lib.rs` | 55149f8 |
| `crates/savana-execd/src/daemon.rs` | 755ba70 |
| `crates/savana-execd/src/durable.rs` | 746b71f |
| `crates/savana-execd/src/lib.rs` | 746b71f |
| `crates/savana-ingressd/src/daemon.rs` | f718f83 |
| `crates/savana-kernel-protocol/src/v2/application.rs` | 03eb2b6 |
| `crates/savana-kernel-protocol/src/v2/browser_assets.rs` | f718f83 |
| `crates/savana-kernel-protocol/src/v2/private_session_v04.rs` | 03eb2b6 |
| `crates/savana-kernel-protocol/src/v2/task_execution_payload.rs` | f718f83 5d8c80b |
| `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs` | f718f83 800aca1 |
| `crates/savana-kerneld/src/v04_fused_compiler.rs` | f718f83 7c0c016 4249f34 |
| `crates/savana-kerneld/src/v04_fused_final_result.rs` | 4249f34 |
| `crates/savana-kerneld/src/v04_fused_release_driver.rs` | 62a70d2 b637672 |
| `crates/savana-kerneld/src/v04_fused_release_recovery.rs` | b637672 02a3966 |
| `crates/savana-kerneld/src/v2_data_plane.rs` | ce3b3fd |
| `crates/savana-kerneld/src/v2_startup.rs` | f718f83 755ba70 d8b9b01 |
| `crates/savana-leak-gate/src/lib.rs` | f718f83 ee39ed8 |
| `crates/savana-leak-gate/src/tests.rs` | f718f83 ee39ed8 |
| `crates/savana-platform-identity/src/lib.rs` | f718f83 |
| `crates/savana-policy-core/src/bin/savana-development-material.rs` |  |
| `crates/savana-policy-core/src/v2/binding.rs` | 407bfca |
| `crates/savana-policy-core/src/v2/continuation_state.rs` | f718f83 |
| `crates/savana-policy-core/src/v2/deployment_authorization.rs` | f718f83 |
| `crates/savana-policy-core/src/v2/deployment_native_bootstrap.rs` | f718f83 |
| `crates/savana-policy-core/src/v2/descriptor_tests.rs` | f718f83 53e18ed |
| `crates/savana-policy-core/src/v2/durable.rs` | f718f83 |
| `crates/savana-policy-core/src/v2/fused_planning.rs` | 407bfca 199e438 |
| `crates/savana-policy-core/src/v2/managed_admin.rs` | f718f83 a67b7e3 |
| `crates/savana-policy-core/src/v2/validator.rs` | 063764c 178dd4e |
| `crates/savana-policy-core/src/v2/validator_tests.rs` | 063764c 178dd4e |
| `crates/savana-policy-core/src/v2/value.rs` | f718f83 407bfca |
| `deploy/linux/integration/assemble.py` | 4bcbc70 b69e2e5 |
| `deploy/linux/integration/build.py` | eef8b39 |
| `deploy/linux/integration/install.py` |  |
| `deploy/systemd/savana-execd.service` | 9dba683 |

提交说明：

- `063764c`（2026-10-07）Make G5 flow confinement fail-closed and confine read addresses
- `f718f83`（2026-10-03）style: rustfmt the files this branch left unformatted
- `55149f8`（2026-10-03）feat(privacy): a value-blind planner view, masked by the kernel's leak gate
- `407bfca`（2026-10-01）feat(kernel): typed text lists and computed result-derived origins
- `746b71f`（2026-10-01）fix(execd): commits re-verify only the journal entries they change
- `5075460`（2026-10-01）fix(kernel-protocol): a parameter text may exceed 1 KB
- `62a70d2`（2026-10-01）fix(kernel): finished releases stop taking turns in the release rotation
- `ee39ed8`（2026-10-01）fix(leak-gate): scan the blocklist in bounded windows
- `eef8b39`（2026-10-01）perf(deploy): build integration daemons with optimized code generation
- `4249f34`（2026-09-30）feat(kernel): G4 matches a result-derived control against the owner rule
- `7cd8c86`（2026-09-30）feat(kernel): compiler accepts result-derived edges into non-payload fields
- `a56f3bd`（2026-09-30）fix(planning): send the model-view deadline as fixed-width bytes
- `755ba70`（2026-09-30）feat(g7): ship deployment connectors bound to the registry genesis
- `03eb2b6`（2026-09-30）fix(protocol): give the private publication attach a response contract
- `5d8c80b`（2026-09-30）fix(kernel): a result-derived step can be displayed, sealed and re-verified
- `9bf8ac2`（2026-09-30）feat(protocol): result-derived control in the signed root (rule-commitment)
- `407ab0e`（2026-09-30）feat(protocol): request alternative under result-derived rules (the G4 key)
- `af2d39d`（2026-09-30）feat(protocol): owner draft_from_json accepts a result-derived control edge
- `ed1a8ea`（2026-09-30）feat(protocol): show result-derived edges to the owner and admit them
- `1a525f3`（2026-09-30）fix(protocol): keep result-derived controls out of root drafts for now
- `800aca1`（2026-09-30）fix(bench-deploy): planner envelope allows every shipped tool's action template
- `7c0c016`（2026-09-30）feat(kernel): refuse an unsigned result edge at prepare, before any effect
- `b637672`（2026-09-30）fix(kerneld): keep settled releases out of the fused release rotation
- `02a3966`（2026-09-30）fix(kerneld): scope fused publications to the task authorization root
- `ce3b3fd`（2026-09-30）feat(kerneld): retain the consented owner document for fused input derivation
- `d8b9b01`（2026-09-30）fix(kerneld): bind production vault to the agentd kernel-client boot id
- `53e18ed`（2026-09-30）test(policy-core): write descriptor + IntentFlowConfinement admits and activates
- `7056daf`（2026-09-30）test(kernel): extraction<->G7 integration for a result-derived edge
- `199e438`（2026-09-30）feat(kernel): extract a result scalar and allow the derived field at G7
- `30a501c`（2026-09-30）chore(policy-core): result_source_clause on remaining SlotBinding literals
- `a67b7e3`（2026-09-30）fix(kernel): an untrusted plan cannot set the model budget or view text
- `23ce7ad`（2026-09-30）feat(policy-core): kernel-side strict scalar extraction from a verified result
- `178dd4e`（2026-09-30）feat(policy-core): deployment rule — write tools must bind IntentFlowConfinement
- `4bcbc70`（2026-09-30）feat(full-dojo): generator ships authorizing write tools with IntentFlowConfinement
- `b69e2e5`（2026-09-30）feat(full-dojo): catalog-driven read-tool deployment, provider and checks
- `9dba683`（2026-09-30）fix(systemd): let execd start the connector worker sandbox

## 三、本次没有改动的检查结果

- 清单的 `.files` 与 `.sha256` 路径一一对应，均已排序。
- 除 `v2_recovery.rs` 外，所有列出的文件都存在，没有符号链接。

## 四、审阅同意之后的重新生成步骤

```sh
# 1. 从文件列表移除已删除的文件
grep -vx 'crates/savana-kerneld/src/v2_recovery.rs' deploy/frozen-v2-core.files > deploy/frozen-v2-core.files.new
mv deploy/frozen-v2-core.files.new deploy/frozen-v2-core.files
# 2. 按列表顺序重新计算哈希
while IFS= read -r p; do shasum -a 256 "$p"; done < deploy/frozen-v2-core.files > deploy/frozen-v2-core.sha256
# 3. 用 CI 同一个脚本复核
tools/check-frozen-v2-core.sh && sh tools/tests/check-frozen-v2-core.sh tools/check-frozen-v2-core.sh
```

若决定把新文件纳入冻结范围（例如 F5 的 agentd 示例），先按字典序加入 `.files` 再执行第 2 步。

## 五、2026-10-13 第二轮：内核修复（K1–K6）、死代码清除（K7）、门禁修复（K8）

用户在 10-13 授权"解除冻结内核、全部修好"。从上一节写成时的 `8e4a6e8` 到本轮结束，
清单中有 **78 个文件**被改动，另删除 2 个清单文件，新增 11 个应纳入清单的核心文件。
清单将在本节之后按第四节的步骤重新生成（这次一并认可第二节的 45 处旧漂移）。

### 5.1 改动按主题

| 主题 | 提交 | 冻结文件里改了什么 | 为什么 | 测试 |
| --- | --- | --- | --- | --- |
| K1 跳过已被拒绝的任务 | `e155076` | `v04_fused_action_driver.rs`：下一步被 owner 拒绝的任务不再反复驱动 | 被拒任务会占住 60 s 窗口拖慢后续 episode | 驱动测试 |
| K2–K4 条件门、抄送目的地、固定字段、owner 常量绑定、计算步骤 | `5e9a6d8` | kernel-protocol 业务控制/请求/任务上下文/授权/动作显示；policy-core 控制选择、描述符、校验器、fused 任务编译与输入；kerneld agent authority | 内核在派发前强制 `when` 门；cc/bcc 作为目的地受审；owner 常量逐字段绑定；计算步骤成为内核派生 | 各 crate 新增测试 |
| K5 执行器自答与模型调用遮蔽 | `21517c0` | execd 连接器运行时与 worker 监督（关门直接回 `CONDITION_SKIPPED`、表计算由执行器本地算）；leak-gate 新 `masking` 模块；core-py `ModelMask` | 不需要提供方的步骤不出执行器；模型调用经内核侧遮蔽，满足"无残余 PII"义务 | execd 59、leak-gate 遮蔽测试 |
| K7 编译器报告的死代码 | `ea9fe0f` | execd 未用构造器和恢复路径；kerneld 连接器授权未用访问器、测试专用注册提案移入测试；TPM 锚点只在用它的构建里编译 | 无调用者 | kerneld connector 30、execd 59 |
| K7 ingressd 旧 worker 栈 | `636a727` | 删除 `ingressd/src/state_owner.rs`（清单移除该项） | 已被协议原生 worker 取代 | ingressd 全部 |
| K7 approvald 第一代审批服务 | `87f24af` | approvald `lib.rs`、`protocol_durable.rs`；vault `lib.rs`、`Cargo.toml`（不再依赖 approvald）；kerneld `v2_runtime.rs`；删除 `approvald/src/state_owner.rs`（清单移除） | 生产只用协议原生服务；命名空间替换检查移植到协议持久化存储的测试 | approvald 53、vault 10 |
| K7 kerneld v1 运行时 | `a6e2463` | kerneld `lib.rs`、`Cargo.toml` 等（被删的 v1 文件不在清单） | v1 只能经测试环境变量到达，生产只跑 V2 | kerneld 275 + 集成 |
| K7 policy-core v1 引擎 | `5f9e1f6` | policy-core `Cargo.toml`、`v2/durable.rs`（原子替换失败只报阶段） | v1 引擎只服务已删的 v1 内核 | policy-core 391 |
| K7 kernel-protocol v1 线协议 | `931dd64` | kernel-protocol `Cargo.toml`；kerneld `v2_startup.rs`（测试时钟改报 `UnixMillisV2`） | 无 v1 使用者；`Clock` 改报 V2 时间类型 | kernel-protocol 全部 |
| K7 被 `allow(dead_code)` 掩盖的死代码 | `15baa88` | 见提交说明：删除 Suite-1 之前的签名帧派发模式、内核派发签名身份、本体集合成员谓词（解码器从不产生、内核调用时集合恒空）、agentd 门控客户端、client 未建句柄种类等；测试专用部分改 `cfg(test)` | 生产与线路都不可达 | 9 个 crate 110 个测试二进制 |
| K8 门禁 | K8（本节提交） | clippy `-D warnings` 归零（十六进制拼接改 `fold`、少量 `allow` 与类型别名）；`deployment_units` 识别三个实验单元；网络策略元数据测试与运行身份无关；Linux 沙箱拒读测试不再受测试输出重定向到普通文件的影响（清单外测试文件） | CI 门禁与全量测试必须通过 | 全工作区 `--all-targets --all-features` |

### 5.2 被删除的清单文件

- `crates/savana-ingressd/src/state_owner.rs`（`636a727`）
- `crates/savana-approvald/src/state_owner.rs`（`87f24af`）

两项已在各自提交里从 `.files` / `.sha256` 移除。

### 5.3 新纳入清单的核心文件

- `crates/savana-leak-gate/src/masking.rs`（模型调用遮蔽表，K5）
- `crates/savana-policy-core/src/v2/model_masking.rs`（遮蔽的策略包装，K5）
- `crates/savana-table-compute/` 的 `Cargo.toml` 与 `src/*.rs`（执行器本地计算，K4/K5；已在 `workspace_boundary` 的冻结核心成员里）

### 5.4 仍未接线、需要设计决定的部分（未改动语义）

- agentd 的内核签名任务声明校验器（`kernel_authority.rs`）：部署时校验密钥、线程里传递，但派发从不调用；内核侧签名者只在测试里存在。保留原状，待决定是接线还是整体移除。

### 5.5 逐文件提交对照（自动生成）

| 文件 | 提交 |
| --- | --- |
| `crates/savana-agentd/src/lib.rs` | `15baa88` |
| `crates/savana-agentd/src/mapper_client.rs` | `15baa88` |
| `crates/savana-approvald/src/lib.rs` | `15baa88`、`87f24af` |
| `crates/savana-approvald/src/protocol_durable.rs` | `87f24af` |
| `crates/savana-approvald/src/protocol_service.rs` | K8（本节提交） |
| `crates/savana-client/src/approval.rs` | `15baa88` |
| `crates/savana-client/src/lib.rs` | `15baa88` |
| `crates/savana-client/src/types.rs` | `15baa88` |
| `crates/savana-continuation-core/src/planning.rs` | K8（本节提交） |
| `crates/savana-core-py/src/client.rs` | K8（本节提交） |
| `crates/savana-core-py/src/lib.rs` | `21517c0` |
| `crates/savana-execd/Cargo.toml` | `21517c0` |
| `crates/savana-execd/src/connector_runtime.rs` | `21517c0` |
| `crates/savana-execd/src/daemon.rs` | `ea9fe0f`、K8（本节提交） |
| `crates/savana-execd/src/lib.rs` | `15baa88`、K8（本节提交） |
| `crates/savana-execd/src/protocol_service.rs` | `ea9fe0f` |
| `crates/savana-execd/src/provider_transport.rs` | `15baa88` |
| `crates/savana-execd/src/worker_protocol.rs` | `15baa88` |
| `crates/savana-execd/src/worker_supervisor.rs` | `15baa88`、`21517c0`、K8（本节提交） |
| `crates/savana-kernel-protocol/Cargo.toml` | `931dd64` |
| `crates/savana-kernel-protocol/src/v2/business_controls.rs` | `5e9a6d8`、K8（本节提交） |
| `crates/savana-kernel-protocol/src/v2/business_request.rs` | `5e9a6d8` |
| `crates/savana-kernel-protocol/src/v2/kernel_ingress.rs` | K8（本节提交） |
| `crates/savana-kernel-protocol/src/v2/mod.rs` | `5e9a6d8` |
| `crates/savana-kernel-protocol/src/v2/task_action_display.rs` | `5e9a6d8` |
| `crates/savana-kernel-protocol/src/v2/task_authorization.rs` | `5e9a6d8` |
| `crates/savana-kernel-protocol/src/v2/task_context.rs` | `5e9a6d8`、K8（本节提交） |
| `crates/savana-kernel-protocol/src/v2/task_execution_payload.rs` | K8（本节提交） |
| `crates/savana-kernel-protocol/src/v2/transport.rs` | K8（本节提交） |
| `crates/savana-kerneld/Cargo.toml` | `a6e2463` |
| `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs` | K8（本节提交） |
| `crates/savana-kerneld/src/lib.rs` | `15baa88`、`a6e2463`、`ea9fe0f`、K8（本节提交） |
| `crates/savana-kerneld/src/v04_fused_action_driver.rs` | `e155076` |
| `crates/savana-kerneld/src/v04_fused_actions.rs` | `15baa88` |
| `crates/savana-kerneld/src/v04_fused_compiler.rs` | `15baa88` |
| `crates/savana-kerneld/src/v04_fused_release_recovery.rs` | K8（本节提交） |
| `crates/savana-kerneld/src/v2_agent_authority.rs` | `15baa88`、`ea9fe0f`、`5e9a6d8`、K8（本节提交） |
| `crates/savana-kerneld/src/v2_connection.rs` | `15baa88` |
| `crates/savana-kerneld/src/v2_connector_authority.rs` | `ea9fe0f` |
| `crates/savana-kerneld/src/v2_core_services.rs` | `15baa88`、K8（本节提交） |
| `crates/savana-kerneld/src/v2_declassification_policy.rs` | `15baa88`、K8（本节提交） |
| `crates/savana-kerneld/src/v2_dispatch.rs` | `15baa88` |
| `crates/savana-kerneld/src/v2_edge.rs` | `15baa88` |
| `crates/savana-kerneld/src/v2_ingress_authority.rs` | K8（本节提交） |
| `crates/savana-kerneld/src/v2_kernel_owner.rs` | `ea9fe0f` |
| `crates/savana-kerneld/src/v2_listener.rs` | `15baa88` |
| `crates/savana-kerneld/src/v2_runtime.rs` | `15baa88`、`87f24af` |
| `crates/savana-kerneld/src/v2_startup.rs` | `15baa88`、`931dd64` |
| `crates/savana-kerneld/src/v2_state_owner.rs` | K8（本节提交） |
| `crates/savana-kerneld/src/v2_task_authority.rs` | K8（本节提交） |
| `crates/savana-kerneld/src/v2_transport_owner.rs` | `15baa88` |
| `crates/savana-kerneld/src/v2_value_owner.rs` | `15baa88` |
| `crates/savana-leak-gate/Cargo.toml` | `21517c0` |
| `crates/savana-leak-gate/src/lib.rs` | `21517c0` |
| `crates/savana-policy-core/Cargo.toml` | `5f9e1f6` |
| `crates/savana-policy-core/src/bin/savana-linux-integration-manifest.rs` | K8（本节提交） |
| `crates/savana-policy-core/src/bin/savana-systemd-agentd-network-policy-v2.rs` | K8（本节提交） |
| `crates/savana-policy-core/src/v2/control_selection.rs` | `5e9a6d8`、K8（本节提交） |
| `crates/savana-policy-core/src/v2/descriptor.rs` | `5e9a6d8` |
| `crates/savana-policy-core/src/v2/dispatch.rs` | `15baa88` |
| `crates/savana-policy-core/src/v2/durable.rs` | `15baa88`、`5f9e1f6`、K8（本节提交） |
| `crates/savana-policy-core/src/v2/durable_tests.rs` | `15baa88` |
| `crates/savana-policy-core/src/v2/fused_inputs.rs` | K8（本节提交） |
| `crates/savana-policy-core/src/v2/fused_planning.rs` | K8（本节提交） |
| `crates/savana-policy-core/src/v2/fused_task_compiler.rs` | K8（本节提交） |
| `crates/savana-policy-core/src/v2/intent.rs` | `15baa88` |
| `crates/savana-policy-core/src/v2/managed_admin.rs` | K8（本节提交） |
| `crates/savana-policy-core/src/v2/mod.rs` | `15baa88`、`5e9a6d8` |
| `crates/savana-policy-core/src/v2/ontology.rs` | `15baa88` |
| `crates/savana-policy-core/src/v2/ontology_tests.rs` | `15baa88` |
| `crates/savana-policy-core/src/v2/production.rs` | `15baa88` |
| `crates/savana-policy-core/src/v2/provenance.rs` | `15baa88` |
| `crates/savana-policy-core/src/v2/provenance_tests.rs` | K8（本节提交） |
| `crates/savana-policy-core/src/v2/quota.rs` | `15baa88` |
| `crates/savana-policy-core/src/v2/task_state.rs` | K8（本节提交） |
| `crates/savana-policy-core/src/v2/validator.rs` | `5e9a6d8` |
| `crates/savana-vault/Cargo.toml` | `87f24af` |
| `crates/savana-vault/src/lib.rs` | `87f24af` |

### 5.6 重新生成结果

按第四节的步骤重新生成：移除已删除的 `crates/savana-kerneld/src/v2_recovery.rs`，按字典序加入 5.3 的 11 个文件，
逐文件重算 SHA-256。清单现为 **339 个文件**；`tools/check-frozen-v2-core.sh` 逐项 OK，
`tools/tests/check-frozen-v2-core.sh` 自测通过。此后改动任何清单文件都会让 CI 的第一步失败，需要再走一次本流程。

## 六、2026-10-14 第三轮：macOS 上对端关闭之后重设套接字超时失败

**现象。** `kerneld (macos-latest)` 的 `cargo test` 每次随机挂 5–12 个 `fused_compiler_tests`，每次挂的都不一样；Linux 上全部通过。
失败位置各不相同：

- `v04_fused_dispatch_tests.rs:704`：空 tick 之后磁盘状态变了；
- `:940`：第二个 effect 没有执行；
- `:1139`：派发意外失败；
- `:1358` 和 `:1563`：`Unavailable`。

它们的起因相同：内核到执行器的某次交换意外返回了 `Unavailable`，后面的断言再以各自的方式失败。

**根因。**

- XNU 在套接字两个方向都已关闭（`SS_CANTRCVMORE | SS_CANTSENDMORE`）时，对任何 `setsockopt` 都返回 EINVAL（`bsd/kern/uipc_socket.c` 的 `sosetoptlock`）。
- Unix 流套接字的一端关闭时，`unp_disconnect` 会把两端都置成这个状态（`bsd/kern/uipc_usrreq.c`）。
- 各帧通道每次读写之前，都用 `set_read_timeout` / `set_write_timeout` 重设剩余时间。
- 执行器写完响应就立即关闭连接。如果执行器在内核重设读超时之前就关了，macOS 上这次重设会失败，内核于是把已经在接收缓冲区里的响应当成"服务不可用"。
- Linux 允许这次 `setsockopt`，所以只有 macOS 会出问题；测试并行越多、负载越重，出现得越频繁。

### 6.1 回归测试（`a259b72`）

测试先于修复单独提交，目的是让 macOS CI 在修复之前先把失败复现出来。这些测试在 Linux 上都通过。按 XNU 源码，修复之前它们在 macOS 上必然失败，因为对端 `drop` 之后 `setsockopt` 会返回 EINVAL。

| 文件 | 新测试 |
| --- | --- |
| `crates/savana-kerneld/src/v2_channel.rs` | `a_frame_sent_before_the_peer_closed_is_still_read`：对端写完一帧就关闭，这一帧照常读出，随后读到 EOF、写入失败，都不必等到截止时间 |
| `crates/savana-agentd/src/kernel_client.rs` | `a_deadline_is_set_after_the_peer_closed` |
| `crates/savana-ingressd/src/kernel_client.rs` | 同名测试 |
| `crates/savana-approvald/src/suite_one.rs` | 同名测试（新增测试模块） |

清单外还加了三个同类测试：

- execd `v2_service.rs` 的服务端测试；
- approvald 客户端的测试，在 `kernel_delivery_transport_tests.rs`；
- agentd `fused_model_transport_tests.rs` 里的 `the_workers_last_bytes_are_read_after_it_closed`。

清单已按第四节的步骤重新生成。这个提交改动了四个冻结文件：`v2_channel.rs`、两个 `kernel_client.rs` 和 `suite_one.rs`，它们的哈希都已更新。`tools/check-frozen-v2-core.sh` 逐项 OK，自测也通过。

**macOS CI 复现了失败**（`a259b72`，ci run 38513286194）。

`kerneld (macos-latest)` 在第一个跑到的 crate（agentd）就失败了，失败的正是两个新测试：

- `kernel_client::tests::a_deadline_is_set_after_the_peer_closed`：`set_deadline` 返回了错误；
- `fused_model_transport::tests::the_workers_last_bytes_are_read_after_it_closed`：`Os { code: 22, kind: InvalidInput, message: "Invalid argument" }`。

也就是说，对端关闭之后，macOS 的 `setsockopt` 返回 EINVAL（错误码 22，Rust 映射为 `InvalidInput`），和上面的根因一致。`cargo test` 遇到第一个失败的 crate 就停止，所以其余 crate 的新测试这次没有跑到。

### 6.2 修复（本提交）

**判断方法。** 重设超时时，如果操作系统返回 EINVAL，就认定套接字已经两向关闭。判断条件是：Rust 把错误映射成 `InvalidInput`，并且错误带系统错误码。

- Rust 对零时长报的 `InvalidInput` 不带系统错误码，而且零时长在这之前已经按 `DeadlineExceeded` 单独处理了。
- 对于大小正确的 `timeval`，XNU 和 Linux 只会因为两向关闭这一种情况返回 EINVAL；数值越界时返回的是 EDOM。

**处理方式。** 两向关闭的套接字不会阻塞：读的时候先返回缓冲区里已有的字节，然后是 EOF；写会立即失败。所以这时不需要定时器，对端发出的最后一帧照常读出来。其他错误仍然报 `Unavailable`。改完之后，macOS 和 Linux 的行为一致，没有放宽任何截止时间。

| 文件 | 改了什么 |
| --- | --- |
| `crates/savana-kerneld/src/v2_channel.rs` | 帧通道的 `set_deadline`：遇到两向关闭不再报 `Unavailable`（`shut_down_both_ways`）。内核与执行器之间、内核与各服务之间的帧都经过这里 |
| `crates/savana-agentd/src/kernel_client.rs` | agentd 到 kerneld 客户端的 `set_deadline`，改法同上 |
| `crates/savana-ingressd/src/kernel_client.rs` | ingressd 到 kerneld 客户端的 `set_deadline`，改法同上 |
| `crates/savana-approvald/src/client.rs` | approvald Suite-1 客户端的 `set_deadline`，改法同上 |
| `crates/savana-approvald/src/suite_one.rs` | approvald Suite-1 服务端的 `set_deadline`，改法同上 |
| `crates/savana-agentd/src/mapper_client.rs` | 只改测试 `blocked_measured_address_is_bounded_by_the_absolute_deadline`。原来断言截止时间 75 ms 的调用在 200 ms 内返回，而负载重的 macOS runner 上 `sleep` 可能多睡远超这个余量，这个测试以前在 macOS 上挂过。现在直接检查它保证的东西：阻塞的连接只被调用一次，拿到的超时不超过截止前剩下的时间。墙钟上限放宽到 1 s |

清单外有两处也做了同样的修改：

- execd Suite-1 服务端 `crates/savana-execd/src/v2_service.rs` 的 `set_deadline`；
- agentd `crates/savana-agentd/src/fused_model_transport.rs` 的 `DeadlineStream`。它在每次读写前都重设超时，这里用 `armed` 处理。

清单再次按第四节重新生成。这次有六个冻结文件的哈希变了，就是上表里的六个文件。`tools/check-frozen-v2-core.sh` 逐项 OK，自测也通过。

本地 Linux 上，五个 crate 都跑了 `cargo test --all-features`：53 个测试二进制，603 个测试通过，0 个失败；全工作区 `cargo clippy --all-targets --all-features -D warnings` 无告警。

本地顺带发现了一个与本次无关、早已存在的问题：kerneld 的 `v2_core_services::tests::finalize_deadline_cancellation_wins_at_real_precommit_and_preserves_closed_error` 单独运行时必然失败，在 1 s 的 `recv_timeout` 处超时；HEAD 上同样如此。整套一起跑时它会通过，CI 跑的是整套，所以不受影响。这里没有修，另作跟进。
