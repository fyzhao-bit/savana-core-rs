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
| `crates/savana-kernel-protocol/src/v2/business_controls.rs` | 待提交 | 新增 `ResultCandidatesV2`（1–64 个成员、总计 ≤4 KiB、按字节严格升序、精确比较）；派生规则可带集合（只用于不计算的文本或文本列表），规范字节在 6 元素形式里写入集合，因此所有提交该规则的摘要都提交集合；不带集合的规则字节不变；解码上限相应放宽 | U7：owner 签名时给数据派生的目的地附一个候选集合，内核派生时逐字节检查成员资格 | `tests/result_candidates.rs` 5 个 |
| `crates/savana-kernel-protocol/src/v2/business_request.rs` | 待提交 | 导出新类型和常量 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-kernel-protocol/src/v2/mod.rs` | 待提交 | 导出新类型和常量 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-kernel-protocol/src/v2/task_context.rs` | 待提交 | owner 草稿 JSON 的派生规则可带 `candidates`（排序后校验，重复则拒绝） | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-kernel-protocol/src/v2/task_draft.rs` | 待提交 | 根审批显示列出集合，并说明集合内的值视为 owner 的选择、其余值仍需批准；有集合时显示版本为 3，其余根的显示不变 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-kernel-protocol/src/v2/task_action_display.rs` | 待提交 | 单步审批显示列出集合和 `in_candidates`（具体值是否成员，列表逐项）；有集合时版本为 3 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-continuation-core/src/planning.rs` | 待提交 | `SlotBinding.result_candidates`（只能在不计算的路径边上，非空、严格升序、有界）；配方摘要按整个操作序列化，自动包含它 | U7：签名时附候选集合，内核逐字节检查成员 | continuation-core 全部 |
| `crates/savana-policy-core/src/v2/fused_task_compiler.rs` | 待提交 | 按绑定重建派生规则时带上集合，G4 在准备和派发时用摘要比对，绑定无法放宽或去掉集合 | U7：签名时附候选集合，内核逐字节检查成员 | `a_trusted_set_edge_is_matched_with_its_set_and_a_binding_cannot_widen_it` |
| `crates/savana-policy-core/src/v2/provenance.rs` | 待提交 | 新派生操作（标签 11）只记录集合摘要；只有 `result_candidate_member_v04` 能产生它：先按原路径取值，成员（列表逐项）才把不可信父值的完整性提为 `UserAuthorized`，保密性、读者、效果不变，根证据记入集合摘要；普通派生拒绝标签 11，代理接口没有入口 | U7：签名时附候选集合，内核逐字节检查成员 | `a_signed_candidate_member_is_endorsed_and_nothing_else_is` |
| `crates/savana-policy-core/src/v2/fused_inputs.rs` | 待提交 | 派生结果值时，带集合且取到成员就走背书，否则与普通边完全相同（仍为不可信，G5 照旧要求批准）；G7 用同一函数重算，因此集合也受 G7 约束 | U7：签名时附候选集合，内核逐字节检查成员 | `a_trusted_set_edge_endorses_only_a_member_and_g7_binds_the_set` |
| `crates/savana-policy-core/src/v2/fused_plan_adapter.rs` | 待提交 | 只改测试里的结构体字面值（新字段 `None`） | U7：签名时附候选集合，内核逐字节检查成员 | policy-core 458 个 |
| `crates/savana-policy-core/src/v2/fused_recipe_approval.rs` | 待提交 | 只改测试里的结构体字面值（新字段 `None`） | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
| `crates/savana-policy-core/src/v2/provenance_tests.rs` | 待提交 | 加 U7 测试 | U7：签名时附候选集合，内核逐字节检查成员 | 同上 |
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
