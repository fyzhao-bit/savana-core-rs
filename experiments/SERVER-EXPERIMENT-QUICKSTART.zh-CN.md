# 服务器防护实验：固定启动入口

这份入口用于 **Linux B/file-backed 集成配置、AgentDojo workspace 日历有限子集**。
3 个用户任务，每个 clean + 2 个攻击，共 9 个样本。不是完整 AgentDojo，
也不是可直接与自由工具调用 Agent 对比的通用防护成绩。

## 一次性部署要求

安装器使用 `--file-backed-integration --owner-control --protected-experiment`。
原生离线部署工具生成三份签名工具描述、G3 精确模型接收方规则，以及实际
模型/工具/发布端 mTLS 身份。不存在人工填写 task/run/root ID 的步骤。

`savana-experiment-operator` 是 root 控制面，只能重建并审核固定 clean 任务。
它使用独立管理密钥，不能替用户签通行密钥，不能调用工具。
`savana-experiment-auth` 只转发真人决定和浏览器 WebAuthn 原始响应。
两者均与不特权的 `savana-protected-experiment` 分开。

本配置不是 TPM/防回滚生产验收。安装器与替换工具拒绝把 B 测试机当作
生产部署；替换时旧状态、密钥和登记一起移入 root 私有归档，不能用于新实验。
已配置的 AWS 自动终止保护保持不变。

## 固定命令（AWS 测试机内执行）

```sh
sudo /usr/libexec/savana/savana-experiment-admin prepare-auth
sudo /usr/libexec/savana/savana-experiment-admin status
```

`status` 只给预检状态，不声称已认证。缺模型凭证时通过私密终端输入：

```sh
sudo /usr/libexec/savana/savana-experiment-admin configure-model
```

密钥不回显，通过 stdin 交给 systemd 加密。不要写在命令参数、SSM 命令正文、
环境清单、S3 源码包或实验日志中。已存在的密钥不会被覆盖。

`task_correlation_trust=false` 表示 Agentd 的任务验签公钥与内核 correlation
签名角色不一致。不能靠再次登记解决，也不能直接改已签名配置或关闭验签。
应先保留失败证据，再走明确授权的部署替换/迁移；`start` 会阻止这类部署。

`authority_envelope_trust=false` 表示审批服务缺少独立授权信封公钥 pin，或
其 key ID/角色隔离不正确。UI/审批信封由 `authority-envelope-v2.seed` 对应
公钥验证，执行信封仍由签名 manifest 的执行信封公钥验证，任务关联使用
第三把 correlation 公钥。不能把三种密钥合并或靠重复登记规避。
新的审批 pin 是被签名部署度量覆盖的 bootstrap 字段，不能热改已运行配置。

新部署需要一次真实通行密钥登记；只有准备操作时才生成短时登记码：

```sh
sudo /usr/libexec/savana/savana-experiment-admin enroll
```

不要将登记码当作实验 task/root，也不要在不确定登记结果时重复生成。

## 本机认证窗口

通过 AWS SSM 将远端 8766、8786 分别转发到本机 18766、18786。
无公网监听，无安全组入站开放。远端认证服务生成的 `browser.token`
只经私密管理通道取回为本机 0600 文件；它不是内核通行密钥或签名授权。

本机运行：

```sh
PYTHONPATH=experiments python -m savana_bench.auth_gateway --token-file /absolute/private/browser.token
```

打开 `http://localhost:8766/experiment-auth`。这个固定页面用于登记链接、
显示内核审批内容和调用真实通行密钥，不是产品聊天前端。
WebAuthn 发生在内核要求的 `http://localhost:8766`；网关不伪造 Origin，
不修改原生登记脚本、Cookie 或响应，不自动同意。
服务器上的 Python SDK 自己完成 ingress，本机只监听 8766，不占用旧 Mac 内核的
8767。只有另行测试原生浏览器 ingress 时，才额外转发远端 8767 到本机 18767，
并显式添加 `--with-native-ingress`；不要为服务器实验停止本机旧内核。

## 开跑与取证

准备好认证窗口后，在测试机执行：

```sh
sudo /usr/libexec/savana/savana-experiment-admin start
```

这一步只让进程进入 **armed / 等待开始** 状态。网页出现可点击的
**开始实验 / Start experiment** 后，由用户点击才开始创建内核 bootstrap 和
短时通行密钥挑战；此前不会打开模型凭证或创建实验 run。等待开始最多 15 分钟，
不延长内核挑战、后续独立审批或测试机自动终止的有效期。

点击开始不代表批准输入、任务、工具或最终发布。保持授权页可见，根据它随后
显示的请求逐项确认。已有通行密钥无需重新登记。页面仅允许一个查询同时进行，
后台标签暂停查询；断线、过期或发送结果不确定时不能再次点击同一请求。
不要刷新重放不确定的审批，先由管理员检查服务器实际结果。

每个样本先创建真实输入和独立任务根，再编译固定任务、进行私密会话交接。
模型仅提议模板，Rust 固定输入并产生实际执行配方；独立 operator 审核并签配方。
用户的执行/最终发布审批仍由原生 G6 验证；配方签名不是执行授权。

`owner_control.issue_bootstrap()` 先把 Ownerctl 的 Jarvis 选择器在固定公开
`/v2/bootstrap/continue` 路由兑换成 ingress transfer，然后交给
`owner_ingress.connect`；两种 43 字符字符串不是同一种能力，不能互换。

```text
clean 任务 + 明确输入文档
  → Python owner_ingress → 真人通行密钥 / 输入确认 / 根授权
  → Python managed_admin → Rust 编译、G3 模型视图、受限模型模板提议
  → Rust 从原始已确认文档派生输入 → 持久固定 → 生成实际 run/配方
  → 独立 operator 审核并签配方 → Rust 仍检查 G4–G7
  → execd mTLS → Python AgentDojo 只读工具 → 结果回内核
  → 独立发布审批 → execd mTLS → 私密结果接收端
  → Python 原生发布回执与字节匹配 → 官方 oracle → 证据/汇总
```

审计在 `/var/lib/savana-benchmark/runs/<run-id>/`，目录 0700、文件 0600。
只含授权的合成任务数据；不记录 API key、TLS 密钥、bootstrap 或 WebAuthn 断言。
已有证据时 `start` 不自动新建任务重跑；先检查未知/迟到结果，避免偷偷重置预算。
接入过程记录固定的 `admission_stage_started` 阶段（bootstrap、认证、输入提交、
根授权/计划、编译、私密交接、执行准备）。异常只额外记录白名单 SDK 错误码，
不记录异常正文、bootstrap、断言或审批内容；阶段开始不代表该阶段成功。

```sh
sudo systemctl status savana-protected-experiment.service
```

以 `savana-experiment` 用户、相同 PYTHONPATH 执行离线复核：

```sh
python -m savana_bench verify-protected /var/lib/savana-benchmark/runs/<run-id>
```

只有发布回执、实际字节、模型调用记录和官方 oracle 都齐全才 `scored`。
拒绝、超时、未开始和中断为 Unknown，不能当安全成功。日志哈希链不等于
可移植的内核签名证明，不能证明生产隔离/防回滚。

## 尚不能宣称的结论

- 该子集模型不读取攻击后的工具结果继续自主规划；低 ASR 不代表通用 loop 安全。
- 原工具结果直接发布，不是模型自然语言回答，任务成功必须以 oracle 实测为准。
- 测试和构建通过不等于真实通行密钥的服务器端全链验收。
- 没有完成 9 个真实样本前，不报告实测防护率或总体完成百分比。
