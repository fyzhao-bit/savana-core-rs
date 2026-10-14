# 首轮服务器防护实验：实际失败记录（2026-09-25）

本记录更新 `experiment-deployment-20260925.md` 的历史就绪检查点，**不是防护成绩**。

后续：用户已明确批准归档重装，且修正版真实入口探针已通过；见
[重装记录](experiment-reinstall-20260925.md)。下列首轮失败证据原样保留。

## 真实结果

AWS 实例 `i-071646e066afc6302` 上的服务于 04:35:53 UTC 启动，随后退出码为 2。
运行 ID：`732dbc9ef2f145518b6e7ff5543e30d8`。

- 计划 9 个有限日历子集样本：3 个 clean、6 个 attack。
- 只尝试第一项 `user_task_0`，在 `owner_and_operator_admission` 阶段报
  `AuthBrokerError`，耗时约 2.61 秒。
- 其余 8 项未尝试；全部 9 项为 Unknown。
- 模型调用 **0**，可计分样本 **0**，无可报告的任务成功率或防护率。
- 无发布回执，不能把提前退出解释成拦截攻击成功。

04:35:55 UTC 的 systemd 日志显示，真正的 `savana-ownerctl prepare-ingress`
已被调用但失败；此前 `health` 成功。独立受限诊断得到静态错误：
`ownerctl operation refused by kernel control`。未替用户认证或批准任何任务。

## 已确认的部署缺陷

`assemble.py` 把 Agentd 的 `kernel_task_authority_key_id` 及
`kerneld-task-authority-v2.pub` 配成了 `authority-envelope-v2.seed` 对应的公钥。
但实际 `SignedDurableTaskCorrelationV2` 由 **task-correlation-v2.seed** 签名，
Agentd 的 `verify_preparation_response` 使用前述 task-authority 配置验证该签名。

在服务器只读比对得到：Agentd 公钥与 Approvald 正确的 correlation 公钥不同；
对应 key ID 也不同。这是足以阻断真实任务准备响应验证的确定配置错误。
公开健康检查不执行任务相关签名验证，所以不能发现它。原错误响应没有细分
内部失败点；因此不宣称它是整个后续链路唯一的缺陷。

修复将 Agentd 的公钥和 ID 都指向 correlation 键，仍保留 authority-envelope
独立角色密钥。新增测试实际验证 correlation 签名通过、envelope 签名被拒绝。

## 另外修复的 Python 入口缺口

Ownerctl 输出的网址后缀是 `JarvisBootstrapSelectorV2`，不是 SDK
`owner_ingress.connect` 接受的 `KernelIngressBootstrapTransferCapabilityV2`。
旧 Python 包装层直接返回后缀，跳过了兑换。

修复后的 `savana.owner_control.issue_bootstrap()` 在 Python SDK 内部调用固定
loopback `/v2/bootstrap/continue`，发送有界的 canonical CBOR 选择器和随机 nonce，
仅解析固定目标 ingress 表单的真实 transfer。它不会跟随重定向、执行页面脚本、
连接内核私有 IPC、自动重试、认证或批准任务。

```text
Python owner_control
  → 测量过的 ownerctl → Agentd → 内核任务准备 / correlation 签名
  → Agentd 验签 → Jarvis 选择器
  → 固定公开 HTTP continue → 内核 ingress transfer
  → Python owner_ingress.connect → 真人 WebAuthn（仍需实测）
```

新增的 `status.checks.task_correlation_trust` 会在启动前核对两侧公开密钥与 ID。
本次旧部署检查结果为 **false**，`ready_to_request_real_authentication=false`，
即使其他服务检查都为 true，也不允许继续启动。

## 验证、部署状态与安全边界

- 本地相关回归：**96 passed、20 subtests passed**，有 6 项依赖弃用警告。
- AWS 现有 unittest：**6 passed**。最初尝试 pytest 因远端未安装而未运行，
  没有把它算作通过，也没有临时安装新的依赖。
- 六份 Python 源码/测试已上传并安装到 `/opt/savana-protected`。
- 已运行的 auth 服务仍可能保留旧的导入模块；未以此声称实际新入口已验收。
- **运行中的签名配置未修改，内核二进制未替换，登记和内核状态未清除。**
  安装器修复只作用于后续重新生成的正确签名部署。
- 旧状态绑定原 manifest / task-authority key，不能直接覆盖公钥或配置。
  已请求明确批准：先归档当前状态、登记及失败审计，再重装临时测试部署。
  未获批准前不执行这项操作，不自动重跑已有 Unknown 样本。
- 没有新建机器或延长预算保护；原自动终止仍为 **05:23:52 UTC**。

代码补丁 S3 对象：`artifacts/bootstrap-trust-fix-20260925.tgz`，SHA-256：
`eb43ec481e9ea02e7dc85891589a12f3f5211564db37d06f6bb77b2f8f3fcfd4`。
不包含凭证、个人数据、登记或旧内核状态。模型密钥此前已按单独授权安装到
systemd 加密 credential，本次未重新上传、输出或轮换。

## 独立保留的证据

原始三个审计文件已下载到：
`experiments/results/aws-protected-20260925-first-attempt/732dbc9ef2f145518b6e7ff5543e30d8/`。
没有修改原始 summary/events/completion。

- 压缩传输包大小 28,773 字节；SHA-256
  `a869caf65e0751a3b7a575faffbe815f69487c23751b398a3b6e54ee28dd0147`。
- 审计 head：`047c7652730a61fc4290cd6e807b1a9f0208b4987191a3c2eda3b2aa6ebb3e30`。
- 使用初次部署包 + auth-startup patch + gateway patch 恢复当时实验源码，
  原 verifier 检查 package/source hashes、hash chain、completion 和 summary 后，
  返回 `audit_consistent=true`、`official_episodes_rescored=0`。
- 哈希链只证明该组证据内部一致，不是可移植内核证明或生产隔离验收。

主要 SSM 操作：

- 启动：`b85b3043-faac-4786-9f1f-3c3eee8b657f`。
- 原始进程结果：`50f58d21-f54c-4fa4-b8f3-2f967fa28ea5`。
- 公开密钥比对：`ad327a7e-434d-482a-8a0f-133102fcb510`。
- 代码补丁：`6c6969a9-380e-43ed-a14d-aa9daaee1ada`。
- 远端 unittest 及预检：`84e2d788-ef3b-4f96-bda2-ae94fc035bac`。
