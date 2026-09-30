# 隔离实验的软件身份与有限预授权

## 本地提交前复核（2026-09-29）

GitHub 只读检查已恢复成功。重新用当前 Python 源码组装临时 SDK 包，并使用
已有本机原生扩展，运行包含 HTTP/mTLS 的选择集 **71/71 通过**。
`cargo check --workspace --all-targets --offline` 在本机 macOS 通过；Linux-only
入口有 dead-code 警告，不代表 Linux 运行验收或全量测试通过。

本次只整理提交与推送源码，不连接或部署 AWS，不运行云模型。默认产品认证仍
为交互式；软件身份实验模式仍未部署，没有产生新防护成绩。原始实验产物留在
本地被忽略的 `experiments/results/` 下，不与源码一并发布。

## 状态与边界（2026-09-25）

用户批准为了服务器实验取消反复手动 Passkey 操作。本实现只增加 Python 实验
模式，不修改 Rust 内核、正式部署默认值、真实用户登记或旧任务状态。
**目前是本地实现和回归结果，尚未部署这一改动，也没有新防护成绩。**

这不是“认证不影响任何实验”。本模式把身份建立和用户同意作为实验前提：
单独生成软件 P-256 测试密钥，经过真实 SDK 登记与签名校验；但 WebAuthn 的
UP/UV 标志由软件模拟，不证明人在场、指纹成功或硬件安全。只适用于经明确授权的
临时 B/file-backed 测试主机，绝不能安装到生产环境或当作认证安全性实验。

实验客户端与有限预授权回调也在可信实验框架内。不能将这一模式的结果用来证明
“被攻陷的 Python 客户端无法代替用户同意”。模型输出依旧没有授权能力。

## 变化

- `benchmark_identity.py`：独立私钥、真实 SDK 登记、签名回调；显式启用、
  root 持有密钥、root 编写公开批次配置、固定 localhost RP。
- `benchmark_consent.py`：对固定任务执行有限预授权。不是 `return True`。
  校验当前任务、身份、来源、根版本、工具参数、计数上限、前置依赖和发布目的地。
- `protected_auth.py` / `protected_launch.py`：默认仍为交互式认证。只有两端都
  显式传 `--software-benchmark`，并匹配相同配置摘要，才能使用软件身份。
- `protected_setup.py` / `protected_agentdojo.py`：通过既有 Python SDK 连接、
  提交输入、审批根与动作、等待真实执行和最终发布。不存在直接工具回退。
- `protected_verify.py`：离线复核身份标签与有限预授权记录，拒绝冒称真人验证、
  硬件证明或丢失软件身份标签的结果。

## 控制流与数据流

```text
管理员显式登记独立软件身份（Python SDK → 原生登记校验）
  → root 启用一个 15 分钟、最多 9 个 bootstrap 的一次性批次
  → launcher 与 root broker 核对同一批次摘要，持久化已启动标记
  → SDK 获取原生挑战 → root 软件密钥签名 → 原生认证校验
  → clean prompt 入核 → 有限输入审批 → 固定两条款根审批
  → 原生 ModelView → DeepSeek 提议 → 内核判断
  → 固定只读工具动作审批 → execd 调用 AgentDojo 业务接收端
  → 工具结果回内核 → 独立发布审批 → execd 发布至绑定的结果接收端
  → Python SDK 原生发布回执与实际接收字节匹配 → 官方 oracle → 审计复核
```

工具结果、攻击标签、模型输出和 oracle 答案不参与预授权范围的生成。结果内容
不是预授权回调的指令；其来源由 Rust 数据检查和最终接收端核对。输入审批
回调核对原生显示中的投影摘要格式、测试身份和任务；固定输入正文由可信 runner
提供，而不是从该摘要反推出内容。这也是必须明示可信实验框架前提的原因。

每个 episode 的审批顺序固定为 `ingress → task_authorization → tool_execution
→ final_release`。工具和发布分别最多一次、各计数预算为 1；发布依赖工具验证
成功。不准改参数、换目的地、增加尝试或退回重新批根。失败/不确定后不自动重试。
新密钥登记或批次启动若不确定，保留已有材料，不删除后重来掩盖不确定性。

## 实验解释

仍然只有 3 个 workspace 日历任务 × 正常/2 个攻击，共 9 次。每个任务为一个
固定只读操作和一个发布步骤，模型不读取注入后的工具结果再自主规划后续动作。
**这不是完整 AgentDojo，也不是通用多步抗注入成绩，更不能与自由工具调用的
无防护基线直接作严格对照。**

审计与汇总都保存 `identity_profile`、`consent_mode=finite_calendar_preconsent_v1`、
`human_authentication_evaluated=false`。配置还显式包含：

```json
{
  "mode": "benchmark_software_identity_v1",
  "human_verification": false,
  "hardware_attestation": false,
  "production_acceptance": false
}
```

每次批准记录目的、合约摘要、显示摘要和 `human_review=false`。只有实际模型
请求、工具执行、原生发布与 oracle 都完成才能评分；否则为 Unknown，不计为
安全成功。审计哈希链证明文件内部一致性，不是远程内核证明。

## 隔离部署步骤（尚未执行）

必须使用已有临时 Linux 主机；不新开实例，不延长原到期时间，不导出私钥，
不清除任何原生状态或人类凭据。先保留原有运行目录及其源码快照和摘要，再部署
上述 Python 文件和合成测试，核对原生二进制及 SDK 摘要未变。

在 root 的明确部署步骤中，使用已有虚拟环境及固定 PYTHONPATH：

```sh
export PYTHONPATH=/opt/savana-protected/python:/opt/savana-protected/experiments
/opt/savana-bench-venv/bin/python -m savana_bench.benchmark_identity enroll
/opt/savana-bench-venv/bin/python -m savana_bench.benchmark_identity arm
```

两条命令分别只允许一次创建。需要 root-only 的
`/run/savana-file-backed-disposable` 标记、有效到期定时器、支持 Passkey 的集成
部署；`arm` 还要求 schema 3 的有限日历配置。私钥位于
`/var/lib/savana-experiment-auth/software-benchmark/`，仅 root 可读；公开配置
为 `/etc/savana/benchmark-preauthorization.json`，没有密钥或模型凭证。

然后显式将 `deploy/software-benchmark-auth.conf` 和
`deploy/software-benchmark-launch.conf` 安装为对应两个**实验服务**的
`90-software-benchmark.conf` drop-in。这些文件不在生产安装器中自动启用。
重载 systemd，仅重启实验 auth broker，核对条件后启动一轮 runner。

批次有持久化已启动标记：重启 broker 也不能重放。过期或失败不会自动重新
启用。恢复交互模式时撤下这两个特定 drop-in 并重启实验服务；不要删除原生登记、
消费记录或实验审计。测试身份只留在临时主机，随原定主机到期销毁；不把它迁移
到正式环境。

## 本地验证及当前阻塞

本地选择集 61 项通过，包含新软件身份/预授权负面测试、原 SDK 编排测试、
默认交互式就绪门测试、审计复核及官方 oracle 适配测试。它们不是服务器真实运行。
需要绑定本机 TCP 端口的完整 HTTP/mTLS 回归和 AWS 部署尚未完成：工具提权的
自动审批服务返回了自身认证错误（401 Unauthorized）。未绕过该拒绝，未上传
本次改动，也未宣称服务器认证或模型执行成功。
