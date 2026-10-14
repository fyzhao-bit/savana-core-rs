# savana_lab：用 Python 跑 Savana 实验

以前跑一轮实验，要靠会话草稿区里的一组 bash 脚本：`run-u9.sh` → `f5-chunk.sh` → `run-batch-f5.sh` →
`planner-attempt.sh` / `fresh-host.sh` → `planner-export.sh`。`savana_lab` 把这一层改写成仓库里的 Python 包。
在主机上执行的命令和顺序都没变，只是现在由 Python 发出，并且有测试覆盖。

整套安全流程一步不少：

- 每批一台全新主机；
- 从已提交的版本安装内核；
- 软件 owner 身份、批次授权（每批最多 9 题，15 分钟内开跑）照旧；
- 离线验证器用同一版本的代码重放，不通过的批次不计入结果。

## 一次性准备

```bash
export PYTHONPATH=experiments          # 在仓库根目录
python3 -m savana_lab setup             # 验证用的 venv（AgentDojo 0.1.35、maturin），在 ~/.savana-lab/venv
python3 -m savana_lab artifacts build   # 内核二进制、SDK wheel、结构化规划示例，约 20 分钟
```

构建产物按代码版本存放在 `~/.savana-lab/artifacts/<rev>/`，并附一份收据 `artifacts.json`，记录版本、
每个文件的 sha256 和构建步骤。只要 Rust 源码（`crates/`、`Cargo.toml`、`Cargo.lock`）没变，同一份产物可以给后面
任何提交使用；源码一变，建运行时会直接拒绝，提示先重新构建。

已经在别处构建好的产物，可以登记进来，不必重新构建：

```bash
python3 -m savana_lab artifacts adopt --rev <rev> --bin-tar linux-b-bin.tar --wheel savana_core-*.whl \
    --example structured_plan_eval --note "由什么构建"
```

主机镜像 `savana-b-host:24.04` 在第一次跑的时候自动构建（配方在 `hostimg/Dockerfile`），会带上本机
`/usr/local/share/ca-certificates/` 里的出口代理证书。

## 写一个实验

```python
import savana_lab as sl

cfg = sl.U9                                  # 或 sl.Config(drafts=3, actions="ask", ...)，字段名就是 spec 的选项名
print(cfg.template())                        # drafted+drafts=3+actions=ask+...:{suite}:{items}

run = sl.run("u9c", cfg)                     # 97 道题，切成 13 批，后台驱动，立即返回
print(run.status())                          # 随时看：几批已验证、正在跑哪批第几题、余额、目前的效用
run.stop()                                   # 跑完当前这批就停

rep = sl.report("u9c")
print(rep.utility())                         # 按场景的效用，只算验证通过的批次
print(rep.compare("u9b"))                    # 逐题对比：多做对、少做对了哪些
print(rep.why("travel", "user_task_13"))     # 每份草稿是否被退回及原因、排序、owner 审批、工具调用、最终回答
for call in rep.episode("travel", "user_task_13").model_calls():
    print(call)                              # 起草模型原话（核对摘要）、排序模型看到的图和回复、抽取模型的输入和输出
```

组合不合法时会直接说明违反哪条规则，例如 `actions: actions='ask' asks for a later draft: drafts >= 2 ...`，
不再只报一个笼统的 `planner_experiment_spec`。规则写在 `config.py`，选项和默认值直接从 runner 导入。
测试会把一千多种组合同时交给这里的检查和 runner 自己的解析器，结论必须一致；生成 spec 后还会再交给 runner
解析一遍，以 runner 的结论为准。

任务和分批：

- 只跑部分场景：`sl.benign("banking", "travel")`；
- 攻击题对：`sl.pairs("banking", users=[0, 2], injections=range(9))`；
- 按场景用不同配置：`sl.make_plan(name, lambda suite: ..., tasks)`。

分批规则和以前一样：每批一个场景，最多 9 题，同一场景的题尽量平均分（16 题分成 8+8，20 题分成 7+7+6）。
`sl.make_plan("u9b", sl.U9, sl.benign()).lines()` 生成的内容和原来的 `u9b-plan.txt` 逐字节相同。

## 命令行

```bash
python3 -m savana_lab plan u9c --preset u9            # 看会切成哪些批
python3 -m savana_lab run u9c --preset u9 --background
python3 -m savana_lab status u9c
python3 -m savana_lab progress u9c --follow           # 驱动的每一步
python3 -m savana_lab stop
python3 -m savana_lab resume u9c --background         # 续跑：验证过的批次跳过
python3 -m savana_lab report u9c --compare u9b
python3 -m savana_lab why u9c travel user_task_13
python3 -m savana_lab episode u9c travel user_task_13 --model-calls
```

以前用 bash 跑出来的结果（u9b、u8s 等）也能用 `report`、`why`、`episode` 读，按 `<名字>-<场景>-<序号>` 找批次。

底线实验（`planner-attempt-floor.sh` 那一套）的部署变体也能在建运行时指定：

```bash
# 反事实内核：补丁只在构建期间打上，构建完立刻撤销；产物存为 <rev>-nofloor，收据里记着补丁的摘要
python3 -m savana_lab artifacts build --patch nofloor.patch --variant nofloor
python3 -m savana_lab run floor-x --template 'drafted+author=fixed+attack=autodojo+review=derived+owner=strict:{suite}:{items}' \
    --tasks floor-tasks.txt --disposition permit --unconfined-write send_money \
    --catalog-variant catalog-no-validator.json --artifacts-variant nofloor
```

`--disposition` 和 `--unconfined-write` 经安装程序的环境变量交给部署生成器，装完会核对主机上实际生效的处置方式，
不一致就停。`--catalog-variant` 指定的目录文件会复制一份存进运行记录，每批开跑前核对它的摘要。

## 和 bash 版不同的地方

- **验证失败就停。** 以前 `planner-export.sh` 验证失败时只打印 `VERIFY_FAILED`，驱动接着跑下一批。现在整轮在这一批停下，
  错误写进进度记录。已经导出但没通过验证的批次，续跑时既不跳过，也不会自动重跑（重跑要再花一次模型调用）。
  这时有两条路：修好验证器后用 `savana_lab verify <批次>` 重新验证（失败那次的记录会改名保留），或者用
  `savana_lab rerun <批次>` 把它挪到 `_interrupted/` 再续跑。
- **安装失败就停。** 以前安装脚本失败后流程还会往下走，到后面某一步才报错。现在每一步失败都在当步停下，报的是那一步自己的错误；
  管道里任一命令失败也算失败。
- **跑到一半失败时保留证据。** runner 已经启动但没跑完时，主机上已有的运行目录和日志会先导出，再停下。
  这批算未完成，下次续跑前挪到 `_interrupted/`，不会因为下一台新主机替换掉旧主机而丢失。
- **验证器用的就是上机的代码。** 实验代码取自暂存版本的 `git archive`（和以前一样）。`savana` 和 `savana_core`
  改为取自上机的那个 wheel；以前取的是工作区里的。用新路径重验 U9b 的一批，结果和原来的验证结果逐字相同。
- **单实例。** 用锁保证同一时间只有一个驱动在跑（主机名只有一个）。停止用 `stop`。驱动收到 SIGTERM 时，
  先记一条"已停止"再退出。
- **密钥。** 只从本机的环境变量 `DEEPSEEK_API_KEY` 读取，后台驱动也是继承这个环境变量。送进主机只经
  `configure-model` 的标准输入，不出现在任何命令的参数或传给主机的环境变量里，也不写进文件；日志写入前也会把它替换掉。
  测试检查了每一条命令的参数和环境变量。

## 记录放在哪里

- `<results>/_lab/<运行名>/`
  - `run.json`：计划、暂存版本、所用产物的版本和摘要，建运行时就定下来；
  - `progress.jsonl`：驱动做的每一步；
  - `driver.log`；
  - `logs/<批次>.<第几次>.log`：每台主机上执行的每条命令及其输出。
- `<results>/<批次>/`：和以前完全一样，导出的运行目录、`offline-verification.json` 等。
- `~/.savana-lab/`：构建产物、暂存目录、验证用的代码树、venv、锁和停止文件。

## 实测（2026-10-14）

**分批和验证与 bash 版逐字一致。**
- `make_plan` 生成的 u9、u9b、u9h、u8sc 计划和原来的计划文件逐字节相同。
- 用新的验证路径重验两批 U9b（`u9b-banking-0`、`u9b-travel-1`），输出和原来的 `offline-verification.json` 逐字相同。
  新路径用的是暂存版本的代码和上机的 wheel；第二次用的是 `setup` 新建的 venv。
- `report` 读 U9b 得 55/97，对 U8S +8 −4、对 U9 +9 −1，和之前手工分析的题目清单一致。

**真跑一轮。** 运行 `u9lab`：U9 配置，banking 16 题，两批，后台驱动。

时间线：
- 第 1 批：起主机、安装、配置 35 秒，跑 8 题 3 分 34 秒，导出加验证 3 秒。
- 第 1 批跑的时候发了 `stop`，它跑完这一批就停了。
- `resume` 后跳过已验证的第 1 批，接着跑第 2 批。

结果：
- 两批都通过离线验证，越权调用 0。
- 每台主机上的命令和 bash 版逐行对应，导出的文件集合相同。
- `provisioning.json` 的配置字段（codecs、disposition、scope、描述符名单）和 bash 跑的批次相同；
  各个摘要字段每台新主机都不一样，两个 bash 批次之间也是如此。
- 效用 10/16。bash 跑的 U9b 同样 16 题是 11/16，差的一题是 banking 15：两次都发布了回答，
  但这次抽取模型把房租改到了 6 号定期转账，应该是 7 号（`episode` 对比两次的工具调用参数，一眼就能看出来）。

## 还没做

- 模型可替换：现在 runner 内部写死了 DeepSeek 客户端。
- 不起主机的"快速试"模式。
- 本机 Docker 以外的主机，比如 AWS 或 SSH。

这几项都要改 runner 本身，会改变实验记录的格式，所以单独做。
