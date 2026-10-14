"""savana_lab: run Savana's AgentDojo experiments from Python.

    import savana_lab as sl

    run = sl.run("u9c", sl.U9)                  # 97 tasks, 13 batches, a detached driver
    print(run.status())                         # any time
    rep = sl.report("u9c")
    print(rep.utility()); print(rep.compare("u9b")); print(rep.why("travel", "user_task_13"))

    print(sl.quick(sl.U9, "travel", "user_task_13"))  # one task in this process, in seconds:
                                                      # no host, no kernel, NOT experiment evidence

Each batch still runs on a brand-new host with the kernel installed from
the committed revision, its owner and batch authorization provisioned as
before, and nothing counts until the offline verifier, replaying that same
revision, has passed it (README.zh-CN.md).
"""
from .config import PRESETS, U8S, U9, U9H, Config, ConfigError
from .lab import Lab, Run
from .plan import SUITES, Batch, Plan, benign, make_plan, pairs
from .quick import QuickResult, quick
from .remote import AwsHosts, DockerHosts, SshHosts
from .quick_check import check as quick_check
from .report import Report

__all__ = ["AwsHosts", "Batch", "Config", "ConfigError", "DockerHosts", "Lab", "PRESETS", "Plan", "QuickResult",
           "Report", "Run", "SUITES", "SshHosts", "U8S", "U9", "U9H", "benign", "make_plan", "pairs", "quick",
           "quick_check", "report", "run"]


def run(name, config, tasks=None, *, lab=None, background=True, deadline=None, capture=False, host=None):
    """Create run `name` of `config` over `tasks` (default: every benign
    task, `benign()`) and start it; returns the Run. With `background`
    (the default) the driver is a detached process and this returns at once.
    `host`: where each batch's brand-new host comes from (DockerHosts() here
    by default, SshHosts(...), AwsHosts(...))."""
    lab = lab or Lab()
    handle = lab.create(make_plan(name, config, benign() if tasks is None else tasks), capture=capture, host=host)
    handle.start(background=background, deadline=deadline)
    return handle


def report(*names, lab=None):
    """The results of one or more runs (savana_lab runs or the shell drivers' by name)."""
    return (lab or Lab()).report(*names)
