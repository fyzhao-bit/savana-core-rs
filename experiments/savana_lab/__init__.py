"""savana_lab: run Savana's AgentDojo experiments from Python.

    import savana_lab as sl

    run = sl.run("u9c", sl.U9)                  # 97 tasks, 13 batches, a detached driver
    print(run.status())                         # any time
    rep = sl.report("u9c")
    print(rep.utility()); print(rep.compare("u9b")); print(rep.why("travel", "user_task_13"))

Each batch still runs on a brand-new host with the kernel installed from
the committed revision, its owner and batch authorization provisioned as
before, and nothing counts until the offline verifier, replaying that same
revision, has passed it (README.zh-CN.md).
"""
from .config import PRESETS, U8S, U9, U9H, Config, ConfigError
from .lab import Lab, Run
from .plan import SUITES, Batch, Plan, benign, make_plan, pairs
from .report import Report

__all__ = ["Batch", "Config", "ConfigError", "Lab", "PRESETS", "Plan", "Report", "Run", "SUITES", "U8S", "U9",
           "U9H", "benign", "make_plan", "pairs", "report", "run"]


def run(name, config, tasks=None, *, lab=None, background=True, deadline=None, capture=False):
    """Create run `name` of `config` over `tasks` (default: every benign
    task, `benign()`) and start it; returns the Run. With `background`
    (the default) the driver is a detached process and this returns at once."""
    lab = lab or Lab()
    handle = lab.create(make_plan(name, config, benign() if tasks is None else tasks), capture=capture)
    handle.start(background=background, deadline=deadline)
    return handle


def report(*names, lab=None):
    """The results of one or more runs (savana_lab runs or the shell drivers' by name)."""
    return (lab or Lab()).report(*names)
