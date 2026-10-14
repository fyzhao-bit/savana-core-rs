"""Which tasks run, and how they are cut into batches.

A batch runs on one brand-new host that serves one AgentDojo suite, with at
most nine cases (an armed batch's bootstrap limit). A plan is the list of
batches, named `<run>-<suite>-<k>` as every earlier run was, and can be
written as the plan files the shell drivers read (`lines`).
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math

from .config import MAX_CASES, Config, ConfigError, runner_cases

# The order every 97-task run went through the suites.
SUITES = ("banking", "slack", "travel", "workspace")
# User tasks per suite in AgentDojo v1.2.2 (`agentdojo_tasks.BENCHMARK`), each
# `user_task_0` .. `user_task_{n-1}` (checked against AgentDojo in the tests).
USER_TASKS = dict(banking=16, slack=21, travel=20, workspace=40)


def benign(*suites):
    """Every user task of these suites (default: all four, 97 tasks), no injection."""
    unknown = [s for s in suites if s not in USER_TASKS]
    if unknown:
        raise ConfigError("suite", f"unknown suite {', '.join(unknown)}")
    return [(suite, f"user_task_{n}") for suite in (suites or SUITES) for n in range(USER_TASKS[suite])]


def pairs(suite, users, injections):
    """Attack pairs: each user task with each injection task (numbers or full names)."""
    def name(prefix, value):
        return value if isinstance(value, str) else f"{prefix}_{value}"
    return [(suite, f"{name('user_task', u)}+{name('injection_task', i)}") for u in users for i in injections]


@dataclass(frozen=True)
class Batch:
    name: str
    suite: str
    items: tuple
    spec: str

    def config(self):
        return Config.from_spec(self.spec)[0]


@dataclass(frozen=True)
class Plan:
    name: str
    batches: tuple

    def lines(self):
        """The plan as a shell driver's plan file: `<name> <suite> <items> <template>` per line."""
        out = []
        for batch in self.batches:
            config = batch.config()
            out.append(f"{batch.name} {batch.suite} {','.join(batch.items)} {config.template()}\n")
        return "".join(out)

    def to_json(self):
        return dict(name=self.name, batches=[dict(name=b.name, suite=b.suite, items=list(b.items), spec=b.spec)
                                             for b in self.batches])

    @classmethod
    def from_json(cls, value):
        return cls(value["name"], tuple(Batch(b["name"], b["suite"], tuple(b["items"]), b["spec"])
                                        for b in value["batches"]))

    @classmethod
    def from_lines(cls, name, text):
        """A shell driver's plan file (the format `lines` writes)."""
        batches = []
        for line in text.splitlines():
            if not line.strip():
                continue
            batch, suite, items, template = line.split()
            spec = template.replace("{suite}", suite).replace("{items}", items)
            Config.from_spec(spec)
            runner_cases(spec)
            batches.append(Batch(batch, suite, tuple(items.split(",")), spec))
        return cls(name, tuple(batches))

    def __len__(self):
        return len(self.batches)

    def tasks(self):
        return [(b.suite, item) for b in self.batches for item in b.items]

    def __str__(self):
        return json.dumps(self.to_json(), indent=1)


def make_plan(name, config, tasks, *, max_cases=MAX_CASES):
    """Cut `tasks` ((suite, item) pairs, e.g. `benign()`) into batches of at
    most `max_cases` cases, one suite per batch, suites in SUITES order and
    tasks in the order given. A suite's tasks are split as evenly as its
    batch count allows (16 -> 8+8, 20 -> 7+7+6). `config` is a Config, or a
    function of the suite returning one."""
    if not name or not all(c.isalnum() or c in "-_." for c in name):
        raise ConfigError("name", "a run name is letters, digits and -_.")
    by_suite = {}
    for suite, item in tasks:
        by_suite.setdefault(suite, []).append(item)
    unknown = [s for s in by_suite if s not in SUITES]
    if unknown:
        raise ConfigError("suite", f"unknown suite {', '.join(unknown)}")
    batches = []
    for suite in (s for s in SUITES if s in by_suite):
        arm = config(suite) if callable(config) else config
        items = by_suite[suite]
        count = math.ceil(len(items) / max_cases)
        while True:
            chunks = _even(items, count)
            specs = [arm.spec(suite, chunk) for chunk in chunks]
            # A case count above the item count (a read and an act turn per
            # adopted item) can overflow a batch: cut finer.
            if all(len(runner_cases(spec)) <= max_cases for spec in specs):
                break
            count += 1
        batches += [Batch(f"{name}-{suite}-{k}", suite, tuple(chunk), spec)
                    for k, (chunk, spec) in enumerate(zip(chunks, specs))]
    return Plan(name, tuple(batches))


def _even(items, count):
    size, extra = divmod(len(items), count)
    chunks, start = [], 0
    for k in range(count):
        end = start + size + (k < extra)
        chunks.append(items[start:end])
        start = end
    return chunks
