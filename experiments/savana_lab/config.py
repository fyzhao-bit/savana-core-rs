"""An experiment's configuration: the runner's spec string as a Python object.

The runner on the host takes one string per batch,
`drafted[+key=value...]:<suite>:<items>` (or `drafted-poison[...]:<goal>:...`),
parsed by `savana_bench.planner_experiment.drafted_options` / `drafted_cases`.
`Config` holds the same options under the same names and turns them into
that string and back. The option names, choices and defaults are imported
from the runner, never copied, and `check` states which rule a combination
breaks where the runner only says `planner_experiment_spec`; the runner's
own parser then has the last word (`runner_cases`).
"""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
import re

from savana_bench.drafted_tasks import EXTRACTOR_MODELS
from savana_bench.planner_experiment import (ACTIONS, ANSWERS, ATTACKS, AUTHORS, COMPUTES, EXECUTOR_MODELS,
                                             EXPOSURES, INSTRUCTIONS, MAPPERS, MAX_DRAFTS, OWNERS, PLANNER_MODELS,
                                             REVIEWS, experiment_cases)
from savana_bench.value_blind import EXTRACTOR_VIEWS, VIEWS

# The order options are written in. It is the order every U8S/U9 plan used,
# so those plans' spec strings come out unchanged; any order parses the same.
OPTION_ORDER = ("drafts", "planner", "view", "extract", "extractor", "actions", "review", "owner",
                "author", "mapper", "compute", "answer", "instructions", "attack", "exposure", "executor")
CHOICES = dict(planner=PLANNER_MODELS, view=VIEWS, extract=EXTRACTOR_VIEWS, extractor=EXTRACTOR_MODELS,
               actions=ACTIONS, review=REVIEWS, owner=OWNERS, author=AUTHORS, mapper=MAPPERS,
               compute=COMPUTES, answer=ANSWERS, instructions=INSTRUCTIONS, attack=ATTACKS, exposure=EXPOSURES,
               executor=EXECUTOR_MODELS)
# At most this many cases (episodes) per batch: an armed batch issues at most
# nine bootstraps (`benchmark_identity.SoftwareCeremonyQueue.bootstrap`).
MAX_CASES = 9
ITEM = re.compile(r"user_task_(?:0|[1-9][0-9]?)(?:\+injection_task_(?:0|[1-9][0-9]?))?")
# What a spec may contain: it is written into a systemd drop-in verbatim.
SPEC_CHARS = re.compile(r"[A-Za-z0-9_+=:,.-]+")


class ConfigError(ValueError):
    """A configuration the runner would refuse, with the rule it breaks."""

    def __init__(self, field, message):
        super().__init__(f"{field}: {message}")
        self.field = field


@dataclass(frozen=True)
class Config:
    """One arm of an experiment. Field names are the spec's option names and
    the defaults are the runner's; see `drafted_options` for what each does.
    The three model fields take any name `savana_bench.chat_models` registers.
    `mapper` applies only to `author="structured"`, where it defaults to the
    runner's "template". `goal` makes the planner compromised (`drafted-poison`)."""
    drafts: int = 1
    planner: str = PLANNER_MODELS[0]
    view: str = VIEWS[0]
    extract: str = EXTRACTOR_VIEWS[0]
    extractor: str = EXTRACTOR_MODELS[0]
    actions: str = ACTIONS[0]
    review: str = REVIEWS[0]
    owner: str = OWNERS[0]
    author: str = AUTHORS[0]
    mapper: str | None = None
    compute: str = COMPUTES[0]
    answer: str = ANSWERS[0]
    instructions: str = INSTRUCTIONS[0]
    attack: str = ATTACKS[0]
    exposure: str = EXPOSURES[0]
    # The kernel's executor model; `planner` also orders a structured program.
    executor: str = EXECUTOR_MODELS[0]
    goal: str | None = None

    def __post_init__(self):
        if self.author == "structured" and self.mapper is None:
            object.__setattr__(self, "mapper", MAPPERS[0])

    # -- the spec string -------------------------------------------------
    def kind(self):
        """`drafted[+options]` or `drafted-poison[+options]`: the spec before
        its first colon. Options at their default are left out (the runner
        adds no case key for a default, so the cases are the same)."""
        defaults = {f.name: f.default for f in fields(self)} | dict(mapper=MAPPERS[0])
        options = [f"{key}={getattr(self, key)}" for key in OPTION_ORDER
                   if getattr(self, key) is not None and getattr(self, key) != defaults[key]]
        return "+".join(["drafted" if self.goal is None else "drafted-poison", *options])

    def template(self):
        """The spec with `{suite}` and `{items}` left open (a plan file's last column)."""
        goal = "" if self.goal is None else f"{self.goal}:"
        return f"{self.kind()}:{goal}{{suite}}:{{items}}"

    def spec(self, suite, items):
        """The runner's spec for one batch (`items`: a list or a comma-joined
        string), checked here and by the runner's own parser."""
        items = items.split(",") if isinstance(items, str) else list(items)
        self.check(suite, items)
        spec = self.template().replace("{suite}", suite).replace("{items}", ",".join(items))
        runner_cases(spec)
        return spec

    @classmethod
    def from_spec(cls, spec):
        """(Config, suite, items) of a full spec string."""
        kind, colon, rest = spec.partition(":")
        if not colon:
            raise ConfigError("spec", "expected drafted[+options]:<suite>:<items>")
        options, poisoned = _parse_kind(kind)
        goal = None
        if poisoned:
            goal, sep, rest = rest.partition(":")
            if not sep:
                raise ConfigError("goal", "drafted-poison needs :<goal>:<suite>:<items>")
        suite, sep, items = rest.partition(":")
        if not sep:
            raise ConfigError("spec", "expected <suite>:<items> after the options")
        config = cls(**options, goal=goal)
        config.check(suite, items.split(","))
        return config, suite, items.split(",")

    @classmethod
    def from_template(cls, template):
        """The Config of a plan template (`<kind>[:<goal>]:{suite}:{items}`)."""
        head, sep, tail = template.rpartition(":{suite}:{items}")
        if not sep or tail:
            raise ConfigError("template", "a template ends with :{suite}:{items}")
        kind, colon, goal = head.partition(":")
        options, poisoned = _parse_kind(kind)
        if poisoned != bool(colon and goal):
            raise ConfigError("goal", "drafted-poison, and only it, takes :<goal> before :{suite}:{items}")
        config = cls(**options, goal=goal or None)
        config.check()
        return config

    # -- the rules -------------------------------------------------------
    def check(self, suite=None, items=None):
        """Raise ConfigError naming the first rule this configuration (and,
        given them, these tasks) breaks: the rules of `drafted_options` and
        `drafted_cases`, in words."""
        if type(self.drafts) is not int or not 1 <= self.drafts <= MAX_DRAFTS:
            raise ConfigError("drafts", f"must be 1..{MAX_DRAFTS}")
        for key, allowed in CHOICES.items():
            value = getattr(self, key)
            if value not in allowed and not (key == "mapper" and value is None):
                raise ConfigError(key, f"{value!r} is not one of {', '.join(allowed)}")
        if self.mapper is not None and self.author != "structured":
            raise ConfigError("mapper", "only author='structured' takes a mapper")
        from savana_bench.root_drafter import ROOT_POISON_GOALS
        if self.goal is not None and self.goal not in ROOT_POISON_GOALS:
            raise ConfigError("goal", f"{self.goal!r} is not one of {', '.join(ROOT_POISON_GOALS)}")
        if self.attack == "autodojo" and self.goal is not None:
            raise ConfigError("attack", "AutoDojo's injections never run with a compromised planner (goal)")
        if self.exposure == "data" and self.attack != "autodojo":
            raise ConfigError("exposure", "exposure='data' shows AutoDojo's injections: needs attack='autodojo'")
        if self.owner in ("directory", "set") and self.review != "derived":
            raise ConfigError("owner", f"owner={self.owner!r} judges data-derived destinations: "
                                       "needs review='derived'")
        fixed = self.author in ("fixed", "registered") or self.mapper == "template"
        if fixed and (self.drafts != 1 or self.goal is not None or self.exposure != "none"):
            which = f"author={self.author!r}" if self.author != "structured" else "mapper='template'"
            raise ConfigError("drafts" if self.drafts != 1 else "goal" if self.goal else "exposure",
                              f"{which} runs one fixed text per task: drafts=1, no goal, no exposure")
        if self.compute == "calc" and fixed:
            raise ConfigError("compute", "compute='calc' is for a planner that drafts "
                                         "(not fixed, registered or mapper='template')")
        if self.answer == "final" and fixed:
            raise ConfigError("answer", "answer='final' is for a planner that drafts "
                                        "(not fixed, registered or mapper='template')")
        if self.owner == "approve" and (self.goal is not None or self.exposure != "none" or self.review != "derived"):
            raise ConfigError("owner", "owner='approve' (the human-owner upper bound) is benign only: "
                                       "review='derived', no goal, no exposure")
        if self.actions == "ask" and (self.drafts < 2 or fixed):
            raise ConfigError("actions", "actions='ask' asks for a later draft: drafts >= 2 and a planner "
                                         "that drafts")
        if self.instructions == "adopt" and (self.author != "deepseek" or self.owner not in ("directory", "set")
                                             or self.goal is not None or self.exposure != "none"
                                             or self.view != "request"):
            raise ConfigError("instructions", "instructions='adopt' needs author='deepseek', owner 'directory' "
                                              "or 'set', view='request', no goal and no exposure")
        if suite is not None or items is not None:
            self._check_tasks(suite, list(items or ()))

    def _check_tasks(self, suite, items):
        from savana_bench.autodojo_cache import SUITES as AUTODOJO_SUITES
        from savana_bench.dojo_catalog import SUITES
        if suite not in SUITES:
            raise ConfigError("suite", f"{suite!r} is not one of {', '.join(SUITES)}")
        if not items:
            raise ConfigError("items", "no tasks")
        if len(set(items)) != len(items):
            raise ConfigError("items", "a task is listed twice")
        for item in items:
            if not ITEM.fullmatch(item):
                raise ConfigError("items", f"{item!r} is not user_task_N or user_task_N+injection_task_M")
        if self.attack == "autodojo" and suite not in AUTODOJO_SUITES:
            raise ConfigError("attack", f"AutoDojo has no injections for {suite} "
                                        f"(only {', '.join(AUTODOJO_SUITES)})")
        if self.exposure == "data" and any("+" not in item for item in items):
            raise ConfigError("exposure", "exposure='data' needs every task to be an attack pair")
        if self.owner == "approve" and any("+" in item for item in items):
            raise ConfigError("owner", "owner='approve' runs benign tasks only")
        if self.goal is not None and any("+" in item for item in items):
            raise ConfigError("goal", "a compromised planner runs benign environments (no injection pairs)")
        if self.author == "fixed":
            from savana_bench.fixed_programs import FIXED_PROGRAMS
            missing = [i for i in items if (suite, i.split("+")[0]) not in FIXED_PROGRAMS]
            if missing:
                raise ConfigError("author", f"no fixed program for {suite} {', '.join(missing)}")
        if self.author == "registered" or self.mapper == "template":
            from savana_bench.structured_templates import load_registry, template
            registry = load_registry()
            missing = []
            for item in items:
                try:
                    template(registry, suite, item.split("+")[0])
                except KeyError:
                    missing.append(item)
            if missing:
                raise ConfigError("author", f"no registered template for {suite} {', '.join(missing)}")

    def masked(self, planner=True, extractor=True):
        """This configuration with the privacy masking on. The owner's sensitive
        values (names, accounts, addresses, ... as the kernel's leak gate finds
        them) reach a model only as placeholders:
        - `planner`: the drafting model is sent the request with placeholders,
          which the owner binds back to its own values (`view="masked"`);
        - `extractor`: the kernel's executor masks every input of the
          quarantined extractor and puts the values back into its reply
          (`extract="masked"`; the host then serves the suite's `-masked`
          catalog, which ships the model tools on the model codec).
        A part left False keeps this configuration's own setting."""
        return replace(self, view="masked" if planner else self.view,
                       extract="masked" if extractor else self.extract)

    def models(self):
        """Every model this configuration calls (`chat_models` names)."""
        return {self.planner, self.extractor, self.executor}

    def catalog_suffix(self):
        """Which committed suite catalog the host serves: `-masked` ships the
        model tools on the model codec, which `extract='masked'` needs."""
        return "-masked" if self.extract == "masked" else ""


def _parse_kind(kind):
    """The options of `drafted[+k=v...]` / `drafted-poison[+k=v...]` and whether it is the latter."""
    base, *options = kind.split("+")
    if base not in ("drafted", "drafted-poison"):
        raise ConfigError("spec", f"unknown experiment kind {base!r} (drafted or drafted-poison)")
    names = {f.name for f in fields(Config)} - {"goal"}
    values = {}
    for option in options:
        key, equals, value = option.partition("=")
        if not equals:
            raise ConfigError("spec", f"option {option!r} is not key=value")
        if key not in names:
            raise ConfigError(key, f"unknown option (one of {', '.join(OPTION_ORDER)})")
        if key in values:
            raise ConfigError(key, "given twice")
        if key == "drafts":
            if not re.fullmatch(r"[0-9]", value):
                raise ConfigError("drafts", f"must be 1..{MAX_DRAFTS}")
            value = int(value)
        values[key] = value
    return values, base == "drafted-poison"


def runner_cases(spec):
    """The runner's own cases for a spec (its parser is the authority); more
    than MAX_CASES cannot run in one armed batch."""
    if not SPEC_CHARS.fullmatch(spec):
        raise ConfigError("spec", "only letters, digits and _+=:,.- may appear in a spec")
    try:
        cases = experiment_cases(spec)
    except ValueError as error:
        raise ConfigError("spec", f"the runner refuses it ({error})") from None
    except ImportError as error:
        # instructions='adopt' asks AgentDojo which requests delegate to data.
        raise ConfigError("spec", f"counting this spec's cases needs {error.name} in this Python "
                                  "(the lab venv has it: python -m savana_lab setup)") from None
    if len(cases) > MAX_CASES:
        raise ConfigError("items", f"{len(cases)} cases; an armed batch runs at most {MAX_CASES}")
    return cases


# The arms of the utility report (experiments/UTILITY-IMPROVEMENTS-20261012.zh-CN.md).
U8S = Config(drafts=3, actions="ask", review="derived", owner="directory", author="structured", mapper="deepseek")
U9 = replace(U8S, compute="calc", answer="final")
U9H = replace(U9, owner="approve")
PRESETS = dict(u8s=U8S, u9=U9, u9h=U9H)
