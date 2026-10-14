"""python -m savana_lab: run Savana experiments and read their results.

    python -m savana_lab setup                               # verification venv (once)
    python -m savana_lab artifacts build                     # kernel binaries, wheel, example (~20 min)
    python -m savana_lab plan u9c --preset u9 --lines        # the batches a run would have
    python -m savana_lab run u9c --preset u9 --background    # start; returns at once
    python -m savana_lab status u9c                          # any time, from any shell
    python -m savana_lab stop                                # after the running batch
    python -m savana_lab report u9c --compare u9b
    python -m savana_lab why u9c travel user_task_13
    python -m savana_lab episode u9c travel user_task_13 --model-calls
    python -m savana_lab quick travel user_task_13 --preset u9 --set planner=deepseek-v4-pro
                                                             # one task here: no host, NOT evidence
    python -m savana_lab quick-check u9b                     # how closely quick follows the host
    python -m savana_lab run u9c --preset u9 --host aws --aws-region us-east-1 --aws-security-group sg-0123
                                                             # each batch on a new EC2 instance (or --host ssh)

Model keys are read from each provider's environment variable
($DEEPSEEK_API_KEY, $OPENAI_API_KEY, ...; savana_bench.chat_models), never
from an argument.
"""
from __future__ import annotations

import argparse
from dataclasses import fields, replace
import json
from pathlib import Path
import sys
import time

from .artifacts import ArtifactError
from .config import PRESETS, Config, ConfigError
from .driver import LabError
from .host import HostError
from .lab import Lab
from .plan import benign, make_plan
from .results import ABSENT, UNVERIFIED, batch_state, move_aside, run_dirs


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m savana_lab", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, help="results directory (default: this checkout's)")
    parser.add_argument("--workdir", type=Path, help="artifacts, staging, verification trees (~/.savana-lab)")
    parser.add_argument("--python", type=Path, help="the Python that verifies (default: <workdir>/venv)")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("setup", help="create the verification venv")
    artifacts = commands.add_parser("artifacts", help="list, build or adopt artifacts")
    artifacts.add_argument("action", choices=("list", "build", "adopt"))
    artifacts.add_argument("--jobs", type=int, default=2)
    artifacts.add_argument("--offline", action="store_true")
    for name in ("rev", "bin-tar", "wheel", "example", "note", "variant"):
        artifacts.add_argument(f"--{name}")
    artifacts.add_argument("--patch", type=Path, help="build a variant: this patch applied for the build only")

    for name in ("plan", "run"):
        sub = commands.add_parser(name, help="show a run's batches" if name == "plan" else "create and start a run")
        sub.add_argument("name")
        _arm(sub)
        sub.add_argument("--suites", help="comma-separated suites (default: all four, 97 tasks)")
        sub.add_argument("--tasks", type=Path, help="a file of '<suite> <item>' lines instead of whole suites")
        if name == "plan":
            sub.add_argument("--lines", action="store_true", help="print a shell driver's plan file")
        else:
            _driving(sub)
            sub.add_argument("--capture", action="store_true", help="record HTTP request/status lines")
            sub.add_argument("--strace", action="store_true")
            floor = sub.add_argument_group("the floor experiment's deployment variants")
            floor.add_argument("--disposition", choices=("require_approval", "permit"))
            floor.add_argument("--unconfined-write", help="the write tool shipped without its intent-flow validator")
            floor.add_argument("--catalog-variant", type=Path, help="a catalog served instead of the committed one")
            floor.add_argument("--artifacts-variant", help="a counterfactual build stored as <rev>-<variant>")
            _hosts_options(sub)
    resume = commands.add_parser("resume", help="continue a run (verified batches are skipped)")
    resume.add_argument("name")
    _driving(resume)
    status = commands.add_parser("status", help="where a run is (default: the newest)")
    status.add_argument("name", nargs="?")
    progress = commands.add_parser("progress", help="a run's progress events")
    progress.add_argument("name")
    progress.add_argument("--follow", action="store_true")
    commands.add_parser("stop", help="stop the running driver before its next batch")
    verify = commands.add_parser("verify", help="verify an exported batch again")
    verify.add_argument("batch")
    verify.add_argument("--rev", help="staged revision (a batch of a savana_lab run knows its own)")
    verify.add_argument("--wheel", type=Path, help="staged wheel (likewise)")
    rerun = commands.add_parser("rerun", help="move a batch to _superseded/ so the next resume runs it again")
    rerun.add_argument("batch")
    report = commands.add_parser("report", help="utility of one or more runs")
    report.add_argument("names", nargs="+")
    report.add_argument("--compare")
    why = commands.add_parser("why", help="what happened to one task")
    episode = commands.add_parser("episode", help="one task's events and model calls")
    for sub in (why, episode):
        sub.add_argument("name")
        sub.add_argument("suite")
        sub.add_argument("task")
    episode.add_argument("--model-calls", action="store_true")
    quick = commands.add_parser("quick", help="try one task in this process: no host, NOT experiment evidence")
    quick.add_argument("suite")
    quick.add_argument("task", help="user_task_N or user_task_N+injection_task_M")
    _arm(quick)
    quick.add_argument("--model-calls", action="store_true", help="also print what each model was shown and said")
    quick.add_argument("--example", type=Path, help="the structured-planning example (default: stored artifacts')")
    quick_check = commands.add_parser("quick-check", help="replay host runs through quick's execution and compare")
    quick_check.add_argument("names", nargs="+")
    leftovers = commands.add_parser("aws-leftovers", help="EC2 instances a driver made that still exist")
    leftovers.add_argument("--aws-region", required=True)
    leftovers.add_argument("--aws-profile")
    leftovers.add_argument("--terminate", action="store_true", help="terminate them")

    args = parser.parse_args(argv)
    lab = Lab(**{k: v for k, v in dict(results=args.results, workdir=args.workdir, python=args.python).items()
                 if v is not None})
    try:
        return COMMANDS[args.command](lab, args) or 0
    except (LabError, ArtifactError, ConfigError, HostError, LookupError) as error:
        print(f"savana_lab: {error}", file=sys.stderr)
        return 1


def _arm(sub):
    arm = sub.add_mutually_exclusive_group(required=True)
    arm.add_argument("--preset", choices=sorted(PRESETS))
    arm.add_argument("--template", help="a plan template, e.g. 'drafted+drafts=3:{suite}:{items}'")
    sub.add_argument("--set", action="append", default=[], metavar="OPTION=VALUE",
                     help="change one option of the preset or template (repeatable), e.g. planner=deepseek-v4-pro")


def _config(args):
    """The preset or template, with each --set applied (checked like any Config)."""
    config = PRESETS[args.preset] if args.preset else Config.from_template(args.template)
    types = {f.name: f.type for f in fields(Config)}
    for item in args.set:
        name, equals, value = item.partition("=")
        if not equals or name not in types:
            raise ConfigError(name or item, f"--set takes OPTION=VALUE with OPTION one of {', '.join(types)}")
        try:
            config = replace(config, **{name: int(value) if types[name] in (int, "int") else value})
        except ValueError:
            raise ConfigError(name, f"{value!r} is not a number") from None
    return config


def _hosts_options(sub):
    group = sub.add_argument_group("where each batch's brand-new host comes from (default: a Docker container here)")
    group.add_argument("--host", choices=("docker", "ssh", "aws"), default="docker")
    group.add_argument("--ssh-create", metavar="COMMAND",
                       help="makes a new machine and prints [user@]host[:port] (then, optionally, its host keys)")
    group.add_argument("--ssh-destroy", metavar="COMMAND", help="destroys it after its batch ($SAVANA_LAB_HOST)")
    group.add_argument("--ssh-identity", type=Path, help="the private key to log in with (never copied)")
    group.add_argument("--ssh-user", default="root", help="when the address names none (not root: passwordless sudo)")
    group.add_argument("--aws-region")
    group.add_argument("--aws-security-group", help="sg-...: must let this machine reach port 22")
    group.add_argument("--aws-subnet")
    group.add_argument("--aws-instance-type", default="c7i.xlarge")
    group.add_argument("--aws-ami", help="default: Canonical's current Ubuntu 24.04")
    group.add_argument("--aws-profile")
    group.add_argument("--aws-volume-gb", type=int, default=40)
    group.add_argument("--aws-private-ip", action="store_true", help="connect to the private address (a VPN or VPC)")


def _hosts(args):
    from .remote import AwsHosts, SshHosts
    if args.host == "ssh":
        if not (args.ssh_create and args.ssh_destroy):
            raise ConfigError("host", "--host ssh needs --ssh-create and --ssh-destroy: every batch gets a new machine")
        return SshHosts(create=args.ssh_create, destroy=args.ssh_destroy, user=args.ssh_user,
                        identity=str(args.ssh_identity) if args.ssh_identity else None)
    if args.host == "aws":
        if not (args.aws_region and args.aws_security_group):
            raise ConfigError("host", "--host aws needs --aws-region and --aws-security-group")
        return AwsHosts(region=args.aws_region, security_group=args.aws_security_group, subnet=args.aws_subnet,
                        instance_type=args.aws_instance_type, ami=args.aws_ami, profile=args.aws_profile,
                        volume_gb=args.aws_volume_gb, public_ip=not args.aws_private_ip)
    return None


def _driving(sub):
    sub.add_argument("--background", action="store_true", help="drive in a detached process")
    sub.add_argument("--deadline", type=int, help="start no batch after this many seconds")


def _plan(args):
    config = _config(args)
    if args.tasks:
        tasks = [tuple(line.split()) for line in args.tasks.read_text().splitlines() if line.strip()]
    else:
        tasks = benign(*(args.suites.split(",") if args.suites else ()))
    return make_plan(args.name, config, tasks)


def cmd_setup(lab, args):
    print(lab.setup())


def cmd_artifacts(lab, args):
    store = lab.store()
    if args.action == "list":
        for receipt, artifacts in store.all():
            variant = "" if artifacts.variant is None else f" variant={artifacts.variant}"
            print(f"{artifacts.rev[:12]} {receipt['origin']:8s} {receipt['created']} {artifacts.wheel.name}{variant}")
    elif args.action == "adopt":
        missing = [n for n in ("rev", "bin_tar", "wheel", "example", "note") if not getattr(args, n)]
        if missing:
            raise LabError(f"adopt needs --{' --'.join(m.replace('_', '-') for m in missing)}")
        rev = lab.git().resolve(args.rev)
        stored = store.adopt(rev=rev, bin_tar=Path(args.bin_tar), wheel=Path(args.wheel),
                             example=Path(args.example), note=args.note, variant=args.variant)
        print(f"{stored.rev[:12]} stored at {stored.bin_tar.parent}")
    else:
        shell = lab.shell()
        shell.log.echo = True
        stored = store.build(shell, lab.git(shell), python=lab.verify_python(), jobs=args.jobs, offline=args.offline,
                             patch=args.patch, variant=args.variant)
        print(f"{stored.rev[:12]} built and stored at {stored.bin_tar.parent}")


def cmd_plan(lab, args):
    plan = _plan(args)
    if args.lines:
        print(plan.lines(), end="")
    else:
        for batch in plan.batches:
            print(f"{batch.name:24s} {len(batch.items)} tasks  {batch.spec}")


def cmd_run(lab, args):
    run = lab.create(_plan(args), capture=args.capture, strace=args.strace, disposition=args.disposition,
                     unconfined_write=args.unconfined_write, catalog_variant=args.catalog_variant,
                     artifacts_variant=args.artifacts_variant, host=_hosts(args))
    return _start(run, args)


def cmd_resume(lab, args):
    return _start(lab.open(args.name), args)


def _start(run, args):
    if args.background:
        print(f"driver started (pid {run.start(background=True, deadline=args.deadline)}); "
              f"python -m savana_lab status {run.name}")
        return 0
    run.lab.echo = True
    result = run.start(deadline=args.deadline)
    print(run.status())
    return 0 if result in ("done", "stopped") else 2


def cmd_status(lab, args):
    runs = [lab.open(args.name)] if args.name else lab.runs()[-1:]
    if not runs:
        raise LabError("no runs yet")
    print(runs[0].status())


def cmd_progress(lab, args):
    for event in lab.open(args.name).progress(follow=args.follow):
        print(json.dumps(event, ensure_ascii=False))


def cmd_stop(lab, args):
    lab.stop()
    print("stop requested: the driver stops before its next batch")


def cmd_verify(lab, args):
    state = batch_state(lab.results, args.batch)
    if state not in (UNVERIFIED,):
        raise LabError(f"{args.batch} is {state}: only a complete, unverified batch is verified again")
    rev, wheel = args.rev, args.wheel
    for run in lab.runs():
        if args.batch in (b.name for b in run.plan.batches):
            rev, wheel = run.meta()["stage_rev"], lab.artifacts_for(run).wheel
    if not rev or not wheel:
        raise LabError("not a savana_lab run's batch: give --rev and --wheel (what it staged)")
    batch = lab.results / args.batch
    stamp = int(time.time())
    for name in ("offline-verification.json", "offline-verification.err"):
        if (batch / name).exists():   # the failed verification stays on record
            (batch / name).rename(batch / name.replace("verification.", f"verification.{stamp}.", 1))
    shell = lab.shell()
    value = lab.verifier(shell).verify(batch, run_dirs(batch)[0], lab.git(shell).resolve(rev), wheel)
    print(json.dumps(value, indent=1))


def cmd_rerun(lab, args):
    state = batch_state(lab.results, args.batch)
    if state == ABSENT:
        raise LabError(f"{args.batch} has no results to move aside")
    print(move_aside(lab.results, args.batch, folder="_superseded"))


def cmd_report(lab, args):
    report = lab.report(*args.names)
    print(report.utility())
    print("  outcomes:", dict(report.outcomes()))
    if args.compare:
        print(report.compare(lab.report(args.compare)))


def cmd_why(lab, args):
    print(lab.report(args.name).why(args.suite, args.task))


def cmd_episode(lab, args):
    episode = lab.report(args.name).episode(args.suite, args.task)
    if not args.model_calls:
        print(episode.why())
        return
    _print_calls(episode.model_calls())


def cmd_quick(lab, args):
    from .quick import quick
    result = quick(_config(args), args.suite, args.task, lab=lab, example=args.example)
    print(result)
    if args.model_calls:
        print()
        _print_calls(result.model_calls())


def cmd_quick_check(lab, args):
    from .quick_check import check
    print(check(*args.names, lab=lab))


def cmd_aws_leftovers(lab, args):
    from .remote import aws_leftovers
    found = aws_leftovers(lab.shell(), region=args.aws_region, profile=args.aws_profile, terminate=args.terminate)
    for instance, state, label in found:
        print(f"{instance} {state:10s} {label}")
    print(f"{len(found)} instance(s)" + (" terminated" if args.terminate and found else ""))


def _print_calls(calls):
    for call in calls:
        head = " ".join(f"{k}={v}" for k, v in call.items() if k not in ("shown", "reply"))
        print(f"[{head}]")
        if "shown" in call:
            shown = call["shown"]
            print("shown:", shown if isinstance(shown, str) else json.dumps(shown, ensure_ascii=False))
        print("reply:", call["reply"])
        print()


COMMANDS = {name[4:].replace("_", "-"): function for name, function in globals().items() if name.startswith("cmd_")}

if __name__ == "__main__":
    sys.exit(main())
