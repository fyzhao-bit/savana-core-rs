"""savana_lab: experiment orchestration from Python (experiments/savana_lab).

No Docker, model or network here: a recording shell stands in for every
command, and synthetic result directories for exported runs."""
import base64
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from unittest import mock

from savana_bench.planner_experiment import experiment_cases
from savana_lab import U8S, U9, U9H, Config, ConfigError, Lab, benign, make_plan, pairs
from savana_lab import driver as driver_module
from savana_lab.__main__ import main
from savana_lab.artifacts import Artifacts, ArtifactStore
from savana_lab.batch import ADMIN, Batch
from savana_lab.config import CHOICES, runner_cases
from savana_lab.driver import LabError, Lock, drive
from savana_lab.host import DockerHost
from savana_lab.plan import USER_TASKS, Plan
from savana_lab.results import ABSENT, INCOMPLETE, UNVERIFIED, VERIFIED, batch_state
from savana_lab.shell import CommandFailed, Log, Result
from savana_lab.stage import build_stage

NEEDS_AGENTDOJO = unittest.skipUnless(importlib.util.find_spec("agentdojo"), "install the explicit AgentDojo test extra")
REPO = Path(__file__).resolve().parents[2]
U9_TEMPLATE = ("drafted+drafts=3+actions=ask+review=derived+owner=directory+author=structured+mapper=deepseek"
               "+compute=calc+answer=final:{suite}:{items}")
# Templates earlier plan files ran (the shell drivers' plan files are not in the repository).
HISTORICAL = (
    U9_TEMPLATE,
    "drafted+drafts=3+actions=ask+review=derived+owner=approve+author=structured+mapper=deepseek"
    "+compute=calc+answer=final:{suite}:{items}",
    "drafted+drafts=3+actions=ask+review=derived+owner=directory+author=structured+mapper=deepseek:{suite}:{items}",
    "drafted+drafts=3+actions=ask+review=derived+owner=directory+author=structured+mapper=deepseek"
    "+attack=autodojo:{suite}:{items}",
    "drafted-poison+drafts=3+author=structured+mapper=service:exfiltrate:{suite}:{items}",
    "drafted-poison+drafts=3+actions=ask+review=derived+owner=directory+author=structured+mapper=service"
    ":redirect:{suite}:{items}",
    "drafted+drafts=3+author=structured+mapper=service:{suite}:{items}",
)


class ConfigTests(unittest.TestCase):
    def test_the_u9_preset_is_the_u9_plans_template(self):
        self.assertEqual(U9.template(), U9_TEMPLATE)
        self.assertEqual(Config.from_template(U9_TEMPLATE), U9)

    def test_every_historical_template_round_trips(self):
        for template in HISTORICAL:
            with self.subTest(template=template):
                self.assertEqual(Config.from_template(template).template(), template)

    def test_a_spec_round_trips_with_its_tasks(self):
        spec = U9.spec("banking", ["user_task_0", "user_task_3"])
        self.assertEqual(Config.from_spec(spec), (U9, "banking", ["user_task_0", "user_task_3"]))
        poisoned = replace(U8S, goal="redirect")
        spec = poisoned.spec("slack", "user_task_1")
        self.assertTrue(spec.startswith("drafted-poison+") and ":redirect:slack:user_task_1" in spec)
        self.assertEqual(Config.from_spec(spec)[0], poisoned)

    def test_a_default_written_out_gives_the_same_cases(self):
        explicit = "drafted+drafts=1+author=structured+mapper=template:banking:user_task_1"
        config, suite, items = Config.from_spec(explicit)
        self.assertEqual(config.spec(suite, items), "drafted+author=structured:banking:user_task_1")
        self.assertEqual(experiment_cases(explicit), experiment_cases(config.spec(suite, items)))

    def test_each_rule_is_named(self):
        cases = {
            "drafts": Config(drafts=6),
            "planner": Config(planner="gpt"),
            "mapper": Config(mapper="deepseek"),
            "owner": Config(owner="directory"),
            "actions": replace(U9, drafts=1),
            "compute": Config(author="registered", compute="calc"),
            "answer": Config(author="structured", answer="final"),
            "exposure": Config(exposure="data"),
            "instructions": Config(instructions="adopt"),
            "attack": Config(attack="autodojo", goal="tamper"),
        }
        for field, config in cases.items():
            with self.subTest(field=field), self.assertRaises(ConfigError) as caught:
                config.check()
            self.assertEqual(caught.exception.field, field)

    def test_task_rules_are_named(self):
        with self.assertRaises(ConfigError) as caught:
            replace(U9, attack="autodojo").check("workspace", ["user_task_0"])
        self.assertIn("AutoDojo", str(caught.exception))
        with self.assertRaises(ConfigError):
            U9H.check("banking", ["user_task_0+injection_task_1"])
        with self.assertRaises(ConfigError):
            U9.check("banking", ["user_task_0", "user_task_0"])
        with self.assertRaises(ConfigError):
            U9.check("banking", ["user_task_100"])

    def test_the_rules_agree_with_the_runner(self):
        """Every combination check() accepts the runner accepts, and the other way round."""
        values = dict(drafts=(1, 2), author=CHOICES["author"], mapper=(None, *CHOICES["mapper"]),
                      owner=CHOICES["owner"], review=CHOICES["review"], actions=CHOICES["actions"],
                      compute=CHOICES["compute"], answer=CHOICES["answer"])
        keys = list(values)
        checked = 0
        for combination in itertools.product(*values.values()):
            options = dict(zip(keys, combination))
            if options["author"] == "fixed":
                continue   # needs a fixed program per task, checked against FIXED_PROGRAMS below
            config = Config(**options)
            try:
                config.check("banking", ["user_task_0"])
                ours = True
            except ConfigError:
                ours = False
            spec = ("drafted+" + "+".join(f"{k}={v}" for k, v in options.items() if v is not None)
                    + ":banking:user_task_0")
            try:
                experiment_cases(spec)
                theirs = True
            except ValueError:
                theirs = False
            self.assertEqual(ours, theirs, spec)
            checked += 1
        self.assertGreater(checked, 1000)

    def test_a_spec_is_safe_to_write_into_a_unit(self):
        with self.assertRaises(ConfigError):
            runner_cases("drafted:banking:user_task_0\nExecStart=/bin/sh")


class PlanTests(unittest.TestCase):
    def test_97_tasks_are_cut_as_every_u9_plan_was(self):
        plan = make_plan("u9c", U9, benign())
        self.assertEqual([(b.name, len(b.items)) for b in plan.batches], [
            ("u9c-banking-0", 8), ("u9c-banking-1", 8), ("u9c-slack-0", 7), ("u9c-slack-1", 7),
            ("u9c-slack-2", 7), ("u9c-travel-0", 7), ("u9c-travel-1", 7), ("u9c-travel-2", 6),
            ("u9c-workspace-0", 8), ("u9c-workspace-1", 8), ("u9c-workspace-2", 8), ("u9c-workspace-3", 8),
            ("u9c-workspace-4", 8)])
        self.assertEqual(len(plan.tasks()), 97)
        first = plan.lines().splitlines()[0]
        self.assertEqual(first, "u9c-banking-0 banking " + ",".join(f"user_task_{n}" for n in range(8)) + " "
                         + U9_TEMPLATE)
        self.assertEqual(Plan.from_lines("u9c", plan.lines()), plan)
        self.assertEqual(Plan.from_json(plan.to_json()), plan)

    def test_attack_pairs_and_a_config_per_suite(self):
        tasks = pairs("workspace", [0], [1, 2]) + pairs("banking", [2], range(9)) + pairs("banking", [5], [0])
        plan = make_plan("x", lambda suite: U8S if suite == "workspace" else replace(U8S, attack="autodojo"), tasks)
        self.assertEqual([b.name for b in plan.batches], ["x-banking-0", "x-banking-1", "x-workspace-0"])
        self.assertTrue(all("+attack=autodojo" in b.spec for b in plan.batches[:2]))
        self.assertNotIn("attack", plan.batches[2].spec)

    @NEEDS_AGENTDOJO
    def test_suite_sizes_are_agentdojos(self):
        from agentdojo.task_suite.load_suites import get_suite
        from savana_bench.agentdojo_tasks import BENCHMARK
        for suite, count in USER_TASKS.items():
            self.assertEqual(sorted(get_suite(BENCHMARK, suite).user_tasks),
                             sorted(f"user_task_{n}" for n in range(count)))


class Recorder:
    """A Shell that records each command and answers from `replies`
    (first matching substring of the joined command)."""

    def __init__(self, replies=()):
        self.calls, self.replies, self.log = [], list(replies), Log()

    def run(self, argv, *, input=None, env=None, cwd=None, timeout=None, check=True, quiet=False, stream=False):
        argv = [str(a) for a in argv]
        self.calls.append(dict(argv=argv, input=input, env=env))
        joined = " ".join(argv)
        result = Result(0, "")
        for pattern, reply in self.replies:
            if pattern in joined:
                result = reply(joined) if callable(reply) else Result(0, reply)
                break
        if check and result.code != 0:
            raise CommandFailed(argv, result.code, result.out, result.err)
        return result

    def pipe(self, first, second, **_):
        self.calls.append(dict(argv=[*map(str, first), "|", *map(str, second)], input=None, env=None))
        return Result(0)

    def spawn(self, argv, *, log_path):
        self.calls.append(dict(argv=list(map(str, argv)), input=None, env=None))


STATUS = json.dumps(dict(checks=dict(a=True), ready_to_request_real_authentication=True))


def host_replies(probes):
    return [("is-system-running", "running"), (f"{ADMIN} status", STATUS),
            ("ls -td /var/lib/savana-benchmark/runs", "/var/lib/savana-benchmark/runs/abc123/\n"),
            ("episode_score", lambda _: Result(0, probes.pop(0)))]


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.key = "sk-test-0123456789"
        self.shell = Recorder(host_replies(["0 running", "3 running", "8 finished"]))
        self.host = DockerHost(self.shell, workdir="/tmp/unused", sleep=lambda _: None)
        self.batch = Batch(self.host, key=self.key, sleep=lambda _: None)

    def test_the_attempt_runs_the_shell_drivers_steps_in_order(self):
        self.batch.attempt("drafted:banking:user_task_0", "/w/stage-opt.tar", "/w/linux-b-bin.tar")
        joined = [" ".join(c["argv"]) for c in self.shell.calls]
        order = ["docker rm -f savana-b", "docker run -d --name savana-b --privileged", "mount --make-rshared",
                 "docker cp /w/stage-opt.tar savana-b:/root/stage-opt.tar", "install.py --file-backed-integration",
                 "prepare-auth", "configure-model --key-fd 3", "benchmark_identity enroll", f"{ADMIN} status",
                 "ss -ltnp", "benchmark_identity arm"]
        positions = [next(i for i, c in enumerate(joined) if step in c) for step in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(f"{ADMIN} start", joined[-1])
        enroll = next(c for c in self.shell.calls if "benchmark_identity enroll" in " ".join(c["argv"]))
        self.assertEqual(enroll["env"], None)
        self.assertIn("PLANNER_SPEC=drafted:banking:user_task_0", enroll["argv"])

    def test_the_key_only_ever_travels_on_stdin(self):
        self.batch.attempt("drafted:banking:user_task_0", "/w/stage-opt.tar", "/w/linux-b-bin.tar")
        carrying = [c for c in self.shell.calls if c["input"] is not None]
        self.assertEqual(len(carrying), 1)
        self.assertIn("configure-model --key-fd 3", " ".join(carrying[0]["argv"]))
        self.assertEqual(carrying[0]["input"], self.key)
        for call in self.shell.calls:
            self.assertNotIn(self.key, " ".join(call["argv"]))
            self.assertNotIn(self.key, json.dumps(call["env"]))

    def test_a_failed_install_stops_the_attempt(self):
        failing = Recorder([("is-system-running", "running"),
                            ("install.py", lambda _: Result(1, "Traceback: install failed"))])
        batch = Batch(DockerHost(failing, workdir="/tmp/unused", sleep=lambda _: None), key=self.key)
        with self.assertRaisesRegex(Exception, "install"):
            batch.attempt("drafted:banking:user_task_0", "/w/s.tar", "/w/b.tar")
        self.assertFalse(any("prepare-auth" in " ".join(c["argv"]) for c in failing.calls))

    def test_waiting_reports_episodes_until_the_summary(self):
        heard = []
        self.assertEqual(self.batch.wait(progress=heard.append), "abc123")
        self.assertEqual(heard, [0, 3, 8])

    def test_a_probe_that_fails_once_does_not_end_the_wait(self):
        probes = iter([Result(1, "", "Error response from daemon"), Result(0, "2 running"), Result(0, "8 finished")])
        shell = Recorder([("ls -td /var/lib/savana-benchmark/runs", "/var/lib/savana-benchmark/runs/r9/"),
                          ("episode_score", lambda _: next(probes))])
        batch = Batch(DockerHost(shell, workdir="/tmp/unused"), key=self.key, sleep=lambda _: None)
        heard = []
        self.assertEqual(batch.wait(progress=heard.append), "r9")
        self.assertEqual(heard, [2, 8])

    def test_the_floor_experiments_disposition_reaches_the_installer_and_is_checked(self):
        shell = Recorder(host_replies([]) + [("kerneld-bootstrap-v2.json", "permit permit send_money")])
        batch = Batch(DockerHost(shell, workdir="/tmp/unused", sleep=lambda _: None), key=self.key,
                      disposition="permit", unconfined_write="send_money", sleep=lambda _: None)
        batch.attempt("drafted:banking:user_task_0", "/w/s.tar", "/w/b.tar")
        install = next(c for c in shell.calls if "install.py" in " ".join(c["argv"]))
        self.assertIn("SAVANA_PROTECTED_EXPERIMENT_DISPOSITION=permit", install["argv"])
        self.assertIn("SAVANA_PROTECTED_EXPERIMENT_UNCONFINED_WRITE=send_money", install["argv"])
        wrong = Recorder(host_replies([]) + [("kerneld-bootstrap-v2.json", "require_approval permit None")])
        batch = Batch(DockerHost(wrong, workdir="/tmp/unused", sleep=lambda _: None), key=self.key,
                      disposition="permit", sleep=lambda _: None)
        with self.assertRaisesRegex(Exception, "provisioned"):
            batch.attempt("drafted:banking:user_task_0", "/w/s.tar", "/w/b.tar")

    def test_a_long_command_streams_its_lines_and_is_stopped_at_its_timeout(self):
        from savana_lab.shell import Shell
        with tempfile.TemporaryDirectory() as root:
            log = Log(Path(root) / "build.log", secrets=["sk-secret"])
            result = Shell(log).run(["python3", "-c", "import sys; print('one'); print('sk-secret', file=sys.stderr)"],
                                    stream=True)
            self.assertEqual(result.out.splitlines(), ["one", "[redacted]"])
            self.assertNotIn("sk-secret", (Path(root) / "build.log").read_text())
            with self.assertRaisesRegex(CommandFailed, "timeout"):
                Shell(log).run(["python3", "-c", "import time; time.sleep(30)"], stream=True, timeout=1)

    def test_a_log_never_holds_a_secret(self):
        with tempfile.TemporaryDirectory() as root:
            log = Log(Path(root) / "x.log", secrets=["sk-secret"])
            log.write("key=sk-secret done")
            self.assertNotIn("sk-secret", (Path(root) / "x.log").read_text())


def write_run(results, batch, rows, *, verified=True, completed=True, events=None):
    run = Path(results) / batch / "r1"
    run.mkdir(parents=True)
    (run / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in (events or [
        dict(kind="manifest", cases=[{k: r[k] for k in ("suite", "user", "injection")} for r in rows])])))
    if completed:
        (run / "summary.json").write_text(json.dumps(dict(rows=rows)))
        (run / "completion.json").write_text("{}")
    if verified:
        (Path(results) / batch / "offline-verification.json").write_text(json.dumps(
            dict(audit_consistent=True, episodes_verified=len(rows), groups={}, unauthorized_provider_attempts=0)))


def row(suite, n, utility, outcome="published", injection=None):
    return dict(suite=suite, user=f"user_task_{n}", injection=injection, utility=utility, outcome=outcome)


class ResultsTests(unittest.TestCase):
    def test_batch_states(self):
        with tempfile.TemporaryDirectory() as results:
            write_run(results, "a", [row("banking", 0, True)])
            write_run(results, "b", [row("banking", 0, True)], verified=False)
            write_run(results, "c", [row("banking", 0, True)], verified=False, completed=False)
            (Path(results) / "d").mkdir()
            (Path(results) / "d" / "offline-verification.json").write_text("")
            self.assertEqual([batch_state(results, n) for n in "abcde"],
                             [VERIFIED, UNVERIFIED, INCOMPLETE, INCOMPLETE, ABSENT])


class FakeLab(Lab):
    """A lab whose host, stage, verifier and balance are fakes."""

    def __init__(self, root, balance=("ok", 10.0), verify_ok=True):
        super().__init__(repo=REPO, results=Path(root) / "results", workdir=Path(root) / "work")
        self.results.mkdir(parents=True)
        self.balance_value, self.verify_ok, self.ran = balance, verify_ok, []

    def shell(self, log=None):
        return Recorder(host_replies(["9 finished"]))

    def lock_path(self):
        return self.workdir / "driver.lock"

    def balance(self, key):
        return self.balance_value

    def artifacts_for(self, run):
        return Artifacts("0" * 40, Path("/w/bin.tar"), Path("/w/x.whl"), Path("/w/example"))

    def verifier(self, shell):
        lab = self

        class Verifier:
            def verify(self, batch_dir, run_dir, rev, wheel):
                if not lab.verify_ok:
                    from savana_lab.verify import VerificationFailed
                    raise VerificationFailed("verifier said no")
                (batch_dir / "offline-verification.json").write_text(json.dumps(dict(
                    audit_consistent=True, episodes_verified=1, groups={}, unauthorized_provider_attempts=0)))
                return json.loads((batch_dir / "offline-verification.json").read_text())
        return Verifier()


def create(lab, plan):
    """A run record as `Lab.create` writes it (without its git checks)."""
    from savana_lab.lab import Run
    run = Run(lab, plan.name)
    run.dir.mkdir(parents=True)
    (run.dir / "run.json").write_text(json.dumps(dict(name=plan.name, created="t", stage_rev="f" * 40,
                                                      artifacts=dict(rev="0" * 40), plan=plan.to_json())))
    return run


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.plan = make_plan("t", U9, [("banking", "user_task_0"), ("slack", "user_task_0"),
                                        ("travel", "user_task_0")])

    def drive(self, lab, run, outcome="published", **options):
        exported = []

        def export(batch, run_id, out):
            episode = row(out.name.split("-")[1], 0, outcome == "published", outcome=outcome)
            if outcome == "setup_failed":
                episode.update(error_type="OSError", error_errno=98)
            write_run(out.parent, out.name, [episode], verified=False)
            exported.append(out.name)
            return out / "r1"

        with mock.patch.object(driver_module, "build_stage", return_value=("/w/stage.tar", "staged")), \
                mock.patch.object(Batch, "attempt", lambda *a: lab.ran.append(a[1])), \
                mock.patch.object(Batch, "export", export):
            result = drive(lab, run, key="sk-k", sleep=lambda _: None, **options)
        return result, exported

    def events(self, run):
        return [e["event"] for e in run.progress()]

    def test_a_plan_runs_to_the_end_and_resumes_by_skipping(self):
        lab = FakeLab(self.root.name)
        run = create(lab, self.plan)
        self.assertEqual(self.drive(lab, run)[0], "done")
        self.assertEqual([batch_state(lab.results, b.name) for b in self.plan.batches], [VERIFIED] * 3)
        self.assertEqual(self.drive(lab, run), ("done", []))
        self.assertEqual(self.events(run).count("skipped"), 3)
        self.assertIn("utility so far (verified batches): 3/3", str(run.status()))

    def test_a_failed_verification_stops_the_run(self):
        lab = FakeLab(self.root.name, verify_ok=False)
        run = create(lab, self.plan)
        result, exported = self.drive(lab, run)
        self.assertEqual((result, exported), ("failed", ["t-banking-0"]))
        self.assertEqual(batch_state(lab.results, "t-banking-0"), UNVERIFIED)
        # Running again neither repeats nor skips it: it must be verified or moved aside on purpose.
        lab.verify_ok = True
        self.assertEqual(self.drive(lab, run), ("failed", []))
        self.assertIn("not verified", str(run.status()))

    def test_an_interrupted_batch_is_moved_aside_never_deleted(self):
        lab = FakeLab(self.root.name)
        run = create(lab, self.plan)
        write_run(lab.results, "t-banking-0", [], verified=False, completed=False)
        self.assertEqual(self.drive(lab, run)[0], "done")
        aside = list((lab.results / "_interrupted").iterdir())
        self.assertEqual(len(aside), 1)
        self.assertTrue(aside[0].name.startswith("t-banking-0-") and (aside[0] / "r1" / "events.jsonl").exists())

    def test_a_low_balance_or_a_stop_request_stops_before_a_batch(self):
        lab = FakeLab(self.root.name, balance=("ok", 0.2))
        run = create(lab, self.plan)
        self.assertEqual(self.drive(lab, run), ("stopped", []))
        lab.balance_value = ("ok", 5.0)
        lab.stop()
        self.assertEqual(self.drive(lab, run), ("stopped", []))
        self.assertEqual(lab.ran, [])

    def test_a_deadline_starts_no_batch_after_it(self):
        lab = FakeLab(self.root.name)
        run = create(lab, self.plan)
        now = [1e7]   # a monotonic clock long after boot

        def clock(step):
            def tick():
                now[0] += step
                return now[0]
            return tick
        self.assertEqual(self.drive(lab, run, clock=clock(1), deadline=1000)[0], "done")
        self.assertEqual(len(lab.ran), 3)
        late = create(lab, make_plan("late", U9, [("banking", "user_task_0"), ("slack", "user_task_0")]))
        self.assertEqual(self.drive(lab, late, clock=clock(400), deadline=1000)[0], "stopped")
        self.assertEqual(len(lab.ran), 4)
        self.assertIn("deadline", [e for e in late.progress()][-1]["reason"])

    def test_a_batch_that_measured_nothing_stops_the_run(self):
        lab = FakeLab(self.root.name)
        run = create(lab, make_plan("s", U9, [("banking", "user_task_0"), ("slack", "user_task_0")]))
        self.assertEqual(self.drive(lab, run, outcome="setup_failed")[0], "failed")
        self.assertEqual(len(lab.ran), 1)
        status = str(run.status())
        self.assertIn("every episode failed at setup (OSError errno 98)", status)
        self.assertIn("s-banking-0 1/1 (OSError errno 98)", status)

    def test_one_driver_at_a_time(self):
        lab = FakeLab(self.root.name)
        with Lock(lab.lock_path()):
            with self.assertRaises(LabError):
                with Lock(lab.lock_path()):
                    pass

    def test_no_key_no_run(self):
        lab = FakeLab(self.root.name)
        with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""}), self.assertRaises(LabError):
            drive(lab, create(lab, self.plan))


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.lab = FakeLab(self.root.name)
        results = self.lab.results
        program = json.dumps({"steps": []})
        answer = base64.b64encode(json.dumps({"result": {"content": [{"text": json.dumps(
            {"text": "Breizh Cafe"})}]}}).encode()).decode()
        events = [dict(kind="manifest", cases=[dict(suite="travel", user="user_task_2", injection=None)]),
                  dict(kind="root_drafted", episode=0, attempt=1, program_text=program,
                       response_sha256=hashlib.sha256(program.encode()).hexdigest()),
                  dict(kind="program_refused", episode=0, attempt=1, reason="edge_path", step=2, field="x"),
                  dict(kind="official_tool_result", episode=0, operation=1, tool="get_all_restaurants_in_city",
                       arguments={}, response={"result": {"content": [{"text": "A, B"}]}}),
                  dict(kind="official_tool_result", episode=0, operation=2, tool="quarantined_extract",
                       arguments=dict(model="deepseek-flash", instruction="Which?", source="1", target="answer",
                                      context=""),
                       response={"result": {"content": [{"text": "{\"text\":\"B\"}"}]}}),
                  dict(kind="episode_observation", episode=0, output_base64=answer),
                  dict(kind="episode_score", episode=0, outcome="published", utility=False)]
        write_run(results, "new-travel-0", [row("travel", 2, False), row("travel", 3, True)], events=events)
        write_run(results, "new-banking-0", [row("banking", 0, True)], verified=False)
        write_run(results, "old-travel-0", [row("travel", 2, True), row("travel", 3, False)])

    def test_utility_counts_verified_batches_only(self):
        report = self.lab.report("new")
        self.assertEqual(report.utility().total(), (1, 2))
        self.assertIn("not counted (not verified): new-banking-0", str(report.utility()))

    def test_compare_task_by_task(self):
        comparison = self.lab.report("new").compare("old")
        self.assertEqual([k for k, *_ in comparison.gained], [("travel", "user_task_3", None)])
        self.assertEqual([k for k, *_ in comparison.lost], [("travel", "user_task_2", None)])

    def test_why_and_model_calls(self):
        episode = self.lab.report("new").episode("travel", "user_task_2")
        why = episode.why()
        self.assertIn("refused: edge_path (step 2, field x)", why)
        self.assertIn("answer: Breizh Cafe", why)
        calls = episode.model_calls()
        self.assertEqual([c["model"] for c in calls], ["drafting", "extractor (deepseek-flash)"])
        self.assertTrue(calls[0]["digest_ok"])
        self.assertEqual(calls[1]["shown"]["source_result"], "A, B")
        self.assertEqual(calls[1]["reply"], "{\"text\":\"B\"}")

    def test_the_cli_reads_the_same(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["--results", str(self.lab.results), "--workdir", str(self.lab.workdir),
                                   "report", "new", "--compare", "old"]), 0)
        self.assertIn("new vs old: +1 -1", out.getvalue())


class StageTests(unittest.TestCase):
    def test_a_stage_is_the_committed_tree_with_one_suites_catalog(self):
        from savana_lab.shell import Shell
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with __import__("zipfile").ZipFile(root / "w.whl", "w") as wheel:
                wheel.writestr("savana_core/__init__.py", "")
                wheel.writestr("savana_core-0.1.0.dist-info/METADATA", "")
            (root / "example").write_bytes(b"\x7fELF")
            rev = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True,
                                 check=True).stdout.strip()
            artifacts = Artifacts(rev, root / "b.tar", root / "w.whl", root / "example")
            tar, line = build_stage(Shell(), REPO, rev, "travel", artifacts, root / "work")
            stage = root / "work" / "stage-opt" / "savana-protected"
            catalogs = stage / "deploy/linux/integration"
            self.assertEqual((catalogs / "read-tool-catalog-v04.json").read_bytes(),
                             (catalogs / "read-tool-catalog-v04-travel.json").read_bytes())
            self.assertTrue((stage / "python/savana_core/__init__.py").exists())
            self.assertFalse(list((stage / "python").glob("*.dist-info")))
            self.assertEqual((stage / "bin/structured_plan_eval").stat().st_mode & 0o777, 0o755)
            self.assertFalse((stage / "experiments/results").exists())
            self.assertFalse(list(stage.rglob("__pycache__")))
            self.assertTrue(tar.is_file() and line.startswith(f"staged {rev[:7]} suite=travel"))
            (root / "variant.json").write_text("{}")
            tar, line = build_stage(Shell(), REPO, rev, "banking", artifacts, root / "work",
                                    catalog_variant=root / "variant.json")
            self.assertEqual((catalogs / "read-tool-catalog-v04.json").read_text(), "{}")
            self.assertIn("catalog-variant=", line)


class SameTree:
    """A Git that finds every revision's Rust sources equal and records what it runs."""

    def __init__(self, repo):
        self.repo, self.calls = Path(repo), []

    def __call__(self, *args, check=True):
        self.calls.append(args)
        return Result(0)

    def head(self):
        return "c" * 40

    def clean(self, paths):
        return True

    def same_tree(self, a, b, paths):
        return True


class ArtifactStoreTests(unittest.TestCase):
    def test_a_variant_is_used_only_when_named(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for name in ("b.tar", "w.whl", "example"):
                (root / name).write_bytes(name.encode())
            store = ArtifactStore(root / "store")
            files = dict(bin_tar=root / "b.tar", wheel=root / "w.whl", example=root / "example")
            plain = store.adopt(rev="a" * 40, note="plain", **files)
            nofloor = store.adopt(rev="a" * 40, note="counterfactual", variant="nofloor", **files)
            git = SameTree(root)
            self.assertEqual(store.for_stage(git, "b" * 40), plain)
            self.assertEqual(store.for_stage(git, "b" * 40, "nofloor"), nofloor)
            self.assertEqual(nofloor.bin_tar.parent.name, "a" * 40 + "-nofloor")
            with self.assertRaises(Exception):
                store.for_stage(git, "b" * 40, "other")

    def test_a_patched_build_undoes_its_patch_even_when_the_build_fails(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / "nofloor.patch").write_text("diff")
            git = SameTree(root)
            failing = Recorder([("build.py", lambda _: Result(1, "", "compile error"))])
            store = ArtifactStore(root / "store")
            with self.assertRaises(CommandFailed):
                store.build(failing, git, python="python3", patch=root / "nofloor.patch", variant="nofloor")
            applied = [c for c in git.calls if c[0] == "apply"]
            self.assertEqual([c[:2] for c in applied], [("apply", "--check"), ("apply", str(root / "nofloor.patch")),
                                                        ("apply", "-R")])
            with self.assertRaises(Exception):
                store.build(failing, git, python="python3", variant="nofloor")


    def test_adopted_artifacts_carry_their_digests(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for name in ("b.tar", "savana_core-0.1.0-cp312-abi3-x.whl", "example"):
                (root / name).write_bytes(name.encode())
            store = ArtifactStore(root / "store")
            artifacts = store.adopt(rev="a" * 40, bin_tar=root / "b.tar", wheel=root / "savana_core-0.1.0-cp312-abi3-x.whl",
                                    example=root / "example", note="test")
            receipt, stored = store.all()[0]
            self.assertEqual(stored, artifacts)
            self.assertEqual(receipt["sha256"]["linux-b-bin.tar"], hashlib.sha256(b"b.tar").hexdigest())
            self.assertEqual(artifacts.digests()["example"], hashlib.sha256(b"example").hexdigest())
            with self.assertRaises(Exception):
                store.adopt(rev="a" * 40, bin_tar=root / "b.tar", wheel=root / "savana_core-0.1.0-cp312-abi3-x.whl",
                            example=root / "example", note="again")


if __name__ == "__main__":
    unittest.main()
