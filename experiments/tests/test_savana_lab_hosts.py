"""savana_lab hosts beyond this machine's Docker: a brand-new machine per batch
over SSH (create/destroy commands), or an EC2 instance per batch (aws CLI).

No network, cloud or machine here: a recording shell stands in for ssh,
the hooks and the aws CLI (`ssh-keygen` runs for real when it is present)."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from savana_lab import U9, make_plan
from savana_lab.__main__ import _hosts, main
from savana_lab.batch import ADMIN, Batch
from savana_lab.host import HostError
from savana_lab.remote import AwsHosts, DockerHosts, SshHosts, aws_leftovers, host_spec, make_host, spec_record
from savana_lab.shell import Result

from test_savana_lab import STATUS, FakeLab, Recorder, create, host_replies

HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE8h9Pq7QZIFUTWP2BZH/49cT1/jPl0p6N+FVNo57w5I root@vm"
KEY = "sk-test-0123456789"


def ssh_replies(created="root@203.0.113.7:2222\n" + HOST_KEY + "\n", runtime=(0,)):
    """`runtime`: what each check of the installed runtime answers, in turn (the last one after)."""
    checks = list(runtime)
    return [("bash -c ./new-vm", created), ("ssh-keygen -l", "256 SHA256:abc h (ED25519)\n"),
            ("for command in systemctl", lambda _: Result(checks.pop(0) if len(checks) > 1 else checks[0], "")),
            ("is-system-running", "running"), (f"{ADMIN} status", STATUS)]


class SpecTests(unittest.TestCase):
    def test_a_run_records_its_hosts_and_reads_them_back(self):
        self.assertEqual(host_spec(None), DockerHosts())
        for spec in (SshHosts(create="./new-vm", destroy="./drop-vm", identity="~/.ssh/k"),
                     AwsHosts(region="eu-central-1", security_group="sg-0123", subnet="subnet-1")):
            self.assertEqual(host_spec(json.loads(json.dumps(spec_record(spec)))), spec)

    def test_every_batch_must_get_a_new_machine_and_aws_needs_its_place(self):
        for bad in (SshHosts(create="./new-vm", destroy=""), dict(kind="ssh", create="x"),
                    AwsHosts(region="mars", security_group="sg-1"), AwsHosts(region="us-east-1", security_group="x"),
                    dict(kind="aws", region="us-east-1", security_group="sg-1", colour="red"), "docker"):
            with self.subTest(bad=bad), self.assertRaises((HostError, TypeError)):
                host_spec(bad)

    def test_the_command_line_says_which_option_is_missing(self):
        import argparse
        args = argparse.Namespace(host="ssh", ssh_create="./new-vm", ssh_destroy=None, ssh_user="root",
                                  ssh_identity=None)
        with self.assertRaisesRegex(Exception, "--ssh-destroy"):
            _hosts(args)
        aws = argparse.Namespace(host="aws", aws_region="us-east-1", aws_security_group="sg-1", aws_subnet=None,
                                 aws_instance_type="c7i.xlarge", aws_ami=None, aws_profile=None, aws_volume_gb=40,
                                 aws_private_ip=False)
        self.assertEqual(_hosts(aws), AwsHosts(region="us-east-1", security_group="sg-1"))


class SshHostTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def host(self, shell, user="root", identity=None):
        host = make_host(SshHosts(create="./new-vm", destroy="./drop-vm", user=user, identity=identity),
                         shell=shell, workdir=self.dir.name, label="u9c-banking-0", sleep=lambda _: None)
        host.prepare(Path(__file__).resolve().parents[2])
        return host

    def test_a_batch_on_a_new_machine_the_key_only_on_stdin(self):
        shell = Recorder(ssh_replies())
        host = self.host(shell)
        with mock.patch("shutil.which", return_value="/usr/bin/ssh"):
            Batch(host, key=KEY, sleep=lambda _: None).attempt("drafted:banking:user_task_0", "/w/stage.tar",
                                                               "/w/bin.tar")
        joined = [" ".join(c["argv"]) for c in shell.calls]
        self.assertEqual(joined[0], "bash -c ./new-vm")
        config = (host.dir / "ssh_config").read_text()
        for line in ("HostName 203.0.113.7", "Port 2222", "User root", "StrictHostKeyChecking yes"):
            self.assertIn(line, config)
        self.assertEqual((host.dir / "known_hosts").read_text(), "[203.0.113.7]:2222 " + HOST_KEY.rsplit(" ", 1)[0]
                         + "\n")
        # The runtime was already there: nothing installed. The payload goes gzip'd over ssh.
        self.assertFalse(any("apt-get install" in c for c in joined))
        self.assertTrue(any(c.startswith("gzip -c /w/stage.tar | ssh -F") and "/root/stage-opt.tar" in c
                            for c in joined))
        self.assertTrue(any("host=ssh-disposable-machine" in c for c in joined))
        carrying = [c for c in shell.calls if c["input"] is not None]
        self.assertEqual(len(carrying), 1)
        self.assertIn("configure-model --key-fd 3", " ".join(carrying[0]["argv"]))
        self.assertNotIn("-n", carrying[0]["argv"])
        for call in shell.calls:
            self.assertNotIn(KEY, " ".join(call["argv"]))
            self.assertNotIn(KEY, json.dumps(call["env"]))
        enroll = next(c for c in joined if "benchmark_identity enroll" in c)
        self.assertIn("env PLANNER_SPEC=drafted:banking:user_task_0 bash -c", enroll)
        released = host.release()
        self.assertEqual(released, dict(kind="ssh", address="root@203.0.113.7:2222", destroyed=True))
        self.assertEqual(shell.calls[-1]["env"], dict(SAVANA_LAB_HOST="root@203.0.113.7:2222"))
        self.assertIsNone(host.release())

    def test_another_user_runs_everything_through_sudo_and_a_new_machine_gets_the_runtime(self):
        shell = Recorder(ssh_replies(created="ubuntu@vm7.example\n", runtime=(1, 0)))
        host = self.host(shell, user="root", identity="~/.ssh/lab")
        with mock.patch("shutil.which", return_value="/usr/bin/ssh"):
            host.fresh("/w/stage.tar", "/w/bin.tar")
        config = (host.dir / "ssh_config").read_text()
        self.assertIn("StrictHostKeyChecking accept-new", config)   # no key given: trust on first use
        self.assertIn(f'IdentityFile "{Path("~/.ssh/lab").expanduser()}"', config)
        remote = [c["argv"][-1] for c in shell.calls if c["argv"][:1] == ["ssh"] and c["argv"][-1] != "true"]
        self.assertTrue(remote and all(r.startswith("sudo -n ") for r in remote), remote[:3])
        joined = [" ".join(c["argv"]) for c in shell.calls]
        self.assertTrue(any("requirements-agentdojo.txt" in c for c in joined))
        self.assertTrue(any("apt-get install" in c and "python3 -m venv /opt/savana-bench-venv" in c for c in joined))

    def test_no_address_no_machine(self):
        for printed in ("", "not an address!\n", "root@h:99999\n"):
            shell = Recorder([("bash -c ./new-vm", printed)])
            with self.subTest(printed=printed), self.assertRaises(HostError):
                self.host(shell).fresh("/w/s.tar", "/w/b.tar")

    def test_a_machine_that_never_answers_fails_its_attempt(self):
        shell = Recorder([("bash -c ./new-vm", "root@203.0.113.7\n"), ("-- true", lambda _: Result(255, "", "no"))])
        host = self.host(shell)
        host.ssh_wait = 10
        with self.assertRaisesRegex(Exception, "did not answer over SSH"):
            Batch(host, key=KEY, sleep=lambda _: None).attempt("drafted:banking:user_task_0", "/w/s", "/w/b")


def aws_replies(dir_holder, ip="198.51.100.4"):
    def keygen(joined):
        path = joined.rsplit(" -f ", 1)[1]
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True)
        return Result(0, "")
    return [("ssh-keygen -q", keygen), ("ssm get-parameter", "ami-0abc\n"),
            ("run-instances", json.dumps({"Instances": [{"InstanceId": "i-0123"}]})),
            ("describe-instances", json.dumps({"Reservations": [{"Instances": [{"PublicIpAddress": ip}]}]})),
            ("terminate-instances", "{}"), ("ssh-keygen -l", "256 SHA256:abc h (ED25519)\n"),
            ("for command in systemctl", ""), ("is-system-running", "running")]


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen (OpenSSH) is not installed")
class AwsHostTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def host(self, shell, **options):
        spec = AwsHosts(region="us-east-1", security_group="sg-0123", profile="lab", **options)
        return make_host(spec, shell=shell, workdir=self.dir.name, label="u9c-banking-0", sleep=lambda _: None)

    def test_an_instance_per_batch_pinned_from_its_first_byte_and_terminated_after(self):
        shell = Recorder(aws_replies(self))
        host = self.host(shell)
        host.repo = Path(__file__).resolve().parents[2]
        host.fresh("/w/stage.tar", "/w/bin.tar")
        joined = [" ".join(c["argv"]) for c in shell.calls]
        launch = next(c for c in joined if "run-instances" in c)
        for part in ("aws --profile lab --region us-east-1 ec2 run-instances --image-id ami-0abc",
                     "--instance-initiated-shutdown-behavior terminate", "HttpTokens=required",
                     "--security-group-ids sg-0123", "Key=savana-lab,Value=u9c-banking-0", "DeleteOnTermination=true",
                     "--associate-public-ip-address", f"--user-data file://{host.dir / 'user-data.yaml'}"):
            self.assertIn(part, launch)
        user_data = (host.dir / "user-data.yaml").read_text()
        host_public = (host.dir / "host_key.pub").read_text().strip()
        self.assertTrue(user_data.startswith("#cloud-config\n"))
        self.assertIn("ed25519_public: " + host_public, user_data)
        self.assertIn("  - " + (host.dir / "login_key.pub").read_text().strip(), user_data)
        self.assertIn("[shutdown, -P, '+240', savana-lab expiry]", user_data)
        self.assertFalse((host.dir / "host_key").exists())    # only the instance keeps its private host key
        self.assertEqual((host.dir / "known_hosts").read_text(), "198.51.100.4 " + host_public.rsplit(" ", 1)[0] + "\n")
        config = (host.dir / "ssh_config").read_text()
        for line in ("User ubuntu", "StrictHostKeyChecking yes", f'IdentityFile "{host.dir / "login_key"}"'):
            self.assertIn(line, config)
        self.assertTrue(any("host=aws-ec2-disposable-instance" in c for c in joined))
        self.assertEqual(host.describe()["instance"], "i-0123")
        self.assertEqual(host.release(), dict(kind="aws", instance="i-0123", terminated=True))
        self.assertIn("ec2 terminate-instances --instance-ids i-0123", " ".join(shell.calls[-1]["argv"]))

    def test_an_instance_that_cannot_be_reached_is_terminated_at_once(self):
        shell = Recorder(aws_replies(self, ip=None))
        host = self.host(shell, public_ip=True)
        host.repo = Path(".")
        with self.assertRaisesRegex(HostError, "no public IP"):
            host.fresh("/w/s.tar", "/w/b.tar")
        self.assertIn("terminate-instances --instance-ids i-0123", " ".join(shell.calls[-1]["argv"]))
        self.assertIsNone(host.release())

    def test_leftovers_are_found_and_terminated(self):
        found = {"Reservations": [{"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"},
                                                  "Tags": [{"Key": "savana-lab", "Value": "u9c-banking-0"}]}]}]}
        shell = Recorder([("describe-instances", json.dumps(found)), ("terminate-instances", "{}")])
        self.assertEqual(aws_leftovers(shell, region="us-east-1", terminate=True),
                         [("i-1", "running", "u9c-banking-0")])
        self.assertIn("Name=tag-key,Values=savana-lab", " ".join(shell.calls[0]["argv"]))
        self.assertIn("terminate-instances --instance-ids i-1", " ".join(shell.calls[1]["argv"]))


class FakeHost:
    """What the driver sees of a remote host: described, then released."""
    kind = "ssh"

    def __init__(self, record):
        self.record, self.shell = record, Recorder(host_replies(["9 finished"]))

    def prepare(self, repo):
        self.record.append("prepare")

    def exec(self, script, **options):
        return self.shell.run(["remote", "bash", "-c", script], **options)

    def describe(self):
        return dict(kind="ssh", address="root@203.0.113.7")

    def release(self):
        self.record.append("release")
        return dict(kind="ssh", address="root@203.0.113.7", destroyed=self.record.count("release") != 2)


class DriverHostTests(unittest.TestCase):
    def test_each_batch_is_recorded_with_its_host_which_is_released_after_it(self):
        from savana_lab import driver as driver_module
        from savana_lab.driver import drive
        from test_savana_lab import row, write_run
        with tempfile.TemporaryDirectory() as root:
            record = []
            lab = FakeLab(root)
            lab.host = lambda shell, spec=None, label="batch": FakeHost(record)
            run = create(lab, make_plan("h", U9, [("banking", "user_task_0"), ("slack", "user_task_0")]))
            meta = run.meta()
            meta["host"] = spec_record(SshHosts(create="./new-vm", destroy="./drop-vm"))
            (run.dir / "run.json").write_text(json.dumps(meta))

            def export(batch, run_id, out):
                write_run(out.parent, out.name, [row(out.name.split("-")[1], 0, True)], verified=False)
                return out / "r1"
            with mock.patch.object(driver_module, "build_stage", return_value=("/w/stage.tar", "staged")), \
                    mock.patch.object(Batch, "attempt", lambda *a: None), mock.patch.object(Batch, "export", export):
                self.assertEqual(drive(lab, run, keys={"deepseek": "sk-k"}, sleep=lambda _: None), "done")
            self.assertEqual(record, ["prepare", "release", "prepare", "release"])
            events = [e for e in run.progress() if e["event"] in ("host", "host_released")]
            self.assertEqual([e["event"] for e in events], ["host", "host_released"] * 2)
            self.assertEqual(json.loads((lab.results / "h-banking-0" / "host.json").read_text())["kind"], "ssh")
            # The second machine's destroy command failed: the status says so until someone looks.
            self.assertIn("host NOT released: h-slack-0", str(run.status()))

    def test_a_failed_attempt_still_releases_its_host(self):
        from savana_lab import driver as driver_module
        from savana_lab.batch import AttemptFailed
        from savana_lab.driver import drive
        with tempfile.TemporaryDirectory() as root:
            record = []
            lab = FakeLab(root)
            lab.host = lambda shell, spec=None, label="batch": FakeHost(record)
            run = create(lab, make_plan("f", U9, [("banking", "user_task_0")]))

            def attempt(*_):
                raise AttemptFailed("install: no")
            with mock.patch.object(driver_module, "build_stage", return_value=("/w/stage.tar", "staged")), \
                    mock.patch.object(Batch, "attempt", attempt):
                self.assertEqual(drive(lab, run, keys={"deepseek": "sk-k"}, sleep=lambda _: None), "failed")
            self.assertEqual(record, ["prepare", "release"])


class CliTests(unittest.TestCase):
    def test_leftovers_need_a_region(self):
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            main(["aws-leftovers"])


if __name__ == "__main__":
    unittest.main()
