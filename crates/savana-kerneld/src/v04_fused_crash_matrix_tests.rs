// Crash matrix over the executor's durable effect pipeline. Each trial runs
// one real fused dispatch (G4/G5/G7, sealed envelope, execd journal) in a
// child process and kills that process with SIGKILL, either at one journal
// commit, inside the provider after it received the request, or at a random
// moment. The parent then reopens the journal from disk exactly as the daemon
// starts (startup recovery first), resends the kernel's original dispatch,
// restarts once more, and counts provider requests across all processes.
// The provider, worker and rollback anchors are test stand-ins (files on
// disk, not a TPM); the kernel side of each trial dies with the child.

#[cfg(feature = "test-support")]
fn crash_matrix_write(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write as _;
    let temp = path.with_extension("partial");
    let mut file = fs::File::create(&temp).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::rename(&temp, path).unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

#[cfg(feature = "test-support")]
fn crash_matrix_record_deployment(
    dir: &std::path::Path,
    installation: Digest32V2,
    manifest: Digest32V2,
    connectors: &[savana_policy_core::v2::ConnectorDescriptorV2],
) {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(installation.as_bytes())
        .unwrap()
        .bytes(manifest.as_bytes())
        .unwrap()
        .array(connectors.len() as u64)
        .unwrap();
    for connector in connectors {
        e.bytes(connector.canonical_bytes()).unwrap();
    }
    crash_matrix_write(&dir.join("deployment.cbor"), &e.into_writer());
}

#[cfg(all(feature = "test-support", unix))]
fn crash_matrix_read_deployment(
    dir: &std::path::Path,
) -> (
    Digest32V2,
    Digest32V2,
    Vec<savana_policy_core::v2::ConnectorDescriptorV2>,
) {
    let bytes = fs::read(dir.join("deployment.cbor")).unwrap();
    let mut d = minicbor::Decoder::new(&bytes);
    assert_eq!(d.array().unwrap(), Some(3));
    let installation = Digest32V2::new(d.bytes().unwrap().try_into().unwrap());
    let manifest = Digest32V2::new(d.bytes().unwrap().try_into().unwrap());
    let count = d.array().unwrap().unwrap();
    let connectors = (0..count)
        .map(|_| {
            savana_policy_core::v2::ConnectorDescriptorV2::from_canonical_bytes(
                d.bytes().unwrap(),
                &[],
            )
            .unwrap()
        })
        .collect();
    (installation, manifest, connectors)
}

/// The provider stand-in. Receiving the request is the external effect, so
/// it is recorded (fsync) before anything else; `kill_on_receipt` then kills
/// the process before the executor sees a response.
#[cfg(all(feature = "test-support", unix))]
fn crash_matrix_provider(
    log: std::path::PathBuf,
    kill_on_receipt: bool,
    latency: std::time::Duration,
) -> savana_execd::intent_bound_test_support::ProviderExchange {
    std::sync::Arc::new(
        move |request: &[u8], _maximum: u32, _deadline: std::time::Instant| {
            use std::io::Write as _;
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .map_err(|_| ())?;
            file.write_all(b"effect\n").map_err(|_| ())?;
            file.sync_all().map_err(|_| ())?;
            if kill_on_receipt {
                savana_execd::intent_bound_test_support::kill_self();
            }
            std::thread::sleep(latency);
            let value: serde_json::Value = serde_json::from_slice(request).map_err(|_| ())?;
            let response = if value.get("jsonrpc").is_some() {
                serde_json::json!({"jsonrpc": "2.0", "id": value["id"], "result": {
                    "isError": false, "content": [],
                    "structuredContent": {"savana_status": "succeeded"}}})
            } else {
                serde_json::json!({"request_id": value["request_id"], "status": "succeeded"})
            };
            serde_json::to_vec(&response).map_err(|_| ())
        },
    )
}

/// One trial's child process. Run only by `fused_crash_matrix_v04`.
#[test]
#[cfg(all(feature = "test-support", unix))]
#[ignore = "child process of fused_crash_matrix_v04"]
fn fused_crash_matrix_child_v04() {
    use savana_execd::intent_bound_test_support::JournalCrashV2;
    let dir = std::path::PathBuf::from(
        std::env::var_os("SAVANA_CRASH_MATRIX_DIR").expect("crash matrix directory"),
    );
    let point = std::env::var("SAVANA_CRASH_MATRIX_POINT").unwrap();
    let crash = match point.split_once(':') {
        Some(("before", n)) => Some(JournalCrashV2::BeforeAnchor(n.parse().unwrap())),
        Some(("after", n)) => Some(JournalCrashV2::AfterAnchor(n.parse().unwrap())),
        _ => None,
    };
    let latency = std::time::Duration::from_micros(
        std::env::var("SAVANA_CRASH_MATRIX_PROVIDER_LATENCY_US")
            .map_or(0, |value| value.parse().unwrap()),
    );
    let exchange = crash_matrix_provider(dir.join("effects.log"), point == "provider", latency);
    private_dispatch_fixture_with_provider(
        0,
        Some(exchange),
        None,
        Some(&DispatchHarness {
            crash_dir: Some(dir.clone()),
            crash,
            timings: None,
        }),
    );
    crash_matrix_write(&dir.join("completed"), b"");
}

#[cfg(all(feature = "test-support", unix))]
struct CrashMatrixTrial {
    point: String,
    exit: &'static str,
    found: Vec<String>,
    recovered: Vec<String>,
    replayed: Vec<String>,
    restarted: Vec<String>,
    effects: [usize; 4],
    bad: Vec<&'static str>,
}

#[cfg(all(feature = "test-support", unix))]
fn crash_matrix_trial(
    base: &std::path::Path,
    name: &str,
    point: &str,
    kill_after: Option<std::time::Duration>,
    latency_us: u64,
) -> CrashMatrixTrial {
    use savana_execd::intent_bound_test_support::{
        durable_journal_states, durable_service_with_provider,
    };
    use savana_execd::ExecdJournalStateV2 as S;
    use std::os::unix::process::ExitStatusExt as _;
    use std::time::{Duration, Instant};
    let dir = base.join(name);
    fs::create_dir_all(&dir).unwrap();
    // The child's kernel keeps its socket in TMPDIR; a Unix socket path must
    // stay under SUN_LEN, so TMPDIR is short and outside the trial directory.
    let scratch = tempfile::Builder::new()
        .prefix("scm")
        .tempdir_in("/tmp")
        .unwrap();
    let test = format!(
        "{}::fused_crash_matrix_child_v04",
        module_path!().split_once("::").unwrap().1
    );
    let log = fs::File::create(dir.join("child.log")).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            test.as_str(),
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SAVANA_CRASH_MATRIX_DIR", &dir)
        .env("SAVANA_CRASH_MATRIX_POINT", point)
        .env("SAVANA_CRASH_MATRIX_PROVIDER_LATENCY_US", latency_us.to_string())
        .env("TMPDIR", scratch.path())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    if let Some(delay) = kill_after {
        let marker = dir.join("dispatching");
        let waiting = Instant::now();
        while !marker.exists() && child.try_wait().unwrap().is_none() {
            assert!(waiting.elapsed() < Duration::from_secs(300), "child stalled");
            std::thread::sleep(Duration::from_micros(50));
        }
        std::thread::sleep(delay);
        let _ = child.kill(); // SIGKILL; no effect if the child already exited
    }
    let status = child.wait().unwrap();
    let exit = match (status.success(), status.signal()) {
        (true, _) => "completed",
        (false, Some(9)) => "killed",
        _ => panic!(
            "child {name} failed: {status:?}\n{}",
            fs::read_to_string(dir.join("child.log")).unwrap_or_default()
        ),
    };
    let effects = || {
        fs::read_to_string(dir.join("effects.log")).map_or(0, |text| text.lines().count())
    };
    let names = |states: Vec<(Nonce32V2, S)>| -> Vec<String> {
        states
            .into_iter()
            .map(|(_, state)| format!("{state:?}"))
            .collect()
    };
    let mut counts = [effects(), 0, 0, 0];
    let mut bad = Vec::new();
    let (installation, manifest, connectors) = crash_matrix_read_deployment(&dir);
    let root = dir.join("executor");
    let reopened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let states = || names(durable_journal_states(&root, installation, manifest, 7, 8));
        // Each start is the daemon's: startup recovery, then serve.
        let start = || {
            durable_service_with_provider(
                &root,
                installation,
                manifest,
                7,
                8,
                connectors.clone(),
                Some(crash_matrix_provider(
                    dir.join("effects.log"),
                    false,
                    Duration::ZERO,
                )),
                None,
                UnixMillisV2::new(205),
            )
            .0
        };
        let found = states();
        drop(start());
        let recovered = states();
        let after_recovery = effects();
        // The kernel never saw a reply, so it resends its original dispatch.
        let executor = start();
        let capture = dir.join("dispatch.cbor");
        if capture.exists() {
            let operation = savana_kernel_protocol::v2::decode_kernel_executor_operation_v2(
                &fs::read(&capture).unwrap(),
            )
            .unwrap();
            let _ = executor.execute(
                operation,
                UnixMillisV2::new(205),
                Instant::now() + Duration::from_secs(5),
            );
        }
        drop(executor);
        let replayed = states();
        let after_replay = effects();
        // One more restart must change nothing.
        drop(start());
        let restarted = states();
        (
            found,
            recovered,
            replayed,
            restarted,
            after_recovery,
            after_replay,
            effects(),
        )
    }));
    let (found, recovered, replayed, restarted) = match reopened {
        Ok((found, recovered, replayed, restarted, after_recovery, after_replay, last)) => {
            counts[1] = after_recovery - counts[0];
            counts[2] = after_replay - after_recovery;
            counts[3] = last - after_replay;
            (found, recovered, replayed, restarted)
        }
        Err(_) => {
            bad.push("unrecoverable");
            (vec![], vec![], vec![], vec![])
        }
    };
    let total: usize = counts.iter().sum();
    let last = restarted.last().map(String::as_str);
    if total > 1 {
        bad.push("duplicate_effect");
    }
    if restarted.len() > 1 || found.len() > 1 {
        bad.push("extra_entry");
    }
    if !found.is_empty() && counts[2] > 0 {
        bad.push("replay_reissued");
    }
    if counts[3] > 0 || restarted != replayed {
        bad.push("restart_not_idempotent");
    }
    if matches!(
        last,
        Some(
            "Prepared"
                | "ProviderAttemptPrepared"
                | "EffectStarted"
                | "ProviderResponseRetained"
                | "ReleaseEvidencePrepared"
        )
    ) {
        bad.push("stuck");
    }
    if total == 1 && last == Some("FailedNoEffect") {
        bad.push("effect_lost");
    }
    if total == 0 && matches!(last, Some("CompletionAvailable" | "Acknowledged")) {
        bad.push("phantom_completion");
    }
    if total == 1 && last.is_none() {
        bad.push("effect_unrecorded");
    }
    CrashMatrixTrial {
        point: point.to_owned(),
        exit,
        found,
        recovered,
        replayed,
        restarted,
        effects: counts,
        bad,
    }
}

/// splitmix64: reproducible kill times without a random-number dependency.
#[cfg(all(feature = "test-support", unix))]
fn crash_matrix_random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Crash matrix (explicit; spawns one child process per trial):
/// SAVANA_CRASH_MATRIX_TRIALS per journal boundary (default 3),
/// SAVANA_CRASH_MATRIX_RANDOM random-time kills (default 0),
/// SAVANA_CRASH_MATRIX_WORKDIR keeps trial directories,
/// SAVANA_CRASH_MATRIX_OUT receives one JSON line per trial.
#[test]
#[cfg(all(feature = "test-support", unix))]
#[ignore = "spawns child processes; run explicitly"]
fn fused_crash_matrix_v04() {
    use std::time::Duration;
    let number = |key: &str, default: u64| {
        std::env::var(key).map_or(default, |value| value.parse().unwrap())
    };
    let trials = number("SAVANA_CRASH_MATRIX_TRIALS", 3);
    let random = number("SAVANA_CRASH_MATRIX_RANDOM", 0);
    let latency_us = number("SAVANA_CRASH_MATRIX_PROVIDER_LATENCY_US", 0);
    let temporary = tempfile::tempdir().unwrap();
    let base = std::env::var_os("SAVANA_CRASH_MATRIX_WORKDIR")
        .map_or_else(|| temporary.path().to_path_buf(), std::path::PathBuf::from);
    fs::create_dir_all(&base).unwrap();
    let mut results = Vec::new();
    // One uninterrupted dispatch, then one kill after each journal commit
    // until a run completes: that fixes the number of commits.
    let clean = crash_matrix_trial(&base, "clean", "none", None, 0);
    assert_eq!(clean.exit, "completed");
    let window = {
        let read = |marker: &str| {
            fs::metadata(base.join("clean").join(marker))
                .unwrap()
                .modified()
                .unwrap()
        };
        read("dispatched").duration_since(read("dispatching")).unwrap()
    };
    results.push(clean);
    let mut commits = 0;
    loop {
        let probe = crash_matrix_trial(
            &base,
            &format!("after-{}-0", commits + 1),
            &format!("after:{}", commits + 1),
            None,
            0,
        );
        let completed = probe.exit == "completed";
        results.push(probe);
        if completed {
            break;
        }
        commits += 1;
        assert!(commits < 64, "journal commits do not terminate");
    }
    for n in 1..=commits {
        for trial in 0..trials {
            if trial > 0 {
                results.push(crash_matrix_trial(
                    &base,
                    &format!("after-{n}-{trial}"),
                    &format!("after:{n}"),
                    None,
                    0,
                ));
            }
            results.push(crash_matrix_trial(
                &base,
                &format!("before-{n}-{trial}"),
                &format!("before:{n}"),
                None,
                0,
            ));
        }
    }
    for trial in 0..trials {
        results.push(crash_matrix_trial(
            &base,
            &format!("provider-{trial}"),
            "provider",
            None,
            0,
        ));
    }
    let mut seed = 0x5341_5641_4e41_u64;
    let span = window.as_micros() as u64 * 3 / 2 + latency_us + 1;
    for trial in 0..random {
        let delay = Duration::from_micros(crash_matrix_random(&mut seed) % span);
        let mut outcome = crash_matrix_trial(
            &base,
            &format!("random-{trial}"),
            "random",
            Some(delay),
            latency_us,
        );
        outcome.point = format!("random:{}us", delay.as_micros());
        results.push(outcome);
    }
    let lines: Vec<String> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "point": r.point, "exit": r.exit, "found": r.found,
                "recovered": r.recovered, "replayed": r.replayed,
                "restarted": r.restarted,
                "effects": {"child": r.effects[0], "recovery": r.effects[1],
                            "replay": r.effects[2], "restart": r.effects[3]},
                "bad": r.bad,
            })
            .to_string()
        })
        .collect();
    if let Some(out) = std::env::var_os("SAVANA_CRASH_MATRIX_OUT") {
        fs::write(out, lines.join("\n") + "\n").unwrap();
    }
    println!(
        "crash matrix: {} trials, {commits} journal commits, dispatch window {:?}",
        results.len(),
        window
    );
    let bad: Vec<&String> = lines
        .iter()
        .zip(&results)
        .filter(|(_, r)| !r.bad.is_empty())
        .map(|(line, _)| line)
        .collect();
    assert!(bad.is_empty(), "bad trials: {bad:#?}");
}
