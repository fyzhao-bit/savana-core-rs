// Mediation latency of one owner-signed tool call: G4 prepare, G5 evaluate,
// G6/G7 dispatch (which includes the executor's journal, worker check and
// Suite-1 IPC) and completion reconciliation (fetch, result commit and
// acknowledgement). Every durable commit is encrypted and fsynced in $TMPDIR.
// The provider stand-in answers at once and no model is called, so each total
// is Savana's own cost per call. Each sample builds a fresh fixture (budgets
// are single-use); only these four kernel calls are timed.

/// Explicit benchmark: SAVANA_LATENCY_SAMPLES (default 20) after 3 warm-up
/// runs; SAVANA_LATENCY_OUT receives the raw samples as JSON.
#[test]
#[cfg(all(feature = "test-support", unix))]
#[ignore = "benchmark; run explicitly, ideally with --profile integration"]
fn fused_mediation_latency_v04() {
    use std::collections::BTreeMap;
    use std::time::Duration;
    let samples: usize = std::env::var("SAVANA_LATENCY_SAMPLES").map_or(20, |v| v.parse().unwrap());
    let warmup = 3;
    let mut stages: BTreeMap<&'static str, Vec<Duration>> = BTreeMap::new();
    for run in 0..warmup + samples {
        let timings = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        private_dispatch_fixture_with_provider(
            0,
            None,
            None,
            Some(&DispatchHarness {
                timings: Some(timings.clone()),
                ..Default::default()
            }),
        );
        if run < warmup {
            continue;
        }
        let timings = timings.lock().unwrap();
        let mut per_call = Duration::ZERO;
        for (stage, elapsed) in timings.iter() {
            stages.entry(stage).or_default().push(*elapsed);
            if stage.starts_with("kernel.") {
                per_call += *elapsed;
            }
        }
        stages.entry("total.per_call").or_default().push(per_call);
    }
    let quantile = |sorted: &[Duration], q: f64| {
        let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
        sorted[rank - 1]
    };
    let mut summary = serde_json::Map::new();
    for (stage, values) in &mut stages {
        values.sort();
        let ms = |d: Duration| d.as_secs_f64() * 1e3;
        let mean = values.iter().map(|d| ms(*d)).sum::<f64>() / values.len() as f64;
        println!(
            "{stage:<28} n={:<4} p50={:>8.3}ms p90={:>8.3}ms p99={:>8.3}ms max={:>8.3}ms mean={:>8.3}ms",
            values.len(),
            ms(quantile(values, 0.50)),
            ms(quantile(values, 0.90)),
            ms(quantile(values, 0.99)),
            ms(*values.last().unwrap()),
            mean
        );
        summary.insert(
            (*stage).to_owned(),
            serde_json::json!({
                "n": values.len(),
                "p50_ms": ms(quantile(values, 0.50)),
                "p90_ms": ms(quantile(values, 0.90)),
                "p99_ms": ms(quantile(values, 0.99)),
                "max_ms": ms(*values.last().unwrap()),
                "mean_ms": mean,
                "samples_ms": values.iter().map(|d| ms(*d)).collect::<Vec<_>>(),
            }),
        );
    }
    if let Some(out) = std::env::var_os("SAVANA_LATENCY_OUT") {
        fs::write(out, serde_json::Value::Object(summary).to_string()).unwrap();
    }
}
