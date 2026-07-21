use libsavana_ner::attempt_classifier::{self, AttemptPolicyProfile};
use libsavana_ner::body_pipeline;
use libsavana_ner::capabilities::{self, Capability, Readers, Source};
use libsavana_ner::dataflow_policy::{self, ArgTaint, DataflowPolicyProfile};
use libsavana_ner::ontology::{self, Store as OntologyStoreData, Value as OntologyValue};
use libsavana_ner::pdp_tool::{self, ToolSpecLite};
use libsavana_ner::sink_policy::{self, BridgedVerdict, SecurityVerdict, SinkPolicyProfile};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::BTreeSet;
use std::path::Path;

/// Report the crate version. Retained as a trivial import-sanity probe.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Fail-closed NER over `text` using the ONNX assets at `assets`.
///
/// Loads a fresh [`libsavana_ner::NerGate`] per call (a cached handle is a
/// later optimization), then runs [`NerGate::detect_strict`]. A load failure
/// or a detect error surfaces to Python as a `RuntimeError` carrying the
/// error's stable code (`"ner_unavailable"` / `"ner_failed"`), matching the
/// Python gate. On success, returns one dict per span:
/// `{"type", "text", "start", "end"}`.
#[pyfunction]
fn detect_strict(py: Python<'_>, text: &str, assets: &str) -> PyResult<Vec<Py<PyDict>>> {
    let mut gate = libsavana_ner::NerGate::load(Path::new(assets))
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    match gate.detect_strict(text) {
        Ok(spans) => spans
            .into_iter()
            .map(|s| {
                let d = PyDict::new_bound(py);
                d.set_item("type", s.entity_type)?;
                d.set_item("text", s.text)?;
                d.set_item("start", s.start)?;
                d.set_item("end", s.end)?;
                Ok(d.unbind())
            })
            .collect(),
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

/// G2 data-plane leak gate — PyO3 surface over
/// [`libsavana_ner::body_pipeline::leak_gate`] (the byte-exact port of the
/// fail-closed residue detector in `server/security/body_pipeline.py`, §7).
///
/// This is the deterministic, model-free G2 privacy boundary in the
/// summarize-send chain: `body` is the masked body text (Python passes `str`,
/// or `None` when the masker returned nothing — `None` → `False`, matching the
/// Python `if body is None: return False`), and `vault` is the on-host
/// placeholder→real map as `(key, value)` pairs (Python's `dict.items()`). Only
/// the values are inspected (code-point len ≥ 4, deduped). Returns `True` iff
/// the body is safe to egress: no structured-PII residue AND no surviving raw
/// vault value at a non-word / non-`<>` boundary. Any doubt (incl. a regex
/// engine error) fails closed to `False`.
#[pyfunction]
#[pyo3(signature = (body, vault))]
fn leak_gate(body: Option<&str>, vault: Vec<(String, String)>) -> bool {
    body_pipeline::leak_gate(body, &vault)
}

/// Parse Python source-name strings into [`Source`]s, mirroring the
/// `ValueError` a bogus value would raise against the Python `Source(str,
/// Enum)` constructor.
fn parse_sources(sources: Vec<String>) -> PyResult<BTreeSet<Source>> {
    sources
        .into_iter()
        .map(|s| {
            Source::from_wire(&s)
                .ok_or_else(|| PyValueError::new_err(format!("invalid source: {s}")))
        })
        .collect()
}

fn sources_to_strings(sources: &BTreeSet<Source>) -> Vec<String> {
    sources.iter().map(|s| s.as_str().to_string()).collect()
}

/// CaMeL capability algebra — PyO3 surface over [`libsavana_ner::capabilities`]
/// (the Rust port of `server/security/capabilities.py`'s pure taint core).
///
/// Merge N capabilities: `combine_caps` (union of sources, intersection of
/// readers — `None` == public). Each input capability is
/// `(sources: list[str], readers: Optional[list[str]])`; the result has the
/// same shape.
#[pyfunction]
fn capabilities_combine(
    caps: Vec<(Vec<String>, Option<Vec<String>>)>,
) -> PyResult<(Vec<String>, Option<Vec<String>>)> {
    let rust_caps: Vec<Capability> = caps
        .into_iter()
        .map(|(sources, readers)| -> PyResult<Capability> {
            let sources = parse_sources(sources)?;
            let readers: Readers = readers.map(|v| v.into_iter().collect());
            Ok(Capability::new(sources, readers))
        })
        .collect::<PyResult<_>>()?;
    let combined = capabilities::combine_caps(&rust_caps);
    let readers_out = combined.readers.map(|r| r.into_iter().collect());
    Ok((sources_to_strings(&combined.sources), readers_out))
}

/// `Capability.is_public` — true iff `readers is None`.
#[pyfunction]
#[pyo3(signature = (readers=None))]
fn capability_is_public(readers: Option<Vec<String>>) -> bool {
    let readers: Readers = readers.map(|v| v.into_iter().collect());
    let cap = Capability::new(BTreeSet::new(), readers);
    capabilities::is_public(&cap)
}

/// `Capability.is_trusted` — true iff every source is in `TRUSTED_SOURCES`.
#[pyfunction]
fn capability_is_trusted(sources: Vec<String>) -> PyResult<bool> {
    let sources = parse_sources(sources)?;
    let cap = Capability::new(sources, None);
    Ok(capabilities::is_trusted(&cap))
}

/// G3 data-flow policy — PyO3 surface over [`libsavana_ner::dataflow_policy`]
/// (the Rust port of `server/security/dataflow_policy.py`'s `check_policy`).
///
/// `args` is `[(name, is_trusted, is_public), ...]` in the SAME order as the
/// original `kwargs` dict (order flows into the denial message) — the
/// caller reduces each `CaMeLValue` to the two booleans `check_policy`
/// actually reads. The three tool sets are the already-resolved
/// `DataflowPolicyProfile` (explicit, or `rules.yaml`/code defaults —
/// resolved on the Python side). Returns `(verdict, reason)` where
/// `verdict` is one of `"allow"`/`"deny"`/`"consent"`.
#[pyfunction]
fn dataflow_check_policy(
    tool_name: &str,
    args: Vec<(String, bool, bool)>,
    no_side_effect_tools: Vec<String>,
    consent_overridable_tools: Vec<String>,
    high_risk_tools: Vec<String>,
) -> (String, String) {
    let profile = DataflowPolicyProfile {
        no_side_effect_tools: no_side_effect_tools.into_iter().collect(),
        consent_overridable_tools: consent_overridable_tools.into_iter().collect(),
        high_risk_tools: high_risk_tools.into_iter().collect(),
    };
    let args: Vec<ArgTaint> = args
        .into_iter()
        .map(|(name, is_trusted, is_public)| ArgTaint {
            name,
            is_trusted,
            is_public,
        })
        .collect();
    let result = dataflow_policy::check_policy(tool_name, &args, &profile);
    (result.verdict.as_str().to_string(), result.reason)
}

/// G4 attempt-type classification + per-run limits — PyO3 surface over
/// [`libsavana_ner::attempt_classifier`] (the Rust port of
/// `server/policy/attempt_classifier.py`'s `validate`).
///
/// `valid_pairs`/`limits`/`cloud_blocked` are the already-resolved
/// `AttemptPolicyProfile` (explicit, or `rules.yaml`/code defaults —
/// resolved on the Python side). Returns `(allowed, reason)`; `reason` is
/// `""` iff `allowed`.
#[pyfunction]
fn attempt_validate(
    tool_name: &str,
    attempt_type: &str,
    attempt_counts: Vec<(String, i64)>,
    provider: &str,
    valid_pairs: Vec<(String, String)>,
    limits: Vec<(String, i64)>,
    cloud_blocked: Vec<String>,
) -> (bool, String) {
    let profile = AttemptPolicyProfile {
        valid_pairs: valid_pairs.into_iter().collect(),
        limits: limits.into_iter().collect(),
        cloud_blocked: cloud_blocked.into_iter().collect(),
    };
    let attempt_counts = attempt_counts.into_iter().collect();
    attempt_classifier::validate(tool_name, attempt_type, &attempt_counts, provider, &profile)
}

/// `get_consent_required` — a hardcoded set, no profile needed.
#[pyfunction]
fn attempt_consent_required(attempt_type: &str) -> bool {
    attempt_classifier::consent_required(attempt_type)
}

/// G2/G4 ontology constraint engine — PyO3 surface over
/// [`libsavana_ner::ontology`] (the Rust port of
/// `server/security/ontology.py`'s `evaluate_constraints`/`_eval_one`/
/// `OntologyStore.resolve`).
///
/// `args` is the tool call's (rehydrated) argument map as `[(name, value),
/// ...]`. The ontology store's already-resolved contents are split into two
/// flat lists — `store_scalars: [(ns, key, field, value), ...]` and
/// `store_collections: [(ns, key, field, values), ...]` — mirroring the two
/// value shapes real callers store (a plain string field like
/// `status="active"`, or a collection field like
/// `contacts={"a@x.com", "b@x.com"}`). Returns `(ok, reason)`; `reason` is
/// `""` iff `ok`.
#[pyfunction]
fn ontology_evaluate_constraints(
    constraints: Vec<String>,
    args: Vec<(String, String)>,
    store_scalars: Vec<(String, String, String, String)>,
    store_collections: Vec<(String, String, String, Vec<String>)>,
) -> (bool, String) {
    let args = args.into_iter().collect();
    let mut store: OntologyStoreData = OntologyStoreData::new();
    for (ns, key, field, value) in store_scalars {
        store
            .entry(ns)
            .or_default()
            .entry(key)
            .or_default()
            .insert(field, OntologyValue::Str(value));
    }
    for (ns, key, field, values) in store_collections {
        store
            .entry(ns)
            .or_default()
            .entry(key)
            .or_default()
            .insert(field, OntologyValue::Collection(values));
    }
    ontology::evaluate_constraints(&constraints, &args, &store)
}

/// `(verdict, reason, resolved_attempt, trace)` — the return shape of
/// [`sink_unified_check`]; `trace` is the ordered `[(gate, outcome), ...]`
/// decision path. Aliased to keep the signature under clippy's
/// `type_complexity` bar.
type SinkVerdictOut = (String, String, String, Vec<(String, String)>);

/// Unified PDP sink verdict — PyO3 surface over
/// [`libsavana_ner::sink_policy`] (the Rust port of the pure verdict
/// adjudication of `server/security/sink_policy.py`'s `unified_sink_check`,
/// composing the already-ported G3 `check_policy` and G4 `validate`).
///
/// All profile fields are the already-resolved `SinkPolicyProfile` (dataflow +
/// attempts sub-profiles), passed as flat lists exactly like
/// `dataflow_check_policy`/`attempt_validate`:
///   - `args`: `[(name, is_trusted, is_public), ...]` in ORIGINAL kwargs order,
///   - dataflow sets: `no_side_effect_tools`/`consent_overridable_tools`/
///     `high_risk_tools`,
///   - attempts profile: `valid_pairs`/`limits`/`cloud_blocked`,
///   - `g5_results`: the Python-side shell/vision/cloud validator outputs,
///     already bridged to `(verdict, reason_value)` and in evaluation order
///     (empty for the DOCUMENT pack). `verdict` must be one of
///     `"allowed"`/`"rejected"`/`"blocked"` (else `ValueError`).
///
/// `attempt` is the DECLARED attempt (resolving an omitted attempt via
/// `infer_attempt` stays Python — see the module docs). Returns
/// `(verdict, reason, resolved_attempt, trace)` where `verdict`/`reason` are
/// the `SecurityVerdict.value`/`RejectReason.value` wire strings and `trace`
/// is the ordered `[(gate, outcome), ...]` decision path.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn sink_unified_check(
    tool_name: &str,
    attempt: &str,
    args: Vec<(String, bool, bool)>,
    attempt_counts: Vec<(String, i64)>,
    provider: &str,
    no_side_effect_tools: Vec<String>,
    consent_overridable_tools: Vec<String>,
    high_risk_tools: Vec<String>,
    valid_pairs: Vec<(String, String)>,
    limits: Vec<(String, i64)>,
    cloud_blocked: Vec<String>,
    g5_results: Vec<(String, String)>,
) -> PyResult<SinkVerdictOut> {
    let profile = SinkPolicyProfile {
        dataflow: DataflowPolicyProfile {
            no_side_effect_tools: no_side_effect_tools.into_iter().collect(),
            consent_overridable_tools: consent_overridable_tools.into_iter().collect(),
            high_risk_tools: high_risk_tools.into_iter().collect(),
        },
        attempts: AttemptPolicyProfile {
            valid_pairs: valid_pairs.into_iter().collect(),
            limits: limits.into_iter().collect(),
            cloud_blocked: cloud_blocked.into_iter().collect(),
        },
    };
    let args: Vec<ArgTaint> = args
        .into_iter()
        .map(|(name, is_trusted, is_public)| ArgTaint {
            name,
            is_trusted,
            is_public,
        })
        .collect();
    let attempt_counts = attempt_counts.into_iter().collect();
    let g5_results: Vec<BridgedVerdict> = g5_results
        .into_iter()
        .map(|(verdict, reason)| -> PyResult<BridgedVerdict> {
            let verdict = SecurityVerdict::from_wire(&verdict)
                .ok_or_else(|| PyValueError::new_err(format!("invalid verdict: {verdict}")))?;
            Ok(BridgedVerdict { verdict, reason })
        })
        .collect::<PyResult<_>>()?;

    let out = sink_policy::unified_sink_check(
        tool_name,
        attempt,
        &args,
        &attempt_counts,
        provider,
        &profile,
        &g5_results,
    );
    Ok((
        out.verdict.as_str().to_string(),
        out.reason,
        out.attempt,
        out.trace,
    ))
}

/// One injected active-set entry — the four `ToolSpec` fields the G4 triple
/// reads: `(name, attempt, constraints, limits_items)`. Aliased to keep
/// [`pdp_adjudicate_tool_call`]'s signature under clippy's `type_complexity`
/// bar.
type ActiveToolEntry = (String, String, Vec<String>, Vec<(String, i64)>);

/// PDP control-plane tool-call adjudication — PyO3 surface over
/// [`libsavana_ner::pdp_tool`] (the Rust port of `server/security/pdp_tool.py`'s
/// `adjudicate_tool_call`, the G4 whitelist/ontology/limit triple), reusing the
/// already-ported ontology engine for step ②.
///
/// The caller resolves the active tool set (packs + MCP discovery, role-scoped)
/// and passes it as `active` = `[(name, attempt, constraints, limits), ...]`.
/// The ontology store is the same two-list shape as
/// `ontology_evaluate_constraints`, gated by `ontology_available`
/// (`False` ⇒ Python's `ontology is None` — the fail-closed
/// "constraints required but ontology unavailable" branch). `real_args` is the
/// rehydrated `name -> str(value)` argument map. Returns
/// `(allowed, reason, attempt)`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn pdp_adjudicate_tool_call(
    tool_name: &str,
    real_args: Vec<(String, String)>,
    role: &str,
    active: Vec<ActiveToolEntry>,
    ontology_available: bool,
    store_scalars: Vec<(String, String, String, String)>,
    store_collections: Vec<(String, String, String, Vec<String>)>,
    attempt_counts: Vec<(String, i64)>,
) -> (bool, String, String) {
    let active: Vec<ToolSpecLite> = active
        .into_iter()
        .map(|(name, attempt, constraints, limits)| ToolSpecLite {
            name,
            attempt,
            constraints,
            limits: limits.into_iter().collect(),
        })
        .collect();
    let real_args = real_args.into_iter().collect();
    let attempt_counts = attempt_counts.into_iter().collect();
    let store = if ontology_available {
        let mut store: OntologyStoreData = OntologyStoreData::new();
        for (ns, key, field, value) in store_scalars {
            store
                .entry(ns)
                .or_default()
                .entry(key)
                .or_default()
                .insert(field, OntologyValue::Str(value));
        }
        for (ns, key, field, values) in store_collections {
            store
                .entry(ns)
                .or_default()
                .entry(key)
                .or_default()
                .insert(field, OntologyValue::Collection(values));
        }
        Some(store)
    } else {
        None
    };
    let v = pdp_tool::adjudicate_tool_call(
        tool_name,
        &real_args,
        role,
        &active,
        store.as_ref(),
        &attempt_counts,
    );
    (v.allowed, v.reason, v.attempt)
}

#[pymodule]
fn savana_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(detect_strict, m)?)?;
    m.add_function(wrap_pyfunction!(leak_gate, m)?)?;
    m.add_function(wrap_pyfunction!(capabilities_combine, m)?)?;
    m.add_function(wrap_pyfunction!(capability_is_public, m)?)?;
    m.add_function(wrap_pyfunction!(capability_is_trusted, m)?)?;
    m.add_function(wrap_pyfunction!(dataflow_check_policy, m)?)?;
    m.add_function(wrap_pyfunction!(attempt_validate, m)?)?;
    m.add_function(wrap_pyfunction!(attempt_consent_required, m)?)?;
    m.add_function(wrap_pyfunction!(ontology_evaluate_constraints, m)?)?;
    m.add_function(wrap_pyfunction!(sink_unified_check, m)?)?;
    m.add_function(wrap_pyfunction!(pdp_adjudicate_tool_call, m)?)?;
    Ok(())
}
