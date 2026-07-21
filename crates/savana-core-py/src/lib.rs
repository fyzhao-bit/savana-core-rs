use libsavana_ner::capabilities::{self, Capability, Readers, Source};
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

#[pymodule]
fn savana_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(detect_strict, m)?)?;
    m.add_function(wrap_pyfunction!(capabilities_combine, m)?)?;
    m.add_function(wrap_pyfunction!(capability_is_public, m)?)?;
    m.add_function(wrap_pyfunction!(capability_is_trusted, m)?)?;
    Ok(())
}
