use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
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

#[pymodule]
fn savana_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(detect_strict, m)?)?;
    Ok(())
}
