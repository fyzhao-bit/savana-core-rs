use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use savana_client::managed_admin::{self, ManagedAdminReceipt, PreparedPrivateArtifact};
use zeroize::Zeroizing;

#[pyclass(name = "_PreparedPrivateArtifact", module = "savana_core")]
struct PreparedArtifact {
    inner: PreparedPrivateArtifact,
}
#[pymethods]
impl PreparedArtifact {
    fn canonical_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.canonical_bytes())
    }
    fn signing_digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.signing_digest())
    }
    fn __repr__(&self) -> &'static str {
        "PreparedPrivateArtifact(<private unsigned artifact>)"
    }
}
#[pyfunction]
fn _managed_admin_prepare_artifact(kind: &str, json: &[u8]) -> PyResult<PreparedArtifact> {
    managed_admin::prepare_artifact(kind, json)
        .map(|inner| PreparedArtifact { inner })
        .map_err(|_| PyValueError::new_err("invalid private artifact"))
}

#[pyclass(name = "_ManagedAdminReceipt", module = "savana_core")]
struct Receipt {
    inner: ManagedAdminReceipt,
}

#[pymethods]
impl Receipt {
    fn private_json(&self) -> PyResult<String> {
        self.inner
            .private_json()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    fn __repr__(&self) -> &'static str {
        "ManagedAdminReceipt(<private historical result>)"
    }
}

#[pyfunction]
fn _managed_admin_submit_signed(
    py: Python<'_>,
    command: &[u8],
    signature: &[u8],
) -> PyResult<Receipt> {
    if command.is_empty() || command.len() > 256 * 1024 {
        return Err(PyValueError::new_err("invalid signed command size"));
    }
    let command = Zeroizing::new(command.to_vec());
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| PyValueError::new_err("signature must contain exactly 64 bytes"))?;
    py.allow_threads(move || managed_admin::submit_signed(&command, &signature))
        .map(|inner| Receipt { inner })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PreparedArtifact>()?;
    m.add_function(wrap_pyfunction!(_managed_admin_prepare_artifact, m)?)?;
    m.add_class::<Receipt>()?;
    m.add_function(wrap_pyfunction!(_managed_admin_submit_signed, m)?)?;
    Ok(())
}
