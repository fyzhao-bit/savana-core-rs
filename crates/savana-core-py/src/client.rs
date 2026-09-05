use std::fs::File;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use std::{collections::HashMap, thread::ThreadId};

#[cfg(debug_assertions)]
use std::collections::VecDeque;
#[cfg(debug_assertions)]
use std::fs;
#[cfg(all(debug_assertions, unix))]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
#[cfg(debug_assertions)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(debug_assertions)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyTuple};
use savana_client::{
    AgentEvent as ClientAgentEvent, ApprovalCallback, ApprovalPurpose,
    ApprovalRequest as ClientApprovalRequest, AuthError as ClientAuthError, Client as RustClient,
    ClientEndpoints, ConnectorDescriptor as ClientConnectorDescriptor,
    ContentKind as ClientContentKind, EventCallback, ExecutionResult as ClientExecutionResult,
    ExecutionStatus, Handle as ClientHandle, Identity as ClientIdentity,
    IntentPrivacy as ClientIntentPrivacy, MaskedView as ClientMaskedView, Plan as ClientPlan,
    RunLimits as ClientRunLimits, SavanaError as ClientError, Session as ClientSession,
    SessionBootstrap, WebAuthnAssertion, WebAuthnAttestation, WebAuthnProvider,
};
#[cfg(debug_assertions)]
use savana_client::{
    BrowserContentType, BrowserRequest, BrowserResponse, BrowserTransport, NonceSource,
};
#[cfg(debug_assertions)]
use savana_kernel_protocol::v2::{
    encode_agent_browser_mutation_response_v2, encode_agent_browser_read_view_response_v2,
    encode_ui_authentication_browser_begin_response_v2,
    encode_ui_authentication_browser_finish_response_v2, render_agent_workspace_v2,
    AgentBrowserMutationResponseV2, AgentBrowserReadViewResponseV2,
    AgentBrowserViewCursorCapabilityV2, AgentMaskedDocumentRefV2, AgentSessionStatusV2,
    AgentTabSessionCapabilityV2, AgentUiAuthenticationBrowserCeremonyCapabilityV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiPreAuthenticationTabCapabilityV2,
    AgentViewFieldV2, AgentViewV2, ArgumentNameV2, BoundedAgentTextV2, ClosedRedactionClassV2,
    FixedOriginV2, Nonce32V2, PlaceholderViewV2, StaticTemplateIdV2,
    UiAuthenticationBrowserBeginResponseV2, UiAuthenticationBrowserFinishResponseV2,
};
#[cfg(debug_assertions)]
use zeroize::Zeroizing;

create_exception!(savana_core, SavanaError, PyException);
create_exception!(savana_core, AuthError, SavanaError);
create_exception!(savana_core, ApprovalDenied, SavanaError);
create_exception!(savana_core, PolicyRefused, SavanaError);

const AGENT_ENDPOINT: &str = "http://localhost:8768";
const INGRESS_ENDPOINT: &str = "http://localhost:8767";
const APPROVAL_ENDPOINT: &str = "http://localhost:8766";
const MAX_CONNECTOR_DESCRIPTOR_BYTES: u64 = 8 * 1024 * 1024;

fn map_auth_error(error: ClientAuthError) -> PyErr {
    let code = error.code();
    with_error_code(
        PyErr::new::<AuthError, _>(format!("{code}: authentication or enrollment failed")),
        code,
    )
}

fn map_client_error(error: ClientError) -> PyErr {
    match error {
        ClientError::Auth(error) => map_auth_error(error),
        ClientError::ApprovalDenied(error) => with_error_code(
            PyErr::new::<ApprovalDenied, _>(format!("{}: approval denied", error.code())),
            error.code(),
        ),
        ClientError::PolicyRefused(error) => {
            let code = error.code();
            let public_code = error.public_code().to_owned();
            let reason = error.reason().to_owned();
            let step = error.step().map(|step| PyPlanStep {
                handle: PyHandle::live(step.handle().clone()),
            });
            let exception = with_error_code(
                PyErr::new::<PolicyRefused, _>(format!("{code}: {public_code}: {reason}")),
                code,
            );
            Python::with_gil(|py| {
                let value = exception.value_bound(py);
                let _ = value.setattr("public_code", public_code);
                let _ = value.setattr("reason", reason);
                if let Some(step) = step.and_then(|step| Py::new(py, step).ok()) {
                    let _ = value.setattr("step", step);
                } else {
                    let _ = value.setattr("step", py.None());
                }
            });
            exception
        }
        other => {
            let code = other.code();
            with_error_code(
                PyErr::new::<SavanaError, _>(format!("{code}: client operation failed")),
                code,
            )
        }
    }
}

fn with_error_code(error: PyErr, code: &str) -> PyErr {
    Python::with_gil(|py| {
        let _ = error.value_bound(py).setattr("code", code);
    });
    error
}

fn parse_content_kind(value: &str) -> PyResult<ClientContentKind> {
    match value {
        "chat_text" => Ok(ClientContentKind::ChatText),
        "plain_text" => Ok(ClientContentKind::PlainText),
        "parsed_document" => Ok(ClientContentKind::ParsedDocument),
        _ => Err(PyValueError::new_err("invalid content kind")),
    }
}

fn parse_intent_privacy(value: &str) -> PyResult<ClientIntentPrivacy> {
    match value {
        "private" => Ok(ClientIntentPrivacy::Private),
        "third_party" => Ok(ClientIntentPrivacy::ThirdParty),
        _ => Err(PyValueError::new_err("invalid intent privacy")),
    }
}

fn purpose_name(purpose: ApprovalPurpose) -> &'static str {
    match purpose {
        ApprovalPurpose::Ingress => "ingress",
        ApprovalPurpose::ToolExecution => "tool_execution",
        ApprovalPurpose::FinalRelease => "final_release",
        ApprovalPurpose::ConnectorRegistration => "connector_registration",
        ApprovalPurpose::TaskAuthorization => "task_authorization",
    }
}

fn status_name(status: ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Succeeded => "succeeded",
        ExecutionStatus::EffectSucceededOutputQuarantined => "effect_succeeded_output_quarantined",
        ExecutionStatus::FailedNoEffect => "failed_no_effect",
    }
}

fn snake_debug(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 4);
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() && index != 0 {
            output.push('_');
        }
        output.push(character.to_ascii_lowercase());
    }
    output
}

#[derive(Default)]
struct CallbackErrors(Mutex<HashMap<ThreadId, PyErr>>);

impl CallbackErrors {
    fn record(&self, error: PyErr) {
        if let Ok(mut pending) = self.0.lock() {
            pending.entry(std::thread::current().id()).or_insert(error);
        }
    }

    fn take(&self) -> Option<PyErr> {
        self.0
            .lock()
            .ok()
            .and_then(|mut pending| pending.remove(&std::thread::current().id()))
    }
}

struct PythonWebAuthn {
    provider: Py<PyAny>,
    errors: Arc<CallbackErrors>,
}

impl PythonWebAuthn {
    fn required_bytes(value: &Bound<'_, PyAny>, key: &str) -> PyResult<Vec<u8>> {
        let mapping = value.downcast::<PyDict>()?;
        mapping
            .get_item(key)?
            .ok_or_else(|| PyTypeError::new_err(format!("missing WebAuthn field: {key}")))?
            .extract::<Vec<u8>>()
    }

    fn assertion(&self, options_json: &[u8]) -> PyResult<WebAuthnAssertion> {
        Python::with_gil(|py| {
            let result = self
                .provider
                .bind(py)
                .call_method1("assert_credential", (PyBytes::new_bound(py, options_json),))?;
            WebAuthnAssertion::new(
                Self::required_bytes(&result, "credential_id")?,
                Self::required_bytes(&result, "authenticator_data")?,
                Self::required_bytes(&result, "client_data_json")?,
                Self::required_bytes(&result, "signature")?,
                Self::required_bytes(&result, "user_handle")?,
            )
            .map_err(map_auth_error)
        })
    }

    fn attestation(&self, options_json: &[u8]) -> PyResult<WebAuthnAttestation> {
        Python::with_gil(|py| {
            let result = self
                .provider
                .bind(py)
                .call_method1("create_credential", (PyBytes::new_bound(py, options_json),))?;
            WebAuthnAttestation::new(
                Self::required_bytes(&result, "credential_id")?,
                Self::required_bytes(&result, "client_data_json")?,
                Self::required_bytes(&result, "attestation_object")?,
            )
            .map_err(map_auth_error)
        })
    }
}

impl WebAuthnProvider for PythonWebAuthn {
    fn assert_credential(&self, options_json: &[u8]) -> Result<WebAuthnAssertion, ClientAuthError> {
        self.assertion(options_json).map_err(|error| {
            self.errors.record(error);
            ClientAuthError::AuthenticationFailed
        })
    }

    fn create_credential(
        &self,
        options_json: &[u8],
    ) -> Result<WebAuthnAttestation, ClientAuthError> {
        self.attestation(options_json).map_err(|error| {
            self.errors.record(error);
            ClientAuthError::EnrollmentFailed
        })
    }
}

struct PythonApproval {
    callback: Py<PyAny>,
    errors: Arc<CallbackErrors>,
}

impl ApprovalCallback for PythonApproval {
    fn decide(&self, request: &ClientApprovalRequest) -> Result<bool, ClientError> {
        let outcome = Python::with_gil(|py| -> PyResult<bool> {
            let request = Py::new(py, PyApprovalRequest::from_client(request))?;
            let result = self.callback.bind(py).call1((request,))?;
            if !result.is_instance_of::<PyBool>() {
                return Err(PyTypeError::new_err(
                    "approval callback must return exactly bool",
                ));
            }
            result.extract::<bool>()
        });
        outcome.map_err(|error| {
            self.errors.record(error);
            ClientError::CallbackFailed
        })
    }
}

struct PythonEvents {
    callback: Py<PyAny>,
    errors: Arc<CallbackErrors>,
}

impl EventCallback for PythonEvents {
    fn on_event(&self, event: &ClientAgentEvent) -> Result<(), ClientError> {
        let outcome = Python::with_gil(|py| -> PyResult<()> {
            let event = Py::new(py, PyAgentEvent::from_client(*event))?;
            self.callback.bind(py).call1((event,))?;
            Ok(())
        });
        outcome.map_err(|error| {
            self.errors.record(error);
            ClientError::CallbackFailed
        })
    }
}

#[pyclass(name = "_Identity", module = "savana_core", frozen)]
struct PyIdentity {
    inner: Arc<ClientIdentity>,
}

#[pymethods]
impl PyIdentity {
    #[staticmethod]
    fn load(path: PathBuf) -> PyResult<Self> {
        ClientIdentity::load(&path)
            .map(|inner| Self {
                inner: Arc::new(inner),
            })
            .map_err(map_auth_error)
    }

    fn __repr__(&self) -> &'static str {
        "Identity(<public-credential>)"
    }
}

#[pyclass(name = "_Client", module = "savana_core", frozen)]
struct PyClient {
    inner: Arc<RustClient>,
}

#[pymethods]
impl PyClient {
    #[new]
    fn new() -> PyResult<Self> {
        let endpoints = ClientEndpoints::new(AGENT_ENDPOINT, INGRESS_ENDPOINT, APPROVAL_ENDPOINT)
            .map_err(map_client_error)?;
        Ok(Self {
            inner: Arc::new(RustClient::new(endpoints)),
        })
    }

    fn session(
        &self,
        py: Python<'_>,
        identity: &PyIdentity,
        bootstrap: &str,
        webauthn: Py<PyAny>,
        approval: Py<PyAny>,
    ) -> PyResult<PySession> {
        let callback_errors = Arc::new(CallbackErrors::default());
        let provider = Arc::new(PythonWebAuthn {
            provider: webauthn,
            errors: callback_errors.clone(),
        });
        let approval = Arc::new(PythonApproval {
            callback: approval,
            errors: callback_errors.clone(),
        });
        let client = self.inner.clone();
        let identity = identity.inner.clone();
        let mut bootstrap =
            SessionBootstrap::from_control_plane_token(bootstrap).map_err(map_auth_error)?;
        let provider_for_session = provider.clone();
        let result = py.allow_threads(move || {
            client.session(
                identity.as_ref(),
                &mut bootstrap,
                provider_for_session,
                approval,
            )
        });
        if let Some(error) = callback_errors.take() {
            return Err(error);
        }
        result
            .map(|session| PySession::live(session, callback_errors))
            .map_err(map_auth_error)
    }

    fn enroll(
        &self,
        py: Python<'_>,
        enrollment_token: String,
        code: String,
        webauthn: Py<PyAny>,
        identity_path: PathBuf,
    ) -> PyResult<PyIdentity> {
        let callback_errors = Arc::new(CallbackErrors::default());
        let provider = Arc::new(PythonWebAuthn {
            provider: webauthn,
            errors: callback_errors.clone(),
        });
        let client = self.inner.clone();
        let result = py.allow_threads(move || {
            client.enroll(&enrollment_token, &code, provider.as_ref(), &identity_path)
        });
        if let Some(error) = callback_errors.take() {
            return Err(error);
        }
        result
            .map(|identity| PyIdentity {
                inner: Arc::new(identity),
            })
            .map_err(map_auth_error)
    }

    fn __repr__(&self) -> &'static str {
        "Client(<fixed-loopback>)"
    }
}

#[derive(Clone)]
enum HandleState {
    Live(Arc<ClientHandle>),
    #[cfg(debug_assertions)]
    Debug(&'static str),
}

#[pyclass(name = "Handle", module = "savana_core", frozen)]
#[derive(Clone)]
struct PyHandle {
    inner: HandleState,
}

impl PyHandle {
    fn live(handle: ClientHandle) -> Self {
        Self {
            inner: HandleState::Live(Arc::new(handle)),
        }
    }

    fn live_arc(&self) -> PyResult<Arc<ClientHandle>> {
        match &self.inner {
            HandleState::Live(handle) => Ok(handle.clone()),
            #[cfg(debug_assertions)]
            HandleState::Debug(_) => Err(PyValueError::new_err("debug handle is not live")),
        }
    }

    fn kind_name(&self) -> &str {
        match &self.inner {
            HandleState::Live(handle) => handle.kind().as_str(),
            #[cfg(debug_assertions)]
            HandleState::Debug(kind) => kind,
        }
    }
}

#[pymethods]
impl PyHandle {
    #[getter]
    fn kind(&self) -> &str {
        self.kind_name()
    }

    fn __repr__(&self) -> String {
        format!("Handle(<opaque:{}>)", self.kind_name())
    }
}

#[pyclass(name = "PlanStep", module = "savana_core", frozen)]
#[derive(Clone)]
struct PyPlanStep {
    handle: PyHandle,
}

#[pymethods]
impl PyPlanStep {
    #[getter]
    fn handle(&self) -> PyHandle {
        self.handle.clone()
    }

    fn __repr__(&self) -> String {
        format!("PlanStep(Handle(<opaque:{}>))", self.handle.kind_name())
    }
}

enum PlanState {
    Live(Arc<ClientPlan>),
    #[cfg(debug_assertions)]
    Debug(Vec<PyPlanStep>),
}

#[pyclass(name = "Plan", module = "savana_core", frozen)]
struct PyPlan {
    inner: PlanState,
}

impl PyPlan {
    fn live(plan: ClientPlan) -> Self {
        Self {
            inner: PlanState::Live(Arc::new(plan)),
        }
    }

    fn live_arc(&self) -> PyResult<Arc<ClientPlan>> {
        match &self.inner {
            PlanState::Live(plan) => Ok(plan.clone()),
            #[cfg(debug_assertions)]
            PlanState::Debug(_) => Err(PyValueError::new_err("debug plan is not live")),
        }
    }

    fn is_debug(&self) -> bool {
        match &self.inner {
            PlanState::Live(_) => false,
            #[cfg(debug_assertions)]
            PlanState::Debug(_) => true,
        }
    }
}

#[pymethods]
impl PyPlan {
    #[getter]
    fn steps(&self) -> Vec<PyPlanStep> {
        match &self.inner {
            PlanState::Live(plan) => plan
                .steps()
                .iter()
                .map(|step| PyPlanStep {
                    handle: PyHandle::live(step.handle().clone()),
                })
                .collect(),
            #[cfg(debug_assertions)]
            PlanState::Debug(steps) => steps.clone(),
        }
    }

    fn __repr__(&self) -> String {
        format!("Plan(step_count={})", self.steps().len())
    }
}

#[pyclass(name = "ApprovalRequest", module = "savana_core", frozen)]
struct PyApprovalRequest {
    #[pyo3(get)]
    display: String,
    #[pyo3(get)]
    purpose: String,
}

impl PyApprovalRequest {
    fn from_client(request: &ClientApprovalRequest) -> Self {
        Self {
            display: request.display().to_owned(),
            purpose: purpose_name(request.purpose()).to_owned(),
        }
    }
}

#[pymethods]
impl PyApprovalRequest {
    fn __repr__(&self) -> String {
        format!(
            "ApprovalRequest(display=<redacted>, purpose={})",
            self.purpose
        )
    }
}

#[pyclass(name = "ExecutionResult", module = "savana_core", frozen)]
struct PyExecutionResult {
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    outputs: Vec<PyHandle>,
    #[pyo3(get)]
    failure_class: Option<String>,
}

impl PyExecutionResult {
    fn from_client(result: ClientExecutionResult) -> Self {
        Self {
            status: status_name(result.status()).to_owned(),
            outputs: result
                .outputs()
                .iter()
                .cloned()
                .map(PyHandle::live)
                .collect(),
            failure_class: result.failure_class().map(str::to_owned),
        }
    }

    #[cfg(debug_assertions)]
    fn debug_success() -> Self {
        Self {
            status: "succeeded".to_owned(),
            outputs: Vec::new(),
            failure_class: None,
        }
    }
}

#[pymethods]
impl PyExecutionResult {
    fn __repr__(&self) -> String {
        format!(
            "ExecutionResult(status={}, output_count={})",
            self.status,
            self.outputs.len()
        )
    }
}

#[pyclass(name = "MaskedView", module = "savana_core", frozen)]
struct PyMaskedView {
    inner: ClientMaskedView,
}

#[pymethods]
impl PyMaskedView {
    #[getter]
    fn continuation(&self) -> Option<PyHandle> {
        self.inner.continuation().cloned().map(PyHandle::live)
    }

    #[getter]
    fn variant(&self) -> &'static str {
        if self.inner.masked_text().is_some() {
            "masked_text"
        } else if self.inner.structured().is_some() {
            "structured"
        } else if self.inner.document_page().is_some() {
            "document_page"
        } else {
            "content_state"
        }
    }

    #[getter]
    fn text(&self) -> Option<String> {
        self.inner
            .masked_text()
            .map(|(text, _)| text.to_owned())
            .or_else(|| {
                self.inner
                    .document_page()
                    .map(|(_, text, _)| text.to_owned())
            })
    }

    #[getter]
    fn page_index(&self) -> Option<u32> {
        self.inner.document_page().map(|(page, _, _)| page)
    }

    #[getter]
    fn template_id(&self) -> Option<u32> {
        self.inner.structured().map(|(template, _)| template.get())
    }

    #[getter]
    fn field_count(&self) -> Option<usize> {
        self.inner.structured().map(|(_, fields)| fields.len())
    }

    #[getter]
    fn fields(&self, py: Python<'_>) -> Option<Py<PyTuple>> {
        let (_, fields) = self.inner.structured()?;
        let fields = fields.iter().map(|field| {
            let placeholders = PyTuple::new_bound(
                py,
                field.placeholders().iter().map(|placeholder| {
                    (
                        placeholder.ordinal(),
                        placeholder.token().as_str().to_owned(),
                        snake_debug(&format!("{:?}", placeholder.redaction_class())),
                    )
                }),
            );
            PyTuple::new_bound(
                py,
                [
                    field.name().as_str().to_object(py),
                    field.text().as_str().to_object(py),
                    placeholders.to_object(py),
                ],
            )
            .to_object(py)
        });
        Some(PyTuple::new_bound(py, fields).unbind())
    }

    #[getter]
    fn content_state(&self) -> Option<String> {
        self.inner
            .content_state()
            .map(|state| snake_debug(&format!("{state:?}")))
    }

    #[getter]
    fn placeholders(&self) -> Option<Vec<(u32, String, String)>> {
        let placeholders = self
            .inner
            .masked_text()
            .map(|(_, placeholders)| placeholders)
            .or_else(|| {
                self.inner
                    .document_page()
                    .map(|(_, _, placeholders)| placeholders)
            })?;
        Some(
            placeholders
                .iter()
                .map(|placeholder| {
                    (
                        placeholder.ordinal(),
                        placeholder.token().as_str().to_owned(),
                        snake_debug(&format!("{:?}", placeholder.redaction_class())),
                    )
                })
                .collect(),
        )
    }

    fn __repr__(&self) -> &'static str {
        "MaskedView(<masked>)"
    }
}

#[pyclass(name = "ConnectorDescriptor", module = "savana_core", frozen)]
struct PyConnectorDescriptor {
    inner: Arc<ClientConnectorDescriptor>,
}

#[pymethods]
impl PyConnectorDescriptor {
    #[staticmethod]
    fn load(path: PathBuf) -> PyResult<Self> {
        let file = File::open(path).map_err(|_| map_client_error(ClientError::InvalidRequest))?;
        let mut bytes = Vec::new();
        file.take(MAX_CONNECTOR_DESCRIPTOR_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| map_client_error(ClientError::InvalidRequest))?;
        if bytes.len() as u64 > MAX_CONNECTOR_DESCRIPTOR_BYTES {
            return Err(map_client_error(ClientError::InvalidRequest));
        }
        ClientConnectorDescriptor::from_canonical_bytes(&bytes)
            .map(|inner| Self {
                inner: Arc::new(inner),
            })
            .map_err(map_client_error)
    }

    fn __repr__(&self) -> &'static str {
        "ConnectorDescriptor(<opaque>)"
    }
}

#[pyclass(name = "TaskAuthorizationDraft", module = "savana_core", frozen)]
struct PyTaskAuthorizationDraft {
    inner: savana_client::TaskAuthorizationDraft,
}

#[pymethods]
impl PyTaskAuthorizationDraft {
    #[staticmethod]
    fn from_canonical_bytes(bytes: &[u8]) -> PyResult<Self> {
        savana_client::TaskAuthorizationDraft::from_canonical_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(map_client_error)
    }
    fn __repr__(&self) -> &'static str {
        "TaskAuthorizationDraft(<untrusted, redacted>)"
    }
}

#[pyclass(name = "TaskAuthorizationReceipt", module = "savana_core", frozen)]
struct PyTaskAuthorizationReceipt {
    inner: savana_client::TaskAuthorizationReceipt,
}

#[pymethods]
impl PyTaskAuthorizationReceipt {
    #[getter]
    fn request_digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.request_digest())
    }
    #[getter]
    fn authorization_digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.authorization_digest())
    }
    fn __repr__(&self) -> &'static str {
        "TaskAuthorizationReceipt(<observation>)"
    }
}

#[pyclass(name = "RunLimits", module = "savana_core", frozen)]
struct PyRunLimits {
    inner: ClientRunLimits,
}

#[pymethods]
impl PyRunLimits {
    #[new]
    fn new(max_steps: u32, max_replans: u32, deadline_seconds: f64) -> PyResult<Self> {
        let deadline = Duration::try_from_secs_f64(deadline_seconds)
            .map_err(|_| PyValueError::new_err("deadline must be finite and positive"))?;
        ClientRunLimits::new(max_steps, max_replans, deadline)
            .map(|inner| Self { inner })
            .map_err(map_client_error)
    }

    #[getter]
    fn max_steps(&self) -> u32 {
        self.inner.max_steps()
    }

    #[getter]
    fn max_replans(&self) -> u32 {
        self.inner.max_replans()
    }

    #[getter]
    fn deadline_seconds(&self) -> f64 {
        self.inner.deadline().as_secs_f64()
    }

    fn cancel(&self) {
        self.inner.cancel();
    }

    #[getter]
    fn cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    fn __repr__(&self) -> String {
        format!(
            "RunLimits(max_steps={}, max_replans={}, deadline_seconds={})",
            self.max_steps(),
            self.max_replans(),
            self.deadline_seconds()
        )
    }
}

#[pyclass(name = "AgentEvent", module = "savana_core", frozen)]
struct PyAgentEvent {
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    index: Option<u32>,
    #[pyo3(get)]
    status: Option<String>,
    #[pyo3(get)]
    purpose: Option<String>,
    #[pyo3(get)]
    count: Option<u32>,
}

impl PyAgentEvent {
    fn from_client(event: ClientAgentEvent) -> Self {
        match event {
            ClientAgentEvent::Planning => Self::new("planning"),
            ClientAgentEvent::StepStarted { index } => Self {
                index: Some(index),
                ..Self::new("step_started")
            },
            ClientAgentEvent::StepCompleted { index, status } => Self {
                index: Some(index),
                status: Some(status_name(status).to_owned()),
                ..Self::new("step_completed")
            },
            ClientAgentEvent::ApprovalRequired { purpose } => Self {
                purpose: Some(purpose_name(purpose).to_owned()),
                ..Self::new("approval_required")
            },
            ClientAgentEvent::Replanning { count } => Self {
                count: Some(count),
                ..Self::new("replanning")
            },
            ClientAgentEvent::Refused => Self::new("refused"),
            ClientAgentEvent::Completed => Self::new("completed"),
        }
    }

    fn new(kind: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            index: None,
            status: None,
            purpose: None,
            count: None,
        }
    }
}

#[pymethods]
impl PyAgentEvent {
    fn __repr__(&self) -> String {
        format!("AgentEvent(kind={})", self.kind)
    }
}

enum SessionState {
    Live(Box<ClientSession>),
    #[cfg(debug_assertions)]
    Debug(DebugSession),
}

#[cfg(debug_assertions)]
struct DebugScriptedTransport {
    responses: Mutex<VecDeque<Result<BrowserResponse, ClientError>>>,
    request_count: AtomicUsize,
    close_count: AtomicUsize,
    delay: Duration,
    last_worker_thread: Mutex<Option<i64>>,
}

#[cfg(debug_assertions)]
impl DebugScriptedTransport {
    fn new(responses: Vec<Result<BrowserResponse, ClientError>>, delay: Duration) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            request_count: AtomicUsize::new(0),
            close_count: AtomicUsize::new(0),
            delay,
            last_worker_thread: Mutex::new(None),
        }
    }

    fn record_worker(&self) {
        let worker = Python::with_gil(|py| -> PyResult<i64> {
            py.import_bound("threading")?
                .call_method0("get_ident")?
                .extract()
        })
        .ok();
        if let Ok(mut observed) = self.last_worker_thread.lock() {
            *observed = worker;
        }
    }
}

#[cfg(debug_assertions)]
impl BrowserTransport for DebugScriptedTransport {
    fn send(&self, request: BrowserRequest) -> Result<BrowserResponse, ClientError> {
        request.validate()?;
        let index = self.request_count.fetch_add(1, Ordering::SeqCst);
        if index >= 4 {
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            self.record_worker();
            self.close_count.fetch_add(1, Ordering::SeqCst);
        }
        self.responses
            .lock()
            .map_err(|_| ClientError::InvalidState)?
            .pop_front()
            .unwrap_or(Err(ClientError::Transport))
    }
}

#[cfg(debug_assertions)]
struct DebugFixedNonces(Mutex<u8>);

#[cfg(debug_assertions)]
impl NonceSource for DebugFixedNonces {
    fn nonce(&self) -> Result<Nonce32V2, ClientError> {
        let mut next = self.0.lock().map_err(|_| ClientError::InvalidState)?;
        let nonce = Nonce32V2::new([*next; 32]);
        *next = next.checked_add(1).ok_or(ClientError::InvalidState)?;
        Ok(nonce)
    }
}

#[cfg(debug_assertions)]
struct DebugWebAuthn;

#[cfg(debug_assertions)]
impl WebAuthnProvider for DebugWebAuthn {
    fn assert_credential(
        &self,
        _options_json: &[u8],
    ) -> Result<WebAuthnAssertion, ClientAuthError> {
        WebAuthnAssertion::new(
            vec![0x61; 16],
            vec![0x62; 32],
            br#"{"type":"webauthn.get"}"#.to_vec(),
            vec![0x63; 64],
            vec![0x64; 32],
        )
    }

    fn create_credential(
        &self,
        _options_json: &[u8],
    ) -> Result<WebAuthnAttestation, ClientAuthError> {
        Err(ClientAuthError::EnrollmentFailed)
    }
}

#[cfg(debug_assertions)]
struct DebugApproval;

#[cfg(debug_assertions)]
impl ApprovalCallback for DebugApproval {
    fn decide(&self, _request: &ClientApprovalRequest) -> Result<bool, ClientError> {
        Ok(true)
    }
}

#[cfg(debug_assertions)]
fn debug_response(
    content_type: BrowserContentType,
    body: Vec<u8>,
) -> Result<BrowserResponse, ClientError> {
    BrowserResponse::from_scripted(content_type, body)
}

#[cfg(debug_assertions)]
fn debug_authentication_html<T: minicbor::Encode<()>>(purpose: &str, capability: T) -> Vec<u8> {
    let capability = URL_SAFE_NO_PAD.encode(minicbor::to_vec(capability).unwrap_or_default());
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana authentication</title></head><body><main data-purpose=\"{purpose}\" data-pre-authentication=\"{capability}\"><h1>Hardware authentication required</h1><button id=\"savana-authenticate\" type=\"button\">Use security key</button><p id=\"savana-status\">The opaque capability is held only in this page.</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
    )
    .into_bytes()
}

#[cfg(debug_assertions)]
fn debug_transport_responses() -> PyResult<Vec<Result<BrowserResponse, ClientError>>> {
    let pre_authentication =
        AgentUiPreAuthenticationTabCapabilityV2::from_authority_entropy([0x31; 32])
            .ok_or_else(|| PyValueError::new_err("invalid fixture capability"))?;
    let ceremony =
        AgentUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy([0x32; 32])
            .ok_or_else(|| PyValueError::new_err("invalid fixture capability"))?;
    let settlement =
        AgentUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy([0x33; 32])
            .ok_or_else(|| PyValueError::new_err("invalid fixture capability"))?;
    let tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x34; 32])
        .ok_or_else(|| PyValueError::new_err("invalid fixture capability"))?;
    let document = AgentMaskedDocumentRefV2::from_authority_entropy([0x35; 16])
        .ok_or_else(|| PyValueError::new_err("invalid fixture capability"))?;
    Ok(vec![
        debug_response(
            BrowserContentType::Html,
            debug_authentication_html("agent", pre_authentication),
        ),
        debug_response(
            BrowserContentType::CanonicalCbor,
            encode_ui_authentication_browser_begin_response_v2(
                &UiAuthenticationBrowserBeginResponseV2::Agent {
                    ceremony,
                    public_key_options_json: Zeroizing::new(b"agent-options".to_vec()),
                },
            )
            .map_err(|_| PyValueError::new_err("invalid fixture response"))?,
        ),
        debug_response(
            BrowserContentType::CanonicalCbor,
            encode_ui_authentication_browser_finish_response_v2(
                UiAuthenticationBrowserFinishResponseV2::TransferToAgent {
                    return_origin: FixedOriginV2::Agent8768,
                    transfer: settlement,
                },
            )
            .map_err(|_| PyValueError::new_err("invalid fixture response"))?,
        ),
        debug_response(
            BrowserContentType::Html,
            render_agent_workspace_v2(tab, document),
        ),
        debug_response(
            BrowserContentType::CanonicalCbor,
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::SessionClosed {
                    state: AgentSessionStatusV2::Closed,
                },
            )
            .map_err(|_| PyValueError::new_err("invalid fixture response"))?,
        ),
    ])
}

#[cfg(debug_assertions)]
fn debug_view_transport_responses() -> PyResult<Vec<Result<BrowserResponse, ClientError>>> {
    let mut responses = debug_transport_responses()?;
    let close_response = responses
        .pop()
        .ok_or_else(|| PyValueError::new_err("missing close fixture response"))?;
    let cursor = AgentBrowserViewCursorCapabilityV2::from_authority_entropy([0x36; 16])
        .ok_or_else(|| PyValueError::new_err("invalid fixture cursor"))?;
    responses.push(debug_response(
        BrowserContentType::CanonicalCbor,
        encode_agent_browser_read_view_response_v2(
            &AgentBrowserReadViewResponseV2::new(
                AgentViewV2::DocumentPage {
                    page_index: 0,
                    text: BoundedAgentTextV2::new("first")
                        .map_err(|_| PyValueError::new_err("invalid fixture view"))?,
                    placeholders: vec![],
                },
                vec![],
                Some(cursor),
            )
            .map_err(|_| PyValueError::new_err("invalid fixture view"))?,
        )
        .map_err(|_| PyValueError::new_err("invalid fixture response"))?,
    ));
    responses.push(debug_response(
        BrowserContentType::CanonicalCbor,
        encode_agent_browser_read_view_response_v2(
            &AgentBrowserReadViewResponseV2::new(
                AgentViewV2::DocumentPage {
                    page_index: 1,
                    text: BoundedAgentTextV2::new("second")
                        .map_err(|_| PyValueError::new_err("invalid fixture view"))?,
                    placeholders: vec![],
                },
                vec![],
                None,
            )
            .map_err(|_| PyValueError::new_err("invalid fixture view"))?,
        )
        .map_err(|_| PyValueError::new_err("invalid fixture response"))?,
    ));
    responses.push(close_response);
    Ok(responses)
}

#[cfg(debug_assertions)]
fn debug_structured_view_transport_responses() -> PyResult<Vec<Result<BrowserResponse, ClientError>>>
{
    let mut responses = debug_transport_responses()?;
    let close_response = responses
        .pop()
        .ok_or_else(|| PyValueError::new_err("missing close fixture response"))?;
    let placeholder = PlaceholderViewV2::new(
        0,
        BoundedAgentTextV2::new("{{PERSON_0}}")
            .map_err(|_| PyValueError::new_err("invalid debug placeholder"))?,
        ClosedRedactionClassV2::PersonalData,
    )
    .map_err(|_| PyValueError::new_err("invalid debug placeholder"))?;
    let field = AgentViewFieldV2::new(
        ArgumentNameV2::new("recipient".to_owned())
            .map_err(|_| PyValueError::new_err("invalid debug field"))?,
        BoundedAgentTextV2::new("Send to {{PERSON_0}}")
            .map_err(|_| PyValueError::new_err("invalid debug field"))?,
        vec![placeholder],
    )
    .map_err(|_| PyValueError::new_err("invalid debug field"))?;
    responses.push(debug_response(
        BrowserContentType::CanonicalCbor,
        encode_agent_browser_read_view_response_v2(
            &AgentBrowserReadViewResponseV2::new(
                AgentViewV2::Structured {
                    template: StaticTemplateIdV2::new(7),
                    fields: vec![field],
                },
                vec![],
                None,
            )
            .map_err(|_| PyValueError::new_err("invalid fixture view"))?,
        )
        .map_err(|_| PyValueError::new_err("invalid fixture response"))?,
    ));
    responses.push(close_response);
    Ok(responses)
}

#[cfg(debug_assertions)]
fn debug_identity_path() -> PyResult<PathBuf> {
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PyValueError::new_err("fixture clock failed"))?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "savana-core-py-{}-{stamp}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).map_err(|_| PyValueError::new_err("fixture setup failed"))?;
    let path = root.join("identity.json");
    fs::write(
        &path,
        b"{\"version\":2,\"credential_digest\":\"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c\",\"credential_id\":\"YWFhYWFhYWFhYWFhYWFhYQ\",\"public_credential_state\":\"active\"}",
    )
    .map_err(|_| PyValueError::new_err("fixture setup failed"))?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| PyValueError::new_err("fixture setup failed"))?;
    Ok(path)
}

#[cfg(debug_assertions)]
struct DebugSession {
    delay: Duration,
    closed: bool,
    close_count: usize,
    last_worker_thread: Option<i64>,
}

#[cfg(debug_assertions)]
impl DebugSession {
    fn run(&mut self) -> Result<(), ClientError> {
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        self.last_worker_thread = Python::with_gil(|py| -> PyResult<i64> {
            py.import_bound("threading")?
                .call_method0("get_ident")?
                .extract()
        })
        .ok();
        Ok(())
    }

    fn close(&mut self) -> Result<(), ClientError> {
        self.run()?;
        if !self.closed {
            self.closed = true;
            self.close_count += 1;
        }
        Ok(())
    }
}

#[pyclass(name = "_Session", module = "savana_core", frozen)]
struct PySession {
    inner: Arc<Mutex<SessionState>>,
    ingress_callback_errors: Arc<CallbackErrors>,
    #[cfg(debug_assertions)]
    debug_transport: Option<Arc<DebugScriptedTransport>>,
}

impl PySession {
    fn live(session: ClientSession, callback_errors: Arc<CallbackErrors>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionState::Live(Box::new(session)))),
            ingress_callback_errors: callback_errors,
            #[cfg(debug_assertions)]
            debug_transport: None,
        }
    }

    fn finish<T>(result: Result<T, ClientError>) -> PyResult<T> {
        result.map_err(map_client_error)
    }

    fn finish_operation<T>(
        result: Result<T, ClientError>,
        callback_errors: &CallbackErrors,
    ) -> PyResult<T> {
        if let Some(error) = callback_errors.take() {
            return Err(error);
        }
        result.map_err(map_client_error)
    }

    fn lock_error() -> ClientError {
        ClientError::InvalidState
    }

    fn try_state(inner: &Mutex<SessionState>) -> Result<MutexGuard<'_, SessionState>, ClientError> {
        // A Rust workflow may invoke Python while it owns mutable session state.
        // Reentrant or concurrent access must fail closed instead of blocking the
        // callback on the same non-reentrant mutex.
        inner.try_lock().map_err(|_| Self::lock_error())
    }
}

#[pymethods]
impl PySession {
    #[getter]
    fn initial_document(&self) -> PyResult<PyHandle> {
        let state = Self::try_state(self.inner.as_ref()).map_err(map_client_error)?;
        match &*state {
            SessionState::Live(session) => Ok(PyHandle::live(session.initial_document().clone())),
            #[cfg(debug_assertions)]
            SessionState::Debug(_) => Ok(PyHandle {
                inner: HandleState::Debug("document"),
            }),
        }
    }

    fn ingest_text(&self, py: Python<'_>, text: String, content_kind: &str) -> PyResult<()> {
        let kind = parse_content_kind(content_kind)?;
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session.ingest_text(&text, kind),
                #[cfg(debug_assertions)]
                SessionState::Debug(session) => session.run(),
            }
        });
        Self::finish_operation(result, self.ingress_callback_errors.as_ref())
    }

    fn ingest_file(&self, py: Python<'_>, path: PathBuf, content_kind: &str) -> PyResult<()> {
        let kind = parse_content_kind(content_kind)?;
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session.ingest_file(&path, kind),
                #[cfg(debug_assertions)]
                SessionState::Debug(session) => session.run(),
            }
        });
        Self::finish_operation(result, self.ingress_callback_errors.as_ref())
    }

    fn establish_task_authorization(
        &self,
        py: Python<'_>,
        draft: &PyTaskAuthorizationDraft,
    ) -> PyResult<PyTaskAuthorizationReceipt> {
        let draft = draft.inner.clone();
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .establish_task_authorization(&draft)
                    .map(|inner| PyTaskAuthorizationReceipt { inner }),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish(result)
    }

    fn approve_task_authorization(
        &self,
        py: Python<'_>,
        draft: &PyTaskAuthorizationDraft,
        approval: Py<PyAny>,
    ) -> PyResult<PyTaskAuthorizationReceipt> {
        let draft = draft.inner.clone();
        let errors = Arc::new(CallbackErrors::default());
        let callback = PythonApproval {
            callback: approval,
            errors: errors.clone(),
        };
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .approve_task_authorization(&draft, &callback)
                    .map(|inner| PyTaskAuthorizationReceipt { inner }),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish_operation(result, errors.as_ref())
    }

    fn recover_task_authorization(
        &self,
        py: Python<'_>,
        request_digest: &[u8],
        approval: Py<PyAny>,
    ) -> PyResult<PyTaskAuthorizationReceipt> {
        let digest: [u8; 32] = request_digest
            .try_into()
            .map_err(|_| map_client_error(ClientError::InvalidRequest))?;
        let errors = Arc::new(CallbackErrors::default());
        let callback = PythonApproval {
            callback: approval,
            errors: errors.clone(),
        };
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .recover_task_authorization(digest, &callback)
                    .map(|inner| PyTaskAuthorizationReceipt { inner }),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish_operation(result, errors.as_ref())
    }

    fn revoke_task_authorization<'py>(
        &self,
        py: Python<'py>,
        draft: &PyTaskAuthorizationDraft,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let draft = draft.inner.clone();
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session.revoke_task_authorization(&draft),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish(result).map(|digest| PyBytes::new_bound(py, &digest))
    }

    fn read_view(&self, py: Python<'_>, handle: &PyHandle) -> PyResult<PyMaskedView> {
        let handle = handle.live_arc()?;
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .read_view(handle.as_ref())
                    .map(|inner| PyMaskedView { inner }),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish(result)
    }

    fn run_planner(&self, py: Python<'_>, intent_privacy: &str) -> PyResult<PyPlan> {
        let privacy = parse_intent_privacy(intent_privacy)?;
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session.run_planner(privacy).map(PyPlan::live),
                #[cfg(debug_assertions)]
                SessionState::Debug(session) => {
                    session.run()?;
                    Ok(debug_plan_value())
                }
            }
        });
        Self::finish(result)
    }

    fn execute(
        &self,
        py: Python<'_>,
        plan: &PyPlan,
        approval: Py<PyAny>,
    ) -> PyResult<PyExecutionResult> {
        let is_debug_plan = plan.is_debug();
        let live_plan = if is_debug_plan {
            None
        } else {
            Some(plan.live_arc()?)
        };
        let callback_errors = Arc::new(CallbackErrors::default());
        let callback = PythonApproval {
            callback: approval,
            errors: callback_errors.clone(),
        };
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .execute(
                        live_plan.as_deref().ok_or(ClientError::InvalidRequest)?,
                        &callback,
                    )
                    .map(PyExecutionResult::from_client),
                #[cfg(debug_assertions)]
                SessionState::Debug(session) if is_debug_plan => {
                    session.run()?;
                    callback.decide(&debug_approval_request_value())?;
                    Ok(PyExecutionResult::debug_success())
                }
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidRequest),
            }
        });
        Self::finish_operation(result, callback_errors.as_ref())
    }

    fn run_agent(
        &self,
        py: Python<'_>,
        intent_privacy: &str,
        limits: &PyRunLimits,
        approval: Py<PyAny>,
        events: Py<PyAny>,
    ) -> PyResult<PyExecutionResult> {
        let privacy = parse_intent_privacy(intent_privacy)?;
        let limits = limits.inner.clone();
        let callback_errors = Arc::new(CallbackErrors::default());
        let approval = PythonApproval {
            callback: approval,
            errors: callback_errors.clone(),
        };
        let events = PythonEvents {
            callback: events,
            errors: callback_errors.clone(),
        };
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .run_agent(privacy, limits, &approval, &events)
                    .map(PyExecutionResult::from_client),
                #[cfg(debug_assertions)]
                SessionState::Debug(session) => {
                    session.run()?;
                    events.on_event(&ClientAgentEvent::Planning)?;
                    events.on_event(&ClientAgentEvent::Completed)?;
                    Ok(PyExecutionResult::debug_success())
                }
            }
        });
        Self::finish_operation(result, callback_errors.as_ref())
    }

    fn release(
        &self,
        py: Python<'_>,
        document: &PyHandle,
        approval: Py<PyAny>,
    ) -> PyResult<PyExecutionResult> {
        let document = document.live_arc()?;
        let callback_errors = Arc::new(CallbackErrors::default());
        let callback = PythonApproval {
            callback: approval,
            errors: callback_errors.clone(),
        };
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .release(document.as_ref(), &callback)
                    .map(PyExecutionResult::from_client),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish_operation(result, callback_errors.as_ref())
    }

    fn register_connector(
        &self,
        py: Python<'_>,
        descriptor: &PyConnectorDescriptor,
        approval: Py<PyAny>,
    ) -> PyResult<PyHandle> {
        let descriptor = descriptor.inner.clone();
        let callback_errors = Arc::new(CallbackErrors::default());
        let callback = PythonApproval {
            callback: approval,
            errors: callback_errors.clone(),
        };
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .register_connector(descriptor.as_ref(), &callback)
                    .map(PyHandle::live),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish_operation(result, callback_errors.as_ref())
    }

    fn remove_connector(&self, py: Python<'_>, connector: &PyHandle) -> PyResult<()> {
        let connector = connector.live_arc()?;
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session.remove_connector(connector.as_ref()),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish(result)
    }

    fn list_connectors(&self, py: Python<'_>) -> PyResult<Vec<PyHandle>> {
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session
                    .list_connectors()
                    .map(|handles| handles.into_iter().map(PyHandle::live).collect()),
                #[cfg(debug_assertions)]
                SessionState::Debug(session) => {
                    session.run()?;
                    Ok(Vec::new())
                }
            }
        });
        Self::finish(result)
    }

    fn revoke(&self, py: Python<'_>, document: &PyHandle) -> PyResult<()> {
        let document = document.live_arc()?;
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session.revoke(document.as_ref()),
                #[cfg(debug_assertions)]
                SessionState::Debug(_) => Err(ClientError::InvalidState),
            }
        });
        Self::finish(result)
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let inner = self.inner.clone();
        let result = py.allow_threads(move || {
            let mut state = Self::try_state(inner.as_ref())?;
            match &mut *state {
                SessionState::Live(session) => session.close(),
                #[cfg(debug_assertions)]
                SessionState::Debug(session) => session.close(),
            }
        });
        Self::finish(result)
    }

    fn __repr__(&self) -> &'static str {
        "Session(<authenticated>)"
    }
}

#[cfg(debug_assertions)]
fn debug_plan_value() -> PyPlan {
    PyPlan {
        inner: PlanState::Debug(vec![PyPlanStep {
            handle: PyHandle {
                inner: HandleState::Debug("plan-step"),
            },
        }]),
    }
}

#[cfg(debug_assertions)]
fn debug_approval_request_value() -> ClientApprovalRequest {
    ClientApprovalRequest {
        display: "Approve exact operation".to_owned(),
        purpose: ApprovalPurpose::ToolExecution,
    }
}

#[cfg(debug_assertions)]
#[pyfunction]
#[pyo3(signature = (delay_seconds=0.0))]
fn _debug_scripted_session(delay_seconds: f64) -> PyResult<PySession> {
    let delay = Duration::try_from_secs_f64(delay_seconds)
        .map_err(|_| PyValueError::new_err("delay must be finite and non-negative"))?;
    Ok(PySession {
        inner: Arc::new(Mutex::new(SessionState::Debug(DebugSession {
            delay,
            closed: false,
            close_count: 0,
            last_worker_thread: None,
        }))),
        ingress_callback_errors: Arc::new(CallbackErrors::default()),
        debug_transport: None,
    })
}

#[cfg(debug_assertions)]
#[pyfunction]
#[pyo3(signature = (delay_seconds=0.0))]
fn _debug_transport_session(delay_seconds: f64) -> PyResult<PySession> {
    let delay = Duration::try_from_secs_f64(delay_seconds)
        .map_err(|_| PyValueError::new_err("delay must be finite and non-negative"))?;
    let transport = Arc::new(DebugScriptedTransport::new(
        debug_transport_responses()?,
        delay,
    ));
    let endpoints = ClientEndpoints::new(AGENT_ENDPOINT, INGRESS_ENDPOINT, APPROVAL_ENDPOINT)
        .map_err(map_client_error)?;
    let client = RustClient::with_transport_and_nonce_source(
        endpoints,
        transport.clone(),
        Arc::new(DebugFixedNonces(Mutex::new(1))),
    );
    let identity_path = debug_identity_path()?;
    let identity = ClientIdentity::load(&identity_path).map_err(map_auth_error);
    let _ = fs::remove_file(&identity_path);
    if let Some(parent) = identity_path.parent() {
        let _ = fs::remove_dir(parent);
    }
    let identity = identity?;
    let mut bootstrap =
        SessionBootstrap::from_control_plane_token(&URL_SAFE_NO_PAD.encode([0x21; 32]))
            .map_err(map_auth_error)?;
    let session = client
        .session(
            &identity,
            &mut bootstrap,
            Arc::new(DebugWebAuthn),
            Arc::new(DebugApproval),
        )
        .map_err(map_auth_error)?;
    Ok(PySession {
        inner: Arc::new(Mutex::new(SessionState::Live(Box::new(session)))),
        ingress_callback_errors: Arc::new(CallbackErrors::default()),
        debug_transport: Some(transport),
    })
}

#[cfg(debug_assertions)]
#[pyfunction]
fn _debug_view_session() -> PyResult<PySession> {
    let transport = Arc::new(DebugScriptedTransport::new(
        debug_view_transport_responses()?,
        Duration::ZERO,
    ));
    let endpoints = ClientEndpoints::new(AGENT_ENDPOINT, INGRESS_ENDPOINT, APPROVAL_ENDPOINT)
        .map_err(map_client_error)?;
    let client = RustClient::with_transport_and_nonce_source(
        endpoints,
        transport.clone(),
        Arc::new(DebugFixedNonces(Mutex::new(1))),
    );
    let identity_path = debug_identity_path()?;
    let identity = ClientIdentity::load(&identity_path).map_err(map_auth_error);
    let _ = fs::remove_file(&identity_path);
    if let Some(parent) = identity_path.parent() {
        let _ = fs::remove_dir(parent);
    }
    let identity = identity?;
    let mut bootstrap =
        SessionBootstrap::from_control_plane_token(&URL_SAFE_NO_PAD.encode([0x21; 32]))
            .map_err(map_auth_error)?;
    let session = client
        .session(
            &identity,
            &mut bootstrap,
            Arc::new(DebugWebAuthn),
            Arc::new(DebugApproval),
        )
        .map_err(map_auth_error)?;
    Ok(PySession {
        inner: Arc::new(Mutex::new(SessionState::Live(Box::new(session)))),
        ingress_callback_errors: Arc::new(CallbackErrors::default()),
        debug_transport: Some(transport),
    })
}

#[cfg(debug_assertions)]
#[pyfunction]
fn _debug_structured_view_session() -> PyResult<PySession> {
    let transport = Arc::new(DebugScriptedTransport::new(
        debug_structured_view_transport_responses()?,
        Duration::ZERO,
    ));
    let endpoints = ClientEndpoints::new(AGENT_ENDPOINT, INGRESS_ENDPOINT, APPROVAL_ENDPOINT)
        .map_err(map_client_error)?;
    let client = RustClient::with_transport_and_nonce_source(
        endpoints,
        transport.clone(),
        Arc::new(DebugFixedNonces(Mutex::new(1))),
    );
    let identity_path = debug_identity_path()?;
    let identity = ClientIdentity::load(&identity_path).map_err(map_auth_error);
    let _ = fs::remove_file(&identity_path);
    if let Some(parent) = identity_path.parent() {
        let _ = fs::remove_dir(parent);
    }
    let identity = identity?;
    let mut bootstrap =
        SessionBootstrap::from_control_plane_token(&URL_SAFE_NO_PAD.encode([0x21; 32]))
            .map_err(map_auth_error)?;
    let session = client
        .session(
            &identity,
            &mut bootstrap,
            Arc::new(DebugWebAuthn),
            Arc::new(DebugApproval),
        )
        .map_err(map_auth_error)?;
    Ok(PySession {
        inner: Arc::new(Mutex::new(SessionState::Live(Box::new(session)))),
        ingress_callback_errors: Arc::new(CallbackErrors::default()),
        debug_transport: Some(transport),
    })
}

#[cfg(debug_assertions)]
#[pyfunction]
fn _debug_handle(kind: &str) -> PyResult<PyHandle> {
    let kind = match kind {
        "document" => "document",
        "plan-step" => "plan-step",
        "connector" => "connector",
        _ => return Err(PyValueError::new_err("unsupported debug handle kind")),
    };
    Ok(PyHandle {
        inner: HandleState::Debug(kind),
    })
}

#[cfg(debug_assertions)]
#[pyfunction]
fn _debug_plan() -> PyPlan {
    debug_plan_value()
}

#[cfg(debug_assertions)]
#[pyfunction]
fn _debug_approval_request() -> PyApprovalRequest {
    PyApprovalRequest::from_client(&debug_approval_request_value())
}

#[cfg(debug_assertions)]
#[pyfunction]
fn _debug_close_count(session: &PySession) -> PyResult<usize> {
    if let Some(transport) = &session.debug_transport {
        return Ok(transport.close_count.load(Ordering::SeqCst));
    }
    let state = PySession::try_state(session.inner.as_ref()).map_err(map_client_error)?;
    match &*state {
        SessionState::Debug(session) => Ok(session.close_count),
        SessionState::Live(_) => Err(PyValueError::new_err("session is not scripted")),
    }
}

#[cfg(debug_assertions)]
#[pyfunction]
fn _debug_last_worker_thread(session: &PySession) -> PyResult<Option<i64>> {
    if let Some(transport) = &session.debug_transport {
        return transport
            .last_worker_thread
            .lock()
            .map(|worker| *worker)
            .map_err(|_| map_client_error(ClientError::InvalidState));
    }
    let state = PySession::try_state(session.inner.as_ref()).map_err(map_client_error)?;
    match &*state {
        SessionState::Debug(session) => Ok(session.last_worker_thread),
        SessionState::Live(_) => Err(PyValueError::new_err("session is not scripted")),
    }
}

#[cfg(debug_assertions)]
#[pyfunction]
fn _debug_callback_error_isolation(py: Python<'_>) -> PyResult<(String, bool, bool, bool)> {
    let first = Arc::new(CallbackErrors::default());
    let second = Arc::new(CallbackErrors::default());
    first.record(PyValueError::new_err("first callback"));

    let unrelated = PySession::finish_operation(Ok("unrelated".to_owned()), second.as_ref())?;
    let own = PySession::finish_operation(Ok(()), first.as_ref())
        .expect_err("the owning operation must receive its callback error");
    Ok((
        unrelated,
        own.is_instance_of::<PyValueError>(py),
        first.take().is_none(),
        second.take().is_none(),
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SavanaError", m.py().get_type_bound::<SavanaError>())?;
    m.add("AuthError", m.py().get_type_bound::<AuthError>())?;
    m.add("ApprovalDenied", m.py().get_type_bound::<ApprovalDenied>())?;
    m.add("PolicyRefused", m.py().get_type_bound::<PolicyRefused>())?;
    m.add_class::<PyIdentity>()?;
    m.add_class::<PyClient>()?;
    m.add_class::<PySession>()?;
    m.add_class::<PyHandle>()?;
    m.add_class::<PyMaskedView>()?;
    m.add_class::<PyPlan>()?;
    m.add_class::<PyPlanStep>()?;
    m.add_class::<PyApprovalRequest>()?;
    m.add_class::<PyExecutionResult>()?;
    m.add_class::<PyConnectorDescriptor>()?;
    m.add_class::<PyTaskAuthorizationDraft>()?;
    m.add_class::<PyTaskAuthorizationReceipt>()?;
    m.add_class::<PyRunLimits>()?;
    m.add_class::<PyAgentEvent>()?;
    #[cfg(debug_assertions)]
    {
        m.add_function(wrap_pyfunction!(_debug_scripted_session, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_transport_session, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_view_session, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_structured_view_session, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_handle, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_plan, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_approval_request, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_close_count, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_last_worker_thread, m)?)?;
        m.add_function(wrap_pyfunction!(_debug_callback_error_isolation, m)?)?;
    }
    Ok(())
}
