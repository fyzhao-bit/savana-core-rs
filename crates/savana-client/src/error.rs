use crate::{HandleKind, PlanStep};

#[derive(Debug, thiserror::Error)]
pub enum SavanaError {
    #[error("invalid client endpoint")]
    InvalidEndpoint,
    #[error("invalid browser request")]
    InvalidRequest,
    #[error("local browser transport failed")]
    Transport,
    #[error("invalid browser response")]
    InvalidResponse,
    #[error("wrong handle kind: expected {expected}, received {actual}")]
    WrongHandleKind {
        expected: HandleKind,
        actual: HandleKind,
    },
    #[error("handle belongs to a different session")]
    WrongSession,
    #[error("invalid client state transition")]
    InvalidState,
    #[error("client deadline exceeded")]
    DeadlineExceeded,
    #[error("client operation was cancelled")]
    Cancelled,
    #[error("agent step limit exceeded")]
    StepLimitExceeded,
    #[error("agent replan limit exceeded")]
    ReplanLimitExceeded,
    #[error("client callback failed")]
    CallbackFailed,
    #[error("effect outcome is indeterminate")]
    IndeterminateEffect,
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    ApprovalDenied(#[from] ApprovalDenied),
    #[error(transparent)]
    PolicyRefused(#[from] PolicyRefused),
}

impl SavanaError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::InvalidRequest => "invalid_request",
            Self::Transport => "transport_failed",
            Self::InvalidResponse => "invalid_response",
            Self::WrongHandleKind { .. } => "wrong_handle_kind",
            Self::WrongSession => "wrong_session",
            Self::InvalidState => "invalid_state",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Cancelled => "cancelled",
            Self::StepLimitExceeded => "step_limit_exceeded",
            Self::ReplanLimitExceeded => "replan_limit_exceeded",
            Self::CallbackFailed => "callback_failed",
            Self::IndeterminateEffect => "effect_indeterminate",
            Self::Auth(error) => error.code(),
            Self::ApprovalDenied(error) => error.code(),
            Self::PolicyRefused(error) => error.code(),
        }
    }

    pub const fn transport() -> Self {
        Self::Transport
    }

    pub(crate) const fn is_local_run_stop(&self) -> bool {
        matches!(
            self,
            Self::DeadlineExceeded | Self::Cancelled | Self::CallbackFailed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("invalid session bootstrap")]
    InvalidBootstrap,
    #[error("browser authentication failed")]
    AuthenticationFailed,
    #[error("credential enrollment failed")]
    EnrollmentFailed,
}

impl AuthError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidBootstrap => "invalid_bootstrap",
            Self::AuthenticationFailed => "authentication_failed",
            Self::EnrollmentFailed => "enrollment_failed",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("approval was denied")]
pub struct ApprovalDenied;

impl ApprovalDenied {
    pub const fn code(&self) -> &'static str {
        "approval_denied"
    }
}

pub struct PolicyRefused {
    step: Option<PlanStep>,
    code: String,
    reason: String,
}

impl PolicyRefused {
    #[allow(dead_code)] // Constructed by the policy workflow added after Task 2.
    pub(crate) fn new(step: Option<PlanStep>, code: String, reason: String) -> Self {
        Self { step, code, reason }
    }

    pub const fn step(&self) -> Option<&PlanStep> {
        self.step.as_ref()
    }

    pub fn public_code(&self) -> &str {
        &self.code
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub const fn code(&self) -> &'static str {
        "policy_refused"
    }
}

impl core::fmt::Debug for PolicyRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PolicyRefused(<redacted>)")
    }
}

impl core::fmt::Display for PolicyRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("policy refused the operation")
    }
}

impl std::error::Error for PolicyRefused {}
