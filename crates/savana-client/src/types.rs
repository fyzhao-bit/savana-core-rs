use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use savana_kernel_protocol::v2::{
    AgentContentStateV2, AgentViewFieldV2, AgentViewV2, PlaceholderViewV2, StaticTemplateIdV2,
};

use crate::{Handle, SavanaError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentPrivacy {
    Private,
    ThirdParty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    ChatText,
    PlainText,
    ParsedDocument,
}

pub struct MaskedView {
    #[allow(dead_code)] // Populated and projected by read_view in Task 4.
    pub(crate) value: AgentViewV2,
    pub(crate) continuation: Option<Handle>,
}

impl MaskedView {
    pub(crate) const fn from_protocol(value: AgentViewV2, continuation: Option<Handle>) -> Self {
        Self {
            value,
            continuation,
        }
    }

    pub const fn continuation(&self) -> Option<&Handle> {
        self.continuation.as_ref()
    }

    pub fn masked_text(&self) -> Option<(&str, &[PlaceholderViewV2])> {
        match &self.value {
            AgentViewV2::MaskedText { text, placeholders } => {
                Some((text.as_str(), placeholders.as_slice()))
            }
            _ => None,
        }
    }

    pub fn structured(&self) -> Option<(StaticTemplateIdV2, &[AgentViewFieldV2])> {
        match &self.value {
            AgentViewV2::Structured { template, fields } => Some((*template, fields.as_slice())),
            _ => None,
        }
    }

    pub fn document_page(&self) -> Option<(u32, &str, &[PlaceholderViewV2])> {
        match &self.value {
            AgentViewV2::DocumentPage {
                page_index,
                text,
                placeholders,
            } => Some((*page_index, text.as_str(), placeholders.as_slice())),
            _ => None,
        }
    }

    pub const fn content_state(&self) -> Option<AgentContentStateV2> {
        match &self.value {
            AgentViewV2::ContentState(state) => Some(*state),
            _ => None,
        }
    }
}

impl core::fmt::Debug for MaskedView {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MaskedView(<masked>)")
    }
}

#[derive(Clone)]
pub struct PlanStep {
    pub(crate) handle: Handle,
}

impl PlanStep {
    pub const fn handle(&self) -> &Handle {
        &self.handle
    }
}

impl core::fmt::Debug for PlanStep {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("PlanStep")
            .field(&self.handle)
            .finish()
    }
}

pub struct Plan {
    pub(crate) steps: Vec<PlanStep>,
}

impl Plan {
    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }
}

impl core::fmt::Debug for Plan {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Plan")
            .field("step_count", &self.steps.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalPurpose {
    Ingress,
    ToolExecution,
    FinalRelease,
    ConnectorRegistration,
}

pub struct ApprovalRequest {
    pub display: String,
    pub purpose: ApprovalPurpose,
}

impl ApprovalRequest {
    pub fn display(&self) -> &str {
        &self.display
    }

    pub const fn purpose(&self) -> ApprovalPurpose {
        self.purpose
    }
}

impl core::fmt::Debug for ApprovalRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalRequest")
            .field("display", &"<redacted>")
            .field("purpose", &self.purpose)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Succeeded,
    EffectSucceededOutputQuarantined,
    FailedNoEffect,
}

pub struct ExecutionResult {
    pub(crate) status: ExecutionStatus,
    pub(crate) outputs: Vec<Handle>,
    pub(crate) failure_class: Option<savana_kernel_protocol::v2::PublicFailureClassV2>,
}

impl ExecutionResult {
    pub const fn status(&self) -> ExecutionStatus {
        self.status
    }

    pub fn outputs(&self) -> &[Handle] {
        &self.outputs
    }

    pub const fn failure_class(&self) -> Option<&'static str> {
        match self.failure_class {
            Some(savana_kernel_protocol::v2::PublicFailureClassV2::Policy) => Some("policy"),
            Some(savana_kernel_protocol::v2::PublicFailureClassV2::Input) => Some("input"),
            Some(savana_kernel_protocol::v2::PublicFailureClassV2::Approval) => Some("approval"),
            Some(savana_kernel_protocol::v2::PublicFailureClassV2::Connector) => Some("connector"),
            Some(savana_kernel_protocol::v2::PublicFailureClassV2::Infrastructure) => {
                Some("infrastructure")
            }
            Some(savana_kernel_protocol::v2::PublicFailureClassV2::ResultGate) => {
                Some("result_gate")
            }
            Some(savana_kernel_protocol::v2::PublicFailureClassV2::Audit) => Some("audit"),
            Some(savana_kernel_protocol::v2::PublicFailureClassV2::ReleaseEvidence) => {
                Some("release_evidence")
            }
            None => None,
        }
    }
}

impl core::fmt::Debug for ExecutionResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ExecutionResult")
            .field("status", &self.status)
            .field("output_count", &self.outputs.len())
            .finish()
    }
}

pub struct ConnectorDescriptor {
    pub(crate) canonical: Vec<u8>,
    pub(crate) connector_id: savana_kernel_protocol::v2::Digest32V2,
}

impl core::fmt::Debug for ConnectorDescriptor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ConnectorDescriptor(<opaque>)")
    }
}

#[derive(Clone)]
pub struct RunLimits {
    max_steps: u32,
    max_replans: u32,
    deadline: Duration,
    cancelled: Arc<AtomicBool>,
}

impl RunLimits {
    pub fn new(max_steps: u32, max_replans: u32, deadline: Duration) -> Result<Self, SavanaError> {
        if max_steps == 0
            || max_replans == 0
            || deadline.is_zero()
            || Instant::now().checked_add(deadline).is_none()
        {
            return Err(SavanaError::InvalidRequest);
        }
        Ok(Self {
            max_steps,
            max_replans,
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub const fn max_steps(&self) -> u32 {
        self.max_steps
    }

    pub const fn max_replans(&self) -> u32 {
        self.max_replans
    }

    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
}

impl core::fmt::Debug for RunLimits {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RunLimits")
            .field("max_steps", &self.max_steps)
            .field("max_replans", &self.max_replans)
            .field("deadline", &self.deadline)
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentEvent {
    Planning,
    StepStarted { index: u32 },
    StepCompleted { index: u32, status: ExecutionStatus },
    ApprovalRequired { purpose: ApprovalPurpose },
    Replanning { count: u32 },
    Refused,
    Completed,
}
