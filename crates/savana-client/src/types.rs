use std::time::Duration;

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
}

impl MaskedView {
    pub(crate) const fn from_protocol(value: AgentViewV2) -> Self {
        Self { value }
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
    FailedNoEffect,
}

pub struct ExecutionResult {
    pub(crate) status: ExecutionStatus,
    pub(crate) outputs: Vec<Handle>,
}

impl ExecutionResult {
    pub const fn status(&self) -> ExecutionStatus {
        self.status
    }

    pub fn outputs(&self) -> &[Handle] {
        &self.outputs
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
    #[allow(dead_code)] // Canonical artifact loading is implemented in Task 5.
    pub(crate) canonical: Vec<u8>,
}

impl core::fmt::Debug for ConnectorDescriptor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ConnectorDescriptor(<opaque>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    max_steps: u32,
    max_replans: u32,
    deadline: Duration,
}

impl RunLimits {
    pub fn new(max_steps: u32, max_replans: u32, deadline: Duration) -> Result<Self, SavanaError> {
        if max_steps == 0 || max_replans == 0 || deadline.is_zero() {
            return Err(SavanaError::InvalidRequest);
        }
        Ok(Self {
            max_steps,
            max_replans,
            deadline,
        })
    }

    pub const fn max_steps(self) -> u32 {
        self.max_steps
    }

    pub const fn max_replans(self) -> u32 {
        self.max_replans
    }

    pub const fn deadline(self) -> Duration {
        self.deadline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentEvent {
    Planning,
    StepStarted { index: u32 },
    StepCompleted { index: u32 },
    ApprovalRequired { purpose: ApprovalPurpose },
    Replanning { count: u32 },
    Refused,
    Completed,
}
