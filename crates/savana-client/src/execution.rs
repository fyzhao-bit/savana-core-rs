use savana_kernel_protocol::v2::{
    decode_agent_browser_read_view_response_v2, encode_agent_browser_request_v2,
    AgentBrowserActionV2, AgentBrowserExecutionStateV2, AgentBrowserMutationResponseV2,
    AgentBrowserObjectRefV2, AgentBrowserReleaseStateV2, AgentBrowserRequestV2,
    AgentExecutionRefV2, AgentMaskedDocumentRefV2, AgentReleaseRefV2, ApprovalPurposeV2,
    FixedBrowserFormPostCarrierV2, PublicFailureClassV2, PublicStableCodeV2,
};

use crate::approval::ApprovalOutcome;
use crate::session::LocalSessionState;
use crate::{
    ApprovalCallback, ApprovalDenied, ApprovalPurpose, BrowserContentType, BrowserOrigin,
    BrowserRequest, BrowserRoute, BrowserService, ExecutionResult, ExecutionStatus, Handle, Plan,
    PlanStep, PolicyRefused, SavanaError, Session,
};

const MAXIMUM_VIEW_BYTES: u32 = 8 * 1024 * 1024 - 512;

impl Session {
    pub fn execute(
        &mut self,
        plan: &Plan,
        approval: &dyn ApprovalCallback,
    ) -> Result<ExecutionResult, SavanaError> {
        self.require_open()?;
        let steps = plan
            .steps
            .iter()
            .map(|step| step.handle.expect_plan_step(&self.binding))
            .collect::<Result<Vec<_>, _>>()?;
        let mut outputs = Vec::new();
        for (step, reference) in plan.steps.iter().zip(steps) {
            let proposed =
                self.workflow_action(AgentBrowserActionV2::ProposePlanStep(reference))?;
            let pending = match proposed {
                AgentBrowserMutationResponseV2::ToolProposed { pending } => pending,
                _ => return self.invalid_transition(),
            };
            let evaluated = self.workflow_action(AgentBrowserActionV2::EvaluatePending(pending))?;
            let ticket = match evaluated {
                AgentBrowserMutationResponseV2::ToolDenied { code, .. } => {
                    return Err(tool_denial(step, code));
                }
                AgentBrowserMutationResponseV2::ToolAuthorized { ticket, .. } => ticket,
                AgentBrowserMutationResponseV2::ToolOpenApproval { post, .. } => {
                    let transfer = match post {
                        FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer) => transfer,
                        _ => return self.invalid_transition(),
                    };
                    let outcome = match self.approve_agent(
                        transfer,
                        ApprovalPurposeV2::ToolExecution,
                        ApprovalPurpose::ToolExecution,
                        approval,
                    ) {
                        Ok(outcome) => outcome,
                        Err(error) if error.is_local_run_stop() => return Err(error),
                        Err(error) => {
                            self.state = LocalSessionState::Closed;
                            return Err(error);
                        }
                    };
                    let settled =
                        self.workflow_action(AgentBrowserActionV2::EvaluatePending(pending))?;
                    match settled {
                        AgentBrowserMutationResponseV2::ToolDenied { code, .. } => {
                            return Err(match outcome {
                                ApprovalOutcome::Denied
                                    if code == PublicStableCodeV2::ApprovalDenied =>
                                {
                                    ApprovalDenied.into()
                                }
                                _ => tool_denial(step, code),
                            });
                        }
                        AgentBrowserMutationResponseV2::ToolAuthorized { ticket, .. }
                            if outcome == ApprovalOutcome::Approved =>
                        {
                            ticket
                        }
                        _ => return self.invalid_transition(),
                    }
                }
                _ => return self.invalid_transition(),
            };
            let dispatched = self.workflow_action(AgentBrowserActionV2::DispatchTicket(ticket))?;
            let execution = match dispatched {
                AgentBrowserMutationResponseV2::ExecutionDispatched { execution, .. } => execution,
                _ => return self.invalid_transition(),
            };
            let result = self.refresh_execution_once(execution)?;
            outputs.extend(result.outputs);
            if result.status != ExecutionStatus::Succeeded {
                return Ok(ExecutionResult {
                    status: result.status,
                    outputs,
                    failure_class: result.failure_class,
                });
            }
        }
        Ok(ExecutionResult {
            status: ExecutionStatus::Succeeded,
            outputs,
            failure_class: None,
        })
    }

    pub fn release(
        &mut self,
        document: &Handle,
        approval: &dyn ApprovalCallback,
    ) -> Result<ExecutionResult, SavanaError> {
        self.require_open()?;
        let document = document.expect_document(&self.binding)?;
        if self.revoked_documents.contains(&document) {
            return Err(SavanaError::InvalidState);
        }
        let prepared = self.workflow_action(AgentBrowserActionV2::PrepareRelease(document))?;
        let transfer = match prepared {
            AgentBrowserMutationResponseV2::ReleaseOpenApproval {
                post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
            } => transfer,
            _ => return self.invalid_transition(),
        };
        let outcome = match self.approve_agent(
            transfer,
            ApprovalPurposeV2::FinalRelease,
            ApprovalPurpose::FinalRelease,
            approval,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        if outcome == ApprovalOutcome::Denied {
            return Err(ApprovalDenied.into());
        }

        let objects = self.release_ticket_projection()?;
        let mut new_tickets = objects.iter().filter_map(|object| match object {
            AgentBrowserObjectRefV2::ReleaseTicket(ticket)
                if !self.observed_release_tickets.contains(ticket) =>
            {
                Some(*ticket)
            }
            _ => None,
        });
        let Some(ticket) = new_tickets.next() else {
            return self.invalid_transition();
        };
        if new_tickets.next().is_some() {
            return self.invalid_transition();
        }
        self.observed_release_tickets.push(ticket);

        let dispatched = self.workflow_action(AgentBrowserActionV2::DispatchRelease(ticket))?;
        let release = match dispatched {
            AgentBrowserMutationResponseV2::ReleaseDispatched { release, .. } => release,
            _ => return self.invalid_transition(),
        };
        self.refresh_release_once(release)
    }

    fn refresh_execution_once(
        &mut self,
        execution: AgentExecutionRefV2,
    ) -> Result<ExecutionResult, SavanaError> {
        let refreshed = self.workflow_action(AgentBrowserActionV2::RefreshExecution(execution))?;
        match refreshed {
            AgentBrowserMutationResponseV2::ExecutionRefreshed {
                execution: returned,
                state: AgentBrowserExecutionStateV2::Succeeded { document },
            } if returned == execution => Ok(success_with_document(&self.binding, document)),
            AgentBrowserMutationResponseV2::ExecutionRefreshed {
                execution: returned,
                state: AgentBrowserExecutionStateV2::EffectSucceededOutputQuarantined { class },
            } if returned == execution => Ok(quarantined(class)),
            AgentBrowserMutationResponseV2::ExecutionRefreshed {
                execution: returned,
                state: AgentBrowserExecutionStateV2::FailedNoEffect { class },
            } if returned == execution => Ok(failed_no_effect(class)),
            AgentBrowserMutationResponseV2::ExecutionRefreshed {
                execution: returned,
                state: AgentBrowserExecutionStateV2::Indeterminate,
            } if returned == execution => {
                self.state = LocalSessionState::Closed;
                Err(SavanaError::IndeterminateEffect)
            }
            _ => self.invalid_transition(),
        }
    }

    fn refresh_release_once(
        &mut self,
        release: AgentReleaseRefV2,
    ) -> Result<ExecutionResult, SavanaError> {
        let refreshed = self.workflow_action(AgentBrowserActionV2::RefreshRelease(release))?;
        match refreshed {
            AgentBrowserMutationResponseV2::ReleaseRefreshed {
                release: returned,
                state: AgentBrowserReleaseStateV2::Succeeded,
            } if returned == release => Ok(succeeded_without_output()),
            AgentBrowserMutationResponseV2::ReleaseRefreshed {
                release: returned,
                state: AgentBrowserReleaseStateV2::EffectSucceededOutputQuarantined { class },
            } if returned == release => Ok(quarantined(class)),
            AgentBrowserMutationResponseV2::ReleaseRefreshed {
                release: returned,
                state: AgentBrowserReleaseStateV2::FailedNoEffect { class },
            } if returned == release => Ok(failed_no_effect(class)),
            AgentBrowserMutationResponseV2::ReleaseRefreshed {
                release: returned,
                state: AgentBrowserReleaseStateV2::Indeterminate,
            } if returned == release => {
                self.state = LocalSessionState::Closed;
                Err(SavanaError::IndeterminateEffect)
            }
            _ => self.invalid_transition(),
        }
    }

    fn release_ticket_projection(&mut self) -> Result<Vec<AgentBrowserObjectRefV2>, SavanaError> {
        let document = self.initial_document().expect_document(&self.binding)?;
        let request = AgentBrowserRequestV2::ReadView {
            tab: self.agent.tab,
            client_request_nonce: match self.nonces.nonce() {
                Ok(nonce) => nonce,
                Err(error) => {
                    self.state = LocalSessionState::Closed;
                    return Err(error);
                }
            },
            document,
            cursor: None,
            maximum_encoded_bytes: MAXIMUM_VIEW_BYTES,
        };
        let response = self.send_browser_request(BrowserRequest {
            service: BrowserService::Agent,
            route: BrowserRoute::AgentView,
            origin: BrowserOrigin::Agent,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_agent_browser_request_v2(request)
                .map_err(|_| SavanaError::InvalidRequest)?,
        });
        let decoded = match response.and_then(|response| {
            decode_agent_browser_read_view_response_v2(response.body())
                .map_err(|_| SavanaError::InvalidResponse)
        }) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        Ok(decoded.objects().to_vec())
    }

    fn workflow_action(
        &mut self,
        action: AgentBrowserActionV2,
    ) -> Result<AgentBrowserMutationResponseV2, SavanaError> {
        match self.agent_action(action) {
            Ok(response) => Ok(response),
            Err(error) if error.is_local_run_stop() => Err(error),
            Err(error) => {
                self.state = LocalSessionState::Closed;
                Err(error)
            }
        }
    }

    fn invalid_transition<T>(&mut self) -> Result<T, SavanaError> {
        self.state = LocalSessionState::Closed;
        Err(SavanaError::InvalidState)
    }
}

fn success_with_document(
    binding: &crate::handle::SessionBinding,
    document: AgentMaskedDocumentRefV2,
) -> ExecutionResult {
    ExecutionResult {
        status: ExecutionStatus::Succeeded,
        outputs: vec![Handle::document(binding, document)],
        failure_class: None,
    }
}

fn succeeded_without_output() -> ExecutionResult {
    ExecutionResult {
        status: ExecutionStatus::Succeeded,
        outputs: Vec::new(),
        failure_class: None,
    }
}

fn quarantined(class: PublicFailureClassV2) -> ExecutionResult {
    ExecutionResult {
        status: ExecutionStatus::EffectSucceededOutputQuarantined,
        outputs: Vec::new(),
        failure_class: Some(class),
    }
}

fn failed_no_effect(class: PublicFailureClassV2) -> ExecutionResult {
    ExecutionResult {
        status: ExecutionStatus::FailedNoEffect,
        outputs: Vec::new(),
        failure_class: Some(class),
    }
}

fn tool_denial(step: &PlanStep, code: PublicStableCodeV2) -> SavanaError {
    if code == PublicStableCodeV2::ApprovalDenied {
        return ApprovalDenied.into();
    }
    let code = stable_code_name(code).to_owned();
    PolicyRefused::new(Some(step.clone()), code.clone(), code).into()
}

const fn stable_code_name(code: PublicStableCodeV2) -> &'static str {
    match code {
        PublicStableCodeV2::InvalidReference => "invalid_reference",
        PublicStableCodeV2::StateConflict => "state_conflict",
        PublicStableCodeV2::IdempotencyConflict => "idempotency_conflict",
        PublicStableCodeV2::CancellationTooLate => "cancellation_too_late",
        PublicStableCodeV2::LimitExceeded => "limit_exceeded",
        PublicStableCodeV2::Overloaded => "overloaded",
        PublicStableCodeV2::DeadlineExceeded => "deadline_exceeded",
        PublicStableCodeV2::Cancelled => "cancelled",
        PublicStableCodeV2::PolicyDenied => "policy_denied",
        PublicStableCodeV2::PolicyExpired => "policy_expired",
        PublicStableCodeV2::ArtifactRollback => "artifact_rollback",
        PublicStableCodeV2::RegistryMismatch => "registry_mismatch",
        PublicStableCodeV2::OntologyMismatch => "ontology_mismatch",
        PublicStableCodeV2::ProjectionMismatch => "projection_mismatch",
        PublicStableCodeV2::ModelUnavailable => "model_unavailable",
        PublicStableCodeV2::ModelContract => "model_contract",
        PublicStableCodeV2::InputDenied => "input_denied",
        PublicStableCodeV2::InputMalformed => "input_malformed",
        PublicStableCodeV2::ApprovalDenied => "approval_denied",
        PublicStableCodeV2::ApprovalExpired => "approval_expired",
        PublicStableCodeV2::ApprovalReplay => "approval_replay",
        PublicStableCodeV2::ApprovalBindingMismatch => "approval_binding_mismatch",
        PublicStableCodeV2::ValidatorMissing => "validator_missing",
        PublicStableCodeV2::ValidatorRejected => "validator_rejected",
        PublicStableCodeV2::ValidatorBindingMismatch => "validator_binding_mismatch",
        PublicStableCodeV2::ExecutionFailedNoEffect => "execution_failed_no_effect",
        PublicStableCodeV2::ExecutionIndeterminate => "execution_indeterminate",
        PublicStableCodeV2::ResultUnavailable => "result_unavailable",
        PublicStableCodeV2::StorageUnavailable => "storage_unavailable",
        PublicStableCodeV2::AuditUnavailable => "audit_unavailable",
        PublicStableCodeV2::EntropyUnavailable => "entropy_unavailable",
        PublicStableCodeV2::ServiceUnavailable => "service_unavailable",
        PublicStableCodeV2::InternalFatal => "internal_fatal",
    }
}
