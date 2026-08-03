use std::time::Instant;

use crate::session::AgentRunGuard;
use crate::{
    AgentEvent, ApprovalCallback, ApprovalRequest, ExecutionResult, ExecutionStatus, IntentPrivacy,
    Plan, RunLimits, SavanaError, Session,
};

pub trait EventCallback: Send + Sync {
    fn on_event(&self, event: &AgentEvent) -> Result<(), SavanaError>;
}

struct LoopApproval<'a> {
    approval: &'a dyn ApprovalCallback,
    events: &'a dyn EventCallback,
}

impl ApprovalCallback for LoopApproval<'_> {
    fn decide(&self, request: &ApprovalRequest) -> Result<bool, SavanaError> {
        emit(
            self.events,
            AgentEvent::ApprovalRequired {
                purpose: request.purpose(),
            },
        )?;
        self.approval
            .decide(request)
            .map_err(|_| SavanaError::CallbackFailed)
    }
}

impl Session {
    pub fn run_agent(
        &mut self,
        privacy: IntentPrivacy,
        limits: RunLimits,
        approval: &dyn ApprovalCallback,
        events: &dyn EventCallback,
    ) -> Result<ExecutionResult, SavanaError> {
        self.require_open()?;
        if self.agent_run_guard.is_some() {
            return Err(SavanaError::InvalidState);
        }
        let deadline = Instant::now()
            .checked_add(limits.deadline())
            .ok_or(SavanaError::InvalidRequest)?;
        self.agent_run_guard = Some(AgentRunGuard::new(deadline, limits.cancellation_flag()));
        let result = self.run_agent_inner(privacy, &limits, approval, events);
        self.agent_run_guard = None;
        result
    }

    fn run_agent_inner(
        &mut self,
        privacy: IntentPrivacy,
        limits: &RunLimits,
        approval: &dyn ApprovalCallback,
        events: &dyn EventCallback,
    ) -> Result<ExecutionResult, SavanaError> {
        let mut completed_steps = 0_u32;
        let mut replans = 0_u32;
        let mut outputs = Vec::new();
        let approval = LoopApproval { approval, events };

        'planning: loop {
            emit(events, AgentEvent::Planning)?;
            let plan = self.run_planner(privacy)?;
            if plan.steps.is_empty() {
                let mut result = self.execute(&plan, &approval)?;
                outputs.append(&mut result.outputs);
                result.outputs = outputs;
                emit(events, AgentEvent::Completed)?;
                return Ok(result);
            }

            for plan_step in plan.steps {
                if completed_steps >= limits.max_steps() {
                    return Err(SavanaError::StepLimitExceeded);
                }
                completed_steps = completed_steps
                    .checked_add(1)
                    .ok_or(SavanaError::StepLimitExceeded)?;
                emit(
                    events,
                    AgentEvent::StepStarted {
                        index: completed_steps,
                    },
                )?;
                let single_step = Plan {
                    steps: vec![plan_step],
                };
                let result = match self.execute(&single_step, &approval) {
                    Ok(result) => result,
                    Err(
                        error @ (SavanaError::PolicyRefused(_) | SavanaError::ApprovalDenied(_)),
                    ) => {
                        emit(events, AgentEvent::Refused)?;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
                let status = result.status;
                outputs.extend(result.outputs);
                emit(
                    events,
                    AgentEvent::StepCompleted {
                        index: completed_steps,
                        status,
                    },
                )?;
                match status {
                    ExecutionStatus::Succeeded => {}
                    ExecutionStatus::EffectSucceededOutputQuarantined => {
                        return Ok(ExecutionResult {
                            status,
                            outputs,
                            failure_class: result.failure_class,
                        });
                    }
                    ExecutionStatus::FailedNoEffect => {
                        if replans >= limits.max_replans() {
                            return Err(SavanaError::ReplanLimitExceeded);
                        }
                        replans = replans
                            .checked_add(1)
                            .ok_or(SavanaError::ReplanLimitExceeded)?;
                        emit(events, AgentEvent::Replanning { count: replans })?;
                        continue 'planning;
                    }
                }
            }

            emit(events, AgentEvent::Completed)?;
            return Ok(ExecutionResult {
                status: ExecutionStatus::Succeeded,
                outputs,
                failure_class: None,
            });
        }
    }
}

fn emit(events: &dyn EventCallback, event: AgentEvent) -> Result<(), SavanaError> {
    events
        .on_event(&event)
        .map_err(|_| SavanaError::CallbackFailed)
}
