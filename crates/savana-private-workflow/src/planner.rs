use crate::{json, Error, StateStore, Workflow};
use serde::{Deserialize, Serialize};

/// Deliberately no text predicate, object ID, destination, payload, or policy update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", deny_unknown_fields)]
pub enum PlannerCommand {
    Observe {},
    Discover { epoch: u64 },
    RequestInvoice { epoch: u64, handle: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotStatus {
    Ready,
    Pending,
    Done,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewSlot {
    pub handle: String,
    pub status: SlotStatus,
}

/// This is the entire declared planner-facing projection. Handles are PRFs of
/// private random salt + slot index, never hashes of private values/evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerView {
    pub schema: u8,
    pub epoch: u64,
    pub discovering: bool,
    pub can_discover: bool,
    pub slots: Vec<ViewSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result")]
pub enum PlannerReply {
    View { view: PlannerView },
    Unavailable,
}

/// Pass only this facade to the model-facing component. The local owner retains
/// the workflow, authenticated source inputs, request bytes and transport.
pub struct PlannerPort<'a, S: StateStore> {
    pub(crate) workflow: &'a mut Workflow<S>,
}
impl<S: StateStore> PlannerPort<'_, S> {
    /// All malformed/unknown/stale/denied commands have the same serialized
    /// refusal. Error detail never crosses this boundary. Timing is not hidden.
    pub fn exchange(&mut self, bytes: &[u8], now: u64) -> Vec<u8> {
        let result = (|| {
            if bytes.is_empty() || bytes.len() > 4096 {
                return Err(Error::Malformed);
            }
            let command: PlannerCommand =
                serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
            match command {
                PlannerCommand::Observe {} => {}
                PlannerCommand::Discover { epoch } => {
                    self.workflow.discover(epoch, now)?;
                }
                PlannerCommand::RequestInvoice { epoch, handle } => {
                    self.workflow.reserve(epoch, &handle, now)?;
                }
            }
            self.workflow.visible(now)
        })();
        let reply = match result {
            Ok(view) => PlannerReply::View { view },
            Err(_) => PlannerReply::Unavailable,
        };
        json(&reply).expect("bounded closed planner reply")
    }
}
