use savana_kernel_protocol::v2::{
    AgentBrowserActionV2, AgentBrowserMutationResponseV2, ApprovalPurposeV2, Digest32V2,
    FixedBrowserFormPostCarrierV2,
};
use savana_policy_core::v2::{ConnectorDescriptorV2, DeploymentHardLimitsV2};

use crate::approval::ApprovalOutcome;
use crate::session::LocalSessionState;
use crate::{
    ApprovalCallback, ApprovalDenied, ApprovalPurpose, ConnectorDescriptor, Handle, SavanaError,
    Session,
};

impl ConnectorDescriptor {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SavanaError> {
        let validated = ConnectorDescriptorV2::from_canonical_bytes_for_local_projection(bytes)
            .map_err(|_| SavanaError::InvalidRequest)?;
        Ok(Self {
            canonical: validated.canonical_bytes().to_vec(),
            connector_id: validated.connector_id(),
        })
    }
}

impl Session {
    pub fn register_connector(
        &mut self,
        descriptor: &ConnectorDescriptor,
        approval: &dyn ApprovalCallback,
    ) -> Result<Handle, SavanaError> {
        self.require_open()?;
        let opened = self.connector_action(AgentBrowserActionV2::RegisterConnector(
            descriptor.canonical.clone(),
        ))?;
        let (pending, transfer) = match opened {
            AgentBrowserMutationResponseV2::ConnectorOpenApproval { pending, post } => {
                let transfer = match post {
                    FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer) => transfer,
                    _ => return self.invalid_connector_transition(),
                };
                (pending, transfer)
            }
            _ => return self.invalid_connector_transition(),
        };
        let outcome = match self.approve_agent(
            transfer,
            ApprovalPurposeV2::ConnectorRegistration,
            ApprovalPurpose::ConnectorRegistration,
            approval,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        if outcome == ApprovalOutcome::Denied {
            let _cleanup =
                self.agent_action(AgentBrowserActionV2::FinalizeConnectorRegistration(pending));
            self.state = LocalSessionState::Closed;
            return Err(ApprovalDenied.into());
        }
        let committed =
            self.connector_action(AgentBrowserActionV2::FinalizeConnectorRegistration(pending))?;
        match committed {
            AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
                pending: returned_pending,
                sequence,
                connector_id,
                ..
            } if returned_pending == pending
                && sequence != 0
                && connector_id == descriptor.connector_id =>
            {
                self.removed_connectors
                    .retain(|removed| *removed != connector_id);
                Ok(Handle::connector(&self.binding, connector_id))
            }
            _ => self.invalid_connector_transition(),
        }
    }

    /// Connector handles bind a session and connector ID, not a registry
    /// generation. Removal makes that ID stale locally until an authoritative
    /// successful registration or snapshot shows the ID registered again.
    pub fn remove_connector(&mut self, connector: &Handle) -> Result<(), SavanaError> {
        self.require_open()?;
        let connector_id = connector.expect_connector(&self.binding)?;
        if self.removed_connectors.contains(&connector_id) {
            return Err(SavanaError::InvalidState);
        }
        let committed =
            self.connector_action(AgentBrowserActionV2::RemoveConnector(connector_id))?;
        match committed {
            AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
                sequence,
                connector_id: returned,
                ..
            } if sequence != 0 && returned == connector_id => {
                self.removed_connectors.push(connector_id);
                Ok(())
            }
            _ => self.invalid_connector_transition(),
        }
    }

    pub fn list_connectors(&mut self) -> Result<Vec<Handle>, SavanaError> {
        self.require_open()?;
        let snapshot = self.connector_action(AgentBrowserActionV2::SnapshotConnectors)?;
        let canonical = match snapshot {
            AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot { canonical_snapshot } => {
                canonical_snapshot.into_bytes()
            }
            _ => return self.invalid_connector_transition(),
        };
        let connector_ids = match decode_registry_snapshot(&canonical) {
            Ok(connector_ids) => connector_ids,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        for connector_id in &connector_ids {
            self.removed_connectors
                .retain(|removed| removed != connector_id);
        }
        Ok(connector_ids
            .into_iter()
            .map(|connector_id| Handle::connector(&self.binding, connector_id))
            .collect())
    }

    fn connector_action(
        &mut self,
        action: AgentBrowserActionV2,
    ) -> Result<AgentBrowserMutationResponseV2, SavanaError> {
        match self.agent_action(action) {
            Ok(response) => Ok(response),
            Err(error) => {
                self.state = LocalSessionState::Closed;
                Err(error)
            }
        }
    }

    fn invalid_connector_transition<T>(&mut self) -> Result<T, SavanaError> {
        self.state = LocalSessionState::Closed;
        Err(SavanaError::InvalidState)
    }
}

fn decode_registry_snapshot(bytes: &[u8]) -> Result<Vec<Digest32V2>, SavanaError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(|_| SavanaError::InvalidResponse)? != Some(6)
        || decoder.u16().map_err(|_| SavanaError::InvalidResponse)? != 1
    {
        return Err(SavanaError::InvalidResponse);
    }
    let genesis = decode_fixed_32(&mut decoder)?;
    let head = decode_fixed_32(&mut decoder)?;
    let sequence = decoder.u64().map_err(|_| SavanaError::InvalidResponse)?;
    let authority = decode_fixed_32(&mut decoder)?;
    if genesis == [0; 32] || head == [0; 32] || authority == [0; 32] {
        return Err(SavanaError::InvalidResponse);
    }
    let count = decoder
        .array()
        .map_err(|_| SavanaError::InvalidResponse)?
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| {
            u64::try_from(*count).is_ok_and(|count| {
                count <= DeploymentHardLimitsV2::compiled().max_active_tool_descriptors()
            })
        })
        .ok_or(SavanaError::InvalidResponse)?;
    let mut entries = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        if decoder.array().map_err(|_| SavanaError::InvalidResponse)? != Some(2) {
            return Err(SavanaError::InvalidResponse);
        }
        let id = decode_fixed_32(&mut decoder)?;
        let active = decoder.bool().map_err(|_| SavanaError::InvalidResponse)?;
        if id == [0; 32] || previous.is_some_and(|previous| previous >= id) {
            return Err(SavanaError::InvalidResponse);
        }
        previous = Some(id);
        entries.push((id, active));
    }
    if decoder.position() != bytes.len() {
        return Err(SavanaError::InvalidResponse);
    }
    let canonical = encode_registry_snapshot(genesis, head, sequence, authority, &entries)?;
    if canonical != bytes {
        return Err(SavanaError::InvalidResponse);
    }
    Ok(entries
        .into_iter()
        .filter(|(_, active)| *active)
        .map(|(id, _)| Digest32V2::new(id))
        .collect())
}

fn decode_fixed_32(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; 32], SavanaError> {
    decoder
        .bytes()
        .map_err(|_| SavanaError::InvalidResponse)?
        .try_into()
        .map_err(|_| SavanaError::InvalidResponse)
}

fn encode_registry_snapshot(
    genesis: [u8; 32],
    head: [u8; 32],
    sequence: u64,
    authority: [u8; 32],
    entries: &[([u8; 32], bool)],
) -> Result<Vec<u8>, SavanaError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(&genesis))
        .and_then(|encoder| encoder.bytes(&head))
        .and_then(|encoder| encoder.u64(sequence))
        .and_then(|encoder| encoder.bytes(&authority))
        .and_then(|encoder| encoder.array(entries.len() as u64))
        .map_err(|_| SavanaError::InvalidResponse)?;
    for (id, active) in entries {
        encoder
            .array(2)
            .and_then(|encoder| encoder.bytes(id))
            .and_then(|encoder| encoder.bool(*active))
            .map_err(|_| SavanaError::InvalidResponse)?;
    }
    Ok(encoder.into_writer())
}

#[cfg(test)]
mod tests {
    use savana_kernel_protocol::v2::Digest32V2;
    use savana_policy_core::v2::DeploymentHardLimitsV2;

    use super::decode_registry_snapshot;

    fn registry_snapshot(count: usize) -> Vec<u8> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(6)
            .unwrap()
            .u16(1)
            .unwrap()
            .bytes(&[0x31; 32])
            .unwrap()
            .bytes(&[0x32; 32])
            .unwrap()
            .u64(7)
            .unwrap()
            .bytes(&[0x33; 32])
            .unwrap()
            .array(count as u64)
            .unwrap();
        for suffix in 1..=count {
            let mut bytes = [0_u8; 32];
            bytes[24..].copy_from_slice(&(suffix as u64).to_be_bytes());
            encoder
                .array(2)
                .unwrap()
                .bytes(Digest32V2::new(bytes).as_bytes())
                .unwrap()
                .bool(true)
                .unwrap();
        }
        encoder.into_writer()
    }

    #[test]
    fn snapshot_connector_count_uses_the_authoritative_registry_limit() {
        let limit =
            usize::try_from(DeploymentHardLimitsV2::compiled().max_active_tool_descriptors())
                .unwrap();
        let exact = decode_registry_snapshot(&registry_snapshot(limit));
        let overflow = decode_registry_snapshot(&registry_snapshot(limit + 1));

        assert_eq!(exact.unwrap().len(), limit);
        assert!(overflow.is_err());
    }
}
