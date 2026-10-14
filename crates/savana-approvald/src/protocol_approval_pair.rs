//! Immutable approval/display delivery binding. No user decision is synthesized.
use super::*;

pub(super) fn validate_pair_material(
    role: EndpointRoleV2,
    approval: &UnsignedApprovalEnvelopeV2,
    display: UnsignedUiAuthenticationEnvelopeV2,
    approval_digest: Digest32V2,
) -> Result<(), ApprovalErrorV2> {
    let role_matches = matches!(
        (role, approval.purpose()),
        (
            EndpointRoleV2::IngressApproval,
            ProtocolApprovalPurposeV2::Ingress | ProtocolApprovalPurposeV2::TaskAuthorization
        ) | (
            EndpointRoleV2::AgentApproval,
            ProtocolApprovalPurposeV2::ToolExecution
                | ProtocolApprovalPurposeV2::FinalRelease
                | ProtocolApprovalPurposeV2::ConnectorRegistration
        )
    ) || (role == EndpointRoleV2::KernelApproval
        && matches!(
            approval.purpose(),
            ProtocolApprovalPurposeV2::ToolExecution | ProtocolApprovalPurposeV2::FinalRelease
        )
        && approval.task_action_binding().is_some());
    let binding_matches = matches!(display.binding(),
    UiAuthenticationBindingV2::ApprovalDisplay { durable_task_id, approval_envelope_digest, approval_purpose, display_digest }
    if approval_envelope_digest == approval_digest && approval_purpose == approval.purpose()
        && display_digest == approval.display_digest()
        && approval.task_action_binding().is_none_or(|binding| binding.task() == durable_task_id)
        && match approval.binding() {
            savana_kernel_protocol::v2::ApprovalBindingV2::TaskAuthorization { task, .. } => task == durable_task_id,
            _ => true,
        });
    if !role_matches
        || !binding_matches
        || display.purpose() != UiAuthenticationPurposeV2::ApprovalDisplay
        || display.expected_principal() != Some(approval.expected_principal())
        || display.issued_at().get() < approval.issued_at().get()
        || display.expires_at().get() > approval.expires_at().get()
    {
        return Err(ApprovalErrorV2::InvalidChallenge);
    }
    Ok(())
}

fn display_approval(display: UnsignedUiAuthenticationEnvelopeV2) -> Option<Digest32V2> {
    match display.binding() {
        UiAuthenticationBindingV2::ApprovalDisplay {
            approval_envelope_digest,
            ..
        } => Some(approval_envelope_digest),
        _ => None,
    }
}

impl ProtocolApprovalServiceV2 {
    pub(super) fn check_approval_delivery_binding(
        &self,
        approval: Digest32V2,
        binding: ApprovalDeliveryBindingV2,
    ) -> Result<(), ApprovalErrorV2> {
        if self.approval_envelopes.iter().any(|r| {
            r.envelope_digest == approval
                && r.delivery_binding.is_some_and(|saved| saved != binding)
        }) || self.ui_authentication_envelopes.iter().any(|r| {
            display_approval(r.unsigned) == Some(approval)
                && r.envelope_digest != binding.display_envelope_digest
        }) {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        Ok(())
    }

    pub(super) fn check_display_delivery_binding(
        &self,
        display: &UnsignedUiAuthenticationEnvelopeV2,
        display_digest: Digest32V2,
    ) -> Result<(), ApprovalErrorV2> {
        let Some(approval) = display_approval(*display) else {
            return Ok(());
        };
        // Also close the standalone UI-registration route: it must not renew a
        // paired display challenge or create an ambiguous legacy pairing.
        if self.approval_envelopes.iter().any(|r| {
            r.envelope_digest == approval
                && r.delivery_binding
                    .is_some_and(|b| b.display_envelope_digest != display_digest)
        }) || self.ui_authentication_envelopes.iter().any(|r| {
            display_approval(r.unsigned) == Some(approval) && r.envelope_digest != display_digest
        }) {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        Ok(())
    }

    pub(super) fn restore_approval_delivery_bindings(
        &mut self,
        schema: u16,
    ) -> Result<(), ApprovalErrorV2> {
        for record in &mut self.approval_envelopes {
            let mut displays = self
                .ui_authentication_envelopes
                .iter()
                .filter(|r| display_approval(r.unsigned) == Some(record.envelope_digest));
            let display = displays.next();
            if displays.next().is_some() {
                return Err(ApprovalErrorV2::DurableState);
            }
            if schema == 4 {
                // Old images do not record a role. Infer only from an existing,
                // uniquely paired signed display and today's closed purpose map.
                // Never select an arbitrary display or create missing material.
                if let Some(display) = display {
                    let role = match record.unsigned.purpose() {
                        ProtocolApprovalPurposeV2::Ingress
                        | ProtocolApprovalPurposeV2::TaskAuthorization => {
                            EndpointRoleV2::IngressApproval
                        }
                        ProtocolApprovalPurposeV2::ToolExecution
                        | ProtocolApprovalPurposeV2::FinalRelease
                        | ProtocolApprovalPurposeV2::ConnectorRegistration => {
                            EndpointRoleV2::AgentApproval
                        }
                    };
                    record.delivery_binding = Some(ApprovalDeliveryBindingV2 {
                        role,
                        display_envelope_digest: display.envelope_digest,
                    });
                }
            }
            if let Some(binding) = record.delivery_binding {
                let display = display.ok_or(ApprovalErrorV2::DurableState)?;
                if binding.display_envelope_digest != display.envelope_digest {
                    return Err(ApprovalErrorV2::DurableState);
                }
                validate_pair_material(
                    binding.role,
                    &record.unsigned,
                    display.unsigned,
                    record.envelope_digest,
                )
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            }
        }
        Ok(())
    }
}

pub(super) fn encode_delivery_binding(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    binding: Option<ApprovalDeliveryBindingV2>,
) -> Result<(), ApprovalErrorV2> {
    match binding {
        Some(binding) => encoder
            .array(2)
            .and_then(|e| e.u16(binding.role.tag()))
            .and_then(|e| e.bytes(binding.display_envelope_digest.as_bytes())),
        None => encoder.null(),
    }
    .map(|_| ())
    .map_err(|_| ApprovalErrorV2::AllocationFailure)
}

pub(super) fn decode_delivery_binding(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<ApprovalDeliveryBindingV2>, ApprovalErrorV2> {
    if decoder
        .datatype()
        .map_err(|_| ApprovalErrorV2::DurableState)?
        == minicbor::data::Type::Null
    {
        decoder.null().map_err(|_| ApprovalErrorV2::DurableState)?;
        return Ok(None);
    }
    require_array(decoder, 2)?;
    let role = match decoder.u16().map_err(|_| ApprovalErrorV2::DurableState)? {
        5 => EndpointRoleV2::AgentApproval,
        6 => EndpointRoleV2::IngressApproval,
        8 => EndpointRoleV2::KernelApproval,
        _ => return Err(ApprovalErrorV2::DurableState),
    };
    Ok(Some(ApprovalDeliveryBindingV2 {
        role,
        display_envelope_digest: Digest32V2::new(decode_fixed::<32>(decoder)?),
    }))
}
