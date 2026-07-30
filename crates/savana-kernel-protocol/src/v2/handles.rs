use core::fmt;

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use zeroize::Zeroize as _;

use crate::StableCode;

use super::{cbor::V2DecodeContext, Digest32V2};

const HANDLE_COMMITMENT_DOMAIN: &[u8] = b"SAVANA_OPAQUE_HANDLE_COMMITMENT_V2\0";

pub struct AuthorityHandleKeyV2([u8; 32]);

impl AuthorityHandleKeyV2 {
    pub fn from_entropy(bytes: [u8; 32]) -> Option<Self> {
        if bytes == [0; 32] {
            None
        } else {
            Some(Self(bytes))
        }
    }
}

impl fmt::Debug for AuthorityHandleKeyV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityHandleKeyV2(<redacted>)")
    }
}

impl Drop for AuthorityHandleKeyV2 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

macro_rules! opaque_bytes_v2 {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn from_authority_entropy(bytes: [u8; 32]) -> Option<Self> {
                if bytes == [0; 32] {
                    None
                } else {
                    Some(Self(bytes))
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                let bytes = <[u8; 32]>::try_from(decoder.bytes()?).map_err(|_| {
                    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                        .at(position)
                })?;
                Ok(Self::from_bytes(bytes))
            }
        }
    };
}

opaque_bytes_v2!(TaskHandleV2);
opaque_bytes_v2!(JarvisBootstrapSelectorV2);

macro_rules! kernel_handle_v2 {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const TYPE_DOMAIN: &'static [u8] = $domain;

            pub fn from_authority_entropy(bytes: [u8; 32]) -> Option<Self> {
                if bytes == [0; 32] {
                    None
                } else {
                    Some(Self(bytes))
                }
            }

            pub fn authority_commitment(self, key: &AuthorityHandleKeyV2) -> Digest32V2 {
                let mut mac = Hmac::<Sha256>::new_from_slice(&key.0)
                    .expect("HMAC-SHA256 accepts a 32-byte key");
                mac.update(HANDLE_COMMITMENT_DOMAIN);
                mac.update(Self::TYPE_DOMAIN);
                mac.update(&self.0);
                Digest32V2::new(mac.finalize().into_bytes().into())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                let bytes = <[u8; 32]>::try_from(decoder.bytes()?).map_err(|_| {
                    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                        .at(position)
                })?;
                Self::from_authority_entropy(bytes).ok_or_else(|| {
                    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                        .at(position)
                })
            }
        }
    };
}

macro_rules! browser_reference_v2 {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const TYPE_DOMAIN: &'static [u8] = $domain;

            pub fn from_authority_entropy(bytes: [u8; 16]) -> Option<Self> {
                if bytes == [0; 16] {
                    None
                } else {
                    Some(Self(bytes))
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                let bytes = <[u8; 16]>::try_from(decoder.bytes()?).map_err(|_| {
                    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                        .at(position)
                })?;
                Self::from_authority_entropy(bytes).ok_or_else(|| {
                    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                        .at(position)
                })
            }
        }
    };
}

kernel_handle_v2!(AgentSessionHandleV2, b"SAVANA_AGENT_SESSION_HANDLE_V2\0");
kernel_handle_v2!(RunHandleV2, b"SAVANA_RUN_HANDLE_V2\0");
kernel_handle_v2!(ValueHandleV2, b"SAVANA_VALUE_HANDLE_V2\0");
kernel_handle_v2!(
    NewTaskPreparationHandleV2,
    b"SAVANA_NEW_TASK_PREPARATION_HANDLE_V2\0"
);
kernel_handle_v2!(
    AgentUiAuthenticationPreparationHandleV2,
    b"SAVANA_AGENT_UI_AUTH_PREPARATION_HANDLE_V2\0"
);
kernel_handle_v2!(
    IngressUiAuthenticationPreparationHandleV2,
    b"SAVANA_INGRESS_UI_AUTH_PREPARATION_HANDLE_V2\0"
);
kernel_handle_v2!(
    KernelIngressBootstrapTransferCapabilityV2,
    b"SAVANA_KERNEL_INGRESS_BOOTSTRAP_TRANSFER_V2\0"
);
kernel_handle_v2!(
    IngressUiAuthorizationHandleV2,
    b"SAVANA_INGRESS_UI_AUTHORIZATION_HANDLE_V2\0"
);
kernel_handle_v2!(
    AgentUiAuthorizationHandleV2,
    b"SAVANA_AGENT_UI_AUTHORIZATION_HANDLE_V2\0"
);
kernel_handle_v2!(
    IngressWriteCapabilityV2,
    b"SAVANA_INGRESS_WRITE_CAPABILITY_V2\0"
);
kernel_handle_v2!(InputSessionHandleV2, b"SAVANA_INPUT_SESSION_HANDLE_V2\0");
kernel_handle_v2!(
    ParserExtractionHandleV2,
    b"SAVANA_PARSER_EXTRACTION_HANDLE_V2\0"
);
kernel_handle_v2!(
    PendingIngressHandleV2,
    b"SAVANA_PENDING_INGRESS_HANDLE_V2\0"
);
kernel_handle_v2!(
    MaskedDocumentHandleV2,
    b"SAVANA_MASKED_DOCUMENT_HANDLE_V2\0"
);
kernel_handle_v2!(PlanStepHandleV2, b"SAVANA_PLAN_STEP_HANDLE_V2\0");
kernel_handle_v2!(PlannerTicketHandleV2, b"SAVANA_PLANNER_TICKET_HANDLE_V2\0");
kernel_handle_v2!(ToolHandleV2, b"SAVANA_TOOL_HANDLE_V2\0");
kernel_handle_v2!(ActionIntentHandleV2, b"SAVANA_ACTION_INTENT_HANDLE_V2\0");
kernel_handle_v2!(
    PendingToolCallHandleV2,
    b"SAVANA_PENDING_TOOL_CALL_HANDLE_V2\0"
);
kernel_handle_v2!(
    IngressKernelApprovalHandleV2,
    b"SAVANA_INGRESS_KERNEL_APPROVAL_HANDLE_V2\0"
);
kernel_handle_v2!(
    ToolKernelApprovalHandleV2,
    b"SAVANA_TOOL_KERNEL_APPROVAL_HANDLE_V2\0"
);
kernel_handle_v2!(
    ReleaseKernelApprovalHandleV2,
    b"SAVANA_RELEASE_KERNEL_APPROVAL_HANDLE_V2\0"
);
kernel_handle_v2!(
    ExecutionTicketHandleV2,
    b"SAVANA_EXECUTION_TICKET_HANDLE_V2\0"
);
kernel_handle_v2!(ExecutionHandleV2, b"SAVANA_EXECUTION_HANDLE_V2\0");
kernel_handle_v2!(
    PendingReleaseHandleV2,
    b"SAVANA_PENDING_RELEASE_HANDLE_V2\0"
);
kernel_handle_v2!(ReleaseTicketHandleV2, b"SAVANA_RELEASE_TICKET_HANDLE_V2\0");
kernel_handle_v2!(ReleaseHandleV2, b"SAVANA_RELEASE_HANDLE_V2\0");
kernel_handle_v2!(
    KernelAgentViewCursorV2,
    b"SAVANA_KERNEL_AGENT_VIEW_CURSOR_V2\0"
);
kernel_handle_v2!(
    ApprovalUiRecordHandleV2,
    b"SAVANA_APPROVAL_UI_RECORD_HANDLE_V2\0"
);
kernel_handle_v2!(
    IngressApprovalRecordHandleV2,
    b"SAVANA_INGRESS_APPROVAL_RECORD_HANDLE_V2\0"
);
kernel_handle_v2!(
    ToolApprovalRecordHandleV2,
    b"SAVANA_TOOL_APPROVAL_RECORD_HANDLE_V2\0"
);
kernel_handle_v2!(
    ReleaseApprovalRecordHandleV2,
    b"SAVANA_RELEASE_APPROVAL_RECORD_HANDLE_V2\0"
);
kernel_handle_v2!(
    IngressUiAuthenticationTransferCapabilityV2,
    b"SAVANA_INGRESS_UI_AUTH_TRANSFER_V2\0"
);
kernel_handle_v2!(
    IngressUiAuthenticationSettlementTransferCapabilityV2,
    b"SAVANA_INGRESS_UI_AUTH_SETTLEMENT_TRANSFER_V2\0"
);
kernel_handle_v2!(
    AgentUiAuthenticationTransferCapabilityV2,
    b"SAVANA_AGENT_UI_AUTH_TRANSFER_V2\0"
);
kernel_handle_v2!(
    AgentUiAuthenticationSettlementTransferCapabilityV2,
    b"SAVANA_AGENT_UI_AUTH_SETTLEMENT_TRANSFER_V2\0"
);
kernel_handle_v2!(
    ApprovalDisplayAuthenticationTransferCapabilityV2,
    b"SAVANA_APPROVAL_DISPLAY_AUTH_TRANSFER_V2\0"
);
kernel_handle_v2!(
    ApprovalTabSessionCapabilityV2,
    b"SAVANA_APPROVAL_TAB_SESSION_V2\0"
);
kernel_handle_v2!(
    IngressUiPreAuthenticationTabCapabilityV2,
    b"SAVANA_INGRESS_UI_PREAUTH_TAB_V2\0"
);
kernel_handle_v2!(
    AgentUiPreAuthenticationTabCapabilityV2,
    b"SAVANA_AGENT_UI_PREAUTH_TAB_V2\0"
);
kernel_handle_v2!(
    ApprovalDisplayUiPreAuthenticationTabCapabilityV2,
    b"SAVANA_APPROVAL_DISPLAY_UI_PREAUTH_TAB_V2\0"
);
kernel_handle_v2!(
    IngressUiAuthenticationBrowserCeremonyCapabilityV2,
    b"SAVANA_INGRESS_UI_AUTH_BROWSER_CEREMONY_V2\0"
);
kernel_handle_v2!(
    AgentUiAuthenticationBrowserCeremonyCapabilityV2,
    b"SAVANA_AGENT_UI_AUTH_BROWSER_CEREMONY_V2\0"
);
kernel_handle_v2!(
    ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
    b"SAVANA_APPROVAL_DISPLAY_UI_AUTH_BROWSER_CEREMONY_V2\0"
);
kernel_handle_v2!(
    IngressTabSessionCapabilityV2,
    b"SAVANA_INGRESS_TAB_SESSION_V2\0"
);
kernel_handle_v2!(
    AgentTabSessionCapabilityV2,
    b"SAVANA_AGENT_TAB_SESSION_V2\0"
);
browser_reference_v2!(
    AgentMaskedDocumentRefV2,
    b"SAVANA_AGENT_MASKED_DOCUMENT_REF_V2\0"
);
browser_reference_v2!(
    AgentBrowserViewCursorCapabilityV2,
    b"SAVANA_AGENT_BROWSER_VIEW_CURSOR_V2\0"
);
browser_reference_v2!(AgentPlanStepRefV2, b"SAVANA_AGENT_PLAN_STEP_REF_V2\0");
browser_reference_v2!(
    AgentPendingToolCallRefV2,
    b"SAVANA_AGENT_PENDING_TOOL_CALL_REF_V2\0"
);
browser_reference_v2!(
    AgentExecutionTicketRefV2,
    b"SAVANA_AGENT_EXECUTION_TICKET_REF_V2\0"
);
browser_reference_v2!(
    AgentReleaseTicketRefV2,
    b"SAVANA_AGENT_RELEASE_TICKET_REF_V2\0"
);
browser_reference_v2!(AgentExecutionRefV2, b"SAVANA_AGENT_EXECUTION_REF_V2\0");
browser_reference_v2!(AgentReleaseRefV2, b"SAVANA_AGENT_RELEASE_REF_V2\0");
kernel_handle_v2!(
    ApprovalDecisionCeremonyCapabilityV2,
    b"SAVANA_APPROVAL_DECISION_CEREMONY_V2\0"
);
kernel_handle_v2!(EnrollmentHandleV2, b"SAVANA_ENROLLMENT_HANDLE_V2\0");
kernel_handle_v2!(
    EnrollmentCeremonyCapabilityV2,
    b"SAVANA_ENROLLMENT_CEREMONY_V2\0"
);

impl InputSessionHandleV2 {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl JarvisBootstrapSelectorV2 {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl KernelIngressBootstrapTransferCapabilityV2 {
    pub(crate) const fn transfer_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl IngressUiAuthenticationTransferCapabilityV2 {
    pub(crate) const fn transfer_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AgentUiAuthenticationTransferCapabilityV2 {
    pub(crate) const fn transfer_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ApprovalDisplayAuthenticationTransferCapabilityV2 {
    pub(crate) const fn transfer_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentSessionHandleV2, AuthorityHandleKeyV2, RunHandleV2};

    #[test]
    fn authority_commitments_are_keyed_and_handle_type_separated() {
        let key = AuthorityHandleKeyV2::from_entropy([0x41; 32]).unwrap();
        let other_key = AuthorityHandleKeyV2::from_entropy([0x42; 32]).unwrap();
        let session = AgentSessionHandleV2::from_authority_entropy([0x51; 32]).unwrap();
        let run = RunHandleV2::from_authority_entropy([0x51; 32]).unwrap();

        assert_ne!(
            session.authority_commitment(&key),
            run.authority_commitment(&key)
        );
        assert_ne!(
            session.authority_commitment(&key),
            session.authority_commitment(&other_key)
        );
        assert_eq!(format!("{key:?}"), "AuthorityHandleKeyV2(<redacted>)");
    }
}
