use crate::{ProtocolError, StableCode};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{
    cbor::{scan_single, V2DecodeContext},
    derive_ed25519_key_id_v2, ActionIntentIdV2, BootIdV2, Digest32V2, DurableRunIdV2,
    DurableTaskIdV2, Ed25519KeyIdV2, Ed25519SignatureV2, FinalReleaseSemanticBindingV2,
    FixedOriginV2, Nonce32V2, PrincipalIdV2, RunRevisionDigestV2, ServiceIdentityV2,
    ToolExecutionSemanticBindingV2, UnixMillisV2,
};

const MAX_SIGNED_PAYLOAD_BYTES_V2: usize = 8 * 1024;
const MAX_APPROVAL_SIGNED_PAYLOAD_BYTES_V2: usize = 1024 * 1024 + 8 * 1024;
const MAX_APPROVAL_DISPLAY_BYTES_V2: usize = 1024 * 1024;
const APPROVAL_DISPLAY_DIGEST_DOMAIN_V2: &[u8] = b"SAVANA_APPROVAL_DISPLAY_BYTES_V2\0";
const INGRESS_APPROVAL_ENVELOPE_DOMAIN_V2: &[u8] = b"SAVANA_INGRESS_APPROVAL_ENVELOPE_V2\0";
const TOOL_APPROVAL_ENVELOPE_DOMAIN_V2: &[u8] = b"SAVANA_TOOL_APPROVAL_ENVELOPE_V2\0";
const RELEASE_APPROVAL_ENVELOPE_DOMAIN_V2: &[u8] = b"SAVANA_RELEASE_APPROVAL_ENVELOPE_V2\0";
const UI_AUTH_INGRESS_ENVELOPE_DOMAIN_V2: &[u8] = b"SAVANA_UI_AUTH_INGRESS_ENVELOPE_V2\0";
const UI_AUTH_APPROVAL_DISPLAY_ENVELOPE_DOMAIN_V2: &[u8] =
    b"SAVANA_UI_AUTH_APPROVAL_DISPLAY_ENVELOPE_V2\0";
const UI_AUTH_AGENT_ENVELOPE_DOMAIN_V2: &[u8] = b"SAVANA_UI_AUTH_AGENT_ENVELOPE_V2\0";
const UI_AUTH_BINDING_DOMAIN_V2: &[u8] = b"SAVANA_UI_AUTH_BINDING_V2\0";
const APPROVAL_BINDING_DOMAIN_V2: &[u8] = b"SAVANA_APPROVAL_BINDING_V2\0";
const UI_AUTH_INGRESS_SETTLEMENT_DOMAIN_V2: &[u8] = b"SAVANA_UI_AUTH_INGRESS_SETTLEMENT_V2\0";
const UI_AUTH_APPROVAL_DISPLAY_SETTLEMENT_DOMAIN_V2: &[u8] =
    b"SAVANA_UI_AUTH_APPROVAL_DISPLAY_SETTLEMENT_V2\0";
const UI_AUTH_AGENT_SETTLEMENT_DOMAIN_V2: &[u8] = b"SAVANA_UI_AUTH_AGENT_SETTLEMENT_V2\0";
const INGRESS_APPROVAL_SETTLEMENT_DOMAIN_V2: &[u8] = b"SAVANA_INGRESS_APPROVAL_SETTLEMENT_V2\0";
const TOOL_APPROVAL_SETTLEMENT_DOMAIN_V2: &[u8] = b"SAVANA_TOOL_APPROVAL_SETTLEMENT_V2\0";
const RELEASE_APPROVAL_SETTLEMENT_DOMAIN_V2: &[u8] = b"SAVANA_RELEASE_APPROVAL_SETTLEMENT_V2\0";
const AGENT_AUTHENTICATION_CLOSURE_DESCRIPTOR_DOMAIN_V2: &[u8] =
    b"SAVANA_AGENT_AUTH_CLOSURE_DESCRIPTOR_V2\0";
const AGENT_AUTHENTICATION_CLOSURE_DESCRIPTOR_DIGEST_DOMAIN_V2: &[u8] =
    b"SAVANA_AGENT_AUTH_CLOSURE_DESCRIPTOR_DIGEST_V2\0";
const AGENT_AUTHENTICATION_ATTEMPT_CLOSURE_PROOF_DOMAIN_V2: &[u8] =
    b"SAVANA_AGENT_AUTH_ATTEMPT_CLOSURE_PROOF_V2\0";

macro_rules! signed_kernel_envelope_v2 {
    ($name:ident, $maximum_payload_bytes:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            canonical_payload: Vec<u8>,
            key_id: Ed25519KeyIdV2,
            signature: Ed25519SignatureV2,
        }

        impl $name {
            pub fn from_canonical_parts(
                canonical_payload: Vec<u8>,
                key_id: Ed25519KeyIdV2,
                signature: Ed25519SignatureV2,
            ) -> Result<Self, ProtocolError> {
                if canonical_payload.is_empty()
                    || canonical_payload.len() > $maximum_payload_bytes
                    || is_zero(key_id.as_bytes())
                    || is_zero(signature.as_bytes())
                {
                    return Err(malformed());
                }
                scan_single(&canonical_payload)?;
                Ok(Self {
                    canonical_payload,
                    key_id,
                    signature,
                })
            }

            pub fn canonical_payload(&self) -> &[u8] {
                &self.canonical_payload
            }

            pub const fn key_id(&self) -> Ed25519KeyIdV2 {
                self.key_id
            }

            pub const fn signature(&self) -> Ed25519SignatureV2 {
                self.signature
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder
                    .array(3)?
                    .bytes(&self.canonical_payload)?
                    .bytes(self.key_id.as_bytes())?
                    .bytes(self.signature.as_bytes())?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some(3) {
                    return Err(decode_error(position));
                }
                let payload = decoder.bytes()?;
                if payload.is_empty() || payload.len() > $maximum_payload_bytes {
                    return Err(decode_error(position));
                }
                let canonical_payload = payload.to_vec();
                let key_id = Ed25519KeyIdV2::new(
                    decoder
                        .bytes()?
                        .try_into()
                        .map_err(|_| decode_error(position))?,
                );
                let signature = Ed25519SignatureV2::new(
                    decoder
                        .bytes()?
                        .try_into()
                        .map_err(|_| decode_error(position))?,
                );
                Self::from_canonical_parts(canonical_payload, key_id, signature)
                    .map_err(|_| decode_error(position))
            }
        }
    };
}

signed_kernel_envelope_v2!(
    SignedApprovalEnvelopeV2,
    MAX_APPROVAL_SIGNED_PAYLOAD_BYTES_V2
);
signed_kernel_envelope_v2!(
    SignedUiAuthenticationEnvelopeV2,
    MAX_SIGNED_PAYLOAD_BYTES_V2
);

pub fn approval_display_digest_v2(display_bytes: &[u8]) -> Digest32V2 {
    domain_hash(APPROVAL_DISPLAY_DIGEST_DOMAIN_V2, display_bytes)
}

macro_rules! closed_unit_enum_v2 {
    (
        $name:ident {
            $($variant:ident = $tag:literal),+ $(,)?
        }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn tag(self) -> u16 {
                match self {
                    $(Self::$variant => $tag),+
                }
            }

            fn from_tag(tag: u16) -> Result<Self, ProtocolError> {
                match tag {
                    $($tag => Ok(Self::$variant)),+,
                    _ => Err(malformed()),
                }
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array(1)?.u16(self.tag())?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some(1) {
                    return Err(decode_error(position));
                }
                Self::from_tag(decoder.u16()?).map_err(|_| decode_error(position))
            }
        }
    };
}

closed_unit_enum_v2! {
    ApprovalPurposeV2 {
        Ingress = 1,
        ToolExecution = 2,
        FinalRelease = 3,
    }
}

closed_unit_enum_v2! {
    AgentAuthenticationInitialTransferTerminalStateV2 {
        NeverRedeemedTerminal = 1,
        ConsumedIntoTerminalizedCeremony = 2,
        Indeterminate = 3,
    }
}

closed_unit_enum_v2! {
    AgentAuthenticationSettlementTerminalStateV2 {
        NotCreated = 1,
        StoredNeverExportedInvalidated = 2,
        ExportedOrTransferRedeemed = 3,
        Indeterminate = 4,
    }
}

closed_unit_enum_v2! {
    AgentAuthenticationSettlementTransferTerminalStateV2 {
        NotCreated = 1,
        TerminalUnredeemed = 2,
        Redeemed = 3,
        Indeterminate = 4,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentAuthenticationTransferTerminalStateV2 {
    initial_transfer_record_digest: Digest32V2,
    initial_transfer_state: AgentAuthenticationInitialTransferTerminalStateV2,
    ceremony_record_digest: Option<Digest32V2>,
    settlement_record_digest: Option<Digest32V2>,
    settlement_state: AgentAuthenticationSettlementTerminalStateV2,
    settlement_transfer_record_digest: Option<Digest32V2>,
    settlement_transfer_state: AgentAuthenticationSettlementTransferTerminalStateV2,
}

impl AgentAuthenticationTransferTerminalStateV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initial_transfer_record_digest: Digest32V2,
        initial_transfer_state: AgentAuthenticationInitialTransferTerminalStateV2,
        ceremony_record_digest: Option<Digest32V2>,
        settlement_record_digest: Option<Digest32V2>,
        settlement_state: AgentAuthenticationSettlementTerminalStateV2,
        settlement_transfer_record_digest: Option<Digest32V2>,
        settlement_transfer_state: AgentAuthenticationSettlementTransferTerminalStateV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(initial_transfer_record_digest.as_bytes())
            || option_is_zero(ceremony_record_digest)
            || option_is_zero(settlement_record_digest)
            || option_is_zero(settlement_transfer_record_digest)
        {
            return Err(malformed());
        }
        Ok(Self {
            initial_transfer_record_digest,
            initial_transfer_state,
            ceremony_record_digest,
            settlement_record_digest,
            settlement_state,
            settlement_transfer_record_digest,
            settlement_transfer_state,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentAuthenticationClosureEvidenceV2 {
    NeverRegisteredDenylisted {
        complete_index_generation: u64,
        current_journal_head_digest: Digest32V2,
        denylist_tombstone_sequence: u64,
        denylist_tombstone_digest: Digest32V2,
        approvald_key_epoch: u64,
    },
    RegisteredInvalidatedUnredeemed {
        approval_record_digest: Digest32V2,
        ceremony_record_digest: Digest32V2,
        transfer_state: AgentAuthenticationTransferTerminalStateV2,
        approvald_terminal_transaction_digest: Digest32V2,
        complete_index_generation: u64,
        current_journal_head_digest: Digest32V2,
        denylist_tombstone_sequence: u64,
        denylist_tombstone_digest: Digest32V2,
        approvald_key_epoch: u64,
    },
    SettlementOrTransferObserved {
        approval_record_digest: Digest32V2,
        ceremony_record_digest: Digest32V2,
        transfer_state: AgentAuthenticationTransferTerminalStateV2,
        settlement_digest: Digest32V2,
        complete_index_generation: u64,
        current_journal_head_digest: Digest32V2,
        approvald_key_epoch: u64,
    },
    Indeterminate {
        observation_digest: Digest32V2,
        complete_index_generation: u64,
        current_journal_head_digest: Digest32V2,
        approvald_key_epoch: u64,
    },
}

impl AgentAuthenticationClosureEvidenceV2 {
    fn validate(self) -> Result<Self, ProtocolError> {
        let valid = match self {
            Self::NeverRegisteredDenylisted {
                complete_index_generation,
                current_journal_head_digest,
                denylist_tombstone_sequence,
                denylist_tombstone_digest,
                approvald_key_epoch,
            } => {
                complete_index_generation > 0
                    && !is_zero(current_journal_head_digest.as_bytes())
                    && denylist_tombstone_sequence > 0
                    && !is_zero(denylist_tombstone_digest.as_bytes())
                    && approvald_key_epoch > 0
            }
            Self::RegisteredInvalidatedUnredeemed {
                approval_record_digest,
                ceremony_record_digest,
                approvald_terminal_transaction_digest,
                complete_index_generation,
                current_journal_head_digest,
                denylist_tombstone_sequence,
                denylist_tombstone_digest,
                approvald_key_epoch,
                ..
            } => {
                !is_zero(approval_record_digest.as_bytes())
                    && !is_zero(ceremony_record_digest.as_bytes())
                    && !is_zero(approvald_terminal_transaction_digest.as_bytes())
                    && complete_index_generation > 0
                    && !is_zero(current_journal_head_digest.as_bytes())
                    && denylist_tombstone_sequence > 0
                    && !is_zero(denylist_tombstone_digest.as_bytes())
                    && approvald_key_epoch > 0
            }
            Self::SettlementOrTransferObserved {
                approval_record_digest,
                ceremony_record_digest,
                settlement_digest,
                complete_index_generation,
                current_journal_head_digest,
                approvald_key_epoch,
                ..
            } => {
                !is_zero(approval_record_digest.as_bytes())
                    && !is_zero(ceremony_record_digest.as_bytes())
                    && !is_zero(settlement_digest.as_bytes())
                    && complete_index_generation > 0
                    && !is_zero(current_journal_head_digest.as_bytes())
                    && approvald_key_epoch > 0
            }
            Self::Indeterminate {
                observation_digest,
                complete_index_generation,
                current_journal_head_digest,
                approvald_key_epoch,
            } => {
                !is_zero(observation_digest.as_bytes())
                    && complete_index_generation > 0
                    && !is_zero(current_journal_head_digest.as_bytes())
                    && approvald_key_epoch > 0
            }
        };
        if !valid {
            return Err(malformed());
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedAgentAuthenticationClosureDescriptorV2 {
    installation_id: Digest32V2,
    attempt_manifest_digest: Digest32V2,
    attempt_deployment_generation: u64,
    closure_issuing_manifest_digest: Digest32V2,
    closure_issuing_deployment_generation: u64,
    agent_claim_compatibility_edge_identity_digest: Option<Digest32V2>,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    signed_correlation_digest: Digest32V2,
    claim_commitment_digest: Digest32V2,
    authenticated_principal: PrincipalIdV2,
    agentd_identity: ServiceIdentityV2,
    originating_agentd_boot_id: BootIdV2,
    kerneld_identity: ServiceIdentityV2,
    originating_kerneld_boot_id: BootIdV2,
    approvald_identity: ServiceIdentityV2,
    auth_attempt_nonce: Nonce32V2,
    authentication_recovery_record_digest: Digest32V2,
    authentication_preparation_hash: Digest32V2,
    authentication_envelope_digest: Digest32V2,
    closure_nonce: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl UnsignedAgentAuthenticationClosureDescriptorV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        attempt_manifest_digest: Digest32V2,
        attempt_deployment_generation: u64,
        closure_issuing_manifest_digest: Digest32V2,
        closure_issuing_deployment_generation: u64,
        agent_claim_compatibility_edge_identity_digest: Option<Digest32V2>,
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        signed_correlation_digest: Digest32V2,
        claim_commitment_digest: Digest32V2,
        authenticated_principal: PrincipalIdV2,
        agentd_identity: ServiceIdentityV2,
        originating_agentd_boot_id: BootIdV2,
        kerneld_identity: ServiceIdentityV2,
        originating_kerneld_boot_id: BootIdV2,
        approvald_identity: ServiceIdentityV2,
        auth_attempt_nonce: Nonce32V2,
        authentication_recovery_record_digest: Digest32V2,
        authentication_preparation_hash: Digest32V2,
        authentication_envelope_digest: Digest32V2,
        closure_nonce: Nonce32V2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        let same_deployment = attempt_manifest_digest == closure_issuing_manifest_digest
            && attempt_deployment_generation == closure_issuing_deployment_generation;
        let compatibility_is_canonical = if same_deployment {
            agent_claim_compatibility_edge_identity_digest.is_none()
        } else {
            agent_claim_compatibility_edge_identity_digest
                .is_some_and(|digest| !is_zero(digest.as_bytes()))
        };
        if !compatibility_is_canonical
            || [
                installation_id.as_bytes(),
                attempt_manifest_digest.as_bytes(),
                closure_issuing_manifest_digest.as_bytes(),
                durable_task_id.as_bytes(),
                durable_run_id.as_bytes(),
                signed_correlation_digest.as_bytes(),
                claim_commitment_digest.as_bytes(),
                authenticated_principal.as_bytes(),
                agentd_identity.as_bytes(),
                originating_agentd_boot_id.as_bytes(),
                kerneld_identity.as_bytes(),
                originating_kerneld_boot_id.as_bytes(),
                approvald_identity.as_bytes(),
                auth_attempt_nonce.as_bytes(),
                authentication_recovery_record_digest.as_bytes(),
                authentication_preparation_hash.as_bytes(),
                authentication_envelope_digest.as_bytes(),
                closure_nonce.as_bytes(),
            ]
            .iter()
            .any(|bytes| is_zero(*bytes))
            || attempt_deployment_generation == 0
            || closure_issuing_deployment_generation == 0
            || issued_at.get() == 0
            || issued_at.get() >= expires_at.get()
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            attempt_manifest_digest,
            attempt_deployment_generation,
            closure_issuing_manifest_digest,
            closure_issuing_deployment_generation,
            agent_claim_compatibility_edge_identity_digest,
            durable_task_id,
            durable_run_id,
            signed_correlation_digest,
            claim_commitment_digest,
            authenticated_principal,
            agentd_identity,
            originating_agentd_boot_id,
            kerneld_identity,
            originating_kerneld_boot_id,
            approvald_identity,
            auth_attempt_nonce,
            authentication_recovery_record_digest,
            authentication_preparation_hash,
            authentication_envelope_digest,
            closure_nonce,
            issued_at,
            expires_at,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn attempt_manifest_digest(self) -> Digest32V2 {
        self.attempt_manifest_digest
    }

    pub const fn attempt_deployment_generation(self) -> u64 {
        self.attempt_deployment_generation
    }

    pub const fn closure_issuing_manifest_digest(self) -> Digest32V2 {
        self.closure_issuing_manifest_digest
    }

    pub const fn closure_issuing_deployment_generation(self) -> u64 {
        self.closure_issuing_deployment_generation
    }

    pub const fn agent_claim_compatibility_edge_identity_digest(self) -> Option<Digest32V2> {
        self.agent_claim_compatibility_edge_identity_digest
    }

    pub const fn durable_task_id(self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn durable_run_id(self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub const fn signed_correlation_digest(self) -> Digest32V2 {
        self.signed_correlation_digest
    }

    pub const fn claim_commitment_digest(self) -> Digest32V2 {
        self.claim_commitment_digest
    }

    pub const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub const fn agentd_identity(self) -> ServiceIdentityV2 {
        self.agentd_identity
    }

    pub const fn originating_agentd_boot_id(self) -> BootIdV2 {
        self.originating_agentd_boot_id
    }

    pub const fn kerneld_identity(self) -> ServiceIdentityV2 {
        self.kerneld_identity
    }

    pub const fn originating_kerneld_boot_id(self) -> BootIdV2 {
        self.originating_kerneld_boot_id
    }

    pub const fn approvald_identity(self) -> ServiceIdentityV2 {
        self.approvald_identity
    }

    pub const fn auth_attempt_nonce(self) -> Nonce32V2 {
        self.auth_attempt_nonce
    }

    pub const fn authentication_recovery_record_digest(self) -> Digest32V2 {
        self.authentication_recovery_record_digest
    }

    pub const fn authentication_preparation_hash(self) -> Digest32V2 {
        self.authentication_preparation_hash
    }

    pub const fn authentication_envelope_digest(self) -> Digest32V2 {
        self.authentication_envelope_digest
    }

    pub const fn closure_nonce(self) -> Nonce32V2 {
        self.closure_nonce
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAgentAuthenticationClosureDescriptorV2 {
    unsigned: UnsignedAgentAuthenticationClosureDescriptorV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedAgentAuthenticationClosureDescriptorV2 {
    pub fn sign(
        unsigned: UnsignedAgentAuthenticationClosureDescriptorV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = encode_unsigned_agent_authentication_closure_descriptor_v2(&unsigned)?;
        Self::from_parts(
            unsigned,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            sign_payload_digest(
                signing_key,
                AGENT_AUTHENTICATION_CLOSURE_DESCRIPTOR_DOMAIN_V2,
                &payload,
            ),
        )
    }

    pub fn from_parts(
        unsigned: UnsignedAgentAuthenticationClosureDescriptorV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        validate_signature_parts(key_id, signature)?;
        Ok(Self {
            unsigned,
            key_id,
            signature,
        })
    }

    pub const fn unsigned(&self) -> UnsignedAgentAuthenticationClosureDescriptorV2 {
        self.unsigned
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn signature(&self) -> Ed25519SignatureV2 {
        self.signature
    }

    pub fn verify(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        now: UnixMillisV2,
    ) -> Result<UnsignedAgentAuthenticationClosureDescriptorV2, ProtocolError> {
        if self.key_id != expected_key_id
            || derive_ed25519_key_id_v2(verifying_key) != expected_key_id
            || now.get() < self.unsigned.issued_at.get()
            || now.get() >= self.unsigned.expires_at.get()
        {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        let payload = encode_unsigned_agent_authentication_closure_descriptor_v2(&self.unsigned)?;
        verify_payload_digest(
            verifying_key,
            AGENT_AUTHENTICATION_CLOSURE_DESCRIPTOR_DOMAIN_V2,
            &payload,
            self.signature,
        )?;
        Ok(self.unsigned)
    }

    pub fn descriptor_digest(&self) -> Result<Digest32V2, ProtocolError> {
        Ok(domain_hash(
            AGENT_AUTHENTICATION_CLOSURE_DESCRIPTOR_DIGEST_DOMAIN_V2,
            &encode_signed_agent_authentication_closure_descriptor_v2(self)?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedAgentAuthenticationAttemptClosureProofV2 {
    installation_id: Digest32V2,
    attempt_manifest_digest: Digest32V2,
    attempt_deployment_generation: u64,
    closure_issuing_manifest_digest: Digest32V2,
    closure_issuing_deployment_generation: u64,
    agent_claim_compatibility_edge_identity_digest: Option<Digest32V2>,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    signed_correlation_digest: Digest32V2,
    claim_commitment_digest: Digest32V2,
    authenticated_principal: PrincipalIdV2,
    agentd_identity: ServiceIdentityV2,
    originating_agentd_boot_id: BootIdV2,
    kerneld_identity: ServiceIdentityV2,
    originating_kerneld_boot_id: BootIdV2,
    approvald_identity: ServiceIdentityV2,
    approvald_boot_id: BootIdV2,
    authentication_recovery_record_digest: Digest32V2,
    authentication_envelope_digest: Digest32V2,
    auth_attempt_nonce: Nonce32V2,
    closure_descriptor_digest: Digest32V2,
    evidence: AgentAuthenticationClosureEvidenceV2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl UnsignedAgentAuthenticationAttemptClosureProofV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        attempt_manifest_digest: Digest32V2,
        attempt_deployment_generation: u64,
        closure_issuing_manifest_digest: Digest32V2,
        closure_issuing_deployment_generation: u64,
        agent_claim_compatibility_edge_identity_digest: Option<Digest32V2>,
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        signed_correlation_digest: Digest32V2,
        claim_commitment_digest: Digest32V2,
        authenticated_principal: PrincipalIdV2,
        agentd_identity: ServiceIdentityV2,
        originating_agentd_boot_id: BootIdV2,
        kerneld_identity: ServiceIdentityV2,
        originating_kerneld_boot_id: BootIdV2,
        approvald_identity: ServiceIdentityV2,
        approvald_boot_id: BootIdV2,
        authentication_recovery_record_digest: Digest32V2,
        authentication_envelope_digest: Digest32V2,
        auth_attempt_nonce: Nonce32V2,
        closure_descriptor_digest: Digest32V2,
        evidence: AgentAuthenticationClosureEvidenceV2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        evidence.validate()?;
        if is_zero(installation_id.as_bytes())
            || is_zero(attempt_manifest_digest.as_bytes())
            || attempt_deployment_generation == 0
            || is_zero(closure_issuing_manifest_digest.as_bytes())
            || closure_issuing_deployment_generation == 0
            || option_is_zero(agent_claim_compatibility_edge_identity_digest)
            || is_zero(durable_task_id.as_bytes())
            || is_zero(durable_run_id.as_bytes())
            || is_zero(signed_correlation_digest.as_bytes())
            || is_zero(claim_commitment_digest.as_bytes())
            || is_zero(authenticated_principal.as_bytes())
            || is_zero(agentd_identity.as_bytes())
            || is_zero(originating_agentd_boot_id.as_bytes())
            || is_zero(kerneld_identity.as_bytes())
            || is_zero(originating_kerneld_boot_id.as_bytes())
            || is_zero(approvald_identity.as_bytes())
            || is_zero(approvald_boot_id.as_bytes())
            || is_zero(authentication_recovery_record_digest.as_bytes())
            || is_zero(authentication_envelope_digest.as_bytes())
            || is_zero(auth_attempt_nonce.as_bytes())
            || is_zero(closure_descriptor_digest.as_bytes())
            || issued_at.get() >= expires_at.get()
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            attempt_manifest_digest,
            attempt_deployment_generation,
            closure_issuing_manifest_digest,
            closure_issuing_deployment_generation,
            agent_claim_compatibility_edge_identity_digest,
            durable_task_id,
            durable_run_id,
            signed_correlation_digest,
            claim_commitment_digest,
            authenticated_principal,
            agentd_identity,
            originating_agentd_boot_id,
            kerneld_identity,
            originating_kerneld_boot_id,
            approvald_identity,
            approvald_boot_id,
            authentication_recovery_record_digest,
            authentication_envelope_digest,
            auth_attempt_nonce,
            closure_descriptor_digest,
            evidence,
            issued_at,
            expires_at,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn attempt_manifest_digest(self) -> Digest32V2 {
        self.attempt_manifest_digest
    }

    pub const fn attempt_deployment_generation(self) -> u64 {
        self.attempt_deployment_generation
    }

    pub const fn closure_issuing_manifest_digest(self) -> Digest32V2 {
        self.closure_issuing_manifest_digest
    }

    pub const fn closure_issuing_deployment_generation(self) -> u64 {
        self.closure_issuing_deployment_generation
    }

    pub const fn agent_claim_compatibility_edge_identity_digest(self) -> Option<Digest32V2> {
        self.agent_claim_compatibility_edge_identity_digest
    }

    pub const fn durable_task_id(self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn durable_run_id(self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub const fn signed_correlation_digest(self) -> Digest32V2 {
        self.signed_correlation_digest
    }

    pub const fn claim_commitment_digest(self) -> Digest32V2 {
        self.claim_commitment_digest
    }

    pub const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub const fn agentd_identity(self) -> ServiceIdentityV2 {
        self.agentd_identity
    }

    pub const fn originating_agentd_boot_id(self) -> BootIdV2 {
        self.originating_agentd_boot_id
    }

    pub const fn kerneld_identity(self) -> ServiceIdentityV2 {
        self.kerneld_identity
    }

    pub const fn originating_kerneld_boot_id(self) -> BootIdV2 {
        self.originating_kerneld_boot_id
    }

    pub const fn approvald_identity(self) -> ServiceIdentityV2 {
        self.approvald_identity
    }

    pub const fn approvald_boot_id(self) -> BootIdV2 {
        self.approvald_boot_id
    }

    pub const fn authentication_recovery_record_digest(self) -> Digest32V2 {
        self.authentication_recovery_record_digest
    }

    pub const fn authentication_envelope_digest(self) -> Digest32V2 {
        self.authentication_envelope_digest
    }

    pub const fn auth_attempt_nonce(self) -> Nonce32V2 {
        self.auth_attempt_nonce
    }

    pub const fn closure_descriptor_digest(self) -> Digest32V2 {
        self.closure_descriptor_digest
    }

    pub const fn evidence(self) -> AgentAuthenticationClosureEvidenceV2 {
        self.evidence
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAgentAuthenticationAttemptClosureProofV2 {
    unsigned: UnsignedAgentAuthenticationAttemptClosureProofV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedAgentAuthenticationAttemptClosureProofV2 {
    pub fn sign(
        unsigned: UnsignedAgentAuthenticationAttemptClosureProofV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = encode_unsigned_agent_authentication_attempt_closure_proof_v2(&unsigned)?;
        Self::from_parts(
            unsigned,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            sign_payload_digest(
                signing_key,
                AGENT_AUTHENTICATION_ATTEMPT_CLOSURE_PROOF_DOMAIN_V2,
                &payload,
            ),
        )
    }

    pub fn from_parts(
        unsigned: UnsignedAgentAuthenticationAttemptClosureProofV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        validate_signature_parts(key_id, signature)?;
        Ok(Self {
            unsigned,
            key_id,
            signature,
        })
    }

    pub const fn unsigned(&self) -> UnsignedAgentAuthenticationAttemptClosureProofV2 {
        self.unsigned
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn signature(&self) -> Ed25519SignatureV2 {
        self.signature
    }

    pub fn verify(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        now: UnixMillisV2,
    ) -> Result<UnsignedAgentAuthenticationAttemptClosureProofV2, ProtocolError> {
        if self.key_id != expected_key_id
            || derive_ed25519_key_id_v2(verifying_key) != expected_key_id
            || now.get() < self.unsigned.issued_at.get()
            || now.get() >= self.unsigned.expires_at.get()
        {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        let payload =
            encode_unsigned_agent_authentication_attempt_closure_proof_v2(&self.unsigned)?;
        verify_payload_digest(
            verifying_key,
            AGENT_AUTHENTICATION_ATTEMPT_CLOSURE_PROOF_DOMAIN_V2,
            &payload,
            self.signature,
        )?;
        Ok(self.unsigned)
    }
}

closed_unit_enum_v2! {
    ApprovalDecisionV2 {
        Deny = 1,
        Approve = 2,
    }
}

closed_unit_enum_v2! {
    UiAuthenticationPurposeV2 {
        IngressInput = 1,
        ApprovalDisplay = 2,
        AgentContent = 3,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalBindingV2 {
    Ingress {
        pending_ingress_id: Digest32V2,
        ingress_subject_digest: Digest32V2,
        channel_commitments_digest: Digest32V2,
        source_provenance_digest: Digest32V2,
    },
    ToolExecution {
        action_intent_id: ActionIntentIdV2,
        binding: ToolExecutionSemanticBindingV2,
    },
    FinalRelease {
        binding: FinalReleaseSemanticBindingV2,
    },
}

impl ApprovalBindingV2 {
    pub const fn purpose(self) -> ApprovalPurposeV2 {
        match self {
            Self::Ingress { .. } => ApprovalPurposeV2::Ingress,
            Self::ToolExecution { .. } => ApprovalPurposeV2::ToolExecution,
            Self::FinalRelease { .. } => ApprovalPurposeV2::FinalRelease,
        }
    }

    pub fn binding_digest(self) -> Result<Digest32V2, ProtocolError> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encode_approval_binding(&mut encoder, self)?;
        Ok(domain_hash(
            APPROVAL_BINDING_DOMAIN_V2,
            &encoder.into_writer(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedApprovalEnvelopeV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    purpose: ApprovalPurposeV2,
    envelope_nonce: Nonce32V2,
    decision_challenge: Nonce32V2,
    binding: ApprovalBindingV2,
    expected_principal: PrincipalIdV2,
    display_projection_digest: Digest32V2,
    display_digest: Digest32V2,
    display_bytes: Vec<u8>,
    display_declassification_provenance_digest: Option<Digest32V2>,
    approvald_endpoint_identity: ServiceIdentityV2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl UnsignedApprovalEnvelopeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        purpose: ApprovalPurposeV2,
        envelope_nonce: Nonce32V2,
        decision_challenge: Nonce32V2,
        binding: ApprovalBindingV2,
        expected_principal: PrincipalIdV2,
        display_projection_digest: Digest32V2,
        display_digest: Digest32V2,
        display_bytes: Vec<u8>,
        display_declassification_provenance_digest: Option<Digest32V2>,
        approvald_endpoint_identity: ServiceIdentityV2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || purpose != binding.purpose()
            || is_zero(envelope_nonce.as_bytes())
            || is_zero(decision_challenge.as_bytes())
            || is_zero(expected_principal.as_bytes())
            || is_zero(display_projection_digest.as_bytes())
            || is_zero(display_digest.as_bytes())
            || display_bytes.is_empty()
            || display_bytes.len() > MAX_APPROVAL_DISPLAY_BYTES_V2
            || approval_display_digest_v2(&display_bytes) != display_digest
            || display_declassification_provenance_digest
                .is_some_and(|digest| is_zero(digest.as_bytes()))
            || (purpose != ApprovalPurposeV2::Ingress
                && display_declassification_provenance_digest.is_none())
            || is_zero(approvald_endpoint_identity.as_bytes())
            || issued_at.get() == 0
            || issued_at.get() >= expires_at.get()
            || !approval_binding_is_nonzero(binding)
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            purpose,
            envelope_nonce,
            decision_challenge,
            binding,
            expected_principal,
            display_projection_digest,
            display_digest,
            display_bytes,
            display_declassification_provenance_digest,
            approvald_endpoint_identity,
            issued_at,
            expires_at,
        })
    }

    pub const fn purpose(&self) -> ApprovalPurposeV2 {
        self.purpose
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }

    pub const fn envelope_nonce(&self) -> Nonce32V2 {
        self.envelope_nonce
    }

    pub const fn binding(&self) -> ApprovalBindingV2 {
        self.binding
    }

    pub const fn expected_principal(&self) -> PrincipalIdV2 {
        self.expected_principal
    }

    pub const fn decision_challenge(&self) -> Nonce32V2 {
        self.decision_challenge
    }

    pub const fn display_projection_digest(&self) -> Digest32V2 {
        self.display_projection_digest
    }

    pub const fn display_digest(&self) -> Digest32V2 {
        self.display_digest
    }

    pub fn display_bytes(&self) -> &[u8] {
        &self.display_bytes
    }

    pub const fn display_declassification_provenance_digest(&self) -> Option<Digest32V2> {
        self.display_declassification_provenance_digest
    }

    pub const fn approvald_endpoint_identity(&self) -> ServiceIdentityV2 {
        self.approvald_endpoint_identity
    }

    pub const fn issued_at(&self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAuthenticationBindingV2 {
    IngressNewTask {
        durable_task_id: DurableTaskIdV2,
        pending_task_digest: Digest32V2,
        ingressd_identity: ServiceIdentityV2,
    },
    IngressExistingRun {
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        captured_run_revision_digest: RunRevisionDigestV2,
        ingressd_identity: ServiceIdentityV2,
    },
    ApprovalDisplay {
        durable_task_id: DurableTaskIdV2,
        approval_envelope_digest: Digest32V2,
        approval_purpose: ApprovalPurposeV2,
        display_digest: Digest32V2,
    },
    AgentContent {
        durable_task_id: DurableTaskIdV2,
        ingress_claim_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        agentd_boot_id: BootIdV2,
    },
}

impl UiAuthenticationBindingV2 {
    pub const fn purpose(self) -> UiAuthenticationPurposeV2 {
        match self {
            Self::IngressNewTask { .. } | Self::IngressExistingRun { .. } => {
                UiAuthenticationPurposeV2::IngressInput
            }
            Self::ApprovalDisplay { .. } => UiAuthenticationPurposeV2::ApprovalDisplay,
            Self::AgentContent { .. } => UiAuthenticationPurposeV2::AgentContent,
        }
    }

    pub fn binding_digest(self) -> Result<Digest32V2, ProtocolError> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encode_ui_authentication_binding(&mut encoder, self)?;
        Ok(domain_hash(
            UI_AUTH_BINDING_DOMAIN_V2,
            &encoder.into_writer(),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedUiAuthenticationEnvelopeV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    purpose: UiAuthenticationPurposeV2,
    binding: UiAuthenticationBindingV2,
    expected_principal: Option<PrincipalIdV2>,
    authentication_origin: FixedOriginV2,
    return_origin: FixedOriginV2,
    envelope_nonce: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl UnsignedUiAuthenticationEnvelopeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        purpose: UiAuthenticationPurposeV2,
        binding: UiAuthenticationBindingV2,
        expected_principal: Option<PrincipalIdV2>,
        authentication_origin: FixedOriginV2,
        return_origin: FixedOriginV2,
        envelope_nonce: Nonce32V2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        let origins_match = matches!(
            (purpose, authentication_origin, return_origin),
            (
                UiAuthenticationPurposeV2::IngressInput,
                FixedOriginV2::Approval8766,
                FixedOriginV2::Ingress8767
            ) | (
                UiAuthenticationPurposeV2::ApprovalDisplay,
                FixedOriginV2::Approval8766,
                FixedOriginV2::Approval8766
            ) | (
                UiAuthenticationPurposeV2::AgentContent,
                FixedOriginV2::Approval8766,
                FixedOriginV2::Agent8768
            )
        );
        let principal_valid = match binding {
            UiAuthenticationBindingV2::IngressNewTask { .. } => {
                expected_principal.is_none_or(|principal| !is_zero(principal.as_bytes()))
            }
            _ => expected_principal.is_some_and(|principal| !is_zero(principal.as_bytes())),
        };
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || purpose != binding.purpose()
            || !ui_authentication_binding_is_nonzero(binding)
            || !principal_valid
            || !origins_match
            || is_zero(envelope_nonce.as_bytes())
            || issued_at.get() == 0
            || issued_at.get() >= expires_at.get()
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            purpose,
            binding,
            expected_principal,
            authentication_origin,
            return_origin,
            envelope_nonce,
            issued_at,
            expires_at,
        })
    }

    pub const fn purpose(self) -> UiAuthenticationPurposeV2 {
        self.purpose
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn binding(self) -> UiAuthenticationBindingV2 {
        self.binding
    }

    pub const fn expected_principal(self) -> Option<PrincipalIdV2> {
        self.expected_principal
    }

    pub fn binding_digest(self) -> Result<Digest32V2, ProtocolError> {
        self.binding.binding_digest()
    }

    pub const fn envelope_nonce(self) -> Nonce32V2 {
        self.envelope_nonce
    }

    pub const fn authentication_origin(self) -> FixedOriginV2 {
        self.authentication_origin
    }

    pub const fn return_origin(self) -> FixedOriginV2 {
        self.return_origin
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

impl SignedApprovalEnvelopeV2 {
    pub fn sign(
        unsigned: UnsignedApprovalEnvelopeV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let canonical_payload = encode_unsigned_approval_envelope_v2(&unsigned)?;
        let domain = approval_envelope_domain(unsigned.purpose);
        let digest = domain_hash(domain, &canonical_payload);
        let signature = sign_domain_digest(signing_key, domain, digest);
        Self::from_canonical_parts(
            canonical_payload,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            signature,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_purpose: ApprovalPurposeV2,
        expected_principal: PrincipalIdV2,
        now: UnixMillisV2,
    ) -> Result<UnsignedApprovalEnvelopeV2, ProtocolError> {
        let unsigned = decode_unsigned_approval_envelope_v2(&self.canonical_payload)?;
        if self.key_id != expected_key_id
            || derive_ed25519_key_id_v2(verifying_key) != expected_key_id
            || unsigned.installation_id != expected_installation_id
            || unsigned.active_state_manifest_digest != expected_active_state_manifest_digest
            || unsigned.deployment_generation != expected_deployment_generation
            || unsigned.purpose != expected_purpose
            || unsigned.expected_principal != expected_principal
            || now.get() < unsigned.issued_at.get()
            || now.get() >= unsigned.expires_at.get()
        {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        verify_domain_digest(
            verifying_key,
            approval_envelope_domain(unsigned.purpose),
            &self.canonical_payload,
            self.signature,
        )?;
        Ok(unsigned)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_approval_service(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_approvald_endpoint_identity: ServiceIdentityV2,
        now: UnixMillisV2,
    ) -> Result<UnsignedApprovalEnvelopeV2, ProtocolError> {
        let unsigned = self.verify_approval_service_deployment(
            expected_key_id,
            verifying_key,
            expected_installation_id,
            expected_active_state_manifest_digest,
            expected_deployment_generation,
            expected_approvald_endpoint_identity,
        )?;
        if now.get() < unsigned.issued_at.get() || now.get() >= unsigned.expires_at.get() {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        Ok(unsigned)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_approval_service_deployment(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_approvald_endpoint_identity: ServiceIdentityV2,
    ) -> Result<UnsignedApprovalEnvelopeV2, ProtocolError> {
        let unsigned = decode_unsigned_approval_envelope_v2(&self.canonical_payload)?;
        if self.key_id != expected_key_id
            || derive_ed25519_key_id_v2(verifying_key) != expected_key_id
            || unsigned.installation_id != expected_installation_id
            || unsigned.active_state_manifest_digest != expected_active_state_manifest_digest
            || unsigned.deployment_generation != expected_deployment_generation
            || unsigned.approvald_endpoint_identity != expected_approvald_endpoint_identity
        {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        verify_domain_digest(
            verifying_key,
            approval_envelope_domain(unsigned.purpose),
            &self.canonical_payload,
            self.signature,
        )?;
        Ok(unsigned)
    }

    pub fn envelope_digest(&self) -> Result<Digest32V2, ProtocolError> {
        let unsigned = decode_unsigned_approval_envelope_v2(&self.canonical_payload)?;
        Ok(domain_hash(
            approval_envelope_domain(unsigned.purpose),
            &self.canonical_payload,
        ))
    }
}

impl SignedUiAuthenticationEnvelopeV2 {
    pub fn sign(
        unsigned: UnsignedUiAuthenticationEnvelopeV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let canonical_payload = encode_unsigned_ui_authentication_envelope_v2(&unsigned)?;
        let domain = ui_authentication_envelope_domain(unsigned.purpose);
        let digest = domain_hash(domain, &canonical_payload);
        let signature = sign_domain_digest(signing_key, domain, digest);
        Self::from_canonical_parts(
            canonical_payload,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            signature,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<UnsignedUiAuthenticationEnvelopeV2, ProtocolError> {
        let unsigned = self.verify_deployment(
            expected_key_id,
            verifying_key,
            expected_installation_id,
            expected_active_state_manifest_digest,
            expected_deployment_generation,
        )?;
        if now.get() < unsigned.issued_at.get() || now.get() >= unsigned.expires_at.get() {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        Ok(unsigned)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_deployment(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
    ) -> Result<UnsignedUiAuthenticationEnvelopeV2, ProtocolError> {
        let unsigned = decode_unsigned_ui_authentication_envelope_v2(&self.canonical_payload)?;
        if self.key_id != expected_key_id
            || derive_ed25519_key_id_v2(verifying_key) != expected_key_id
            || unsigned.installation_id != expected_installation_id
            || unsigned.active_state_manifest_digest != expected_active_state_manifest_digest
            || unsigned.deployment_generation != expected_deployment_generation
        {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        verify_domain_digest(
            verifying_key,
            ui_authentication_envelope_domain(unsigned.purpose),
            &self.canonical_payload,
            self.signature,
        )?;
        Ok(unsigned)
    }

    pub fn envelope_digest(&self) -> Result<Digest32V2, ProtocolError> {
        let unsigned = decode_unsigned_ui_authentication_envelope_v2(&self.canonical_payload)?;
        Ok(domain_hash(
            ui_authentication_envelope_domain(unsigned.purpose),
            &self.canonical_payload,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedApprovalSettlementV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    purpose: ApprovalPurposeV2,
    envelope_digest: Digest32V2,
    decision: ApprovalDecisionV2,
    authenticated_principal: PrincipalIdV2,
    authentication_context_digest: Digest32V2,
    credential_digest: Digest32V2,
    user_present: bool,
    user_verified: bool,
    backup_eligible: bool,
    backup_state: bool,
    signature_counter: u32,
    challenge: Nonce32V2,
    settlement_nonce: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl UnsignedApprovalSettlementV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        purpose: ApprovalPurposeV2,
        envelope_digest: Digest32V2,
        decision: ApprovalDecisionV2,
        authenticated_principal: PrincipalIdV2,
        authentication_context_digest: Digest32V2,
        credential_digest: Digest32V2,
        user_present: bool,
        user_verified: bool,
        backup_eligible: bool,
        backup_state: bool,
        signature_counter: u32,
        challenge: Nonce32V2,
        settlement_nonce: Nonce32V2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || is_zero(envelope_digest.as_bytes())
            || is_zero(authenticated_principal.as_bytes())
            || is_zero(authentication_context_digest.as_bytes())
            || is_zero(credential_digest.as_bytes())
            || !user_present
            || !user_verified
            || backup_eligible
            || backup_state
            || signature_counter == 0
            || is_zero(challenge.as_bytes())
            || is_zero(settlement_nonce.as_bytes())
            || issued_at.get() >= expires_at.get()
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            purpose,
            envelope_digest,
            decision,
            authenticated_principal,
            authentication_context_digest,
            credential_digest,
            user_present,
            user_verified,
            backup_eligible,
            backup_state,
            signature_counter,
            challenge,
            settlement_nonce,
            issued_at,
            expires_at,
        })
    }

    pub const fn purpose(self) -> ApprovalPurposeV2 {
        self.purpose
    }

    pub const fn envelope_digest(self) -> Digest32V2 {
        self.envelope_digest
    }

    pub const fn decision(self) -> ApprovalDecisionV2 {
        self.decision
    }

    pub const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub const fn authentication_context_digest(self) -> Digest32V2 {
        self.authentication_context_digest
    }

    pub const fn credential_digest(self) -> Digest32V2 {
        self.credential_digest
    }

    pub const fn signature_counter(self) -> u32 {
        self.signature_counter
    }

    pub const fn challenge(self) -> Nonce32V2 {
        self.challenge
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedApprovalSettlementV2 {
    unsigned: UnsignedApprovalSettlementV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedApprovalSettlementV2 {
    pub fn sign(
        unsigned: UnsignedApprovalSettlementV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let canonical_payload = encode_unsigned_approval_settlement_v2(&unsigned)?;
        let domain = approval_settlement_domain(unsigned.purpose);
        let digest = domain_hash(domain, &canonical_payload);
        Self::from_parts(
            unsigned,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            sign_domain_digest(signing_key, domain, digest),
        )
    }

    pub fn from_parts(
        unsigned: UnsignedApprovalSettlementV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        validate_signature_parts(key_id, signature)?;
        Ok(Self {
            unsigned,
            key_id,
            signature,
        })
    }

    pub const fn unsigned(&self) -> UnsignedApprovalSettlementV2 {
        self.unsigned
    }

    pub const fn purpose(&self) -> ApprovalPurposeV2 {
        self.unsigned.purpose
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn signature(&self) -> Ed25519SignatureV2 {
        self.signature
    }

    pub fn settlement_digest(&self) -> Result<Digest32V2, ProtocolError> {
        let canonical_payload = encode_unsigned_approval_settlement_v2(&self.unsigned)?;
        Ok(domain_hash(
            approval_settlement_domain(self.unsigned.purpose),
            &canonical_payload,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_ingress(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_envelope_digest: Digest32V2,
        expected_principal: PrincipalIdV2,
        expected_challenge: Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<VerifiedApprovalSettlementV2, ProtocolError> {
        self.verify_for_purpose(
            expected_key_id,
            verifying_key,
            expected_installation_id,
            expected_active_state_manifest_digest,
            expected_deployment_generation,
            ApprovalPurposeV2::Ingress,
            expected_envelope_digest,
            expected_principal,
            expected_challenge,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_tool_execution(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_envelope_digest: Digest32V2,
        expected_principal: PrincipalIdV2,
        expected_challenge: Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<VerifiedApprovalSettlementV2, ProtocolError> {
        self.verify_for_purpose(
            expected_key_id,
            verifying_key,
            expected_installation_id,
            expected_active_state_manifest_digest,
            expected_deployment_generation,
            ApprovalPurposeV2::ToolExecution,
            expected_envelope_digest,
            expected_principal,
            expected_challenge,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_final_release(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_envelope_digest: Digest32V2,
        expected_principal: PrincipalIdV2,
        expected_challenge: Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<VerifiedApprovalSettlementV2, ProtocolError> {
        self.verify_for_purpose(
            expected_key_id,
            verifying_key,
            expected_installation_id,
            expected_active_state_manifest_digest,
            expected_deployment_generation,
            ApprovalPurposeV2::FinalRelease,
            expected_envelope_digest,
            expected_principal,
            expected_challenge,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_for_purpose(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_purpose: ApprovalPurposeV2,
        expected_envelope_digest: Digest32V2,
        expected_principal: PrincipalIdV2,
        expected_challenge: Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<VerifiedApprovalSettlementV2, ProtocolError> {
        if self.key_id != expected_key_id
            || derive_ed25519_key_id_v2(verifying_key) != expected_key_id
        {
            return Err(ProtocolError::stable(StableCode::ApprovalInvalidSignature));
        }
        let unsigned = self.unsigned;
        if unsigned.purpose != expected_purpose
            || unsigned.installation_id != expected_installation_id
            || unsigned.active_state_manifest_digest != expected_active_state_manifest_digest
            || unsigned.deployment_generation != expected_deployment_generation
            || unsigned.envelope_digest != expected_envelope_digest
            || unsigned.authenticated_principal != expected_principal
            || unsigned.challenge != expected_challenge
        {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        if now.get() < unsigned.issued_at.get() || now.get() >= unsigned.expires_at.get() {
            return Err(ProtocolError::stable(StableCode::ApprovalReplayed));
        }

        let canonical_payload = encode_unsigned_approval_settlement_v2(&unsigned)?;
        let domain = approval_settlement_domain(expected_purpose);
        let settlement_digest = domain_hash(domain, &canonical_payload);
        let mut signature_input = Vec::with_capacity(domain.len() + 32);
        signature_input.extend_from_slice(domain);
        signature_input.extend_from_slice(settlement_digest.as_bytes());
        let key = VerifyingKey::from_bytes(&verifying_key)
            .map_err(|_| ProtocolError::stable(StableCode::ApprovalInvalidSignature))?;
        key.verify_strict(
            &signature_input,
            &Signature::from_bytes(self.signature.as_bytes()),
        )
        .map_err(|_| ProtocolError::stable(StableCode::ApprovalInvalidSignature))?;

        Ok(VerifiedApprovalSettlementV2 {
            decision: unsigned.decision,
            authenticated_principal: unsigned.authenticated_principal,
            authentication_context_digest: unsigned.authentication_context_digest,
            credential_digest: unsigned.credential_digest,
            challenge: unsigned.challenge,
            settlement_digest,
            issued_at: unsigned.issued_at,
            expires_at: unsigned.expires_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedApprovalSettlementV2 {
    decision: ApprovalDecisionV2,
    authenticated_principal: PrincipalIdV2,
    authentication_context_digest: Digest32V2,
    credential_digest: Digest32V2,
    challenge: Nonce32V2,
    settlement_digest: Digest32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl VerifiedApprovalSettlementV2 {
    pub const fn decision(self) -> ApprovalDecisionV2 {
        self.decision
    }

    pub const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub const fn authentication_context_digest(self) -> Digest32V2 {
        self.authentication_context_digest
    }

    pub const fn credential_digest(self) -> Digest32V2 {
        self.credential_digest
    }

    pub const fn challenge(self) -> Nonce32V2 {
        self.challenge
    }

    pub const fn settlement_digest(self) -> Digest32V2 {
        self.settlement_digest
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedUiAuthenticationSettlementV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    purpose: UiAuthenticationPurposeV2,
    envelope_digest: Digest32V2,
    binding_digest: Digest32V2,
    authentication_origin: FixedOriginV2,
    return_origin: FixedOriginV2,
    authenticated_principal: PrincipalIdV2,
    authentication_context_digest: Digest32V2,
    credential_digest: Digest32V2,
    user_present: bool,
    user_verified: bool,
    backup_eligible: bool,
    backup_state: bool,
    signature_counter: u32,
    challenge: Nonce32V2,
    settlement_nonce: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl UnsignedUiAuthenticationSettlementV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        purpose: UiAuthenticationPurposeV2,
        envelope_digest: Digest32V2,
        binding_digest: Digest32V2,
        authentication_origin: FixedOriginV2,
        return_origin: FixedOriginV2,
        authenticated_principal: PrincipalIdV2,
        authentication_context_digest: Digest32V2,
        credential_digest: Digest32V2,
        user_present: bool,
        user_verified: bool,
        backup_eligible: bool,
        backup_state: bool,
        signature_counter: u32,
        challenge: Nonce32V2,
        settlement_nonce: Nonce32V2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        let origins_match = matches!(
            (purpose, authentication_origin, return_origin),
            (
                UiAuthenticationPurposeV2::IngressInput,
                FixedOriginV2::Approval8766,
                FixedOriginV2::Ingress8767
            ) | (
                UiAuthenticationPurposeV2::ApprovalDisplay,
                FixedOriginV2::Approval8766,
                FixedOriginV2::Approval8766
            ) | (
                UiAuthenticationPurposeV2::AgentContent,
                FixedOriginV2::Approval8766,
                FixedOriginV2::Agent8768
            )
        );
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || is_zero(envelope_digest.as_bytes())
            || is_zero(binding_digest.as_bytes())
            || !origins_match
            || is_zero(authenticated_principal.as_bytes())
            || is_zero(authentication_context_digest.as_bytes())
            || is_zero(credential_digest.as_bytes())
            || !user_present
            || !user_verified
            || backup_eligible
            || backup_state
            || signature_counter == 0
            || is_zero(challenge.as_bytes())
            || is_zero(settlement_nonce.as_bytes())
            || issued_at.get() >= expires_at.get()
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            purpose,
            envelope_digest,
            binding_digest,
            authentication_origin,
            return_origin,
            authenticated_principal,
            authentication_context_digest,
            credential_digest,
            user_present,
            user_verified,
            backup_eligible,
            backup_state,
            signature_counter,
            challenge,
            settlement_nonce,
            issued_at,
            expires_at,
        })
    }

    pub const fn purpose(self) -> UiAuthenticationPurposeV2 {
        self.purpose
    }

    pub const fn envelope_digest(self) -> Digest32V2 {
        self.envelope_digest
    }

    pub const fn binding_digest(self) -> Digest32V2 {
        self.binding_digest
    }

    pub const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub const fn authentication_context_digest(self) -> Digest32V2 {
        self.authentication_context_digest
    }

    pub const fn credential_digest(self) -> Digest32V2 {
        self.credential_digest
    }

    pub const fn signature_counter(self) -> u32 {
        self.signature_counter
    }

    pub const fn challenge(self) -> Nonce32V2 {
        self.challenge
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedUiAuthenticationSettlementV2 {
    unsigned: UnsignedUiAuthenticationSettlementV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedUiAuthenticationSettlementV2 {
    pub fn sign(
        unsigned: UnsignedUiAuthenticationSettlementV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let canonical_payload = encode_unsigned_ui_authentication_settlement_v2(&unsigned)?;
        let domain = ui_authentication_settlement_domain(unsigned.purpose);
        let digest = domain_hash(domain, &canonical_payload);
        Self::from_parts(
            unsigned,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            sign_domain_digest(signing_key, domain, digest),
        )
    }

    pub fn from_parts(
        unsigned: UnsignedUiAuthenticationSettlementV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        validate_signature_parts(key_id, signature)?;
        Ok(Self {
            unsigned,
            key_id,
            signature,
        })
    }

    pub const fn unsigned(&self) -> UnsignedUiAuthenticationSettlementV2 {
        self.unsigned
    }

    pub const fn purpose(&self) -> UiAuthenticationPurposeV2 {
        self.unsigned.purpose
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn signature(&self) -> Ed25519SignatureV2 {
        self.signature
    }

    pub fn settlement_digest(&self) -> Result<Digest32V2, ProtocolError> {
        let canonical_payload = encode_unsigned_ui_authentication_settlement_v2(&self.unsigned)?;
        Ok(domain_hash(
            ui_authentication_settlement_domain(self.unsigned.purpose),
            &canonical_payload,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_ingress_input(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<VerifiedUiAuthenticationSettlementV2, ProtocolError> {
        self.verify_for_purpose(
            expected_key_id,
            verifying_key,
            expected_installation_id,
            expected_active_state_manifest_digest,
            expected_deployment_generation,
            UiAuthenticationPurposeV2::IngressInput,
            FixedOriginV2::Ingress8767,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_agent_content(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<VerifiedUiAuthenticationSettlementV2, ProtocolError> {
        self.verify_for_purpose(
            expected_key_id,
            verifying_key,
            expected_installation_id,
            expected_active_state_manifest_digest,
            expected_deployment_generation,
            UiAuthenticationPurposeV2::AgentContent,
            FixedOriginV2::Agent8768,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_approval_display(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<VerifiedUiAuthenticationSettlementV2, ProtocolError> {
        self.verify_for_purpose(
            expected_key_id,
            verifying_key,
            expected_installation_id,
            expected_active_state_manifest_digest,
            expected_deployment_generation,
            UiAuthenticationPurposeV2::ApprovalDisplay,
            FixedOriginV2::Approval8766,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_for_purpose(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_deployment_generation: u64,
        expected_purpose: UiAuthenticationPurposeV2,
        expected_return_origin: FixedOriginV2,
        now: UnixMillisV2,
    ) -> Result<VerifiedUiAuthenticationSettlementV2, ProtocolError> {
        if self.key_id != expected_key_id
            || derive_ed25519_key_id_v2(verifying_key) != expected_key_id
        {
            return Err(ProtocolError::stable(StableCode::ApprovalInvalidSignature));
        }
        let unsigned = self.unsigned;
        if unsigned.purpose != expected_purpose
            || unsigned.installation_id != expected_installation_id
            || unsigned.active_state_manifest_digest != expected_active_state_manifest_digest
            || unsigned.deployment_generation != expected_deployment_generation
            || unsigned.authentication_origin != FixedOriginV2::Approval8766
            || unsigned.return_origin != expected_return_origin
        {
            return Err(ProtocolError::stable(StableCode::ApprovalBindingMismatch));
        }
        if now.get() < unsigned.issued_at.get() || now.get() >= unsigned.expires_at.get() {
            return Err(ProtocolError::stable(StableCode::ApprovalReplayed));
        }

        let canonical_payload = encode_unsigned_ui_authentication_settlement_v2(&unsigned)?;
        let domain = ui_authentication_settlement_domain(expected_purpose);
        let settlement_digest = domain_hash(domain, &canonical_payload);
        let mut signature_input = Vec::with_capacity(domain.len() + 32);
        signature_input.extend_from_slice(domain);
        signature_input.extend_from_slice(settlement_digest.as_bytes());
        let key = VerifyingKey::from_bytes(&verifying_key)
            .map_err(|_| ProtocolError::stable(StableCode::ApprovalInvalidSignature))?;
        key.verify_strict(
            &signature_input,
            &Signature::from_bytes(self.signature.as_bytes()),
        )
        .map_err(|_| ProtocolError::stable(StableCode::ApprovalInvalidSignature))?;

        Ok(VerifiedUiAuthenticationSettlementV2 {
            installation_id: unsigned.installation_id,
            active_state_manifest_digest: unsigned.active_state_manifest_digest,
            deployment_generation: unsigned.deployment_generation,
            envelope_digest: unsigned.envelope_digest,
            binding_digest: unsigned.binding_digest,
            authenticated_principal: unsigned.authenticated_principal,
            authentication_context_digest: unsigned.authentication_context_digest,
            credential_digest: unsigned.credential_digest,
            challenge: unsigned.challenge,
            settlement_digest,
            issued_at: unsigned.issued_at,
            expires_at: unsigned.expires_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedUiAuthenticationSettlementV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    envelope_digest: Digest32V2,
    binding_digest: Digest32V2,
    authenticated_principal: PrincipalIdV2,
    authentication_context_digest: Digest32V2,
    credential_digest: Digest32V2,
    challenge: Nonce32V2,
    settlement_digest: Digest32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl VerifiedUiAuthenticationSettlementV2 {
    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn envelope_digest(self) -> Digest32V2 {
        self.envelope_digest
    }

    pub const fn binding_digest(self) -> Digest32V2 {
        self.binding_digest
    }

    pub const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub const fn authentication_context_digest(self) -> Digest32V2 {
        self.authentication_context_digest
    }

    pub const fn credential_digest(self) -> Digest32V2 {
        self.credential_digest
    }

    pub const fn challenge(self) -> Nonce32V2 {
        self.challenge
    }

    pub const fn settlement_digest(self) -> Digest32V2 {
        self.settlement_digest
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

macro_rules! signed_object_v2 {
    ($signed:ident, $unsigned:ident, $encode_payload:ident, $decode_payload:ident) => {
        impl<C> minicbor::Encode<C> for $signed {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                let payload = $encode_payload(&self.unsigned).map_err(|_| {
                    minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                })?;
                encoder.array(3)?.bytes(&payload)?;
                minicbor::Encode::encode(&self.key_id, encoder, &mut ())?;
                minicbor::Encode::encode(&self.signature, encoder, &mut ())?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $signed {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some(3) {
                    return Err(decode_error(position));
                }
                let payload = decoder.bytes()?;
                if payload.len() > MAX_SIGNED_PAYLOAD_BYTES_V2 {
                    return Err(decode_error(position));
                }
                let unsigned = $decode_payload(payload).map_err(|_| decode_error(position))?;
                let key_id = minicbor::Decode::decode(decoder, context)?;
                let signature = minicbor::Decode::decode(decoder, context)?;
                Self::from_parts(unsigned, key_id, signature).map_err(|_| decode_error(position))
            }
        }
    };
}

signed_object_v2!(
    SignedApprovalSettlementV2,
    UnsignedApprovalSettlementV2,
    encode_unsigned_approval_settlement_v2,
    decode_unsigned_approval_settlement_v2
);
signed_object_v2!(
    SignedUiAuthenticationSettlementV2,
    UnsignedUiAuthenticationSettlementV2,
    encode_unsigned_ui_authentication_settlement_v2,
    decode_unsigned_ui_authentication_settlement_v2
);
signed_object_v2!(
    SignedAgentAuthenticationClosureDescriptorV2,
    UnsignedAgentAuthenticationClosureDescriptorV2,
    encode_unsigned_agent_authentication_closure_descriptor_v2,
    decode_unsigned_agent_authentication_closure_descriptor_v2
);
signed_object_v2!(
    SignedAgentAuthenticationAttemptClosureProofV2,
    UnsignedAgentAuthenticationAttemptClosureProofV2,
    encode_unsigned_agent_authentication_attempt_closure_proof_v2,
    decode_unsigned_agent_authentication_attempt_closure_proof_v2
);

pub fn encode_signed_approval_envelope_v2(
    value: &SignedApprovalEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode_exact_signed_object(value)
}

pub fn decode_signed_approval_envelope_v2(
    bytes: &[u8],
) -> Result<SignedApprovalEnvelopeV2, ProtocolError> {
    decode_exact_signed_object(bytes)
}

pub fn encode_signed_ui_authentication_envelope_v2(
    value: &SignedUiAuthenticationEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode_exact_signed_object(value)
}

pub fn decode_signed_ui_authentication_envelope_v2(
    bytes: &[u8],
) -> Result<SignedUiAuthenticationEnvelopeV2, ProtocolError> {
    decode_exact_signed_object(bytes)
}

pub fn encode_signed_approval_settlement_v2(
    value: &SignedApprovalSettlementV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode_exact_signed_object(value)
}

pub fn decode_signed_approval_settlement_v2(
    bytes: &[u8],
) -> Result<SignedApprovalSettlementV2, ProtocolError> {
    decode_exact_signed_object(bytes)
}

pub fn encode_signed_ui_authentication_settlement_v2(
    value: &SignedUiAuthenticationSettlementV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode_exact_signed_object(value)
}

pub fn decode_signed_ui_authentication_settlement_v2(
    bytes: &[u8],
) -> Result<SignedUiAuthenticationSettlementV2, ProtocolError> {
    decode_exact_signed_object(bytes)
}

pub fn encode_signed_agent_authentication_closure_descriptor_v2(
    value: &SignedAgentAuthenticationClosureDescriptorV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode_exact_signed_object(value)
}

pub fn decode_signed_agent_authentication_closure_descriptor_v2(
    bytes: &[u8],
) -> Result<SignedAgentAuthenticationClosureDescriptorV2, ProtocolError> {
    decode_exact_signed_object(bytes)
}

pub fn encode_signed_agent_authentication_attempt_closure_proof_v2(
    value: &SignedAgentAuthenticationAttemptClosureProofV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode_exact_signed_object(value)
}

pub fn decode_signed_agent_authentication_attempt_closure_proof_v2(
    bytes: &[u8],
) -> Result<SignedAgentAuthenticationAttemptClosureProofV2, ProtocolError> {
    decode_exact_signed_object(bytes)
}

fn encode_exact_signed_object<T>(value: &T) -> Result<Vec<u8>, ProtocolError>
where
    T: minicbor::Encode<()>,
{
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

fn decode_exact_signed_object<T>(bytes: &[u8]) -> Result<T, ProtocolError>
where
    for<'bytes> T: minicbor::Decode<'bytes, V2DecodeContext> + minicbor::Encode<()>,
{
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = T::decode(&mut decoder, &mut context).map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let canonical = encode_exact_signed_object(&value)?;
    if canonical != bytes {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

fn encode_unsigned_approval_envelope_v2(
    value: &UnsignedApprovalEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(16)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.installation_id)?;
    encode_fixed(&mut encoder, &value.active_state_manifest_digest)?;
    encoder
        .u64(value.deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.purpose)?;
    encode_fixed(&mut encoder, &value.envelope_nonce)?;
    encode_fixed(&mut encoder, &value.decision_challenge)?;
    encode_approval_binding(&mut encoder, value.binding)?;
    encode_fixed(&mut encoder, &value.expected_principal)?;
    encode_fixed(&mut encoder, &value.display_projection_digest)?;
    encode_fixed(&mut encoder, &value.display_digest)?;
    encoder
        .bytes(&value.display_bytes)
        .map_err(ProtocolError::malformed)?;
    encode_optional_fixed(
        &mut encoder,
        value.display_declassification_provenance_digest,
    )?;
    encode_fixed(&mut encoder, &value.approvald_endpoint_identity)?;
    encode_fixed(&mut encoder, &value.issued_at)?;
    encode_fixed(&mut encoder, &value.expires_at)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_approval_envelope_v2(
    bytes: &[u8],
) -> Result<UnsignedApprovalEnvelopeV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 16)?;
    expect_schema_two(&mut decoder)?;
    let mut context = V2DecodeContext;
    let value = UnsignedApprovalEnvelopeV2::new(
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_approval_binding(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decode_optional_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_unsigned_approval_envelope_v2(&value)?,
    )?;
    Ok(value)
}

fn encode_unsigned_ui_authentication_envelope_v2(
    value: &UnsignedUiAuthenticationEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(12)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.installation_id)?;
    encode_fixed(&mut encoder, &value.active_state_manifest_digest)?;
    encoder
        .u64(value.deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.purpose)?;
    encode_ui_authentication_binding(&mut encoder, value.binding)?;
    encode_optional_fixed(&mut encoder, value.expected_principal)?;
    encode_fixed(&mut encoder, &value.authentication_origin)?;
    encode_fixed(&mut encoder, &value.return_origin)?;
    encode_fixed(&mut encoder, &value.envelope_nonce)?;
    encode_fixed(&mut encoder, &value.issued_at)?;
    encode_fixed(&mut encoder, &value.expires_at)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_ui_authentication_envelope_v2(
    bytes: &[u8],
) -> Result<UnsignedUiAuthenticationEnvelopeV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 12)?;
    expect_schema_two(&mut decoder)?;
    let mut context = V2DecodeContext;
    let value = UnsignedUiAuthenticationEnvelopeV2::new(
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_ui_authentication_binding(&mut decoder, &mut context)?,
        decode_optional_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_unsigned_ui_authentication_envelope_v2(&value)?,
    )?;
    Ok(value)
}

fn encode_approval_binding(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: ApprovalBindingV2,
) -> Result<(), ProtocolError> {
    match value {
        ApprovalBindingV2::Ingress {
            pending_ingress_id,
            ingress_subject_digest,
            channel_commitments_digest,
            source_provenance_digest,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &pending_ingress_id)?;
            encode_fixed(encoder, &ingress_subject_digest)?;
            encode_fixed(encoder, &channel_commitments_digest)?;
            encode_fixed(encoder, &source_provenance_digest)?;
        }
        ApprovalBindingV2::ToolExecution {
            action_intent_id,
            binding,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &action_intent_id)?;
            encode_fixed(encoder, &binding)?;
        }
        ApprovalBindingV2::FinalRelease { binding } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &binding)?;
        }
    }
    Ok(())
}

fn decode_approval_binding(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ApprovalBindingV2, ProtocolError> {
    let length = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (1, Some(5)) => Ok(ApprovalBindingV2::Ingress {
            pending_ingress_id: decode_fixed(decoder, context)?,
            ingress_subject_digest: decode_fixed(decoder, context)?,
            channel_commitments_digest: decode_fixed(decoder, context)?,
            source_provenance_digest: decode_fixed(decoder, context)?,
        }),
        (2, Some(3)) => Ok(ApprovalBindingV2::ToolExecution {
            action_intent_id: decode_fixed(decoder, context)?,
            binding: decode_fixed(decoder, context)?,
        }),
        (3, Some(2)) => Ok(ApprovalBindingV2::FinalRelease {
            binding: decode_fixed(decoder, context)?,
        }),
        _ => Err(malformed()),
    }
}

fn encode_ui_authentication_binding(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: UiAuthenticationBindingV2,
) -> Result<(), ProtocolError> {
    match value {
        UiAuthenticationBindingV2::IngressNewTask {
            durable_task_id,
            pending_task_digest,
            ingressd_identity,
        } => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &durable_task_id)?;
            encode_fixed(encoder, &pending_task_digest)?;
            encode_fixed(encoder, &ingressd_identity)?;
        }
        UiAuthenticationBindingV2::IngressExistingRun {
            durable_task_id,
            durable_run_id,
            captured_run_revision_digest,
            ingressd_identity,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &durable_task_id)?;
            encode_fixed(encoder, &durable_run_id)?;
            encode_fixed(encoder, &captured_run_revision_digest)?;
            encode_fixed(encoder, &ingressd_identity)?;
        }
        UiAuthenticationBindingV2::ApprovalDisplay {
            durable_task_id,
            approval_envelope_digest,
            approval_purpose,
            display_digest,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &durable_task_id)?;
            encode_fixed(encoder, &approval_envelope_digest)?;
            encode_fixed(encoder, &approval_purpose)?;
            encode_fixed(encoder, &display_digest)?;
        }
        UiAuthenticationBindingV2::AgentContent {
            durable_task_id,
            ingress_claim_digest,
            agentd_identity,
            agentd_boot_id,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(4))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &durable_task_id)?;
            encode_fixed(encoder, &ingress_claim_digest)?;
            encode_fixed(encoder, &agentd_identity)?;
            encode_fixed(encoder, &agentd_boot_id)?;
        }
    }
    Ok(())
}

fn decode_ui_authentication_binding(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<UiAuthenticationBindingV2, ProtocolError> {
    let length = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (1, Some(4)) => Ok(UiAuthenticationBindingV2::IngressNewTask {
            durable_task_id: decode_fixed(decoder, context)?,
            pending_task_digest: decode_fixed(decoder, context)?,
            ingressd_identity: decode_fixed(decoder, context)?,
        }),
        (2, Some(5)) => Ok(UiAuthenticationBindingV2::IngressExistingRun {
            durable_task_id: decode_fixed(decoder, context)?,
            durable_run_id: decode_fixed(decoder, context)?,
            captured_run_revision_digest: decode_fixed(decoder, context)?,
            ingressd_identity: decode_fixed(decoder, context)?,
        }),
        (3, Some(5)) => Ok(UiAuthenticationBindingV2::ApprovalDisplay {
            durable_task_id: decode_fixed(decoder, context)?,
            approval_envelope_digest: decode_fixed(decoder, context)?,
            approval_purpose: decode_fixed(decoder, context)?,
            display_digest: decode_fixed(decoder, context)?,
        }),
        (4, Some(5)) => Ok(UiAuthenticationBindingV2::AgentContent {
            durable_task_id: decode_fixed(decoder, context)?,
            ingress_claim_digest: decode_fixed(decoder, context)?,
            agentd_identity: decode_fixed(decoder, context)?,
            agentd_boot_id: decode_fixed(decoder, context)?,
        }),
        _ => Err(malformed()),
    }
}

fn encode_unsigned_approval_settlement_v2(
    value: &UnsignedApprovalSettlementV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(19)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.installation_id)?;
    encode_fixed(&mut encoder, &value.active_state_manifest_digest)?;
    encoder
        .u64(value.deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.purpose)?;
    encode_fixed(&mut encoder, &value.envelope_digest)?;
    encode_fixed(&mut encoder, &value.decision)?;
    encode_fixed(&mut encoder, &value.authenticated_principal)?;
    encode_fixed(&mut encoder, &value.authentication_context_digest)?;
    encode_fixed(&mut encoder, &value.credential_digest)?;
    encoder
        .bool(value.user_present)
        .and_then(|encoder| encoder.bool(value.user_verified))
        .and_then(|encoder| encoder.bool(value.backup_eligible))
        .and_then(|encoder| encoder.bool(value.backup_state))
        .and_then(|encoder| encoder.u32(value.signature_counter))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.challenge)?;
    encode_fixed(&mut encoder, &value.settlement_nonce)?;
    encode_fixed(&mut encoder, &value.issued_at)?;
    encode_fixed(&mut encoder, &value.expires_at)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_approval_settlement_v2(
    bytes: &[u8],
) -> Result<UnsignedApprovalSettlementV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 19)?;
    expect_schema_two(&mut decoder)?;
    let mut context = V2DecodeContext;
    let value = UnsignedApprovalSettlementV2::new(
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decoder.u32().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_unsigned_approval_settlement_v2(&value)?,
    )?;
    Ok(value)
}

fn encode_unsigned_ui_authentication_settlement_v2(
    value: &UnsignedUiAuthenticationSettlementV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(21)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.installation_id)?;
    encode_fixed(&mut encoder, &value.active_state_manifest_digest)?;
    encoder
        .u64(value.deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.purpose)?;
    encode_fixed(&mut encoder, &value.envelope_digest)?;
    encode_fixed(&mut encoder, &value.binding_digest)?;
    encode_fixed(&mut encoder, &value.authentication_origin)?;
    encode_fixed(&mut encoder, &value.return_origin)?;
    encode_fixed(&mut encoder, &value.authenticated_principal)?;
    encode_fixed(&mut encoder, &value.authentication_context_digest)?;
    encode_fixed(&mut encoder, &value.credential_digest)?;
    encoder
        .bool(value.user_present)
        .and_then(|encoder| encoder.bool(value.user_verified))
        .and_then(|encoder| encoder.bool(value.backup_eligible))
        .and_then(|encoder| encoder.bool(value.backup_state))
        .and_then(|encoder| encoder.u32(value.signature_counter))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.challenge)?;
    encode_fixed(&mut encoder, &value.settlement_nonce)?;
    encode_fixed(&mut encoder, &value.issued_at)?;
    encode_fixed(&mut encoder, &value.expires_at)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_ui_authentication_settlement_v2(
    bytes: &[u8],
) -> Result<UnsignedUiAuthenticationSettlementV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 21)?;
    expect_schema_two(&mut decoder)?;
    let mut context = V2DecodeContext;
    let value = UnsignedUiAuthenticationSettlementV2::new(
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decoder.bool().map_err(ProtocolError::malformed)?,
        decoder.u32().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_unsigned_ui_authentication_settlement_v2(&value)?,
    )?;
    Ok(value)
}

fn encode_unsigned_agent_authentication_closure_descriptor_v2(
    value: &UnsignedAgentAuthenticationClosureDescriptorV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(24)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.installation_id)?;
    encode_fixed(&mut encoder, &value.attempt_manifest_digest)?;
    encoder
        .u64(value.attempt_deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.closure_issuing_manifest_digest)?;
    encoder
        .u64(value.closure_issuing_deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_optional_fixed(
        &mut encoder,
        value.agent_claim_compatibility_edge_identity_digest,
    )?;
    encode_fixed(&mut encoder, &value.durable_task_id)?;
    encode_fixed(&mut encoder, &value.durable_run_id)?;
    encode_fixed(&mut encoder, &value.signed_correlation_digest)?;
    encode_fixed(&mut encoder, &value.claim_commitment_digest)?;
    encode_fixed(&mut encoder, &value.authenticated_principal)?;
    encode_fixed(&mut encoder, &value.agentd_identity)?;
    encode_fixed(&mut encoder, &value.originating_agentd_boot_id)?;
    encode_fixed(&mut encoder, &value.kerneld_identity)?;
    encode_fixed(&mut encoder, &value.originating_kerneld_boot_id)?;
    encode_fixed(&mut encoder, &value.approvald_identity)?;
    encode_fixed(&mut encoder, &value.auth_attempt_nonce)?;
    encode_fixed(&mut encoder, &value.authentication_recovery_record_digest)?;
    encode_fixed(&mut encoder, &value.authentication_preparation_hash)?;
    encode_fixed(&mut encoder, &value.authentication_envelope_digest)?;
    encode_fixed(&mut encoder, &value.closure_nonce)?;
    encode_fixed(&mut encoder, &value.issued_at)?;
    encode_fixed(&mut encoder, &value.expires_at)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_agent_authentication_closure_descriptor_v2(
    bytes: &[u8],
) -> Result<UnsignedAgentAuthenticationClosureDescriptorV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 24)?;
    expect_schema_two(&mut decoder)?;
    let mut context = V2DecodeContext;
    let value = UnsignedAgentAuthenticationClosureDescriptorV2::new(
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_fixed(&mut decoder, &mut context)?,
        decoder.u64().map_err(ProtocolError::malformed)?,
        decode_optional_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
        decode_fixed(&mut decoder, &mut context)?,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_unsigned_agent_authentication_closure_descriptor_v2(&value)?,
    )?;
    Ok(value)
}

fn encode_unsigned_agent_authentication_attempt_closure_proof_v2(
    value: &UnsignedAgentAuthenticationAttemptClosureProofV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(25)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.installation_id)?;
    encode_fixed(&mut encoder, &value.attempt_manifest_digest)?;
    encoder
        .u64(value.attempt_deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, &value.closure_issuing_manifest_digest)?;
    encoder
        .u64(value.closure_issuing_deployment_generation)
        .map_err(ProtocolError::malformed)?;
    encode_optional_fixed(
        &mut encoder,
        value.agent_claim_compatibility_edge_identity_digest,
    )?;
    encode_fixed(&mut encoder, &value.durable_task_id)?;
    encode_fixed(&mut encoder, &value.durable_run_id)?;
    encode_fixed(&mut encoder, &value.signed_correlation_digest)?;
    encode_fixed(&mut encoder, &value.claim_commitment_digest)?;
    encode_fixed(&mut encoder, &value.authenticated_principal)?;
    encode_fixed(&mut encoder, &value.agentd_identity)?;
    encode_fixed(&mut encoder, &value.originating_agentd_boot_id)?;
    encode_fixed(&mut encoder, &value.kerneld_identity)?;
    encode_fixed(&mut encoder, &value.originating_kerneld_boot_id)?;
    encode_fixed(&mut encoder, &value.approvald_identity)?;
    encode_fixed(&mut encoder, &value.approvald_boot_id)?;
    encode_fixed(&mut encoder, &value.authentication_recovery_record_digest)?;
    encode_fixed(&mut encoder, &value.authentication_envelope_digest)?;
    encode_fixed(&mut encoder, &value.auth_attempt_nonce)?;
    encode_fixed(&mut encoder, &value.closure_descriptor_digest)?;
    encode_agent_authentication_closure_evidence(&mut encoder, value.evidence)?;
    encode_fixed(&mut encoder, &value.issued_at)?;
    encode_fixed(&mut encoder, &value.expires_at)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_agent_authentication_attempt_closure_proof_v2(
    bytes: &[u8],
) -> Result<UnsignedAgentAuthenticationAttemptClosureProofV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 25)?;
    expect_schema_two(&mut decoder)?;
    let mut context = V2DecodeContext;
    let installation_id = decode_fixed(&mut decoder, &mut context)?;
    let attempt_manifest_digest = decode_fixed(&mut decoder, &mut context)?;
    let attempt_deployment_generation = decoder.u64().map_err(ProtocolError::malformed)?;
    let closure_issuing_manifest_digest = decode_fixed(&mut decoder, &mut context)?;
    let closure_issuing_deployment_generation = decoder.u64().map_err(ProtocolError::malformed)?;
    let agent_claim_compatibility_edge_identity_digest =
        decode_optional_fixed(&mut decoder, &mut context)?;
    let durable_task_id = decode_fixed(&mut decoder, &mut context)?;
    let durable_run_id = decode_fixed(&mut decoder, &mut context)?;
    let signed_correlation_digest = decode_fixed(&mut decoder, &mut context)?;
    let claim_commitment_digest = decode_fixed(&mut decoder, &mut context)?;
    let authenticated_principal = decode_fixed(&mut decoder, &mut context)?;
    let agentd_identity = decode_fixed(&mut decoder, &mut context)?;
    let originating_agentd_boot_id = decode_fixed(&mut decoder, &mut context)?;
    let kerneld_identity = decode_fixed(&mut decoder, &mut context)?;
    let originating_kerneld_boot_id = decode_fixed(&mut decoder, &mut context)?;
    let approvald_identity = decode_fixed(&mut decoder, &mut context)?;
    let approvald_boot_id = decode_fixed(&mut decoder, &mut context)?;
    let authentication_recovery_record_digest = decode_fixed(&mut decoder, &mut context)?;
    let authentication_envelope_digest = decode_fixed(&mut decoder, &mut context)?;
    let auth_attempt_nonce = decode_fixed(&mut decoder, &mut context)?;
    let closure_descriptor_digest = decode_fixed(&mut decoder, &mut context)?;
    let evidence = decode_agent_authentication_closure_evidence(&mut decoder, &mut context)?;
    let issued_at = decode_fixed(&mut decoder, &mut context)?;
    let expires_at = decode_fixed(&mut decoder, &mut context)?;
    let value = UnsignedAgentAuthenticationAttemptClosureProofV2::new(
        installation_id,
        attempt_manifest_digest,
        attempt_deployment_generation,
        closure_issuing_manifest_digest,
        closure_issuing_deployment_generation,
        agent_claim_compatibility_edge_identity_digest,
        durable_task_id,
        durable_run_id,
        signed_correlation_digest,
        claim_commitment_digest,
        authenticated_principal,
        agentd_identity,
        originating_agentd_boot_id,
        kerneld_identity,
        originating_kerneld_boot_id,
        approvald_identity,
        approvald_boot_id,
        authentication_recovery_record_digest,
        authentication_envelope_digest,
        auth_attempt_nonce,
        closure_descriptor_digest,
        evidence,
        issued_at,
        expires_at,
    )?;
    require_canonical_end(
        &decoder,
        bytes,
        encode_unsigned_agent_authentication_attempt_closure_proof_v2(&value)?,
    )?;
    Ok(value)
}

fn encode_agent_authentication_transfer_terminal_state(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: AgentAuthenticationTransferTerminalStateV2,
) -> Result<(), ProtocolError> {
    encoder.array(7).map_err(ProtocolError::malformed)?;
    encode_fixed(encoder, &value.initial_transfer_record_digest)?;
    encode_fixed(encoder, &value.initial_transfer_state)?;
    encode_optional_fixed(encoder, value.ceremony_record_digest)?;
    encode_optional_fixed(encoder, value.settlement_record_digest)?;
    encode_fixed(encoder, &value.settlement_state)?;
    encode_optional_fixed(encoder, value.settlement_transfer_record_digest)?;
    encode_fixed(encoder, &value.settlement_transfer_state)
}

fn decode_agent_authentication_transfer_terminal_state(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<AgentAuthenticationTransferTerminalStateV2, ProtocolError> {
    expect_array(decoder, 7)?;
    AgentAuthenticationTransferTerminalStateV2::new(
        decode_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_optional_fixed(decoder, context)?,
        decode_optional_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
        decode_optional_fixed(decoder, context)?,
        decode_fixed(decoder, context)?,
    )
}

fn encode_agent_authentication_closure_evidence(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: AgentAuthenticationClosureEvidenceV2,
) -> Result<(), ProtocolError> {
    value.validate()?;
    match value {
        AgentAuthenticationClosureEvidenceV2::NeverRegisteredDenylisted {
            complete_index_generation,
            current_journal_head_digest,
            denylist_tombstone_sequence,
            denylist_tombstone_digest,
            approvald_key_epoch,
        } => {
            encoder
                .array(6)
                .and_then(|encoder| encoder.u16(1))
                .and_then(|encoder| encoder.u64(complete_index_generation))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &current_journal_head_digest)?;
            encoder
                .u64(denylist_tombstone_sequence)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &denylist_tombstone_digest)?;
            encoder
                .u64(approvald_key_epoch)
                .map_err(ProtocolError::malformed)?;
        }
        AgentAuthenticationClosureEvidenceV2::RegisteredInvalidatedUnredeemed {
            approval_record_digest,
            ceremony_record_digest,
            transfer_state,
            approvald_terminal_transaction_digest,
            complete_index_generation,
            current_journal_head_digest,
            denylist_tombstone_sequence,
            denylist_tombstone_digest,
            approvald_key_epoch,
        } => {
            encoder
                .array(10)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &approval_record_digest)?;
            encode_fixed(encoder, &ceremony_record_digest)?;
            encode_agent_authentication_transfer_terminal_state(encoder, transfer_state)?;
            encode_fixed(encoder, &approvald_terminal_transaction_digest)?;
            encoder
                .u64(complete_index_generation)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &current_journal_head_digest)?;
            encoder
                .u64(denylist_tombstone_sequence)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &denylist_tombstone_digest)?;
            encoder
                .u64(approvald_key_epoch)
                .map_err(ProtocolError::malformed)?;
        }
        AgentAuthenticationClosureEvidenceV2::SettlementOrTransferObserved {
            approval_record_digest,
            ceremony_record_digest,
            transfer_state,
            settlement_digest,
            complete_index_generation,
            current_journal_head_digest,
            approvald_key_epoch,
        } => {
            encoder
                .array(8)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &approval_record_digest)?;
            encode_fixed(encoder, &ceremony_record_digest)?;
            encode_agent_authentication_transfer_terminal_state(encoder, transfer_state)?;
            encode_fixed(encoder, &settlement_digest)?;
            encoder
                .u64(complete_index_generation)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &current_journal_head_digest)?;
            encoder
                .u64(approvald_key_epoch)
                .map_err(ProtocolError::malformed)?;
        }
        AgentAuthenticationClosureEvidenceV2::Indeterminate {
            observation_digest,
            complete_index_generation,
            current_journal_head_digest,
            approvald_key_epoch,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(4))
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &observation_digest)?;
            encoder
                .u64(complete_index_generation)
                .map_err(ProtocolError::malformed)?;
            encode_fixed(encoder, &current_journal_head_digest)?;
            encoder
                .u64(approvald_key_epoch)
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(())
}

fn decode_agent_authentication_closure_evidence(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<AgentAuthenticationClosureEvidenceV2, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let value = match (tag, length) {
        (1, 6) => AgentAuthenticationClosureEvidenceV2::NeverRegisteredDenylisted {
            complete_index_generation: decoder.u64().map_err(ProtocolError::malformed)?,
            current_journal_head_digest: decode_fixed(decoder, context)?,
            denylist_tombstone_sequence: decoder.u64().map_err(ProtocolError::malformed)?,
            denylist_tombstone_digest: decode_fixed(decoder, context)?,
            approvald_key_epoch: decoder.u64().map_err(ProtocolError::malformed)?,
        },
        (2, 10) => AgentAuthenticationClosureEvidenceV2::RegisteredInvalidatedUnredeemed {
            approval_record_digest: decode_fixed(decoder, context)?,
            ceremony_record_digest: decode_fixed(decoder, context)?,
            transfer_state: decode_agent_authentication_transfer_terminal_state(decoder, context)?,
            approvald_terminal_transaction_digest: decode_fixed(decoder, context)?,
            complete_index_generation: decoder.u64().map_err(ProtocolError::malformed)?,
            current_journal_head_digest: decode_fixed(decoder, context)?,
            denylist_tombstone_sequence: decoder.u64().map_err(ProtocolError::malformed)?,
            denylist_tombstone_digest: decode_fixed(decoder, context)?,
            approvald_key_epoch: decoder.u64().map_err(ProtocolError::malformed)?,
        },
        (3, 8) => AgentAuthenticationClosureEvidenceV2::SettlementOrTransferObserved {
            approval_record_digest: decode_fixed(decoder, context)?,
            ceremony_record_digest: decode_fixed(decoder, context)?,
            transfer_state: decode_agent_authentication_transfer_terminal_state(decoder, context)?,
            settlement_digest: decode_fixed(decoder, context)?,
            complete_index_generation: decoder.u64().map_err(ProtocolError::malformed)?,
            current_journal_head_digest: decode_fixed(decoder, context)?,
            approvald_key_epoch: decoder.u64().map_err(ProtocolError::malformed)?,
        },
        (4, 5) => AgentAuthenticationClosureEvidenceV2::Indeterminate {
            observation_digest: decode_fixed(decoder, context)?,
            complete_index_generation: decoder.u64().map_err(ProtocolError::malformed)?,
            current_journal_head_digest: decode_fixed(decoder, context)?,
            approvald_key_epoch: decoder.u64().map_err(ProtocolError::malformed)?,
        },
        _ => return Err(malformed()),
    };
    value.validate()
}

fn encode_fixed<T: minicbor::Encode<()>>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &T,
) -> Result<(), ProtocolError> {
    minicbor::Encode::encode(value, encoder, &mut ()).map_err(ProtocolError::malformed)
}

fn encode_optional_fixed<T: minicbor::Encode<()>>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<T>,
) -> Result<(), ProtocolError> {
    match value {
        Some(value) => encode_fixed(encoder, &value),
        None => {
            encoder.null().map_err(ProtocolError::malformed)?;
            Ok(())
        }
    }
}

fn decode_fixed<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
) -> Result<T, ProtocolError>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)
}

fn decode_optional_fixed<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
) -> Result<Option<T>, ProtocolError>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    if decoder.datatype().map_err(ProtocolError::malformed)? == minicbor::data::Type::Null {
        decoder.null().map_err(ProtocolError::malformed)?;
        Ok(None)
    } else {
        decode_fixed(decoder, context).map(Some)
    }
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(expected) {
        return Err(malformed());
    }
    Ok(())
}

fn expect_schema_two(decoder: &mut minicbor::Decoder<'_>) -> Result<(), ProtocolError> {
    if decoder.u16().map_err(ProtocolError::malformed)? != 2 {
        return Err(malformed());
    }
    Ok(())
}

fn require_canonical_end(
    decoder: &minicbor::Decoder<'_>,
    original: &[u8],
    canonical: Vec<u8>,
) -> Result<(), ProtocolError> {
    if decoder.position() != original.len() || canonical != original {
        return Err(malformed());
    }
    Ok(())
}

fn validate_signature_parts(
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
) -> Result<(), ProtocolError> {
    if is_zero(key_id.as_bytes()) || is_zero(signature.as_bytes()) {
        return Err(malformed());
    }
    Ok(())
}

fn approval_binding_is_nonzero(binding: ApprovalBindingV2) -> bool {
    match binding {
        ApprovalBindingV2::Ingress {
            pending_ingress_id,
            ingress_subject_digest,
            channel_commitments_digest,
            source_provenance_digest,
        } => [
            pending_ingress_id,
            ingress_subject_digest,
            channel_commitments_digest,
            source_provenance_digest,
        ]
        .iter()
        .all(|digest| !is_zero(digest.as_bytes())),
        ApprovalBindingV2::ToolExecution {
            action_intent_id, ..
        } => !is_zero(action_intent_id.as_bytes()),
        ApprovalBindingV2::FinalRelease { .. } => true,
    }
}

fn ui_authentication_binding_is_nonzero(binding: UiAuthenticationBindingV2) -> bool {
    match binding {
        UiAuthenticationBindingV2::IngressNewTask {
            durable_task_id,
            pending_task_digest,
            ingressd_identity,
        } => {
            !is_zero(durable_task_id.as_bytes())
                && !is_zero(pending_task_digest.as_bytes())
                && !is_zero(ingressd_identity.as_bytes())
        }
        UiAuthenticationBindingV2::IngressExistingRun {
            durable_task_id,
            durable_run_id,
            captured_run_revision_digest,
            ingressd_identity,
        } => {
            !is_zero(durable_task_id.as_bytes())
                && !is_zero(durable_run_id.as_bytes())
                && !is_zero(captured_run_revision_digest.as_bytes())
                && !is_zero(ingressd_identity.as_bytes())
        }
        UiAuthenticationBindingV2::ApprovalDisplay {
            durable_task_id,
            approval_envelope_digest,
            display_digest,
            ..
        } => {
            !is_zero(durable_task_id.as_bytes())
                && !is_zero(approval_envelope_digest.as_bytes())
                && !is_zero(display_digest.as_bytes())
        }
        UiAuthenticationBindingV2::AgentContent {
            durable_task_id,
            ingress_claim_digest,
            agentd_identity,
            agentd_boot_id,
        } => {
            !is_zero(durable_task_id.as_bytes())
                && !is_zero(ingress_claim_digest.as_bytes())
                && !is_zero(agentd_identity.as_bytes())
                && !is_zero(agentd_boot_id.as_bytes())
        }
    }
}

const fn approval_envelope_domain(purpose: ApprovalPurposeV2) -> &'static [u8] {
    match purpose {
        ApprovalPurposeV2::Ingress => INGRESS_APPROVAL_ENVELOPE_DOMAIN_V2,
        ApprovalPurposeV2::ToolExecution => TOOL_APPROVAL_ENVELOPE_DOMAIN_V2,
        ApprovalPurposeV2::FinalRelease => RELEASE_APPROVAL_ENVELOPE_DOMAIN_V2,
    }
}

const fn ui_authentication_envelope_domain(purpose: UiAuthenticationPurposeV2) -> &'static [u8] {
    match purpose {
        UiAuthenticationPurposeV2::IngressInput => UI_AUTH_INGRESS_ENVELOPE_DOMAIN_V2,
        UiAuthenticationPurposeV2::ApprovalDisplay => UI_AUTH_APPROVAL_DISPLAY_ENVELOPE_DOMAIN_V2,
        UiAuthenticationPurposeV2::AgentContent => UI_AUTH_AGENT_ENVELOPE_DOMAIN_V2,
    }
}

const fn ui_authentication_settlement_domain(purpose: UiAuthenticationPurposeV2) -> &'static [u8] {
    match purpose {
        UiAuthenticationPurposeV2::IngressInput => UI_AUTH_INGRESS_SETTLEMENT_DOMAIN_V2,
        UiAuthenticationPurposeV2::ApprovalDisplay => UI_AUTH_APPROVAL_DISPLAY_SETTLEMENT_DOMAIN_V2,
        UiAuthenticationPurposeV2::AgentContent => UI_AUTH_AGENT_SETTLEMENT_DOMAIN_V2,
    }
}

const fn approval_settlement_domain(purpose: ApprovalPurposeV2) -> &'static [u8] {
    match purpose {
        ApprovalPurposeV2::Ingress => INGRESS_APPROVAL_SETTLEMENT_DOMAIN_V2,
        ApprovalPurposeV2::ToolExecution => TOOL_APPROVAL_SETTLEMENT_DOMAIN_V2,
        ApprovalPurposeV2::FinalRelease => RELEASE_APPROVAL_SETTLEMENT_DOMAIN_V2,
    }
}

fn sign_domain_digest(
    signing_key: &SigningKey,
    domain: &[u8],
    digest: Digest32V2,
) -> Ed25519SignatureV2 {
    let mut signature_input = Vec::with_capacity(domain.len() + 32);
    signature_input.extend_from_slice(domain);
    signature_input.extend_from_slice(digest.as_bytes());
    Ed25519SignatureV2::new(signing_key.sign(&signature_input).to_bytes())
}

fn sign_payload_digest(
    signing_key: &SigningKey,
    domain: &[u8],
    canonical_payload: &[u8],
) -> Ed25519SignatureV2 {
    let digest = Sha256::digest(canonical_payload);
    let mut signature_input = Vec::with_capacity(domain.len() + digest.len());
    signature_input.extend_from_slice(domain);
    signature_input.extend_from_slice(&digest);
    Ed25519SignatureV2::new(signing_key.sign(&signature_input).to_bytes())
}

fn verify_payload_digest(
    verifying_key: [u8; 32],
    domain: &[u8],
    canonical_payload: &[u8],
    signature: Ed25519SignatureV2,
) -> Result<(), ProtocolError> {
    let digest = Sha256::digest(canonical_payload);
    let mut signature_input = Vec::with_capacity(domain.len() + digest.len());
    signature_input.extend_from_slice(domain);
    signature_input.extend_from_slice(&digest);
    let key = VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| ProtocolError::stable(StableCode::ApprovalInvalidSignature))?;
    key.verify_strict(
        &signature_input,
        &Signature::from_bytes(signature.as_bytes()),
    )
    .map_err(|_| ProtocolError::stable(StableCode::ApprovalInvalidSignature))
}

fn verify_domain_digest(
    verifying_key: [u8; 32],
    domain: &[u8],
    canonical_payload: &[u8],
    signature: Ed25519SignatureV2,
) -> Result<(), ProtocolError> {
    let digest = domain_hash(domain, canonical_payload);
    let mut signature_input = Vec::with_capacity(domain.len() + 32);
    signature_input.extend_from_slice(domain);
    signature_input.extend_from_slice(digest.as_bytes());
    let key = VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| ProtocolError::stable(StableCode::ApprovalInvalidSignature))?;
    key.verify_strict(
        &signature_input,
        &Signature::from_bytes(signature.as_bytes()),
    )
    .map_err(|_| ProtocolError::stable(StableCode::ApprovalInvalidSignature))
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn option_is_zero(value: Option<Digest32V2>) -> bool {
    value.is_some_and(|digest| is_zero(digest.as_bytes()))
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};

    use super::{
        encode_unsigned_approval_settlement_v2, encode_unsigned_ui_authentication_settlement_v2,
        ApprovalDecisionV2, ApprovalPurposeV2, SignedApprovalSettlementV2,
        SignedUiAuthenticationSettlementV2, UiAuthenticationPurposeV2,
        UnsignedApprovalSettlementV2, UnsignedUiAuthenticationSettlementV2,
    };
    use crate::v2::{
        derive_ed25519_key_id_v2, Digest32V2, Ed25519SignatureV2, FixedOriginV2, Nonce32V2,
        PrincipalIdV2, UnixMillisV2,
    };
    use crate::StableCode;

    const DOMAIN: &[u8] = b"SAVANA_UI_AUTH_INGRESS_SETTLEMENT_V2\0";

    fn signed_ui_settlement() -> (
        SignedUiAuthenticationSettlementV2,
        [u8; 32],
        Digest32V2,
        Digest32V2,
    ) {
        let installation = Digest32V2::new([0x11; 32]);
        let manifest = Digest32V2::new([0x12; 32]);
        let unsigned = UnsignedUiAuthenticationSettlementV2::new(
            installation,
            manifest,
            7,
            UiAuthenticationPurposeV2::IngressInput,
            Digest32V2::new([0x13; 32]),
            Digest32V2::new([0x14; 32]),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Ingress8767,
            PrincipalIdV2::new([0x15; 32]),
            Digest32V2::new([0x16; 32]),
            Digest32V2::new([0x17; 32]),
            true,
            true,
            false,
            false,
            1,
            Nonce32V2::new([0x18; 32]),
            Nonce32V2::new([0x19; 32]),
            UnixMillisV2::new(100),
            UnixMillisV2::new(200),
        )
        .unwrap();
        let payload = encode_unsigned_ui_authentication_settlement_v2(&unsigned).unwrap();
        let signing_key = SigningKey::from_bytes(&[0x21; 32]);
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(&payload);
        let payload_digest: [u8; 32] = digest.finalize().into();
        let mut signing_input = Vec::from(DOMAIN);
        signing_input.extend_from_slice(&payload_digest);
        let signature = signing_key.sign(&signing_input).to_bytes();
        (
            SignedUiAuthenticationSettlementV2::from_parts(
                unsigned,
                derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
                Ed25519SignatureV2::new(signature),
            )
            .unwrap(),
            signing_key.verifying_key().to_bytes(),
            installation,
            manifest,
        )
    }

    #[test]
    fn ui_authentication_settlement_verification_binds_key_deployment_and_time() {
        let (signed, public_key, installation, manifest) = signed_ui_settlement();
        let verified = signed
            .verify_ingress_input(
                derive_ed25519_key_id_v2(public_key),
                public_key,
                installation,
                manifest,
                7,
                UnixMillisV2::new(150),
            )
            .unwrap();

        assert_eq!(
            verified.authenticated_principal(),
            PrincipalIdV2::new([0x15; 32])
        );
        assert_eq!(
            verified.authentication_context_digest(),
            Digest32V2::new([0x16; 32])
        );
        assert_eq!(verified.binding_digest(), Digest32V2::new([0x14; 32]));
        assert_ne!(verified.settlement_digest(), Digest32V2::new([0; 32]));

        assert_eq!(
            signed
                .verify_ingress_input(
                    derive_ed25519_key_id_v2(public_key),
                    public_key,
                    installation,
                    manifest,
                    7,
                    UnixMillisV2::new(200),
                )
                .unwrap_err()
                .code(),
            StableCode::ApprovalReplayed
        );
    }

    #[test]
    fn ingress_approval_settlement_verification_binds_envelope_principal_and_challenge() {
        let installation = Digest32V2::new([0x41; 32]);
        let manifest = Digest32V2::new([0x42; 32]);
        let envelope = Digest32V2::new([0x43; 32]);
        let principal = PrincipalIdV2::new([0x44; 32]);
        let challenge = Nonce32V2::new([0x45; 32]);
        let unsigned = UnsignedApprovalSettlementV2::new(
            installation,
            manifest,
            9,
            ApprovalPurposeV2::Ingress,
            envelope,
            ApprovalDecisionV2::Approve,
            principal,
            Digest32V2::new([0x46; 32]),
            Digest32V2::new([0x47; 32]),
            true,
            true,
            false,
            false,
            1,
            challenge,
            Nonce32V2::new([0x48; 32]),
            UnixMillisV2::new(100),
            UnixMillisV2::new(200),
        )
        .unwrap();
        let payload = encode_unsigned_approval_settlement_v2(&unsigned).unwrap();
        let signing_key = SigningKey::from_bytes(&[0x49; 32]);
        let domain = b"SAVANA_INGRESS_APPROVAL_SETTLEMENT_V2\0";
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(&payload);
        let payload_digest: [u8; 32] = digest.finalize().into();
        let mut signing_input = Vec::from(domain);
        signing_input.extend_from_slice(&payload_digest);
        let signed = SignedApprovalSettlementV2::from_parts(
            unsigned,
            derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
            Ed25519SignatureV2::new(signing_key.sign(&signing_input).to_bytes()),
        )
        .unwrap();

        let verified = signed
            .verify_ingress(
                derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
                signing_key.verifying_key().to_bytes(),
                installation,
                manifest,
                9,
                envelope,
                principal,
                challenge,
                UnixMillisV2::new(150),
            )
            .unwrap();
        assert_eq!(verified.decision(), ApprovalDecisionV2::Approve);
        assert_eq!(verified.authenticated_principal(), principal);
        assert_ne!(verified.settlement_digest(), Digest32V2::new([0; 32]));
    }
}
