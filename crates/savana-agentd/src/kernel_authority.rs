use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    decode_public_task_status_v2, encode_public_task_status_v2, BootIdV2, Digest32V2,
    DurableTaskIdV2, Ed25519KeyIdV2, Ed25519SignatureV2, PublicTaskStatusV2, ServiceIdentityV2,
    UnixMillisV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    is_zero, AgentTaskErrorV2, AuthenticatedJarvisControlV2, VerifiedKernelCancellationV2,
    VerifiedKernelTaskPreparationV2, VerifiedKernelTaskStatusV2,
};

const SIGNATURE_DOMAIN: &[u8] = b"SAVANA_KERNEL_AGENT_TASK_STATEMENT_V2\0";
const SCHEMA_VERSION: u16 = 2;
const PREPARATION_TAG: u16 = 1;
const STATUS_TAG: u16 = 2;
const CANCELLATION_TAG: u16 = 3;
const MAX_STATEMENT_BYTES: usize = 8 * 1024;
const AUTHORITY_BINDING_DOMAIN: &[u8] = b"SAVANA_KERNEL_AGENT_TASK_AUTHORITY_BINDING_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelTaskStatementV2 {
    Preparation {
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        machine_boot_id: BootIdV2,
        jarvis_control_client_boot_id: BootIdV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        kernel_bootstrap_binding_digest: Digest32V2,
        task_logical_expires_at: UnixMillisV2,
        status_retain_until: UnixMillisV2,
    },
    Status {
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        status: PublicTaskStatusV2,
        public_state_revision: u64,
    },
    Cancellation {
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        cancellation_commit_digest: Digest32V2,
    },
}

impl KernelTaskStatementV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn preparation(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        machine_boot_id: BootIdV2,
        jarvis_control_client_boot_id: BootIdV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        kernel_bootstrap_binding_digest: Digest32V2,
        task_logical_expires_at: UnixMillisV2,
        status_retain_until: UnixMillisV2,
    ) -> Result<Self, AgentTaskErrorV2> {
        let statement = Self::Preparation {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            machine_boot_id,
            jarvis_control_client_boot_id,
            agentd_server_boot_id,
            kerneld_server_boot_id,
            durable_task_id,
            correlation_digest,
            kernel_bootstrap_binding_digest,
            task_logical_expires_at,
            status_retain_until,
        };
        statement.validate()?;
        Ok(statement)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn status(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        status: PublicTaskStatusV2,
        public_state_revision: u64,
    ) -> Result<Self, AgentTaskErrorV2> {
        let statement = Self::Status {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            agentd_server_boot_id,
            kerneld_server_boot_id,
            durable_task_id,
            correlation_digest,
            status: super::strip_bootstrap(status),
            public_state_revision,
        };
        statement.validate()?;
        Ok(statement)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cancellation(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        durable_task_id: DurableTaskIdV2,
        correlation_digest: Digest32V2,
        cancellation_commit_digest: Digest32V2,
    ) -> Result<Self, AgentTaskErrorV2> {
        let statement = Self::Cancellation {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            agentd_server_boot_id,
            kerneld_server_boot_id,
            durable_task_id,
            correlation_digest,
            cancellation_commit_digest,
        };
        statement.validate()?;
        Ok(statement)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AgentTaskErrorV2> {
        let payload = self.canonical_payload()?;
        let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32);
        bytes.extend_from_slice(SIGNATURE_DOMAIN);
        bytes.extend_from_slice(&Sha256::digest(&payload));
        Ok(bytes)
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, AgentTaskErrorV2> {
        self.validate()?;
        let mut encoder = minicbor::Encoder::new(Vec::new());
        match *self {
            Self::Preparation {
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                protocol_abi_digest,
                agentd_identity,
                machine_boot_id,
                jarvis_control_client_boot_id,
                agentd_server_boot_id,
                kerneld_server_boot_id,
                durable_task_id,
                correlation_digest,
                kernel_bootstrap_binding_digest,
                task_logical_expires_at,
                status_retain_until,
            } => {
                encoder
                    .array(15)
                    .and_then(|encoder| encoder.u16(PREPARATION_TAG))
                    .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
                encode_many(
                    &mut encoder,
                    &[
                        installation_id.as_bytes(),
                        active_state_manifest_digest.as_bytes(),
                    ],
                )?;
                encoder
                    .u64(deployment_generation)
                    .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
                encode_many(
                    &mut encoder,
                    &[
                        protocol_abi_digest.as_bytes(),
                        agentd_identity.as_bytes(),
                        machine_boot_id.as_bytes(),
                        jarvis_control_client_boot_id.as_bytes(),
                        agentd_server_boot_id.as_bytes(),
                        kerneld_server_boot_id.as_bytes(),
                        durable_task_id.as_bytes(),
                        correlation_digest.as_bytes(),
                        kernel_bootstrap_binding_digest.as_bytes(),
                    ],
                )?;
                encoder
                    .u64(task_logical_expires_at.get())
                    .and_then(|encoder| encoder.u64(status_retain_until.get()))
                    .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
            }
            Self::Status {
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                protocol_abi_digest,
                agentd_identity,
                agentd_server_boot_id,
                kerneld_server_boot_id,
                durable_task_id,
                correlation_digest,
                status,
                public_state_revision,
            } => {
                encoder
                    .array(12)
                    .and_then(|encoder| encoder.u16(STATUS_TAG))
                    .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
                encode_many(
                    &mut encoder,
                    &[
                        installation_id.as_bytes(),
                        active_state_manifest_digest.as_bytes(),
                    ],
                )?;
                encoder
                    .u64(deployment_generation)
                    .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
                encode_many(
                    &mut encoder,
                    &[
                        protocol_abi_digest.as_bytes(),
                        agentd_identity.as_bytes(),
                        agentd_server_boot_id.as_bytes(),
                        kerneld_server_boot_id.as_bytes(),
                        durable_task_id.as_bytes(),
                        correlation_digest.as_bytes(),
                    ],
                )?;
                let status = encode_public_task_status_v2(&status)
                    .map_err(|_| AgentTaskErrorV2::InvalidInput)?;
                encoder
                    .bytes(&status)
                    .and_then(|encoder| encoder.u64(public_state_revision))
                    .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
            }
            Self::Cancellation {
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                protocol_abi_digest,
                agentd_identity,
                agentd_server_boot_id,
                kerneld_server_boot_id,
                durable_task_id,
                correlation_digest,
                cancellation_commit_digest,
            } => {
                encoder
                    .array(11)
                    .and_then(|encoder| encoder.u16(CANCELLATION_TAG))
                    .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
                encode_many(
                    &mut encoder,
                    &[
                        installation_id.as_bytes(),
                        active_state_manifest_digest.as_bytes(),
                    ],
                )?;
                encoder
                    .u64(deployment_generation)
                    .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
                encode_many(
                    &mut encoder,
                    &[
                        protocol_abi_digest.as_bytes(),
                        agentd_identity.as_bytes(),
                        agentd_server_boot_id.as_bytes(),
                        kerneld_server_boot_id.as_bytes(),
                        durable_task_id.as_bytes(),
                        correlation_digest.as_bytes(),
                        cancellation_commit_digest.as_bytes(),
                    ],
                )?;
            }
        }
        let bytes = encoder.into_writer();
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(AgentTaskErrorV2::AllocationFailure);
        }
        Ok(bytes)
    }

    fn validate(self) -> Result<(), AgentTaskErrorV2> {
        let valid = match self {
            Self::Preparation {
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                protocol_abi_digest,
                agentd_identity,
                machine_boot_id,
                jarvis_control_client_boot_id,
                agentd_server_boot_id,
                kerneld_server_boot_id,
                durable_task_id,
                correlation_digest,
                kernel_bootstrap_binding_digest,
                task_logical_expires_at,
                status_retain_until,
            } => {
                !any_zero(&[
                    installation_id.as_bytes(),
                    active_state_manifest_digest.as_bytes(),
                    protocol_abi_digest.as_bytes(),
                    agentd_identity.as_bytes(),
                    machine_boot_id.as_bytes(),
                    jarvis_control_client_boot_id.as_bytes(),
                    agentd_server_boot_id.as_bytes(),
                    kerneld_server_boot_id.as_bytes(),
                    durable_task_id.as_bytes(),
                    correlation_digest.as_bytes(),
                    kernel_bootstrap_binding_digest.as_bytes(),
                ]) && deployment_generation != 0
                    && task_logical_expires_at.get() != 0
                    && status_retain_until.get() > task_logical_expires_at.get()
            }
            Self::Status {
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                protocol_abi_digest,
                agentd_identity,
                agentd_server_boot_id,
                kerneld_server_boot_id,
                durable_task_id,
                correlation_digest,
                status,
                public_state_revision,
            } => {
                !any_zero(&[
                    installation_id.as_bytes(),
                    active_state_manifest_digest.as_bytes(),
                    protocol_abi_digest.as_bytes(),
                    agentd_identity.as_bytes(),
                    agentd_server_boot_id.as_bytes(),
                    kerneld_server_boot_id.as_bytes(),
                    durable_task_id.as_bytes(),
                    correlation_digest.as_bytes(),
                ]) && deployment_generation != 0
                    && public_state_revision != 0
                    && status == super::strip_bootstrap(status)
                    && encode_public_task_status_v2(&status).is_ok()
            }
            Self::Cancellation {
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                protocol_abi_digest,
                agentd_identity,
                agentd_server_boot_id,
                kerneld_server_boot_id,
                durable_task_id,
                correlation_digest,
                cancellation_commit_digest,
            } => {
                !any_zero(&[
                    installation_id.as_bytes(),
                    active_state_manifest_digest.as_bytes(),
                    protocol_abi_digest.as_bytes(),
                    agentd_identity.as_bytes(),
                    agentd_server_boot_id.as_bytes(),
                    kerneld_server_boot_id.as_bytes(),
                    durable_task_id.as_bytes(),
                    correlation_digest.as_bytes(),
                    cancellation_commit_digest.as_bytes(),
                ]) && deployment_generation != 0
            }
        };
        if valid {
            Ok(())
        } else {
            Err(AgentTaskErrorV2::InvalidInput)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedKernelTaskStatementV2 {
    statement: KernelTaskStatementV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedKernelTaskStatementV2 {
    pub fn from_kernel_signature(
        statement: KernelTaskStatementV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, AgentTaskErrorV2> {
        statement.validate()?;
        if is_zero(key_id.as_bytes()) || signature.as_bytes() == &[0; 64] {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        Ok(Self {
            statement,
            key_id,
            signature,
        })
    }

    pub const fn statement(self) -> KernelTaskStatementV2 {
        self.statement
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AgentTaskErrorV2> {
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        require_array(&mut decoder, 4)?;
        if decoder
            .u16()
            .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?
            != SCHEMA_VERSION
        {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        let key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
        let payload = decoder
            .bytes()
            .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?;
        let statement = decode_statement(payload)?;
        let signature = Ed25519SignatureV2::new(decode_fixed::<64>(&mut decoder)?);
        if decoder.position() != bytes.len() {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        let signed = Self::from_kernel_signature(statement, key_id, signature)
            .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?;
        if signed.canonical_bytes()?.as_slice() != bytes {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        Ok(signed)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AgentTaskErrorV2> {
        let payload = self.statement.canonical_payload()?;
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(4)
            .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        self.key_id
            .encode(&mut encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        encoder
            .bytes(&payload)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        self.signature
            .encode(&mut encoder, &mut ())
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
        Ok(encoder.into_writer())
    }
}

pub struct KernelTaskAuthorityVerifierV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    protocol_abi_digest: Digest32V2,
    agentd_identity: ServiceIdentityV2,
    current_agentd_boot_id: BootIdV2,
    current_kerneld_boot_id: BootIdV2,
    key_id: Ed25519KeyIdV2,
    authority_binding_digest: Digest32V2,
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for KernelTaskAuthorityVerifierV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelTaskAuthorityVerifierV2")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl KernelTaskAuthorityVerifierV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        current_agentd_boot_id: BootIdV2,
        current_kerneld_boot_id: BootIdV2,
        key_id: Ed25519KeyIdV2,
        public_key: [u8; 32],
    ) -> Result<Self, AgentTaskErrorV2> {
        if any_zero(&[
            installation_id.as_bytes(),
            active_state_manifest_digest.as_bytes(),
            protocol_abi_digest.as_bytes(),
            agentd_identity.as_bytes(),
            current_agentd_boot_id.as_bytes(),
            current_kerneld_boot_id.as_bytes(),
            key_id.as_bytes(),
            &public_key,
        ]) || deployment_generation == 0
        {
            return Err(AgentTaskErrorV2::InvalidInput);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| AgentTaskErrorV2::InvalidInput)?;
        let authority_binding_digest = kernel_task_authority_binding_digest(key_id, &public_key);
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            current_agentd_boot_id,
            current_kerneld_boot_id,
            key_id,
            authority_binding_digest,
            verifying_key,
        })
    }

    pub fn verify_preparation(
        &self,
        signed: SignedKernelTaskStatementV2,
        context: AuthenticatedJarvisControlV2,
    ) -> Result<VerifiedKernelTaskPreparationV2, AgentTaskErrorV2> {
        self.verify_signature(signed)?;
        let KernelTaskStatementV2::Preparation {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            machine_boot_id,
            jarvis_control_client_boot_id,
            agentd_server_boot_id,
            kerneld_server_boot_id,
            durable_task_id,
            correlation_digest,
            kernel_bootstrap_binding_digest,
            task_logical_expires_at,
            status_retain_until,
        } = signed.statement
        else {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        };
        if !self.common_matches(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            agentd_server_boot_id,
            kerneld_server_boot_id,
        ) || context.installation_id != installation_id
            || context.origin_boots.machine_boot_id != machine_boot_id
            || context.origin_boots.jarvis_control_client_boot_id != jarvis_control_client_boot_id
            || context.origin_boots.agentd_server_boot_id != agentd_server_boot_id
            || context.origin_boots.kerneld_server_boot_id != kerneld_server_boot_id
        {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        VerifiedKernelTaskPreparationV2::from_verified_correlation(
            durable_task_id,
            correlation_digest,
            kernel_bootstrap_binding_digest,
            task_logical_expires_at,
            status_retain_until,
            self.authority_binding_digest,
        )
    }

    pub fn verify_status(
        &self,
        signed: SignedKernelTaskStatementV2,
    ) -> Result<VerifiedKernelTaskStatusV2, AgentTaskErrorV2> {
        self.verify_signature(signed)?;
        let KernelTaskStatementV2::Status {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            agentd_server_boot_id,
            kerneld_server_boot_id,
            durable_task_id,
            correlation_digest,
            status,
            public_state_revision,
        } = signed.statement
        else {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        };
        if !self.common_matches(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            agentd_server_boot_id,
            kerneld_server_boot_id,
        ) {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        VerifiedKernelTaskStatusV2::from_verified_query(
            durable_task_id,
            correlation_digest,
            status,
            public_state_revision,
            self.authority_binding_digest,
        )
    }

    pub fn verify_cancellation(
        &self,
        signed: SignedKernelTaskStatementV2,
    ) -> Result<VerifiedKernelCancellationV2, AgentTaskErrorV2> {
        self.verify_signature(signed)?;
        let KernelTaskStatementV2::Cancellation {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            agentd_server_boot_id,
            kerneld_server_boot_id,
            durable_task_id,
            correlation_digest,
            cancellation_commit_digest,
        } = signed.statement
        else {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        };
        if !self.common_matches(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            protocol_abi_digest,
            agentd_identity,
            agentd_server_boot_id,
            kerneld_server_boot_id,
        ) {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        VerifiedKernelCancellationV2::cancelled(
            durable_task_id,
            correlation_digest,
            cancellation_commit_digest,
            self.authority_binding_digest,
        )
    }

    fn verify_signature(
        &self,
        signed: SignedKernelTaskStatementV2,
    ) -> Result<(), AgentTaskErrorV2> {
        if signed.key_id != self.key_id {
            return Err(AgentTaskErrorV2::KernelAuthentication);
        }
        let input = signed.statement.signing_bytes()?;
        self.verifying_key
            .verify_strict(&input, &Signature::from_bytes(signed.signature.as_bytes()))
            .map_err(|_| AgentTaskErrorV2::KernelAuthentication)
    }

    #[allow(clippy::too_many_arguments)]
    fn common_matches(
        &self,
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        protocol_abi_digest: Digest32V2,
        agentd_identity: ServiceIdentityV2,
        agentd_server_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
    ) -> bool {
        installation_id == self.installation_id
            && active_state_manifest_digest == self.active_state_manifest_digest
            && deployment_generation == self.deployment_generation
            && protocol_abi_digest == self.protocol_abi_digest
            && agentd_identity == self.agentd_identity
            && agentd_server_boot_id == self.current_agentd_boot_id
            && kerneld_server_boot_id == self.current_kerneld_boot_id
    }
}

fn encode_many(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    values: &[&[u8; 32]],
) -> Result<(), AgentTaskErrorV2> {
    for value in values {
        encoder
            .bytes(*value)
            .map_err(|_| AgentTaskErrorV2::AllocationFailure)?;
    }
    Ok(())
}

fn decode_statement(bytes: &[u8]) -> Result<KernelTaskStatementV2, AgentTaskErrorV2> {
    if bytes.len() > MAX_STATEMENT_BYTES {
        return Err(AgentTaskErrorV2::KernelAuthentication);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let length = decoder
        .array()
        .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?
        .ok_or(AgentTaskErrorV2::KernelAuthentication)?;
    let tag = decoder
        .u16()
        .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?;
    let statement = match (tag, length) {
        (PREPARATION_TAG, 15) => KernelTaskStatementV2::preparation(
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            decoder
                .u64()
                .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?,
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?),
            BootIdV2::new(decode_fixed::<32>(&mut decoder)?),
            BootIdV2::new(decode_fixed::<32>(&mut decoder)?),
            BootIdV2::new(decode_fixed::<32>(&mut decoder)?),
            BootIdV2::new(decode_fixed::<32>(&mut decoder)?),
            DurableTaskIdV2::new(decode_fixed::<32>(&mut decoder)?),
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            UnixMillisV2::new(
                decoder
                    .u64()
                    .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?,
            ),
            UnixMillisV2::new(
                decoder
                    .u64()
                    .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?,
            ),
        ),
        (STATUS_TAG, 12) => {
            let installation_id = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
            let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
            let deployment_generation = decoder
                .u64()
                .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?;
            let protocol_abi_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
            let agentd_identity = ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?);
            let agentd_server_boot_id = BootIdV2::new(decode_fixed::<32>(&mut decoder)?);
            let kerneld_server_boot_id = BootIdV2::new(decode_fixed::<32>(&mut decoder)?);
            let durable_task_id = DurableTaskIdV2::new(decode_fixed::<32>(&mut decoder)?);
            let correlation_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
            let status = decode_public_task_status_v2(
                decoder
                    .bytes()
                    .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?,
            )
            .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?;
            let public_state_revision = decoder
                .u64()
                .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?;
            KernelTaskStatementV2::status(
                installation_id,
                active_state_manifest_digest,
                deployment_generation,
                protocol_abi_digest,
                agentd_identity,
                agentd_server_boot_id,
                kerneld_server_boot_id,
                durable_task_id,
                correlation_digest,
                status,
                public_state_revision,
            )
        }
        (CANCELLATION_TAG, 11) => KernelTaskStatementV2::cancellation(
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            decoder
                .u64()
                .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?,
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?),
            BootIdV2::new(decode_fixed::<32>(&mut decoder)?),
            BootIdV2::new(decode_fixed::<32>(&mut decoder)?),
            DurableTaskIdV2::new(decode_fixed::<32>(&mut decoder)?),
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
            Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        ),
        _ => return Err(AgentTaskErrorV2::KernelAuthentication),
    }
    .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?;
    if decoder.position() != bytes.len() || statement.canonical_payload()?.as_slice() != bytes {
        return Err(AgentTaskErrorV2::KernelAuthentication);
    }
    Ok(statement)
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), AgentTaskErrorV2> {
    if decoder
        .array()
        .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?
        != Some(expected)
    {
        return Err(AgentTaskErrorV2::KernelAuthentication);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], AgentTaskErrorV2> {
    decoder
        .bytes()
        .map_err(|_| AgentTaskErrorV2::KernelAuthentication)?
        .try_into()
        .map_err(|_| AgentTaskErrorV2::KernelAuthentication)
}

fn any_zero(values: &[&[u8; 32]]) -> bool {
    values.iter().any(|value| is_zero(value))
}

pub(super) fn kernel_task_authority_binding_digest(
    key_id: Ed25519KeyIdV2,
    public_key: &[u8; 32],
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_BINDING_DOMAIN);
    hasher.update(key_id.as_bytes());
    hasher.update(public_key);
    Digest32V2::new(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use savana_kernel_protocol::v2::{Ed25519SignatureV2, Nonce32V2};

    use super::*;
    use crate::AgentTaskServiceV2;

    fn fixture() -> (
        KernelTaskAuthorityVerifierV2,
        SigningKey,
        AuthenticatedJarvisControlV2,
    ) {
        let signing = SigningKey::from_bytes(&[21; 32]);
        let verifier = KernelTaskAuthorityVerifierV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([6; 32]),
            BootIdV2::new([7; 32]),
            Ed25519KeyIdV2::new([8; 32]),
            signing.verifying_key().to_bytes(),
        )
        .unwrap();
        let context = AuthenticatedJarvisControlV2::from_mutual_authentication(
            Digest32V2::new([1; 32]),
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            BootIdV2::new([11; 32]),
            BootIdV2::new([12; 32]),
            BootIdV2::new([6; 32]),
            BootIdV2::new([7; 32]),
        )
        .unwrap();
        (verifier, signing, context)
    }

    fn sign(signing: &SigningKey, statement: KernelTaskStatementV2) -> SignedKernelTaskStatementV2 {
        let signature = signing.sign(&statement.signing_bytes().unwrap()).to_bytes();
        SignedKernelTaskStatementV2::from_kernel_signature(
            statement,
            Ed25519KeyIdV2::new([8; 32]),
            Ed25519SignatureV2::new(signature),
        )
        .unwrap()
    }

    fn preparation_statement() -> KernelTaskStatementV2 {
        KernelTaskStatementV2::preparation(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([11; 32]),
            BootIdV2::new([12; 32]),
            BootIdV2::new([6; 32]),
            BootIdV2::new([7; 32]),
            DurableTaskIdV2::new([13; 32]),
            Digest32V2::new([14; 32]),
            Digest32V2::new([15; 32]),
            UnixMillisV2::new(1_000),
            UnixMillisV2::new(2_000),
        )
        .unwrap()
    }

    #[test]
    fn signed_preparation_is_bound_to_deployment_and_all_four_boots() {
        let (verifier, signing, context) = fixture();
        let verified = verifier
            .verify_preparation(sign(&signing, preparation_statement()), context)
            .unwrap();
        assert_eq!(verified.durable_task_id(), DurableTaskIdV2::new([13; 32]));

        let wrong_context = AuthenticatedJarvisControlV2::from_mutual_authentication(
            Digest32V2::new([1; 32]),
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            BootIdV2::new([11; 32]),
            BootIdV2::new([16; 32]),
            BootIdV2::new([6; 32]),
            BootIdV2::new([7; 32]),
        )
        .unwrap();
        assert_eq!(
            verifier.verify_preparation(sign(&signing, preparation_statement()), wrong_context),
            Err(AgentTaskErrorV2::KernelAuthentication)
        );
    }

    #[test]
    fn signature_and_statement_purpose_cannot_be_substituted() {
        let (verifier, signing, _) = fixture();
        let status = KernelTaskStatementV2::status(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([6; 32]),
            BootIdV2::new([7; 32]),
            DurableTaskIdV2::new([13; 32]),
            Digest32V2::new([14; 32]),
            PublicTaskStatusV2::Running,
            2,
        )
        .unwrap();
        let signed = sign(&signing, status);
        assert!(verifier.verify_status(signed).is_ok());
        assert_eq!(
            verifier.verify_cancellation(signed),
            Err(AgentTaskErrorV2::KernelAuthentication)
        );

        let other_signing = SigningKey::from_bytes(&[22; 32]);
        assert_eq!(
            verifier.verify_status(sign(&other_signing, status)),
            Err(AgentTaskErrorV2::KernelAuthentication)
        );
        assert!(!signed.canonical_bytes().unwrap().is_empty());
    }

    #[test]
    fn verified_value_from_a_self_selected_key_cannot_enter_a_deployed_service() {
        let (_, legitimate_signing, context) = fixture();
        let attacker_signing = SigningKey::from_bytes(&[23; 32]);
        let attacker_verifier = KernelTaskAuthorityVerifierV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([6; 32]),
            BootIdV2::new([7; 32]),
            Ed25519KeyIdV2::new([8; 32]),
            attacker_signing.verifying_key().to_bytes(),
        )
        .unwrap();
        let attacker_verified = attacker_verifier
            .verify_preparation(sign(&attacker_signing, preparation_statement()), context)
            .unwrap();
        let mut deployed = AgentTaskServiceV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            Digest32V2::new([4; 32]),
            ServiceIdentityV2::new([5; 32]),
            BootIdV2::new([6; 32]),
            BootIdV2::new([7; 32]),
            Ed25519KeyIdV2::new([8; 32]),
            legitimate_signing.verifying_key().to_bytes(),
            128,
        )
        .unwrap();
        assert_eq!(
            deployed.prepare_ingress(
                context,
                Nonce32V2::new([24; 32]),
                attacker_verified,
                UnixMillisV2::new(100),
            ),
            Err(AgentTaskErrorV2::KernelAuthentication)
        );
    }
}
