use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
#[cfg(any(test, feature = "test-support"))]
use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2,
};
use sha2::{Digest as _, Sha256};

use super::{
    DeploymentControlErrorV2, DeploymentHardLimitsV2, DeploymentLedgerRecordV2,
    DeploymentTransactionIntentV2,
};

const ROLLBACK_GRANT_SCHEMA_VERSION_V2: u16 = 2;
const ROLLBACK_GRANT_OBJECT_DOMAIN_TAG_V2: u16 = 3;
const ROLLBACK_GRANT_SIGNATURE_TAG_V2: u16 = 4;
const TRANSACTION_AUTHORIZATION_SIGNATURE_TAG_V2: u16 = 3;
const ROLLBACK_GRANT_COMPLETE_FIELDS_V2: u64 = 19;
const ROLLBACK_GRANT_ID_FIELDS_V2: u64 = 17;
const RECOVERY_HIGH_WATER_VALUES_V2: u64 = 21;
const TRANSACTION_COMPLETE_FIELDS_V2: u64 = 5;
const TRANSACTION_PAYLOAD_FIELDS_V2: u64 = 3;
const SIGNATURE_FIELDS_V2: u64 = 4;
const ROLLBACK_GRANT_ID_DOMAIN_V2: &[u8] = b"savana.rollback-grant.v2.id\0";
const ROLLBACK_GRANT_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.rollback-grant.v2.authorization\0";
const TRANSACTION_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.deployment-transaction.v2.payload\0";
const TRANSACTION_AUTHORIZATION_DOMAIN_V2: &[u8] =
    b"savana.deployment-transaction.v2.authorization\0";
const DOMAIN_SIGNATURE_INPUT_V2: &[u8] = b"savana.domain-signature.v2\0";

#[derive(Clone)]
pub struct DeploymentAuthorizationVerifierV2 {
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for DeploymentAuthorizationVerifierV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentAuthorizationVerifierV2")
            .field("key_id", &self.key_id)
            .field("key_epoch", &self.key_epoch)
            .finish_non_exhaustive()
    }
}

impl DeploymentAuthorizationVerifierV2 {
    pub fn new(
        key_id: Ed25519KeyIdV2,
        key_epoch: u64,
        public_key: [u8; 32],
    ) -> Result<Self, DeploymentControlErrorV2> {
        if key_epoch == 0
            || is_zero(key_id.as_bytes())
            || derive_ed25519_key_id_v2(public_key) != key_id
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        Ok(Self {
            key_id,
            key_epoch,
            verifying_key,
        })
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    fn verify(
        &self,
        wrapper: ExternalDomainSignatureV2,
        expected_tag: u16,
        domain: &[u8],
        payload_digest: Digest32V2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if wrapper.domain_tag != expected_tag
            || wrapper.signer_key_id != self.key_id
            || wrapper.signer_key_epoch != self.key_epoch
            || is_zero(wrapper.signature.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let input = signature_input(expected_tag, domain, payload_digest);
        self.verifying_key
            .verify(&input, &Signature::from_bytes(wrapper.signature.as_bytes()))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExternalDomainSignatureV2 {
    domain_tag: u16,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPhaseHighWaterV2 {
    tag: u16,
    values: [Digest32V2; 21],
    canonical_bytes: Vec<u8>,
}

impl RecoveryPhaseHighWaterV2 {
    pub fn normal(values: [Digest32V2; 21]) -> Result<Self, DeploymentControlErrorV2> {
        Self::new(1, values)
    }

    pub fn bootstrap_bridge_restore(
        values: [Digest32V2; 21],
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::new(2, values)
    }

    fn new(tag: u16, values: [Digest32V2; 21]) -> Result<Self, DeploymentControlErrorV2> {
        if !matches!(tag, 1 | 2) || values.iter().any(|digest| is_zero(digest.as_bytes())) {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let canonical_bytes = encode_recovery_high_water(tag, &values)?;
        Ok(Self {
            tag,
            values,
            canonical_bytes,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, 2)?;
        let tag = decode_u16(&mut decoder)?;
        expect_array(&mut decoder, RECOVERY_HIGH_WATER_VALUES_V2)?;
        let mut values = [Digest32V2::new([0; 32]); 21];
        for value in &mut values {
            *value = decode_digest(&mut decoder)?;
        }
        if decoder.position() != bytes.len() {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let value = Self::new(tag, values)?;
        if value.canonical_bytes != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        Ok(value)
    }

    pub const fn tag(&self) -> u16 {
        self.tag
    }

    pub const fn values(&self) -> &[Digest32V2; 21] {
        &self.values
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RollbackGrantV2 {
    canonical_bytes: Vec<u8>,
    grant_id: Digest32V2,
    transaction_id: Nonce32V2,
    transaction_intent_digest: Digest32V2,
    installation_id: Digest32V2,
    installation_epoch: u64,
    expected_pre_active_manifest_digest: Digest32V2,
    attempted_manifest_digest: Digest32V2,
    recovery_target_digest: Digest32V2,
    phase_highwater: RecoveryPhaseHighWaterV2,
    expected_install_identity_profile_signed_digest: Digest32V2,
    issued_at_unix_ms: u64,
    not_before_unix_ms: u64,
    arm_expires_at_unix_ms: u64,
    rollback_support_until_unix_ms: u64,
    maximum_cutover_duration_ns: u64,
    maximum_boot_recovery_duration_ns: u64,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
}

impl std::fmt::Debug for RollbackGrantV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RollbackGrantV2")
            .field("grant_id", &self.grant_id)
            .field("installation_epoch", &self.installation_epoch)
            .field(
                "rollback_support_until_unix_ms",
                &self.rollback_support_until_unix_ms,
            )
            .finish_non_exhaustive()
    }
}

impl RollbackGrantV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &DeploymentAuthorizationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).ok().is_none_or(|length| {
                length > DeploymentHardLimitsV2::compiled().max_transaction_bytes()
            })
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let decoded = decode_rollback_grant(bytes)?;
        validate_rollback_grant_shape(&decoded)?;
        if encode_rollback_grant_complete(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        let grant_id = hash_domain(
            ROLLBACK_GRANT_ID_DOMAIN_V2,
            &encode_rollback_grant_id_material(&decoded)?,
        );
        if decoded.grant_id != grant_id {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        verifier.verify(
            decoded.signature,
            ROLLBACK_GRANT_SIGNATURE_TAG_V2,
            ROLLBACK_GRANT_SIGNATURE_DOMAIN_V2,
            grant_id,
        )?;
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
            grant_id,
            transaction_id: decoded.transaction_id,
            transaction_intent_digest: decoded.transaction_intent_digest,
            installation_id: decoded.installation_id,
            installation_epoch: decoded.installation_epoch,
            expected_pre_active_manifest_digest: decoded.expected_pre_active_manifest_digest,
            attempted_manifest_digest: decoded.attempted_manifest_digest,
            recovery_target_digest: decoded.recovery_target_digest,
            phase_highwater: decoded.phase_highwater,
            expected_install_identity_profile_signed_digest: decoded
                .expected_install_identity_profile_signed_digest,
            issued_at_unix_ms: decoded.issued_at_unix_ms,
            not_before_unix_ms: decoded.not_before_unix_ms,
            arm_expires_at_unix_ms: decoded.arm_expires_at_unix_ms,
            rollback_support_until_unix_ms: decoded.rollback_support_until_unix_ms,
            maximum_cutover_duration_ns: decoded.maximum_cutover_duration_ns,
            maximum_boot_recovery_duration_ns: decoded.maximum_boot_recovery_duration_ns,
            signer_key_id: decoded.signature.signer_key_id,
            signer_key_epoch: decoded.signature.signer_key_epoch,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_signed_for_test(
        intent: &DeploymentTransactionIntentV2,
        phase_highwater: RecoveryPhaseHighWaterV2,
        rollback_support_until_unix_ms: u64,
        signing_key: &SigningKey,
        signer_key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let material = intent.material();
        let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        let mut decoded = DecodedRollbackGrantV2 {
            schema_version: ROLLBACK_GRANT_SCHEMA_VERSION_V2,
            object_domain_tag: ROLLBACK_GRANT_OBJECT_DOMAIN_TAG_V2,
            grant_id: Digest32V2::new([1; 32]),
            transaction_id: material.transaction_id,
            transaction_intent_digest: intent.intent_digest(),
            installation_id: material.installation_id,
            installation_epoch: material.expected_pre_state.installation_epoch(),
            expected_pre_active_manifest_digest: material
                .expected_pre_state
                .active_manifest_digest(),
            attempted_manifest_digest: material.desired_manifest_digest,
            recovery_target_digest: material.recovery_target.digest(),
            phase_highwater,
            expected_install_identity_profile_signed_digest: material
                .expected_pre_state
                .install_identity_profile_signed_digest(),
            issued_at_unix_ms: material.created_at_unix_ms,
            not_before_unix_ms: material.not_before_unix_ms,
            arm_expires_at_unix_ms: material.expires_at_unix_ms,
            rollback_support_until_unix_ms,
            maximum_cutover_duration_ns: material.maximum_cutover_duration_ns,
            maximum_boot_recovery_duration_ns: material.maximum_boot_recovery_duration_ns,
            signature: ExternalDomainSignatureV2 {
                domain_tag: ROLLBACK_GRANT_SIGNATURE_TAG_V2,
                signer_key_id: key_id,
                signer_key_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.grant_id = hash_domain(
            ROLLBACK_GRANT_ID_DOMAIN_V2,
            &encode_rollback_grant_id_material(&decoded)?,
        );
        decoded.signature.signature = Ed25519SignatureV2::new(
            signing_key
                .sign(&signature_input(
                    ROLLBACK_GRANT_SIGNATURE_TAG_V2,
                    ROLLBACK_GRANT_SIGNATURE_DOMAIN_V2,
                    decoded.grant_id,
                ))
                .to_bytes(),
        );
        let verifier = DeploymentAuthorizationVerifierV2::new(
            key_id,
            signer_key_epoch,
            signing_key.verifying_key().to_bytes(),
        )?;
        Self::from_canonical_bytes(&encode_rollback_grant_complete(&decoded)?, &verifier)
    }

    pub fn validate_against_intent(
        &self,
        intent: &DeploymentTransactionIntentV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let material = intent.material();
        let support_delta_ms = ceil_ns_to_ms(material.maximum_cutover_duration_ns)?
            .checked_add(ceil_ns_to_ms(material.maximum_boot_recovery_duration_ns)?)
            .and_then(|value| {
                value.checked_add(ceil_ns_to_ms(material.maximum_clock_skew_ns).ok()?)
            })
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        let minimum_support = material
            .expires_at_unix_ms
            .checked_add(support_delta_ms)
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        if self.transaction_id != material.transaction_id
            || self.transaction_intent_digest != intent.intent_digest()
            || self.installation_id != material.installation_id
            || self.installation_epoch != material.expected_pre_state.installation_epoch()
            || self.expected_pre_active_manifest_digest
                != material.expected_pre_state.active_manifest_digest()
            || self.attempted_manifest_digest != material.desired_manifest_digest
            || self.recovery_target_digest != material.recovery_target.digest()
            || self.phase_highwater.tag() != material.recovery_target.tag()
            || self.expected_install_identity_profile_signed_digest
                != material
                    .expected_pre_state
                    .install_identity_profile_signed_digest()
            || self.issued_at_unix_ms != material.created_at_unix_ms
            || self.not_before_unix_ms != material.not_before_unix_ms
            || self.arm_expires_at_unix_ms != material.expires_at_unix_ms
            || self.rollback_support_until_unix_ms < minimum_support
            || self.maximum_cutover_duration_ns != material.maximum_cutover_duration_ns
            || self.maximum_boot_recovery_duration_ns != material.maximum_boot_recovery_duration_ns
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn grant_id(&self) -> Digest32V2 {
        self.grant_id
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn transaction_intent_digest(&self) -> Digest32V2 {
        self.transaction_intent_digest
    }

    pub const fn signer_key_id(&self) -> Ed25519KeyIdV2 {
        self.signer_key_id
    }

    pub const fn signer_key_epoch(&self) -> u64 {
        self.signer_key_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedRollbackGrantV2 {
    schema_version: u16,
    object_domain_tag: u16,
    grant_id: Digest32V2,
    transaction_id: Nonce32V2,
    transaction_intent_digest: Digest32V2,
    installation_id: Digest32V2,
    installation_epoch: u64,
    expected_pre_active_manifest_digest: Digest32V2,
    attempted_manifest_digest: Digest32V2,
    recovery_target_digest: Digest32V2,
    phase_highwater: RecoveryPhaseHighWaterV2,
    expected_install_identity_profile_signed_digest: Digest32V2,
    issued_at_unix_ms: u64,
    not_before_unix_ms: u64,
    arm_expires_at_unix_ms: u64,
    rollback_support_until_unix_ms: u64,
    maximum_cutover_duration_ns: u64,
    maximum_boot_recovery_duration_ns: u64,
    signature: ExternalDomainSignatureV2,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DeploymentTransactionV2 {
    canonical_bytes: Vec<u8>,
    intent: DeploymentTransactionIntentV2,
    rollback_grant: RollbackGrantV2,
    transaction_payload_digest: Digest32V2,
    authorization_key_id: Ed25519KeyIdV2,
    authorization_key_epoch: u64,
}

/// Bounded, non-authoritative key selection metadata parsed before signature
/// verification. Callers may use it only to select exact members from an
/// already authenticated deployment trust-root set, then must run the full
/// transaction decoder with those verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentAuthorizationKeyRefsV2 {
    rollback_key_id: Ed25519KeyIdV2,
    rollback_key_epoch: u64,
    transaction_key_id: Ed25519KeyIdV2,
    transaction_key_epoch: u64,
    authorization_time_unix_ms: u64,
}

impl DeploymentAuthorizationKeyRefsV2 {
    pub fn peek(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).ok().is_none_or(|length| {
                length > DeploymentHardLimitsV2::compiled().max_transaction_bytes()
            })
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, TRANSACTION_COMPLETE_FIELDS_V2)?;
        let intent = decode_nested(
            &mut decoder,
            DeploymentTransactionIntentV2::from_canonical_bytes,
        )?;
        let intent_digest = decode_digest(&mut decoder)?;
        let grant = decode_nested(&mut decoder, |canonical| {
            let decoded = decode_rollback_grant(canonical)?;
            validate_rollback_grant_shape(&decoded)?;
            if encode_rollback_grant_complete(&decoded)? != canonical {
                return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
            }
            Ok(decoded)
        })?;
        let _transaction_payload_digest = decode_digest(&mut decoder)?;
        let transaction_signature = decode_signature(&mut decoder)?;
        if decoder.position() != bytes.len()
            || intent_digest != intent.intent_digest()
            || grant.transaction_intent_digest != intent_digest
            || grant.transaction_id != intent.transaction_id()
            || grant.installation_id != intent.installation_id()
            || grant.installation_epoch != intent.material().expected_pre_state.installation_epoch()
            || grant.signature.domain_tag != ROLLBACK_GRANT_SIGNATURE_TAG_V2
            || transaction_signature.domain_tag != TRANSACTION_AUTHORIZATION_SIGNATURE_TAG_V2
            || grant.signature.signer_key_epoch == 0
            || transaction_signature.signer_key_epoch == 0
            || is_zero(grant.signature.signer_key_id.as_bytes())
            || is_zero(transaction_signature.signer_key_id.as_bytes())
            || is_zero(grant.signature.signature.as_bytes())
            || is_zero(transaction_signature.signature.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        Ok(Self {
            rollback_key_id: grant.signature.signer_key_id,
            rollback_key_epoch: grant.signature.signer_key_epoch,
            transaction_key_id: transaction_signature.signer_key_id,
            transaction_key_epoch: transaction_signature.signer_key_epoch,
            authorization_time_unix_ms: intent.material().created_at_unix_ms,
        })
    }

    pub const fn rollback_key_id(self) -> Ed25519KeyIdV2 {
        self.rollback_key_id
    }

    pub const fn rollback_key_epoch(self) -> u64 {
        self.rollback_key_epoch
    }

    pub const fn transaction_key_id(self) -> Ed25519KeyIdV2 {
        self.transaction_key_id
    }

    pub const fn transaction_key_epoch(self) -> u64 {
        self.transaction_key_epoch
    }

    pub const fn authorization_time_unix_ms(self) -> u64 {
        self.authorization_time_unix_ms
    }
}

impl std::fmt::Debug for DeploymentTransactionV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentTransactionV2")
            .field("transaction_id", &self.intent.transaction_id())
            .field("intent_digest", &self.intent.intent_digest())
            .field(
                "transaction_payload_digest",
                &self.transaction_payload_digest,
            )
            .finish_non_exhaustive()
    }
}

impl DeploymentTransactionV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        rollback_grant_verifier: &DeploymentAuthorizationVerifierV2,
        transaction_authorization_verifier: &DeploymentAuthorizationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).ok().is_none_or(|length| {
                length > DeploymentHardLimitsV2::compiled().max_transaction_bytes()
            })
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, TRANSACTION_COMPLETE_FIELDS_V2)?;
        let intent = decode_nested(
            &mut decoder,
            DeploymentTransactionIntentV2::from_canonical_bytes,
        )?;
        let intent_digest = decode_digest(&mut decoder)?;
        let rollback_grant = decode_nested(&mut decoder, |bytes| {
            RollbackGrantV2::from_canonical_bytes(bytes, rollback_grant_verifier)
        })?;
        let transaction_payload_digest = decode_digest(&mut decoder)?;
        let authorization_signature = decode_signature(&mut decoder)?;
        if decoder.position() != bytes.len()
            || intent_digest != intent.intent_digest()
            || rollback_grant.transaction_intent_digest() != intent_digest
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        rollback_grant.validate_against_intent(&intent)?;
        let computed_payload_digest = hash_domain(
            TRANSACTION_PAYLOAD_DOMAIN_V2,
            &encode_transaction_payload(&intent, intent_digest, &rollback_grant)?,
        );
        if computed_payload_digest != transaction_payload_digest {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        transaction_authorization_verifier.verify(
            authorization_signature,
            TRANSACTION_AUTHORIZATION_SIGNATURE_TAG_V2,
            TRANSACTION_AUTHORIZATION_DOMAIN_V2,
            transaction_payload_digest,
        )?;
        let canonical_bytes = encode_transaction_complete(
            &intent,
            intent_digest,
            &rollback_grant,
            transaction_payload_digest,
            authorization_signature,
        )?;
        if canonical_bytes != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        Ok(Self {
            canonical_bytes,
            intent,
            rollback_grant,
            transaction_payload_digest,
            authorization_key_id: authorization_signature.signer_key_id,
            authorization_key_epoch: authorization_signature.signer_key_epoch,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_signed_for_test(
        intent: DeploymentTransactionIntentV2,
        rollback_grant: RollbackGrantV2,
        authorization_signing_key: &SigningKey,
        authorization_key_epoch: u64,
        rollback_grant_verifier: &DeploymentAuthorizationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        rollback_grant.validate_against_intent(&intent)?;
        let payload_digest = hash_domain(
            TRANSACTION_PAYLOAD_DOMAIN_V2,
            &encode_transaction_payload(&intent, intent.intent_digest(), &rollback_grant)?,
        );
        let key_id = derive_ed25519_key_id_v2(authorization_signing_key.verifying_key().to_bytes());
        let signature = ExternalDomainSignatureV2 {
            domain_tag: TRANSACTION_AUTHORIZATION_SIGNATURE_TAG_V2,
            signer_key_id: key_id,
            signer_key_epoch: authorization_key_epoch,
            signature: Ed25519SignatureV2::new(
                authorization_signing_key
                    .sign(&signature_input(
                        TRANSACTION_AUTHORIZATION_SIGNATURE_TAG_V2,
                        TRANSACTION_AUTHORIZATION_DOMAIN_V2,
                        payload_digest,
                    ))
                    .to_bytes(),
            ),
        };
        let bytes = encode_transaction_complete(
            &intent,
            intent.intent_digest(),
            &rollback_grant,
            payload_digest,
            signature,
        )?;
        let verifier = DeploymentAuthorizationVerifierV2::new(
            key_id,
            authorization_key_epoch,
            authorization_signing_key.verifying_key().to_bytes(),
        )?;
        Self::from_canonical_bytes(&bytes, rollback_grant_verifier, &verifier)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn intent(&self) -> &DeploymentTransactionIntentV2 {
        &self.intent
    }

    pub const fn rollback_grant(&self) -> &RollbackGrantV2 {
        &self.rollback_grant
    }

    pub const fn transaction_payload_digest(&self) -> Digest32V2 {
        self.transaction_payload_digest
    }

    pub const fn authorization_key_id(&self) -> Ed25519KeyIdV2 {
        self.authorization_key_id
    }

    pub const fn authorization_key_epoch(&self) -> u64 {
        self.authorization_key_epoch
    }

    /// Binds an already signature-authenticated transaction to the exact
    /// authenticated ledger snapshot and trust-root revisions from which it
    /// was authorized. This check must complete before any staging or runtime
    /// side effect is allowed.
    pub fn validate_authenticated_pre_state(
        &self,
        selected: &DeploymentLedgerRecordV2,
        deployment_trust_root_set_digest: Digest32V2,
        activation_trust_root_set_digest: Digest32V2,
        release_trust_root_set_digest: Digest32V2,
        declassification_trust_root_set_digest: Digest32V2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let expected = self.intent.expected_pre_state();
        let projection = selected.projection();
        if projection.installation_id() != self.intent.installation_id()
            || projection.installation_epoch() != expected.installation_epoch()
            || projection.generation() != expected.ledger_generation()
            || projection.record_payload_digest() != expected.ledger_record_payload_digest()
            || projection.phase() != expected.phase()
            || selected.active_activation() != expected.active_activation()
            || projection.effects_fenced() != expected.effects_fenced()
            || projection.effect_fence_epoch() != expected.effect_fence_epoch()
            || selected.active_manifest_digest() != expected.active_manifest_digest()
            || selected.highest_ever().digest()? != expected.highest_ever_digest()
            || selected.install_identity_profile_signed_digest()
                != expected.install_identity_profile_signed_digest()
            || deployment_trust_root_set_digest != expected.deployment_trust_root_set_digest()
            || activation_trust_root_set_digest != expected.activation_trust_root_set_digest()
            || release_trust_root_set_digest != expected.release_trust_root_set_digest()
            || declassification_trust_root_set_digest
                != expected.declassification_trust_root_set_digest()
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        Ok(())
    }
}

fn validate_rollback_grant_shape(
    value: &DecodedRollbackGrantV2,
) -> Result<(), DeploymentControlErrorV2> {
    let limits = DeploymentHardLimitsV2::compiled();
    if value.schema_version != ROLLBACK_GRANT_SCHEMA_VERSION_V2
        || value.object_domain_tag != ROLLBACK_GRANT_OBJECT_DOMAIN_TAG_V2
        || value.installation_epoch == 0
        || value.issued_at_unix_ms == 0
        || value.not_before_unix_ms < value.issued_at_unix_ms
        || value.arm_expires_at_unix_ms <= value.not_before_unix_ms
        || value.rollback_support_until_unix_ms <= value.arm_expires_at_unix_ms
        || value.maximum_cutover_duration_ns == 0
        || value.maximum_cutover_duration_ns > limits.max_cutover_duration_ns()
        || value.maximum_boot_recovery_duration_ns == 0
        || value.maximum_boot_recovery_duration_ns > limits.max_boot_recovery_duration_ns()
        || [
            value.grant_id.as_bytes(),
            value.transaction_id.as_bytes(),
            value.transaction_intent_digest.as_bytes(),
            value.installation_id.as_bytes(),
            value.expected_pre_active_manifest_digest.as_bytes(),
            value.attempted_manifest_digest.as_bytes(),
            value.recovery_target_digest.as_bytes(),
            value
                .expected_install_identity_profile_signed_digest
                .as_bytes(),
        ]
        .iter()
        .any(|digest| is_zero(*digest))
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    Ok(())
}

fn encode_recovery_high_water(
    tag: u16,
    values: &[Digest32V2; 21],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(tag))
        .and_then(|encoder| encoder.array(RECOVERY_HIGH_WATER_VALUES_V2))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    for value in values {
        encoder
            .bytes(value.as_bytes())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    }
    Ok(encoder.into_writer())
}

fn encode_rollback_grant_id_material(
    value: &DecodedRollbackGrantV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(ROLLBACK_GRANT_ID_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.schema_version))
        .and_then(|encoder| encoder.u16(value.object_domain_tag))
        .and_then(|encoder| encoder.bytes(value.transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.transaction_intent_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.installation_epoch))
        .and_then(|encoder| encoder.bytes(value.expected_pre_active_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.attempted_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.recovery_target_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.phase_highwater.canonical_bytes());
    encoder
        .bytes(
            value
                .expected_install_identity_profile_signed_digest
                .as_bytes(),
        )
        .and_then(|encoder| encoder.u64(value.issued_at_unix_ms))
        .and_then(|encoder| encoder.u64(value.not_before_unix_ms))
        .and_then(|encoder| encoder.u64(value.arm_expires_at_unix_ms))
        .and_then(|encoder| encoder.u64(value.rollback_support_until_unix_ms))
        .and_then(|encoder| encoder.u64(value.maximum_cutover_duration_ns))
        .and_then(|encoder| encoder.u64(value.maximum_boot_recovery_duration_ns))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(encoder.into_writer())
}

fn encode_rollback_grant_complete(
    value: &DecodedRollbackGrantV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(ROLLBACK_GRANT_COMPLETE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.schema_version))
        .and_then(|encoder| encoder.u16(value.object_domain_tag))
        .and_then(|encoder| encoder.bytes(value.grant_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.transaction_intent_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.installation_epoch))
        .and_then(|encoder| encoder.bytes(value.expected_pre_active_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.attempted_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.recovery_target_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.phase_highwater.canonical_bytes());
    encoder
        .bytes(
            value
                .expected_install_identity_profile_signed_digest
                .as_bytes(),
        )
        .and_then(|encoder| encoder.u64(value.issued_at_unix_ms))
        .and_then(|encoder| encoder.u64(value.not_before_unix_ms))
        .and_then(|encoder| encoder.u64(value.arm_expires_at_unix_ms))
        .and_then(|encoder| encoder.u64(value.rollback_support_until_unix_ms))
        .and_then(|encoder| encoder.u64(value.maximum_cutover_duration_ns))
        .and_then(|encoder| encoder.u64(value.maximum_boot_recovery_duration_ns))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encode_signature(&mut encoder, value.signature)?;
    Ok(encoder.into_writer())
}

fn decode_rollback_grant(bytes: &[u8]) -> Result<DecodedRollbackGrantV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, ROLLBACK_GRANT_COMPLETE_FIELDS_V2)?;
    let value = DecodedRollbackGrantV2 {
        schema_version: decode_u16(&mut decoder)?,
        object_domain_tag: decode_u16(&mut decoder)?,
        grant_id: decode_digest(&mut decoder)?,
        transaction_id: decode_nonce(&mut decoder)?,
        transaction_intent_digest: decode_digest(&mut decoder)?,
        installation_id: decode_digest(&mut decoder)?,
        installation_epoch: decode_u64(&mut decoder)?,
        expected_pre_active_manifest_digest: decode_digest(&mut decoder)?,
        attempted_manifest_digest: decode_digest(&mut decoder)?,
        recovery_target_digest: decode_digest(&mut decoder)?,
        phase_highwater: decode_nested(
            &mut decoder,
            RecoveryPhaseHighWaterV2::from_canonical_bytes,
        )?,
        expected_install_identity_profile_signed_digest: decode_digest(&mut decoder)?,
        issued_at_unix_ms: decode_u64(&mut decoder)?,
        not_before_unix_ms: decode_u64(&mut decoder)?,
        arm_expires_at_unix_ms: decode_u64(&mut decoder)?,
        rollback_support_until_unix_ms: decode_u64(&mut decoder)?,
        maximum_cutover_duration_ns: decode_u64(&mut decoder)?,
        maximum_boot_recovery_duration_ns: decode_u64(&mut decoder)?,
        signature: decode_signature(&mut decoder)?,
    };
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    Ok(value)
}

fn encode_transaction_payload(
    intent: &DeploymentTransactionIntentV2,
    intent_digest: Digest32V2,
    grant: &RollbackGrantV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(TRANSACTION_PAYLOAD_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(intent.canonical_bytes());
    encoder
        .bytes(intent_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(grant.canonical_bytes());
    Ok(encoder.into_writer())
}

fn encode_transaction_complete(
    intent: &DeploymentTransactionIntentV2,
    intent_digest: Digest32V2,
    grant: &RollbackGrantV2,
    payload_digest: Digest32V2,
    signature: ExternalDomainSignatureV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(TRANSACTION_COMPLETE_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(intent.canonical_bytes());
    encoder
        .bytes(intent_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(grant.canonical_bytes());
    encoder
        .bytes(payload_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encode_signature(&mut encoder, signature)?;
    Ok(encoder.into_writer())
}

fn encode_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: ExternalDomainSignatureV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(SIGNATURE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.domain_tag))
        .and_then(|encoder| encoder.bytes(value.signer_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.signer_key_epoch))
        .and_then(|encoder| encoder.bytes(value.signature.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(())
}

fn decode_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ExternalDomainSignatureV2, DeploymentControlErrorV2> {
    expect_array(decoder, SIGNATURE_FIELDS_V2)?;
    Ok(ExternalDomainSignatureV2 {
        domain_tag: decode_u16(decoder)?,
        signer_key_id: Ed25519KeyIdV2::new(decode_fixed::<32>(decoder)?),
        signer_key_epoch: decode_u64(decoder)?,
        signature: Ed25519SignatureV2::new(decode_fixed::<64>(decoder)?),
    })
}

fn signature_input(tag: u16, domain: &[u8], payload_digest: Digest32V2) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN_SIGNATURE_INPUT_V2);
    hash.update(tag.to_be_bytes());
    hash.update(domain);
    hash.update(payload_digest.as_bytes());
    hash.finalize().into()
}

fn ceil_ns_to_ms(value: u64) -> Result<u64, DeploymentControlErrorV2> {
    value
        .checked_add(999_999)
        .map(|value| value / 1_000_000)
        .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn decode_nested<T>(
    decoder: &mut minicbor::Decoder<'_>,
    decode: impl FnOnce(&[u8]) -> Result<T, DeploymentControlErrorV2>,
) -> Result<T, DeploymentControlErrorV2> {
    let start = decoder.position();
    decoder
        .skip()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    decode(
        decoder
            .input()
            .get(start..decoder.position())
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)?,
    )
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    Ok(())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(decode_fixed::<32>(decoder)?))
}

fn decode_nonce(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Nonce32V2, DeploymentControlErrorV2> {
    Ok(Nonce32V2::new(decode_fixed::<32>(decoder)?))
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
