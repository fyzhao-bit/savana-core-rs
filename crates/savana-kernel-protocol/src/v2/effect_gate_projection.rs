use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{Digest32V2, Ed25519KeyIdV2};

const PROJECTION_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0";

pub const MAX_EFFECT_LEDGER_PROJECTION_BYTES_V2: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EffectLedgerProjectionErrorV2 {
    #[error("effect ledger projection binding is invalid")]
    InvalidBinding,
    #[error("effect ledger projection is malformed or noncanonical")]
    NonCanonical,
    #[error("effect ledger projection signature is invalid")]
    InvalidSignature,
    #[error("effect ledger projection does not match the active deployment")]
    DeploymentBinding,
    #[error("effect ledger projection is fenced")]
    Fenced,
    #[error("effect ledger projection is not in a terminal deployment phase")]
    NonTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectLedgerProjectionBindingV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    projection_identity: Digest32V2,
    authenticated_head_digest: Digest32V2,
    signing_key_id: Ed25519KeyIdV2,
    signing_public_key: [u8; 32],
}

impl EffectLedgerProjectionBindingV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        projection_identity: Digest32V2,
        authenticated_head_digest: Digest32V2,
        signing_key_id: Ed25519KeyIdV2,
        signing_public_key: [u8; 32],
    ) -> Result<Self, EffectLedgerProjectionErrorV2> {
        if deployment_generation == 0
            || effect_fence_epoch == 0
            || [
                installation_id.as_bytes(),
                active_state_manifest_digest.as_bytes(),
                projection_identity.as_bytes(),
                authenticated_head_digest.as_bytes(),
                signing_key_id.as_bytes(),
                &signing_public_key,
            ]
            .iter()
            .any(|bytes| is_zero(*bytes))
            || Ed25519VerifyingKey::from_bytes(&signing_public_key).is_err()
        {
            return Err(EffectLedgerProjectionErrorV2::InvalidBinding);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            projection_identity,
            authenticated_head_digest,
            signing_key_id,
            signing_public_key,
        })
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

    pub const fn effect_fence_epoch(self) -> u64 {
        self.effect_fence_epoch
    }

    pub const fn projection_identity(self) -> Digest32V2 {
        self.projection_identity
    }

    pub const fn authenticated_head_digest(self) -> Digest32V2 {
        self.authenticated_head_digest
    }

    pub const fn signing_key_id(self) -> Ed25519KeyIdV2 {
        self.signing_key_id
    }

    pub const fn signing_public_key(self) -> [u8; 32] {
        self.signing_public_key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedEffectLedgerProjectionV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    projection_identity: Digest32V2,
    authenticated_head_digest: Digest32V2,
    selected_record_digest: Digest32V2,
    predecessor_digest: Digest32V2,
    effects_fenced: bool,
    terminal_phase: bool,
}

impl VerifiedEffectLedgerProjectionV2 {
    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn effect_fence_epoch(self) -> u64 {
        self.effect_fence_epoch
    }

    pub const fn projection_identity(self) -> Digest32V2 {
        self.projection_identity
    }

    pub const fn authenticated_head_digest(self) -> Digest32V2 {
        self.authenticated_head_digest
    }

    pub const fn selected_record_digest(self) -> Digest32V2 {
        self.selected_record_digest
    }

    pub const fn predecessor_digest(self) -> Digest32V2 {
        self.predecessor_digest
    }

    pub const fn effects_fenced(self) -> bool {
        self.effects_fenced
    }

    pub const fn terminal_phase(self) -> bool {
        self.terminal_phase
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProjectionPayloadV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    projection_identity: Digest32V2,
    authenticated_head_digest: Digest32V2,
    effects_fenced: bool,
    terminal_phase: bool,
    selected_record_digest: Digest32V2,
    predecessor_digest: Digest32V2,
}

pub fn verify_effect_ledger_projection_v2(
    canonical_signed_projection: &[u8],
    binding: EffectLedgerProjectionBindingV2,
) -> Result<VerifiedEffectLedgerProjectionV2, EffectLedgerProjectionErrorV2> {
    if canonical_signed_projection.is_empty()
        || canonical_signed_projection.len() > MAX_EFFECT_LEDGER_PROJECTION_BYTES_V2
    {
        return Err(EffectLedgerProjectionErrorV2::NonCanonical);
    }
    let mut decoder = minicbor::Decoder::new(canonical_signed_projection);
    require_array(&mut decoder, 3)?;
    let payload_bytes = decoder
        .bytes()
        .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?;
    let signing_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let signature = decode_fixed::<64>(&mut decoder)?;
    if decoder.position() != canonical_signed_projection.len()
        || signing_key_id != binding.signing_key_id
        || encode_signed_projection(payload_bytes, signing_key_id, &signature)?
            != canonical_signed_projection
    {
        return Err(EffectLedgerProjectionErrorV2::NonCanonical);
    }

    let verifying_key = Ed25519VerifyingKey::from_bytes(&binding.signing_public_key)
        .map_err(|_| EffectLedgerProjectionErrorV2::InvalidBinding)?;
    let payload_digest: [u8; 32] = Sha256::digest(payload_bytes).into();
    let mut signature_input =
        Vec::with_capacity(PROJECTION_SIGNATURE_DOMAIN.len() + payload_digest.len());
    signature_input.extend_from_slice(PROJECTION_SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(&payload_digest);
    verifying_key
        .verify_strict(&signature_input, &Ed25519Signature::from_bytes(&signature))
        .map_err(|_| EffectLedgerProjectionErrorV2::InvalidSignature)?;

    let payload = decode_payload(payload_bytes)?;
    if encode_payload(payload)? != payload_bytes {
        return Err(EffectLedgerProjectionErrorV2::NonCanonical);
    }
    if payload.installation_id != binding.installation_id
        || payload.active_state_manifest_digest != binding.active_state_manifest_digest
        || payload.deployment_generation != binding.deployment_generation
        || payload.effect_fence_epoch != binding.effect_fence_epoch
        || payload.projection_identity != binding.projection_identity
        || payload.authenticated_head_digest != binding.authenticated_head_digest
    {
        return Err(EffectLedgerProjectionErrorV2::DeploymentBinding);
    }
    if payload.effects_fenced {
        return Err(EffectLedgerProjectionErrorV2::Fenced);
    }
    if !payload.terminal_phase {
        return Err(EffectLedgerProjectionErrorV2::NonTerminal);
    }
    if is_zero(payload.selected_record_digest.as_bytes()) {
        return Err(EffectLedgerProjectionErrorV2::NonCanonical);
    }
    Ok(VerifiedEffectLedgerProjectionV2 {
        installation_id: payload.installation_id,
        active_state_manifest_digest: payload.active_state_manifest_digest,
        deployment_generation: payload.deployment_generation,
        effect_fence_epoch: payload.effect_fence_epoch,
        projection_identity: payload.projection_identity,
        authenticated_head_digest: payload.authenticated_head_digest,
        selected_record_digest: payload.selected_record_digest,
        predecessor_digest: payload.predecessor_digest,
        effects_fenced: payload.effects_fenced,
        terminal_phase: payload.terminal_phase,
    })
}

fn decode_payload(bytes: &[u8]) -> Result<ProjectionPayloadV2, EffectLedgerProjectionErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 11)?;
    if decoder
        .u16()
        .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?
        != 2
    {
        return Err(EffectLedgerProjectionErrorV2::NonCanonical);
    }
    let payload = ProjectionPayloadV2 {
        installation_id: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        active_state_manifest_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        deployment_generation: decoder
            .u64()
            .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?,
        effect_fence_epoch: decoder
            .u64()
            .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?,
        projection_identity: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        authenticated_head_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        effects_fenced: decoder
            .bool()
            .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?,
        terminal_phase: decoder
            .bool()
            .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?,
        selected_record_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        predecessor_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
    };
    if decoder.position() != bytes.len() {
        return Err(EffectLedgerProjectionErrorV2::NonCanonical);
    }
    Ok(payload)
}

fn encode_payload(payload: ProjectionPayloadV2) -> Result<Vec<u8>, EffectLedgerProjectionErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(11)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(payload.installation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.active_state_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(payload.deployment_generation))
        .and_then(|encoder| encoder.u64(payload.effect_fence_epoch))
        .and_then(|encoder| encoder.bytes(payload.projection_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.authenticated_head_digest.as_bytes()))
        .and_then(|encoder| encoder.bool(payload.effects_fenced))
        .and_then(|encoder| encoder.bool(payload.terminal_phase))
        .and_then(|encoder| encoder.bytes(payload.selected_record_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(payload.predecessor_digest.as_bytes()))
        .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?;
    Ok(encoder.into_writer())
}

fn encode_signed_projection(
    payload: &[u8],
    key_id: Ed25519KeyIdV2,
    signature: &[u8; 64],
) -> Result<Vec<u8>, EffectLedgerProjectionErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(payload))
        .and_then(|encoder| encoder.bytes(key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?;
    Ok(encoder.into_writer())
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), EffectLedgerProjectionErrorV2> {
    if decoder
        .array()
        .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?
        != Some(expected)
    {
        return Err(EffectLedgerProjectionErrorV2::NonCanonical);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], EffectLedgerProjectionErrorV2> {
    decoder
        .bytes()
        .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)?
        .try_into()
        .map_err(|_| EffectLedgerProjectionErrorV2::NonCanonical)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};

    use super::*;

    const DOMAIN: &[u8] = b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0";

    fn binding(key: &SigningKey) -> EffectLedgerProjectionBindingV2 {
        EffectLedgerProjectionBindingV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            4,
            Digest32V2::new([5; 32]),
            Digest32V2::new([6; 32]),
            Ed25519KeyIdV2::new([7; 32]),
            key.verifying_key().to_bytes(),
        )
        .unwrap()
    }

    fn signed_projection(
        key: &SigningKey,
        binding: EffectLedgerProjectionBindingV2,
        effects_fenced: bool,
        terminal: bool,
    ) -> Vec<u8> {
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload
            .array(11)
            .unwrap()
            .u16(2)
            .unwrap()
            .bytes(binding.installation_id().as_bytes())
            .unwrap()
            .bytes(binding.active_state_manifest_digest().as_bytes())
            .unwrap()
            .u64(binding.deployment_generation())
            .unwrap()
            .u64(binding.effect_fence_epoch())
            .unwrap()
            .bytes(binding.projection_identity().as_bytes())
            .unwrap()
            .bytes(binding.authenticated_head_digest().as_bytes())
            .unwrap()
            .bool(effects_fenced)
            .unwrap()
            .bool(terminal)
            .unwrap()
            .bytes(&[8; 32])
            .unwrap()
            .bytes(&[9; 32])
            .unwrap();
        let payload = payload.into_writer();
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut input = Vec::from(DOMAIN);
        input.extend_from_slice(&digest);
        let signature = key.sign(&input).to_bytes();
        let mut outer = minicbor::Encoder::new(Vec::new());
        outer
            .array(3)
            .unwrap()
            .bytes(&payload)
            .unwrap()
            .bytes(binding.signing_key_id().as_bytes())
            .unwrap()
            .bytes(&signature)
            .unwrap();
        outer.into_writer()
    }

    #[test]
    fn verifies_exact_unfenced_terminal_projection() {
        let key = SigningKey::from_bytes(&[0x41; 32]);
        let binding = binding(&key);
        let canonical = signed_projection(&key, binding, false, true);

        let projection = verify_effect_ledger_projection_v2(&canonical, binding).unwrap();

        assert_eq!(
            projection.authenticated_head_digest(),
            binding.authenticated_head_digest()
        );
        assert!(!projection.effects_fenced());
        assert!(projection.terminal_phase());
    }

    #[test]
    fn rejects_stale_fenced_nonterminal_and_noncanonical_projection() {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let binding = binding(&key);

        assert_eq!(
            verify_effect_ledger_projection_v2(
                &signed_projection(&key, binding, true, true),
                binding
            )
            .unwrap_err(),
            EffectLedgerProjectionErrorV2::Fenced
        );
        assert_eq!(
            verify_effect_ledger_projection_v2(
                &signed_projection(&key, binding, false, false),
                binding
            )
            .unwrap_err(),
            EffectLedgerProjectionErrorV2::NonTerminal
        );

        let mut stale = binding;
        stale = EffectLedgerProjectionBindingV2::from_verified_deployment(
            stale.installation_id(),
            stale.active_state_manifest_digest(),
            stale.deployment_generation() + 1,
            stale.effect_fence_epoch(),
            stale.projection_identity(),
            stale.authenticated_head_digest(),
            stale.signing_key_id(),
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify_effect_ledger_projection_v2(
                &signed_projection(&key, binding, false, true),
                stale
            )
            .unwrap_err(),
            EffectLedgerProjectionErrorV2::DeploymentBinding
        );

        let mut trailing = signed_projection(&key, binding, false, true);
        trailing.push(0);
        assert_eq!(
            verify_effect_ledger_projection_v2(&trailing, binding).unwrap_err(),
            EffectLedgerProjectionErrorV2::NonCanonical
        );
    }

    #[test]
    fn rejects_signature_and_head_substitution() {
        let key = SigningKey::from_bytes(&[0x43; 32]);
        let binding = binding(&key);
        let mut corrupted = signed_projection(&key, binding, false, true);
        let final_index = corrupted.len() - 1;
        corrupted[final_index] ^= 1;
        assert_eq!(
            verify_effect_ledger_projection_v2(&corrupted, binding).unwrap_err(),
            EffectLedgerProjectionErrorV2::InvalidSignature
        );

        let wrong_head = EffectLedgerProjectionBindingV2::from_verified_deployment(
            binding.installation_id(),
            binding.active_state_manifest_digest(),
            binding.deployment_generation(),
            binding.effect_fence_epoch(),
            binding.projection_identity(),
            Digest32V2::new([0x55; 32]),
            binding.signing_key_id(),
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify_effect_ledger_projection_v2(
                &signed_projection(&key, binding, false, true),
                wrong_head
            )
            .unwrap_err(),
            EffectLedgerProjectionErrorV2::DeploymentBinding
        );
    }
}
