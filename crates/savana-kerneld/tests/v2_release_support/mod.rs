use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer as _, SigningKey};
use savana_execd::{
    DurableExecdNamespaceV2, ExecdErrorV2, ExecdRollbackAnchorV2, ExecdStateHeadV2,
    ExecdStateOwnerV2, VerifiedExecdDeploymentV2,
};
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, encode_signed_sealed_execution_envelope_v2, ActionIntentIdV2,
    AttemptKindV2, BoundedCiphertextV2, Digest32V2, DispatchCoreV2, DispatchSubjectV2,
    DurableRunIdV2, DurableTaskIdV2, EffectLedgerProjectionBindingV2, ExecutorIdentityV2,
    FixedBytes32V2, HpkeX25519KeyIdV2, InternalStepIdV2, Nonce32V2, PlanRevisionDigestV2,
    SealedExecutionEnvelopePayloadV2, SignedSealedExecutionEnvelopeV2,
    ToolExecutionSemanticBindingV2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};

const EFFECT_PROJECTION_DOMAIN: &[u8] = b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0";

#[derive(Clone, Default)]
pub struct SharedAnchor(Arc<Mutex<ExecdStateHeadV2>>);

impl ExecdRollbackAnchorV2 for SharedAnchor {
    fn current_head(&self) -> Result<ExecdStateHeadV2, ExecdErrorV2> {
        self.0
            .lock()
            .map(|head| *head)
            .map_err(|_| ExecdErrorV2::DurableState)
    }

    fn compare_and_advance(
        &mut self,
        expected: ExecdStateHeadV2,
        next: ExecdStateHeadV2,
    ) -> Result<(), ExecdErrorV2> {
        let mut head = self.0.lock().map_err(|_| ExecdErrorV2::DurableState)?;
        if *head != expected {
            return Err(ExecdErrorV2::RollbackDetected);
        }
        *head = next;
        Ok(())
    }
}

pub struct ExecdCrashFixture {
    root: tempfile::TempDir,
    anchor: SharedAnchor,
    kernel_key: SigningKey,
    projection_key: SigningKey,
    projection_binding: EffectLedgerProjectionBindingV2,
    installation: Digest32V2,
    manifest: Digest32V2,
    executor: ExecutorIdentityV2,
    receipt_seed: [u8; 32],
}

impl ExecdCrashFixture {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.path().join("effect-gate-v2"), []).unwrap();
        let kernel_key = SigningKey::from_bytes(&[0x31; 32]);
        let projection_key = SigningKey::from_bytes(&[0x32; 32]);
        let installation = Digest32V2::new([0x11; 32]);
        let manifest = Digest32V2::new([0x12; 32]);
        let executor = ExecutorIdentityV2::new([0x13; 32]);
        let projection_binding = EffectLedgerProjectionBindingV2::from_verified_deployment(
            installation,
            manifest,
            7,
            9,
            Digest32V2::new([0x14; 32]),
            Digest32V2::new([0x15; 32]),
            derive_ed25519_key_id_v2(projection_key.verifying_key().to_bytes()),
            projection_key.verifying_key().to_bytes(),
        )
        .unwrap();
        let fixture = Self {
            root,
            anchor: SharedAnchor::default(),
            kernel_key,
            projection_key,
            projection_binding,
            installation,
            manifest,
            executor,
            receipt_seed: [0x33; 32],
        };
        fixture.write_projection(false);
        fixture
    }

    pub fn journal_path(&self) -> PathBuf {
        self.root.path().join("execd-journal-v2.cbor")
    }

    #[allow(dead_code)]
    pub const fn installation(&self) -> Digest32V2 {
        self.installation
    }

    #[allow(dead_code)]
    pub const fn manifest(&self) -> Digest32V2 {
        self.manifest
    }

    pub fn open_owner(&self, capacity: usize) -> ExecdStateOwnerV2 {
        let gate = OpenOptions::new()
            .read(true)
            .open(self.root.path().join("effect-gate-v2"))
            .unwrap();
        let projection = OpenOptions::new()
            .read(true)
            .open(self.root.path().join("effect-ledger-projection-v2.cbor"))
            .unwrap();
        ExecdStateOwnerV2::open(
            &self.journal_path(),
            [0x34; 32],
            DurableExecdNamespaceV2::from_verified_installation(
                self.installation,
                Digest32V2::new([0x35; 32]),
            )
            .unwrap(),
            Box::new(self.anchor.clone()),
            self.deployment(),
            gate,
            projection,
            self.projection_binding,
            deadline(),
            capacity,
        )
        .unwrap()
    }

    pub fn signed_tool_envelope(&self, nonce: Nonce32V2) -> Vec<u8> {
        let binding = ToolExecutionSemanticBindingV2::new(
            PlanRevisionDigestV2::new([0x41; 32]),
            InternalStepIdV2::new([0x42; 32]),
            Digest32V2::new([0x43; 32]),
            Digest32V2::new([0x44; 32]),
            Digest32V2::new([0x45; 32]),
            Digest32V2::new([0x46; 32]),
            Digest32V2::new([0x47; 32]),
            Digest32V2::new([0x48; 32]),
            Digest32V2::new([0x49; 32]),
            Digest32V2::new(*self.executor.as_bytes()),
            AttemptKindV2::new(1),
        )
        .unwrap();
        let core = DispatchCoreV2::new(
            self.installation,
            self.manifest,
            7,
            9,
            DurableTaskIdV2::new([0x4a; 32]),
            DurableRunIdV2::new([0x4b; 32]),
            nonce,
            DispatchSubjectV2::tool_execution(ActionIntentIdV2::new([0x4c; 32]), binding, None)
                .unwrap(),
            self.executor,
            HpkeX25519KeyIdV2::new([0x4d; 32]),
            Digest32V2::new([0x4e; 32]),
            UnixMillisV2::new(10_000),
        )
        .unwrap();
        let payload = SealedExecutionEnvelopePayloadV2::new(
            core,
            Digest32V2::new([0x4e; 32]),
            FixedBytes32V2::new([0x4f; 32]),
            BoundedCiphertextV2::new(vec![0x50; 64]).unwrap(),
        )
        .unwrap();
        let envelope = SignedSealedExecutionEnvelopeV2::sign(payload, &self.kernel_key).unwrap();
        encode_signed_sealed_execution_envelope_v2(&envelope).unwrap()
    }

    fn deployment(&self) -> VerifiedExecdDeploymentV2 {
        let receipt_key = SigningKey::from_bytes(&self.receipt_seed);
        VerifiedExecdDeploymentV2::from_verified_manifest(
            self.installation,
            self.manifest,
            7,
            9,
            Digest32V2::new(*self.executor.as_bytes()),
            derive_ed25519_key_id_v2(self.kernel_key.verifying_key().to_bytes()),
            self.kernel_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(receipt_key.verifying_key().to_bytes()),
            self.receipt_seed,
        )
        .unwrap()
    }

    fn write_projection(&self, effects_fenced: bool) {
        let bytes = signed_effect_projection(
            &self.projection_key,
            self.projection_binding,
            effects_fenced,
        );
        fs::write(
            self.root.path().join("effect-ledger-projection-v2.cbor"),
            bytes,
        )
        .unwrap();
    }
}

pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

pub fn now(value: u64) -> UnixMillisV2 {
    UnixMillisV2::new(value)
}

fn signed_effect_projection(
    projection_key: &SigningKey,
    binding: EffectLedgerProjectionBindingV2,
    effects_fenced: bool,
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
        .bool(true)
        .unwrap()
        .bytes(&[0x51; 32])
        .unwrap()
        .bytes(&[0; 32])
        .unwrap();
    let payload = payload.into_writer();
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let mut signature_input = Vec::from(EFFECT_PROJECTION_DOMAIN);
    signature_input.extend_from_slice(&digest);
    let signature = projection_key.sign(&signature_input).to_bytes();
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
