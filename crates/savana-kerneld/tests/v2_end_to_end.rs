mod v2_release_support;

use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::Encode as _;
use savana_execd::ExecdJournalStateV2;
use savana_ingressd::{
    AuthenticatedKernelIngressReceiverV2, ContentKindV2, IngressBrowserContextV2, IngressServiceV2,
    VerifiedIngressUiAuthorizationV2,
};
use savana_input_runtime::{
    InputRuntimeV2, SignedInputRuntimeAssetsV2, VerifiedInputRuntimeAssetsV2,
};
use savana_kernel_protocol::v2::{
    ActionTemplateIdV2, BootIdV2, Digest32V2, DurableRunIdV2, DurableTaskIdV2, Ed25519KeyIdV2,
    Nonce32V2, PlannerRouteIdV2, PrincipalIdV2, ProducerIdentityV2, ServiceIdentityV2,
    UnixMillisV2,
};
use savana_vault::{
    DurableVaultNamespaceV2, DurableVaultServiceV2, VaultErrorV2, VaultRollbackAnchorV2,
    VaultServiceV2, VaultStateHeadV2,
};
use sha2::{Digest as _, Sha256};

use v2_release_support::{deadline, now, ExecdCrashFixture};

#[derive(Clone)]
struct VaultAnchor(Arc<Mutex<VaultStateHeadV2>>);

impl VaultAnchor {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(
            VaultStateHeadV2::new(0, Digest32V2::new([0; 32])).unwrap(),
        )))
    }
}

impl VaultRollbackAnchorV2 for VaultAnchor {
    fn current_head(&self) -> Result<VaultStateHeadV2, VaultErrorV2> {
        self.0
            .lock()
            .map(|head| *head)
            .map_err(|_| VaultErrorV2::DurableState)
    }

    fn compare_and_advance(
        &mut self,
        expected: VaultStateHeadV2,
        next: VaultStateHeadV2,
    ) -> Result<(), VaultErrorV2> {
        let mut head = self.0.lock().map_err(|_| VaultErrorV2::DurableState)?;
        if *head != expected {
            return Err(VaultErrorV2::RollbackDetected);
        }
        *head = next;
        Ok(())
    }
}

#[test]
fn authenticated_ingress_reaches_rust_gates_vault_and_exact_once_exec_completion() {
    let execd = ExecdCrashFixture::new();
    let installation = execd.installation();
    let manifest = execd.manifest();
    let ingress_boot = BootIdV2::new([0x21; 32]);
    let kernel_boot = BootIdV2::new([0x22; 32]);
    let ingress_identity = ServiceIdentityV2::new([0x23; 32]);
    let kernel_identity = ServiceIdentityV2::new([0x24; 32]);
    let browser = IngressBrowserContextV2::from_authenticated_origin(
        ingress_boot,
        Digest32V2::new([0x25; 32]),
        UnixMillisV2::new(500),
    )
    .unwrap();
    let mut ingress = IngressServiceV2::from_verified_deployment(
        installation,
        manifest,
        ingress_boot,
        ingress_identity,
        kernel_boot,
        kernel_identity,
        8,
        4096,
    )
    .unwrap();
    let tab = ingress
        .open_authenticated_tab(
            VerifiedIngressUiAuthorizationV2::from_verified_ui_settlement(
                PrincipalIdV2::new([0x26; 32]),
                Digest32V2::new([0x27; 32]),
                Digest32V2::new([0x28; 32]),
                UnixMillisV2::new(500),
            )
            .unwrap(),
            browser,
            UnixMillisV2::new(30),
        )
        .unwrap();
    let content = b"send to alice@example.com".to_vec();
    let content_digest = Digest32V2::new(Sha256::digest(&content).into());
    ingress
        .begin(
            &tab,
            browser,
            Nonce32V2::new([0x29; 32]),
            ContentKindV2::ChatText,
            content.len() as u64,
            Some(content_digest),
            UnixMillisV2::new(31),
        )
        .unwrap();
    ingress
        .append(
            &tab,
            browser,
            Nonce32V2::new([0x2a; 32]),
            0,
            content,
            UnixMillisV2::new(32),
        )
        .unwrap();
    let finalized = ingress
        .finalize(
            &tab,
            browser,
            Nonce32V2::new([0x2b; 32]),
            content_digest,
            UnixMillisV2::new(33),
        )
        .unwrap();
    let transfer = ingress
        .consume_for_kernel(
            finalized,
            AuthenticatedKernelIngressReceiverV2::from_mutual_authentication(
                kernel_boot,
                kernel_identity,
                UnixMillisV2::new(500),
            )
            .unwrap(),
            UnixMillisV2::new(34),
        )
        .unwrap();

    let vault_root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(vault_root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let vault_path = vault_root.path().join("vault-state-v2.cbor");
    let mut vault = DurableVaultServiceV2::open(
        &vault_path,
        [0x2c; 32],
        DurableVaultNamespaceV2::from_verified_installation(
            installation,
            Digest32V2::new([0x2d; 32]),
        )
        .unwrap(),
        Box::new(VaultAnchor::new()),
        VaultServiceV2::from_verified_deployment(installation, manifest, kernel_boot, 8).unwrap(),
    )
    .unwrap();
    let evidence = savana_kerneld::test_support::execute_v2_ingress_pipeline_for_release_evidence(
        &input_runtime(),
        &mut vault,
        transfer,
        installation,
        manifest,
        ProducerIdentityV2::new([0x2e; 32]),
        DurableTaskIdV2::new([0x2f; 32]),
        DurableRunIdV2::new([0x30; 32]),
        UnixMillisV2::new(35),
        UnixMillisV2::new(500),
    )
    .unwrap();
    assert_eq!(evidence.protected_value_count, 1);
    assert_eq!(evidence.provenance_root_evidence_count, 3);
    assert_eq!(evidence.vault_segment_count, 1);
    let encrypted_vault = std::fs::read(vault_path).unwrap();
    assert!(!encrypted_vault
        .windows(b"alice@example.com".len())
        .any(|window| window == b"alice@example.com"));

    let nonce = Nonce32V2::new([0x31; 32]);
    let envelope = execd.signed_tool_envelope(nonce);
    let owner = execd.open_owner(8);
    assert_eq!(
        owner
            .accept_signed_dispatch(envelope.clone(), now(200), deadline())
            .unwrap()
            .state(),
        ExecdJournalStateV2::Prepared
    );
    let predecessor = owner
        .prepare_provider_attempt(nonce, Digest32V2::new([0x32; 32]), now(210), deadline())
        .unwrap();
    owner
        .record_effect_started(predecessor, now(211), deadline())
        .unwrap();
    owner
        .record_provider_response(nonce, b"provider result".to_vec(), deadline())
        .unwrap();
    owner
        .record_tool_completion(
            nonce,
            b"typed result".to_vec(),
            Digest32V2::new([0x33; 32]),
            now(220),
            deadline(),
        )
        .unwrap();
    assert_eq!(
        owner
            .accept_signed_dispatch(envelope, now(221), deadline())
            .unwrap()
            .state(),
        ExecdJournalStateV2::CompletionAvailable
    );
}

fn input_runtime() -> InputRuntimeV2 {
    const ASSET_DIGEST_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_V2\0";
    const ASSET_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_SIGNATURE_V2\0";

    let mut payload = minicbor::Encoder::new(Vec::new());
    payload
        .array(7)
        .unwrap()
        .u16(2)
        .unwrap()
        .u64(10)
        .unwrap()
        .u64(10_000)
        .unwrap();
    PlannerRouteIdV2::new(7)
        .encode(&mut payload, &mut ())
        .unwrap();
    payload
        .array(6)
        .unwrap()
        .u32(4096)
        .unwrap()
        .u16(32)
        .unwrap()
        .u16(8)
        .unwrap()
        .u16(8)
        .unwrap()
        .u16(8)
        .unwrap()
        .u32(65_536)
        .unwrap()
        .array(0)
        .unwrap()
        .array(1)
        .unwrap()
        .array(6)
        .unwrap()
        .u32(1)
        .unwrap()
        .str("send")
        .unwrap()
        .u16(1)
        .unwrap()
        .u32(11)
        .unwrap()
        .array(1)
        .unwrap();
    ActionTemplateIdV2::new(21)
        .encode(&mut payload, &mut ())
        .unwrap();
    payload.null().unwrap();
    let payload = payload.into_writer();
    let signing_key = SigningKey::from_bytes(&[0x34; 32]);
    let key_id = Ed25519KeyIdV2::new([0x35; 32]);
    let mut digest = Sha256::new();
    digest.update(ASSET_DIGEST_DOMAIN);
    digest.update(&payload);
    let digest: [u8; 32] = digest.finalize().into();
    let mut signature_input = Vec::from(ASSET_SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(&digest);
    let signature = signing_key.sign(&signature_input).to_bytes();
    let mut signed = minicbor::Encoder::new(Vec::new());
    signed.array(3).unwrap().bytes(&payload).unwrap();
    key_id.encode(&mut signed, &mut ()).unwrap();
    signed.bytes(&signature).unwrap();
    let signed = SignedInputRuntimeAssetsV2::from_canonical_bytes(&signed.into_writer()).unwrap();
    InputRuntimeV2::new(
        VerifiedInputRuntimeAssetsV2::verify(
            &signed,
            key_id,
            signing_key.verifying_key().to_bytes(),
            UnixMillisV2::new(20),
        )
        .unwrap(),
    )
}
