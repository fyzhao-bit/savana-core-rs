//! Debug-only native integration fixture. Real executor protocol, encrypted
//! journal, effect gate, worker verification and retained-response classification;
//! in-memory worker/provider and rollback anchors, not OS or TLS evidence.
use crate::{
    connector_runtime::VerifiedConnectorExecutionRuntimeV2,
    worker_protocol::ConnectorJobDescriptorIssuerV2,
    worker_supervisor::{
        ConnectorWorkerSupervisorErrorV2 as Error, ConnectorWorkerSupervisorV2,
        ProviderTransportV2, VerifiedProviderRequestV2, VerifiedProviderTargetV2,
    },
    *,
};
use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::*;
use savana_policy_core::v2::{
    BoundedConnectorHostV2, BoundedConnectorUrlV2, ConnectorDescriptorV2, ConnectorTierV2,
    ConnectorTransportV2, DurableStateNamespaceV2, G4Error, RollbackProtectedStateAnchorV2,
    RollbackProtectedStateHeadV2, UnsignedToolDescriptorV2,
};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    fs::OpenOptions,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const PROVIDER_URL: &str = "https://provider.example/savana/final-release";
pub fn target_identity() -> Digest32V2 {
    business_target_identity_v2(PROVIDER_URL, Digest32V2::new([0x28; 32])).unwrap()
}

pub fn deployment_connector(tools: Vec<UnsignedToolDescriptorV2>) -> ConnectorDescriptorV2 {
    deployment_connector_named(tools, "intent-bound-test")
}

pub fn deployment_connector_named(
    tools: Vec<UnsignedToolDescriptorV2>,
    name: &str,
) -> ConnectorDescriptorV2 {
    let mut identity = minicbor::Encoder::new(Vec::new());
    identity
        .array(2)
        .unwrap()
        .str(name)
        .unwrap()
        .array(3)
        .unwrap()
        .u16(2)
        .unwrap()
        .str(PROVIDER_URL)
        .unwrap()
        .bytes(&[0x28; 32])
        .unwrap();
    let id: [u8; 32] = Sha256::new()
        .chain_update(b"savana.connector.deployment.v2\0")
        .chain_update(identity.into_writer())
        .finalize()
        .into();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(8)
        .unwrap()
        .bytes(&id)
        .unwrap()
        .str(name)
        .unwrap()
        .u16(1)
        .unwrap()
        .array(3)
        .unwrap()
        .u16(2)
        .unwrap()
        .str(PROVIDER_URL)
        .unwrap()
        .bytes(&[0x28; 32])
        .unwrap()
        .array(tools.len() as u64)
        .unwrap();
    for tool in tools {
        e.writer_mut()
            .extend_from_slice(&minicbor::to_vec(tool).unwrap());
    }
    e.u16(savana_policy_core::v2::EffectSetV2::SEND.bits())
        .unwrap()
        .u16(savana_policy_core::v2::ConnectorStructuralRoleV2::Sink.tag())
        .unwrap()
        .u64(1)
        .unwrap();
    ConnectorDescriptorV2::from_canonical_bytes(&e.into_writer(), &[]).unwrap()
}

#[derive(Clone, Copy)]
pub enum ProviderReply {
    Success,
    Failure,
    Unknown,
}

#[derive(Clone, Default)]
pub struct Observations(Arc<Mutex<Vec<Vec<u8>>>>);
impl Observations {
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
}
struct Provider {
    observed: Observations,
    reply: ProviderReply,
}
impl ProviderTransportV2 for Provider {
    fn business_credential_identity(&self) -> Result<Digest32V2, Error> {
        Ok(Digest32V2::new([0x29; 32]))
    }
    fn verified_deployment_target(&self) -> Result<VerifiedProviderTargetV2, Error> {
        VerifiedProviderTargetV2::https(
            BoundedConnectorUrlV2::new(PROVIDER_URL).unwrap(),
            Digest32V2::new([0x28; 32]),
        )
    }
    fn verify_connector_target(
        &self,
        tier: ConnectorTierV2,
        transport: &ConnectorTransportV2,
        _allowlist: &[BoundedConnectorHostV2],
    ) -> Result<VerifiedProviderTargetV2, Error> {
        match transport {
            ConnectorTransportV2::Https {
                canonical_url,
                tls_identity_pin,
            } if tier == ConnectorTierV2::DeploymentShipped
                && canonical_url.as_str() == PROVIDER_URL
                && *tls_identity_pin == Digest32V2::new([0x28; 32]) =>
            {
                self.verified_deployment_target()
            }
            _ => Err(Error::ProviderAttemptFailed),
        }
    }
    fn execute(
        &mut self,
        request: &VerifiedProviderRequestV2,
        permit: &EffectPermitV2,
        _maximum: u32,
        deadline: Instant,
    ) -> Result<Vec<u8>, Error> {
        if !request.matches_permit(permit) || Instant::now() >= deadline {
            return Err(Error::ProviderAttemptFailed);
        }
        let bytes = request.canonical_bytes();
        let mut decoder = minicbor::Decoder::new(bytes);
        if decoder.array().ok() != Some(Some(11)) {
            return Err(Error::ProtocolViolation);
        }
        for _ in 0..10 {
            decoder.skip().map_err(|_| Error::ProtocolViolation)?;
        }
        let inner = decoder.bytes().map_err(|_| Error::ProtocolViolation)?;
        let value: serde_json::Value =
            serde_json::from_slice(inner).map_err(|_| Error::ProtocolViolation)?;
        let mcp = value.get("jsonrpc").is_some();
        let request_id = value[if mcp { "id" } else { "request_id" }]
            .as_str()
            .ok_or(Error::ProtocolViolation)?;
        self.observed.0.lock().unwrap().push(bytes.to_vec());
        let status = match self.reply {
            ProviderReply::Success => "succeeded",
            ProviderReply::Failure => "failed",
            ProviderReply::Unknown => "unknown",
        };
        let response = if mcp {
            serde_json::json!({"jsonrpc": "2.0", "id": request_id, "result": {
                "isError": matches!(self.reply, ProviderReply::Failure), "content": [],
                "structuredContent": {"savana_status": status}}})
        } else {
            serde_json::json!({"request_id": request_id, "status": status})
        };
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

#[derive(Clone, Default)]
struct Anchor(Arc<Mutex<ExecdStateHeadV2>>);
impl ExecdRollbackAnchorV2 for Anchor {
    fn current_head(&self) -> Result<ExecdStateHeadV2, ExecdErrorV2> {
        Ok(*self.0.lock().unwrap())
    }
    fn compare_and_advance(
        &mut self,
        expected: ExecdStateHeadV2,
        next: ExecdStateHeadV2,
    ) -> Result<(), ExecdErrorV2> {
        let mut head = self.0.lock().unwrap();
        if *head != expected {
            return Err(ExecdErrorV2::RollbackDetected);
        }
        *head = next;
        Ok(())
    }
}
#[derive(Clone)]
struct RegistryAnchor(Arc<Mutex<RollbackProtectedStateHeadV2>>);
impl RollbackProtectedStateAnchorV2 for RegistryAnchor {
    fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
        Ok(*self.0.lock().unwrap())
    }
    fn compare_and_advance(
        &mut self,
        expected: RollbackProtectedStateHeadV2,
        next: RollbackProtectedStateHeadV2,
    ) -> Result<(), G4Error> {
        let mut head = self.0.lock().unwrap();
        if *head != expected || next.sequence() != expected.sequence() + 1 {
            return Err(G4Error::DurableStateRollback);
        }
        *head = next;
        Ok(())
    }
}

/// Fixed test keys match the native G7 fixture. The caller supplies an isolated
/// test directory; this never reads an installed deployment or user credentials.
pub struct ReopenableExecutor {
    service: Mutex<Option<ExecdProtocolServiceV2>>,
    rebuild: Box<dyn Fn() -> ExecdProtocolServiceV2 + Send + Sync>,
}
impl ReopenableExecutor {
    pub fn execute(
        &self,
        operation: KernelExecutorOperationV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, ExecdProtocolServiceErrorV2> {
        self.service
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .execute(operation, now, deadline)
    }
    pub fn restart(&self) {
        let mut service = self.service.lock().unwrap();
        drop(service.take());
        *service = Some((self.rebuild)());
    }
}

pub fn service(
    root: &Path,
    installation: Digest32V2,
    manifest: Digest32V2,
    generation: u64,
    fence: u64,
    substitute_request: bool,
    reply: ProviderReply,
) -> (ReopenableExecutor, Observations) {
    service_with_connectors(
        root,
        installation,
        manifest,
        generation,
        fence,
        substitute_request,
        reply,
        vec![],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn service_with_connectors(
    root: &Path,
    installation: Digest32V2,
    manifest: Digest32V2,
    generation: u64,
    fence: u64,
    substitute_request: bool,
    reply: ProviderReply,
    connectors: Vec<ConnectorDescriptorV2>,
) -> (ReopenableExecutor, Observations) {
    let root = root.to_path_buf();
    let anchor = Anchor::default();
    let registry_anchor = RegistryAnchor(Arc::new(Mutex::new(
        RollbackProtectedStateHeadV2::new(0, Digest32V2::new([0; 32])).unwrap(),
    )));
    let observed = Observations::default();
    let output = observed.clone();
    let rebuild = move || {
        build(
            &root,
            installation,
            manifest,
            generation,
            fence,
            substitute_request,
            reply,
            anchor.clone(),
            registry_anchor.clone(),
            observed.clone(),
            connectors.clone(),
        )
    };
    let service = rebuild();
    (
        ReopenableExecutor {
            service: Mutex::new(Some(service)),
            rebuild: Box::new(rebuild),
        },
        output,
    )
}

#[allow(clippy::too_many_arguments)]
fn build(
    root: &Path,
    installation: Digest32V2,
    manifest: Digest32V2,
    generation: u64,
    fence: u64,
    substitute_request: bool,
    reply: ProviderReply,
    anchor: Anchor,
    registry_anchor: RegistryAnchor,
    observed: Observations,
    connectors: Vec<ConnectorDescriptorV2>,
) -> ExecdProtocolServiceV2 {
    let kernel = SigningKey::from_bytes(&[0xc0; 32]);
    let receipt = SigningKey::from_bytes(&[0xbd; 32]);
    let deployment = VerifiedExecdDeploymentV2::from_verified_manifest(
        installation,
        manifest,
        generation,
        fence,
        Digest32V2::new([0xa7; 32]),
        derive_ed25519_key_id_v2(kernel.verifying_key().to_bytes()),
        kernel.verifying_key().to_bytes(),
        derive_ed25519_key_id_v2(receipt.verifying_key().to_bytes()),
        receipt.to_bytes(),
    )
    .unwrap();
    let secret = [0xbc; 32];
    let public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
    let genesis = Digest32V2::new([0xbf; 32]);
    let protocol = ExecdProtocolDeploymentV2::from_verified_deployment(
        &deployment,
        crate::protocol_service::hpke_x25519_key_id(public),
        secret,
        1,
        1,
        genesis,
    )
    .unwrap();
    let projection_key = SigningKey::from_bytes(&[0xaa; 32]);
    let projection_binding = EffectLedgerProjectionBindingV2::from_verified_deployment(
        installation,
        manifest,
        generation,
        fence,
        Digest32V2::new([0xab; 32]),
        Digest32V2::new([0xac; 32]),
        derive_ed25519_key_id_v2(projection_key.verifying_key().to_bytes()),
        projection_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let mut payload = minicbor::Encoder::new(Vec::new());
    payload
        .array(11)
        .unwrap()
        .u16(2)
        .unwrap()
        .bytes(installation.as_bytes())
        .unwrap()
        .bytes(manifest.as_bytes())
        .unwrap()
        .u64(generation)
        .unwrap()
        .u64(fence)
        .unwrap()
        .bytes(&[0xab; 32])
        .unwrap()
        .bytes(&[0xac; 32])
        .unwrap()
        .bool(false)
        .unwrap()
        .bool(true)
        .unwrap()
        .bytes(&[0xad; 32])
        .unwrap()
        .bytes(&[0xae; 32])
        .unwrap();
    let payload = payload.into_writer();
    let mut signing = b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0".to_vec();
    signing.extend_from_slice(&Sha256::digest(&payload));
    let mut signed = minicbor::Encoder::new(Vec::new());
    signed
        .array(3)
        .unwrap()
        .bytes(&payload)
        .unwrap()
        .bytes(projection_binding.signing_key_id().as_bytes())
        .unwrap()
        .bytes(&projection_key.sign(&signing).to_bytes())
        .unwrap();
    let gate_path = root.join("effect-gate");
    let projection_path = root.join("projection.cbor");
    if !gate_path.exists() {
        fs::write(&gate_path, []).unwrap();
    }
    if !projection_path.exists() {
        fs::write(&projection_path, signed.into_writer()).unwrap();
    }
    let owner = ExecdStateOwnerV2::open(
        &root.join("execd-journal-v2.cbor"),
        [0xd2; 32],
        DurableExecdNamespaceV2::from_verified_installation(
            installation,
            Digest32V2::new([0xd3; 32]),
        )
        .unwrap(),
        Box::new(anchor),
        deployment,
        OpenOptions::new().read(true).open(gate_path).unwrap(),
        OpenOptions::new().read(true).open(projection_path).unwrap(),
        projection_binding,
        Instant::now() + Duration::from_secs(5),
        16,
    )
    .unwrap();
    let registry = Arc::new(
        ExecdConnectorRegistryV2::open(
            &root.join("connector-registry-v2.cbor"),
            [0xd4; 32],
            DurableStateNamespaceV2::from_verified_installation(
                installation,
                Digest32V2::new([0xd5; 32]),
            )
            .unwrap(),
            Box::new(registry_anchor),
            ExecdConnectorRegistryTrustV2::from_authenticated_deployment(
                installation,
                manifest,
                generation,
                genesis,
                Ed25519KeyIdV2::new([0; 32]),
                [0; 32],
                vec![],
                connectors,
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let issuer = ConnectorJobDescriptorIssuerV2::from_verified_deployment(
        installation,
        manifest,
        generation,
        fence,
        Digest32V2::new([0xe1; 32]),
        Digest32V2::new([0xe2; 32]),
        Digest32V2::new([0xe3; 32]),
        Digest32V2::new([0x29; 32]),
        Zeroizing::new([0xe4; 32]),
    )
    .unwrap();
    let supervisor = ConnectorWorkerSupervisorV2::from_verified_launcher(
        issuer.trust(),
        Some(Box::new(
            crate::worker_process::intent_bound_fixture::Launcher {
                now: UnixMillisV2::new(205),
                substitute_request,
            },
        )),
    )
    .unwrap();
    let processor = VerifiedConnectorExecutionRuntimeV2::from_verified_components(
        supervisor,
        issuer,
        Box::new(Provider {
            observed: observed.clone(),
            reply,
        }),
    );
    ExecdProtocolServiceV2::new_with_connector_registry(
        protocol,
        owner,
        Box::new(processor),
        registry,
    )
    .unwrap()
}
