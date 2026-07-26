use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const RESOURCE_PROFILE_DOMAIN: &[u8] = b"SAVANA_RESOURCE_PROFILE_V1\0";
const RELEASE_TARGET_DOMAIN: &[u8] = b"SAVANA_RELEASE_TARGET_V1\0";

pub(crate) struct ReleaseBoundVectorFixture {
    pub(crate) policy: crate::policy_support::TestPolicy,
    pub(crate) roots_bytes: Vec<u8>,
    pub(crate) profile_bytes: Vec<u8>,
    pub(crate) roots_digest: [u8; 32],
    pub(crate) installation_profile_digest: [u8; 32],
    pub(crate) resource_profile_digest: [u8; 32],
    pub(crate) release_target_id: [u8; 32],
}

pub(crate) fn release_bound_vector_fixture() -> ReleaseBoundVectorFixture {
    let daemon_key = SigningKey::from_bytes(&[0x61; 32]);
    let client_key = SigningKey::from_bytes(&[0x62; 32]);
    let policy_key = SigningKey::from_bytes(&[0x42; 32]);
    let roots_bytes = encode_policy_roots(&policy_key.verifying_key().to_bytes());
    let profile_bytes = encode_profile(
        &daemon_key.verifying_key().to_bytes(),
        &client_key.verifying_key().to_bytes(),
        &policy_key.verifying_key().to_bytes(),
    );
    let roots_digest = sha256(&roots_bytes);
    let installation_profile_digest = sha256(&profile_bytes);

    let mut policy = crate::policy_support::valid_policy(7, 3);
    let resources = minicbor::to_vec(policy.resources).expect("fixed resource profile encodes");
    let resource_profile_digest = domain_hash(RESOURCE_PROFILE_DOMAIN, &resources);
    let release_target_id = compute_release_target(
        roots_digest,
        resource_profile_digest,
        installation_profile_digest,
    );
    policy.release.compatible_release_target_ids = vec![release_target_id];

    ReleaseBoundVectorFixture {
        policy,
        roots_bytes,
        profile_bytes,
        roots_digest,
        installation_profile_digest,
        resource_profile_digest,
        release_target_id,
    }
}

fn encode_profile(daemon_key: &[u8; 32], client_key: &[u8; 32], policy_key: &[u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[0x71; 32])
        .unwrap()
        .u8(0)
        .unwrap()
        .array(2)
        .unwrap()
        .str("daemon-key")
        .unwrap()
        .bytes(daemon_key)
        .unwrap()
        .array(1)
        .unwrap()
        .array(6)
        .unwrap()
        .str("jarvis-client")
        .unwrap()
        .str("jarvis-key")
        .unwrap()
        .bytes(client_key)
        .unwrap()
        .u8(0)
        .unwrap()
        .u32(1_001)
        .unwrap()
        .u32(1_003)
        .unwrap();
    encoder
        .writer_mut()
        .extend_from_slice(&encode_policy_roots(policy_key));
    encoder
        .u32(1_002)
        .unwrap()
        .u32(1_002)
        .unwrap()
        .u32(1_001)
        .unwrap()
        .str("/run/savana/kernel/kerneld.sock")
        .unwrap()
        .str("/etc/savana/kernel/selected-policy-v1.cbor")
        .unwrap()
        .str("/etc/savana/kernel/selected-policy-v1.sig")
        .unwrap()
        .u16(0o750)
        .unwrap()
        .u16(0o660)
        .unwrap();
    encoder.into_writer()
}

fn encode_policy_roots(policy_key: &[u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(1)
        .unwrap()
        .array(4)
        .unwrap()
        .str("policy-root")
        .unwrap()
        .bytes(policy_key)
        .unwrap()
        .u64(3)
        .unwrap()
        .bool(false)
        .unwrap();
    encoder.into_writer()
}

fn compute_release_target(
    roots_digest: [u8; 32],
    resource_profile_digest: [u8; 32],
    installation_profile_digest: [u8; 32],
) -> [u8; 32] {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(0)
        .unwrap()
        .u16(0)
        .unwrap()
        .array(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&roots_digest)
        .unwrap()
        .bytes(&resource_profile_digest)
        .unwrap()
        .bytes(&installation_profile_digest)
        .unwrap();
    domain_hash(RELEASE_TARGET_DOMAIN, &encoder.into_writer())
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
