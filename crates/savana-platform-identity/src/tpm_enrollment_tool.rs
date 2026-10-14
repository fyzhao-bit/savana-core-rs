//! Offline public-material authoring. No private keys, TPM commands, installation
//! or authority activation. Only an external installer can approve a proposal.
use crate::{
    TpmClientIdentityV3, TpmEnrollmentProposalV3, TpmEnrollmentV3, TpmNvBindingV3, TpmPcrPolicyV3,
    TpmSignatureErrorV3 as Error, TpmSigningBindingV3, TpmSigningPublicV3, TpmStateHeadV3,
    TpmStoreV3,
};
use serde::{Deserialize, Serialize};

const MAX_REQUEST: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    uid: u32,
    gid: u32,
    executable_sha256: String,
}
impl Identity {
    fn build(self) -> Result<TpmClientIdentityV3, Error> {
        TpmClientIdentityV3::new(self.uid, self.gid, fixed(&self.executable_sha256)?)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    index: u32,
    name: String,
    store_id: String,
    initial_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    installation_id: String,
    epoch: u64,
    signing_handle: u32,
    tpm2b_public: String,
    qualified_name: String,
    pcr_mask: u8,
    pcr_digest: String,
    stores: [Store; 5],
    deployer: Identity,
    kernel: Identity,
    broker: Identity,
    not_before: u64,
    expires: u64,
}
impl Material {
    fn build(self) -> Result<TpmEnrollmentProposalV3, Error> {
        let installation = fixed(&self.installation_id)?;
        let signing = TpmSigningBindingV3::new_with_pcr(
            TpmSigningPublicV3::from_tpm2b_public(&unhex(&self.tpm2b_public, 128)?)?,
            fixed(&self.qualified_name)?,
            self.signing_handle,
            installation,
            self.epoch,
            TpmPcrPolicyV3::new(self.pcr_mask, fixed(&self.pcr_digest)?)?,
        )?;
        let mut stores = Vec::with_capacity(5);
        for (slot, value) in self.stores.into_iter().enumerate() {
            if value.index != TpmStoreV3::ALL[slot].index() {
                return Err(Error::BindingMismatch);
            }
            stores.push(TpmNvBindingV3::new(
                value.index,
                fixed(&value.name)?,
                installation,
                fixed(&value.store_id)?,
                self.epoch,
                fixed(&value.initial_root)?,
                TpmStateHeadV3::GENESIS,
            )?);
        }
        TpmEnrollmentProposalV3::new(
            signing,
            stores.try_into().map_err(|_| Error::Malformed)?,
            self.deployer.build()?,
            self.kernel.build()?,
            self.broker.build()?,
            self.not_before,
            self.expires,
            [0; 32],
        )
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    InspectPrepared {
        unsigned_enrollment: String,
    },
    FinalizePrepared {
        unsigned_enrollment: String,
        installer_public_key: String,
        signature: String,
    },
    Prepare {
        material: Material,
    },
    Finalize {
        material: Material,
        installer_public_key: String,
        signature: String,
    },
    Verify {
        enrollment: String,
        installer_public_key: String,
    },
}

#[derive(Serialize)]
struct Prepared {
    schema: &'static str,
    unsigned_enrollment: String,
    signature_input: String,
    hardware_attested: bool,
    activated: bool,
    material: serde_json::Value,
}
#[derive(Serialize)]
struct Verified {
    schema: &'static str,
    enrollment: String,
    enrollment_digest: String,
    expected_guard_root: String,
    hardware_attested: bool,
    activated: bool,
}

/// Bounded JSON stdin/stdout codec used by the offline authoring executable.
/// `now` is the verifier's clock in Unix seconds. The native service independently
/// checks its clock, installed root, TPM key and NV guard on every operation.
/// Supplied measurements and trust roots are NOT attestation evidence.
pub fn process_tpm_enrollment_request_v3(input: &[u8], now: u64) -> Result<Vec<u8>, Error> {
    if input.is_empty() || input.len() > MAX_REQUEST {
        return Err(Error::Malformed);
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| Error::Malformed)?;
    match request {
        Request::InspectPrepared {
            unsigned_enrollment,
        } => prepared(
            TpmEnrollmentProposalV3::from_canonical_bytes(&unhex(&unsigned_enrollment, 1984)?)?,
            now,
        ),
        Request::FinalizePrepared {
            unsigned_enrollment,
            installer_public_key,
            signature,
        } => {
            let mut bytes = unhex(&unsigned_enrollment, 1984)?;
            bytes.extend_from_slice(&fixed::<64>(&signature)?);
            verified(bytes, fixed(&installer_public_key)?, now)
        }
        Request::Prepare { material } => prepared(material.build()?, now),
        Request::Finalize {
            material,
            installer_public_key,
            signature,
        } => {
            let p = material.build()?;
            verified(
                p.attach_signature(fixed(&signature)?),
                fixed(&installer_public_key)?,
                now,
            )
        }
        Request::Verify {
            enrollment,
            installer_public_key,
        } => verified(
            unhex(&enrollment, 2048)?,
            fixed(&installer_public_key)?,
            now,
        ),
    }
}
fn prepared(p: TpmEnrollmentProposalV3, now: u64) -> Result<Vec<u8>, Error> {
    if now < p.not_before || now >= p.expires {
        return Err(Error::BindingMismatch);
    }
    let identity = |i: TpmClientIdentityV3| serde_json::json!({"uid":i.uid(), "gid":i.gid(), "executable_sha256":hex(&i.executable_digest())});
    let policy = p.signing.pcr_policy().ok_or(Error::Malformed)?;
    encode(&Prepared {
        schema: "savana-tpm-enrollment-proposal-v3",
        unsigned_enrollment: hex(&p.canonical_bytes()),
        signature_input: hex(&p.signature_input()),
        hardware_attested: false,
        activated: false,
        material: serde_json::json!({
            "installation_id":hex(&p.signing.installation), "epoch":p.signing.epoch,
            "signing_handle":p.signing.handle, "tpm2b_public":hex(&p.signing.public.tpm2b_public()),
            "qualified_name":hex(&p.signing.qualified_name), "pcr_mask":policy.mask(), "pcr_digest":hex(&policy.pcr_digest()),
            "stores":p.stores.iter().map(|s| serde_json::json!({"index":s.index,"name":hex(&s.name),"store_id":hex(&s.store),"initial_root":hex(&s.initial_root)})).collect::<Vec<_>>(),
            "deployer":identity(p.deployer), "kernel":identity(p.kernel), "broker":identity(p.broker),
            "not_before":p.not_before, "expires":p.expires,
        }),
    })
}
fn verified(bytes: Vec<u8>, root: [u8; 32], now: u64) -> Result<Vec<u8>, Error> {
    let value = TpmEnrollmentV3::verify(&bytes, root, now)?;
    encode(&Verified {
        schema: "savana-tpm-enrollment-verified-v3",
        enrollment: hex(&bytes),
        enrollment_digest: hex(&value.digest()),
        expected_guard_root: hex(&value.active_enrollment_root()),
        hardware_attested: false,
        activated: false,
    })
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|_| Error::Malformed)
}
fn unhex(text: &str, max: usize) -> Result<Vec<u8>, Error> {
    if text.is_empty() || text.len() > max * 2 || text.len() % 2 != 0 {
        return Err(Error::Malformed);
    }
    fn nibble(v: u8) -> Result<u8, Error> {
        match v {
            b'0'..=b'9' => Ok(v - b'0'),
            b'a'..=b'f' => Ok(v - b'a' + 10),
            _ => Err(Error::Malformed),
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|c| Ok(nibble(c[0])? * 16 + nibble(c[1])?))
        .collect()
}
pub(crate) fn fixed<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    unhex(text, N)?.try_into().map_err(|_| Error::Malformed)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("String formatting");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};

    fn material() -> Value {
        let p = crate::tpm_enrollment::tests::proposal();
        let identity = |i: TpmClientIdentityV3| json!({"uid":i.uid(), "gid":i.gid(), "executable_sha256":hex(&i.executable_digest())});
        json!({
            "installation_id":hex(&p.signing.installation), "epoch":p.signing.epoch,
            "signing_handle":p.signing.handle, "tpm2b_public":hex(&p.signing.public.tpm2b_public()),
            "qualified_name":hex(&p.signing.qualified_name), "pcr_mask":0x81, "pcr_digest":hex(&[8;32]),
            "stores":p.stores.iter().map(|s| json!({"index":s.index,"name":hex(&s.name),"store_id":hex(&s.store),"initial_root":hex(&s.initial_root)})).collect::<Vec<_>>(),
            "deployer":identity(p.deployer), "kernel":identity(p.kernel), "broker":identity(p.broker),
            "not_before":100, "expires":200,
        })
    }
    fn call(request: &Value, now: u64) -> Result<Value, Error> {
        let out = process_tpm_enrollment_request_v3(&serde_json::to_vec(request).unwrap(), now)?;
        Ok(serde_json::from_slice(&out).unwrap())
    }
    #[test]
    fn offline_prepare_external_sign_finalize_and_verify_match_runtime_codec() {
        let material = material();
        let prepared = call(&json!({"operation":"prepare", "material":material}), 150).unwrap();
        assert_eq!(prepared["material"], material);
        assert_eq!(call(&json!({"operation":"inspect_prepared", "unsigned_enrollment":prepared["unsigned_enrollment"]}), 150).unwrap(), prepared);
        let key = SigningKey::from_bytes(&[9; 32]);
        let signature =
            key.sign(&fixed::<32>(prepared["signature_input"].as_str().unwrap()).unwrap());
        let finalized = call(&json!({"operation":"finalize", "material":material,
            "installer_public_key":hex(&key.verifying_key().to_bytes()), "signature":hex(&signature.to_bytes())}), 150).unwrap();
        assert_eq!(call(&json!({"operation":"finalize_prepared", "unsigned_enrollment":prepared["unsigned_enrollment"],
            "installer_public_key":hex(&key.verifying_key().to_bytes()), "signature":hex(&signature.to_bytes())}), 150).unwrap(), finalized);
        assert_eq!(finalized["activated"], false);
        assert_eq!(finalized["hardware_attested"], false);
        let verified = call(
            &json!({"operation":"verify", "enrollment":finalized["enrollment"],
            "installer_public_key":hex(&key.verifying_key().to_bytes())}),
            150,
        )
        .unwrap();
        assert_eq!(finalized, verified);
        let native = crate::tpm_enrollment::tests::verified();
        assert_eq!(finalized["enrollment_digest"], hex(&native.digest()));
        assert_eq!(
            finalized["expected_guard_root"],
            hex(&native.active_enrollment_root())
        );
    }
    #[test]
    fn authoring_rejects_changed_material_wrong_root_expiry_and_unsigned_input() {
        let p = crate::tpm_enrollment::tests::proposal();
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut req = json!({"operation":"finalize", "material":material(),
            "installer_public_key":hex(&key.verifying_key().to_bytes()), "signature":hex(&key.sign(&p.signature_input()).to_bytes())});
        for now in [0, 99, 200, u64::MAX] {
            assert!(call(&req, now).is_err());
        }
        req["material"]["expires"] = json!(201);
        assert!(call(&req, 150).is_err());
        req["material"]["expires"] = json!(200);
        req["installer_public_key"] = json!(hex(&SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes()));
        assert!(call(&req, 150).is_err());
        assert!(call(
            &json!({"operation":"verify", "enrollment":hex(&p.canonical_bytes()),
            "installer_public_key":hex(&key.verifying_key().to_bytes())}),
            150
        )
        .is_err());
    }
    #[test]
    fn authoring_cannot_request_private_key_reset_migration_or_weak_policy() {
        for field in [
            "private_key",
            "previous_enrollment_root",
            "reset",
            "initial_head",
        ] {
            let mut m = material();
            m[field] = json!(0);
            assert!(call(&json!({"operation":"prepare", "material":m}), 150).is_err());
        }
        for (field, value) in [
            ("pcr_mask", json!(1)),
            ("epoch", json!(0)),
            ("qualified_name", json!("AA")),
        ] {
            let mut m = material();
            m[field] = value;
            assert!(call(&json!({"operation":"prepare", "material":m}), 150).is_err());
        }
        let mut m = material();
        m["stores"][1] = m["stores"][0].clone();
        assert!(call(&json!({"operation":"prepare", "material":m}), 150).is_err());
    }
    #[test]
    fn input_is_bounded_closed_and_duplicate_fields_fail() {
        for bytes in [
            vec![],
            vec![b' '; MAX_REQUEST + 1],
            br#"{"operation":"prepare","operation":"verify"}"#.to_vec(),
            br#"{"operation":"clear"}"#.to_vec(),
        ] {
            assert!(process_tpm_enrollment_request_v3(&bytes, 150).is_err());
        }
        let mut req = json!({"operation":"prepare", "material":material()});
        req["extra"] = json!(true);
        assert!(call(&req, 150).is_err());
    }
    #[test]
    fn prepared_input_is_canonical_bounded_and_never_counts_as_approval() {
        let proposal = crate::tpm_enrollment::tests::proposal();
        let bytes = proposal.canonical_bytes();
        for bad in [
            vec![],
            vec![0; 1985],
            [&bytes[..], &[0]].concat(),
            bytes[..bytes.len() - 1].to_vec(),
        ] {
            assert!(call(
                &json!({"operation":"inspect_prepared", "unsigned_enrollment":hex(&bad)}),
                150
            )
            .is_err());
        }
        assert!(call(
            &json!({"operation":"inspect_prepared", "unsigned_enrollment":hex(&bytes)}),
            200
        )
        .is_err());
        let key = SigningKey::from_bytes(&[9; 32]);
        assert!(call(&json!({"operation":"finalize_prepared", "unsigned_enrollment":hex(&bytes),
            "installer_public_key":hex(&key.verifying_key().to_bytes()), "signature":"00".repeat(64)}),150).is_err());
    }
}
