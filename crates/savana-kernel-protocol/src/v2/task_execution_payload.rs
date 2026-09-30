//! Closed plaintext sealed by the kernel. Decoding is not authentication: the
//! executor must first verify the enclosing kernel signature and AEAD binding.
//! Control data is never taken from the untrusted codec worker.
use super::{
    action_content_digest_v2, decode_action_content_v2, decode_business_profile_v2,
    decode_result_derived_controls_v2, encode_action_content_v2, encode_business_profile_v2,
    encode_result_derived_controls_v2, ActionContentV2, BusinessCodecErrorV2, BusinessRequestV2,
    Digest32V2, DispatchCoreV2, DispatchSubjectV2, ResultDerivedControlV2,
    MAX_BUSINESS_JSON_BYTES_V2, MAX_BUSINESS_PROFILE_BYTES_V2,
};
use std::collections::BTreeMap;
use sha2::{Digest as _, Sha256};

pub const MAX_TASK_EXECUTION_PAYLOAD_BYTES_V2: usize = 96 * 1024;

/// Exact plaintext plus the independently checked G3 node. This commitment is
/// shared by kernel and executor; computing it alone does not authorize egress.
pub fn presealed_tool_payload_digest_v2(bytes: &[u8], provenance: Digest32V2) -> Digest32V2 {
    presealed_payload_digest(b"SAVANA_PRESEALED_EXECUTOR_PAYLOAD_V2\0", bytes, provenance)
}
pub fn presealed_release_payload_digest_v2(bytes: &[u8], provenance: Digest32V2) -> Digest32V2 {
    presealed_payload_digest(
        b"SAVANA_PRESEALED_FINAL_RELEASE_PAYLOAD_V2\0",
        bytes,
        provenance,
    )
}
fn presealed_payload_digest(domain: &[u8], bytes: &[u8], provenance: Digest32V2) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.update(32u64.to_be_bytes());
    hash.update(provenance.as_bytes());
    Digest32V2::new(hash.finalize().into())
}

#[derive(Clone, PartialEq, Eq)]
pub struct TaskExecutionPayloadV2 {
    content: ActionContentV2,
    request: BusinessRequestV2,
    /// The step's owner-signed result-derived rules (empty for an exact-only
    /// action). The matched action commits to them, so the request can only be
    /// re-verified against the action under the same rules.
    derived: BTreeMap<String, ResultDerivedControlV2>,
}

impl std::fmt::Debug for TaskExecutionPayloadV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskExecutionPayloadV2")
            .finish_non_exhaustive()
    }
}

impl TaskExecutionPayloadV2 {
    pub fn new(
        content: ActionContentV2,
        request: BusinessRequestV2,
    ) -> Result<Self, BusinessCodecErrorV2> {
        Self::new_with_derived(content, request, BTreeMap::new())
    }

    pub fn new_with_derived(
        content: ActionContentV2,
        request: BusinessRequestV2,
        derived: BTreeMap<String, ResultDerivedControlV2>,
    ) -> Result<Self, BusinessCodecErrorV2> {
        if request.action_alternative_with_derived(content.action().tool_descriptor_digest(), &derived)?
            != *content.action()
            || request.magnitude() != content.magnitude()
            || request.payload_digest() != content.payload_digest()
        {
            return Err(BusinessCodecErrorV2::Binding);
        }
        Ok(Self {
            content,
            request,
            derived,
        })
    }

    pub fn derived(&self) -> &BTreeMap<String, ResultDerivedControlV2> {
        &self.derived
    }

    pub fn request(&self) -> &BusinessRequestV2 {
        &self.request
    }
    pub fn content(&self) -> &ActionContentV2 {
        &self.content
    }

    /// Consistency check against the already authenticated dispatch core. This
    /// method deliberately does not claim to verify a kernel signature itself.
    pub fn check_core(&self, core: &DispatchCoreV2) -> Result<(), BusinessCodecErrorV2> {
        let binding = core.task_binding().ok_or(BusinessCodecErrorV2::Binding)?;
        if binding.content_digest()
            != action_content_digest_v2(&self.content).map_err(|_| BusinessCodecErrorV2::Binding)?
        {
            return Err(BusinessCodecErrorV2::Binding);
        }
        match core.subject() {
            DispatchSubjectV2::ToolExecution { binding, .. } => {
                if self.content.action().tool_descriptor_digest()
                    != binding.tool_descriptor_digest()
                    || self.content.plan_revision_digest().as_bytes()
                        != binding.plan_revision_digest().as_bytes()
                    || self.content.provenance_digest() != binding.provenance_set_digest()
                    || self.content.action().effect() == super::TaskEffectV2::FinalRelease
                {
                    return Err(BusinessCodecErrorV2::Binding);
                }
            }
            DispatchSubjectV2::FinalRelease { binding, .. } => {
                let profile = self.request.profile();
                if self.content.action().effect() != super::TaskEffectV2::FinalRelease
                    || self.content.action().destination_digest() != binding.destination_digest()
                    || self.content.provenance_digest() != binding.evidence_digest()
                {
                    return Err(BusinessCodecErrorV2::Binding);
                }
                let payload = if *profile
                    == super::final_release_business_profile_v2(
                        profile.target_identity(),
                        profile.credential_identity(),
                    )? {
                    super::decode_final_release_delivery_v2(&self.request.canonical_json())?
                        .payload()
                        .to_vec()
                } else if *profile
                    == super::final_result_release_business_profile_v04(
                        profile.target_identity(),
                        profile.credential_identity(),
                    )?
                {
                    super::decode_final_result_release_delivery_v04(&self.request.canonical_json())?
                        .payload()
                        .to_vec()
                } else {
                    return Err(BusinessCodecErrorV2::Binding);
                };
                let payload = zeroize::Zeroizing::new(payload);
                let mut digest = Sha256::new();
                digest.update(b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0");
                digest.update((payload.len() as u64).to_be_bytes());
                digest.update(&*payload);
                if Digest32V2::new(digest.finalize().into()) != binding.release_payload_digest() {
                    return Err(BusinessCodecErrorV2::Binding);
                }
            }
        }
        Ok(())
    }
}

pub fn encode_task_execution_payload_v2(
    value: &TaskExecutionPayloadV2,
) -> Result<Vec<u8>, BusinessCodecErrorV2> {
    let content =
        encode_action_content_v2(&value.content).map_err(|_| BusinessCodecErrorV2::Malformed)?;
    let profile = encode_business_profile_v2(value.request.profile())?;
    let request = value.request.canonical_json();
    // Version 1 (exact-only) is byte-identical to before; version 2 appends the
    // step's non-empty derived rule set.
    let derived = if value.derived.is_empty() {
        None
    } else {
        Some(encode_result_derived_controls_v2(&value.derived)?)
    };
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(if derived.is_some() { 6 } else { 5 })
        .and_then(|e| e.u16(if derived.is_some() { 2 } else { 1 }))
        .and_then(|e| e.bytes(&content))
        .and_then(|e| e.bytes(&profile))
        .and_then(|e| e.str(value.request.request_id()))
        .and_then(|e| e.bytes(&request))
        .map_err(|_| BusinessCodecErrorV2::Malformed)?;
    if let Some(derived) = derived {
        e.bytes(&derived).map_err(|_| BusinessCodecErrorV2::Malformed)?;
    }
    let bytes = e.into_writer();
    if bytes.len() > MAX_TASK_EXECUTION_PAYLOAD_BYTES_V2 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    Ok(bytes)
}

pub fn decode_task_execution_payload_v2(
    bytes: &[u8],
) -> Result<TaskExecutionPayloadV2, BusinessCodecErrorV2> {
    let malformed = |_| BusinessCodecErrorV2::Malformed;
    if bytes.is_empty() || bytes.len() > MAX_TASK_EXECUTION_PAYLOAD_BYTES_V2 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut d = minicbor::Decoder::new(bytes);
    let with_derived = match (d.array().map_err(malformed)?, d.u16().map_err(malformed)?) {
        (Some(5), 1) => false,
        (Some(6), 2) => true,
        _ => return Err(BusinessCodecErrorV2::Malformed),
    };
    let content = decode_action_content_v2(d.bytes().map_err(malformed)?)
        .map_err(|_| BusinessCodecErrorV2::Malformed)?;
    let profile_bytes = d.bytes().map_err(malformed)?;
    if profile_bytes.len() > MAX_BUSINESS_PROFILE_BYTES_V2 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let profile = decode_business_profile_v2(profile_bytes)?;
    let id = d.str().map_err(malformed)?;
    if id.len() > 128 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let json = d.bytes().map_err(malformed)?;
    if json.len() > MAX_BUSINESS_JSON_BYTES_V2 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let request = BusinessRequestV2::parse(&profile, id, json)?;
    let derived = if with_derived {
        let rules = decode_result_derived_controls_v2(d.bytes().map_err(malformed)?)?;
        // An empty rule set must use the exact-only version 1 encoding.
        if rules.is_empty() {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        rules
    } else {
        BTreeMap::new()
    };
    let value = TaskExecutionPayloadV2::new_with_derived(content, request, derived)?;
    if d.position() != bytes.len() || encode_task_execution_payload_v2(&value)? != bytes {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    Ok(value)
}

/// Identity of the application gateway route, not a TLS transcript. Callers
/// supply the canonical URL from the reviewed connector transport and its pin.
pub fn business_target_identity_v2(
    canonical_url: &str,
    tls_pin: Digest32V2,
) -> Result<Digest32V2, BusinessCodecErrorV2> {
    if !canonical_url.starts_with("https://")
        || canonical_url.len() > 4096
        || canonical_url.chars().any(char::is_control)
        || tls_pin.as_bytes() == &[0; 32]
    {
        return Err(BusinessCodecErrorV2::Binding);
    }
    let mut hash = Sha256::new();
    hash.update(b"SAVANA_BUSINESS_GATEWAY_TARGET_V2_SCHEMA1\0");
    hash.update((canonical_url.len() as u64).to_be_bytes());
    hash.update(canonical_url.as_bytes());
    hash.update(32u64.to_be_bytes());
    hash.update(tls_pin.as_bytes());
    Ok(Digest32V2::new(hash.finalize().into()))
}

#[cfg(test)]
mod preseal_tests {
    use super::*;

    #[test]
    fn presealed_commitments_preserve_v2_wire_golden_and_separate_domains() {
        let node = Digest32V2::new([0x71; 32]);
        let tool = presealed_tool_payload_digest_v2(b"exact plaintext", node);
        let release = presealed_release_payload_digest_v2(b"exact plaintext", node);
        let hex = |d: Digest32V2| {
            d.as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            hex(tool),
            "96040396b9929db73190121c0018f093e223b0924e97a022f02dc8a1e65b1bfe"
        );
        assert_eq!(
            hex(release),
            "fbaeee3c7419ce4d12be43f1d7b936d66c4eba327206b3601f8b91c7a41e56d8"
        );
        assert_ne!(tool, release);
        assert_ne!(
            tool,
            presealed_tool_payload_digest_v2(b"other plaintext", node)
        );
        assert_ne!(
            tool,
            presealed_tool_payload_digest_v2(b"exact plaintext", Digest32V2::new([0x72; 32]))
        );
    }
}
