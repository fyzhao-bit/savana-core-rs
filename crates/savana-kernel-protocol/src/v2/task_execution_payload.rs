//! Closed plaintext sealed by the kernel. Decoding is not authentication: the
//! executor must first verify the enclosing kernel signature and AEAD binding.
//! Control data is never taken from the untrusted codec worker.
use super::{
    action_content_digest_v2, decode_action_content_v2, decode_business_profile_v2,
    encode_action_content_v2, encode_business_profile_v2, ActionContentV2, BusinessCodecErrorV2,
    BusinessRequestV2, Digest32V2, DispatchCoreV2, DispatchSubjectV2, MAX_BUSINESS_JSON_BYTES_V2,
    MAX_BUSINESS_PROFILE_BYTES_V2,
};
use sha2::{Digest as _, Sha256};

pub const MAX_TASK_EXECUTION_PAYLOAD_BYTES_V2: usize = 96 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct TaskExecutionPayloadV2 {
    content: ActionContentV2,
    request: BusinessRequestV2,
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
        if request.action_alternative(content.action().tool_descriptor_digest())?
            != *content.action()
            || request.magnitude() != content.magnitude()
            || request.payload_digest() != content.payload_digest()
        {
            return Err(BusinessCodecErrorV2::Binding);
        }
        Ok(Self { content, request })
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
                    || *profile
                        != super::final_release_business_profile_v2(
                            profile.target_identity(),
                            profile.credential_identity(),
                        )?
                {
                    return Err(BusinessCodecErrorV2::Binding);
                }
                let delivery =
                    super::decode_final_release_delivery_v2(&self.request.canonical_json())?;
                let mut digest = Sha256::new();
                digest.update(b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0");
                digest.update((delivery.payload().len() as u64).to_be_bytes());
                digest.update(delivery.payload());
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
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(5)
        .and_then(|e| e.u16(1))
        .and_then(|e| e.bytes(&content))
        .and_then(|e| e.bytes(&profile))
        .and_then(|e| e.str(value.request.request_id()))
        .and_then(|e| e.bytes(&request))
        .map_err(|_| BusinessCodecErrorV2::Malformed)?;
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
    if d.array().map_err(malformed)? != Some(5) || d.u16().map_err(malformed)? != 1 {
        return Err(BusinessCodecErrorV2::Malformed);
    }
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
    let value = TaskExecutionPayloadV2::new(content, request)?;
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
