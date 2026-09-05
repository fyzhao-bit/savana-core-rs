//! Finite reviewed business profiles, NOT a general MCP client or HTTP proxy.
//!
//! MCP profile pins the 2025-11-25 `tools/call` request subset with string IDs,
//! flat typed arguments and no task/interactive extensions. Its reviewed result
//! schema additionally requires `structuredContent.savana_status` and explicit
//! `isError`; this is NOT a generic MCP success detector. See
//! <https://modelcontextprotocol.io/specification/2025-11-25/server/tools> and
//! <https://www.jsonrpc.org/specification>.
//!
//! Fixed POST is an application JSON envelope, not HTTP framing. The deployed
//! transport must bind this inside its custom CBOR/mTLS gateway request. A signed
//! mapping attests a reviewed provider contract; parsing does not prove arbitrary
//! provider-internal semantics. Results and readable fields remain untrusted data.
//!
//! Canonical JSON uses lexically sorted ASCII object keys, no whitespace, decimal
//! integers, literal UTF-8, and serde_json string escaping. No floats, nulls,
//! batches, optional/unknown keys, or open/nested argument types are supported.
//! This is the canonical encoding of this closed grammar, not general JCS.
//! Byte magnitude means the UTF-8 bytes of the decoded payload, not JSON escape
//! bytes, TLS bytes, or remote storage size. The remaining-parameter commitment
//! excludes separately mapped controls and payload; the full request commits all.
//! Profile target/credential identities must be checked against the executor's
//! actual route/credential. They are nonsecret identities, never credential bytes.
use super::business_json::{self, Json};
use super::{ActionAlternativeV2, ActionCodecProfileV2, Digest32V2, MagnitudeUnitV2, TaskEffectV2};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

#[path = "business_controls.rs"]
mod controls;
pub use controls::{decode_business_controls_v2, encode_business_controls_v2, BusinessControlsV2};

pub const MAX_BUSINESS_JSON_BYTES_V2: usize = 64 * 1024;
pub const MAX_BUSINESS_PROFILE_BYTES_V2: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BusinessCodecErrorV2 {
    #[error("unsupported business profile")]
    Unsupported,
    #[error("invalid business request")]
    Malformed,
    #[error("business request bound exceeded")]
    Limit,
    #[error("business request binding mismatch")]
    Binding,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessFieldRoleV2 {
    Resource = 1,
    Destination = 2,
    Magnitude = 3,
    Payload = 4,
    Parameter = 5,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessFieldTypeV2 {
    Text = 1,
    Unsigned = 2,
    Boolean = 3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessMagnitudeV2 {
    CountField,
    FixedCount(u64),
    Utf8PayloadBytes,
}
/// Plain data for trusted owner projection, never authorization evidence.
#[derive(Clone, PartialEq, Eq)]
pub enum BusinessValueV2 {
    Text(String),
    Unsigned(u64),
    Boolean(bool),
}
impl std::fmt::Debug for BusinessValueV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Text(_) => "BusinessValueV2::Text(..)",
            Self::Unsigned(_) => "BusinessValueV2::Unsigned(..)",
            Self::Boolean(_) => "BusinessValueV2::Boolean(..)",
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusinessFieldV2 {
    name: String,
    role: BusinessFieldRoleV2,
    kind: BusinessFieldTypeV2,
}
impl BusinessFieldV2 {
    pub fn new(
        name: &str,
        role: BusinessFieldRoleV2,
        kind: BusinessFieldTypeV2,
    ) -> Result<Self, BusinessCodecErrorV2> {
        if !identifier(name, 64)
            || match role {
                BusinessFieldRoleV2::Resource
                | BusinessFieldRoleV2::Destination
                | BusinessFieldRoleV2::Payload => kind != BusinessFieldTypeV2::Text,
                BusinessFieldRoleV2::Magnitude => kind != BusinessFieldTypeV2::Unsigned,
                BusinessFieldRoleV2::Parameter => false,
            }
        {
            return Err(BusinessCodecErrorV2::Unsupported);
        }
        Ok(Self {
            name: name.into(),
            role,
            kind,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn role(&self) -> BusinessFieldRoleV2 {
        self.role
    }
    pub fn kind(&self) -> BusinessFieldTypeV2 {
        self.kind
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BusinessProfileV2 {
    codec: ActionCodecProfileV2,
    operation: String,
    target: Digest32V2,
    credential: Digest32V2,
    effect: TaskEffectV2,
    magnitude: BusinessMagnitudeV2,
    fields: Vec<BusinessFieldV2>,
}
impl std::fmt::Debug for BusinessProfileV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BusinessProfileV2")
            .field("codec", &self.codec)
            .field("effect", &self.effect)
            .finish_non_exhaustive()
    }
}
impl BusinessProfileV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        codec: ActionCodecProfileV2,
        operation: &str,
        target: Digest32V2,
        credential: Digest32V2,
        effect: TaskEffectV2,
        magnitude: BusinessMagnitudeV2,
        fields: Vec<BusinessFieldV2>,
    ) -> Result<Self, BusinessCodecErrorV2> {
        let operation_valid = match codec {
            ActionCodecProfileV2::McpToolsCallJsonV1 => identifier(operation, 128),
            ActionCodecProfileV2::FixedJsonPostV1 => {
                operation.starts_with('/')
                    && operation.len() <= 256
                    && operation
                        .split('/')
                        .skip(1)
                        .all(|s| identifier(s, 64) && s != "." && s != "..")
            }
        };
        if !operation_valid
            || target.as_bytes() == &[0; 32]
            || credential.as_bytes() == &[0; 32]
            || fields.len() < 3
            || fields.len() > 32
            || fields.windows(2).any(|p| p[0].name >= p[1].name)
        {
            return Err(BusinessCodecErrorV2::Unsupported);
        }
        for role in [
            BusinessFieldRoleV2::Resource,
            BusinessFieldRoleV2::Destination,
            BusinessFieldRoleV2::Payload,
        ] {
            if fields.iter().filter(|f| f.role == role).count() != 1 {
                return Err(BusinessCodecErrorV2::Unsupported);
            }
        }
        let count_fields = fields
            .iter()
            .filter(|f| f.role == BusinessFieldRoleV2::Magnitude)
            .count();
        if (magnitude == BusinessMagnitudeV2::CountField && count_fields != 1)
            || (magnitude != BusinessMagnitudeV2::CountField && count_fields != 0)
            || magnitude == BusinessMagnitudeV2::FixedCount(0)
        {
            return Err(BusinessCodecErrorV2::Unsupported);
        }
        Ok(Self {
            codec,
            operation: operation.into(),
            target,
            credential,
            effect,
            magnitude,
            fields,
        })
    }
    pub fn codec(&self) -> ActionCodecProfileV2 {
        self.codec
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn target_identity(&self) -> Digest32V2 {
        self.target
    }
    pub fn credential_identity(&self) -> Digest32V2 {
        self.credential
    }
    pub fn effect(&self) -> TaskEffectV2 {
        self.effect
    }
    pub fn magnitude_rule(&self) -> BusinessMagnitudeV2 {
        self.magnitude
    }
    pub fn fields(&self) -> &[BusinessFieldV2] {
        &self.fields
    }
    pub fn digest(&self) -> Digest32V2 {
        hash(
            b"SAVANA_BUSINESS_PROFILE_V2_SCHEMA1\0",
            &[&encode_business_profile_v2(self).expect("validated profile")],
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BusinessRequestV2 {
    profile: BusinessProfileV2,
    request_id: String,
    fields: BTreeMap<String, Json>,
    canonical: Vec<u8>,
    magnitude: u64,
}
impl std::fmt::Debug for BusinessRequestV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BusinessRequestV2")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}
impl BusinessRequestV2 {
    /// Builds the same closed envelope checked by `parse`, without requiring the
    /// kernel to implement its own JSON schema or field-to-control interpretation.
    pub fn from_fields(
        profile: &BusinessProfileV2,
        request_id: &str,
        fields: Vec<(String, BusinessValueV2)>,
    ) -> Result<Self, BusinessCodecErrorV2> {
        if fields.len() != profile.fields.len() || !identifier(request_id, 128) {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        let args = controls::field_map(fields)?;
        let text = |s: &str| Json::Text(s.into());
        let pairs = match profile.codec {
            ActionCodecProfileV2::McpToolsCallJsonV1 => vec![
                ("jsonrpc", text("2.0")),
                ("id", text(request_id)),
                ("method", text("tools/call")),
                (
                    "params",
                    Json::Object(BTreeMap::from([
                        ("name".into(), text(&profile.operation)),
                        ("arguments".into(), Json::Object(args)),
                    ])),
                ),
            ],
            ActionCodecProfileV2::FixedJsonPostV1 => vec![
                ("request_id", text(request_id)),
                ("method", text("POST")),
                ("path", text(&profile.operation)),
                ("body", Json::Object(args)),
            ],
        };
        let root = Json::Object(
            pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        );
        Self::parse(profile, request_id, &root.canonical())
    }
    pub fn parse(
        profile: &BusinessProfileV2,
        expected_id: &str,
        bytes: &[u8],
    ) -> Result<Self, BusinessCodecErrorV2> {
        if !identifier(expected_id, 128) {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        let root = business_json::parse(bytes)?;
        let args = match profile.codec {
            ActionCodecProfileV2::McpToolsCallJsonV1 => {
                let map = business_json::exact(&root, &["jsonrpc", "id", "method", "params"])?;
                if map["jsonrpc"].text()? != "2.0"
                    || map["id"].text()? != expected_id
                    || map["method"].text()? != "tools/call"
                {
                    return Err(BusinessCodecErrorV2::Binding);
                }
                let params = business_json::exact(&map["params"], &["name", "arguments"])?;
                if params["name"].text()? != profile.operation {
                    return Err(BusinessCodecErrorV2::Binding);
                }
                params["arguments"].object()?
            }
            ActionCodecProfileV2::FixedJsonPostV1 => {
                let map = business_json::exact(&root, &["request_id", "method", "path", "body"])?;
                if map["request_id"].text()? != expected_id
                    || map["method"].text()? != "POST"
                    || map["path"].text()? != profile.operation
                {
                    return Err(BusinessCodecErrorV2::Binding);
                }
                map["body"].object()?
            }
        };
        if args.len() != profile.fields.len() {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        let mut magnitude = match profile.magnitude {
            BusinessMagnitudeV2::FixedCount(n) => n,
            _ => 0,
        };
        for field in &profile.fields {
            let value = args
                .get(&field.name)
                .ok_or(BusinessCodecErrorV2::Malformed)?;
            controls::validate_field(field, value)?;
            match (field.kind, value) {
                (BusinessFieldTypeV2::Text, Json::Text(v)) => {
                    if field.role == BusinessFieldRoleV2::Payload
                        && profile.magnitude == BusinessMagnitudeV2::Utf8PayloadBytes
                    {
                        magnitude = v.len() as u64;
                    }
                }
                (BusinessFieldTypeV2::Unsigned, Json::Unsigned(v)) => {
                    if field.role == BusinessFieldRoleV2::Magnitude {
                        magnitude = *v;
                    }
                }
                (BusinessFieldTypeV2::Boolean, Json::Bool(_)) => (),
                _ => return Err(BusinessCodecErrorV2::Malformed),
            }
        }
        if magnitude == 0 {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        let canonical = root.canonical();
        if canonical.len() > MAX_BUSINESS_JSON_BYTES_V2 {
            return Err(BusinessCodecErrorV2::Limit);
        }
        Ok(Self {
            profile: profile.clone(),
            request_id: expected_id.into(),
            fields: args.clone(),
            canonical,
            magnitude,
        })
    }
    pub fn canonical_json(&self) -> Vec<u8> {
        self.canonical.clone()
    }
    pub fn profile(&self) -> &BusinessProfileV2 {
        &self.profile
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn magnitude(&self) -> u64 {
        self.magnitude
    }
    pub fn unit(&self) -> MagnitudeUnitV2 {
        if self.profile.magnitude == BusinessMagnitudeV2::Utf8PayloadBytes {
            MagnitudeUnitV2::Bytes
        } else {
            MagnitudeUnitV2::Count
        }
    }
    fn text_role(&self, role: BusinessFieldRoleV2) -> &str {
        let field = self
            .profile
            .fields
            .iter()
            .find(|f| f.role == role)
            .expect("validated role");
        self.fields[&field.name]
            .text()
            .expect("validated text role")
    }
    pub fn resource(&self) -> &str {
        self.text_role(BusinessFieldRoleV2::Resource)
    }
    pub fn destination(&self) -> &str {
        self.text_role(BusinessFieldRoleV2::Destination)
    }
    pub fn payload(&self) -> &str {
        self.text_role(BusinessFieldRoleV2::Payload)
    }
    pub fn resource_digest(&self) -> Digest32V2 {
        controls::resource_digest(&self.profile, &self.fields)
    }
    pub fn destination_digest(&self) -> Digest32V2 {
        controls::destination_digest(&self.profile, &self.fields)
    }
    pub fn payload_digest(&self) -> Digest32V2 {
        hash(
            b"SAVANA_BUSINESS_UTF8_PAYLOAD_V2_SCHEMA1\0",
            &[self.payload().as_bytes()],
        )
    }
    pub fn field_values(&self) -> Vec<(String, BusinessValueV2)> {
        self.fields
            .iter()
            .map(|(name, value)| {
                let value = match value {
                    Json::Text(s) => BusinessValueV2::Text(s.clone()),
                    Json::Unsigned(n) => BusinessValueV2::Unsigned(*n),
                    Json::Bool(b) => BusinessValueV2::Boolean(*b),
                    _ => unreachable!("validated flat typed fields"),
                };
                (name.clone(), value)
            })
            .collect()
    }
    pub fn action_alternative(
        &self,
        descriptor_digest: Digest32V2,
    ) -> Result<ActionAlternativeV2, BusinessCodecErrorV2> {
        ActionAlternativeV2::new(
            descriptor_digest,
            self.profile.codec,
            self.profile.effect,
            self.resource_digest(),
            self.destination_digest(),
            self.parameters_digest(),
            self.unit(),
        )
        .map_err(malformed)
    }
    pub fn parameters_digest(&self) -> Digest32V2 {
        controls::parameters_digest(&self.profile, &self.fields)
    }
    pub fn digest(&self) -> Digest32V2 {
        hash(
            b"SAVANA_BUSINESS_REQUEST_V2_SCHEMA1\0",
            &[self.profile.digest().as_bytes(), &self.canonical],
        )
    }
    pub fn verify_equivalent(&self, worker_bytes: &[u8]) -> Result<(), BusinessCodecErrorV2> {
        if Self::parse(&self.profile, &self.request_id, worker_bytes)? != *self {
            return Err(BusinessCodecErrorV2::Binding);
        }
        Ok(())
    }
    /// Classification is data, NOT a verified task outcome. Only the executor's
    /// authenticated retained-response path may issue completion evidence.
    pub fn classify_response(
        &self,
        bytes: &[u8],
    ) -> Result<BusinessResponseDispositionV2, BusinessCodecErrorV2> {
        let root = business_json::parse(bytes)?;
        match self.profile.codec {
            ActionCodecProfileV2::FixedJsonPostV1 => {
                let map = business_json::exact(&root, &["request_id", "status"])?;
                if map["request_id"].text()? != self.request_id {
                    return Err(BusinessCodecErrorV2::Binding);
                }
                disposition(map["status"].text()?)
            }
            ActionCodecProfileV2::McpToolsCallJsonV1 => {
                let is_error = root.object()?.contains_key("error");
                let map = business_json::exact(
                    &root,
                    &["jsonrpc", "id", if is_error { "error" } else { "result" }],
                )?;
                if map["jsonrpc"].text()? != "2.0" || map["id"].text()? != self.request_id {
                    return Err(BusinessCodecErrorV2::Binding);
                }
                if is_error {
                    let error = business_json::exact(&map["error"], &["code", "message"])?;
                    if !matches!(error["code"], Json::Signed(_) | Json::Unsigned(_)) {
                        return Err(BusinessCodecErrorV2::Malformed);
                    }
                    error["message"].text()?;
                    return Ok(BusinessResponseDispositionV2::Failed);
                }
                let result = business_json::exact(
                    &map["result"],
                    &["isError", "content", "structuredContent"],
                )?;
                let Json::Array(content) = &result["content"] else {
                    return Err(BusinessCodecErrorV2::Malformed);
                };
                for part in content {
                    let part = business_json::exact(part, &["type", "text"])?;
                    if part["type"].text()? != "text" {
                        return Err(BusinessCodecErrorV2::Unsupported);
                    }
                    part["text"].text()?;
                }
                let structured =
                    business_json::exact(&result["structuredContent"], &["savana_status"])?;
                let status = disposition(structured["savana_status"].text()?)?;
                match result["isError"] {
                    Json::Bool(true) => Ok(BusinessResponseDispositionV2::Failed),
                    Json::Bool(false) => Ok(status),
                    _ => Err(BusinessCodecErrorV2::Malformed),
                }
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Provider-reported application status only. `Failed` does NOT prove that no
/// effect occurred and cannot authorize a magnitude refund or an automatic retry.
pub enum BusinessResponseDispositionV2 {
    Succeeded,
    Failed,
    Indeterminate,
}
fn disposition(value: &str) -> Result<BusinessResponseDispositionV2, BusinessCodecErrorV2> {
    match value {
        "succeeded" => Ok(BusinessResponseDispositionV2::Succeeded),
        "failed" => Ok(BusinessResponseDispositionV2::Failed),
        "indeterminate" => Ok(BusinessResponseDispositionV2::Indeterminate),
        _ => Err(BusinessCodecErrorV2::Unsupported),
    }
}
fn identifier(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
fn control_text(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1024
        && s.trim() == s
        && !s.chars().any(|c| {
            matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}' | '\u{2028}' | '\u{2029}')
                || super::business_unicode::formatting_or_ignorable(c)
        })
}
fn hash(domain: &[u8], parts: &[&[u8]]) -> Digest32V2 {
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    Digest32V2::new(h.finalize().into())
}
fn malformed<E>(_: E) -> BusinessCodecErrorV2 {
    BusinessCodecErrorV2::Malformed
}

pub fn encode_business_profile_v2(p: &BusinessProfileV2) -> Result<Vec<u8>, BusinessCodecErrorV2> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(8)
        .and_then(|e| e.u16(1))
        .and_then(|e| e.u16(p.codec as u16))
        .and_then(|e| e.str(&p.operation))
        .and_then(|e| e.bytes(p.target.as_bytes()))
        .and_then(|e| e.bytes(p.credential.as_bytes()))
        .and_then(|e| e.u16(p.effect as u16))
        .map_err(malformed)?;
    let (tag, n) = match p.magnitude {
        BusinessMagnitudeV2::CountField => (1, 0),
        BusinessMagnitudeV2::FixedCount(n) => (2, n),
        BusinessMagnitudeV2::Utf8PayloadBytes => (3, 0),
    };
    e.array(2)
        .and_then(|e| e.u16(tag))
        .and_then(|e| e.u64(n))
        .and_then(|e| e.array(p.fields.len() as u64))
        .map_err(malformed)?;
    for f in &p.fields {
        e.array(3)
            .and_then(|e| e.str(&f.name))
            .and_then(|e| e.u16(f.role as u16))
            .and_then(|e| e.u16(f.kind as u16))
            .map_err(malformed)?;
    }
    let bytes = e.into_writer();
    if bytes.len() > MAX_BUSINESS_PROFILE_BYTES_V2 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    Ok(bytes)
}
pub fn decode_business_profile_v2(bytes: &[u8]) -> Result<BusinessProfileV2, BusinessCodecErrorV2> {
    if bytes.len() > MAX_BUSINESS_PROFILE_BYTES_V2 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(malformed)? != Some(8) || d.u16().map_err(malformed)? != 1 {
        return Err(BusinessCodecErrorV2::Unsupported);
    }
    let codec = match d.u16().map_err(malformed)? {
        1 => ActionCodecProfileV2::McpToolsCallJsonV1,
        2 => ActionCodecProfileV2::FixedJsonPostV1,
        _ => return Err(BusinessCodecErrorV2::Unsupported),
    };
    let operation = d.str().map_err(malformed)?;
    let target = Digest32V2::new(
        d.bytes()
            .map_err(malformed)?
            .try_into()
            .map_err(malformed)?,
    );
    let credential = Digest32V2::new(
        d.bytes()
            .map_err(malformed)?
            .try_into()
            .map_err(malformed)?,
    );
    let effect = match d.u16().map_err(malformed)? {
        1 => TaskEffectV2::Read,
        2 => TaskEffectV2::Create,
        3 => TaskEffectV2::Update,
        4 => TaskEffectV2::Delete,
        5 => TaskEffectV2::Send,
        6 => TaskEffectV2::Execute,
        7 => TaskEffectV2::FinalRelease,
        _ => return Err(BusinessCodecErrorV2::Unsupported),
    };
    if d.array().map_err(malformed)? != Some(2) {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    let tag = d.u16().map_err(malformed)?;
    let n = d.u64().map_err(malformed)?;
    let magnitude = match (tag, n) {
        (1, 0) => BusinessMagnitudeV2::CountField,
        (2, n) if n > 0 => BusinessMagnitudeV2::FixedCount(n),
        (3, 0) => BusinessMagnitudeV2::Utf8PayloadBytes,
        _ => return Err(BusinessCodecErrorV2::Unsupported),
    };
    let count = d
        .array()
        .map_err(malformed)?
        .ok_or(BusinessCodecErrorV2::Malformed)?;
    if !(3..=32).contains(&count) {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut fields = Vec::new();
    for _ in 0..count {
        if d.array().map_err(malformed)? != Some(3) {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        let name = d.str().map_err(malformed)?;
        let role = match d.u16().map_err(malformed)? {
            1 => BusinessFieldRoleV2::Resource,
            2 => BusinessFieldRoleV2::Destination,
            3 => BusinessFieldRoleV2::Magnitude,
            4 => BusinessFieldRoleV2::Payload,
            5 => BusinessFieldRoleV2::Parameter,
            _ => return Err(BusinessCodecErrorV2::Unsupported),
        };
        let kind = match d.u16().map_err(malformed)? {
            1 => BusinessFieldTypeV2::Text,
            2 => BusinessFieldTypeV2::Unsigned,
            3 => BusinessFieldTypeV2::Boolean,
            _ => return Err(BusinessCodecErrorV2::Unsupported),
        };
        fields.push(BusinessFieldV2::new(name, role, kind)?);
    }
    let profile = BusinessProfileV2::new(
        codec, operation, target, credential, effect, magnitude, fields,
    )?;
    if d.position() != bytes.len() || encode_business_profile_v2(&profile)? != bytes {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    Ok(profile)
}
