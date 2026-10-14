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
pub use controls::{
    decode_business_controls_v2, decode_result_derived_controls_v2, encode_business_controls_v2,
    encode_result_derived_controls_v2, BusinessControlsV2, ResultCandidatesV2, ResultComputeOpV2,
    ResultComputeV2, ResultDerivedControlV2, MAX_RESULT_CANDIDATES_V2,
    MAX_RESULT_CANDIDATE_BYTES_V2,
};

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
    /// The owner's condition gate (at most one per profile): the executor
    /// performs the call only when the value is `CONDITION_ALWAYS_V2` or a
    /// yes (`condition_holds_v2`), and otherwise answers with a fixed no-effect
    /// result without contacting the provider. Bound like a parameter, never
    /// an address.
    Condition = 6,
    /// A further address the action also discloses to (an e-mail's cc and
    /// bcc), beside the one destination. Any number per profile; bound like a
    /// parameter, but held to every destination rule (address flow, owner
    /// origin, display).
    CopyDestination = 7,
}
impl BusinessFieldRoleV2 {
    /// Committed field by field in the parameters digest (an action
    /// alternative's remaining-parameter commitment).
    pub const fn bound_as_parameter(self) -> bool {
        matches!(
            self,
            Self::Parameter | Self::Condition | Self::CopyDestination
        )
    }
    /// An address the action discloses to or acts on.
    pub const fn is_destination_class(self) -> bool {
        matches!(self, Self::Destination | Self::CopyDestination)
    }
}

/// The owner constant that lets a guarded call happen unconditionally.
pub const CONDITION_ALWAYS_V2: &str = "always";
/// The whole result of a guarded call whose condition does not hold: the
/// executor answers with this text and contacts no provider.
pub const CONDITION_SKIPPED_TEXT_V2: &str =
    "Skipped: the owner's condition for this action does not hold.";

/// The parameter fields of a `TableComputeV1` profile, in name order: four
/// inputs, three filters, two orders and the output (the profile also has
/// its one resource, destination and payload field, each fixed).
pub const TABLE_COMPUTE_FIELDS_V2: [&str; 10] = [
    "filter1", "filter2", "filter3", "input1", "input2", "input3", "input4", "order1", "order2",
    "output",
];

/// Whether a condition gate's value lets the call happen: exactly
/// `CONDITION_ALWAYS_V2`, or a yes (surrounding whitespace, any number of
/// final '.' or '!', and ASCII case aside). Anything else -- "no", an
/// unexpected answer, an injected instruction -- means no.
pub fn condition_holds_v2(value: &str) -> bool {
    if value == CONDITION_ALWAYS_V2 {
        return true;
    }
    value
        .trim()
        .trim_end_matches(['.', '!'])
        .trim()
        .eq_ignore_ascii_case("yes")
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessFieldTypeV2 {
    Text = 1,
    Unsigned = 2,
    Boolean = 3,
    /// An ordered list of control texts (e.g. recipients), each item held to
    /// the same rules as a text control; encoded as a JSON array of strings.
    TextList = 4,
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
    TextList(Vec<String>),
}
impl std::fmt::Debug for BusinessValueV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Text(_) => "BusinessValueV2::Text(..)",
            Self::Unsigned(_) => "BusinessValueV2::Unsigned(..)",
            Self::Boolean(_) => "BusinessValueV2::Boolean(..)",
            Self::TextList(_) => "BusinessValueV2::TextList(..)",
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusinessFieldV2 {
    name: String,
    role: BusinessFieldRoleV2,
    kind: BusinessFieldTypeV2,
    /// A deployment-fixed value (a synthetic control a tool without a natural
    /// resource, destination or payload carries): every request and control
    /// must hold exactly this text, so no owner input, constant or result
    /// edge can choose it.
    fixed: Option<String>,
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
                | BusinessFieldRoleV2::Payload
                | BusinessFieldRoleV2::Condition => kind != BusinessFieldTypeV2::Text,
                // Several recipients are one destination list.
                BusinessFieldRoleV2::Destination | BusinessFieldRoleV2::CopyDestination => {
                    !matches!(
                        kind,
                        BusinessFieldTypeV2::Text | BusinessFieldTypeV2::TextList
                    )
                }
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
            fixed: None,
        })
    }
    /// The same field with a deployment-fixed text value. Only a text field
    /// that is not a condition gate can be fixed, and the value must be one
    /// the field itself admits.
    pub fn with_fixed(mut self, value: &str) -> Result<Self, BusinessCodecErrorV2> {
        if self.kind != BusinessFieldTypeV2::Text
            || matches!(
                self.role,
                BusinessFieldRoleV2::Condition | BusinessFieldRoleV2::Magnitude
            )
        {
            return Err(BusinessCodecErrorV2::Unsupported);
        }
        self.fixed = None;
        controls::validate_field(&self, &Json::Text(value.into()))?;
        self.fixed = Some(value.into());
        Ok(self)
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
    pub fn fixed(&self) -> Option<&str> {
        self.fixed.as_deref()
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
            ActionCodecProfileV2::McpToolsCallJsonV1
            | ActionCodecProfileV2::McpModelToolsCallJsonV1
            | ActionCodecProfileV2::TableComputeV1 => identifier(operation, 128),
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
        if fields
            .iter()
            .filter(|f| f.role == BusinessFieldRoleV2::Condition)
            .count()
            > 1
        {
            return Err(BusinessCodecErrorV2::Unsupported);
        }
        // The executor evaluates a table computation itself: a read with
        // exactly the compute parameters, every other field fixed.
        if codec == ActionCodecProfileV2::TableComputeV1
            && (effect != TaskEffectV2::Read
                || magnitude != BusinessMagnitudeV2::FixedCount(1)
                || fields
                    .iter()
                    .filter(|f| f.role == BusinessFieldRoleV2::Parameter)
                    .map(|f| (f.name.as_str(), f.kind, f.fixed.is_some()))
                    .ne(TABLE_COMPUTE_FIELDS_V2
                        .iter()
                        .map(|name| (*name, BusinessFieldTypeV2::Text, false)))
                || fields
                    .iter()
                    .any(|f| f.role != BusinessFieldRoleV2::Parameter && f.fixed.is_none()))
        {
            return Err(BusinessCodecErrorV2::Unsupported);
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
            ActionCodecProfileV2::McpToolsCallJsonV1
            | ActionCodecProfileV2::McpModelToolsCallJsonV1
            | ActionCodecProfileV2::TableComputeV1 => vec![
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
            ActionCodecProfileV2::McpToolsCallJsonV1
            | ActionCodecProfileV2::McpModelToolsCallJsonV1
            | ActionCodecProfileV2::TableComputeV1 => {
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
                (BusinessFieldTypeV2::Boolean, Json::Bool(_))
                | (BusinessFieldTypeV2::TextList, Json::Array(_)) => (),
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
    /// The destination of a profile whose destination is a single text (as
    /// every final-release destination is). A destination list has no single
    /// text: use `destination_items`.
    pub fn destination(&self) -> &str {
        self.text_role(BusinessFieldRoleV2::Destination)
    }
    /// Every destination item, in order: one for a text destination, each
    /// recipient for a destination list.
    pub fn destination_items(&self) -> Vec<&str> {
        let field = self
            .profile
            .fields
            .iter()
            .find(|f| f.role == BusinessFieldRoleV2::Destination)
            .expect("validated role");
        match &self.fields[&field.name] {
            Json::Text(s) => vec![s.as_str()],
            Json::Array(items) => items.iter().filter_map(|i| i.text().ok()).collect(),
            _ => Vec::new(),
        }
    }
    /// True when the destination is a list of recipients.
    pub fn destination_is_list(&self) -> bool {
        self.profile.fields.iter().any(|f| {
            f.role == BusinessFieldRoleV2::Destination && f.kind == BusinessFieldTypeV2::TextList
        })
    }
    pub fn payload(&self) -> &str {
        self.text_role(BusinessFieldRoleV2::Payload)
    }
    pub fn resource_digest(&self) -> Digest32V2 {
        controls::resource_digest(
            &self.profile,
            &self.fields,
            &std::collections::BTreeMap::new(),
        )
    }
    pub fn destination_digest(&self) -> Digest32V2 {
        controls::destination_digest(
            &self.profile,
            &self.fields,
            &std::collections::BTreeMap::new(),
        )
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
                    Json::Array(items) => BusinessValueV2::TextList(
                        items
                            .iter()
                            .map(|i| i.text().map(str::to_owned))
                            .collect::<Result<_, _>>()
                            .expect("validated text list"),
                    ),
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
        self.action_alternative_with_derived(descriptor_digest, &BTreeMap::new())
    }
    /// Build the alternative treating `derived` fields as owner-signed result
    /// edges: their digests commit to the RULE (under the derived domain), not
    /// this request's concrete value, so the alternative equals the owner-signed
    /// derived alternative iff the rule matches. The concrete value's integrity
    /// is checked separately (G7 check_result_argument); here it is ignored for
    /// the derived fields. `derived` must name only fields this profile controls.
    pub fn action_alternative_with_derived(
        &self,
        descriptor_digest: Digest32V2,
        derived: &BTreeMap<String, ResultDerivedControlV2>,
    ) -> Result<ActionAlternativeV2, BusinessCodecErrorV2> {
        ActionAlternativeV2::new(
            descriptor_digest,
            self.profile.codec,
            self.profile.effect,
            controls::resource_digest(&self.profile, &self.fields, derived),
            controls::destination_digest(&self.profile, &self.fields, derived),
            controls::parameters_digest(&self.profile, &self.fields, derived),
            self.unit(),
        )
        .map_err(malformed)
    }
    pub fn parameters_digest(&self) -> Digest32V2 {
        controls::parameters_digest(
            &self.profile,
            &self.fields,
            &std::collections::BTreeMap::new(),
        )
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
    /// Whether this call may happen: true without a condition gate, else
    /// `condition_holds_v2` of the gate's value.
    pub fn condition_holds(&self) -> bool {
        self.profile
            .fields
            .iter()
            .find(|f| f.role == BusinessFieldRoleV2::Condition)
            .is_none_or(|f| self.fields[&f.name].text().is_ok_and(condition_holds_v2))
    }
    /// One text field's value, if this profile has a text field of that name.
    pub fn text_field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).and_then(|value| value.text().ok())
    }
    /// The same request with every text and text-list item of every field
    /// that is not deployment-fixed replaced by `map` (same profile, request
    /// id and field set). The executor sends this, never the original, to a
    /// model provider (`McpModelToolsCallJsonV1`).
    pub fn map_texts(
        &self,
        mut map: impl FnMut(&str) -> Result<String, BusinessCodecErrorV2>,
    ) -> Result<Self, BusinessCodecErrorV2> {
        let mut fields = Vec::new();
        for (name, value) in self.field_values() {
            let fixed = self
                .profile
                .fields
                .iter()
                .any(|f| f.name == name && f.fixed.is_some());
            let value = match value {
                BusinessValueV2::Text(text) if !fixed => BusinessValueV2::Text(map(&text)?),
                BusinessValueV2::TextList(items) => BusinessValueV2::TextList(
                    items
                        .iter()
                        .map(|item| map(item))
                        .collect::<Result<_, _>>()?,
                ),
                other => other,
            };
            fields.push((name, value));
        }
        Self::from_fields(&self.profile, &self.request_id, fields)
    }
    /// A provider reply to this MCP-shaped request with the text of every
    /// content item replaced by `map`; every other byte keeps its canonical
    /// form. The executor puts a model call's values back with it.
    pub fn map_response_texts(
        &self,
        bytes: &[u8],
        mut map: impl FnMut(&str) -> String,
    ) -> Result<Vec<u8>, BusinessCodecErrorV2> {
        if self.profile.codec == ActionCodecProfileV2::FixedJsonPostV1 {
            return Err(BusinessCodecErrorV2::Unsupported);
        }
        self.classify_response(bytes)?;
        let mut root = business_json::parse(bytes)?;
        if let Json::Object(map_root) = &mut root {
            if let Some(Json::Object(result)) = map_root.get_mut("result") {
                if let Some(Json::Array(content)) = result.get_mut("content") {
                    for part in content {
                        if let Json::Object(part) = part {
                            if let Some(Json::Text(text)) = part.get_mut("text") {
                                *text = map(text);
                            }
                        }
                    }
                }
            }
        }
        let mapped = root.canonical();
        self.classify_response(&mapped)?;
        Ok(mapped)
    }
    /// The canonical reply a provider of an MCP-shaped profile gives when the
    /// call succeeded with one text result (`classify_response` reads it as
    /// Succeeded). The executor uses it for a result it produces itself: a
    /// skipped guarded call, a table computation.
    pub fn mcp_success_response(&self, text: &str) -> Result<Vec<u8>, BusinessCodecErrorV2> {
        if self.profile.codec == ActionCodecProfileV2::FixedJsonPostV1 {
            return Err(BusinessCodecErrorV2::Unsupported);
        }
        let text_json = |s: &str| Json::Text(s.into());
        let object = |pairs: Vec<(&str, Json)>| {
            Json::Object(
                pairs
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect(),
            )
        };
        let response = object(vec![
            ("jsonrpc", text_json("2.0")),
            ("id", text_json(&self.request_id)),
            (
                "result",
                object(vec![
                    ("isError", Json::Bool(false)),
                    (
                        "content",
                        Json::Array(vec![object(vec![
                            ("type", text_json("text")),
                            ("text", text_json(text)),
                        ])]),
                    ),
                    (
                        "structuredContent",
                        object(vec![("savana_status", text_json("succeeded"))]),
                    ),
                ]),
            ),
        ])
        .canonical();
        if self.classify_response(&response)? != BusinessResponseDispositionV2::Succeeded {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        Ok(response)
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
            ActionCodecProfileV2::McpToolsCallJsonV1
            | ActionCodecProfileV2::McpModelToolsCallJsonV1
            | ActionCodecProfileV2::TableComputeV1 => {
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
pub(super) fn identifier(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
/// Bounds of a text-list control: at most this many items, each a control text.
pub const MAX_TEXT_LIST_ITEMS_V2: usize = 32;

/// At most this many bytes in one parameter text (a resource, destination
/// or list item stays within 1 KB).
pub const MAX_PARAMETER_TEXT_BYTES_V2: usize = 8 * 1024;

pub(super) fn control_text(s: &str) -> bool {
    s.len() <= 1024 && parameter_text(s)
}

pub(super) fn parameter_text(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_PARAMETER_TEXT_BYTES_V2
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
        // An unfixed field keeps its three-element encoding byte for byte; a
        // fixed one appends its text.
        e.array(if f.fixed.is_some() { 4 } else { 3 })
            .and_then(|e| e.str(&f.name))
            .and_then(|e| e.u16(f.role as u16))
            .and_then(|e| e.u16(f.kind as u16))
            .map_err(malformed)?;
        if let Some(fixed) = &f.fixed {
            e.str(fixed).map_err(malformed)?;
        }
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
        3 => ActionCodecProfileV2::McpModelToolsCallJsonV1,
        4 => ActionCodecProfileV2::TableComputeV1,
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
        let fixed = match d.array().map_err(malformed)? {
            Some(3) => false,
            Some(4) => true,
            _ => return Err(BusinessCodecErrorV2::Malformed),
        };
        let name = d.str().map_err(malformed)?;
        let role = match d.u16().map_err(malformed)? {
            1 => BusinessFieldRoleV2::Resource,
            2 => BusinessFieldRoleV2::Destination,
            3 => BusinessFieldRoleV2::Magnitude,
            4 => BusinessFieldRoleV2::Payload,
            5 => BusinessFieldRoleV2::Parameter,
            6 => BusinessFieldRoleV2::Condition,
            7 => BusinessFieldRoleV2::CopyDestination,
            _ => return Err(BusinessCodecErrorV2::Unsupported),
        };
        let kind = match d.u16().map_err(malformed)? {
            1 => BusinessFieldTypeV2::Text,
            2 => BusinessFieldTypeV2::Unsigned,
            3 => BusinessFieldTypeV2::Boolean,
            4 => BusinessFieldTypeV2::TextList,
            _ => return Err(BusinessCodecErrorV2::Unsupported),
        };
        let field = BusinessFieldV2::new(name, role, kind)?;
        fields.push(if fixed {
            field.with_fixed(d.str().map_err(malformed)?)?
        } else {
            field
        });
    }
    let profile = BusinessProfileV2::new(
        codec, operation, target, credential, effect, magnitude, fields,
    )?;
    if d.position() != bytes.len() || encode_business_profile_v2(&profile)? != bytes {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    Ok(profile)
}
