//! Plain readable task-draft controls. No payload/request/quantity is invented
//! here. Both this projection and actual requests use the same field checks and
//! hash domains. A draft still needs active-descriptor resolution and independent
//! user authentication/approval before the issuer may grant any authority.
use super::*;

/// An owner-signed edge, not a value: field F takes the scalar the kernel
/// extracts, at dispatch, from the verified result of `source_clause` at `path`.
/// A compromised planner cannot forge this into a literal value, because a
/// derived control commits (below) under a domain no literal request produces.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResultDerivedControlV2 {
    source_clause: u64,
    path: Vec<String>,
    kind: BusinessFieldTypeV2,
    max_bytes: u16,
    compute: Option<ResultComputeV2>,
}

/// A computation the owner signs into a derived control: the kernel applies
/// it to the text it extracts at the signed path (a computed origin). The
/// operand is never a planner or model literal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResultComputeOpV2 {
    /// "YYYY-MM-DD HH:MM" plus `amount` minutes.
    AddMinutes = 1,
    /// "YYYY-MM-DD[ HH:MM]" plus `amount` days.
    AddDays = 2,
    /// A two-decimal amount plus `amount` hundredths, never negative.
    AddCents = 3,
}
impl ResultComputeOpV2 {
    pub const fn max_amount(self) -> i64 {
        match self {
            Self::AddMinutes => 527_040,
            Self::AddDays => 3_660,
            Self::AddCents => 1_000_000_000,
        }
    }
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::AddMinutes),
            2 => Some(Self::AddDays),
            3 => Some(Self::AddCents),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::AddMinutes => "add_minutes",
            Self::AddDays => "add_days",
            Self::AddCents => "add_cents",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResultComputeV2 {
    op: ResultComputeOpV2,
    amount: i64,
}
impl ResultComputeV2 {
    pub fn new(op: ResultComputeOpV2, amount: i64) -> Result<Self, BusinessCodecErrorV2> {
        if amount.unsigned_abs() > op.max_amount().unsigned_abs() {
            return Err(BusinessCodecErrorV2::Limit);
        }
        Ok(Self { op, amount })
    }
    pub fn op(&self) -> ResultComputeOpV2 {
        self.op
    }
    pub fn amount(&self) -> i64 {
        self.amount
    }
}
impl ResultDerivedControlV2 {
    pub fn new(
        source_clause: u64,
        path: Vec<String>,
        kind: BusinessFieldTypeV2,
        max_bytes: u16,
    ) -> Result<Self, BusinessCodecErrorV2> {
        if source_clause == 0
            || max_bytes == 0
            || path.len() > 16
            || path
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        Ok(Self {
            source_clause,
            path,
            kind,
            max_bytes,
            compute: None,
        })
    }
    /// A computed control: the extracted text, transformed by `compute`. Only
    /// a text field can be computed.
    pub fn with_compute(mut self, compute: ResultComputeV2) -> Result<Self, BusinessCodecErrorV2> {
        if self.kind != BusinessFieldTypeV2::Text {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        self.compute = Some(compute);
        Ok(self)
    }
    pub fn compute(&self) -> Option<ResultComputeV2> {
        self.compute
    }
    pub fn source_clause(&self) -> u64 {
        self.source_clause
    }
    pub fn path(&self) -> &[String] {
        &self.path
    }
    pub fn kind(&self) -> BusinessFieldTypeV2 {
        self.kind
    }
    pub fn max_bytes(&self) -> u16 {
        self.max_bytes
    }
    fn put<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
    ) -> Result<(), BusinessCodecErrorV2> {
        // A plain edge keeps its four-element encoding byte for byte; a
        // computed edge appends [op, amount].
        e.array(if self.compute.is_some() { 5 } else { 4 })
            .and_then(|e| e.u64(self.source_clause))
            .and_then(|e| e.array(self.path.len() as u64))
            .map_err(malformed)?;
        for segment in &self.path {
            e.str(segment).map_err(malformed)?;
        }
        e.u16(self.kind as u16)
            .and_then(|e| e.u16(self.max_bytes))
            .map_err(malformed)?;
        if let Some(compute) = self.compute {
            e.array(2)
                .and_then(|e| e.u16(compute.op as u16))
                .and_then(|e| e.i64(compute.amount))
                .map_err(malformed)?;
        }
        Ok(())
    }
    /// Canonical rule bytes, folded into the field's control digest.
    fn canonical(&self) -> Vec<u8> {
        let mut e = minicbor::Encoder::new(Vec::new());
        self.put(&mut e).expect("validated rule");
        e.into_writer()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BusinessControlsV2 {
    profile: BusinessProfileV2,
    values: BTreeMap<String, Json>,
    /// Result-derived control fields, disjoint from `values`. Empty for every
    /// exact-only control, whose encoding and digests stay byte-identical.
    derived: BTreeMap<String, ResultDerivedControlV2>,
}
impl std::fmt::Debug for BusinessControlsV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BusinessControlsV2")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}
impl BusinessControlsV2 {
    pub fn from_fields(
        profile: &BusinessProfileV2,
        fields: Vec<(String, BusinessValueV2)>,
    ) -> Result<Self, BusinessCodecErrorV2> {
        Self::from_map(profile, field_map(fields)?, BTreeMap::new())
    }
    pub fn from_fields_with_derived(
        profile: &BusinessProfileV2,
        fields: Vec<(String, BusinessValueV2)>,
        derived: BTreeMap<String, ResultDerivedControlV2>,
    ) -> Result<Self, BusinessCodecErrorV2> {
        Self::from_map(profile, field_map(fields)?, derived)
    }
    fn from_map(
        profile: &BusinessProfileV2,
        values: BTreeMap<String, Json>,
        derived: BTreeMap<String, ResultDerivedControlV2>,
    ) -> Result<Self, BusinessCodecErrorV2> {
        let controlled: Vec<_> = profile
            .fields
            .iter()
            .filter(|f| {
                !matches!(
                    f.role,
                    BusinessFieldRoleV2::Payload | BusinessFieldRoleV2::Magnitude
                )
            })
            .collect();
        // Exact and derived controls must partition exactly the controlled
        // fields: none omitted, none both, none unknown.
        if values.len() + derived.len() != controlled.len()
            || values.keys().any(|name| derived.contains_key(name))
        {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        for field in &controlled {
            if let Some(rule) = derived.get(&field.name) {
                // A derived control may not choose the payload (handled as the
                // whole prior result) and its type must match the field.
                if rule.kind != field.kind {
                    return Err(BusinessCodecErrorV2::Malformed);
                }
            } else {
                validate_field(
                    field,
                    values
                        .get(&field.name)
                        .ok_or(BusinessCodecErrorV2::Malformed)?,
                )?;
            }
        }
        let result = Self {
            profile: profile.clone(),
            values,
            derived,
        };
        if result.canonical_values_json().len() > MAX_BUSINESS_JSON_BYTES_V2 {
            return Err(BusinessCodecErrorV2::Limit);
        }
        Ok(result)
    }
    pub fn derived(&self) -> &BTreeMap<String, ResultDerivedControlV2> {
        &self.derived
    }
    pub fn profile(&self) -> &BusinessProfileV2 {
        &self.profile
    }
    pub fn resource(&self) -> &str {
        text_role(&self.profile, &self.values, BusinessFieldRoleV2::Resource)
    }
    pub fn destination(&self) -> &str {
        text_role(
            &self.profile,
            &self.values,
            BusinessFieldRoleV2::Destination,
        )
    }
    pub fn canonical_values_json(&self) -> Vec<u8> {
        Json::Object(self.values.clone()).canonical()
    }
    pub fn action_alternative(
        &self,
        descriptor: Digest32V2,
    ) -> Result<ActionAlternativeV2, BusinessCodecErrorV2> {
        ActionAlternativeV2::new(
            descriptor,
            self.profile.codec,
            self.profile.effect,
            resource_digest(&self.profile, &self.values, &self.derived),
            destination_digest(&self.profile, &self.values, &self.derived),
            parameters_digest(&self.profile, &self.values, &self.derived),
            if self.profile.magnitude == BusinessMagnitudeV2::Utf8PayloadBytes {
                MagnitudeUnitV2::Bytes
            } else {
                MagnitudeUnitV2::Count
            },
        )
        .map_err(malformed)
    }
}

pub(super) fn validate_field(
    field: &BusinessFieldV2,
    value: &Json,
) -> Result<(), BusinessCodecErrorV2> {
    match (field.kind, value) {
        // An empty parameter is an argument left unset: it carries no data.
        // A resource or destination text is never empty and at most 1 KB; a
        // parameter (a subject, a message, an extraction's context) may carry
        // up to MAX_PARAMETER_TEXT_BYTES_V2 under the same character rules.
        (BusinessFieldTypeV2::Text, Json::Text(s))
            if field.role == BusinessFieldRoleV2::Payload
                || control_text(s)
                || (field.role == BusinessFieldRoleV2::Parameter
                    && (s.is_empty() || parameter_text(s))) =>
        {
            Ok(())
        }
        // An empty list is exactly "no one" (an event without participants),
        // never a default: it may be a destination too.
        (BusinessFieldTypeV2::TextList, Json::Array(items))
            if items.len() <= MAX_TEXT_LIST_ITEMS_V2
                && items
                    .iter()
                    .all(|item| matches!(item, Json::Text(s) if control_text(s))) =>
        {
            Ok(())
        }
        (BusinessFieldTypeV2::Unsigned, Json::Unsigned(_))
        | (BusinessFieldTypeV2::Boolean, Json::Bool(_)) => Ok(()),
        _ => Err(BusinessCodecErrorV2::Malformed),
    }
}
pub(super) fn field_map(
    fields: Vec<(String, BusinessValueV2)>,
) -> Result<BTreeMap<String, Json>, BusinessCodecErrorV2> {
    if fields.len() > 32 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut result = BTreeMap::new();
    let mut size = 0usize;
    for (name, value) in fields {
        if !identifier(&name, 64) || result.contains_key(&name) {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        let value = match value {
            BusinessValueV2::Text(s) => {
                size = size
                    .checked_add(s.len())
                    .ok_or(BusinessCodecErrorV2::Limit)?;
                if size > MAX_BUSINESS_JSON_BYTES_V2 {
                    return Err(BusinessCodecErrorV2::Limit);
                }
                Json::Text(s)
            }
            BusinessValueV2::Unsigned(n) => Json::Unsigned(n),
            BusinessValueV2::Boolean(b) => Json::Bool(b),
            BusinessValueV2::TextList(items) => {
                if items.len() > MAX_TEXT_LIST_ITEMS_V2 {
                    return Err(BusinessCodecErrorV2::Limit);
                }
                for item in &items {
                    size = size
                        .checked_add(item.len())
                        .ok_or(BusinessCodecErrorV2::Limit)?;
                }
                if size > MAX_BUSINESS_JSON_BYTES_V2 {
                    return Err(BusinessCodecErrorV2::Limit);
                }
                Json::Array(items.into_iter().map(Json::Text).collect())
            }
        };
        result.insert(name, value);
    }
    Ok(result)
}
fn text_role<'a>(
    profile: &BusinessProfileV2,
    values: &'a BTreeMap<String, Json>,
    role: BusinessFieldRoleV2,
) -> &'a str {
    let field = profile
        .fields
        .iter()
        .find(|f| f.role == role)
        .expect("validated role");
    values[&field.name].text().expect("validated text")
}
fn role_field<'profile>(
    profile: &'profile BusinessProfileV2,
    role: BusinessFieldRoleV2,
) -> &'profile BusinessFieldV2 {
    profile
        .fields
        .iter()
        .find(|f| f.role == role)
        .expect("validated role")
}
fn text_role_digest(
    profile: &BusinessProfileV2,
    values: &BTreeMap<String, Json>,
    derived: &BTreeMap<String, ResultDerivedControlV2>,
    role: BusinessFieldRoleV2,
    exact_domain: &[u8],
    derived_domain: &[u8],
) -> Digest32V2 {
    let field = role_field(profile, role);
    match derived.get(&field.name) {
        // A derived control commits to its rule under a distinct domain, so a
        // literal request (which carries no rule) can never collide with it.
        Some(rule) => hash(derived_domain, &[profile.target.as_bytes(), &rule.canonical()]),
        None => match &values[&field.name] {
            // A destination list commits to its canonical JSON array under a
            // list domain, so no list collides with a single text.
            Json::Array(_) => hash(
                &list_domain(exact_domain),
                &[profile.target.as_bytes(), &values[&field.name].canonical()],
            ),
            value => hash(
                exact_domain,
                &[
                    profile.target.as_bytes(),
                    value.text().expect("validated text").as_bytes(),
                ],
            ),
        },
    }
}
/// `SAVANA_BUSINESS_X_V2_SCHEMA1\0` -> `SAVANA_BUSINESS_X_LIST_V2_SCHEMA1\0`.
fn list_domain(exact_domain: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(exact_domain).expect("ascii domain");
    text.replacen("_V2_SCHEMA1", "_LIST_V2_SCHEMA1", 1).into_bytes()
}
pub(super) fn resource_digest(
    profile: &BusinessProfileV2,
    values: &BTreeMap<String, Json>,
    derived: &BTreeMap<String, ResultDerivedControlV2>,
) -> Digest32V2 {
    text_role_digest(
        profile,
        values,
        derived,
        BusinessFieldRoleV2::Resource,
        b"SAVANA_BUSINESS_RESOURCE_V2_SCHEMA1\0",
        b"SAVANA_BUSINESS_RESOURCE_DERIVED_V2_SCHEMA1\0",
    )
}
pub(super) fn destination_digest(
    profile: &BusinessProfileV2,
    values: &BTreeMap<String, Json>,
    derived: &BTreeMap<String, ResultDerivedControlV2>,
) -> Digest32V2 {
    text_role_digest(
        profile,
        values,
        derived,
        BusinessFieldRoleV2::Destination,
        b"SAVANA_BUSINESS_DESTINATION_V2_SCHEMA1\0",
        b"SAVANA_BUSINESS_DESTINATION_DERIVED_V2_SCHEMA1\0",
    )
}
pub(super) fn parameters_digest(
    profile: &BusinessProfileV2,
    values: &BTreeMap<String, Json>,
    derived: &BTreeMap<String, ResultDerivedControlV2>,
) -> Digest32V2 {
    // profile.fields are strictly name-sorted, so Parameter fields visit in
    // canonical (name) order for both the exact map and the derived rules.
    let exact: BTreeMap<String, Json> = profile
        .fields
        .iter()
        .filter(|f| f.role == BusinessFieldRoleV2::Parameter && !derived.contains_key(&f.name))
        .map(|f| (f.name.clone(), values[&f.name].clone()))
        .collect();
    let derived_params: Vec<(&String, &ResultDerivedControlV2)> = profile
        .fields
        .iter()
        .filter(|f| f.role == BusinessFieldRoleV2::Parameter)
        .filter_map(|f| derived.get(&f.name).map(|rule| (&f.name, rule)))
        .collect();
    let exact_json = Json::Object(exact).canonical();
    if derived_params.is_empty() {
        hash(b"SAVANA_BUSINESS_PARAMETERS_V2_SCHEMA1\0", &[&exact_json])
    } else {
        let mut rules = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut rules);
        encoder.array(derived_params.len() as u64).expect("bounded");
        for (name, rule) in derived_params {
            encoder.str(name).expect("bounded");
            rule.put(&mut encoder).expect("validated rule");
        }
        hash(
            b"SAVANA_BUSINESS_PARAMETERS_V2_SCHEMA2\0",
            &[&exact_json, &rules],
        )
    }
}

pub fn encode_business_controls_v2(
    value: &BusinessControlsV2,
) -> Result<Vec<u8>, BusinessCodecErrorV2> {
    let mut e = minicbor::Encoder::new(Vec::new());
    if value.derived.is_empty() {
        // Exact-only controls keep the byte-identical v1 shape [1, profile, json].
        e.array(3)
            .and_then(|e| e.u16(1))
            .and_then(|e| {
                e.bytes(&encode_business_profile_v2(&value.profile).expect("validated profile"))
            })
            .and_then(|e| e.bytes(&value.canonical_values_json()))
            .map_err(malformed)?;
    } else {
        e.array(4)
            .and_then(|e| e.u16(2))
            .and_then(|e| {
                e.bytes(&encode_business_profile_v2(&value.profile).expect("validated profile"))
            })
            .and_then(|e| e.bytes(&value.canonical_values_json()))
            .and_then(|e| e.array(value.derived.len() as u64))
            .map_err(malformed)?;
        // BTreeMap iterates name-sorted, so the encoding is canonical.
        for (name, rule) in &value.derived {
            e.str(name).map_err(malformed)?;
            rule.put(&mut e)?;
        }
    }
    Ok(e.into_writer())
}
pub fn decode_business_controls_v2(
    bytes: &[u8],
) -> Result<BusinessControlsV2, BusinessCodecErrorV2> {
    // Room for up to 32 derived rules (name + 16 path segments of 128 bytes each).
    if bytes.len() > MAX_BUSINESS_PROFILE_BYTES_V2 + MAX_BUSINESS_JSON_BYTES_V2 + 128 + 96 * 1024 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut d = minicbor::Decoder::new(bytes);
    // Exact-only controls are [1, profile, json]; controls with result-derived
    // fields are [2, profile, json, {name -> rule}] in name-sorted order.
    let (length, discriminant) = (d.array().map_err(malformed)?, d.u16().map_err(malformed)?);
    if (length, discriminant) != (Some(3), 1) && (length, discriminant) != (Some(4), 2) {
        return Err(BusinessCodecErrorV2::Unsupported);
    }
    let profile = decode_business_profile_v2(d.bytes().map_err(malformed)?)?;
    let Json::Object(values) = business_json::parse(d.bytes().map_err(malformed)?)? else {
        return Err(BusinessCodecErrorV2::Malformed);
    };
    let mut derived = BTreeMap::new();
    if discriminant == 2 {
        let count = d.array().map_err(malformed)?.ok_or(BusinessCodecErrorV2::Malformed)?;
        if count == 0 || count > 32 {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        for _ in 0..count {
            let name = d.str().map_err(malformed)?.to_owned();
            let rule = decode_result_derived_control(&mut d)?;
            if derived.insert(name, rule).is_some() {
                return Err(BusinessCodecErrorV2::Malformed);
            }
        }
    }
    let result = BusinessControlsV2::from_map(&profile, values, derived)?;
    if d.position() != bytes.len() || encode_business_controls_v2(&result)? != bytes {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    Ok(result)
}

/// Canonical bytes of one step's result-derived rule set, in field-name order.
/// Carried with a sealed task execution payload so every verifier can rebuild
/// the owner-signed alternative the kernel matched at G4.
pub fn encode_result_derived_controls_v2(
    derived: &BTreeMap<String, ResultDerivedControlV2>,
) -> Result<Vec<u8>, BusinessCodecErrorV2> {
    if derived.len() > 32 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(derived.len() as u64).map_err(malformed)?;
    for (name, rule) in derived {
        e.array(2).and_then(|e| e.str(name)).map_err(malformed)?;
        rule.put(&mut e)?;
    }
    Ok(e.into_writer())
}

/// Strict inverse of [`encode_result_derived_controls_v2`]: bounded, names
/// strictly ascending, every rule re-validated, no trailing bytes.
pub fn decode_result_derived_controls_v2(
    bytes: &[u8],
) -> Result<BTreeMap<String, ResultDerivedControlV2>, BusinessCodecErrorV2> {
    let mut d = minicbor::Decoder::new(bytes);
    let count = d.array().map_err(malformed)?.ok_or(BusinessCodecErrorV2::Malformed)?;
    if count > 32 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut out = BTreeMap::new();
    let mut last: Option<String> = None;
    for _ in 0..count {
        if d.array().map_err(malformed)? != Some(2) {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        let name = d.str().map_err(malformed)?.to_owned();
        if name.is_empty() || name.len() > 64 || last.as_ref().is_some_and(|l| *l >= name) {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        let rule = decode_result_derived_control(&mut d)?;
        last = Some(name.clone());
        out.insert(name, rule);
    }
    if d.position() != bytes.len() {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    Ok(out)
}

fn decode_result_derived_control(
    d: &mut minicbor::Decoder<'_>,
) -> Result<ResultDerivedControlV2, BusinessCodecErrorV2> {
    let length = d.array().map_err(malformed)?;
    if length != Some(4) && length != Some(5) {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    let source_clause = d.u64().map_err(malformed)?;
    let segments = d.array().map_err(malformed)?.ok_or(BusinessCodecErrorV2::Malformed)?;
    if segments > 16 {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    let mut path = Vec::new();
    for _ in 0..segments {
        path.push(d.str().map_err(malformed)?.to_owned());
    }
    let kind = match d.u16().map_err(malformed)? {
        1 => BusinessFieldTypeV2::Text,
        2 => BusinessFieldTypeV2::Unsigned,
        3 => BusinessFieldTypeV2::Boolean,
        4 => BusinessFieldTypeV2::TextList,
        _ => return Err(BusinessCodecErrorV2::Unsupported),
    };
    let max_bytes = d.u16().map_err(malformed)?;
    let rule = ResultDerivedControlV2::new(source_clause, path, kind, max_bytes)?;
    if length == Some(4) {
        return Ok(rule);
    }
    if d.array().map_err(malformed)? != Some(2) {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    let op = ResultComputeOpV2::from_code(d.u16().map_err(malformed)?)
        .ok_or(BusinessCodecErrorV2::Unsupported)?;
    rule.with_compute(ResultComputeV2::new(op, d.i64().map_err(malformed)?)?)
}
