//! Plain readable task-draft controls. No payload/request/quantity is invented
//! here. Both this projection and actual requests use the same field checks and
//! hash domains. A draft still needs active-descriptor resolution and independent
//! user authentication/approval before the issuer may grant any authority.
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub struct BusinessControlsV2 {
    profile: BusinessProfileV2,
    values: BTreeMap<String, Json>,
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
        Self::from_map(profile, field_map(fields)?)
    }
    fn from_map(
        profile: &BusinessProfileV2,
        values: BTreeMap<String, Json>,
    ) -> Result<Self, BusinessCodecErrorV2> {
        let fields: Vec<_> = profile
            .fields
            .iter()
            .filter(|f| {
                !matches!(
                    f.role,
                    BusinessFieldRoleV2::Payload | BusinessFieldRoleV2::Magnitude
                )
            })
            .collect();
        if values.len() != fields.len() {
            return Err(BusinessCodecErrorV2::Malformed);
        }
        for field in fields {
            validate_field(
                field,
                values
                    .get(&field.name)
                    .ok_or(BusinessCodecErrorV2::Malformed)?,
            )?;
        }
        let result = Self {
            profile: profile.clone(),
            values,
        };
        if result.canonical_values_json().len() > MAX_BUSINESS_JSON_BYTES_V2 {
            return Err(BusinessCodecErrorV2::Limit);
        }
        Ok(result)
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
            resource_digest(&self.profile, &self.values),
            destination_digest(&self.profile, &self.values),
            parameters_digest(&self.profile, &self.values),
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
        (BusinessFieldTypeV2::Text, Json::Text(s))
            if field.role == BusinessFieldRoleV2::Payload || control_text(s) =>
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
pub(super) fn resource_digest(
    profile: &BusinessProfileV2,
    values: &BTreeMap<String, Json>,
) -> Digest32V2 {
    hash(
        b"SAVANA_BUSINESS_RESOURCE_V2_SCHEMA1\0",
        &[
            profile.target.as_bytes(),
            text_role(profile, values, BusinessFieldRoleV2::Resource).as_bytes(),
        ],
    )
}
pub(super) fn destination_digest(
    profile: &BusinessProfileV2,
    values: &BTreeMap<String, Json>,
) -> Digest32V2 {
    hash(
        b"SAVANA_BUSINESS_DESTINATION_V2_SCHEMA1\0",
        &[
            profile.target.as_bytes(),
            text_role(profile, values, BusinessFieldRoleV2::Destination).as_bytes(),
        ],
    )
}
pub(super) fn parameters_digest(
    profile: &BusinessProfileV2,
    values: &BTreeMap<String, Json>,
) -> Digest32V2 {
    let parameters = profile
        .fields
        .iter()
        .filter(|f| f.role == BusinessFieldRoleV2::Parameter)
        .map(|f| (f.name.clone(), values[&f.name].clone()))
        .collect();
    hash(
        b"SAVANA_BUSINESS_PARAMETERS_V2_SCHEMA1\0",
        &[&Json::Object(parameters).canonical()],
    )
}

pub fn encode_business_controls_v2(
    value: &BusinessControlsV2,
) -> Result<Vec<u8>, BusinessCodecErrorV2> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.u16(1))
        .and_then(|e| {
            e.bytes(&encode_business_profile_v2(&value.profile).expect("validated profile"))
        })
        .and_then(|e| e.bytes(&value.canonical_values_json()))
        .map_err(malformed)?;
    Ok(e.into_writer())
}
pub fn decode_business_controls_v2(
    bytes: &[u8],
) -> Result<BusinessControlsV2, BusinessCodecErrorV2> {
    if bytes.len() > MAX_BUSINESS_PROFILE_BYTES_V2 + MAX_BUSINESS_JSON_BYTES_V2 + 128 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(malformed)? != Some(3) || d.u16().map_err(malformed)? != 1 {
        return Err(BusinessCodecErrorV2::Unsupported);
    }
    let profile = decode_business_profile_v2(d.bytes().map_err(malformed)?)?;
    let Json::Object(values) = business_json::parse(d.bytes().map_err(malformed)?)? else {
        return Err(BusinessCodecErrorV2::Malformed);
    };
    let result = BusinessControlsV2::from_map(&profile, values)?;
    if d.position() != bytes.len() || encode_business_controls_v2(&result)? != bytes {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    Ok(result)
}
