use crate::{runtime::Entry, Error, RootRule};
use savana_kernel_protocol::v2::{
    ActionCodecProfileV2, BusinessFieldRoleV2 as Role, BusinessFieldTypeV2 as Kind,
    BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2, BusinessRequestV2,
    BusinessValueV2 as Value, Digest32V2, TaskEffectV2,
};

/// A single reviewed application profile. The provider contract must enforce
/// `order_version` and interpret success as acceptance of this exact request.
/// This is not a generic email/MCP adapter and performs no network I/O.
pub fn invoice_profile(root: &RootRule) -> Result<BusinessProfileV2, Error> {
    let field = |n, r, k| BusinessFieldV2::new(n, r, k).map_err(|_| Error::Malformed);
    BusinessProfileV2::new(
        ActionCodecProfileV2::FixedJsonPostV1,
        "/invoice/request",
        Digest32V2::new(root.executor_target),
        Digest32V2::new(root.executor_credential),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::FixedCount(1),
        vec![
            field("body", Role::Payload, Kind::Text)?,
            field("merchant", Role::Parameter, Kind::Text)?,
            field("order", Role::Resource, Kind::Text)?,
            field("order_version", Role::Parameter, Kind::Unsigned)?,
            field("recipient", Role::Destination, Kind::Text)?,
        ],
    )
    .map_err(|_| Error::Malformed)
}

pub(crate) fn request(root: &RootRule, entry: &Entry) -> Result<BusinessRequestV2, Error> {
    BusinessRequestV2::from_fields(
        &invoice_profile(root)?,
        &entry.execution,
        vec![
            (
                "body".into(),
                Value::Text(format!(
                    "Please provide the invoice for order {}.",
                    entry.order
                )),
            ),
            ("merchant".into(), Value::Text(entry.merchant.clone())),
            ("order".into(), Value::Text(entry.order.clone())),
            ("order_version".into(), Value::Unsigned(entry.version)),
            ("recipient".into(), Value::Text(entry.contact.clone())),
        ],
    )
    .map_err(|_| Error::Malformed)
}
