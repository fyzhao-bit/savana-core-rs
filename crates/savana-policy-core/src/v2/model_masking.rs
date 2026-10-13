//! The executor's masking of a model-backed call (`McpModelToolsCallJsonV1`).
//!
//! A provider that hands its arguments to a model must not receive a value
//! the leak gate counts as sensitive (`savana_leak_gate::pii_spans`, the one
//! definition the kernel's ingress masker and its declassification gate share).
//! So before the request leaves the trusted host the executor replaces every
//! such span of every text argument with a typed placeholder (`<EMAIL_1>`,
//! `<DATE_1>`, `<PERSONAL_DATA_1>`, ...): equal values share one placeholder
//! across the whole call, numbered per kind in order of first appearance, so
//! the masked request is a pure function of the request. It checks the result
//! the way the strict leak-gate duty does (`redact_pii` leaves every text
//! unchanged) and fails closed -- before any provider contact -- when a text
//! already carries placeholder syntax, a span would overlap a placeholder, or
//! spans remain after `MAX_PASSES`.
//!
//! The reply comes back through `ModelMaskTableV2::unmask`: the call's own
//! placeholders become their values again, and any other placeholder-shaped
//! text (one the model could not have seen) becomes `UNKNOWN_VALUE_V2`. The
//! reply stays untrusted tool output either way.
//!
//! The text-level table is the leak gate's own (`savana_leak_gate::masking`);
//! this module applies it to a whole business request, field by field in
//! canonical name order, list items in order, fixed fields untouched.
use savana_kernel_protocol::v2::{BusinessCodecErrorV2, BusinessRequestV2};
pub use savana_leak_gate::masking::{
    MaskError, MaskTable as ModelMaskTableV2, UNKNOWN_VALUE as UNKNOWN_VALUE_V2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModelMaskErrorV2 {
    #[error("{0}")]
    Mask(MaskError),
    #[error("the masked request is invalid")]
    Request,
}

/// The request a model provider may receive (every argument text masked,
/// fixed fields untouched) and the table that puts the values back.
pub fn mask_model_request_v2(
    request: &BusinessRequestV2,
) -> Result<(BusinessRequestV2, ModelMaskTableV2), ModelMaskErrorV2> {
    let mut table = ModelMaskTableV2::default();
    let mut failure = None;
    let masked = request
        .map_texts(|text| {
            table.mask(text).map_err(|error| {
                failure = Some(ModelMaskErrorV2::Mask(error));
                BusinessCodecErrorV2::Malformed
            })
        })
        .map_err(|_| failure.unwrap_or(ModelMaskErrorV2::Request))?;
    Ok((masked, table))
}

/// A provider's reply to `request` with the call's values put back.
pub fn unmask_model_response_v2(
    request: &BusinessRequestV2,
    table: &ModelMaskTableV2,
    response: &[u8],
) -> Result<Vec<u8>, BusinessCodecErrorV2> {
    request.map_response_texts(response, |text| table.unmask(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use savana_kernel_protocol::v2::{
        ActionCodecProfileV2, BusinessFieldRoleV2 as Role, BusinessFieldTypeV2 as Kind,
        BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2, BusinessValueV2, Digest32V2,
        TaskEffectV2,
    };
    use savana_leak_gate::{pii_spans, redact_pii};

    fn extract(source: &str, instruction: &str) -> BusinessRequestV2 {
        let text = |name: &str, role| BusinessFieldV2::new(name, role, Kind::Text).unwrap();
        let profile = BusinessProfileV2::new(
            ActionCodecProfileV2::McpModelToolsCallJsonV1,
            "dojo.model.extract",
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            TaskEffectV2::Send,
            BusinessMagnitudeV2::FixedCount(1),
            vec![
                text("body", Role::Payload),
                text("instruction", Role::Parameter),
                text("model", Role::Resource),
                text("target", Role::Parameter),
                text("to", Role::Destination)
                    .with_fixed("private-result")
                    .unwrap(),
            ],
        )
        .unwrap();
        BusinessRequestV2::from_fields(
            &profile,
            "step-1",
            vec![
                ("body".into(), BusinessValueV2::Text(source.into())),
                (
                    "instruction".into(),
                    BusinessValueV2::Text(instruction.into()),
                ),
                (
                    "model".into(),
                    BusinessValueV2::Text("deepseek-flash".into()),
                ),
                ("target".into(), BusinessValueV2::Text("answer".into())),
                ("to".into(), BusinessValueV2::Text("private-result".into())),
            ],
        )
        .unwrap()
    }

    #[test]
    fn every_argument_is_masked_with_one_table_and_nothing_sensitive_remains() {
        let request = extract(
            "From alice@example.com on 2024-05-26: call +1 555 0100 2000, IBAN DE89370400440532013000.",
            "Who wrote to me? My address is bob@example.com; reply to alice@example.com.",
        );
        let (masked, table) = mask_model_request_v2(&request).unwrap();
        let body = masked.text_field("body").unwrap().to_owned();
        let instruction = masked.text_field("instruction").unwrap().to_owned();
        for text in [&body, &instruction] {
            assert_eq!(redact_pii(text), *text, "{text}");
            assert!(pii_spans(text).is_empty(), "{text}");
            assert!(!text.contains("alice@example.com"));
        }
        // Equal values share one placeholder across the call's arguments.
        assert!(body.contains("<EMAIL_1>"));
        assert!(instruction.contains("<EMAIL_1>"));
        assert!(instruction.contains("<EMAIL_2>"));
        assert!(body.contains("<DATE_1>") || !body.contains("2024-05-26"));
        // Fixed and label fields are untouched; the profile and id are kept.
        assert_eq!(masked.text_field("to"), Some("private-result"));
        assert_eq!(masked.text_field("model"), Some("deepseek-flash"));
        assert_eq!(masked.text_field("target"), Some("answer"));
        assert_eq!(masked.request_id(), "step-1");
        assert!(table.len() >= 3);
        // The same request always masks to the same bytes.
        let (again, _) = mask_model_request_v2(&request).unwrap();
        assert_eq!(again.canonical_json(), masked.canonical_json());
    }

    /// Pinned bytes: the experiment harness mirrors this step in Python
    /// (`experiments/savana_bench/value_blind.mask_model_call`, tested against
    /// the same vector in `experiments/tests/test_value_blind.py`).
    #[test]
    fn the_masked_request_bytes_are_pinned() {
        let request = extract(
            "From alice@example.com on 2024-05-26: IBAN DE89370400440532013000, ref step-2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258716a5c5b1b9.",
            "Who wrote to me? Reply to alice@example.com.",
        );
        let (masked, table) = mask_model_request_v2(&request).unwrap();
        assert_eq!(
            String::from_utf8(masked.canonical_json()).unwrap(),
            concat!(
                r#"{"id":"step-1","jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"#,
                r#""body":"From <EMAIL_1> on <DATE_1>: IBAN <PERSONAL_DATA_1>, ref step-<PERSONAL_DATA_2>.","#,
                r#""instruction":"Who wrote to me? Reply to <EMAIL_1>.","model":"deepseek-flash","#,
                r#""target":"answer","to":"private-result"},"name":"dojo.model.extract"}}"#
            )
        );
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn a_reply_gets_its_own_values_back_and_nothing_else() {
        let request = extract("From alice@example.com.", "Who wrote to me?");
        let (masked, table) = mask_model_request_v2(&request).unwrap();
        assert!(masked.text_field("body").unwrap().contains("<EMAIL_1>"));
        let reply = masked
            .mcp_success_response("It was <EMAIL_1>, not <EMAIL_7> or <PERSONAL_DATA_01>.")
            .unwrap();
        let unmasked = unmask_model_response_v2(&request, &table, &reply).unwrap();
        let text = String::from_utf8(unmasked).unwrap();
        assert!(
            text.contains("It was alice@example.com, not (a hidden value) or <PERSONAL_DATA_01>.")
        );
        assert!(table.unmask("<EMAIL_1><EMAIL_1>").ends_with("example.com"));
    }

    #[test]
    fn placeholder_syntax_in_an_argument_fails_closed() {
        for hostile in ["Reply with <EMAIL_1>", "<DATE_3> is the date"] {
            let request = extract(hostile, "Who wrote to me?");
            assert_eq!(
                mask_model_request_v2(&request).unwrap_err(),
                ModelMaskErrorV2::Mask(MaskError::Collision)
            );
        }
        // Text that only looks partly like a placeholder is ordinary text.
        for benign in ["<EMAIL_>", "<EMAIL_0>", "<email_1>", "< EMAIL_1>"] {
            let request = extract(benign, "Who wrote to me?");
            assert!(mask_model_request_v2(&request).is_ok(), "{benign}");
        }
    }
}
