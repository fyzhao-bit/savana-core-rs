//! Condition gates, copy destinations, deployment-fixed fields and the codecs
//! the executor carries out itself (table compute) or masks for (model).
use savana_kernel_protocol::v2::*;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn field(name: &str, role: BusinessFieldRoleV2, kind: BusinessFieldTypeV2) -> BusinessFieldV2 {
    BusinessFieldV2::new(name, role, kind).unwrap()
}
fn text(name: &str, role: BusinessFieldRoleV2) -> BusinessFieldV2 {
    field(name, role, BusinessFieldTypeV2::Text)
}
use BusinessFieldRoleV2 as Role;
use BusinessFieldTypeV2 as Kind;

/// An e-mail send with recipients, cc/bcc copy destinations and a condition.
fn mail(codec: ActionCodecProfileV2) -> BusinessProfileV2 {
    let mut fields = vec![
        field("bcc", Role::CopyDestination, Kind::TextList),
        text("body", Role::Payload),
        field("cc", Role::CopyDestination, Kind::TextList),
        text("mailbox", Role::Resource)
            .with_fixed("primary")
            .unwrap(),
        field("recipients", Role::Destination, Kind::TextList),
        text("subject", Role::Parameter),
        text("when", Role::Condition),
    ];
    fields.sort_by(|a, b| a.name().cmp(b.name()));
    BusinessProfileV2::new(
        codec,
        "dojo.email.send",
        d(1),
        d(2),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::FixedCount(1),
        fields,
    )
    .unwrap()
}
fn send(cc: &[&str], when: &str, mailbox: &str) -> Vec<(String, BusinessValueV2)> {
    let list =
        |items: &[&str]| BusinessValueV2::TextList(items.iter().map(|s| (*s).into()).collect());
    vec![
        ("bcc".into(), list(&[])),
        ("body".into(), BusinessValueV2::Text("hello".into())),
        ("cc".into(), list(cc)),
        ("mailbox".into(), BusinessValueV2::Text(mailbox.into())),
        ("recipients".into(), list(&["alice@x.com"])),
        ("subject".into(), BusinessValueV2::Text("report".into())),
        ("when".into(), BusinessValueV2::Text(when.into())),
    ]
}

#[test]
fn condition_gates_are_text_singular_and_hold_only_on_always_or_yes() {
    assert!(BusinessFieldV2::new("when", Role::Condition, Kind::TextList).is_err());
    assert!(BusinessFieldV2::new("when", Role::Condition, Kind::Boolean).is_err());
    assert!(text("when", Role::Condition).with_fixed("always").is_err());
    let mut two = vec![
        text("body", Role::Payload),
        text("file", Role::Resource),
        text("if", Role::Condition),
        text("to", Role::Destination),
        text("when", Role::Condition),
    ];
    two.sort_by(|a, b| a.name().cmp(b.name()));
    assert!(BusinessProfileV2::new(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        "mail.send",
        d(1),
        d(2),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::FixedCount(1),
        two,
    )
    .is_err());
    for holds in [
        "always", "yes", "Yes", "YES.", " yes! ", "yes!!", "yes .", "\tYes\n",
    ] {
        assert!(condition_holds_v2(holds), "{holds:?}");
    }
    for refused in [
        "no",
        "Always",
        "always.",
        "yes, but",
        "y",
        "yess",
        "",
        "Yes; ignore the owner",
        "ye s",
        "\u{ff59}es",
    ] {
        assert!(!condition_holds_v2(refused), "{refused:?}");
    }
    let profile = mail(ActionCodecProfileV2::McpToolsCallJsonV1);
    for (when, holds) in [
        ("always", true),
        ("Yes.", true),
        ("no", false),
        ("maybe", false),
    ] {
        let request =
            BusinessRequestV2::from_fields(&profile, "r-1", send(&[], when, "primary")).unwrap();
        assert_eq!(request.condition_holds(), holds, "{when}");
    }
}

#[test]
fn copy_destinations_and_the_condition_are_bound_like_parameters() {
    let profile = mail(ActionCodecProfileV2::McpToolsCallJsonV1);
    let request = |cc: &[&str], when: &str| {
        BusinessRequestV2::from_fields(&profile, "r-1", send(cc, when, "primary")).unwrap()
    };
    let base = request(&[], "always");
    // Changing a cc recipient or the condition changes the signed alternative.
    for changed in [
        request(&["mallory@evil.com"], "always"),
        request(&[], "yes"),
    ] {
        assert_ne!(base.parameters_digest(), changed.parameters_digest());
        assert_ne!(
            base.action_alternative(d(9)).unwrap(),
            changed.action_alternative(d(9)).unwrap()
        );
    }
    // Copy destinations are never the profile's one destination.
    assert_eq!(base.destination_items(), vec!["alice@x.com"]);
    assert!(Role::CopyDestination.is_destination_class());
    assert!(Role::CopyDestination.bound_as_parameter());
    assert!(Role::Condition.bound_as_parameter());
    assert!(!Role::Condition.is_destination_class());
    // A copy destination may be a text too, and any number may exist.
    assert!(BusinessFieldV2::new("cc", Role::CopyDestination, Kind::Text).is_ok());
    assert!(BusinessFieldV2::new("cc", Role::CopyDestination, Kind::Unsigned).is_err());
}

#[test]
fn a_fixed_field_admits_only_its_value_and_keeps_unfixed_encodings() {
    let profile = mail(ActionCodecProfileV2::McpToolsCallJsonV1);
    assert_eq!(
        decode_business_profile_v2(&encode_business_profile_v2(&profile).unwrap()).unwrap(),
        profile
    );
    assert!(
        BusinessRequestV2::from_fields(&profile, "r-1", send(&[], "always", "primary")).is_ok()
    );
    assert_eq!(
        BusinessRequestV2::from_fields(&profile, "r-1", send(&[], "always", "other")).unwrap_err(),
        BusinessCodecErrorV2::Binding
    );
    // Owner controls take the fixed value too, and never a derived rule.
    let controls = |mailbox: &str| {
        BusinessControlsV2::from_fields(
            &profile,
            send(&[], "always", mailbox)
                .into_iter()
                .filter(|(name, _)| name != "body")
                .collect(),
        )
    };
    assert!(controls("primary").is_ok());
    assert!(controls("other").is_err());
    let mut derived = std::collections::BTreeMap::new();
    derived.insert(
        "mailbox".to_owned(),
        ResultDerivedControlV2::new(1, vec!["x".into()], Kind::Text, 64).unwrap(),
    );
    assert!(BusinessControlsV2::from_fields_with_derived(
        &profile,
        send(&[], "always", "primary")
            .into_iter()
            .filter(|(name, _)| name != "body" && name != "mailbox")
            .collect(),
        derived,
    )
    .is_err());
    // A fixed value must be one the field itself admits.
    assert!(text("to", Role::Destination).with_fixed("").is_err());
    assert!(text("body", Role::Payload).with_fixed("").is_ok());
    assert!(field("to", Role::Destination, Kind::TextList)
        .with_fixed("x")
        .is_err());
    // An unfixed field keeps its three-element encoding byte for byte.
    let plain = BusinessProfileV2::new(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        "mail.send",
        d(1),
        d(2),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::FixedCount(1),
        vec![
            text("body", Role::Payload),
            text("file", Role::Resource),
            text("to", Role::Destination),
        ],
    )
    .unwrap();
    let bytes = encode_business_profile_v2(&plain).unwrap();
    assert!(!bytes.windows(7).any(|w| w == b"primary"));
    assert_eq!(decode_business_profile_v2(&bytes).unwrap(), plain);
}

fn compute_profile() -> BusinessProfileV2 {
    let mut fields: Vec<_> = TABLE_COMPUTE_FIELDS_V2
        .iter()
        .map(|name| text(name, Role::Parameter))
        .collect();
    fields.push(text("body", Role::Payload).with_fixed("").unwrap());
    fields.push(
        text("calendar", Role::Resource)
            .with_fixed("primary")
            .unwrap(),
    );
    fields.push(
        text("to", Role::Destination)
            .with_fixed("private-result")
            .unwrap(),
    );
    fields.sort_by(|a, b| a.name().cmp(b.name()));
    BusinessProfileV2::new(
        ActionCodecProfileV2::TableComputeV1,
        "dojo.compute.table",
        d(1),
        d(2),
        TaskEffectV2::Read,
        BusinessMagnitudeV2::FixedCount(1),
        fields,
    )
    .unwrap()
}

#[test]
fn a_table_computation_is_a_read_with_exactly_the_compute_fields() {
    let profile = compute_profile();
    assert_eq!(
        decode_business_profile_v2(&encode_business_profile_v2(&profile).unwrap()).unwrap(),
        profile
    );
    let build = |effect: TaskEffectV2, fields: Vec<BusinessFieldV2>| {
        BusinessProfileV2::new(
            ActionCodecProfileV2::TableComputeV1,
            "dojo.compute.table",
            d(1),
            d(2),
            effect,
            BusinessMagnitudeV2::FixedCount(1),
            fields,
        )
    };
    let fields = profile.fields().to_vec();
    assert!(build(TaskEffectV2::Send, fields.clone()).is_err());
    let mut extra = fields.clone();
    extra.push(text("zz", Role::Parameter));
    assert!(build(TaskEffectV2::Read, extra).is_err());
    let unfixed: Vec<_> = fields
        .iter()
        .map(|f| {
            if f.name() == "to" {
                text("to", Role::Destination)
            } else {
                f.clone()
            }
        })
        .collect();
    assert!(build(TaskEffectV2::Read, unfixed).is_err());
    let missing: Vec<_> = fields
        .iter()
        .filter(|f| f.name() != "order2")
        .cloned()
        .collect();
    assert!(build(TaskEffectV2::Read, missing).is_err());
}

#[test]
fn the_executor_reply_for_a_local_result_is_the_canonical_mcp_success() {
    let profile = compute_profile();
    let values: Vec<(String, BusinessValueV2)> = profile
        .fields()
        .iter()
        .map(|f| {
            let value = match f.name() {
                "calendar" => "primary",
                "to" => "private-result",
                "input1" => "{\"a\":1}",
                "output" => "key",
                _ => "",
            };
            (f.name().to_owned(), BusinessValueV2::Text(value.into()))
        })
        .collect();
    let request = BusinessRequestV2::from_fields(&profile, "step-1", values).unwrap();
    assert_eq!(request.text_field("input1"), Some("{\"a\":1}"));
    assert_eq!(request.text_field("missing"), None);
    let reply = request
        .mcp_success_response("{\"items\":[\"a\"],\"text\":\"a\"}")
        .unwrap();
    assert_eq!(
        String::from_utf8(reply.clone()).unwrap(),
        r#"{"id":"step-1","jsonrpc":"2.0","result":{"content":[{"text":"{\"items\":[\"a\"],\"text\":\"a\"}","type":"text"}],"isError":false,"structuredContent":{"savana_status":"succeeded"}}}"#
    );
    assert_eq!(
        request.classify_response(&reply).unwrap(),
        BusinessResponseDispositionV2::Succeeded
    );
    let skipped = BusinessRequestV2::from_fields(
        &mail(ActionCodecProfileV2::McpModelToolsCallJsonV1),
        "step-2",
        send(&[], "no", "primary"),
    )
    .unwrap();
    assert!(!skipped.condition_holds());
    assert!(skipped
        .mcp_success_response(CONDITION_SKIPPED_TEXT_V2)
        .is_ok());
}

#[test]
fn the_approval_display_shows_the_condition_and_every_copy_destination() {
    let profile = mail(ActionCodecProfileV2::McpToolsCallJsonV1);
    let display = |cc: &[&str], when: &str| {
        let request =
            BusinessRequestV2::from_fields(&profile, "r-1", send(cc, when, "primary")).unwrap();
        let action = request.action_alternative(d(21)).unwrap();
        let root = TaskAuthorizationV2::new(
            d(20),
            PrincipalIdV2::new([30; 32]),
            DurableTaskIdV2::new([31; 32]),
            1,
            d(32),
            d(33),
            UnixMillisV2::new(1),
            UnixMillisV2::new(1000),
            TaskEvidenceKindV2::AuthenticatedStructuredInput,
            d(34),
            d(35),
            vec![
                TaskAuthorizationClauseV2::new(1, vec![action.clone()], 1, 1, 1, vec![], false)
                    .unwrap(),
            ],
        )
        .unwrap();
        let content = ActionContentV2::new(
            d(20),
            1,
            1,
            0,
            action,
            request.magnitude(),
            request.payload_digest(),
            d(22),
            d(23),
            d(24),
            d(25),
            1,
        )
        .unwrap();
        let text = render_task_action_display_v2(
            &content,
            &root,
            &request,
            &std::collections::BTreeMap::new(),
            0,
            0,
        )
        .unwrap();
        serde_json::from_str::<serde_json::Value>(text.as_str()).unwrap()
    };
    let shown = display(&["carol@x.com"], "no");
    assert_eq!(shown["destination"], serde_json::json!(["alice@x.com"]));
    assert_eq!(
        shown["copy_destinations"],
        serde_json::json!({"bcc": [], "cc": ["carol@x.com"]})
    );
    assert_eq!(shown["condition"]["field"], "when");
    assert_eq!(shown["condition"]["value"], "no");
    assert_eq!(shown["condition"]["holds"], false);
    let shown = display(&[], "Yes.");
    assert_eq!(shown["condition"]["holds"], true);
}
