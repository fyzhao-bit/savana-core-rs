use savana_kernel_protocol::{HardLimits, StableCode, PROTOCOL_MAJOR, PROTOCOL_MINOR};

#[test]
fn v1_constants_are_frozen() {
    assert_eq!((PROTOCOL_MAJOR, PROTOCOL_MINOR), (1, 0));
    let limits = HardLimits::COMPILED;
    assert_eq!(limits.frame_bytes(), 8 * 1024 * 1024);
    assert_eq!(limits.cbor_depth(), 32);
    assert_eq!(limits.pages(), 2_048);
    assert_eq!(limits.chars_per_page(), 50_000);
    assert_eq!(limits.chars_per_document(), 1_000_000);
    assert_eq!(limits.observations(), 100_000);
    assert_eq!(limits.vault_entries(), 20_000);
    assert_eq!(limits.vault_raw_bytes(), 32 * 1024 * 1024);
    assert_eq!(limits.runs_per_client(), 128);
    assert_eq!(limits.vaults_per_client(), 512);
    assert_eq!(limits.approval_ledger_entries(), 65_536);
    assert_eq!(limits.model_manifest_bytes(), 256 * 1024);
    assert_eq!(limits.model_assets(), 32);
    assert_eq!(limits.model_tensor_contracts(), 32);
    assert_eq!(limits.model_tensor_rank(), 8);
    assert_eq!(limits.single_model_asset_bytes(), 256 * 1024 * 1024);
    assert_eq!(limits.total_model_asset_bytes(), 512 * 1024 * 1024);
    assert_eq!(limits.ner_workers(), 4);
    assert_eq!(limits.ner_queue(), 128);
    assert_eq!(limits.ner_text_bytes(), 200_000);
    assert_eq!(limits.model_probes(), 16);
    assert_eq!(limits.model_probe_spans(), 512);
    assert_eq!(limits.ner_failure_threshold(), 32);
    assert_eq!(limits.request_deadline_ms(), 120_000);
}

#[test]
fn stable_codes_are_wire_strings() {
    assert_eq!(
        StableCode::ProtocolFrameTooLarge.as_str(),
        "PROTOCOL_FRAME_TOO_LARGE"
    );
    assert_eq!(
        StableCode::IdentityInvalidSignature.as_str(),
        "IDENTITY_INVALID_SIGNATURE"
    );
    assert_eq!(StableCode::KernelUnavailable.as_str(), "KERNEL_UNAVAILABLE");
}
