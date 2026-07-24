#[derive(Debug, Clone, Copy, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct ResourceLimitsV1 {
    #[n(0)]
    pub frame_bytes: u64,
    #[n(1)]
    pub cbor_depth: u64,
    #[n(2)]
    pub pages: u64,
    #[n(3)]
    pub chars_per_page: u64,
    #[n(4)]
    pub chars_per_document: u64,
    #[n(5)]
    pub observations: u64,
    #[n(6)]
    pub vault_entries: u64,
    #[n(7)]
    pub vault_raw_bytes: u64,
    #[n(8)]
    pub runs_per_client: u64,
    #[n(9)]
    pub vaults_per_client: u64,
    #[n(10)]
    pub approval_ledger_entries: u64,
    #[n(11)]
    pub model_manifest_bytes: u64,
    #[n(12)]
    pub model_assets: u64,
    #[n(13)]
    pub model_tensor_contracts: u64,
    #[n(14)]
    pub model_tensor_rank: u64,
    #[n(15)]
    pub single_model_asset_bytes: u64,
    #[n(16)]
    pub total_model_asset_bytes: u64,
    #[n(17)]
    pub ner_workers: u64,
    #[n(18)]
    pub ner_queue: u64,
    #[n(19)]
    pub ner_text_bytes: u64,
    #[n(20)]
    pub model_probes: u64,
    #[n(21)]
    pub model_probe_spans: u64,
    #[n(22)]
    pub ner_failure_threshold: u64,
    #[n(23)]
    pub request_deadline_ms: u64,
}
