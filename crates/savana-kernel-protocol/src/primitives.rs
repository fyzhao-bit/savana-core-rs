use crate::StableCode;

const RESOURCE_LIMIT_FIELD_COUNT: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, minicbor::Encode)]
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

impl<'b, C> minicbor::Decode<'b, C> for ResourceLimitsV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'b>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let map_position = decoder.position();
        let entries = match decoder.map() {
            Ok(Some(entries)) => entries,
            Ok(None) | Err(_) => return Err(malformed_cbor(map_position)),
        };
        let mut fields = [None; RESOURCE_LIMIT_FIELD_COUNT];

        for _ in 0..entries {
            let field_position = decoder.position();
            let field = match decoder.u64() {
                Ok(field) => field,
                Err(_) => return Err(malformed_cbor(field_position)),
            };
            let index = match usize::try_from(field) {
                Ok(index) if index < RESOURCE_LIMIT_FIELD_COUNT => index,
                _ => return Err(unknown_field(field_position)),
            };
            if fields[index].is_some() {
                return Err(malformed_cbor(field_position));
            }

            let value_position = decoder.position();
            fields[index] = Some(match decoder.u64() {
                Ok(value) => value,
                Err(_) => return Err(malformed_cbor(value_position)),
            });
        }

        Ok(Self {
            frame_bytes: required(&fields, 0)?,
            cbor_depth: required(&fields, 1)?,
            pages: required(&fields, 2)?,
            chars_per_page: required(&fields, 3)?,
            chars_per_document: required(&fields, 4)?,
            observations: required(&fields, 5)?,
            vault_entries: required(&fields, 6)?,
            vault_raw_bytes: required(&fields, 7)?,
            runs_per_client: required(&fields, 8)?,
            vaults_per_client: required(&fields, 9)?,
            approval_ledger_entries: required(&fields, 10)?,
            model_manifest_bytes: required(&fields, 11)?,
            model_assets: required(&fields, 12)?,
            model_tensor_contracts: required(&fields, 13)?,
            model_tensor_rank: required(&fields, 14)?,
            single_model_asset_bytes: required(&fields, 15)?,
            total_model_asset_bytes: required(&fields, 16)?,
            ner_workers: required(&fields, 17)?,
            ner_queue: required(&fields, 18)?,
            ner_text_bytes: required(&fields, 19)?,
            model_probes: required(&fields, 20)?,
            model_probe_spans: required(&fields, 21)?,
            ner_failure_threshold: required(&fields, 22)?,
            request_deadline_ms: required(&fields, 23)?,
        })
    }
}

fn required(
    fields: &[Option<u64>; RESOURCE_LIMIT_FIELD_COUNT],
    index: usize,
) -> Result<u64, minicbor::decode::Error> {
    fields[index].ok_or_else(|| malformed_cbor(0))
}

fn malformed_cbor(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn unknown_field(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolUnknownField.as_str()).at(position)
}
