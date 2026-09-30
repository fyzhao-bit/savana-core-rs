//! Immutable, owner-authenticated local input snapshots. Never model/admin JSON
//! admission: the trusted host must first resolve values through its G1–G4 owner.
use super::{G4Error, KernelValueV2, ProvenanceRecordV2};
use savana_kernel_protocol::v2::{Digest32V2, DurableRunIdV2, ValueInternalIdV2};
use serde::{Deserialize, Serialize};

/// Locally checked value; deliberately no Deserialize, Debug or public fields.
pub struct FusedOwnedInputV04(Input);
impl FusedOwnedInputV04 {
    pub fn from_owned_value(
        slot: [u8; 16],
        identity: ValueInternalIdV2,
        value: &KernelValueV2,
        provenance: &ProvenanceRecordV2,
    ) -> Result<Self, G4Error> {
        let input = Input {
            slot,
            identity: *identity.as_bytes(),
            value: minicbor::to_vec(value).map_err(|_| G4Error::StateConflict)?,
            provenance: super::encode_provenance_record_v2(provenance)
                .map_err(|_| G4Error::StateConflict)?,
        };
        input.decode()?;
        Ok(Self(input))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    slot: [u8; 16],
    identity: [u8; 32],
    value: Vec<u8>,
    provenance: Vec<u8>,
}
impl Drop for Input {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
        self.provenance.zeroize();
    }
}
impl Input {
    pub(super) fn storage_bytes(&self) -> usize {
        self.value.len() + self.provenance.len()
    }
    pub(super) fn decode(&self) -> Result<(KernelValueV2, ProvenanceRecordV2), G4Error> {
        let fail = || G4Error::StateConflict;
        if self.slot == [0; 16]
            || self.identity == [0; 32]
            || self.value.len() > 32768
            || self.provenance.len() > 32768
        {
            return Err(fail());
        }
        let mut decoder = minicbor::Decoder::new(&self.value);
        let value: KernelValueV2 = decoder
            .decode_with(&mut savana_kernel_protocol::v2::V2DecodeContext)
            .map_err(|_| fail())?;
        let provenance =
            super::decode_provenance_record_v2(&self.provenance).map_err(|_| fail())?;
        if decoder.position() != self.value.len()
            || value.contains_internal_slot()
            || minicbor::to_vec(&value).map_err(|_| fail())? != self.value
            || super::value_digest_v2(&value).map_err(|_| fail())? != provenance.value_digest()
        {
            return Err(fail());
        }
        Ok((value, provenance))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InputSnapshot {
    profile: [u8; 32],
    schema: u16,
    pub(super) run: [u8; 32],
    manifest: [u8; 32],
    generation: u64,
    pub(super) captured_at: u64,
    inputs: Vec<Input>,
}
impl InputSnapshot {
    pub(super) fn commitment(&self) -> Result<[u8; 32], G4Error> {
        let bytes =
            zeroize::Zeroizing::new(serde_json::to_vec(self).map_err(|_| G4Error::StateConflict)?);
        Ok(
            *super::task_authorization::hash_parts(b"SAVANA_FUSED_PINNED_INPUTS_V04\0", &[&bytes])
                .as_bytes(),
        )
    }
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
    pub(super) fn new(
        run: DurableRunIdV2,
        manifest: Digest32V2,
        generation: u64,
        now: u64,
        inputs: Vec<FusedOwnedInputV04>,
    ) -> Self {
        let mut inputs: Vec<_> = inputs.into_iter().map(|i| i.0).collect();
        inputs.sort_by_key(|i| i.slot);
        Self {
            schema: 1,
            profile: [0; 32],
            run: *run.as_bytes(),
            manifest: *manifest.as_bytes(),
            generation,
            captured_at: now,
            inputs,
        }
    }
    pub(super) fn bind_profile(
        &mut self,
        profile: &super::FusedPlanningProfileV04,
    ) -> Result<(), G4Error> {
        self.profile = profile.signing_digest()?;
        Ok(())
    }
    pub(super) fn validate(
        &self,
        profile: &super::FusedPlanningProfileV04,
        manifest: Digest32V2,
    ) -> Result<(), G4Error> {
        if self.schema != 1
            || self.profile != profile.signing_digest()?
            || self.run == [0; 32]
            || self.manifest != *manifest.as_bytes()
            || self.generation == 0
            || self.captured_at < profile.not_before
            || self.captured_at >= profile.expires_at
            || self.inputs.is_empty()
            || self.inputs.len() > 256
            || self
                .inputs
                .iter()
                .map(|i| i.value.len() + i.provenance.len())
                .sum::<usize>()
                > 128 * 1024
        {
            return Err(G4Error::StateConflict);
        }
        let expected: std::collections::BTreeSet<_> = profile
            .policy
            .operations
            .iter()
            .flat_map(|o| {
                o.bindings
                    .iter()
                    .filter(|b| b.result_of.is_none())
                    .map(|b| b.slot)
            })
            .collect();
        if expected.iter().copied().collect::<Vec<_>>()
            != self.inputs.iter().map(|i| i.slot).collect::<Vec<_>>()
        {
            return Err(G4Error::StateConflict);
        }
        for (n, i) in self.inputs.iter().enumerate() {
            let (_, p) = i.decode()?;
            if self.inputs[..n]
                .iter()
                .any(|old| old.identity == i.identity)
                || p.run_internal_id().as_bytes() != &self.run
                || p.active_state_manifest_digest() != manifest
                || self.captured_at < p.created_at().get()
                || self.captured_at >= p.expires_at().get()
            {
                return Err(G4Error::StateConflict);
            }
        }
        Ok(())
    }
    pub(super) fn same_inputs(&self, other: &Self) -> bool {
        self.profile == other.profile
            && self.run == other.run
            && self.manifest == other.manifest
            && self.generation == other.generation
            && self.inputs == other.inputs
    }
    pub(super) fn check_operation(
        &self,
        operation: &savana_continuation_core::planning::Operation,
        intent: &super::ActionIntentRecordV2,
    ) -> Result<(), G4Error> {
        if intent.durable_run_id.as_bytes() != &self.run
            || intent.active_state_manifest_digest.as_bytes() != &self.manifest
        {
            return Err(G4Error::StateConflict);
        }
        for b in &operation.bindings {
            if b.result_of.is_some() {
                continue;
            }
            let input = self
                .inputs
                .iter()
                .find(|i| i.slot == b.slot)
                .ok_or(G4Error::StateConflict)?;
            let (_, p) = input.decode()?;
            let arg = intent
                .material
                .normalized_arguments()
                .iter()
                .find(|a| a.argument_name().as_str() == b.argument)
                .ok_or(G4Error::StateConflict)?;
            if arg.value_internal_id().as_bytes() != &input.identity
                || arg.value_digest() != p.value_digest()
                || arg.provenance_digest() != p.provenance_digest()
            {
                return Err(G4Error::StateConflict);
            }
        }
        Ok(())
    }
    pub(super) fn recover(
        &self,
        generation: u64,
        now: u64,
    ) -> Result<RecoveredFusedInputsV04, G4Error> {
        if generation != self.generation || now < self.captured_at {
            return Err(G4Error::StateConflict);
        }
        let mut inputs = Vec::new();
        for i in &self.inputs {
            let (value, provenance) = i.decode()?;
            if now >= provenance.expires_at().get() {
                return Err(G4Error::StateConflict);
            }
            inputs.push(RecoveredFusedInputV04 {
                slot: i.slot,
                identity: ValueInternalIdV2::new(i.identity),
                value,
                provenance,
            });
        }
        Ok(RecoveredFusedInputsV04 {
            run: DurableRunIdV2::new(self.run),
            manifest: Digest32V2::new(self.manifest),
            inputs,
        })
    }
    pub(super) fn execution_expiry(&self, generation: u64, now: u64) -> Result<u64, G4Error> {
        let recovered = self.recover(generation, now)?;
        recovered
            .inputs
            .iter()
            .map(|i| i.provenance.expires_at().get())
            .min()
            .ok_or(G4Error::StateConflict)
    }
}

/// Only the durable owner can construct this authenticated recovery result.
/// No public raw-byte/JSON constructor, Debug or Serialize.
pub struct RecoveredFusedInputsV04 {
    run: DurableRunIdV2,
    manifest: Digest32V2,
    inputs: Vec<RecoveredFusedInputV04>,
}
pub struct RecoveredFusedInputV04 {
    slot: [u8; 16],
    identity: ValueInternalIdV2,
    value: KernelValueV2,
    provenance: ProvenanceRecordV2,
}
impl RecoveredFusedInputsV04 {
    pub(super) fn add_result(
        &mut self,
        slot: [u8; 16],
        input: &Input,
        extract: Option<(&[String], u16)>,
        now: u64,
    ) -> Result<(), G4Error> {
        let (value, provenance) = input.result_value(extract)?;
        if provenance.run_internal_id() != self.run
            || provenance.active_state_manifest_digest() != self.manifest
            || now < provenance.created_at().get()
            || now >= provenance.expires_at().get()
            || self.inputs.len() >= 256
            || self.inputs.iter().any(|i| i.slot == slot)
        {
            return Err(G4Error::StateConflict);
        }
        self.inputs.push(RecoveredFusedInputV04 {
            slot,
            identity: input.result_identity(slot),
            value,
            provenance,
        });
        self.inputs.sort_by_key(|i| i.slot);
        Ok(())
    }
    pub fn run(&self) -> DurableRunIdV2 {
        self.run
    }
    pub fn manifest(&self) -> Digest32V2 {
        self.manifest
    }
    pub fn inputs(&self) -> &[RecoveredFusedInputV04] {
        &self.inputs
    }
}

/// Only the trusted result gate calls this constructor after receipt verification.
/// This is data, never a dispatch grant; the durable owner rechecks its source.
pub struct FusedOwnedResultV04(pub(super) Input);
impl FusedOwnedResultV04 {
    pub fn from_verified_result(
        value: &KernelValueV2,
        provenance: &ProvenanceRecordV2,
    ) -> Result<Self, G4Error> {
        if !matches!(
            provenance.source_kind(),
            super::SourceKindV2::ToolResult { .. }
        ) {
            return Err(G4Error::StateConflict);
        }
        Ok(Self(
            FusedOwnedInputV04::from_owned_value(
                [1; 16],
                ValueInternalIdV2::new(*provenance.provenance_digest().as_bytes()),
                value,
                provenance,
            )?
            .0,
        ))
    }
}
impl Input {
    /// A whole-result edge (`extract` None) decodes the result as UTF-8 text for
    /// the payload; a path edge extracts one scalar at the signed JSON path. The
    /// derive op is folded into the value's provenance, so `add_result` and
    /// `check_result_argument` must pass the SAME extract to agree on the digest.
    fn result_value(
        &self,
        extract: Option<(&[String], u16)>,
    ) -> Result<(KernelValueV2, ProvenanceRecordV2), G4Error> {
        let (raw, p) = self.decode()?;
        let context = super::ProvenanceContextV2::from_authenticated_runtime(
            p.producer_identity(),
            p.run_internal_id(),
            p.active_state_manifest_digest(),
            p.created_at(),
            p.expires_at(),
        )
        .map_err(|_| G4Error::StateConflict)?;
        let operation = match extract {
            None => super::DeriveOperationV2::decode_utf8(),
            Some((path, max_bytes)) => {
                super::DeriveOperationV2::select_result_json_path_v04(path.to_vec(), max_bytes)
                    .map_err(|_| G4Error::StateConflict)?
            }
        };
        ProvenanceRecordV2::derived(context, operation, &[(&raw, &p)], p.label().effects())
            .map_err(|_| G4Error::StateConflict)
    }
    fn result_identity(&self, slot: [u8; 16]) -> ValueInternalIdV2 {
        ValueInternalIdV2::new(
            *super::task_authorization::hash_parts(
                b"SAVANA_FUSED_RESULT_SLOT_V04\0",
                &[&self.identity, &slot],
            )
            .as_bytes(),
        )
    }
    pub(super) fn check_result_argument(
        &self,
        slot: [u8; 16],
        argument: &super::StableActionArgumentBindingV2,
        extract: Option<(&[String], u16)>,
    ) -> Result<(), G4Error> {
        let (_, p) = self.result_value(extract)?;
        if argument.value_internal_id() != self.result_identity(slot)
            || argument.value_digest() != p.value_digest()
            || argument.provenance_digest() != p.provenance_digest()
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
    pub(super) fn check_result_time(&self, now: u64) -> Result<(), G4Error> {
        let (_, p) = self.decode()?;
        if now < p.created_at().get() || now >= p.expires_at().get() {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
    pub(super) fn check_result_window(&self, admitted: u64, expiry: u64) -> Result<(), G4Error> {
        self.check_result_time(admitted)?;
        let (_, p) = self.decode()?;
        if expiry <= admitted || expiry > p.expires_at().get() {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
}
impl RecoveredFusedInputV04 {
    pub fn slot(&self) -> [u8; 16] {
        self.slot
    }
    pub fn identity(&self) -> ValueInternalIdV2 {
        self.identity
    }
    pub fn value(&self) -> &KernelValueV2 {
        &self.value
    }
    pub fn copy_value(&self) -> Result<KernelValueV2, G4Error> {
        self.value
            .try_clone_internal()
            .map_err(|_| G4Error::StateConflict)
    }
    pub fn provenance(&self) -> &ProvenanceRecordV2 {
        &self.provenance
    }
}

#[cfg(test)]
mod result_edge_tests {
    use super::*;
    use crate::v2::intent::StableActionArgumentBindingV2;
    use crate::v2::{encode_provenance_record_v2, EffectSetV2, ProvenanceContextV2, ProvenanceRecordV2};
    use crate::v2::ArgumentNameV2;
    use savana_kernel_protocol::v2::{
        Digest32V2, DurableRunIdV2, InternalSlotDigestV2, ProducerIdentityV2, UnixMillisV2,
    };

    // A structured tool result, wrapped as an Input the kernel would recover.
    fn result_input(json: &[u8]) -> Input {
        let value = KernelValueV2::bytes(json.to_vec()).unwrap();
        let context = ProvenanceContextV2::from_authenticated_runtime(
            ProducerIdentityV2::new([90; 32]),
            DurableRunIdV2::new([44; 32]),
            Digest32V2::new([3; 32]),
            UnixMillisV2::new(10),
            UnixMillisV2::new(1000),
        )
        .unwrap();
        let provenance = ProvenanceRecordV2::gated_ingress(
            &value,
            context,
            Digest32V2::new([41; 32]),
            Digest32V2::new([42; 32]),
            Digest32V2::new([43; 32]),
            EffectSetV2::READ,
        )
        .unwrap();
        Input {
            slot: [1; 16],
            identity: [9; 32],
            value: minicbor::to_vec(&value).unwrap(),
            provenance: encode_provenance_record_v2(&provenance).unwrap(),
        }
    }

    fn path(segments: &[&str]) -> Vec<String> {
        segments.iter().map(|s| s.to_string()).collect()
    }

    fn matching_argument(
        input: &Input,
        slot: [u8; 16],
        extract: Option<(&[String], u16)>,
    ) -> StableActionArgumentBindingV2 {
        let (_, provenance) = input.result_value(extract).unwrap();
        StableActionArgumentBindingV2::new_for_test(
            ArgumentNameV2::new("to").unwrap(),
            InternalSlotDigestV2::new([6; 32]),
            input.result_identity(slot),
            provenance.value_digest(),
            provenance.provenance_digest(),
        )
    }

    #[test]
    fn a_path_edge_extracts_the_scalar_and_g7_accepts_only_that_extraction() {
        // Step 1's structured result: the participants of a found event.
        let json = br#"{"events":[{"participants":["a@x.com","b@y.com"],"count":2}]}"#;
        let input = result_input(json);
        let slot = [5; 16];
        let to_path = path(&["events", "0", "participants", "0"]);
        let extract = Some((&to_path[..], 256u16));

        // The kernel extracts exactly the scalar at the signed path.
        let (value, _) = input.result_value(extract).unwrap();
        assert_eq!(value.as_text(), Some("a@x.com"));

        // A whole-result edge (payload) produces a DIFFERENT value and provenance,
        // so a path edge and a payload edge never alias.
        let (_, path_prov) = input.result_value(extract).unwrap();
        let (whole, whole_prov) = input.result_value(None).unwrap();
        assert!(whole.as_text().unwrap().contains("participants"));
        assert_ne!(path_prov.provenance_digest(), whole_prov.provenance_digest());

        // G7 accepts an argument built from the kernel's own extraction.
        let ok = matching_argument(&input, slot, extract);
        assert!(input.check_result_argument(slot, &ok, extract).is_ok());

        // G7 rejects that same argument checked under a DIFFERENT path: the
        // recomputed provenance differs, so a planner that changes the edge
        // after the fact cannot pass.
        let other = path(&["events", "0", "count"]);
        assert!(input
            .check_result_argument(slot, &ok, Some((&other[..], 256)))
            .is_err());
        // And rejects it under the whole-result edge.
        assert!(input.check_result_argument(slot, &ok, None).is_err());
    }

    #[test]
    fn a_path_edge_fails_closed_on_nonscalar_or_oversize() {
        let json = br#"{"events":[{"participants":["a@x.com"],"count":2}]}"#;
        let input = result_input(json);
        // The participants array is not a scalar.
        let array = path(&["events", "0", "participants"]);
        assert!(input.result_value(Some((&array[..], 256))).is_err());
        // The scalar exceeds the signed byte bound.
        let addr = path(&["events", "0", "participants", "0"]);
        assert!(input.result_value(Some((&addr[..], 3))).is_err());
        // A missing path fails.
        let missing = path(&["events", "1", "participants", "0"]);
        assert!(input.result_value(Some((&missing[..], 256))).is_err());
    }
}
