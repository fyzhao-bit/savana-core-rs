use getrandom::getrandom;
use hmac::{Hmac, Mac as _};
use savana_kernel_protocol::v2::{
    encode_kernel_agent_operation_v2, AuthorityHandleKeyV2,
    DeriveOperationV2 as ProtocolDeriveOperationV2, DeriveValueRequestV2, Digest32V2,
    DurableRunIdV2, KernelAgentOperationV2, ProducerIdentityV2, RunHandleV2, UnixMillisV2,
    ValueHandleV2, ValueInternalIdV2,
};
use savana_policy_core::v2::{
    value_digest_v2, ArgumentNameV2, DeriveOperationV2, EffectSetV2, G3Error, KernelValueV2,
    PolicyConstantIdV2, ProvenanceContextV2, ProvenanceRecordV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

const DERIVED_VALUE_HANDLE_DOMAIN: &[u8] = b"SAVANA_DERIVED_VALUE_HANDLE_MINT_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelValueErrorV2 {
    InvalidReference,
    WrongRun,
    Expired,
    LimitExceeded,
    PolicyDenied,
    StateConflict,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelDerivedValueV2 {
    handle: ValueHandleV2,
    value_digest: Digest32V2,
}

impl KernelDerivedValueV2 {
    pub(crate) const fn handle(self) -> ValueHandleV2 {
        self.handle
    }

    pub(crate) const fn value_digest(self) -> Digest32V2 {
        self.value_digest
    }
}

pub(crate) struct PreparedVerifiedRunAdmissionV2 {
    run_handle: RunHandleV2,
    run_record: RunRecordV2,
    initial_handle: ValueHandleV2,
    initial_commitment: Digest32V2,
    initial_value_digest: Digest32V2,
}

impl PreparedVerifiedRunAdmissionV2 {
    pub(crate) const fn run_handle(&self) -> RunHandleV2 {
        self.run_handle
    }

    pub(crate) const fn initial_value(&self) -> KernelDerivedValueV2 {
        KernelDerivedValueV2 {
            handle: self.initial_handle,
            value_digest: self.initial_value_digest,
        }
    }
}

struct RunRecordV2 {
    commitment: Digest32V2,
    producer_identity: ProducerIdentityV2,
    durable_run_id: DurableRunIdV2,
    active_state_manifest_digest: Digest32V2,
    expires_at: UnixMillisV2,
    policy_allowed_effects: EffectSetV2,
}

struct ValueRecordV2 {
    commitment: Digest32V2,
    run_commitment: Digest32V2,
    value: KernelValueV2,
    provenance: ProvenanceRecordV2,
    derive_request_digest: Option<Digest32V2>,
}

pub(crate) struct KernelResolvedG4ValueV2<'value> {
    // Carried so a resolved value names the run it was resolved under. G4
    // callers bind the run through the action intent record instead.
    #[allow(dead_code)]
    durable_run_id: DurableRunIdV2,
    active_state_manifest_digest: Digest32V2,
    value_internal_id: ValueInternalIdV2,
    value: &'value KernelValueV2,
    provenance: &'value ProvenanceRecordV2,
}

impl KernelResolvedG4ValueV2<'_> {
    #[allow(dead_code)]
    pub(crate) const fn durable_run_id(&self) -> DurableRunIdV2 {
        self.durable_run_id
    }

    pub(crate) const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub(crate) const fn value_internal_id(&self) -> ValueInternalIdV2 {
        self.value_internal_id
    }

    pub(crate) const fn value(&self) -> &KernelValueV2 {
        self.value
    }

    pub(crate) const fn provenance(&self) -> &ProvenanceRecordV2 {
        self.provenance
    }

    pub(crate) const fn value_digest(&self) -> Digest32V2 {
        self.provenance.value_digest()
    }
}

pub(crate) struct KernelValueOwnerV2 {
    handle_key: AuthorityHandleKeyV2,
    derived_mint_key: Zeroizing<[u8; 32]>,
    maximum_runs: usize,
    maximum_values: usize,
    runs: Vec<RunRecordV2>,
    values: Vec<ValueRecordV2>,
}

impl std::fmt::Debug for KernelValueOwnerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelValueOwnerV2")
            .field("run_count", &self.runs.len())
            .field("value_count", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl KernelValueOwnerV2 {
    pub(crate) fn new(
        maximum_runs: usize,
        maximum_values: usize,
    ) -> Result<Self, KernelValueErrorV2> {
        if maximum_runs == 0
            || maximum_runs > 65_536
            || maximum_values == 0
            || maximum_values > 65_536
        {
            return Err(KernelValueErrorV2::LimitExceeded);
        }
        let handle_key = AuthorityHandleKeyV2::from_entropy(random_bytes()?)
            .ok_or(KernelValueErrorV2::Unavailable)?;
        Ok(Self {
            handle_key,
            derived_mint_key: Zeroizing::new(random_bytes()?),
            maximum_runs,
            maximum_values,
            runs: Vec::new(),
            values: Vec::new(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn open_verified_run(
        &mut self,
        producer_identity: ProducerIdentityV2,
        durable_run_id: DurableRunIdV2,
        active_state_manifest_digest: Digest32V2,
        now: UnixMillisV2,
        expires_at: UnixMillisV2,
        policy_allowed_effects: EffectSetV2,
    ) -> Result<RunHandleV2, KernelValueErrorV2> {
        if self.runs.len() >= self.maximum_runs || now.get() >= expires_at.get() {
            return Err(KernelValueErrorV2::LimitExceeded);
        }
        ProvenanceContextV2::from_authenticated_runtime(
            producer_identity,
            durable_run_id,
            active_state_manifest_digest,
            now,
            expires_at,
        )
        .map_err(map_g3_error)?;
        for _ in 0..8 {
            let handle = RunHandleV2::from_authority_entropy(random_bytes()?)
                .ok_or(KernelValueErrorV2::Unavailable)?;
            let commitment = handle.authority_commitment(&self.handle_key);
            if self.runs.iter().all(|run| run.commitment != commitment) {
                self.runs
                    .try_reserve(1)
                    .map_err(|_| KernelValueErrorV2::Unavailable)?;
                self.runs.push(RunRecordV2 {
                    commitment,
                    producer_identity,
                    durable_run_id,
                    active_state_manifest_digest,
                    expires_at,
                    policy_allowed_effects,
                });
                return Ok(handle);
            }
        }
        Err(KernelValueErrorV2::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn register_verified_value(
        &mut self,
        run: RunHandleV2,
        value: KernelValueV2,
        provenance: ProvenanceRecordV2,
    ) -> Result<KernelDerivedValueV2, KernelValueErrorV2> {
        let run_commitment = run.authority_commitment(&self.handle_key);
        let run = self
            .runs
            .iter()
            .find(|record| record.commitment == run_commitment)
            .ok_or(KernelValueErrorV2::InvalidReference)?;
        let value_digest = value_digest_v2(&value).map_err(map_g3_error)?;
        if provenance.value_digest() != value_digest
            || provenance.run_internal_id() != run.durable_run_id
            || provenance.active_state_manifest_digest() != run.active_state_manifest_digest
        {
            return Err(KernelValueErrorV2::WrongRun);
        }
        let handle = self.mint_random_value_handle()?;
        let commitment = handle.authority_commitment(&self.handle_key);
        self.push_value(ValueRecordV2 {
            commitment,
            run_commitment,
            value,
            provenance,
            derive_request_digest: None,
        })?;
        Ok(KernelDerivedValueV2 {
            handle,
            value_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_verified_run_admission(
        &mut self,
        producer_identity: ProducerIdentityV2,
        durable_run_id: DurableRunIdV2,
        active_state_manifest_digest: Digest32V2,
        now: UnixMillisV2,
        expires_at: UnixMillisV2,
        policy_allowed_effects: EffectSetV2,
        initial_value: &KernelValueV2,
        provenance: &ProvenanceRecordV2,
    ) -> Result<PreparedVerifiedRunAdmissionV2, KernelValueErrorV2> {
        if self.runs.len() >= self.maximum_runs || self.values.len() >= self.maximum_values {
            return Err(KernelValueErrorV2::LimitExceeded);
        }
        ProvenanceContextV2::from_authenticated_runtime(
            producer_identity,
            durable_run_id,
            active_state_manifest_digest,
            now,
            expires_at,
        )
        .map_err(map_g3_error)?;
        let initial_value_digest = value_digest_v2(initial_value).map_err(map_g3_error)?;
        if provenance.value_digest() != initial_value_digest
            || provenance.run_internal_id() != durable_run_id
            || provenance.active_state_manifest_digest() != active_state_manifest_digest
        {
            return Err(KernelValueErrorV2::WrongRun);
        }

        self.runs
            .try_reserve(1)
            .map_err(|_| KernelValueErrorV2::Unavailable)?;
        self.values
            .try_reserve(1)
            .map_err(|_| KernelValueErrorV2::Unavailable)?;

        let run_handle = self.mint_random_run_handle()?;
        let run_commitment = run_handle.authority_commitment(&self.handle_key);
        let initial_handle = self.mint_random_value_handle()?;
        let initial_commitment = initial_handle.authority_commitment(&self.handle_key);
        Ok(PreparedVerifiedRunAdmissionV2 {
            run_handle,
            run_record: RunRecordV2 {
                commitment: run_commitment,
                producer_identity,
                durable_run_id,
                active_state_manifest_digest,
                expires_at,
                policy_allowed_effects,
            },
            initial_handle,
            initial_commitment,
            initial_value_digest,
        })
    }

    pub(crate) fn commit_verified_run_admission(
        &mut self,
        admission: PreparedVerifiedRunAdmissionV2,
        initial_value: KernelValueV2,
        provenance: ProvenanceRecordV2,
    ) -> (RunHandleV2, KernelDerivedValueV2) {
        let initial = admission.initial_value();
        let run_handle = admission.run_handle();
        let run_commitment = admission.run_record.commitment;
        self.runs.push(admission.run_record);
        self.values.push(ValueRecordV2 {
            commitment: admission.initial_commitment,
            run_commitment,
            value: initial_value,
            provenance,
            derive_request_digest: None,
        });
        (run_handle, initial)
    }

    pub(crate) fn derive(
        &mut self,
        request: DeriveValueRequestV2,
        now: UnixMillisV2,
    ) -> Result<KernelDerivedValueV2, KernelValueErrorV2> {
        let canonical_request =
            encode_kernel_agent_operation_v2(&KernelAgentOperationV2::DeriveValue(request.clone()))
                .map_err(|_| KernelValueErrorV2::Unavailable)?;
        let request_digest = Digest32V2::new(Sha256::digest(&canonical_request).into());
        let deterministic_handle = self.derived_handle(request_digest)?;
        let deterministic_commitment = deterministic_handle.authority_commitment(&self.handle_key);
        if let Some(existing) = self
            .values
            .iter()
            .find(|value| value.derive_request_digest == Some(request_digest))
        {
            if existing.commitment != deterministic_commitment {
                return Err(KernelValueErrorV2::StateConflict);
            }
            return Ok(KernelDerivedValueV2 {
                handle: deterministic_handle,
                value_digest: existing.provenance.value_digest(),
            });
        }
        if self
            .values
            .iter()
            .any(|value| value.commitment == deterministic_commitment)
        {
            return Err(KernelValueErrorV2::StateConflict);
        }

        let run_commitment = request.run().authority_commitment(&self.handle_key);
        let run = self
            .runs
            .iter()
            .find(|run| run.commitment == run_commitment)
            .ok_or(KernelValueErrorV2::InvalidReference)?;
        if now.get() == 0 || now.get() >= run.expires_at.get() {
            return Err(KernelValueErrorV2::Expired);
        }
        let context = ProvenanceContextV2::from_authenticated_runtime(
            run.producer_identity,
            run.durable_run_id,
            run.active_state_manifest_digest,
            now,
            run.expires_at,
        )
        .map_err(map_g3_error)?;
        let operation = map_operation(request.operation())?;
        let mut parent_indexes = Vec::new();
        parent_indexes
            .try_reserve_exact(request.inputs().len())
            .map_err(|_| KernelValueErrorV2::Unavailable)?;
        for input in request.inputs() {
            let commitment = input.authority_commitment(&self.handle_key);
            let index = self
                .values
                .iter()
                .position(|value| {
                    value.commitment == commitment && value.run_commitment == run_commitment
                })
                .ok_or(KernelValueErrorV2::InvalidReference)?;
            parent_indexes.push(index);
        }
        let mut parents = Vec::new();
        parents
            .try_reserve_exact(parent_indexes.len())
            .map_err(|_| KernelValueErrorV2::Unavailable)?;
        parents.extend(parent_indexes.iter().map(|index| {
            let value = &self.values[*index];
            (&value.value, &value.provenance)
        }));
        let (value, provenance) =
            ProvenanceRecordV2::derived(context, operation, &parents, run.policy_allowed_effects)
                .map_err(map_g3_error)?;
        let value_digest = provenance.value_digest();
        self.push_value(ValueRecordV2 {
            commitment: deterministic_commitment,
            run_commitment,
            value,
            provenance,
            derive_request_digest: Some(request_digest),
        })?;
        Ok(KernelDerivedValueV2 {
            handle: deterministic_handle,
            value_digest,
        })
    }

    pub(crate) fn validate_run_values(
        &self,
        run: RunHandleV2,
        values: &[ValueHandleV2],
        now: UnixMillisV2,
    ) -> Result<(), KernelValueErrorV2> {
        let run_commitment = run.authority_commitment(&self.handle_key);
        let run = self
            .runs
            .iter()
            .find(|record| record.commitment == run_commitment)
            .ok_or(KernelValueErrorV2::InvalidReference)?;
        if now.get() == 0 || now.get() >= run.expires_at.get() {
            return Err(KernelValueErrorV2::Expired);
        }
        for value in values {
            let commitment = value.authority_commitment(&self.handle_key);
            if !self.values.iter().any(|record| {
                record.commitment == commitment && record.run_commitment == run_commitment
            }) {
                return Err(KernelValueErrorV2::InvalidReference);
            }
        }
        Ok(())
    }

    pub(crate) fn resolve_g4_value(
        &self,
        run: RunHandleV2,
        value: ValueHandleV2,
        now: UnixMillisV2,
    ) -> Result<KernelResolvedG4ValueV2<'_>, KernelValueErrorV2> {
        let run_commitment = run.authority_commitment(&self.handle_key);
        let run = self
            .runs
            .iter()
            .find(|record| record.commitment == run_commitment)
            .ok_or(KernelValueErrorV2::InvalidReference)?;
        if now.get() == 0 || now.get() >= run.expires_at.get() {
            return Err(KernelValueErrorV2::Expired);
        }
        let value_commitment = value.authority_commitment(&self.handle_key);
        let value = self
            .values
            .iter()
            .find(|record| {
                record.commitment == value_commitment && record.run_commitment == run_commitment
            })
            .ok_or(KernelValueErrorV2::InvalidReference)?;
        Ok(KernelResolvedG4ValueV2 {
            durable_run_id: run.durable_run_id,
            active_state_manifest_digest: run.active_state_manifest_digest,
            value_internal_id: ValueInternalIdV2::new(*value.commitment.as_bytes()),
            value: &value.value,
            provenance: &value.provenance,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_planner_value(
        &mut self,
        run: RunHandleV2,
        parent_handles: &[ValueHandleV2],
        canonical_plan: Vec<u8>,
        planner_route_digest: Digest32V2,
        planner_envelope_digest: Digest32V2,
        planner_output_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<KernelDerivedValueV2, KernelValueErrorV2> {
        if canonical_plan.is_empty() {
            return Err(KernelValueErrorV2::PolicyDenied);
        }
        let run_commitment = run.authority_commitment(&self.handle_key);
        let run_record = self
            .runs
            .iter()
            .find(|record| record.commitment == run_commitment)
            .ok_or(KernelValueErrorV2::InvalidReference)?;
        if now.get() == 0 || now.get() >= run_record.expires_at.get() {
            return Err(KernelValueErrorV2::Expired);
        }
        let context = ProvenanceContextV2::from_authenticated_runtime(
            run_record.producer_identity,
            run_record.durable_run_id,
            run_record.active_state_manifest_digest,
            now,
            run_record.expires_at,
        )
        .map_err(map_g3_error)?;
        let policy_allowed_effects = run_record.policy_allowed_effects;

        let mut parent_indexes = Vec::new();
        parent_indexes
            .try_reserve_exact(parent_handles.len())
            .map_err(|_| KernelValueErrorV2::Unavailable)?;
        for parent in parent_handles {
            let commitment = parent.authority_commitment(&self.handle_key);
            let index = self
                .values
                .iter()
                .position(|record| {
                    record.commitment == commitment && record.run_commitment == run_commitment
                })
                .ok_or(KernelValueErrorV2::InvalidReference)?;
            parent_indexes.push(index);
        }

        let value = KernelValueV2::bytes(canonical_plan).map_err(map_g3_error)?;
        let parent_provenance = parent_indexes
            .iter()
            .map(|index| &self.values[*index].provenance)
            .collect::<Vec<_>>();
        let provenance = ProvenanceRecordV2::planner_output(
            &value,
            context,
            planner_route_digest,
            planner_envelope_digest,
            planner_output_digest,
            &parent_provenance,
            policy_allowed_effects,
        )
        .map_err(map_g3_error)?;
        let value_digest = provenance.value_digest();
        let handle = self.mint_random_value_handle()?;
        let commitment = handle.authority_commitment(&self.handle_key);
        self.push_value(ValueRecordV2 {
            commitment,
            run_commitment,
            value,
            provenance,
            derive_request_digest: None,
        })?;
        Ok(KernelDerivedValueV2 {
            handle,
            value_digest,
        })
    }

    fn mint_random_value_handle(&self) -> Result<ValueHandleV2, KernelValueErrorV2> {
        for _ in 0..8 {
            let handle = ValueHandleV2::from_authority_entropy(random_bytes()?)
                .ok_or(KernelValueErrorV2::Unavailable)?;
            let commitment = handle.authority_commitment(&self.handle_key);
            if self
                .values
                .iter()
                .all(|value| value.commitment != commitment)
            {
                return Ok(handle);
            }
        }
        Err(KernelValueErrorV2::Unavailable)
    }

    fn mint_random_run_handle(&self) -> Result<RunHandleV2, KernelValueErrorV2> {
        for _ in 0..8 {
            let handle = RunHandleV2::from_authority_entropy(random_bytes()?)
                .ok_or(KernelValueErrorV2::Unavailable)?;
            let commitment = handle.authority_commitment(&self.handle_key);
            if self.runs.iter().all(|run| run.commitment != commitment) {
                return Ok(handle);
            }
        }
        Err(KernelValueErrorV2::Unavailable)
    }

    fn derived_handle(
        &self,
        request_digest: Digest32V2,
    ) -> Result<ValueHandleV2, KernelValueErrorV2> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.derived_mint_key.as_ref())
            .map_err(|_| KernelValueErrorV2::Unavailable)?;
        mac.update(DERIVED_VALUE_HANDLE_DOMAIN);
        mac.update(request_digest.as_bytes());
        let mut token: [u8; 32] = mac.finalize().into_bytes().into();
        let handle =
            ValueHandleV2::from_authority_entropy(token).ok_or(KernelValueErrorV2::Unavailable);
        token.zeroize();
        handle
    }

    fn push_value(&mut self, value: ValueRecordV2) -> Result<(), KernelValueErrorV2> {
        if self.values.len() >= self.maximum_values {
            return Err(KernelValueErrorV2::LimitExceeded);
        }
        self.values
            .try_reserve(1)
            .map_err(|_| KernelValueErrorV2::Unavailable)?;
        self.values.push(value);
        Ok(())
    }

    #[cfg(test)]
    fn value_count(&self) -> usize {
        self.values.len()
    }

    #[cfg(test)]
    fn run_count(&self) -> usize {
        self.runs.len()
    }
}

fn map_operation(
    operation: &ProtocolDeriveOperationV2,
) -> Result<DeriveOperationV2, KernelValueErrorV2> {
    match operation {
        ProtocolDeriveOperationV2::ConcatenateText => Ok(DeriveOperationV2::concatenate_text()),
        ProtocolDeriveOperationV2::NormalizeNfc => Ok(DeriveOperationV2::normalize_nfc()),
        ProtocolDeriveOperationV2::SelectObjectField(name) => {
            Ok(DeriveOperationV2::select_object_field(
                ArgumentNameV2::new(name.as_str()).map_err(map_g3_error)?,
            ))
        }
        ProtocolDeriveOperationV2::AssembleList => Ok(DeriveOperationV2::assemble_list()),
        ProtocolDeriveOperationV2::AssembleObject(fields) => {
            let mapped = fields
                .iter()
                .map(|field| ArgumentNameV2::new(field.as_str()).map_err(map_g3_error))
                .collect::<Result<Vec<_>, _>>()?;
            DeriveOperationV2::assemble_object(mapped).map_err(map_g3_error)
        }
        ProtocolDeriveOperationV2::PolicyConstant(constant) => Ok(
            DeriveOperationV2::policy_constant(PolicyConstantIdV2::new(constant.get())),
        ),
    }
}

const fn map_g3_error(error: G3Error) -> KernelValueErrorV2 {
    match error {
        G3Error::CollectionLimitExceeded
        | G3Error::ParentLimitExceeded
        | G3Error::RootEvidenceOverflow
        | G3Error::ValueDepthExceeded
        | G3Error::ValueNodeLimitExceeded
        | G3Error::ValueEncodedBytesExceeded => KernelValueErrorV2::LimitExceeded,
        G3Error::AllocationFailure => KernelValueErrorV2::Unavailable,
        G3Error::CrossRunParent | G3Error::CrossManifestParent => KernelValueErrorV2::WrongRun,
        G3Error::InvalidTimeRange => KernelValueErrorV2::Expired,
        G3Error::BindingMismatch | G3Error::DuplicateInternalId => {
            KernelValueErrorV2::StateConflict
        }
        _ => KernelValueErrorV2::PolicyDenied,
    }
}

fn random_bytes() -> Result<[u8; 32], KernelValueErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom(&mut bytes).map_err(|_| KernelValueErrorV2::Unavailable)?;
    if bytes == [0; 32] {
        return Err(KernelValueErrorV2::Unavailable);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use savana_kernel_protocol::v2::{
        DeriveOperationV2, DeriveValueRequestV2, Digest32V2, DurableRunIdV2, ProducerIdentityV2,
        UnixMillisV2,
    };
    use savana_policy_core::v2::{
        value_digest_v2, EffectSetV2, KernelValueV2, ProvenanceContextV2, ProvenanceRecordV2,
    };

    use super::{KernelValueErrorV2, KernelValueOwnerV2};

    fn planner_input(
        producer: ProducerIdentityV2,
        durable_run: DurableRunIdV2,
        manifest: Digest32V2,
        marker: u8,
    ) -> (KernelValueV2, ProvenanceRecordV2) {
        let value = KernelValueV2::bytes(vec![marker]).unwrap();
        let provenance = ProvenanceRecordV2::planner_output(
            &value,
            ProvenanceContextV2::from_authenticated_runtime(
                producer,
                durable_run,
                manifest,
                UnixMillisV2::new(10),
                UnixMillisV2::new(100),
            )
            .unwrap(),
            Digest32V2::new([0x41; 32]),
            Digest32V2::new([0x42; 32]),
            Digest32V2::new([0x43; 32]),
            &[],
            EffectSetV2::SEND,
        )
        .unwrap();
        (value, provenance)
    }

    #[test]
    fn failed_atomic_run_admission_never_partially_commits_a_run_or_value() {
        let producer = ProducerIdentityV2::new([0x21; 32]);
        let manifest = Digest32V2::new([0x22; 32]);
        let mut owner = KernelValueOwnerV2::new(1, 1).unwrap();
        let first_run = DurableRunIdV2::new([0x23; 32]);
        let (first_value, first_provenance) = planner_input(producer, first_run, manifest, 0x24);
        let admission = owner
            .prepare_verified_run_admission(
                producer,
                first_run,
                manifest,
                UnixMillisV2::new(10),
                UnixMillisV2::new(100),
                EffectSetV2::SEND,
                &first_value,
                &first_provenance,
            )
            .unwrap();
        owner.commit_verified_run_admission(admission, first_value, first_provenance);

        let second_run = DurableRunIdV2::new([0x25; 32]);
        let (second_value, second_provenance) = planner_input(producer, second_run, manifest, 0x26);
        assert!(matches!(
            owner.prepare_verified_run_admission(
                producer,
                second_run,
                manifest,
                UnixMillisV2::new(10),
                UnixMillisV2::new(100),
                EffectSetV2::SEND,
                &second_value,
                &second_provenance,
            ),
            Err(KernelValueErrorV2::LimitExceeded)
        ));
        assert_eq!(owner.run_count(), 1);
        assert_eq!(owner.value_count(), 1);
    }

    #[test]
    fn g3_derive_is_run_bound_and_exact_replay_returns_the_same_opaque_handle() {
        let producer = ProducerIdentityV2::new([0x31; 32]);
        let durable_run = DurableRunIdV2::new([0x32; 32]);
        let manifest = Digest32V2::new([0x33; 32]);
        let mut owner = KernelValueOwnerV2::new(4, 32).unwrap();
        let run = owner
            .open_verified_run(
                producer,
                durable_run,
                manifest,
                UnixMillisV2::new(10),
                UnixMillisV2::new(100),
                EffectSetV2::SEND,
            )
            .unwrap();
        let input = KernelValueV2::text("e\u{301}").unwrap();
        let provenance = ProvenanceRecordV2::planner_output(
            &input,
            ProvenanceContextV2::from_authenticated_runtime(
                producer,
                durable_run,
                manifest,
                UnixMillisV2::new(10),
                UnixMillisV2::new(100),
            )
            .unwrap(),
            Digest32V2::new([0x34; 32]),
            Digest32V2::new([0x35; 32]),
            Digest32V2::new([0x36; 32]),
            &[],
            EffectSetV2::SEND,
        )
        .unwrap();
        let input = owner
            .register_verified_value(run, input, provenance)
            .unwrap();
        let request = DeriveValueRequestV2::new(
            run,
            DeriveOperationV2::normalize_nfc(),
            vec![input.handle()],
        )
        .unwrap();
        let derived = owner
            .derive(request.clone(), UnixMillisV2::new(11))
            .unwrap();
        assert_eq!(
            derived.value_digest(),
            value_digest_v2(&KernelValueV2::text("é").unwrap()).unwrap()
        );
        assert_eq!(owner.value_count(), 2);

        let replay = owner.derive(request, UnixMillisV2::new(12)).unwrap();
        assert_eq!(replay, derived);
        assert_eq!(owner.value_count(), 2);
    }

    #[test]
    fn g4_resolver_returns_only_exact_run_bound_internal_material() {
        let producer = ProducerIdentityV2::new([0x61; 32]);
        let durable_run = DurableRunIdV2::new([0x62; 32]);
        let manifest = Digest32V2::new([0x63; 32]);
        let mut owner = KernelValueOwnerV2::new(4, 32).unwrap();
        let run = owner
            .open_verified_run(
                producer,
                durable_run,
                manifest,
                UnixMillisV2::new(10),
                UnixMillisV2::new(100),
                EffectSetV2::SEND,
            )
            .unwrap();
        let value = KernelValueV2::text("private").unwrap();
        let provenance = ProvenanceRecordV2::planner_output(
            &value,
            ProvenanceContextV2::from_authenticated_runtime(
                producer,
                durable_run,
                manifest,
                UnixMillisV2::new(10),
                UnixMillisV2::new(100),
            )
            .unwrap(),
            Digest32V2::new([0x64; 32]),
            Digest32V2::new([0x65; 32]),
            Digest32V2::new([0x66; 32]),
            &[],
            EffectSetV2::SEND,
        )
        .unwrap();
        let registered = owner
            .register_verified_value(run, value, provenance)
            .unwrap();

        let resolved = owner
            .resolve_g4_value(run, registered.handle(), UnixMillisV2::new(11))
            .unwrap();
        assert_eq!(resolved.durable_run_id(), durable_run);
        assert_eq!(resolved.active_state_manifest_digest(), manifest);
        assert_eq!(resolved.value_digest(), registered.value_digest());
        assert_ne!(resolved.value_internal_id().as_bytes(), &[0; 32]);

        let other = owner
            .open_verified_run(
                producer,
                DurableRunIdV2::new([0x67; 32]),
                manifest,
                UnixMillisV2::new(10),
                UnixMillisV2::new(100),
                EffectSetV2::SEND,
            )
            .unwrap();
        assert!(matches!(
            owner.resolve_g4_value(other, registered.handle(), UnixMillisV2::new(11)),
            Err(KernelValueErrorV2::InvalidReference)
        ));
    }
}
