//! Exercise the actual G5 -> G7 -> encrypted owner path, not a parallel ledger.
use super::*;
use crate::v2::durable_tests::{
    shared_connector_registry, signed_task, task_clause, task_request, task_store,
};
use crate::v2::*;
use ed25519_dalek::{Signer, SigningKey};
use savana_continuation_core::ledger::{DomainLimit, ResourceKey};
use savana_continuation_core::observation::{Projection, Slot};
use savana_kernel_protocol::v2::{
    action_content_digest_v2, ActionAlternativeV2, ActionCodecProfileV2, ExecutorIdentityV2,
    HpkeX25519KeyIdV2, InternalStepIdV2, MagnitudeUnitV2, PlanRevisionDigestV2, TaskEffectV2,
};

#[path = "durable_managed_admin_tests.rs"]
mod admin_tests;
#[path = "durable_fused_execution_tests.rs"]
mod fused_execution_tests;
#[path = "durable_managed_handoff_tests.rs"]
mod handoff_tests;
#[path = "durable_managed_resource_tests.rs"]
mod managed_tests;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn task() -> DurableTaskIdV2 {
    DurableTaskIdV2::new([5; 32])
}
fn now() -> UnixMillisV2 {
    UnixMillisV2::new(10)
}
fn resource_key() -> SigningKey {
    SigningKey::from_bytes(&[0x41; 32])
}
fn admin_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}
fn subject() -> DispatchQuotaSubjectV2 {
    DispatchQuotaSubjectV2::tool_attempt(AttemptKindV2::ToolWrite)
}

#[test]
fn fused_enrollment_cannot_fall_back_to_unbound_legacy_g7() {
    let mut f = Fixture::new();
    let parent = f.store.task_authorization_state(task()).unwrap();
    let mut p = super::fused_planning_tests::profile();
    p.task = *task().as_bytes();
    p.policy.root = *parent.authorization().digest().as_bytes();
    let signature = admin_key().sign(&p.signing_digest().unwrap()).to_bytes();
    let verified = VerifiedFusedPlanningProfileV04::verify(
        &serde_json::to_vec(&p).unwrap(),
        &signature,
        &admin_key().verifying_key(),
        parent.authorization(),
        now(),
    )
    .unwrap();
    f.store.install_fused_planning_v04(verified, now()).unwrap();
    let mut input = f.input(40, 1, 1);
    f.attach(&mut input, 50);
    let head = f.store.current_head;
    assert!(f.prepare(&input).is_err());
    assert_eq!(f.store.current_head, head);
    assert!(f.store.snapshot.dispatch.entries.is_empty());
    assert_eq!(f.usage(), (0, 0));
}

struct Input {
    id: ActionIntentIdV2,
    semantic: Digest32V2,
    request: TaskDispatchAuthorizationV2,
    plaintext: Option<Vec<u8>>,
}
struct Fixture {
    dir: tempfile::TempDir,
    anchor: TestRollbackProtectedStateAnchorV2,
    store: DurableG4StateV2,
    profile: ContinuationStorageProfileV04,
    policy: ContinuationDispatchPolicyV04,
    managed_keys: Vec<ResourceKey>,
    bridge: bool,
}
impl Fixture {
    fn new() -> Self {
        Self::build(false)
    }
    fn build(managed: bool) -> Self {
        Self::build_mode(managed, false, false)
    }
    fn build_mode(managed: bool, bridge: bool, projection: bool) -> Self {
        Self::build_with_storage(managed, bridge, projection, true)
    }
    fn build_with_storage(managed: bool, bridge: bool, projection: bool, storage: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let anchor = TestRollbackProtectedStateAnchorV2::default();
        let mut store = task_store(
            &dir.path().join(STATE_FILE_NAME),
            [0x81; 32],
            anchor.clone(),
        );
        let managed_keys = if managed {
            let mut source = managed_tests::source_policy();
            if projection {
                source.execution_projection = Some(ManagedInputProjectionV04::Utf8PayloadV1);
            }
            store
                .install_managed_source_v04(managed_tests::verified_source(source), now())
                .unwrap();
            (0..2)
                .map(|_| {
                    store
                        .create_managed_resource_v04(
                            [33; 32],
                            [34; 32],
                            "same display name",
                            b"private initial bytes",
                            now(),
                        )
                        .unwrap()
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let implementation = crate::v2::validator_tests::implementation(
            InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
            0x82,
        );
        let (template, _) =
            crate::v2::validator_tests::evaluation_fixture(vec![implementation.declaration()]);
        let mut clauses: Vec<_> = (1..=2)
            .map(|id| {
                task_clause(
                    id,
                    if bridge {
                        handoff_tests::business(
                            managed_keys[id as usize - 1],
                            b"private initial bytes",
                        )
                        .action_alternative(template.binding().tool_descriptor_digest())
                        .unwrap()
                    } else {
                        ActionAlternativeV2::new(
                            template.binding().tool_descriptor_digest(),
                            ActionCodecProfileV2::FixedJsonPostV1,
                            TaskEffectV2::Update,
                            if managed {
                                managed_resource_selector_digest_v04(
                                    d(23),
                                    managed_keys[id as usize - 1],
                                )
                                .unwrap()
                            } else {
                                d(20 + id as u8)
                            },
                            d(23),
                            d(24),
                            MagnitudeUnitV2::Count,
                        )
                        .unwrap()
                    },
                    100,
                    100,
                    vec![],
                    true,
                )
            })
            .collect();
        clauses.push(task_clause(
            3,
            crate::v2::durable_tests::release_action(
                crate::v2::dispatch::final_release_binding_for_test(0x91, [13; 32]),
            ),
            100,
            100,
            vec![],
            true,
        ));
        let auth = signed_task(task(), 1, clauses);
        store
            .install_verified_task_authorization(auth.clone())
            .unwrap();
        let profile = ContinuationStorageProfileV04 {
            schema: 1,
            installation: [2; 32],
            task: [5; 32],
            parent_authorization: *auth.digest().as_bytes(),
            not_before: 1,
            expires_at: 1000,
            observer_scope: [31; 32],
            renderer: [32; 32],
            domains: vec![
                DomainLimit {
                    domain: 1,
                    total: 2,
                    per_resource: 1,
                },
                DomainLimit {
                    domain: 2,
                    total: 10,
                    per_resource: 10,
                },
            ],
            max_executions: 4,
            slots: vec![Slot {
                id: 1,
                logical_round: 1,
                projection: Projection::PublicConstant(b"pending".to_vec()),
            }],
        };
        let signature = admin_key()
            .sign(&profile.signing_digest().unwrap())
            .to_bytes();
        if storage {
            store
                .install_continuation_storage_v04(
                    VerifiedContinuationStorageV04::verify(
                        &serde_json::to_vec(&profile).unwrap(),
                        &signature,
                        &admin_key().verifying_key(),
                        &auth,
                        now(),
                    )
                    .unwrap(),
                    now(),
                )
                .unwrap();
        }
        let policy = ContinuationDispatchPolicyV04 {
            schema: 1,
            task: [5; 32],
            storage_profile: profile.signing_digest().unwrap(),
            resource_issuer: resource_key().verifying_key().to_bytes(),
            source: [33; 32],
            namespace: [34; 32],
            not_before: 1,
            expires_at: 1000,
            max_evidence_age_ms: 50,
            charges: vec![
                ContinuationChargeRuleV04 {
                    domain: 1,
                    basis: ContinuationChargeBasisV04::PerExecution { amount: 1 },
                },
                ContinuationChargeRuleV04 {
                    domain: 2,
                    basis: ContinuationChargeBasisV04::Magnitude {
                        unit: ContinuationMagnitudeV04::Count,
                        multiplier: 4,
                    },
                },
            ],
        };
        Self {
            dir,
            anchor,
            store,
            profile,
            policy,
            managed_keys,
            bridge,
        }
    }
    fn verified_policy(&self) -> VerifiedContinuationDispatchPolicyV04 {
        let signature = admin_key()
            .sign(&self.policy.signing_digest().unwrap())
            .to_bytes();
        VerifiedContinuationDispatchPolicyV04::verify(
            &serde_json::to_vec(&self.policy).unwrap(),
            &signature,
            &admin_key().verifying_key(),
            &self.profile,
            now(),
        )
        .unwrap()
    }
    fn activate(&mut self) -> Result<(), G4Error> {
        self.store
            .install_continuation_dispatch_policy_v04(self.verified_policy(), now())
    }
    fn input(&mut self, id: u8, clause: u64, magnitude: u64) -> Input {
        let implementation = crate::v2::validator_tests::implementation(
            InternalValidatorImplementationKindV2::ProjectionBindingIntegrity,
            0x82,
        );
        let registry =
            VerifiedInternalValidatorRegistryV2::from_build_manifest(vec![implementation.clone()])
                .unwrap();
        let (_, stored) = crate::v2::validator_tests::evaluation_fixture(vec![]);
        let binding = ToolExecutionSemanticBindingV2::from_verified_authorization(
            PlanRevisionDigestV2::new([6; 32]),
            InternalStepIdV2::new([id; 32]),
            d(7),
            stored.argument_digest(),
            stored.provenance_set_digest(),
            stored.token_set_digest(),
            d(10),
            d(11),
            d(12),
            ExecutorIdentityV2::new([13; 32]),
            AttemptKindV2::ToolWrite,
        )
        .unwrap();
        let business = self.bridge.then(|| {
            handoff_tests::business(
                self.managed_keys[clause as usize - 1],
                b"private initial bytes",
            )
        });
        let request = task_request(
            &self.store,
            task(),
            clause,
            magnitude,
            business
                .as_ref()
                .map_or(binding.argument_digest(), |b| b.payload_digest()),
            binding.provenance_set_digest(),
            d(6),
        );
        let material = VerifiedActionIntentMaterialV2::new_for_test_with_validators(
            binding,
            vec![],
            6,
            vec![implementation.declaration()],
        );
        let semantic = tool_execution_semantic_binding_digest_v2(material.binding()).unwrap();
        let proposal = VerifiedToolProposalV2::from_authenticated_decoded_request(
            RequestIdV2::new([id; 16]),
            &[id],
            d(2),
            d(3),
            DurableRunIdV2::new([4; 32]),
            task(),
            &material,
        )
        .unwrap();
        let intent = self
            .store
            .create_or_replay_intent(proposal, material)
            .unwrap();
        self.store
            .evaluate_g5(
                &registry,
                intent.action_intent_id(),
                &stored,
                OntologyEvaluationV2::Match,
                G5PolicyDispositionV2::permit_for_test(),
            )
            .unwrap();
        let plaintext = business.map(|b| {
            savana_kernel_protocol::v2::encode_task_execution_payload_v2(
                &savana_kernel_protocol::v2::TaskExecutionPayloadV2::new(
                    request.matched.content().clone(),
                    b,
                )
                .unwrap(),
            )
            .unwrap()
        });
        Input {
            id: intent.action_intent_id(),
            semantic,
            request,
            plaintext,
        }
    }
    fn fact(&self, input: &Input, object: u8) -> ContinuationResourceFactV04 {
        ContinuationResourceFactV04 {
            schema: 1,
            policy: self.policy.signing_digest().unwrap(),
            action_content: *action_content_digest_v2(input.request.matched.content())
                .unwrap()
                .as_bytes(),
            resource: ResourceKey {
                source: [33; 32],
                namespace: [34; 32],
                object: [object; 32],
                incarnation: 0,
            },
            issued_at: 1,
            expires_at: 100,
            managed_revision: None,
        }
    }
    fn attach(&self, input: &mut Input, object: u8) {
        input.request = input
            .request
            .clone()
            .with_continuation_resource(sign_fact(self.fact(input, object), resource_key()));
    }
    fn prepare(&mut self, input: &Input) -> Result<KernelPreparedDispatchV2, G4Error> {
        self.prepare_at(input, now(), 100)
    }
    fn prepare_at(
        &mut self,
        input: &Input,
        time: UnixMillisV2,
        quota: u32,
    ) -> Result<KernelPreparedDispatchV2, G4Error> {
        self.store.prepare_task_bound_tool_dispatch(
            input.id,
            VerifiedQuotaLimitV2::new_for_test(quota, 0x85, subject()),
            None,
            ResolvedExecutionTicketV2::from_resolved_kernel_ticket(
                Digest32V2::new(*input.id.as_bytes()),
                input.id,
                input.semantic,
            )
            .unwrap(),
            VerifiedEffectGateLeaseV2::from_authenticated_ledger(
                d(2),
                d(3),
                7,
                8,
                false,
                ExecutorIdentityV2::new([13; 32]),
                HpkeX25519KeyIdV2::new([0x83; 32]),
                &shared_connector_registry(0x84),
                UnixMillisV2::new(10_000),
            )
            .unwrap(),
            input.plaintext.as_ref().map_or(d(0x87), |p| {
                savana_kernel_protocol::v2::presealed_tool_payload_digest_v2(p, d(0x88))
            }),
            &input.request,
            time,
        )
    }
    fn reopen(self) -> Self {
        let Self {
            dir,
            anchor,
            store,
            profile,
            policy,
            managed_keys,
            bridge,
        } = self;
        drop(store);
        let store = task_store(
            &dir.path().join(STATE_FILE_NAME),
            [0x81; 32],
            anchor.clone(),
        );
        Self {
            dir,
            anchor,
            store,
            profile,
            policy,
            managed_keys,
            bridge,
        }
    }
    fn usage(&self) -> (u64, u64) {
        let view = self.store.continuation_storage_v04(task()).unwrap();
        (view.ledger.usage(1).unwrap(), view.ledger.usage(2).unwrap())
    }
}
fn sign_fact(
    fact: ContinuationResourceFactV04,
    key: SigningKey,
) -> ContinuationResourceEvidenceV04 {
    let signature = key.sign(&fact.signing_digest().unwrap()).to_bytes();
    ContinuationResourceEvidenceV04::from_signed(&serde_json::to_vec(&fact).unwrap(), &signature)
        .unwrap()
}

#[test]
fn continuation_g7_commits_all_ledgers_and_original_handoff_once() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    assert_eq!(f.store.snapshot.payload_schema, 6);
    let mut input = f.input(40, 1, 1);
    f.attach(&mut input, 50);
    let head = f.store.current_head;
    let prepared = f.prepare(&input).unwrap();
    assert_eq!(f.store.current_head.sequence, head.sequence + 1);
    assert_eq!(f.usage(), (1, 4));
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((1, 1))
    );
    assert_eq!(
        f.store
            .quota_counter(DurableRunIdV2::new([4; 32]), subject())
            .unwrap()
            .reserved(),
        1
    );
    let view = f.store.continuation_storage_v04(task()).unwrap();
    let execution = *prepared.preparation().execution_nonce().as_bytes();
    assert_eq!(
        view.ledger.reservation(&execution).unwrap().resource.object,
        [50; 32]
    );
    let mut f = f.reopen();
    let head = f.store.current_head;
    // Replay refers to retained evidence, not a new issuer lookup/charge.
    input.request.continuation_resource = None;
    let replay = f.prepare_at(&input, UnixMillisV2::new(101), 100).unwrap();
    assert_eq!(
        replay.preparation().kind(),
        DispatchPreparationKindV2::Replay
    );
    assert_eq!(replay.core(), prepared.core());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn continuation_g7_rejects_missing_wrong_key_scope_action_and_freshness() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut input = f.input(40, 1, 1);
    let head = f.store.current_head;
    assert!(f.prepare(&input).is_err());
    for case in 0..8 {
        let mut fact = f.fact(&input, 50);
        let key = if case == 0 {
            admin_key()
        } else {
            resource_key()
        };
        match case {
            1 => fact.policy = [99; 32],
            2 => fact.resource.source = [99; 32],
            3 => fact.resource.namespace = [99; 32],
            4 => fact.action_content = [99; 32],
            5 => fact.issued_at = 11,
            6 => fact.expires_at = 10,
            7 => fact.expires_at = 1001,
            _ => (),
        }
        input.request.continuation_resource = Some(sign_fact(fact, key));
        assert!(f.prepare(&input).is_err(), "case {case}");
        assert_eq!(f.store.current_head, head);
        assert_eq!(f.usage(), (0, 0));
    }
    f.attach(&mut input, 50);
    assert!(f.prepare_at(&input, UnixMillisV2::new(60), 100).is_err());
    assert_eq!(f.store.current_head, head);
    assert!(f.store.recovery_projection().unwrap().is_empty());
}

#[test]
fn continuation_g7_alias_and_new_step_cannot_reset_resource_consumption() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut first = f.input(40, 1, 1);
    f.attach(&mut first, 50);
    f.prepare(&first).unwrap();
    // A different, root-authorized resource selector maps to the same object.
    let mut alias = f.input(41, 2, 1);
    f.attach(&mut alias, 50);
    let head = f.store.current_head;
    assert!(f.prepare(&alias).is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
    // Only the pinned issuer may establish that it is genuinely another object.
    f.attach(&mut alias, 51);
    f.prepare(&alias).unwrap();
    assert_eq!(f.usage(), (2, 8));
    let mut third = f.input(42, 1, 1);
    f.attach(&mut third, 52);
    assert!(f.prepare(&third).is_err());
    assert_eq!(f.usage(), (2, 8));
}

#[test]
fn continuation_g7_precommit_failure_and_multidomain_limit_are_atomic() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut input = f.input(40, 1, 3);
    f.attach(&mut input, 50);
    let head = f.store.current_head;
    assert!(f.prepare(&input).is_err()); // domain 2 = 12 > 10
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (0, 0));
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(1),
        Some((0, 0))
    );
    let mut input = f.input(41, 1, 1);
    f.attach(&mut input, 50);
    let head = f.store.current_head;
    f.store
        .set_before_next_commit_hook_for_test(|| Err(G4Error::DurableStateIo));
    assert!(matches!(f.prepare(&input), Err(G4Error::DurableStateIo)));
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (0, 0));
    assert!(f.store.recovery_projection().unwrap().is_empty());
    f.prepare(&input).unwrap();
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn continuation_g7_cannot_enable_over_past_execution_or_change_policy() {
    let mut f = Fixture::new();
    let input = f.input(40, 1, 1);
    f.prepare(&input).unwrap();
    let head = f.store.current_head;
    assert!(f.activate().is_err());
    assert_eq!(f.store.current_head, head);
    let mut f = Fixture::new();
    f.activate().unwrap();
    let head = f.store.current_head;
    f.activate().unwrap();
    assert_eq!(f.store.current_head, head);
    f.policy.charges[0].basis = ContinuationChargeBasisV04::PerExecution { amount: 2 };
    assert!(f.activate().is_err());
    assert_eq!(f.store.current_head, head);
}

#[test]
fn continuation_g7_refuses_direct_bookkeeping_and_unenrolled_evidence() {
    let mut f = Fixture::new();
    let mut input = f.input(40, 1, 1);
    f.attach(&mut input, 50);
    assert!(f.prepare(&input).is_err()); // no silently ignored opt-in evidence
    f.activate().unwrap();
    let revision = f.store.continuation_storage_v04(task()).unwrap().revision;
    let fact = f.fact(&input, 50);
    assert!(f
        .store
        .update_continuation_storage_v04(
            task(),
            revision,
            vec![ContinuationStorageUpdateV04::RecordReservation(
                savana_continuation_core::ledger::Reservation {
                    execution: [55; 32],
                    request_binding: [56; 32],
                    resource: fact.resource,
                    charges: vec![
                        savana_continuation_core::ledger::Charge {
                            domain: 1,
                            amount: 1
                        },
                        savana_continuation_core::ledger::Charge {
                            domain: 2,
                            amount: 4
                        }
                    ]
                }
            )],
            now()
        )
        .is_err());
    assert_eq!(f.usage(), (0, 0));
    f.prepare(&input).unwrap();
}

#[test]
fn continuation_g7_reopen_validation_requires_exact_bijection() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut input = f.input(40, 1, 1);
    f.attach(&mut input, 50);
    f.prepare(&input).unwrap();
    let mut broken = f.store.snapshot.clone();
    broken.dispatch.entries.clear();
    assert!(validate_snapshot(&broken).is_err());
    let mut broken = f.store.snapshot.clone();
    broken.dispatch.entries[0].sealed_envelope_digest = d(99);
    assert!(validate_snapshot(&broken).is_err());
    let mut broken = f.store.snapshot.clone();
    broken.payload_schema = 5;
    assert!(validate_snapshot(&broken).is_err());
    let bytes = encode_snapshot_payload(&f.store.snapshot).unwrap();
    let restored = decode_snapshot_payload(&bytes).unwrap();
    validate_snapshot(&restored).unwrap();
    assert_eq!(*encode_snapshot_payload(&restored).unwrap(), *bytes);
}

#[test]
fn continuation_g7_revocation_expiry_and_changed_replay_evidence_fail_closed() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut input = f.input(40, 1, 1);
    f.attach(&mut input, 50);
    f.prepare(&input).unwrap();
    let head = f.store.current_head;
    f.attach(&mut input, 51);
    assert!(f.prepare(&input).is_err());
    assert_eq!(f.store.current_head, head);
    input.request.continuation_resource = None;
    assert!(f.prepare_at(&input, UnixMillisV2::new(1000), 100).is_err());
    f.store.revoke_task_authorization(task()).unwrap();
    assert!(f.prepare(&input).is_err());
    assert_eq!(f.usage(), (1, 4));
    assert_eq!(f.reopen().usage(), (1, 4));
}

#[test]
fn continuation_g7_policy_signature_and_complete_domain_rules_are_mandatory() {
    let f = Fixture::new();
    let bytes = serde_json::to_vec(&f.policy).unwrap();
    let sig = admin_key()
        .sign(&f.policy.signing_digest().unwrap())
        .to_bytes();
    let verify = |bytes: &[u8], key: &ed25519_dalek::VerifyingKey| {
        VerifiedContinuationDispatchPolicyV04::verify(bytes, &sig, key, &f.profile, now())
    };
    assert!(verify(&bytes, &resource_key().verifying_key()).is_err());
    let mut whitespace = bytes.clone();
    whitespace.push(b' ');
    assert!(verify(&whitespace, &admin_key().verifying_key()).is_err());
    let mut changed = f.policy.clone();
    changed.max_evidence_age_ms += 1;
    assert!(verify(
        &serde_json::to_vec(&changed).unwrap(),
        &admin_key().verifying_key()
    )
    .is_err());
    for kind in 0..6 {
        let mut changed = f.policy.clone();
        match kind {
            0 => {
                changed.charges.pop();
            }
            1 => changed.storage_profile = [99; 32],
            2 => changed.task = [99; 32],
            3 => changed.expires_at = 1001,
            4 => changed.not_before = 0,
            5 => changed.charges[1].domain = 3,
            _ => unreachable!(),
        }
        let sig = admin_key()
            .sign(&changed.signing_digest().unwrap())
            .to_bytes();
        assert!(
            VerifiedContinuationDispatchPolicyV04::verify(
                &serde_json::to_vec(&changed).unwrap(),
                &sig,
                &admin_key().verifying_key(),
                &f.profile,
                now()
            )
            .is_err(),
            "case {kind}"
        );
    }
    let mut changed = f.policy.clone();
    changed.charges[1].domain = 1;
    assert!(changed.signing_digest().is_err());
    changed = f.policy.clone();
    changed.max_evidence_age_ms = 0;
    assert!(changed.signing_digest().is_err());
    assert!(verify(&bytes, &admin_key().verifying_key()).is_ok());
}

#[test]
fn continuation_g7_cost_unit_and_arithmetic_are_checked_not_model_supplied() {
    for basis in [
        ContinuationChargeBasisV04::Magnitude {
            unit: ContinuationMagnitudeV04::Bytes,
            multiplier: 1,
        },
        ContinuationChargeBasisV04::Magnitude {
            unit: ContinuationMagnitudeV04::Count,
            multiplier: u64::MAX,
        },
    ] {
        let mut f = Fixture::new();
        f.policy.charges[1].basis = basis;
        f.activate().unwrap();
        let mut input = f.input(40, 1, 2);
        f.attach(&mut input, 50);
        let head = f.store.current_head;
        assert!(f.prepare(&input).is_err());
        assert_eq!(f.store.current_head, head);
        assert_eq!(f.usage(), (0, 0));
    }
}

#[test]
fn continuation_g7_original_quota_failure_also_rolls_back_new_debit() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let mut a = f.input(40, 1, 1);
    f.attach(&mut a, 50);
    f.prepare_at(&a, now(), 1).unwrap();
    let mut b = f.input(41, 2, 1);
    f.attach(&mut b, 51);
    let head = f.store.current_head;
    assert!(f.prepare_at(&b, now(), 1).is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
    assert_eq!(
        f.store
            .task_authorization_state(task())
            .unwrap()
            .clause_consumption(2),
        Some((0, 0))
    );
    assert_eq!(f.store.recovery_projection().unwrap().len(), 1);
}

#[test]
fn continuation_g7_activation_never_reinterprets_unlinked_bookkeeping() {
    let mut f = Fixture::new();
    f.store
        .update_continuation_storage_v04(
            task(),
            1,
            vec![ContinuationStorageUpdateV04::RecordReservation(
                savana_continuation_core::ledger::Reservation {
                    execution: [55; 32],
                    request_binding: [56; 32],
                    resource: ResourceKey {
                        source: [33; 32],
                        namespace: [34; 32],
                        object: [50; 32],
                        incarnation: 0,
                    },
                    charges: vec![
                        savana_continuation_core::ledger::Charge {
                            domain: 1,
                            amount: 1,
                        },
                        savana_continuation_core::ledger::Charge {
                            domain: 2,
                            amount: 4,
                        },
                    ],
                },
            )],
            now(),
        )
        .unwrap();
    let head = f.store.current_head;
    assert!(f.activate().is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn continuation_g7_uncertain_commit_returns_no_handoff_and_recovers_once() {
    for after in [false, true] {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let mut input = f.input(40, 1, 1);
        f.attach(&mut input, 50);
        f.store.rollback_anchor = Box::new(super::continuation_tests::FailAnchor {
            inner: f.anchor.clone(),
            after,
        });
        assert!(matches!(
            f.prepare(&input),
            Err(G4Error::DurableCommitUncertain)
        ));
        assert!(f.store.authenticated_state_head().is_err());
        assert!(f.prepare(&input).is_err());
        let mut f = f.reopen();
        let head = f.store.current_head;
        assert_eq!(f.usage(), (1, 4));
        let p = f.prepare(&input).unwrap();
        assert_eq!(p.preparation().kind(), DispatchPreparationKindV2::Replay);
        assert_eq!(f.store.current_head, head);
        assert_eq!(f.store.recovery_projection().unwrap().len(), 1);
    }
}

#[test]
fn continuation_g7_outcomes_never_refund_stable_consumption() {
    // Trusted receipt-verification output is injected at the private test seam;
    // no production constructor for these proof fields is exposed.
    for disposition in [
        AuthenticatedEffectDispositionV2::known_success_for_test(),
        AuthenticatedEffectDispositionV2::failed_no_effect_for_test(),
        AuthenticatedEffectDispositionV2::indeterminate_for_test(),
    ] {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let mut input = f.input(40, 1, 1);
        f.attach(&mut input, 50);
        let p = f.prepare(&input).unwrap().preparation();
        let proof = VerifiedExecutorDispositionV2 {
            execution_nonce: p.execution_nonce(),
            dispatch_core_digest: p.dispatch_core_digest(),
            dispatch_subject_digest: p.dispatch_subject_digest(),
            evidence_digest: d(66),
            disposition,
        };
        f.store
            .reconcile_tool_dispatch_with_outcome(proof, true)
            .unwrap();
        assert_eq!(f.usage(), (1, 4));
        let mut f = f.reopen();
        let mut again = f.input(41, 1, 1);
        f.attach(&mut again, 50);
        assert!(f.prepare(&again).is_err());
        assert_eq!(f.usage(), (1, 4));
    }
}

#[test]
fn continuation_g7_legacy_final_release_is_explicitly_blocked_when_enrolled() {
    fn prepare_release(f: &mut Fixture) -> Result<DispatchPreparationV2, G4Error> {
        let binding = crate::v2::dispatch::final_release_binding_for_test(0x91, [13; 32]);
        let release = VerifiedFinalReleaseDispatchV2::from_verified_release(
            d(2),
            d(3),
            task(),
            DurableRunIdV2::new([4; 32]),
            binding.durable_release_id(),
            binding,
        )
        .unwrap();
        let request = task_request(
            &f.store,
            task(),
            3,
            1,
            d(0x92),
            binding.evidence_digest(),
            d(6),
        );
        f.store.prepare_final_release_dispatch(
            &release,
            VerifiedQuotaLimitV2::new_for_test(
                100,
                0x85,
                DispatchQuotaSubjectV2::final_release(binding.release_quota_subject_digest()),
            ),
            VerifiedFinalReleaseApprovalBindingV2::new_for_test(&release, 70),
            VerifiedFinalReleaseTicketV2::new_for_test(&release, 71),
            VerifiedEffectGateAuthorityV2::from_authenticated_unfenced_ledger(
                d(2),
                d(3),
                7,
                8,
                false,
                ExecutorIdentityV2::new([13; 32]),
                HpkeX25519KeyIdV2::new([0x83; 32]),
                &shared_connector_registry(0x84),
                UnixMillisV2::new(10_000),
            )
            .unwrap(),
            d(72),
            &request,
            now(),
        )
    }
    let mut legacy = Fixture::new();
    prepare_release(&mut legacy).unwrap();
    let mut enrolled = Fixture::new();
    enrolled.activate().unwrap();
    let head = enrolled.store.current_head;
    assert!(prepare_release(&mut enrolled).is_err());
    assert_eq!(enrolled.store.current_head, head);
    assert_eq!(enrolled.usage(), (0, 0));
    assert!(enrolled.store.recovery_projection().unwrap().is_empty());
}
