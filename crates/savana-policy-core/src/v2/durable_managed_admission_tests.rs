//! Production admission helper with real G7/store; no caller-supplied facts.
use super::*;

fn setup(projection: bool) -> (Fixture, Input) {
    let mut f = Fixture::build_mode(true, true, projection);
    f.activate().unwrap();
    let i = f.input(40, 1, 1);
    (f, i)
}
fn bind(
    f: &Fixture,
    i: &Input,
    key: Option<&SigningKey>,
) -> Result<TaskDispatchAuthorizationV2, G4Error> {
    f.store.bind_managed_dispatch_input_v04(
        i.id,
        i.request.clone(),
        i.plaintext.as_ref().unwrap(),
        key,
        now(),
    )
}

#[test]
fn managed_admission_issues_current_fact_without_debit_then_g7_pins_once() {
    let (mut f, mut i) = setup(true);
    let head = f.store.current_head;
    i.request = bind(&f, &i, Some(&resource_key())).unwrap();
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (0, 0));
    let p = f.prepare(&i).unwrap();
    check(&f, &i, &p).unwrap();
    assert_eq!(f.usage(), (1, 4));
    assert_eq!(
        f.store
            .managed_execution_snapshot_v04(
                task(),
                p.preparation().execution_nonce(),
                p.preparation().dispatch_core_digest()
            )
            .unwrap()
            .revision(),
        1
    );
}

#[test]
fn managed_admission_missing_wrong_role_and_unconfigured_keys_never_debit() {
    let (f, i) = setup(true);
    let head = f.store.current_head;
    assert!(bind(&f, &i, None).is_err());
    assert!(bind(&f, &i, Some(&admin_key())).is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (0, 0));
    let (f, i) = setup(false);
    assert!(bind(&f, &i, Some(&resource_key())).is_err());
    assert_eq!(f.usage(), (0, 0));
}

#[test]
fn managed_admission_rejects_injected_even_correctly_signed_resource_facts() {
    let (f, mut i) = setup(true);
    i.request = bind(&f, &i, Some(&resource_key())).unwrap();
    assert!(bind(&f, &i, Some(&resource_key())).is_err());
    assert_eq!(f.usage(), (0, 0));
}

#[test]
fn managed_admission_stale_content_and_tombstones_fail_before_debit() {
    for delete in [false, true] {
        let (mut f, i) = setup(true);
        f.store
            .update_managed_resource_v04(
                f.managed_keys[0],
                1,
                if delete {
                    None
                } else {
                    Some(("same display name", b"changed".as_slice()))
                },
                now(),
            )
            .unwrap();
        let head = f.store.current_head;
        assert!(bind(&f, &i, Some(&resource_key())).is_err());
        assert_eq!(f.store.current_head, head);
        assert_eq!(f.usage(), (0, 0));
    }
}

#[test]
fn managed_admission_source_change_between_issue_and_g7_is_rechecked() {
    let (mut f, mut i) = setup(true);
    i.request = bind(&f, &i, Some(&resource_key())).unwrap();
    // Even a same-content edit increments revision; an issued fact is not a lock.
    f.store
        .update_managed_resource_v04(
            f.managed_keys[0],
            1,
            Some(("renamed", b"private initial bytes")),
            now(),
        )
        .unwrap();
    let head = f.store.current_head;
    assert!(f.prepare(&i).is_err());
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (0, 0));
    i.request.continuation_resource = None;
    i.request = bind(&f, &i, Some(&resource_key())).unwrap();
    let p = f.prepare(&i).unwrap();
    assert_eq!(
        f.store
            .managed_execution_snapshot_v04(
                task(),
                p.preparation().execution_nonce(),
                p.preparation().dispatch_core_digest()
            )
            .unwrap()
            .revision(),
        2
    );
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_admission_replay_after_delete_restart_never_requires_new_fact_or_key() {
    let (mut f, mut i) = setup(true);
    let original_request = i.request.clone();
    i.request = bind(&f, &i, Some(&resource_key())).unwrap();
    let p = f.prepare(&i).unwrap();
    f.store
        .update_managed_resource_v04(f.managed_keys[0], 1, None, now())
        .unwrap();
    let mut f = f.reopen();
    i.request = original_request;
    i.request = bind(&f, &i, None).unwrap();
    assert!(i.request.continuation_resource.is_none());
    let head = f.store.current_head;
    let replay = f.prepare(&i).unwrap();
    assert_eq!(replay.core(), p.core());
    check(&f, &i, &replay).unwrap();
    assert_eq!(f.store.current_head, head);
    assert_eq!(f.usage(), (1, 4));
}

#[test]
fn managed_admission_rejects_malformed_and_substituted_plaintext() {
    let (f, i) = setup(true);
    for bytes in [vec![], vec![0; 100], {
        let mut bytes = i.plaintext.clone().unwrap();
        bytes.push(0);
        bytes
    }] {
        assert!(f
            .store
            .bind_managed_dispatch_input_v04(
                i.id,
                i.request.clone(),
                &bytes,
                Some(&resource_key()),
                now()
            )
            .is_err());
    }
    assert_eq!(f.usage(), (0, 0));
}

#[test]
fn managed_admission_same_label_does_not_resolve_another_object() {
    let (mut f, i) = setup(true);
    // The second object has identical label and bytes. Deleting the requested
    // object's immutable ID must never redirect to that other object.
    f.store
        .update_managed_resource_v04(f.managed_keys[0], 1, None, now())
        .unwrap();
    assert!(bind(&f, &i, Some(&resource_key())).is_err());
    assert!(
        !f.store
            .managed_resource_v04(f.managed_keys[1])
            .unwrap()
            .deleted
    );
}

#[test]
fn managed_admission_revoked_or_expired_roots_fail_without_issuing() {
    let (mut f, i) = setup(true);
    assert!(f
        .store
        .bind_managed_dispatch_input_v04(
            i.id,
            i.request.clone(),
            i.plaintext.as_ref().unwrap(),
            Some(&resource_key()),
            UnixMillisV2::new(1000)
        )
        .is_err());
    f.store.revoke_task_authorization(task()).unwrap();
    assert!(bind(&f, &i, Some(&resource_key())).is_err());
    assert_eq!(f.usage(), (0, 0));
}

#[test]
fn managed_admission_non_enrolled_tasks_preserve_existing_path() {
    let mut f = Fixture::new();
    let i = f.input(40, 1, 1);
    // No continuation dispatch enrollment: ordinary G3/G7 continue to own it.
    let request = f
        .store
        .bind_managed_dispatch_input_v04(i.id, i.request.clone(), &[], None, now())
        .unwrap();
    assert!(request.continuation_resource.is_none());
}

#[test]
fn managed_admission_external_sources_do_not_silently_become_managed() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let i = f.input(40, 1, 1);
    assert!(f
        .store
        .bind_managed_dispatch_input_v04(i.id, i.request.clone(), &[], Some(&resource_key()), now())
        .is_err());
    assert_eq!(f.usage(), (0, 0));
}
