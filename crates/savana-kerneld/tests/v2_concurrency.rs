mod v2_release_support;

use std::sync::{Arc, Barrier};
use std::thread;

use savana_execd::ExecdJournalStateV2;
use savana_kernel_protocol::v2::Nonce32V2;

use v2_release_support::{deadline, now, ExecdCrashFixture};

#[test]
fn one_owner_serializes_128_concurrent_exact_dispatch_replays() {
    let fixture = ExecdCrashFixture::new();
    let owner = Arc::new(fixture.open_owner(128));
    let nonce = Nonce32V2::new([0x71; 32]);
    let envelope = Arc::new(fixture.signed_tool_envelope(nonce));
    let barrier = Arc::new(Barrier::new(128));
    let mut workers = Vec::with_capacity(128);

    for _ in 0..128 {
        let owner = Arc::clone(&owner);
        let envelope = Arc::clone(&envelope);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            owner.accept_signed_dispatch(envelope.as_ref().clone(), now(200), deadline())
        }));
    }

    for worker in workers {
        let response = worker.join().unwrap().unwrap();
        assert_eq!(response.execution_nonce(), nonce);
        assert_eq!(response.state(), ExecdJournalStateV2::Prepared);
    }
    assert_eq!(
        owner.recovery_projection(deadline()).unwrap().len(),
        1,
        "concurrent exact replay must create one durable nonce only"
    );
}
