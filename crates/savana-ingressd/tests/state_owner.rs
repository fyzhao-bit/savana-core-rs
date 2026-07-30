use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use savana_ingressd::{
    IngressBrowserContextV2, IngressServiceV2, IngressStateOwnerErrorV2, IngressStateOwnerV2,
    VerifiedIngressUiAuthorizationV2,
};
use savana_kernel_protocol::v2::{
    BootIdV2, Digest32V2, PrincipalIdV2, ServiceIdentityV2, UnixMillisV2,
};

#[test]
fn concurrent_browser_admission_is_serialized_by_the_bounded_owner() {
    let boot = BootIdV2::new([3; 32]);
    let service = IngressServiceV2::from_verified_deployment(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        boot,
        ServiceIdentityV2::new([4; 32]),
        BootIdV2::new([5; 32]),
        ServiceIdentityV2::new([6; 32]),
        128,
        1024,
    )
    .unwrap();
    let owner = Arc::new(IngressStateOwnerV2::spawn(service, 16).unwrap());
    let context = IngressBrowserContextV2::from_authenticated_origin(
        boot,
        Digest32V2::new([7; 32]),
        UnixMillisV2::new(10_000),
    )
    .unwrap();

    let callers = (0..64)
        .map(|index| {
            let owner = Arc::clone(&owner);
            thread::spawn(move || {
                let mut binding = [0_u8; 32];
                binding[..8].copy_from_slice(&(index + 1_u64).to_be_bytes());
                let authorization = VerifiedIngressUiAuthorizationV2::from_verified_ui_settlement(
                    PrincipalIdV2::new([8; 32]),
                    Digest32V2::new([9; 32]),
                    Digest32V2::new(binding),
                    UnixMillisV2::new(9_000),
                )
                .unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match owner.open_authenticated_tab(
                        authorization,
                        context,
                        UnixMillisV2::new(100),
                        deadline,
                    ) {
                        Err(IngressStateOwnerErrorV2::Busy) => thread::yield_now(),
                        outcome => break outcome,
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    assert_eq!(
        callers
            .into_iter()
            .map(|caller| caller.join().unwrap())
            .filter(Result::is_ok)
            .count(),
        64
    );
}
