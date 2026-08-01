use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use savana_kernel_protocol::v2::EndpointRoleV2;
use savana_kernel_protocol::v2::UnixMillisV2;
use savana_kernel_protocol::StableCode;

use crate::policy_runtime::V2GenerationRuntime;
use crate::server::ServerLifecycle;
use crate::v2_core_services::KernelReadinessAuthorityV2;
use crate::v2_listener::{KerneldV2EndpointListener, V2ListenerError};

const WORKERS_PER_ENDPOINT_V2: usize = 2;
const CONNECTION_DEADLINE_V2: Duration = Duration::from_secs(5);
const POLL_INTERVAL_V2: Duration = Duration::from_millis(25);

pub(crate) trait V2VerifiedSuccessorPublisher {
    fn publish_next_verified_successor(&self) -> Result<(), StableCode>;
}

fn publish_requested_v2_successor(
    lifecycle: &mut dyn ServerLifecycle,
    publisher: &dyn V2VerifiedSuccessorPublisher,
) -> Result<(), StableCode> {
    if lifecycle.take_v2_rollover_request()? {
        let _ = publisher.publish_next_verified_successor();
    }
    Ok(())
}

#[cfg(test)]
const fn production_worker_roles_v2() -> [EndpointRoleV2; 4] {
    [
        EndpointRoleV2::AgentKernel,
        EndpointRoleV2::AgentKernel,
        EndpointRoleV2::IngressKernel,
        EndpointRoleV2::IngressKernel,
    ]
}

pub(crate) fn run_kerneld_v2_workers(
    agent: KerneldV2EndpointListener,
    ingress: KerneldV2EndpointListener,
    runtime: &V2GenerationRuntime,
    readiness: KernelReadinessAuthorityV2,
    lifecycle: &mut dyn ServerLifecycle,
    successor_publisher: &dyn V2VerifiedSuccessorPublisher,
) -> Result<(), StableCode> {
    agent
        .set_nonblocking()
        .map_err(|_| StableCode::KernelUnavailable)?;
    ingress
        .set_nonblocking()
        .map_err(|_| StableCode::KernelUnavailable)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    workers
        .try_reserve_exact(WORKERS_PER_ENDPOINT_V2 * 2)
        .map_err(|_| StableCode::KernelUnavailable)?;
    spawn_endpoint_workers("agent", agent, &shutdown, &failed, &mut workers)?;
    if let Err(error) = spawn_endpoint_workers("ingress", ingress, &shutdown, &failed, &mut workers)
    {
        shutdown.store(true, Ordering::Release);
        join_workers(workers)?;
        return Err(error);
    }
    if lifecycle.workers_started().is_err()
        || readiness.publish_ready().is_err()
        || lifecycle.activation_completed().is_err()
    {
        shutdown.store(true, Ordering::Release);
        join_workers(workers)?;
        return Err(StableCode::KernelUnavailable);
    }

    loop {
        if failed.load(Ordering::Acquire) {
            shutdown.store(true, Ordering::Release);
            break;
        }
        match lifecycle.poll_shutdown() {
            Ok(true) => {
                shutdown.store(true, Ordering::Release);
                break;
            }
            Ok(false) => {
                if publish_requested_v2_successor(lifecycle, successor_publisher).is_err() {
                    failed.store(true, Ordering::Release);
                    shutdown.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(POLL_INTERVAL_V2);
            }
            Err(_) => {
                failed.store(true, Ordering::Release);
                shutdown.store(true, Ordering::Release);
                break;
            }
        }
    }
    join_workers(workers)?;
    runtime.close_and_drain().map(|_| ())?;
    if failed.load(Ordering::Acquire) {
        Err(StableCode::KernelUnavailable)
    } else {
        Ok(())
    }
}

fn spawn_endpoint_workers(
    role_name: &str,
    endpoint: KerneldV2EndpointListener,
    shutdown: &Arc<AtomicBool>,
    failed: &Arc<AtomicBool>,
    workers: &mut Vec<JoinHandle<()>>,
) -> Result<(), StableCode> {
    for index in 0..WORKERS_PER_ENDPOINT_V2 {
        let worker_endpoint = endpoint
            .try_clone()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let worker_shutdown = Arc::clone(shutdown);
        let worker_failed = Arc::clone(failed);
        let name = format!("savana-kerneld-v2-{role_name}-{index}");
        let worker = thread::Builder::new()
            .name(name)
            .spawn(move || worker_loop(worker_endpoint, worker_shutdown, worker_failed))
            .map_err(|_| StableCode::KernelUnavailable)?;
        workers.push(worker);
    }
    Ok(())
}

fn worker_loop(
    endpoint: KerneldV2EndpointListener,
    shutdown: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        let now = match unix_millis_now_v2() {
            Ok(now) => now,
            Err(()) => {
                failed.store(true, Ordering::Release);
                shutdown.store(true, Ordering::Release);
                return;
            }
        };
        match endpoint.serve_one(now, Instant::now() + CONNECTION_DEADLINE_V2) {
            Ok(())
            | Err(V2ListenerError::NativeIdentity)
            | Err(V2ListenerError::DeadlineExceeded)
            | Err(V2ListenerError::Connection(_)) => {}
            Err(V2ListenerError::Idle) => thread::sleep(POLL_INTERVAL_V2),
            Err(V2ListenerError::EndpointRole | V2ListenerError::Accept) => {
                failed.store(true, Ordering::Release);
                shutdown.store(true, Ordering::Release);
                return;
            }
        }
    }
}

fn unix_millis_now_v2() -> Result<UnixMillisV2, ()> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_millis();
    let millis = u64::try_from(millis).map_err(|_| ())?;
    if millis == 0 {
        return Err(());
    }
    Ok(UnixMillisV2::new(millis))
}

fn join_workers(workers: Vec<JoinHandle<()>>) -> Result<(), StableCode> {
    let mut failed = false;
    for worker in workers {
        failed |= worker.join().is_err();
    }
    if failed {
        Err(StableCode::KernelUnavailable)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use savana_kernel_protocol::v2::EndpointRoleV2;
    use savana_kernel_protocol::StableCode;

    use super::{
        production_worker_roles_v2, publish_requested_v2_successor, V2VerifiedSuccessorPublisher,
    };
    use crate::server::ServerLifecycle;

    #[test]
    fn production_workers_are_bounded_and_isolated_per_endpoint_role() {
        assert_eq!(
            production_worker_roles_v2(),
            [
                EndpointRoleV2::AgentKernel,
                EndpointRoleV2::AgentKernel,
                EndpointRoleV2::IngressKernel,
                EndpointRoleV2::IngressKernel,
            ],
        );
    }

    struct RequestedRollover(bool);

    impl ServerLifecycle for RequestedRollover {
        fn workers_started(&mut self) -> Result<(), StableCode> {
            Ok(())
        }

        fn poll_shutdown(&mut self) -> Result<bool, StableCode> {
            Ok(false)
        }

        fn take_v2_rollover_request(&mut self) -> Result<bool, StableCode> {
            Ok(std::mem::take(&mut self.0))
        }
    }

    struct RejectingPublisher(AtomicUsize);

    impl V2VerifiedSuccessorPublisher for RejectingPublisher {
        fn publish_next_verified_successor(&self) -> Result<(), StableCode> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(StableCode::KernelUnavailable)
        }
    }

    #[test]
    fn requested_successor_publication_is_reachable_and_rejection_is_nonfatal() {
        let publisher = RejectingPublisher(AtomicUsize::new(0));
        let mut lifecycle = RequestedRollover(true);

        assert_eq!(
            publish_requested_v2_successor(&mut lifecycle, &publisher),
            Ok(())
        );
        assert_eq!(publisher.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            publish_requested_v2_successor(&mut lifecycle, &publisher),
            Ok(())
        );
        assert_eq!(publisher.0.load(Ordering::SeqCst), 1);
    }
}
