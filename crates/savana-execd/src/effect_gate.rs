use std::collections::BTreeSet;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Instant;

use rustix::fs::{fcntl_getfl, fcntl_lock, fstat, FileType, FlockOperation, OFlags};
use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};
use savana_kernel_protocol::v2::{
    verify_effect_ledger_projection_v2, Digest32V2, EffectLedgerProjectionBindingV2,
    EffectLedgerProjectionErrorV2, MAX_EFFECT_LEDGER_PROJECTION_BYTES_V2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectGateErrorV2 {
    DeadlineExceeded,
    Fenced,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectGateOperationKindV2 {
    DispatchExecution,
    Recovery,
}

#[derive(Debug)]
struct EffectGateStateV2 {
    active_count: u64,
    closing: bool,
    os_lock_held: bool,
    poisoned: bool,
    active_operation_ids: BTreeSet<[u8; 32]>,
}

pub(crate) struct EffectGateCoordinatorV2 {
    descriptor: Arc<File>,
    projection: ProjectionSourceV2,
    registration: Arc<ProcessGateRegistrationV2>,
    state: Arc<Mutex<EffectGateStateV2>>,
    drained: Arc<Condvar>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct GateInodeKeyV2 {
    device: i128,
    inode: i128,
}

struct ProcessGateRegistrationV2 {
    key: GateInodeKeyV2,
}

static PROCESS_GATE_INODES_V2: OnceLock<Mutex<BTreeSet<GateInodeKeyV2>>> = OnceLock::new();
static QUARANTINED_GATE_DESCRIPTORS_V2: OnceLock<Mutex<Vec<File>>> = OnceLock::new();

enum ProjectionSourceV2 {
    Authenticated {
        descriptor: File,
        binding: Box<EffectLedgerProjectionBindingV2>,
    },
    #[cfg(test)]
    TrustedTestOnly,
}

impl std::fmt::Debug for EffectGateCoordinatorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EffectGateCoordinatorV2(<shared-only descriptor>)")
    }
}

impl EffectGateCoordinatorV2 {
    pub(crate) fn from_shared_only_descriptors(
        descriptor: File,
        projection_descriptor: File,
        projection_binding: EffectLedgerProjectionBindingV2,
    ) -> Result<Self, EffectGateErrorV2> {
        validate_read_only_regular_descriptor(&projection_descriptor)?;
        set_and_verify_cloexec(&projection_descriptor)?;
        Self::from_validated_sources(
            descriptor,
            ProjectionSourceV2::Authenticated {
                descriptor: projection_descriptor,
                binding: Box::new(projection_binding),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn from_shared_only_descriptor(descriptor: File) -> Result<Self, EffectGateErrorV2> {
        Self::from_validated_sources(descriptor, ProjectionSourceV2::TrustedTestOnly)
    }

    fn from_validated_sources(
        descriptor: File,
        projection: ProjectionSourceV2,
    ) -> Result<Self, EffectGateErrorV2> {
        let metadata = fstat(&descriptor).map_err(|_| EffectGateErrorV2::Unavailable)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_nlink != 1
        {
            return Err(EffectGateErrorV2::Unavailable);
        }
        if fcntl_getfl(&descriptor).map_err(|_| EffectGateErrorV2::Unavailable)? & OFlags::RWMODE
            != OFlags::RDONLY
        {
            return Err(EffectGateErrorV2::Unavailable);
        }
        set_and_verify_cloexec(&descriptor)?;
        let registration = match register_process_gate(&metadata) {
            Ok(registration) => registration,
            Err(error) => {
                quarantine_duplicate_gate_descriptor(descriptor);
                return Err(error);
            }
        };
        fcntl_lock(&descriptor, FlockOperation::NonBlockingLockShared)
            .map_err(|_| EffectGateErrorV2::Unavailable)?;
        fcntl_lock(&descriptor, FlockOperation::NonBlockingUnlock)
            .map_err(|_| EffectGateErrorV2::Unavailable)?;
        Ok(Self {
            descriptor: Arc::new(descriptor),
            projection,
            registration,
            state: Arc::new(Mutex::new(EffectGateStateV2 {
                active_count: 0,
                closing: false,
                os_lock_held: false,
                poisoned: false,
                active_operation_ids: BTreeSet::new(),
            })),
            drained: Arc::new(Condvar::new()),
        })
    }

    pub(crate) fn acquire(
        &self,
        operation: EffectGateOperationKindV2,
        operation_id: Digest32V2,
        deadline: Instant,
    ) -> Result<EffectGateGuardV2, EffectGateErrorV2> {
        if Instant::now() >= deadline {
            return Err(EffectGateErrorV2::DeadlineExceeded);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| EffectGateErrorV2::Unavailable)?;
        if state.poisoned {
            return Err(EffectGateErrorV2::Unavailable);
        }
        if state.closing {
            return Err(EffectGateErrorV2::Fenced);
        }
        if operation_id.as_bytes().iter().all(|byte| *byte == 0)
            || state.active_operation_ids.contains(operation_id.as_bytes())
        {
            state.poisoned = true;
            return Err(EffectGateErrorV2::Unavailable);
        }
        if state.active_count == 0 {
            fcntl_lock(
                self.descriptor.as_ref(),
                FlockOperation::NonBlockingLockShared,
            )
            .map_err(|_| EffectGateErrorV2::Unavailable)?;
            state.os_lock_held = true;
            if let Err(error) = self.projection.reread_and_validate() {
                if error == EffectGateErrorV2::Fenced {
                    state.closing = true;
                } else {
                    state.poisoned = true;
                }
                if fcntl_lock(self.descriptor.as_ref(), FlockOperation::NonBlockingUnlock).is_err()
                {
                    state.poisoned = true;
                } else {
                    state.os_lock_held = false;
                }
                return Err(error);
            }
        }
        state.active_count = state
            .active_count
            .checked_add(1)
            .ok_or(EffectGateErrorV2::Unavailable)?;
        if !state.active_operation_ids.insert(*operation_id.as_bytes())
            || state.active_operation_ids.len() as u64 != state.active_count
        {
            state.poisoned = true;
            return Err(EffectGateErrorV2::Unavailable);
        }
        Ok(EffectGateGuardV2 {
            descriptor: Arc::clone(&self.descriptor),
            registration: Arc::clone(&self.registration),
            state: Arc::clone(&self.state),
            drained: Arc::clone(&self.drained),
            operation,
            operation_id,
        })
    }

    pub(crate) fn fence(&self, deadline: Instant) -> Result<(), EffectGateErrorV2> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EffectGateErrorV2::Unavailable)?;
        if state.poisoned {
            return Err(EffectGateErrorV2::Unavailable);
        }
        if state.closing {
            return Err(EffectGateErrorV2::Fenced);
        }
        state.closing = true;
        while state.active_count != 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(EffectGateErrorV2::DeadlineExceeded);
            }
            let waited = self
                .drained
                .wait_timeout(state, remaining)
                .map_err(|_| EffectGateErrorV2::Unavailable)?;
            state = waited.0;
            if waited.1.timed_out() && state.active_count != 0 {
                return Err(EffectGateErrorV2::DeadlineExceeded);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn closing_for_test(&self) -> bool {
        self.state.lock().map(|state| state.closing).unwrap_or(true)
    }
}

fn quarantine_duplicate_gate_descriptor(descriptor: File) {
    let quarantine = QUARANTINED_GATE_DESCRIPTORS_V2.get_or_init(|| Mutex::new(Vec::new()));
    let Ok(mut descriptors) = quarantine.lock() else {
        std::mem::forget(descriptor);
        return;
    };
    if descriptors.try_reserve(1).is_err() {
        std::mem::forget(descriptor);
        return;
    }
    descriptors.push(descriptor);
}

fn register_process_gate(
    metadata: &rustix::fs::Stat,
) -> Result<Arc<ProcessGateRegistrationV2>, EffectGateErrorV2> {
    let key = GateInodeKeyV2 {
        device: i128::from(metadata.st_dev),
        inode: i128::from(metadata.st_ino),
    };
    let registry = PROCESS_GATE_INODES_V2.get_or_init(|| Mutex::new(BTreeSet::new()));
    let mut registered = registry
        .lock()
        .map_err(|_| EffectGateErrorV2::Unavailable)?;
    if !registered.insert(key) {
        return Err(EffectGateErrorV2::Unavailable);
    }
    Ok(Arc::new(ProcessGateRegistrationV2 { key }))
}

impl Drop for ProcessGateRegistrationV2 {
    fn drop(&mut self) {
        let registry = PROCESS_GATE_INODES_V2
            .get()
            .unwrap_or_else(|| std::process::abort());
        let mut registered = registry.lock().unwrap_or_else(|_| std::process::abort());
        if !registered.remove(&self.key) {
            std::process::abort();
        }
    }
}

impl ProjectionSourceV2 {
    fn reread_and_validate(&self) -> Result<(), EffectGateErrorV2> {
        match self {
            Self::Authenticated {
                descriptor,
                binding,
            } => {
                let bytes = read_fixed_projection(descriptor)?;
                verify_effect_ledger_projection_v2(&bytes, **binding)
                    .map(|_| ())
                    .map_err(|error| match error {
                        EffectLedgerProjectionErrorV2::Fenced => EffectGateErrorV2::Fenced,
                        _ => EffectGateErrorV2::Unavailable,
                    })
            }
            #[cfg(test)]
            Self::TrustedTestOnly => Ok(()),
        }
    }
}

fn validate_read_only_regular_descriptor(descriptor: &File) -> Result<(), EffectGateErrorV2> {
    let metadata = fstat(descriptor).map_err(|_| EffectGateErrorV2::Unavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || fcntl_getfl(descriptor).map_err(|_| EffectGateErrorV2::Unavailable)? & OFlags::RWMODE
            != OFlags::RDONLY
    {
        return Err(EffectGateErrorV2::Unavailable);
    }
    Ok(())
}

fn set_and_verify_cloexec(descriptor: &File) -> Result<(), EffectGateErrorV2> {
    let flags = fcntl_getfd(descriptor).map_err(|_| EffectGateErrorV2::Unavailable)?;
    fcntl_setfd(descriptor, flags | FdFlags::CLOEXEC)
        .map_err(|_| EffectGateErrorV2::Unavailable)?;
    if !fcntl_getfd(descriptor)
        .map_err(|_| EffectGateErrorV2::Unavailable)?
        .contains(FdFlags::CLOEXEC)
    {
        return Err(EffectGateErrorV2::Unavailable);
    }
    Ok(())
}

fn read_fixed_projection(descriptor: &File) -> Result<Vec<u8>, EffectGateErrorV2> {
    let before = fstat(descriptor).map_err(|_| EffectGateErrorV2::Unavailable)?;
    let length = usize::try_from(before.st_size).map_err(|_| EffectGateErrorV2::Unavailable)?;
    if length == 0 || length > MAX_EFFECT_LEDGER_PROJECTION_BYTES_V2 {
        return Err(EffectGateErrorV2::Unavailable);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| EffectGateErrorV2::Unavailable)?;
    bytes.resize(length, 0);
    let mut offset = 0usize;
    while offset < length {
        let read = descriptor
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|_| EffectGateErrorV2::Unavailable)?;
        if read == 0 {
            return Err(EffectGateErrorV2::Unavailable);
        }
        offset = offset
            .checked_add(read)
            .ok_or(EffectGateErrorV2::Unavailable)?;
    }
    let after = fstat(descriptor).map_err(|_| EffectGateErrorV2::Unavailable)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_nlink != after.st_nlink
        || before.st_size != after.st_size
    {
        return Err(EffectGateErrorV2::Unavailable);
    }
    Ok(bytes)
}

pub(crate) struct EffectGateGuardV2 {
    descriptor: Arc<File>,
    registration: Arc<ProcessGateRegistrationV2>,
    state: Arc<Mutex<EffectGateStateV2>>,
    drained: Arc<Condvar>,
    operation: EffectGateOperationKindV2,
    operation_id: Digest32V2,
}

impl std::fmt::Debug for EffectGateGuardV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectGateGuardV2")
            .field("operation", &self.operation)
            .field("operation_id", &self.operation_id)
            .field(
                "process_gate_registration",
                &Arc::strong_count(&self.registration),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for EffectGateGuardV2 {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|_| std::process::abort());
        if !state
            .active_operation_ids
            .remove(self.operation_id.as_bytes())
        {
            std::process::abort();
        }
        state.active_count = state
            .active_count
            .checked_sub(1)
            .unwrap_or_else(|| std::process::abort());
        if state.active_operation_ids.len() as u64 != state.active_count {
            std::process::abort();
        }
        if state.active_count == 0 {
            if !state.os_lock_held {
                std::process::abort();
            }
            if fcntl_lock(self.descriptor.as_ref(), FlockOperation::NonBlockingUnlock).is_err() {
                state.poisoned = true;
            } else {
                state.os_lock_held = false;
            }
            self.drained.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::process::Command;
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::{Duration, Instant};

    use rustix::fs::{fcntl_lock, FlockOperation};
    use savana_kernel_protocol::v2::Digest32V2;
    use tempfile::tempdir;

    use super::{EffectGateCoordinatorV2, EffectGateErrorV2, EffectGateOperationKindV2};

    const CHILD_PATH_ENV: &str = "SAVANA_EXECD_EFFECT_GATE_CHILD_PATH";
    const CHILD_EXPECT_ENV: &str = "SAVANA_EXECD_EFFECT_GATE_CHILD_EXPECT";

    #[test]
    fn overlapping_dispatch_guards_keep_the_os_gate_shared_locked() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("effect-gate-v2");
        let file = create_read_only_gate(&path);
        let coordinator = EffectGateCoordinatorV2::from_shared_only_descriptor(file).unwrap();
        let first = coordinator
            .acquire(
                EffectGateOperationKindV2::DispatchExecution,
                Digest32V2::new([1; 32]),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let second = coordinator
            .acquire(
                EffectGateOperationKindV2::Recovery,
                Digest32V2::new([2; 32]),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        run_child_probe(&path, false);
        drop(first);
        run_child_probe(&path, false);
        drop(second);
        run_child_probe(&path, true);
    }

    #[test]
    fn fence_intent_blocks_new_dispatch_and_waits_for_the_last_guard() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("effect-gate-v2");
        let file = create_read_only_gate(&path);
        let coordinator =
            Arc::new(EffectGateCoordinatorV2::from_shared_only_descriptor(file).unwrap());
        let active = coordinator
            .acquire(
                EffectGateOperationKindV2::DispatchExecution,
                Digest32V2::new([1; 32]),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let fenced = Arc::clone(&coordinator);
        let closer = thread::spawn(move || {
            started_tx.send(()).unwrap();
            fenced.fence(Instant::now() + Duration::from_secs(5))
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !coordinator.closing_for_test() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(
            coordinator
                .acquire(
                    EffectGateOperationKindV2::Recovery,
                    Digest32V2::new([2; 32]),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap_err(),
            EffectGateErrorV2::Fenced
        );
        drop(active);
        assert_eq!(closer.join().unwrap(), Ok(()));
    }

    #[test]
    fn duplicate_execution_operation_id_is_rejected_without_releasing_the_first_hold() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("effect-gate-v2");
        let file = create_read_only_gate(&path);
        let coordinator = EffectGateCoordinatorV2::from_shared_only_descriptor(file).unwrap();
        let operation_id = Digest32V2::new([9; 32]);
        let guard = coordinator
            .acquire(
                EffectGateOperationKindV2::DispatchExecution,
                operation_id,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(
            coordinator
                .acquire(
                    EffectGateOperationKindV2::Recovery,
                    operation_id,
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap_err(),
            EffectGateErrorV2::Unavailable
        );
        run_child_probe(&path, false);
        drop(guard);
        run_child_probe(&path, true);
    }

    #[test]
    fn a_second_process_local_coordinator_for_the_same_inode_is_rejected_before_lock_probe() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("effect-gate-v2");
        let first_file = create_read_only_gate(&path);
        let second_file = OpenOptions::new().read(true).open(&path).unwrap();
        let coordinator = EffectGateCoordinatorV2::from_shared_only_descriptor(first_file).unwrap();
        let guard = coordinator
            .acquire(
                EffectGateOperationKindV2::DispatchExecution,
                Digest32V2::new([0xa1; 32]),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(
            EffectGateCoordinatorV2::from_shared_only_descriptor(second_file).unwrap_err(),
            EffectGateErrorV2::Unavailable
        );
        run_child_probe(&path, false);
        drop(guard);
        run_child_probe(&path, true);
    }

    #[test]
    fn child_process_effect_gate_probe() {
        let Ok(path) = std::env::var(CHILD_PATH_ENV) else {
            return;
        };
        let expected_available = std::env::var(CHILD_EXPECT_ENV).unwrap() == "available";
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let available = fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive).is_ok();
        assert_eq!(available, expected_available);
    }

    fn run_child_probe(path: &std::path::Path, expected_available: bool) {
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("effect_gate::tests::child_process_effect_gate_probe")
            .arg("--nocapture")
            .env(CHILD_PATH_ENV, path)
            .env(
                CHILD_EXPECT_ENV,
                if expected_available {
                    "available"
                } else {
                    "blocked"
                },
            )
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn create_read_only_gate(path: &std::path::Path) -> File {
        drop(File::create(path).unwrap());
        OpenOptions::new().read(true).open(path).unwrap()
    }
}
