use std::fs::{self, File};
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use savana_openclaw_release::{
    ReleaseReceiver, ReleaseReceiverConfig, ReleaseReceiverError, ReleaseReservationStore,
    ReservationError, ReservationId,
};
use zeroize::Zeroizing;

const MAX_CERTIFICATE_BYTES: u64 = 128 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
const MAX_RESERVATION_DURATION: Duration = Duration::from_secs(300);
const RECEIVER_POLL: Duration = Duration::from_millis(250);
const DELIVERY_POLL: Duration = Duration::from_millis(10);

#[pyclass(name = "_ReleaseReservation", module = "savana_core", frozen)]
struct PyReleaseReservation {
    id: ReservationId,
    store: Arc<ReleaseReservationStore>,
}

#[pymethods]
impl PyReleaseReservation {
    fn __repr__(&self) -> &'static str {
        "_ReleaseReservation(<opaque>)"
    }
}

#[pyclass(name = "_ReleaseReceiver", module = "savana_core", frozen)]
struct PyReleaseReceiver {
    store: Arc<ReleaseReservationStore>,
    canonical_url: String,
    worker: Arc<ReceiverWorker>,
}

#[pymethods]
impl PyReleaseReceiver {
    #[new]
    #[pyo3(signature = (
        journal_path,
        canonical_host,
        listen_port,
        client_root_certificate_path,
        server_certificate_path,
        server_private_key_path,
        expected_client_spki_pin
    ))]
    fn new(
        journal_path: PathBuf,
        canonical_host: String,
        listen_port: u16,
        client_root_certificate_path: PathBuf,
        server_certificate_path: PathBuf,
        server_private_key_path: PathBuf,
        expected_client_spki_pin: Vec<u8>,
    ) -> PyResult<Self> {
        if listen_port == 0 {
            return Err(PyValueError::new_err(
                "release receiver port must be a fixed nonzero port",
            ));
        }
        require_absolute(&journal_path)?;
        require_absolute(&client_root_certificate_path)?;
        require_absolute(&server_certificate_path)?;
        require_absolute(&server_private_key_path)?;
        require_private_key_permissions(&server_private_key_path)?;
        let expected_client_spki_pin: [u8; 32] = expected_client_spki_pin
            .try_into()
            .map_err(|_| PyValueError::new_err("client SPKI pin must be exactly 32 bytes"))?;
        let client_root_certificate =
            read_bounded(&client_root_certificate_path, MAX_CERTIFICATE_BYTES)?;
        let server_certificate = read_bounded(&server_certificate_path, MAX_CERTIFICATE_BYTES)?;
        let server_private_key = Zeroizing::new(read_bounded(
            &server_private_key_path,
            MAX_PRIVATE_KEY_BYTES,
        )?);
        let config = ReleaseReceiverConfig::new(
            canonical_host,
            client_root_certificate,
            vec![server_certificate],
            server_private_key,
            expected_client_spki_pin,
        )
        .map_err(map_receiver_error)?;
        let store =
            Arc::new(ReleaseReservationStore::open(&journal_path).map_err(map_reservation_error)?);
        let receiver = ReleaseReceiver::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port),
            config,
            Arc::clone(&store),
        )
        .map_err(map_receiver_error)?;
        let canonical_url = receiver.canonical_url().to_owned();
        let worker = ReceiverWorker::start(receiver);
        Ok(Self {
            store,
            canonical_url,
            worker,
        })
    }

    #[getter]
    fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    fn reserve(
        &self,
        turn_binding: Vec<u8>,
        timeout_seconds: f64,
    ) -> PyResult<PyReleaseReservation> {
        let turn_binding: [u8; 32] = turn_binding
            .try_into()
            .map_err(|_| PyValueError::new_err("turn binding must be exactly 32 bytes"))?;
        let duration = Duration::try_from_secs_f64(timeout_seconds)
            .map_err(|_| PyValueError::new_err("reservation timeout is invalid"))?;
        if duration.is_zero() || duration > MAX_RESERVATION_DURATION {
            return Err(PyValueError::new_err(
                "reservation timeout must be between zero and 300 seconds",
            ));
        }
        let now = unix_now_ms()?;
        let duration_ms = u64::try_from(duration.as_millis())
            .map_err(|_| PyValueError::new_err("reservation timeout is invalid"))?;
        let expires = now
            .checked_add(duration_ms)
            .ok_or_else(|| PyValueError::new_err("reservation timeout is invalid"))?;
        let id = self
            .store
            .reserve(turn_binding, now, expires)
            .map_err(map_reservation_error)?;
        Ok(PyReleaseReservation {
            id,
            store: Arc::clone(&self.store),
        })
    }

    fn wait<'py>(
        &self,
        py: Python<'py>,
        reservation: &PyReleaseReservation,
        timeout_seconds: f64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.require_own_reservation(reservation)?;
        let duration = Duration::try_from_secs_f64(timeout_seconds)
            .map_err(|_| PyValueError::new_err("release wait timeout is invalid"))?;
        if duration.is_zero() || duration > MAX_RESERVATION_DURATION {
            return Err(PyValueError::new_err(
                "release wait timeout must be between zero and 300 seconds",
            ));
        }
        let store = Arc::clone(&self.store);
        let id = reservation.id;
        let result = py.allow_threads(move || {
            let deadline = Instant::now()
                .checked_add(duration)
                .ok_or(ReservationError::Expired)?;
            loop {
                match store.read_delivery(&id) {
                    Ok(delivery) => return Ok(delivery.payload().to_vec()),
                    Err(ReservationError::NotClaimed) if Instant::now() < deadline => {
                        thread::sleep(DELIVERY_POLL);
                    }
                    Err(ReservationError::NotClaimed) => {
                        let _ = store.seal_indeterminate(&id);
                        return Err(ReservationError::Expired);
                    }
                    Err(error) => return Err(error),
                }
            }
        });
        result
            .map(|payload| PyBytes::new_bound(py, &payload))
            .map_err(map_reservation_error)
    }

    fn complete(&self, reservation: &PyReleaseReservation) -> PyResult<()> {
        self.require_own_reservation(reservation)?;
        self.store
            .complete_delivery(&reservation.id)
            .map_err(map_reservation_error)
    }

    fn clear_failed_no_effect(&self, reservation: &PyReleaseReservation) -> PyResult<()> {
        self.require_own_reservation(reservation)?;
        self.store
            .clear_failed_no_effect(&reservation.id)
            .map_err(map_reservation_error)
    }

    fn seal_indeterminate(&self, reservation: &PyReleaseReservation) -> PyResult<()> {
        self.require_own_reservation(reservation)?;
        self.store
            .seal_indeterminate(&reservation.id)
            .map_err(map_reservation_error)
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.worker.close())
            .map_err(|()| private_error("release_receiver_unavailable"))
    }

    fn __repr__(&self) -> &'static str {
        "_ReleaseReceiver(<private-mtls>)"
    }
}

impl PyReleaseReceiver {
    fn require_own_reservation(&self, reservation: &PyReleaseReservation) -> PyResult<()> {
        if !Arc::ptr_eq(&self.store, &reservation.store) {
            return Err(private_error("release_cross_turn"));
        }
        Ok(())
    }
}

struct ReceiverWorker {
    stopped: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ReceiverWorker {
    fn start(receiver: ReleaseReceiver) -> Arc<Self> {
        let stopped = Arc::new(AtomicBool::new(false));
        let worker = Arc::new(Self {
            stopped: Arc::clone(&stopped),
            thread: Mutex::new(None),
        });
        let thread = thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                let now = match unix_now_ms_raw() {
                    Some(now) => now,
                    None => break,
                };
                match receiver.accept_one(now, Instant::now() + RECEIVER_POLL) {
                    Ok(()) | Err(ReleaseReceiverError::DeadlineExceeded) => {}
                    Err(_) => thread::sleep(DELIVERY_POLL),
                }
            }
        });
        if let Ok(mut slot) = worker.thread.lock() {
            *slot = Some(thread);
        }
        worker
    }

    fn close(&self) -> Result<(), ()> {
        self.stopped.store(true, Ordering::Release);
        let thread = self.thread.lock().map_err(|_| ())?.take();
        if let Some(thread) = thread {
            thread.join().map_err(|_| ())?;
        }
        Ok(())
    }
}

impl Drop for ReceiverWorker {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Ok(slot) = self.thread.get_mut() {
            if let Some(thread) = slot.take() {
                let _ = thread.join();
            }
        }
    }
}

fn require_absolute(path: &Path) -> PyResult<()> {
    if !path.is_absolute() {
        return Err(PyValueError::new_err(
            "release receiver paths must be absolute",
        ));
    }
    Ok(())
}

fn require_private_key_permissions(path: &Path) -> PyResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| private_error("release_receiver_invalid_config"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(private_error("release_receiver_invalid_config"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(private_error("release_receiver_invalid_config"));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> PyResult<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| private_error("release_receiver_invalid_config"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(private_error("release_receiver_invalid_config"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(maximum + 1).read_to_end(&mut bytes))
        .map_err(|_| private_error("release_receiver_invalid_config"))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(private_error("release_receiver_invalid_config"));
    }
    Ok(bytes)
}

fn unix_now_ms() -> PyResult<u64> {
    unix_now_ms_raw().ok_or_else(|| private_error("release_receiver_unavailable"))
}

fn unix_now_ms_raw() -> Option<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    u64::try_from(millis).ok()
}

fn map_receiver_error(error: ReleaseReceiverError) -> PyErr {
    let code = match error {
        ReleaseReceiverError::InvalidConfig => "release_receiver_invalid_config",
        ReleaseReceiverError::DeadlineExceeded => "release_receiver_deadline",
        ReleaseReceiverError::UnauthorizedClient => "release_receiver_unauthorized",
        ReleaseReceiverError::AlpnMismatch | ReleaseReceiverError::InvalidRequest => {
            "release_receiver_protocol"
        }
        ReleaseReceiverError::Reservation(error) => return map_reservation_error(error),
        ReleaseReceiverError::Transport | ReleaseReceiverError::Tls => {
            "release_receiver_unavailable"
        }
    };
    private_error(code)
}

fn map_reservation_error(error: ReservationError) -> PyErr {
    let code = match error {
        ReservationError::Busy => "release_busy",
        ReservationError::Sealed => "release_sealed",
        ReservationError::Expired => "release_deadline",
        ReservationError::CrossTurn => "release_cross_turn",
        ReservationError::InvalidBusinessRequest => "release_invalid_request",
        ReservationError::DuplicateDelivery => "release_duplicate",
        ReservationError::NoReservation => "release_not_reserved",
        ReservationError::AlreadyClaimed => "release_already_claimed",
        ReservationError::NotClaimed => "release_not_claimed",
        ReservationError::DurableState | ReservationError::EntropyUnavailable => {
            "release_receiver_unavailable"
        }
    };
    private_error(code)
}

fn private_error(code: &'static str) -> PyErr {
    Python::with_gil(|py| {
        let error = PyRuntimeError::new_err(format!("{code}: final release unavailable"));
        let _ = error.value_bound(py).setattr("code", code);
        error
    })
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyReleaseReservation>()?;
    module.add_class::<PyReleaseReceiver>()?;
    Ok(())
}
