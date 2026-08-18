#![forbid(unsafe_code)]

mod request;
mod reservation;

pub use request::{
    ReleaseRequestError, VerifiedReleaseRequest, MAX_RELEASE_PAYLOAD_BYTES,
    MAX_RELEASE_REQUEST_BYTES,
};
pub use reservation::{ReleaseReservationStore, ReleasedPayload, ReservationError, ReservationId};
