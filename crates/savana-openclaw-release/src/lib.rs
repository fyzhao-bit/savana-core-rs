#![forbid(unsafe_code)]

mod request;

pub use request::{
    ReleaseRequestError, VerifiedReleaseRequest, MAX_RELEASE_PAYLOAD_BYTES,
    MAX_RELEASE_REQUEST_BYTES,
};
