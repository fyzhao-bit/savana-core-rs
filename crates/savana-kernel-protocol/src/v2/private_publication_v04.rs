//! Owner-only publication metadata. This value is not a grant, raw result or
//! portable attestation. Trust comes from the authenticated KernelApproval edge
//! and the live, authenticated private browser session, not its constructor.
use super::*;
use crate::ProtocolError;
use minicbor::Decode as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatePublicationV04 {
    task: DurableTaskIdV2,
    run: DurableRunIdV2,
    root: Digest32V2,
    boot: BootIdV2,
    release: DurableReleaseIdV2,
    payload: Digest32V2,
    destination: Digest32V2,
    approval: Digest32V2,
    receipt: Digest32V2,
    audit: Digest32V2,
    commit: Digest32V2,
}

impl PrivatePublicationV04 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task: DurableTaskIdV2,
        run: DurableRunIdV2,
        root: Digest32V2,
        boot: BootIdV2,
        release: DurableReleaseIdV2,
        payload: Digest32V2,
        destination: Digest32V2,
        approval: Digest32V2,
        receipt: Digest32V2,
        audit: Digest32V2,
        commit: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if [
            task.as_bytes(),
            run.as_bytes(),
            root.as_bytes(),
            boot.as_bytes(),
            release.as_bytes(),
            payload.as_bytes(),
            destination.as_bytes(),
            approval.as_bytes(),
            receipt.as_bytes(),
            audit.as_bytes(),
            commit.as_bytes(),
        ]
        .iter()
        .any(|v| **v == [0; 32])
        {
            return Err(invalid());
        }
        Ok(Self {
            task,
            run,
            root,
            boot,
            release,
            payload,
            destination,
            approval,
            receipt,
            audit,
            commit,
        })
    }
    pub const fn task(self) -> DurableTaskIdV2 {
        self.task
    }
    pub const fn run(self) -> DurableRunIdV2 {
        self.run
    }
    pub const fn root(self) -> Digest32V2 {
        self.root
    }
    pub const fn boot(self) -> BootIdV2 {
        self.boot
    }
    pub const fn release(self) -> DurableReleaseIdV2 {
        self.release
    }
    pub const fn payload_digest(self) -> Digest32V2 {
        self.payload
    }
    pub const fn destination_digest(self) -> Digest32V2 {
        self.destination
    }
    pub const fn approval_digest(self) -> Digest32V2 {
        self.approval
    }
    pub const fn receipt_digest(self) -> Digest32V2 {
        self.receipt
    }
    pub const fn audit_digest(self) -> Digest32V2 {
        self.audit
    }
    pub const fn commit_digest(self) -> Digest32V2 {
        self.commit
    }

    /// Match already received bytes. Does not fetch bytes, permit another
    /// disclosure or establish that the application durably stored them.
    pub fn matches_payload(self, payload: &[u8]) -> bool {
        use sha2::{Digest as _, Sha256};
        if payload.len() > 32 * 1024 {
            return false;
        }
        let mut h = Sha256::new();
        h.update(b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0");
        h.update((payload.len() as u64).to_be_bytes());
        h.update(payload);
        self.payload.as_bytes() == &<[u8; 32]>::from(h.finalize())
    }
}

pub fn encode_private_publication_v04(v: PrivatePublicationV04) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(12)
        .and_then(|e| e.u16(1))
        .map_err(ProtocolError::malformed)?;
    for bytes in [
        v.task.as_bytes(),
        v.run.as_bytes(),
        v.root.as_bytes(),
        v.boot.as_bytes(),
        v.release.as_bytes(),
        v.payload.as_bytes(),
        v.destination.as_bytes(),
        v.approval.as_bytes(),
        v.receipt.as_bytes(),
        v.audit.as_bytes(),
        v.commit.as_bytes(),
    ] {
        e.bytes(bytes).map_err(ProtocolError::malformed)?;
    }
    Ok(e.into_writer())
}

pub fn decode_private_publication_v04(
    bytes: &[u8],
) -> Result<PrivatePublicationV04, ProtocolError> {
    if bytes.len() > 512 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(ProtocolError::malformed)? != Some(12)
        || d.u16().map_err(ProtocolError::malformed)? != 1
    {
        return Err(invalid());
    }
    let mut c = V2DecodeContext;
    let v = PrivatePublicationV04::new(
        DurableTaskIdV2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        DurableRunIdV2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        Digest32V2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        BootIdV2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        DurableReleaseIdV2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        Digest32V2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        Digest32V2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        Digest32V2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        Digest32V2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        Digest32V2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
        Digest32V2::decode(&mut d, &mut c).map_err(ProtocolError::malformed)?,
    )?;
    if encode_private_publication_v04(v)? != bytes {
        return Err(invalid());
    }
    Ok(v)
}

pub fn encode_private_publication_status_v04(
    v: Option<PrivatePublicationV04>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.u16(4))
        .map_err(ProtocolError::malformed)?;
    if let Some(v) = v {
        e.bytes(&encode_private_publication_v04(v)?)
            .map_err(ProtocolError::malformed)?;
    } else {
        e.null().map_err(ProtocolError::malformed)?;
    }
    Ok(e.into_writer())
}

pub fn decode_private_publication_status_v04(
    bytes: &[u8],
) -> Result<Option<PrivatePublicationV04>, ProtocolError> {
    if bytes.len() > 1024 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(ProtocolError::malformed)? != Some(2)
        || d.u16().map_err(ProtocolError::malformed)? != 4
    {
        return Err(invalid());
    }
    let v = if d.datatype().map_err(ProtocolError::malformed)? == minicbor::data::Type::Null {
        d.null().map_err(ProtocolError::malformed)?;
        None
    } else {
        Some(decode_private_publication_v04(
            d.bytes().map_err(ProtocolError::malformed)?,
        )?)
    };
    if encode_private_publication_status_v04(v)? != bytes {
        return Err(invalid());
    }
    Ok(v)
}

fn invalid() -> ProtocolError {
    ProtocolError::stable(crate::StableCode::ProtocolMalformedCbor)
}
