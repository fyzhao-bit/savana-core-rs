use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StableCode {
    ProtocolMalformedFrame,
    ProtocolTruncatedFrame,
    ProtocolFrameTooLarge,
    ProtocolAllocationRefused,
    ProtocolIo,
    ProtocolMalformedCbor,
    ProtocolNonCanonicalCbor,
    ProtocolNestingTooDeep,
    ProtocolUnknownField,
    ProtocolUnknownOperation,
    ProtocolUnsupportedVersion,
    IdentityPeerRejected,
    IdentityUnknownClient,
    IdentityInvalidSignature,
    IdentityTranscriptMismatch,
    IdentityReplay,
    IdentityReleaseMismatch,
    IdentityKeyPermissions,
    IdentitySocketPermissions,
    PolicyInvalidSignature,
    PolicyExpired,
    PolicyNotYetValid,
    PolicyRollback,
    PolicyEquivocation,
    PolicyLimitExceeded,
    PolicyReleaseIncompatible,
    DeadlineExceeded,
    KernelOverloaded,
    KernelUnavailable,
    AttestationInvalidSignature,
    AttestationExpired,
    AttestationBindingMismatch,
    OntologySequenceGap,
    HandleUnknown,
    HandleWrongClient,
    HandleWrongConnection,
    HandleWrongRun,
    HandleWrongType,
    HandleStalePolicy,
    HandleStaleRegistry,
    HandleAlreadyConsumed,
    HandleInvalidatedBoot,
    CancellationTooLate,
    RegistryInvalidSignature,
    RegistryEquivocation,
    OntologyInvalidSignature,
    OntologyEquivocation,
    PolicyDenied,
    ApprovalRequired,
    ApprovalInvalidSignature,
    ApprovalBindingMismatch,
    ApprovalReplayed,
    ApprovalLedgerFull,
}

impl StableCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolMalformedFrame => "PROTOCOL_MALFORMED_FRAME",
            Self::ProtocolTruncatedFrame => "PROTOCOL_TRUNCATED_FRAME",
            Self::ProtocolFrameTooLarge => "PROTOCOL_FRAME_TOO_LARGE",
            Self::ProtocolAllocationRefused => "PROTOCOL_ALLOCATION_REFUSED",
            Self::ProtocolIo => "PROTOCOL_IO",
            Self::ProtocolMalformedCbor => "PROTOCOL_MALFORMED_CBOR",
            Self::ProtocolNonCanonicalCbor => "PROTOCOL_NON_CANONICAL_CBOR",
            Self::ProtocolNestingTooDeep => "PROTOCOL_NESTING_TOO_DEEP",
            Self::ProtocolUnknownField => "PROTOCOL_UNKNOWN_FIELD",
            Self::ProtocolUnknownOperation => "PROTOCOL_UNKNOWN_OPERATION",
            Self::ProtocolUnsupportedVersion => "PROTOCOL_UNSUPPORTED_VERSION",
            Self::IdentityPeerRejected => "IDENTITY_PEER_REJECTED",
            Self::IdentityUnknownClient => "IDENTITY_UNKNOWN_CLIENT",
            Self::IdentityInvalidSignature => "IDENTITY_INVALID_SIGNATURE",
            Self::IdentityTranscriptMismatch => "IDENTITY_TRANSCRIPT_MISMATCH",
            Self::IdentityReplay => "IDENTITY_REPLAY",
            Self::IdentityReleaseMismatch => "IDENTITY_RELEASE_MISMATCH",
            Self::IdentityKeyPermissions => "IDENTITY_KEY_PERMISSIONS",
            Self::IdentitySocketPermissions => "IDENTITY_SOCKET_PERMISSIONS",
            Self::PolicyInvalidSignature => "POLICY_INVALID_SIGNATURE",
            Self::PolicyExpired => "POLICY_EXPIRED",
            Self::PolicyNotYetValid => "POLICY_NOT_YET_VALID",
            Self::PolicyRollback => "POLICY_ROLLBACK",
            Self::PolicyEquivocation => "POLICY_EQUIVOCATION",
            Self::PolicyLimitExceeded => "POLICY_LIMIT_EXCEEDED",
            Self::PolicyReleaseIncompatible => "POLICY_RELEASE_INCOMPATIBLE",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::KernelOverloaded => "KERNEL_OVERLOADED",
            Self::KernelUnavailable => "KERNEL_UNAVAILABLE",
            Self::AttestationInvalidSignature => "ATTESTATION_INVALID_SIGNATURE",
            Self::AttestationExpired => "ATTESTATION_EXPIRED",
            Self::AttestationBindingMismatch => "ATTESTATION_BINDING_MISMATCH",
            Self::OntologySequenceGap => "ONTOLOGY_SEQUENCE_GAP",
            Self::HandleUnknown => "HANDLE_UNKNOWN",
            Self::HandleWrongClient => "HANDLE_WRONG_CLIENT",
            Self::HandleWrongConnection => "HANDLE_WRONG_CONNECTION",
            Self::HandleWrongRun => "HANDLE_WRONG_RUN",
            Self::HandleWrongType => "HANDLE_WRONG_TYPE",
            Self::HandleStalePolicy => "HANDLE_STALE_POLICY",
            Self::HandleStaleRegistry => "HANDLE_STALE_REGISTRY",
            Self::HandleAlreadyConsumed => "HANDLE_ALREADY_CONSUMED",
            Self::HandleInvalidatedBoot => "HANDLE_INVALIDATED_BOOT",
            Self::CancellationTooLate => "CANCELLATION_TOO_LATE",
            Self::RegistryInvalidSignature => "REGISTRY_INVALID_SIGNATURE",
            Self::RegistryEquivocation => "REGISTRY_EQUIVOCATION",
            Self::OntologyInvalidSignature => "ONTOLOGY_INVALID_SIGNATURE",
            Self::OntologyEquivocation => "ONTOLOGY_EQUIVOCATION",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::ApprovalRequired => "APPROVAL_REQUIRED",
            Self::ApprovalInvalidSignature => "APPROVAL_INVALID_SIGNATURE",
            Self::ApprovalBindingMismatch => "APPROVAL_BINDING_MISMATCH",
            Self::ApprovalReplayed => "APPROVAL_REPLAYED",
            Self::ApprovalLedgerFull => "APPROVAL_LEDGER_FULL",
        }
    }

    pub(crate) fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "PROTOCOL_MALFORMED_FRAME" => Self::ProtocolMalformedFrame,
            "PROTOCOL_TRUNCATED_FRAME" => Self::ProtocolTruncatedFrame,
            "PROTOCOL_FRAME_TOO_LARGE" => Self::ProtocolFrameTooLarge,
            "PROTOCOL_ALLOCATION_REFUSED" => Self::ProtocolAllocationRefused,
            "PROTOCOL_IO" => Self::ProtocolIo,
            "PROTOCOL_MALFORMED_CBOR" => Self::ProtocolMalformedCbor,
            "PROTOCOL_NON_CANONICAL_CBOR" => Self::ProtocolNonCanonicalCbor,
            "PROTOCOL_NESTING_TOO_DEEP" => Self::ProtocolNestingTooDeep,
            "PROTOCOL_UNKNOWN_FIELD" => Self::ProtocolUnknownField,
            "PROTOCOL_UNKNOWN_OPERATION" => Self::ProtocolUnknownOperation,
            "PROTOCOL_UNSUPPORTED_VERSION" => Self::ProtocolUnsupportedVersion,
            "IDENTITY_PEER_REJECTED" => Self::IdentityPeerRejected,
            "IDENTITY_UNKNOWN_CLIENT" => Self::IdentityUnknownClient,
            "IDENTITY_INVALID_SIGNATURE" => Self::IdentityInvalidSignature,
            "IDENTITY_TRANSCRIPT_MISMATCH" => Self::IdentityTranscriptMismatch,
            "IDENTITY_REPLAY" => Self::IdentityReplay,
            "IDENTITY_RELEASE_MISMATCH" => Self::IdentityReleaseMismatch,
            "IDENTITY_KEY_PERMISSIONS" => Self::IdentityKeyPermissions,
            "IDENTITY_SOCKET_PERMISSIONS" => Self::IdentitySocketPermissions,
            "POLICY_INVALID_SIGNATURE" => Self::PolicyInvalidSignature,
            "POLICY_EXPIRED" => Self::PolicyExpired,
            "POLICY_NOT_YET_VALID" => Self::PolicyNotYetValid,
            "POLICY_ROLLBACK" => Self::PolicyRollback,
            "POLICY_EQUIVOCATION" => Self::PolicyEquivocation,
            "POLICY_LIMIT_EXCEEDED" => Self::PolicyLimitExceeded,
            "POLICY_RELEASE_INCOMPATIBLE" => Self::PolicyReleaseIncompatible,
            "DEADLINE_EXCEEDED" => Self::DeadlineExceeded,
            "KERNEL_OVERLOADED" => Self::KernelOverloaded,
            "KERNEL_UNAVAILABLE" => Self::KernelUnavailable,
            "ATTESTATION_INVALID_SIGNATURE" => Self::AttestationInvalidSignature,
            "ATTESTATION_EXPIRED" => Self::AttestationExpired,
            "ATTESTATION_BINDING_MISMATCH" => Self::AttestationBindingMismatch,
            "ONTOLOGY_SEQUENCE_GAP" => Self::OntologySequenceGap,
            "HANDLE_UNKNOWN" => Self::HandleUnknown,
            "HANDLE_WRONG_CLIENT" => Self::HandleWrongClient,
            "HANDLE_WRONG_CONNECTION" => Self::HandleWrongConnection,
            "HANDLE_WRONG_RUN" => Self::HandleWrongRun,
            "HANDLE_WRONG_TYPE" => Self::HandleWrongType,
            "HANDLE_STALE_POLICY" => Self::HandleStalePolicy,
            "HANDLE_STALE_REGISTRY" => Self::HandleStaleRegistry,
            "HANDLE_ALREADY_CONSUMED" => Self::HandleAlreadyConsumed,
            "HANDLE_INVALIDATED_BOOT" => Self::HandleInvalidatedBoot,
            "CANCELLATION_TOO_LATE" => Self::CancellationTooLate,
            "REGISTRY_INVALID_SIGNATURE" => Self::RegistryInvalidSignature,
            "REGISTRY_EQUIVOCATION" => Self::RegistryEquivocation,
            "ONTOLOGY_INVALID_SIGNATURE" => Self::OntologyInvalidSignature,
            "ONTOLOGY_EQUIVOCATION" => Self::OntologyEquivocation,
            "POLICY_DENIED" => Self::PolicyDenied,
            "APPROVAL_REQUIRED" => Self::ApprovalRequired,
            "APPROVAL_INVALID_SIGNATURE" => Self::ApprovalInvalidSignature,
            "APPROVAL_BINDING_MISMATCH" => Self::ApprovalBindingMismatch,
            "APPROVAL_REPLAYED" => Self::ApprovalReplayed,
            "APPROVAL_LEDGER_FULL" => Self::ApprovalLedgerFull,
            _ => return None,
        })
    }
}

impl<C> minicbor::Encode<C> for StableCode {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.str(self.as_str())?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for StableCode {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let value = decoder.str()?;
        Self::from_wire(value).ok_or_else(|| {
            minicbor::decode::Error::message(Self::ProtocolMalformedCbor.as_str()).at(position)
        })
    }
}

impl fmt::Display for StableCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolError {
    code: StableCode,
}

impl ProtocolError {
    pub const fn stable(code: StableCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> StableCode {
        self.code
    }

    pub(crate) fn malformed<T>(_error: T) -> Self {
        Self::stable(StableCode::ProtocolMalformedCbor)
    }

    pub(crate) fn indefinite() -> Self {
        Self::stable(StableCode::ProtocolMalformedCbor)
    }

    pub(crate) fn unsupported_cbor() -> Self {
        Self::stable(StableCode::ProtocolMalformedCbor)
    }

    pub(crate) fn from_typed_decode(error: minicbor::decode::Error) -> Self {
        if error
            .to_string()
            .contains(StableCode::ProtocolUnknownOperation.as_str())
        {
            Self::stable(StableCode::ProtocolUnknownOperation)
        } else {
            Self::stable(StableCode::ProtocolMalformedCbor)
        }
    }

    pub(crate) fn io(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                Self::stable(StableCode::DeadlineExceeded)
            }
            _ => Self::stable(StableCode::ProtocolIo),
        }
    }

    pub(crate) fn from_read(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::UnexpectedEof => Self::stable(StableCode::ProtocolTruncatedFrame),
            _ => Self::io(error),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for ProtocolError {}
