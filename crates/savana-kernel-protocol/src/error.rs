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
        }
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
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for ProtocolError {}
