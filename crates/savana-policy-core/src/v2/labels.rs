#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrityV2 {
    KernelTrusted,
    UserAuthorized,
    ExternalUntrusted,
}

impl IntegrityV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::KernelTrusted => 1,
            Self::UserAuthorized => 2,
            Self::ExternalUntrusted => 3,
        }
    }

    pub const fn join(self, other: Self) -> Self {
        if self.tag() >= other.tag() {
            self
        } else {
            other
        }
    }
}

impl<C> minicbor::Encode<C> for IntegrityV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for IntegrityV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(1) {
            return Err(minicbor::decode::Error::message("invalid integrity").at(position));
        }
        match decoder.u16()? {
            1 => Ok(Self::KernelTrusted),
            2 => Ok(Self::UserAuthorized),
            3 => Ok(Self::ExternalUntrusted),
            _ => Err(minicbor::decode::Error::message("invalid integrity").at(position)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfidentialityV2 {
    Public,
    PlannerAbstract,
    AgentMasked,
    VaultBound,
}

impl ConfidentialityV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Public => 1,
            Self::PlannerAbstract => 2,
            Self::AgentMasked => 3,
            Self::VaultBound => 4,
        }
    }

    pub const fn join(self, other: Self) -> Self {
        use ConfidentialityV2::{AgentMasked, PlannerAbstract, Public, VaultBound};

        match (self, other) {
            (Public, value) | (value, Public) => value,
            (PlannerAbstract, PlannerAbstract) => PlannerAbstract,
            (AgentMasked, AgentMasked) => AgentMasked,
            (PlannerAbstract, AgentMasked) | (AgentMasked, PlannerAbstract) => VaultBound,
            (VaultBound, _) | (_, VaultBound) => VaultBound,
        }
    }
}

impl<C> minicbor::Encode<C> for ConfidentialityV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ConfidentialityV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(1) {
            return Err(minicbor::decode::Error::message("invalid confidentiality").at(position));
        }
        match decoder.u16()? {
            1 => Ok(Self::Public),
            2 => Ok(Self::PlannerAbstract),
            3 => Ok(Self::AgentMasked),
            4 => Ok(Self::VaultBound),
            _ => Err(minicbor::decode::Error::message("invalid confidentiality").at(position)),
        }
    }
}

macro_rules! closed_bit_set_v2 {
    (
        $name:ident, $valid_bits:literal,
        $($constant:ident = $bit:literal),+ $(,)?
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(u16);

        impl $name {
            pub const EMPTY: Self = Self(0);
            pub const ALL: Self = Self($valid_bits);
            $(pub const $constant: Self = Self($bit);)+

            pub const fn from_bits(bits: u16) -> Option<Self> {
                if bits & !$valid_bits == 0 {
                    Some(Self(bits))
                } else {
                    None
                }
            }

            pub const fn bits(self) -> u16 {
                self.0
            }

            pub const fn union(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }

            pub const fn intersection(self, other: Self) -> Self {
                Self(self.0 & other.0)
            }

            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.u16(self.0)?;
                Ok(())
            }
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                Self::from_bits(decoder.u16()?).ok_or_else(|| {
                    minicbor::decode::Error::message("invalid closed bit set").at(position)
                })
            }
        }
    };
}

closed_bit_set_v2!(
    ReaderSetV2,
    0x007f,
    KERNEL = 0x0001,
    AGENT = 0x0002,
    INGRESS = 0x0004,
    APPROVAL_DISPLAY = 0x0008,
    EXECUTOR = 0x0010,
    EXTERNAL_PLANNER = 0x0020,
    EXTERNAL_SINK = 0x0040,
);

closed_bit_set_v2!(
    EffectSetV2,
    0x007f,
    READ = 0x0001,
    CREATE = 0x0002,
    UPDATE = 0x0004,
    DELETE = 0x0008,
    SEND = 0x0010,
    EXECUTE = 0x0020,
    FINAL_RELEASE = 0x0040,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum G3Error {
    #[error("G3 declassification blocked: value carries blocklisted content")]
    LeakGateBlockedContent,
    #[error("G3 declassification blocked: value still carries unmasked personal data")]
    LeakGateResidualPii,
    #[error("G3 derivation requires at least one parent")]
    EmptyParents,
    #[error("G3 root evidence contains a duplicate")]
    DuplicateRootEvidence,
    #[error("G3 root evidence exceeds 64 entries")]
    RootEvidenceOverflow,
    #[error("G3 provenance exceeds 256 parents")]
    ParentLimitExceeded,
    #[error("G3 parent belongs to another run")]
    CrossRunParent,
    #[error("G3 parent belongs to another manifest")]
    CrossManifestParent,
    #[error("G3 kernel extraction has no gated-ingress parent")]
    MissingGatedIngressParent,
    #[error("G3 provenance time range is invalid")]
    InvalidTimeRange,
    #[error("G3 identifier is outside the closed ASCII identifier language")]
    InvalidIdentifier,
    #[error("G3 collection is not in strict canonical order")]
    NonCanonicalOrder,
    #[error("G3 kernel value exceeds the maximum depth")]
    ValueDepthExceeded,
    #[error("G3 kernel value exceeds the maximum node count")]
    ValueNodeLimitExceeded,
    #[error("G3 kernel value exceeds the maximum encoded size")]
    ValueEncodedBytesExceeded,
    #[error("G3 collection exceeds its maximum item count")]
    CollectionLimitExceeded,
    #[error("G3 binding contains a duplicate internal value identity")]
    DuplicateInternalId,
    #[error("G3 provenance set does not exactly match the argument binding")]
    BindingMismatch,
    #[error("G3 derivation operand count is invalid for the selected operation")]
    DeriveArityMismatch,
    #[error("G3 derivation operand has the wrong value type")]
    DeriveTypeMismatch,
    #[error("G3 selected object field does not exist")]
    DeriveFieldMissing,
    #[error("G3 parent value bytes do not match the parent provenance digest")]
    ParentValueMismatch,
    #[error("G3 fallible allocation failed")]
    AllocationFailure,
    #[error("G3 canonical encoding failed")]
    CanonicalEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecurityLabelV2 {
    integrity: IntegrityV2,
    confidentiality: ConfidentialityV2,
    readers: ReaderSetV2,
    effects: EffectSetV2,
}

/// The effects an `ExternalUntrusted` value may carry. Untrusted data may be
/// read and analysed — that is what an agent is for — but it may not carry the
/// capability to authorize an effect.
///
/// Without this ceiling a value's effect set comes from the session-wide
/// `policy_allowed_effects`, so planner output and tool results carry the same
/// effects as user input and a recipient fabricated from fetched content
/// passes [`SecurityLabelV2::effects`]-based confinement. The ceiling is
/// applied on every construction and every derivation below, so no provenance
/// source can hand an untrusted value an authorizing effect.
pub const UNTRUSTED_EFFECT_CEILING_V2: EffectSetV2 = EffectSetV2::READ;

impl SecurityLabelV2 {
    /// Applies the [`UNTRUSTED_EFFECT_CEILING_V2`] invariant:
    /// `integrity == ExternalUntrusted` implies `effects ⊆ {READ}`.
    const fn confined_effects(integrity: IntegrityV2, effects: EffectSetV2) -> EffectSetV2 {
        match integrity {
            IntegrityV2::ExternalUntrusted => effects.intersection(UNTRUSTED_EFFECT_CEILING_V2),
            IntegrityV2::UserAuthorized | IntegrityV2::KernelTrusted => effects,
        }
    }

    pub(crate) const fn from_verified_source(
        integrity: IntegrityV2,
        confidentiality: ConfidentialityV2,
        readers: ReaderSetV2,
        effects: EffectSetV2,
    ) -> Self {
        Self {
            integrity,
            confidentiality,
            readers,
            effects: Self::confined_effects(integrity, effects),
        }
    }

    pub(crate) fn derive_normal(
        parents: &[Self],
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        let Some((first, rest)) = parents.split_first() else {
            return Err(G3Error::EmptyParents);
        };

        let mut derived = *first;
        for parent in rest {
            derived.integrity = derived.integrity.join(parent.integrity);
            derived.confidentiality = derived.confidentiality.join(parent.confidentiality);
            derived.readers = derived.readers.intersection(parent.readers);
            derived.effects = derived.effects.intersection(parent.effects);
        }
        derived.effects = derived.effects.intersection(policy_allowed_effects);
        // Re-apply the ceiling after the join: a value derived from a trusted
        // and an untrusted parent becomes `ExternalUntrusted` here, and must
        // lose the authorizing effects its trusted parent contributed.
        derived.effects = Self::confined_effects(derived.integrity, derived.effects);
        Ok(derived)
    }

    pub const fn integrity(self) -> IntegrityV2 {
        self.integrity
    }

    pub const fn confidentiality(self) -> ConfidentialityV2 {
        self.confidentiality
    }

    pub const fn readers(self) -> ReaderSetV2 {
        self.readers
    }

    pub const fn effects(self) -> EffectSetV2 {
        self.effects
    }
}

#[cfg(test)]
#[path = "labels_tests.rs"]
mod tests;
