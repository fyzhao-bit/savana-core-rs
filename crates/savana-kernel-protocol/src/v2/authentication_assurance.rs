/// Authentication provenance, not task authorization. A passkey must never be
/// represented as an attested, non-backup hardware credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationAssuranceV04 {
    #[default]
    AttestedHardware,
    UserVerifiedPasskey,
}

impl AuthenticationAssuranceV04 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::AttestedHardware => 1,
            Self::UserVerifiedPasskey => 2,
        }
    }

    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::AttestedHardware),
            2 => Some(Self::UserVerifiedPasskey),
            _ => None,
        }
    }

    pub const fn accepts_evidence(
        self,
        up: bool,
        uv: bool,
        be: bool,
        bs: bool,
        counter: u32,
    ) -> bool {
        if !up || !uv || (bs && !be) {
            return false;
        }
        match self {
            Self::AttestedHardware => !be && !bs && counter > 0,
            Self::UserVerifiedPasskey => true,
        }
    }
}
