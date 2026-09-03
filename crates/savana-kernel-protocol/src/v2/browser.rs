use minicbor::Encode as _;
use zeroize::Zeroizing;

use super::{
    cbor::V2DecodeContext, AgentUiAuthenticationBrowserCeremonyCapabilityV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiPreAuthenticationTabCapabilityV2,
    ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
    ApprovalDisplayUiPreAuthenticationTabCapabilityV2, ApprovalTabSessionCapabilityV2,
    FixedOriginV2, IngressUiAuthenticationBrowserCeremonyCapabilityV2,
    IngressUiAuthenticationSettlementTransferCapabilityV2,
    IngressUiPreAuthenticationTabCapabilityV2, Nonce32V2, UnixMillisV2,
};
use crate::ProtocolError;

const MAX_BROWSER_BODY_BYTES_V2: usize = 1024 * 1024;
const MAX_CREDENTIAL_ID_BYTES_V2: usize = 4096;
const MAX_AUTHENTICATOR_DATA_BYTES_V2: usize = 4096;
const MAX_CLIENT_DATA_JSON_BYTES_V2: usize = 8192;
const MAX_SIGNATURE_BYTES_V2: usize = 256;
const PRINCIPAL_BYTES_V2: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAuthenticationBrowserBeginRequestV2 {
    Ingress {
        pre_authentication: IngressUiPreAuthenticationTabCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
    ApprovalDisplay {
        pre_authentication: ApprovalDisplayUiPreAuthenticationTabCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
    Agent {
        pre_authentication: AgentUiPreAuthenticationTabCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
}

impl UiAuthenticationBrowserBeginRequestV2 {
    pub const fn client_request_nonce(self) -> Nonce32V2 {
        match self {
            Self::Ingress {
                client_request_nonce,
                ..
            }
            | Self::ApprovalDisplay {
                client_request_nonce,
                ..
            }
            | Self::Agent {
                client_request_nonce,
                ..
            } => client_request_nonce,
        }
    }
}

pub enum UiAuthenticationBrowserBeginResponseV2 {
    Ingress {
        ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2,
        public_key_options_json: Zeroizing<Vec<u8>>,
    },
    ApprovalDisplay {
        ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
        public_key_options_json: Zeroizing<Vec<u8>>,
    },
    Agent {
        ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2,
        public_key_options_json: Zeroizing<Vec<u8>>,
    },
}

impl core::fmt::Debug for UiAuthenticationBrowserBeginResponseV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ingress { ceremony, .. } => formatter
                .debug_struct("Ingress")
                .field("ceremony", ceremony)
                .field("public_key_options_json", &"<redacted>")
                .finish(),
            Self::ApprovalDisplay { ceremony, .. } => formatter
                .debug_struct("ApprovalDisplay")
                .field("ceremony", ceremony)
                .field("public_key_options_json", &"<redacted>")
                .finish(),
            Self::Agent { ceremony, .. } => formatter
                .debug_struct("Agent")
                .field("ceremony", ceremony)
                .field("public_key_options_json", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAuthenticationProfileV2 {
    MacPlatform,
    HardwareWebAuthnCompatibility,
}

impl OwnerAuthenticationProfileV2 {
    pub const fn as_bootstrap_str(self) -> &'static str {
        match self {
            Self::MacPlatform => "mac-platform",
            Self::HardwareWebAuthnCompatibility => "hardware-webauthn-compatibility",
        }
    }

    pub fn from_bootstrap_str(value: &str) -> Result<Self, ProtocolError> {
        match value {
            "mac-platform" => Ok(Self::MacPlatform),
            "hardware-webauthn-compatibility" => Ok(Self::HardwareWebAuthnCompatibility),
            _ => Err(malformed()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAuthenticationPlatformBeginResponseV2 {
    Ingress {
        ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2,
        expires_at: UnixMillisV2,
    },
    ApprovalDisplay {
        ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
        expires_at: UnixMillisV2,
    },
    Agent {
        ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2,
        expires_at: UnixMillisV2,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAuthenticationPlatformStatusRequestV2 {
    Ingress {
        ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
    ApprovalDisplay {
        ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
    Agent {
        ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
}

impl UiAuthenticationPlatformStatusRequestV2 {
    pub const fn client_request_nonce(self) -> Nonce32V2 {
        match self {
            Self::Ingress {
                client_request_nonce,
                ..
            }
            | Self::ApprovalDisplay {
                client_request_nonce,
                ..
            }
            | Self::Agent {
                client_request_nonce,
                ..
            } => client_request_nonce,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAuthenticationPlatformStatusResponseV2 {
    Pending,
    Completed(UiAuthenticationBrowserFinishResponseV2),
    Denied,
    Expired,
    CredentialInvalidated,
    Unavailable,
    Indeterminate,
    ProtocolFailure,
}

pub struct BrowserWebAuthnAssertionV2 {
    credential_id: Zeroizing<Vec<u8>>,
    authenticator_data: Zeroizing<Vec<u8>>,
    client_data_json: Zeroizing<Vec<u8>>,
    signature: Zeroizing<Vec<u8>>,
    user_handle: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for BrowserWebAuthnAssertionV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BrowserWebAuthnAssertionV2")
            .field("credential_id", &"<redacted>")
            .field("authenticator_data", &"<redacted>")
            .field("client_data_json", &"<redacted>")
            .field("signature", &"<redacted>")
            .field("user_handle", &"<redacted>")
            .finish()
    }
}

impl BrowserWebAuthnAssertionV2 {
    pub fn new(
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if credential_id.is_empty()
            || credential_id.len() > MAX_CREDENTIAL_ID_BYTES_V2
            || authenticator_data.is_empty()
            || authenticator_data.len() > MAX_AUTHENTICATOR_DATA_BYTES_V2
            || client_data_json.is_empty()
            || client_data_json.len() > MAX_CLIENT_DATA_JSON_BYTES_V2
            || signature.is_empty()
            || signature.len() > MAX_SIGNATURE_BYTES_V2
            || user_handle.len() != PRINCIPAL_BYTES_V2
        {
            return Err(malformed());
        }
        Ok(Self {
            credential_id: Zeroizing::new(credential_id),
            authenticator_data: Zeroizing::new(authenticator_data),
            client_data_json: Zeroizing::new(client_data_json),
            signature: Zeroizing::new(signature),
            user_handle: Zeroizing::new(user_handle),
        })
    }

    pub fn into_parts(self) -> BrowserWebAuthnAssertionPartsV2 {
        (
            self.credential_id,
            self.authenticator_data,
            self.client_data_json,
            self.signature,
            self.user_handle,
        )
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    pub fn authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }

    pub fn client_data_json(&self) -> &[u8] {
        &self.client_data_json
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn user_handle(&self) -> &[u8] {
        &self.user_handle
    }
}

pub type BrowserWebAuthnAssertionPartsV2 = (
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
);

pub enum UiAuthenticationBrowserFinishRequestV2 {
    Ingress {
        ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
        assertion: BrowserWebAuthnAssertionV2,
    },
    ApprovalDisplay {
        ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
        assertion: BrowserWebAuthnAssertionV2,
    },
    Agent {
        ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
        assertion: BrowserWebAuthnAssertionV2,
    },
}

impl core::fmt::Debug for UiAuthenticationBrowserFinishRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ingress {
                ceremony,
                client_request_nonce,
                ..
            } => formatter
                .debug_struct("Ingress")
                .field("ceremony", ceremony)
                .field("client_request_nonce", client_request_nonce)
                .field("assertion", &"<redacted>")
                .finish(),
            Self::ApprovalDisplay {
                ceremony,
                client_request_nonce,
                ..
            } => formatter
                .debug_struct("ApprovalDisplay")
                .field("ceremony", ceremony)
                .field("client_request_nonce", client_request_nonce)
                .field("assertion", &"<redacted>")
                .finish(),
            Self::Agent {
                ceremony,
                client_request_nonce,
                ..
            } => formatter
                .debug_struct("Agent")
                .field("ceremony", ceremony)
                .field("client_request_nonce", client_request_nonce)
                .field("assertion", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAuthenticationBrowserFinishResponseV2 {
    TransferToIngress {
        return_origin: FixedOriginV2,
        transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
    },
    ApprovalDisplayReady {
        tab: ApprovalTabSessionCapabilityV2,
    },
    TransferToAgent {
        return_origin: FixedOriginV2,
        transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
    },
}

pub fn encode_owner_authentication_profile_v2(
    value: OwnerAuthenticationProfileV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(match value {
        OwnerAuthenticationProfileV2::MacPlatform => 1_u16,
        OwnerAuthenticationProfileV2::HardwareWebAuthnCompatibility => 2_u16,
    })
    .map_err(ProtocolError::malformed)
}

pub fn decode_owner_authentication_profile_v2(
    bytes: &[u8],
) -> Result<OwnerAuthenticationProfileV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let value = match tag {
        1 => OwnerAuthenticationProfileV2::MacPlatform,
        2 => OwnerAuthenticationProfileV2::HardwareWebAuthnCompatibility,
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len() || encode_owner_authentication_profile_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_ui_authentication_platform_begin_response_v2(
    value: UiAuthenticationPlatformBeginResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    let expires_at = match value {
        UiAuthenticationPlatformBeginResponseV2::Ingress {
            ceremony,
            expires_at,
        } => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            expires_at
        }
        UiAuthenticationPlatformBeginResponseV2::ApprovalDisplay {
            ceremony,
            expires_at,
        } => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            expires_at
        }
        UiAuthenticationPlatformBeginResponseV2::Agent {
            ceremony,
            expires_at,
        } => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            expires_at
        }
    };
    if expires_at.get() == 0 {
        return Err(malformed());
    }
    expires_at
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_ui_authentication_platform_begin_response_v2(
    bytes: &[u8],
) -> Result<UiAuthenticationPlatformBeginResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 3)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    macro_rules! decode_begin {
        ($variant:ident, $ceremony:ty) => {{
            let ceremony: $ceremony = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let expires_at: UnixMillisV2 = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            UiAuthenticationPlatformBeginResponseV2::$variant {
                ceremony,
                expires_at,
            }
        }};
    }
    let value = match tag {
        1 => decode_begin!(Ingress, IngressUiAuthenticationBrowserCeremonyCapabilityV2),
        2 => decode_begin!(
            ApprovalDisplay,
            ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2
        ),
        3 => decode_begin!(Agent, AgentUiAuthenticationBrowserCeremonyCapabilityV2),
        _ => return Err(malformed()),
    };
    let expires_at = match value {
        UiAuthenticationPlatformBeginResponseV2::Ingress { expires_at, .. }
        | UiAuthenticationPlatformBeginResponseV2::ApprovalDisplay { expires_at, .. }
        | UiAuthenticationPlatformBeginResponseV2::Agent { expires_at, .. } => expires_at,
    };
    if expires_at.get() == 0
        || decoder.position() != bytes.len()
        || encode_ui_authentication_platform_begin_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_ui_authentication_platform_status_request_v2(
    value: UiAuthenticationPlatformStatusRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    let nonce = match value {
        UiAuthenticationPlatformStatusRequestV2::Ingress {
            ceremony,
            client_request_nonce,
        } => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            client_request_nonce
        }
        UiAuthenticationPlatformStatusRequestV2::ApprovalDisplay {
            ceremony,
            client_request_nonce,
        } => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            client_request_nonce
        }
        UiAuthenticationPlatformStatusRequestV2::Agent {
            ceremony,
            client_request_nonce,
        } => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            client_request_nonce
        }
    };
    if nonce.as_bytes() == &[0; 32] {
        return Err(malformed());
    }
    nonce
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_ui_authentication_platform_status_request_v2(
    bytes: &[u8],
) -> Result<UiAuthenticationPlatformStatusRequestV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 3)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    macro_rules! decode_status_request {
        ($variant:ident, $ceremony:ty) => {{
            let ceremony: $ceremony = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let client_request_nonce: Nonce32V2 =
                minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?;
            UiAuthenticationPlatformStatusRequestV2::$variant {
                ceremony,
                client_request_nonce,
            }
        }};
    }
    let value = match tag {
        1 => decode_status_request!(Ingress, IngressUiAuthenticationBrowserCeremonyCapabilityV2),
        2 => decode_status_request!(
            ApprovalDisplay,
            ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2
        ),
        3 => decode_status_request!(Agent, AgentUiAuthenticationBrowserCeremonyCapabilityV2),
        _ => return Err(malformed()),
    };
    if value.client_request_nonce().as_bytes() == &[0; 32]
        || decoder.position() != bytes.len()
        || encode_ui_authentication_platform_status_request_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_ui_authentication_platform_status_response_v2(
    value: UiAuthenticationPlatformStatusResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        UiAuthenticationPlatformStatusResponseV2::Pending => {
            encode_platform_status(&mut encoder, 1)?
        }
        UiAuthenticationPlatformStatusResponseV2::Completed(completion) => {
            encode_platform_completion(
                &mut encoder,
                &encode_ui_authentication_browser_finish_response_v2(completion)?,
            )?
        }
        UiAuthenticationPlatformStatusResponseV2::Denied => {
            encode_platform_status(&mut encoder, 3)?
        }
        UiAuthenticationPlatformStatusResponseV2::Expired => {
            encode_platform_status(&mut encoder, 4)?
        }
        UiAuthenticationPlatformStatusResponseV2::CredentialInvalidated => {
            encode_platform_status(&mut encoder, 5)?
        }
        UiAuthenticationPlatformStatusResponseV2::Unavailable => {
            encode_platform_status(&mut encoder, 6)?
        }
        UiAuthenticationPlatformStatusResponseV2::Indeterminate => {
            encode_platform_status(&mut encoder, 7)?
        }
        UiAuthenticationPlatformStatusResponseV2::ProtocolFailure => {
            encode_platform_status(&mut encoder, 8)?
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_ui_authentication_platform_status_response_v2(
    bytes: &[u8],
) -> Result<UiAuthenticationPlatformStatusResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let value = match (count, tag) {
        (Some(1), 1) => UiAuthenticationPlatformStatusResponseV2::Pending,
        (Some(2), 2) => UiAuthenticationPlatformStatusResponseV2::Completed(
            decode_ui_authentication_browser_finish_response_v2(
                decoder.bytes().map_err(ProtocolError::malformed)?,
            )?,
        ),
        (Some(1), 3) => UiAuthenticationPlatformStatusResponseV2::Denied,
        (Some(1), 4) => UiAuthenticationPlatformStatusResponseV2::Expired,
        (Some(1), 5) => UiAuthenticationPlatformStatusResponseV2::CredentialInvalidated,
        (Some(1), 6) => UiAuthenticationPlatformStatusResponseV2::Unavailable,
        (Some(1), 7) => UiAuthenticationPlatformStatusResponseV2::Indeterminate,
        (Some(1), 8) => UiAuthenticationPlatformStatusResponseV2::ProtocolFailure,
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len()
        || encode_ui_authentication_platform_status_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_platform_status<W: minicbor::encode::Write>(
    encoder: &mut minicbor::Encoder<W>,
    tag: u16,
) -> Result<(), ProtocolError> {
    encoder
        .array(1)
        .and_then(|encoder| encoder.u16(tag))
        .map_err(ProtocolError::malformed)?;
    Ok(())
}

fn encode_platform_completion<W: minicbor::encode::Write>(
    encoder: &mut minicbor::Encoder<W>,
    completion: &[u8],
) -> Result<(), ProtocolError> {
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(completion))
        .map_err(ProtocolError::malformed)?;
    Ok(())
}

pub fn encode_ui_authentication_browser_begin_request_v2(
    value: UiAuthenticationBrowserBeginRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    match value {
        UiAuthenticationBrowserBeginRequestV2::Ingress {
            pre_authentication,
            client_request_nonce,
        } => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            pre_authentication
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            client_request_nonce
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        UiAuthenticationBrowserBeginRequestV2::ApprovalDisplay {
            pre_authentication,
            client_request_nonce,
        } => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            pre_authentication
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            client_request_nonce
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        UiAuthenticationBrowserBeginRequestV2::Agent {
            pre_authentication,
            client_request_nonce,
        } => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            pre_authentication
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            client_request_nonce
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_ui_authentication_browser_begin_request_v2(
    bytes: &[u8],
) -> Result<UiAuthenticationBrowserBeginRequestV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 3)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match tag {
        1 => UiAuthenticationBrowserBeginRequestV2::Ingress {
            pre_authentication: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        2 => UiAuthenticationBrowserBeginRequestV2::ApprovalDisplay {
            pre_authentication: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        3 => UiAuthenticationBrowserBeginRequestV2::Agent {
            pre_authentication: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        _ => return Err(malformed()),
    };
    if value.client_request_nonce().as_bytes() == &[0; 32]
        || decoder.position() != bytes.len()
        || encode_ui_authentication_browser_begin_request_v2(value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_ui_authentication_browser_begin_response_v2(
    value: &UiAuthenticationBrowserBeginResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    match value {
        UiAuthenticationBrowserBeginResponseV2::Ingress {
            ceremony,
            public_key_options_json,
        } => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encode_options(&mut encoder, public_key_options_json)?;
        }
        UiAuthenticationBrowserBeginResponseV2::ApprovalDisplay {
            ceremony,
            public_key_options_json,
        } => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encode_options(&mut encoder, public_key_options_json)?;
        }
        UiAuthenticationBrowserBeginResponseV2::Agent {
            ceremony,
            public_key_options_json,
        } => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encode_options(&mut encoder, public_key_options_json)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_ui_authentication_browser_begin_response_v2(
    bytes: &[u8],
) -> Result<UiAuthenticationBrowserBeginResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 3)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match tag {
        1 => UiAuthenticationBrowserBeginResponseV2::Ingress {
            ceremony: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            public_key_options_json: decode_options(&mut decoder)?,
        },
        2 => UiAuthenticationBrowserBeginResponseV2::ApprovalDisplay {
            ceremony: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            public_key_options_json: decode_options(&mut decoder)?,
        },
        3 => UiAuthenticationBrowserBeginResponseV2::Agent {
            ceremony: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            public_key_options_json: decode_options(&mut decoder)?,
        },
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len()
        || encode_ui_authentication_browser_begin_response_v2(&value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_ui_authentication_browser_finish_request_v2(
    value: &UiAuthenticationBrowserFinishRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).map_err(ProtocolError::malformed)?;
    let (tag, nonce, assertion) = match value {
        UiAuthenticationBrowserFinishRequestV2::Ingress {
            ceremony,
            client_request_nonce,
            assertion,
        } => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            (1_u16, client_request_nonce, assertion)
        }
        UiAuthenticationBrowserFinishRequestV2::ApprovalDisplay {
            ceremony,
            client_request_nonce,
            assertion,
        } => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            (2_u16, client_request_nonce, assertion)
        }
        UiAuthenticationBrowserFinishRequestV2::Agent {
            ceremony,
            client_request_nonce,
            assertion,
        } => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            ceremony
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            (3_u16, client_request_nonce, assertion)
        }
    };
    let _ = tag;
    nonce
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encode_assertion(&mut encoder, assertion)?;
    Ok(encoder.into_writer())
}

pub fn decode_ui_authentication_browser_finish_request_v2(
    bytes: &[u8],
) -> Result<UiAuthenticationBrowserFinishRequestV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 4)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    macro_rules! finish_variant {
        ($variant:ident, $ceremony:ty) => {{
            let ceremony: $ceremony = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let client_request_nonce: Nonce32V2 =
                minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?;
            let assertion = decode_assertion(&mut decoder)?;
            UiAuthenticationBrowserFinishRequestV2::$variant {
                ceremony,
                client_request_nonce,
                assertion,
            }
        }};
    }
    let value = match tag {
        1 => finish_variant!(Ingress, IngressUiAuthenticationBrowserCeremonyCapabilityV2),
        2 => finish_variant!(
            ApprovalDisplay,
            ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2
        ),
        3 => finish_variant!(Agent, AgentUiAuthenticationBrowserCeremonyCapabilityV2),
        _ => return Err(malformed()),
    };
    let nonce = match &value {
        UiAuthenticationBrowserFinishRequestV2::Ingress {
            client_request_nonce,
            ..
        }
        | UiAuthenticationBrowserFinishRequestV2::ApprovalDisplay {
            client_request_nonce,
            ..
        }
        | UiAuthenticationBrowserFinishRequestV2::Agent {
            client_request_nonce,
            ..
        } => *client_request_nonce,
    };
    if nonce.as_bytes() == &[0; 32] || decoder.position() != bytes.len() {
        return Err(malformed());
    }
    let canonical = encode_ui_authentication_browser_finish_request_v2(&value)?;
    if canonical != bytes {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_ui_authentication_browser_finish_response_v2(
    value: UiAuthenticationBrowserFinishResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
            return_origin,
            transfer,
        } => {
            if return_origin != FixedOriginV2::Ingress8767 {
                return Err(malformed());
            }
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            return_origin
                .encode(&mut encoder, &mut ())
                .and_then(|()| transfer.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady { tab } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            tab.encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        UiAuthenticationBrowserFinishResponseV2::TransferToAgent {
            return_origin,
            transfer,
        } => {
            if return_origin != FixedOriginV2::Agent8768 {
                return Err(malformed());
            }
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            return_origin
                .encode(&mut encoder, &mut ())
                .and_then(|()| transfer.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_ui_authentication_browser_finish_response_v2(
    bytes: &[u8],
) -> Result<UiAuthenticationBrowserFinishResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match (tag, count) {
        (1, Some(3)) => UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
            return_origin: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            transfer: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (2, Some(2)) => UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady {
            tab: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (3, Some(3)) => UiAuthenticationBrowserFinishResponseV2::TransferToAgent {
            return_origin: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            transfer: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len()
        || encode_ui_authentication_browser_finish_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_options<W: minicbor::encode::Write>(
    encoder: &mut minicbor::Encoder<W>,
    bytes: &[u8],
) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_CLIENT_DATA_JSON_BYTES_V2 {
        return Err(malformed());
    }
    encoder.bytes(bytes).map_err(ProtocolError::malformed)?;
    Ok(())
}

fn decode_options(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let bytes = decoder.bytes().map_err(ProtocolError::malformed)?;
    if bytes.is_empty() || bytes.len() > MAX_CLIENT_DATA_JSON_BYTES_V2 {
        return Err(malformed());
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

fn encode_assertion<W: minicbor::encode::Write>(
    encoder: &mut minicbor::Encoder<W>,
    assertion: &BrowserWebAuthnAssertionV2,
) -> Result<(), ProtocolError> {
    encoder.array(5).map_err(ProtocolError::malformed)?;
    for bytes in [
        assertion.credential_id.as_slice(),
        assertion.authenticator_data.as_slice(),
        assertion.client_data_json.as_slice(),
        assertion.signature.as_slice(),
        assertion.user_handle.as_slice(),
    ] {
        encoder.bytes(bytes).map_err(ProtocolError::malformed)?;
    }
    Ok(())
}

fn decode_assertion(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<BrowserWebAuthnAssertionV2, ProtocolError> {
    require_array(decoder, 5)?;
    BrowserWebAuthnAssertionV2::new(
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
    )
}

fn validate_body(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_BROWSER_BODY_BYTES_V2 {
        Err(malformed())
    } else {
        Ok(())
    }
}

fn require_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? == Some(expected) {
        Ok(())
    } else {
        Err(malformed())
    }
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(crate::StableCode::ProtocolMalformedCbor)
}

fn noncanonical() -> ProtocolError {
    ProtocolError::stable(crate::StableCode::ProtocolNonCanonicalCbor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_status_profile_is_canonical_and_closed() {
        for (profile, tag, name) in [
            (
                OwnerAuthenticationProfileV2::MacPlatform,
                1_u8,
                "mac-platform",
            ),
            (
                OwnerAuthenticationProfileV2::HardwareWebAuthnCompatibility,
                2_u8,
                "hardware-webauthn-compatibility",
            ),
        ] {
            let bytes = encode_owner_authentication_profile_v2(profile).unwrap();
            assert_eq!(bytes, vec![tag]);
            assert_eq!(
                decode_owner_authentication_profile_v2(&bytes).unwrap(),
                profile
            );
            assert_eq!(profile.as_bootstrap_str(), name);
            assert_eq!(
                OwnerAuthenticationProfileV2::from_bootstrap_str(name).unwrap(),
                profile
            );
        }

        assert!(decode_owner_authentication_profile_v2(&[3]).is_err());
        assert!(decode_owner_authentication_profile_v2(&[0x18, 1]).is_err());
        assert!(OwnerAuthenticationProfileV2::from_bootstrap_str("MacPlatform").is_err());
        assert!(OwnerAuthenticationProfileV2::from_bootstrap_str("mac-platform ").is_err());
    }

    #[test]
    fn platform_status_ui_begin_and_request_preserve_exact_kind_capability_expiry_and_nonce() {
        let expires_at = super::super::UnixMillisV2::new(90_001);
        let nonce = Nonce32V2::new([0x44; 32]);
        let cases = [
            (
                UiAuthenticationPlatformBeginResponseV2::Ingress {
                    ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                        [0x11; 32],
                    )
                    .unwrap(),
                    expires_at,
                },
                UiAuthenticationPlatformStatusRequestV2::Ingress {
                    ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                        [0x11; 32],
                    )
                    .unwrap(),
                    client_request_nonce: nonce,
                },
            ),
            (
                UiAuthenticationPlatformBeginResponseV2::ApprovalDisplay {
                    ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                        [0x22; 32],
                    )
                    .unwrap(),
                    expires_at,
                },
                UiAuthenticationPlatformStatusRequestV2::ApprovalDisplay {
                    ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                        [0x22; 32],
                    )
                    .unwrap(),
                    client_request_nonce: nonce,
                },
            ),
            (
                UiAuthenticationPlatformBeginResponseV2::Agent {
                    ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                        [0x33; 32],
                    )
                    .unwrap(),
                    expires_at,
                },
                UiAuthenticationPlatformStatusRequestV2::Agent {
                    ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                        [0x33; 32],
                    )
                    .unwrap(),
                    client_request_nonce: nonce,
                },
            ),
        ];

        for (begin, status) in cases {
            let bytes = encode_ui_authentication_platform_begin_response_v2(begin).unwrap();
            let decoded = decode_ui_authentication_platform_begin_response_v2(&bytes).unwrap();
            assert_eq!(decoded, begin);
            assert_eq!(
                encode_ui_authentication_platform_begin_response_v2(decoded).unwrap(),
                bytes
            );

            let bytes = encode_ui_authentication_platform_status_request_v2(status).unwrap();
            let decoded = decode_ui_authentication_platform_status_request_v2(&bytes).unwrap();
            assert_eq!(decoded, status);
            assert_eq!(decoded.client_request_nonce(), nonce);
            assert_eq!(
                encode_ui_authentication_platform_status_request_v2(decoded).unwrap(),
                bytes
            );
        }

        let zero_expiry = [0x83, 0x01, 0x58, 0x20]
            .into_iter()
            .chain([0x11; 32])
            .chain([0x00])
            .collect::<Vec<_>>();
        assert!(decode_ui_authentication_platform_begin_response_v2(&zero_expiry).is_err());

        let mut zero_ceremony =
            encode_ui_authentication_platform_begin_response_v2(cases[0].0).unwrap();
        zero_ceremony[4..36].fill(0);
        assert!(decode_ui_authentication_platform_begin_response_v2(&zero_ceremony).is_err());
        let mut unknown_kind =
            encode_ui_authentication_platform_begin_response_v2(cases[0].0).unwrap();
        unknown_kind[1] = 4;
        assert!(decode_ui_authentication_platform_begin_response_v2(&unknown_kind).is_err());

        let valid = encode_ui_authentication_platform_status_request_v2(cases[0].1).unwrap();
        let mut zero_nonce = valid.clone();
        zero_nonce[38..70].fill(0);
        assert!(decode_ui_authentication_platform_status_request_v2(&zero_nonce).is_err());
        let mut wrong_length = valid.clone();
        wrong_length[0] = 0x82;
        assert!(decode_ui_authentication_platform_status_request_v2(&wrong_length).is_err());
        let mut trailing = valid;
        trailing.push(0);
        assert!(decode_ui_authentication_platform_status_request_v2(&trailing).is_err());
    }

    #[test]
    fn platform_status_ui_responses_cover_every_terminal_and_completion_kind() {
        let responses = [
            UiAuthenticationPlatformStatusResponseV2::Pending,
            UiAuthenticationPlatformStatusResponseV2::Completed(
                UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
                    return_origin: FixedOriginV2::Ingress8767,
                    transfer: IngressUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy(
                        [0x61; 32],
                    )
                    .unwrap(),
                },
            ),
            UiAuthenticationPlatformStatusResponseV2::Completed(
                UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady {
                    tab: ApprovalTabSessionCapabilityV2::from_authority_entropy([0x62; 32])
                        .unwrap(),
                },
            ),
            UiAuthenticationPlatformStatusResponseV2::Completed(
                UiAuthenticationBrowserFinishResponseV2::TransferToAgent {
                    return_origin: FixedOriginV2::Agent8768,
                    transfer: AgentUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy(
                        [0x63; 32],
                    )
                    .unwrap(),
                },
            ),
            UiAuthenticationPlatformStatusResponseV2::Denied,
            UiAuthenticationPlatformStatusResponseV2::Expired,
            UiAuthenticationPlatformStatusResponseV2::CredentialInvalidated,
            UiAuthenticationPlatformStatusResponseV2::Unavailable,
            UiAuthenticationPlatformStatusResponseV2::Indeterminate,
            UiAuthenticationPlatformStatusResponseV2::ProtocolFailure,
        ];

        for response in responses {
            let bytes = encode_ui_authentication_platform_status_response_v2(response).unwrap();
            let decoded = decode_ui_authentication_platform_status_response_v2(&bytes).unwrap();
            assert_eq!(decoded, response);
            assert_eq!(
                encode_ui_authentication_platform_status_response_v2(decoded).unwrap(),
                bytes
            );
        }

        assert_eq!(
            encode_ui_authentication_platform_status_response_v2(
                UiAuthenticationPlatformStatusResponseV2::Pending
            )
            .unwrap(),
            vec![0x81, 0x01]
        );
        for (response, tag) in [
            (UiAuthenticationPlatformStatusResponseV2::Denied, 3_u8),
            (UiAuthenticationPlatformStatusResponseV2::Expired, 4),
            (
                UiAuthenticationPlatformStatusResponseV2::CredentialInvalidated,
                5,
            ),
            (UiAuthenticationPlatformStatusResponseV2::Unavailable, 6),
            (UiAuthenticationPlatformStatusResponseV2::Indeterminate, 7),
            (UiAuthenticationPlatformStatusResponseV2::ProtocolFailure, 8),
        ] {
            assert_eq!(
                encode_ui_authentication_platform_status_response_v2(response).unwrap(),
                vec![0x81, tag]
            );
        }

        for malformed in [
            vec![0x81, 0x09],
            vec![0x82, 0x01, 0x01],
            vec![0x81, 0x18, 0x01],
            vec![0x81, 0x01, 0x00],
            vec![0x82, 0x02, 0x02],
        ] {
            assert!(decode_ui_authentication_platform_status_response_v2(&malformed).is_err());
        }
    }

    #[test]
    fn begin_request_is_canonical_and_purpose_typed() {
        let value = UiAuthenticationBrowserBeginRequestV2::Ingress {
            pre_authentication: IngressUiPreAuthenticationTabCapabilityV2::from_authority_entropy(
                [1; 32],
            )
            .unwrap(),
            client_request_nonce: Nonce32V2::new([2; 32]),
        };
        let bytes = encode_ui_authentication_browser_begin_request_v2(value).unwrap();
        assert_eq!(
            decode_ui_authentication_browser_begin_request_v2(&bytes).unwrap(),
            value
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_ui_authentication_browser_begin_request_v2(&trailing).is_err());
    }

    #[test]
    fn finish_assertion_round_trips_without_weak_json_reparse() {
        let value = UiAuthenticationBrowserFinishRequestV2::Agent {
            ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                [3; 32],
            )
            .unwrap(),
            client_request_nonce: Nonce32V2::new([4; 32]),
            assertion: BrowserWebAuthnAssertionV2::new(
                vec![5],
                vec![6; 37],
                br#"{"type":"webauthn.get"}"#.to_vec(),
                vec![7; 64],
                vec![8; 32],
            )
            .unwrap(),
        };
        let bytes = encode_ui_authentication_browser_finish_request_v2(&value).unwrap();
        let decoded = decode_ui_authentication_browser_finish_request_v2(&bytes).unwrap();
        assert_eq!(
            encode_ui_authentication_browser_finish_request_v2(&decoded).unwrap(),
            bytes
        );
    }

    #[test]
    fn ui_authentication_responses_round_trip_canonically_and_reject_trailing_data() {
        let begin = UiAuthenticationBrowserBeginResponseV2::Ingress {
            ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                [9; 32],
            )
            .unwrap(),
            public_key_options_json: Zeroizing::new(br#"{"challenge":"AQID"}"#.to_vec()),
        };
        let bytes = encode_ui_authentication_browser_begin_response_v2(&begin).unwrap();
        let decoded = decode_ui_authentication_browser_begin_response_v2(&bytes).unwrap();
        assert_eq!(
            encode_ui_authentication_browser_begin_response_v2(&decoded).unwrap(),
            bytes
        );
        let mut noncanonical = vec![bytes[0], 0x18, bytes[1]];
        noncanonical.extend_from_slice(&bytes[2..]);
        assert!(decode_ui_authentication_browser_begin_response_v2(&noncanonical).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_ui_authentication_browser_begin_response_v2(&trailing).is_err());

        let finish = UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady {
            tab: ApprovalTabSessionCapabilityV2::from_authority_entropy([10; 32]).unwrap(),
        };
        let bytes = encode_ui_authentication_browser_finish_response_v2(finish).unwrap();
        let decoded = decode_ui_authentication_browser_finish_response_v2(&bytes).unwrap();
        assert_eq!(
            encode_ui_authentication_browser_finish_response_v2(decoded).unwrap(),
            bytes
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_ui_authentication_browser_finish_response_v2(&trailing).is_err());
    }
}
