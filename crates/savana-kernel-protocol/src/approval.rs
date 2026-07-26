use crate::{
    value::{
        decode_kernel_value, encode_kernel_value_unchecked, validate_kernel_value_with_budget,
        DecodeBudget,
    },
    ArtifactId, BootId, BoundedText, ConversationId, Digest32, KernelValue, KeyId, Nonce32,
    PrincipalId, ProtocolError, RunId, ServerIdentityV1, Signature64, StableCode, TaskId,
    ToolExecutionIdentity, UnixMillis,
};
use sha2::{Digest, Sha256};

const APPROVAL_DISPLAY_DOMAIN: &[u8] = b"SAVANA_APPROVAL_DISPLAY_V1\0";

macro_rules! unit_tagged_enum {
    ($name:ident { $($variant:ident = $tag:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant),+
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array(2)?;
                match self {
                    $(Self::$variant => encoder.u8($tag)?.array(0)?,)+
                };
                Ok(())
            }
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                expect_array(decoder, 2)?;
                let value = match decoder.u8()? {
                    $($tag => Self::$variant,)+
                    _ => return Err(decode_error(position)),
                };
                expect_array(decoder, 0)?;
                Ok(value)
            }
        }
    };
}

unit_tagged_enum!(ApprovalPurposeV1 {
    ToolMaterialization = 0,
    FinalRelease = 1,
});
unit_tagged_enum!(ApprovalDecision {
    Approve = 0,
    Deny = 1,
});
unit_tagged_enum!(ApprovalAuthMethod { WebAuthnUv = 0 });

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalSubjectV1 {
    ToolCall {
        pending: crate::PendingToolCallHandle,
        argument_digest: Digest32,
        provenance_digest: Digest32,
    },
    VaultRelease {
        vault_session_id: Nonce32,
        evidence_digest: Digest32,
        masked_output_digest: Digest32,
        token_set_digest: Digest32,
        artifact_id: ArtifactId,
        artifact_generation: u32,
    },
}

impl<C> minicbor::Encode<C> for ApprovalSubjectV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?;
        match self {
            Self::ToolCall {
                pending,
                argument_digest,
                provenance_digest,
            } => {
                encoder.u8(0)?.array(3)?;
                pending.encode(encoder, context)?;
                argument_digest.encode(encoder, context)?;
                provenance_digest.encode(encoder, context)?;
            }
            Self::VaultRelease {
                vault_session_id,
                evidence_digest,
                masked_output_digest,
                token_set_digest,
                artifact_id,
                artifact_generation,
            } => {
                encoder.u8(1)?.array(6)?;
                vault_session_id.encode(encoder, context)?;
                evidence_digest.encode(encoder, context)?;
                masked_output_digest.encode(encoder, context)?;
                token_set_digest.encode(encoder, context)?;
                artifact_id.encode(encoder, context)?;
                encoder.u32(*artifact_generation)?;
            }
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ApprovalSubjectV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, 2)?;
        match decoder.u8()? {
            0 => {
                expect_array(decoder, 3)?;
                Ok(Self::ToolCall {
                    pending: crate::PendingToolCallHandle::decode(decoder, context)?,
                    argument_digest: Digest32::decode(decoder, context)?,
                    provenance_digest: Digest32::decode(decoder, context)?,
                })
            }
            1 => {
                expect_array(decoder, 6)?;
                Ok(Self::VaultRelease {
                    vault_session_id: Nonce32::decode(decoder, context)?,
                    evidence_digest: Digest32::decode(decoder, context)?,
                    masked_output_digest: Digest32::decode(decoder, context)?,
                    token_set_digest: Digest32::decode(decoder, context)?,
                    artifact_id: ArtifactId::decode(decoder, context)?,
                    artifact_generation: decoder.u32()?,
                })
            }
            _ => Err(decode_error(position)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct ApprovalChallengeV1 {
    #[n(0)]
    pub challenge_id: Nonce32,
    #[n(1)]
    pub purpose: ApprovalPurposeV1,
    #[n(2)]
    pub subject: ApprovalSubjectV1,
    #[n(3)]
    pub boot_id: BootId,
    #[n(4)]
    pub run_id: RunId,
    #[n(5)]
    pub principal: PrincipalId,
    #[n(6)]
    pub conversation_id: ConversationId,
    #[n(7)]
    pub task_id: TaskId,
    #[n(8)]
    pub tool: ToolExecutionIdentity,
    #[n(9)]
    pub destination_digest: Digest32,
    #[n(10)]
    pub policy_version: u64,
    #[n(11)]
    pub issued_at: UnixMillis,
    #[n(12)]
    pub expires_at: UnixMillis,
    #[n(13)]
    pub nonce: Nonce32,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ApprovalChallengeV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 14)?;
        Ok(Self {
            challenge_id: Nonce32::decode(decoder, context)?,
            purpose: ApprovalPurposeV1::decode(decoder, context)?,
            subject: ApprovalSubjectV1::decode(decoder, context)?,
            boot_id: BootId::decode(decoder, context)?,
            run_id: RunId::decode(decoder, context)?,
            principal: PrincipalId::decode(decoder, context)?,
            conversation_id: ConversationId::decode(decoder, context)?,
            task_id: TaskId::decode(decoder, context)?,
            tool: ToolExecutionIdentity::decode(decoder, context)?,
            destination_digest: Digest32::decode(decoder, context)?,
            policy_version: decoder.u64()?,
            issued_at: UnixMillis::decode(decoder, context)?,
            expires_at: UnixMillis::decode(decoder, context)?,
            nonce: Nonce32::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedDisplayBundleV1 {
    pub purpose_label: BoundedText,
    pub tool_label: BoundedText,
    pub masked_destination: KernelValue,
    pub masked_output: KernelValue,
}

pub fn approval_display_digest(display: &MaskedDisplayBundleV1) -> Result<Digest32, ProtocolError> {
    let canonical = minicbor::to_vec(display).map_err(ProtocolError::malformed)?;
    let mut hasher = Sha256::new();
    hasher.update(APPROVAL_DISPLAY_DOMAIN);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}

impl<C> minicbor::Encode<C> for MaskedDisplayBundleV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut budget = DecodeBudget::new();
        validate_kernel_value_with_budget(&self.masked_destination, &mut budget).map_err(|_| {
            minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
        })?;
        validate_kernel_value_with_budget(&self.masked_output, &mut budget).map_err(|_| {
            minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
        })?;
        encoder.array(4)?;
        self.purpose_label.encode(encoder, context)?;
        self.tool_label.encode(encoder, context)?;
        encode_kernel_value_unchecked(&self.masked_destination, encoder, context)?;
        encode_kernel_value_unchecked(&self.masked_output, encoder, context)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for MaskedDisplayBundleV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 4)?;
        let purpose_label = BoundedText::decode(decoder, context)?;
        let tool_label = BoundedText::decode(decoder, context)?;
        let mut budget = DecodeBudget::new();
        let masked_destination = decode_kernel_value(decoder, &mut budget)?;
        let masked_output = decode_kernel_value(decoder, &mut budget)?;
        Ok(Self {
            purpose_label,
            tool_label,
            masked_destination,
            masked_output,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct UnsignedApprovalEnvelopeV1 {
    #[n(0)]
    pub daemon_identity: ServerIdentityV1,
    #[n(1)]
    pub challenge: ApprovalChallengeV1,
    #[n(2)]
    pub display: MaskedDisplayBundleV1,
    #[n(3)]
    pub display_digest: Digest32,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for UnsignedApprovalEnvelopeV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 4)?;
        Ok(Self {
            daemon_identity: ServerIdentityV1::decode(decoder, context)?,
            challenge: ApprovalChallengeV1::decode(decoder, context)?,
            display: MaskedDisplayBundleV1::decode(decoder, context)?,
            display_digest: Digest32::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct SignedApprovalEnvelopeV1 {
    #[n(0)]
    pub unsigned: UnsignedApprovalEnvelopeV1,
    #[n(1)]
    pub daemon_key_id: KeyId,
    #[n(2)]
    pub signature: Signature64,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for SignedApprovalEnvelopeV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 3)?;
        Ok(Self {
            unsigned: UnsignedApprovalEnvelopeV1::decode(decoder, context)?,
            daemon_key_id: KeyId::decode(decoder, context)?,
            signature: Signature64::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct UnsignedApprovalReceiptV1 {
    #[n(0)]
    pub envelope_digest: Digest32,
    #[n(1)]
    pub challenge: ApprovalChallengeV1,
    #[n(2)]
    pub decision: ApprovalDecision,
    #[n(3)]
    pub approval_principal: PrincipalId,
    #[n(4)]
    pub auth_method: ApprovalAuthMethod,
    #[n(5)]
    pub approval_key_id: KeyId,
    #[n(6)]
    pub issued_at: UnixMillis,
    #[n(7)]
    pub expires_at: UnixMillis,
    #[n(8)]
    pub receipt_nonce: Nonce32,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for UnsignedApprovalReceiptV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 9)?;
        Ok(Self {
            envelope_digest: Digest32::decode(decoder, context)?,
            challenge: ApprovalChallengeV1::decode(decoder, context)?,
            decision: ApprovalDecision::decode(decoder, context)?,
            approval_principal: PrincipalId::decode(decoder, context)?,
            auth_method: ApprovalAuthMethod::decode(decoder, context)?,
            approval_key_id: KeyId::decode(decoder, context)?,
            issued_at: UnixMillis::decode(decoder, context)?,
            expires_at: UnixMillis::decode(decoder, context)?,
            receipt_nonce: Nonce32::decode(decoder, context)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode)]
#[cbor(array)]
pub struct ApprovalReceiptV1 {
    #[n(0)]
    pub unsigned: UnsignedApprovalReceiptV1,
    #[n(1)]
    pub signature: Signature64,
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ApprovalReceiptV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        expect_array(decoder, 2)?;
        Ok(Self {
            unsigned: UnsignedApprovalReceiptV1::decode(decoder, context)?,
            signature: Signature64::decode(decoder, context)?,
        })
    }
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), minicbor::decode::Error> {
    let position = decoder.position();
    if decoder.array()? == Some(expected) {
        Ok(())
    } else {
        Err(decode_error(position))
    }
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}
