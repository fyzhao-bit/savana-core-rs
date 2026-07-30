use minicbor::Encode as _;
use savana_kernel_protocol::v2::{Digest32V2, InternalSlotDigestV2, V2DecodeContext};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::G3Error;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_COLLECTION_ITEMS: usize = 65_536;
const MAX_VALUE_DEPTH: usize = 16;
const MAX_VALUE_NODES: usize = 65_536;
const MAX_VALUE_ENCODED_BYTES: usize = 8 * 1024 * 1024;

macro_rules! ascii_identifier_v2 {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, G3Error> {
                let value = value.into();
                if !is_valid_identifier(&value) {
                    return Err(G3Error::InvalidIdentifier);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.str(&self.0)?;
                Ok(())
            }
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                Self::new(decoder.str()?).map_err(|_| {
                    minicbor::decode::Error::message("invalid canonical identifier").at(position)
                })
            }
        }
    };
}

ascii_identifier_v2!(IdentifierV2);
ascii_identifier_v2!(FieldNameV2);
ascii_identifier_v2!(ArgumentNameV2);

fn is_valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENTIFIER_BYTES || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

pub struct KernelValueV2(KernelValueKindV2);

enum KernelValueKindV2 {
    Null,
    Bool(bool),
    I64(i64),
    Text(Zeroizing<String>),
    Bytes(Zeroizing<Vec<u8>>),
    List(Vec<KernelValueV2>),
    Object(Vec<(FieldNameV2, KernelValueV2)>),
    InternalSlot(InternalSlotDigestV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelScalarRefV2<'value> {
    Null,
    Bool(bool),
    I64(i64),
    Text(&'value str),
    Digest(Digest32V2),
}

impl KernelValueV2 {
    pub const fn null() -> Self {
        Self(KernelValueKindV2::Null)
    }

    pub const fn boolean(value: bool) -> Self {
        Self(KernelValueKindV2::Bool(value))
    }

    pub const fn integer(value: i64) -> Self {
        Self(KernelValueKindV2::I64(value))
    }

    pub fn text(value: impl Into<String>) -> Result<Self, G3Error> {
        let value = Self(KernelValueKindV2::Text(Zeroizing::new(value.into())));
        value.validate_complete()?;
        Ok(value)
    }

    pub fn bytes(value: impl Into<Vec<u8>>) -> Result<Self, G3Error> {
        let value = Self(KernelValueKindV2::Bytes(Zeroizing::new(value.into())));
        value.validate_complete()?;
        Ok(value)
    }

    pub fn list(values: Vec<Self>) -> Result<Self, G3Error> {
        if values.len() > MAX_COLLECTION_ITEMS {
            return Err(G3Error::CollectionLimitExceeded);
        }
        let value = Self(KernelValueKindV2::List(values));
        value.validate_complete()?;
        Ok(value)
    }

    pub fn object(fields: Vec<(FieldNameV2, Self)>) -> Result<Self, G3Error> {
        if fields.len() > MAX_COLLECTION_ITEMS {
            return Err(G3Error::CollectionLimitExceeded);
        }
        if fields.windows(2).any(|pair| {
            canonical_text_order(pair[0].0.as_str(), pair[1].0.as_str()) != std::cmp::Ordering::Less
        }) {
            return Err(G3Error::NonCanonicalOrder);
        }
        let value = Self(KernelValueKindV2::Object(fields));
        value.validate_complete()?;
        Ok(value)
    }

    pub const fn internal_slot(digest: InternalSlotDigestV2) -> Self {
        Self(KernelValueKindV2::InternalSlot(digest))
    }

    pub(crate) fn as_text(&self) -> Option<&str> {
        match &self.0 {
            KernelValueKindV2::Text(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn object_field(&self, name: &str) -> Option<&Self> {
        match &self.0 {
            KernelValueKindV2::Object(fields) => fields
                .iter()
                .find_map(|(field, value)| (field.as_str() == name).then_some(value)),
            _ => None,
        }
    }

    pub(crate) fn select_path(&self, fields: &[FieldNameV2]) -> Option<&Self> {
        let mut selected = self;
        for field in fields {
            selected = selected.object_field(field.as_str())?;
        }
        Some(selected)
    }

    pub(crate) fn scalar_ref(&self) -> Option<KernelScalarRefV2<'_>> {
        match &self.0 {
            KernelValueKindV2::Null => Some(KernelScalarRefV2::Null),
            KernelValueKindV2::Bool(value) => Some(KernelScalarRefV2::Bool(*value)),
            KernelValueKindV2::I64(value) => Some(KernelScalarRefV2::I64(*value)),
            KernelValueKindV2::Text(value) => Some(KernelScalarRefV2::Text(value)),
            KernelValueKindV2::InternalSlot(digest) => Some(KernelScalarRefV2::Digest(
                Digest32V2::new(*digest.as_bytes()),
            )),
            KernelValueKindV2::Bytes(_)
            | KernelValueKindV2::List(_)
            | KernelValueKindV2::Object(_) => None,
        }
    }

    pub(crate) fn contains_internal_slot(&self) -> bool {
        match &self.0 {
            KernelValueKindV2::InternalSlot(_) => true,
            KernelValueKindV2::List(values) => {
                values.iter().any(KernelValueV2::contains_internal_slot)
            }
            KernelValueKindV2::Object(fields) => fields
                .iter()
                .any(|(_, value)| value.contains_internal_slot()),
            KernelValueKindV2::Null
            | KernelValueKindV2::Bool(_)
            | KernelValueKindV2::I64(_)
            | KernelValueKindV2::Text(_)
            | KernelValueKindV2::Bytes(_) => false,
        }
    }

    pub(crate) fn try_clone_internal(&self) -> Result<Self, G3Error> {
        let kind = match &self.0 {
            KernelValueKindV2::Null => KernelValueKindV2::Null,
            KernelValueKindV2::Bool(value) => KernelValueKindV2::Bool(*value),
            KernelValueKindV2::I64(value) => KernelValueKindV2::I64(*value),
            KernelValueKindV2::Text(value) => {
                let mut output = String::new();
                output
                    .try_reserve_exact(value.len())
                    .map_err(|_| G3Error::AllocationFailure)?;
                output.push_str(value);
                KernelValueKindV2::Text(Zeroizing::new(output))
            }
            KernelValueKindV2::Bytes(value) => {
                let mut output = Vec::new();
                output
                    .try_reserve_exact(value.len())
                    .map_err(|_| G3Error::AllocationFailure)?;
                output.extend_from_slice(value);
                KernelValueKindV2::Bytes(Zeroizing::new(output))
            }
            KernelValueKindV2::List(values) => {
                let mut output = Vec::new();
                output
                    .try_reserve_exact(values.len())
                    .map_err(|_| G3Error::AllocationFailure)?;
                for value in values {
                    output.push(value.try_clone_internal()?);
                }
                KernelValueKindV2::List(output)
            }
            KernelValueKindV2::Object(fields) => {
                let mut output = Vec::new();
                output
                    .try_reserve_exact(fields.len())
                    .map_err(|_| G3Error::AllocationFailure)?;
                for (name, value) in fields {
                    output.push((name.clone(), value.try_clone_internal()?));
                }
                KernelValueKindV2::Object(output)
            }
            KernelValueKindV2::InternalSlot(digest) => KernelValueKindV2::InternalSlot(*digest),
        };
        Ok(Self(kind))
    }

    pub(crate) fn list_from_refs(values: &[&Self]) -> Result<Self, G3Error> {
        if values.len() > MAX_COLLECTION_ITEMS {
            return Err(G3Error::CollectionLimitExceeded);
        }
        validate_borrowed_list(values)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(values.len())
            .map_err(|_| G3Error::AllocationFailure)?;
        for value in values {
            output.push(value.try_clone_internal()?);
        }
        Ok(Self(KernelValueKindV2::List(output)))
    }

    pub(crate) fn object_from_refs(
        fields: &[ArgumentNameV2],
        values: &[&Self],
    ) -> Result<Self, G3Error> {
        if fields.len() != values.len() {
            return Err(G3Error::DeriveArityMismatch);
        }
        validate_borrowed_object(fields, values)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(fields.len())
            .map_err(|_| G3Error::AllocationFailure)?;
        for (name, value) in fields.iter().zip(values) {
            output.push((
                FieldNameV2::new(name.as_str())?,
                value.try_clone_internal()?,
            ));
        }
        Ok(Self(KernelValueKindV2::Object(output)))
    }

    pub(crate) fn validate_text_output_size(length: usize) -> Result<(), G3Error> {
        let encoded_size = 2_usize
            .checked_add(cbor_length_prefix_size(length))
            .and_then(|size| size.checked_add(length))
            .ok_or(G3Error::ValueEncodedBytesExceeded)?;
        if encoded_size > MAX_VALUE_ENCODED_BYTES {
            return Err(G3Error::ValueEncodedBytesExceeded);
        }
        Ok(())
    }

    fn validate(&self, depth: usize, nodes: &mut usize) -> Result<(), G3Error> {
        if depth > MAX_VALUE_DEPTH {
            return Err(G3Error::ValueDepthExceeded);
        }
        *nodes = nodes
            .checked_add(1)
            .ok_or(G3Error::ValueNodeLimitExceeded)?;
        if *nodes > MAX_VALUE_NODES {
            return Err(G3Error::ValueNodeLimitExceeded);
        }
        match &self.0 {
            KernelValueKindV2::List(values) => {
                for value in values {
                    value.validate(depth + 1, nodes)?;
                }
            }
            KernelValueKindV2::Object(fields) => {
                for (_, value) in fields {
                    value.validate(depth + 1, nodes)?;
                }
            }
            KernelValueKindV2::Null
            | KernelValueKindV2::Bool(_)
            | KernelValueKindV2::I64(_)
            | KernelValueKindV2::Text(_)
            | KernelValueKindV2::Bytes(_)
            | KernelValueKindV2::InternalSlot(_) => {}
        }
        Ok(())
    }

    fn validate_complete(&self) -> Result<(), G3Error> {
        let mut nodes = 0;
        self.validate(1, &mut nodes)?;
        let mut encoder = minicbor::Encoder::new(BoundedDigestWriter::new(b""));
        if self.encode(&mut encoder, &mut ()).is_err() {
            return if encoder.writer().overflowed {
                Err(G3Error::ValueEncodedBytesExceeded)
            } else {
                Err(G3Error::CanonicalEncoding)
            };
        }
        Ok(())
    }

    fn shape_metrics(&self) -> Result<(usize, usize), G3Error> {
        match &self.0 {
            KernelValueKindV2::List(values) => shape_metrics_for_children(values.iter()),
            KernelValueKindV2::Object(fields) => {
                shape_metrics_for_children(fields.iter().map(|(_, value)| value))
            }
            KernelValueKindV2::Null
            | KernelValueKindV2::Bool(_)
            | KernelValueKindV2::I64(_)
            | KernelValueKindV2::Text(_)
            | KernelValueKindV2::Bytes(_)
            | KernelValueKindV2::InternalSlot(_) => Ok((1, 1)),
        }
    }
}

impl<C> minicbor::Encode<C> for KernelValueV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match &self.0 {
            KernelValueKindV2::Null => {
                encoder.array(1)?.u16(0)?;
            }
            KernelValueKindV2::Bool(value) => {
                encoder.array(2)?.u16(1)?.bool(*value)?;
            }
            KernelValueKindV2::I64(value) => {
                encoder.array(2)?.u16(2)?.i64(*value)?;
            }
            KernelValueKindV2::Text(value) => {
                encoder.array(2)?.u16(3)?.str(value)?;
            }
            KernelValueKindV2::Bytes(value) => {
                encoder.array(2)?.u16(4)?.bytes(value)?;
            }
            KernelValueKindV2::List(values) => {
                encoder.array(2)?.u16(5)?.array(values.len() as u64)?;
                for value in values {
                    value.encode(encoder, context)?;
                }
            }
            KernelValueKindV2::Object(fields) => {
                encoder.array(2)?.u16(6)?.array(fields.len() as u64)?;
                for (name, value) in fields {
                    encoder.array(2)?;
                    name.encode(encoder, context)?;
                    value.encode(encoder, context)?;
                }
            }
            KernelValueKindV2::InternalSlot(digest) => {
                encoder.array(2)?.u16(7)?;
                digest.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for KernelValueV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let mut nodes = 0_usize;
        decode_kernel_value(decoder, context, 1, &mut nodes)
    }
}

fn decode_kernel_value(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
    depth: usize,
    nodes: &mut usize,
) -> Result<KernelValueV2, minicbor::decode::Error> {
    let position = decoder.position();
    if depth > MAX_VALUE_DEPTH {
        return Err(minicbor::decode::Error::message("value depth exceeded").at(position));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| minicbor::decode::Error::message("value nodes exceeded").at(position))?;
    if *nodes > MAX_VALUE_NODES {
        return Err(minicbor::decode::Error::message("value nodes exceeded").at(position));
    }
    let length = decoder
        .array()?
        .ok_or_else(|| minicbor::decode::Error::message("indefinite value").at(position))?;
    let tag = decoder.u16()?;
    let value = match (length, tag) {
        (1, 0) => KernelValueV2::null(),
        (2, 1) => KernelValueV2::boolean(decoder.bool()?),
        (2, 2) => KernelValueV2::integer(decoder.i64()?),
        (2, 3) => KernelValueV2::text(decoder.str()?)
            .map_err(|_| minicbor::decode::Error::message("invalid text value").at(position))?,
        (2, 4) => KernelValueV2::bytes(decoder.bytes()?)
            .map_err(|_| minicbor::decode::Error::message("invalid byte value").at(position))?,
        (2, 5) => {
            let count = decode_value_count(decoder, position)?;
            let mut values = Vec::new();
            values.try_reserve_exact(count).map_err(|_| {
                minicbor::decode::Error::message("value allocation failed").at(position)
            })?;
            for _ in 0..count {
                values.push(decode_kernel_value(decoder, context, depth + 1, nodes)?);
            }
            KernelValueV2::list(values)
                .map_err(|_| minicbor::decode::Error::message("invalid list value").at(position))?
        }
        (2, 6) => {
            let count = decode_value_count(decoder, position)?;
            let mut fields = Vec::new();
            fields.try_reserve_exact(count).map_err(|_| {
                minicbor::decode::Error::message("value allocation failed").at(position)
            })?;
            for _ in 0..count {
                if decoder.array()? != Some(2) {
                    return Err(
                        minicbor::decode::Error::message("invalid object field").at(position)
                    );
                }
                let name = minicbor::Decode::decode(decoder, context)?;
                let value = decode_kernel_value(decoder, context, depth + 1, nodes)?;
                fields.push((name, value));
            }
            KernelValueV2::object(fields).map_err(|_| {
                minicbor::decode::Error::message("invalid object value").at(position)
            })?
        }
        (2, 7) => KernelValueV2::internal_slot(minicbor::Decode::decode(decoder, context)?),
        _ => return Err(minicbor::decode::Error::message("unknown value tag").at(position)),
    };
    value
        .validate_complete()
        .map_err(|_| minicbor::decode::Error::message("invalid value").at(position))?;
    Ok(value)
}

fn decode_value_count(
    decoder: &mut minicbor::Decoder<'_>,
    position: usize,
) -> Result<usize, minicbor::decode::Error> {
    let count = decoder
        .array()?
        .ok_or_else(|| minicbor::decode::Error::message("indefinite collection").at(position))?;
    let count = usize::try_from(count)
        .map_err(|_| minicbor::decode::Error::message("collection too large").at(position))?;
    if count > MAX_COLLECTION_ITEMS {
        return Err(minicbor::decode::Error::message("collection too large").at(position));
    }
    Ok(count)
}

pub fn value_digest_v2(value: &KernelValueV2) -> Result<Digest32V2, G3Error> {
    value.validate_complete()?;
    let mut encoder = minicbor::Encoder::new(BoundedDigestWriter::new(b"SAVANA_VALUE_V2\0"));
    if value.encode(&mut encoder, &mut ()).is_err() {
        return if encoder.writer().overflowed {
            Err(G3Error::ValueEncodedBytesExceeded)
        } else {
            Err(G3Error::CanonicalEncoding)
        };
    }
    Ok(encoder.into_writer().finish())
}

fn canonical_text_order(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

struct BoundedDigestWriter {
    hasher: Sha256,
    encoded_bytes: usize,
    overflowed: bool,
}

impl BoundedDigestWriter {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        Self {
            hasher,
            encoded_bytes: 0,
            overflowed: false,
        }
    }

    fn finish(self) -> Digest32V2 {
        Digest32V2::new(self.hasher.finalize().into())
    }
}

#[derive(Debug, Clone, Copy)]
struct ValueSizeLimit;

impl std::fmt::Display for ValueSizeLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("kernel value encoded-size limit exceeded")
    }
}

impl std::error::Error for ValueSizeLimit {}

impl minicbor::encode::Write for BoundedDigestWriter {
    type Error = ValueSizeLimit;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let Some(next_size) = self.encoded_bytes.checked_add(bytes.len()) else {
            self.overflowed = true;
            return Err(ValueSizeLimit);
        };
        if next_size > MAX_VALUE_ENCODED_BYTES {
            self.overflowed = true;
            return Err(ValueSizeLimit);
        }
        self.hasher.update(bytes);
        self.encoded_bytes = next_size;
        Ok(())
    }
}

fn validate_borrowed_list(values: &[&KernelValueV2]) -> Result<(), G3Error> {
    validate_borrowed_shape(values)?;
    let mut encoder = minicbor::Encoder::new(BoundedDigestWriter::new(b""));
    let result = (|| {
        encoder.array(2)?.u16(5)?.array(values.len() as u64)?;
        for value in values {
            value.encode(&mut encoder, &mut ())?;
        }
        Ok::<(), minicbor::encode::Error<ValueSizeLimit>>(())
    })();
    validate_borrowed_encoding_result(result, &encoder)
}

fn validate_borrowed_object(
    fields: &[ArgumentNameV2],
    values: &[&KernelValueV2],
) -> Result<(), G3Error> {
    validate_borrowed_shape(values)?;
    let mut encoder = minicbor::Encoder::new(BoundedDigestWriter::new(b""));
    let result = (|| {
        encoder.array(2)?.u16(6)?.array(fields.len() as u64)?;
        for (name, value) in fields.iter().zip(values) {
            encoder.array(2)?.str(name.as_str())?;
            value.encode(&mut encoder, &mut ())?;
        }
        Ok::<(), minicbor::encode::Error<ValueSizeLimit>>(())
    })();
    validate_borrowed_encoding_result(result, &encoder)
}

fn validate_borrowed_shape(values: &[&KernelValueV2]) -> Result<(), G3Error> {
    let (nodes, depth) = shape_metrics_for_children(values.iter().copied())?;
    if nodes > MAX_VALUE_NODES {
        return Err(G3Error::ValueNodeLimitExceeded);
    }
    if depth > MAX_VALUE_DEPTH {
        return Err(G3Error::ValueDepthExceeded);
    }
    Ok(())
}

fn shape_metrics_for_children<'value>(
    values: impl Iterator<Item = &'value KernelValueV2>,
) -> Result<(usize, usize), G3Error> {
    let mut nodes = 1_usize;
    let mut depth = 1_usize;
    for value in values {
        let (child_nodes, child_depth) = value.shape_metrics()?;
        nodes = nodes
            .checked_add(child_nodes)
            .ok_or(G3Error::ValueNodeLimitExceeded)?;
        depth = depth.max(
            child_depth
                .checked_add(1)
                .ok_or(G3Error::ValueDepthExceeded)?,
        );
    }
    Ok((nodes, depth))
}

fn validate_borrowed_encoding_result(
    result: Result<(), minicbor::encode::Error<ValueSizeLimit>>,
    encoder: &minicbor::Encoder<BoundedDigestWriter>,
) -> Result<(), G3Error> {
    if result.is_err() {
        return if encoder.writer().overflowed {
            Err(G3Error::ValueEncodedBytesExceeded)
        } else {
            Err(G3Error::CanonicalEncoding)
        };
    }
    Ok(())
}

const fn cbor_length_prefix_size(length: usize) -> usize {
    match length {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}
