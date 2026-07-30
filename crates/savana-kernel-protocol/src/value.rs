use minicbor::Encode;

use crate::{
    limits::{
        KERNEL_VALUE_MAX_DEPTH, KERNEL_VALUE_MAX_NODES, KERNEL_VALUE_MAX_TEXT_BYTES,
        KERNEL_VALUE_MAX_TOTAL_BYTES,
    },
    primitives::canonical_text_cmp,
    ProtocolError, StableCode,
};

pub const MAX_BOUNDED_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_BOUNDED_BYTES: usize = 1024 * 1024;
pub const MAX_BOUNDED_LIST_ITEMS: usize = 1_024;
pub const MAX_BOUNDED_OBJECT_ITEMS: usize = 256;
pub const MAX_ARGUMENT_NAMES: usize = 256;

fn protocol_error() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn valid_text(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len()) && !value.chars().any(char::is_control)
}

fn valid_bounded_content(value: &str, maximum: usize) -> bool {
    value.len() <= maximum && !value.chars().any(char::is_control)
}

macro_rules! bounded_identifier {
    ($name:ident, $maximum:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self, ProtocolError> {
                let value = value.as_ref();
                if !valid_text(value, $maximum) {
                    return Err(protocol_error());
                }
                Ok(Self(value.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ProtocolError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                if !valid_text(value, $maximum) {
                    return Err(protocol_error());
                }
                Ok(Self(value.to_owned()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = ProtocolError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                if !valid_text(&value, $maximum) {
                    return Err(protocol_error());
                }
                Ok(Self(value))
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
                let value = decoder.str()?;
                if !valid_text(value, $maximum) {
                    return Err(decode_error(position));
                }
                Ok(Self(value.to_owned()))
            }
        }
    };
}

bounded_identifier!(RoleId, 64);
bounded_identifier!(PrincipalId, 128);
bounded_identifier!(ConversationId, 128);
bounded_identifier!(TaskId, 128);
bounded_identifier!(ArtifactId, 128);
bounded_identifier!(PlannerId, 128);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArgumentName(String);

impl ArgumentName {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ProtocolError> {
        let value = value.as_ref();
        if !valid_argument_name(value) {
            return Err(protocol_error());
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_argument_name(value: &str) -> bool {
    if !(1..=64).contains(&value.len()) {
        return false;
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

impl TryFrom<&str> for ArgumentName {
    type Error = ProtocolError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !valid_argument_name(value) {
            return Err(protocol_error());
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for ArgumentName {
    type Error = ProtocolError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !valid_argument_name(&value) {
            return Err(protocol_error());
        }
        Ok(Self(value))
    }
}

impl<C> minicbor::Encode<C> for ArgumentName {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.str(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ArgumentName {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let value = decoder.str()?;
        if !valid_argument_name(value) {
            return Err(decode_error(position));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RunId([u8; 32]);

impl RunId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<C> minicbor::Encode<C> for RunId {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for RunId {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let bytes = <[u8; 32]>::try_from(decoder.bytes()?).map_err(|_| decode_error(position))?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedText(String);

impl BoundedText {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ProtocolError> {
        let value = value.as_ref();
        if !valid_bounded_content(value, MAX_BOUNDED_TEXT_BYTES) {
            return Err(protocol_error());
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for BoundedText {
    type Error = ProtocolError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !valid_bounded_content(value, MAX_BOUNDED_TEXT_BYTES) {
            return Err(protocol_error());
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for BoundedText {
    type Error = ProtocolError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !valid_bounded_content(&value, MAX_BOUNDED_TEXT_BYTES) {
            return Err(protocol_error());
        }
        Ok(Self(value))
    }
}

impl<C> minicbor::Encode<C> for BoundedText {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.str(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for BoundedText {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let value = decoder.str()?;
        if !valid_bounded_content(value, MAX_BOUNDED_TEXT_BYTES) {
            return Err(decode_error(position));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedBytes(Vec<u8>);

impl BoundedBytes {
    pub fn new(value: Vec<u8>) -> Result<Self, ProtocolError> {
        if value.len() > MAX_BOUNDED_BYTES {
            return Err(protocol_error());
        }
        Ok(Self(value))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for BoundedBytes {
    type Error = ProtocolError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<C> minicbor::Encode<C> for BoundedBytes {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for BoundedBytes {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let value = decoder.bytes()?;
        if value.len() > MAX_BOUNDED_BYTES {
            return Err(decode_error(position));
        }
        Ok(Self(value.to_vec()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedList(Vec<KernelValue>);

impl BoundedList {
    pub fn new(value: Vec<KernelValue>) -> Result<Self, ProtocolError> {
        if value.len() > MAX_BOUNDED_LIST_ITEMS {
            return Err(protocol_error());
        }
        Ok(Self(value))
    }

    pub fn as_slice(&self) -> &[KernelValue] {
        &self.0
    }
}

impl TryFrom<Vec<KernelValue>> for BoundedList {
    type Error = ProtocolError;

    fn try_from(value: Vec<KernelValue>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedObject(Vec<(ArgumentName, KernelValue)>);

impl BoundedObject {
    pub fn new(value: Vec<(ArgumentName, KernelValue)>) -> Result<Self, ProtocolError> {
        if value.len() > MAX_BOUNDED_OBJECT_ITEMS
            || !value
                .windows(2)
                .all(|pair| canonical_text_cmp(pair[0].0.as_str(), pair[1].0.as_str()).is_lt())
        {
            return Err(protocol_error());
        }
        Ok(Self(value))
    }

    pub fn as_slice(&self) -> &[(ArgumentName, KernelValue)] {
        &self.0
    }
}

impl TryFrom<Vec<(ArgumentName, KernelValue)>> for BoundedObject {
    type Error = ProtocolError;

    fn try_from(value: Vec<(ArgumentName, KernelValue)>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedArgumentNames(Vec<ArgumentName>);

impl BoundedArgumentNames {
    pub fn new(value: Vec<ArgumentName>) -> Result<Self, ProtocolError> {
        if value.len() > MAX_ARGUMENT_NAMES {
            return Err(protocol_error());
        }
        for (index, name) in value.iter().enumerate() {
            if value[..index].contains(name) {
                return Err(protocol_error());
            }
        }
        Ok(Self(value))
    }

    pub fn as_slice(&self) -> &[ArgumentName] {
        &self.0
    }
}

impl TryFrom<Vec<ArgumentName>> for BoundedArgumentNames {
    type Error = ProtocolError;

    fn try_from(value: Vec<ArgumentName>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelValue {
    Null,
    Bool(bool),
    Integer(i64),
    Text(BoundedText),
    Bytes(BoundedBytes),
    List(BoundedList),
    Object(BoundedObject),
}

pub(crate) struct DecodeBudget {
    depth: usize,
    nodes: usize,
    text_bytes: usize,
    total_bytes: usize,
}

impl DecodeBudget {
    pub(crate) fn new() -> Self {
        Self {
            depth: 0,
            nodes: 0,
            text_bytes: 0,
            total_bytes: 0,
        }
    }

    fn enter(&mut self, position: usize) -> Result<(), minicbor::decode::Error> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| decode_error(position))?;
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| decode_error(position))?;
        if self.depth > KERNEL_VALUE_MAX_DEPTH || self.nodes > KERNEL_VALUE_MAX_NODES {
            return Err(decode_error(position));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn charge_text(
        &mut self,
        bytes: usize,
        position: usize,
    ) -> Result<(), minicbor::decode::Error> {
        self.text_bytes = self
            .text_bytes
            .checked_add(bytes)
            .ok_or_else(|| decode_error(position))?;
        self.charge_total(bytes, position)?;
        if self.text_bytes > KERNEL_VALUE_MAX_TEXT_BYTES {
            return Err(decode_error(position));
        }
        Ok(())
    }

    fn charge_total(
        &mut self,
        bytes: usize,
        position: usize,
    ) -> Result<(), minicbor::decode::Error> {
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .ok_or_else(|| decode_error(position))?;
        if self.total_bytes > KERNEL_VALUE_MAX_TOTAL_BYTES {
            return Err(decode_error(position));
        }
        Ok(())
    }
}

pub(crate) fn validate_kernel_value_with_budget(
    value: &KernelValue,
    budget: &mut DecodeBudget,
) -> Result<(), ProtocolError> {
    enter_validation_node(budget)?;
    match value {
        KernelValue::Null | KernelValue::Bool(_) => charge_validation_total(budget, 1)?,
        KernelValue::Integer(_) => charge_validation_total(budget, 8)?,
        KernelValue::Text(text) => {
            charge_validation_text(budget, text.0.len())?;
        }
        KernelValue::Bytes(bytes) => charge_validation_total(budget, bytes.0.len())?,
        KernelValue::List(list) => {
            if list.0.len() > MAX_BOUNDED_LIST_ITEMS
                || list.0.len() > KERNEL_VALUE_MAX_NODES.saturating_sub(budget.nodes)
            {
                return Err(protocol_error());
            }
            for child in &list.0 {
                validate_kernel_value_with_budget(child, budget)?;
            }
        }
        KernelValue::Object(object) => validate_object_contents(object, budget)?,
    }
    budget.depth -= 1;
    Ok(())
}

fn enter_validation_node(budget: &mut DecodeBudget) -> Result<(), ProtocolError> {
    budget.depth = budget.depth.checked_add(1).ok_or_else(protocol_error)?;
    budget.nodes = budget.nodes.checked_add(1).ok_or_else(protocol_error)?;
    if budget.depth > KERNEL_VALUE_MAX_DEPTH || budget.nodes > KERNEL_VALUE_MAX_NODES {
        return Err(protocol_error());
    }
    Ok(())
}

fn validate_object_contents(
    object: &BoundedObject,
    budget: &mut DecodeBudget,
) -> Result<(), ProtocolError> {
    if object.0.len() > MAX_BOUNDED_OBJECT_ITEMS
        || object.0.len() > KERNEL_VALUE_MAX_NODES.saturating_sub(budget.nodes)
        || !object
            .0
            .windows(2)
            .all(|pair| canonical_text_cmp(pair[0].0.as_str(), pair[1].0.as_str()).is_lt())
    {
        return Err(protocol_error());
    }
    for (name, child) in &object.0 {
        charge_validation_text(budget, name.0.len())?;
        validate_kernel_value_with_budget(child, budget)?;
    }
    Ok(())
}

fn charge_validation_text(budget: &mut DecodeBudget, bytes: usize) -> Result<(), ProtocolError> {
    budget.text_bytes = budget
        .text_bytes
        .checked_add(bytes)
        .ok_or_else(protocol_error)?;
    if budget.text_bytes > KERNEL_VALUE_MAX_TEXT_BYTES {
        return Err(protocol_error());
    }
    charge_validation_total(budget, bytes)
}

fn charge_validation_total(budget: &mut DecodeBudget, bytes: usize) -> Result<(), ProtocolError> {
    budget.total_bytes = budget
        .total_bytes
        .checked_add(bytes)
        .ok_or_else(protocol_error)?;
    if budget.total_bytes > KERNEL_VALUE_MAX_TOTAL_BYTES {
        Err(protocol_error())
    } else {
        Ok(())
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

pub(crate) fn decode_kernel_value(
    decoder: &mut minicbor::Decoder<'_>,
    budget: &mut DecodeBudget,
) -> Result<KernelValue, minicbor::decode::Error> {
    let position = decoder.position();
    budget.enter(position)?;
    expect_array(decoder, 2)?;
    let tag = decoder.u8()?;
    let value = match tag {
        0 => {
            decoder.null()?;
            budget.charge_total(1, position)?;
            KernelValue::Null
        }
        1 => {
            let value = decoder.bool()?;
            budget.charge_total(1, position)?;
            KernelValue::Bool(value)
        }
        2 => {
            let value = decoder.i64()?;
            budget.charge_total(8, position)?;
            KernelValue::Integer(value)
        }
        3 => {
            let value_position = decoder.position();
            let value = decoder.str()?;
            if !valid_bounded_content(value, MAX_BOUNDED_TEXT_BYTES) {
                return Err(decode_error(value_position));
            }
            budget.charge_text(value.len(), value_position)?;
            KernelValue::Text(BoundedText(value.to_owned()))
        }
        4 => {
            let value_position = decoder.position();
            let value = decoder.bytes()?;
            if value.len() > MAX_BOUNDED_BYTES {
                return Err(decode_error(value_position));
            }
            budget.charge_total(value.len(), value_position)?;
            KernelValue::Bytes(BoundedBytes(value.to_vec()))
        }
        5 => {
            let array_position = decoder.position();
            let length = decoder
                .array()?
                .ok_or_else(|| decode_error(array_position))?;
            let length = usize::try_from(length).map_err(|_| decode_error(array_position))?;
            if length > MAX_BOUNDED_LIST_ITEMS
                || length > KERNEL_VALUE_MAX_NODES.saturating_sub(budget.nodes)
            {
                return Err(decode_error(array_position));
            }
            let mut values = Vec::with_capacity(length);
            for _ in 0..length {
                values.push(decode_kernel_value(decoder, budget)?);
            }
            KernelValue::List(BoundedList(values))
        }
        6 => {
            let array_position = decoder.position();
            let length = decoder
                .array()?
                .ok_or_else(|| decode_error(array_position))?;
            let length = usize::try_from(length).map_err(|_| decode_error(array_position))?;
            if length > MAX_BOUNDED_OBJECT_ITEMS
                || length > KERNEL_VALUE_MAX_NODES.saturating_sub(budget.nodes)
            {
                return Err(decode_error(array_position));
            }
            let mut entries = Vec::with_capacity(length);
            for _ in 0..length {
                expect_array(decoder, 2)?;
                let name_position = decoder.position();
                let name = decoder.str()?;
                if !valid_argument_name(name) {
                    return Err(decode_error(name_position));
                }
                budget.charge_text(name.len(), name_position)?;
                let name = ArgumentName(name.to_owned());
                let value = decode_kernel_value(decoder, budget)?;
                if entries
                    .last()
                    .is_some_and(|(previous, _): &(ArgumentName, KernelValue)| {
                        !canonical_text_cmp(previous.as_str(), name.as_str()).is_lt()
                    })
                {
                    return Err(decode_error(name_position));
                }
                entries.push((name, value));
            }
            KernelValue::Object(BoundedObject(entries))
        }
        _ => return Err(decode_error(position)),
    };
    budget.leave();
    Ok(value)
}

impl<C> minicbor::Encode<C> for KernelValue {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        validate_kernel_value_with_budget(self, &mut DecodeBudget::new()).map_err(|_| {
            minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
        })?;
        encode_kernel_value_unchecked(self, encoder, context)
    }
}

pub(crate) fn encode_kernel_value_unchecked<C, W>(
    value: &KernelValue,
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
) -> Result<(), minicbor::encode::Error<W::Error>>
where
    W: minicbor::encode::Write,
{
    encoder.array(2)?;
    match value {
        KernelValue::Null => {
            encoder.u8(0)?.null()?;
        }
        KernelValue::Bool(value) => {
            encoder.u8(1)?.bool(*value)?;
        }
        KernelValue::Integer(value) => {
            encoder.u8(2)?.i64(*value)?;
        }
        KernelValue::Text(value) => {
            encoder.u8(3)?;
            value.encode(encoder, context)?;
        }
        KernelValue::Bytes(value) => {
            encoder.u8(4)?;
            value.encode(encoder, context)?;
        }
        KernelValue::List(value) => {
            encoder.u8(5)?.array(
                u64::try_from(value.0.len())
                    .map_err(|error| minicbor::encode::Error::message(error.to_string()))?,
            )?;
            for child in &value.0 {
                encode_kernel_value_unchecked(child, encoder, context)?;
            }
        }
        KernelValue::Object(value) => {
            encoder.u8(6)?.array(
                u64::try_from(value.0.len())
                    .map_err(|error| minicbor::encode::Error::message(error.to_string()))?,
            )?;
            for (name, child) in &value.0 {
                encoder.array(2)?;
                name.encode(encoder, context)?;
                encode_kernel_value_unchecked(child, encoder, context)?;
            }
        }
    }
    Ok(())
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for KernelValue {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        decode_kernel_value(decoder, &mut DecodeBudget::new())
    }
}

impl<C> minicbor::Encode<C> for BoundedList {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut budget = DecodeBudget::new();
        for value in &self.0 {
            validate_kernel_value_with_budget(value, &mut budget).map_err(|_| {
                minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
            })?;
        }
        encoder.array(
            u64::try_from(self.0.len())
                .map_err(|error| minicbor::encode::Error::message(error.to_string()))?,
        )?;
        for value in &self.0 {
            encode_kernel_value_unchecked(value, encoder, context)?;
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for BoundedList {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let length = decoder.array()?.ok_or_else(|| decode_error(position))?;
        let length = usize::try_from(length).map_err(|_| decode_error(position))?;
        let mut budget = DecodeBudget::new();
        if length > MAX_BOUNDED_LIST_ITEMS
            || length > KERNEL_VALUE_MAX_NODES.saturating_sub(budget.nodes)
        {
            return Err(decode_error(position));
        }
        let mut values = Vec::with_capacity(length);
        for _ in 0..length {
            values.push(decode_kernel_value(decoder, &mut budget)?);
        }
        Ok(Self(values))
    }
}

impl<C> minicbor::Encode<C> for BoundedObject {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        validate_object_contents(self, &mut DecodeBudget::new()).map_err(|_| {
            minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
        })?;
        encoder.array(
            u64::try_from(self.0.len())
                .map_err(|error| minicbor::encode::Error::message(error.to_string()))?,
        )?;
        for (name, value) in &self.0 {
            encoder.array(2)?;
            name.encode(encoder, context)?;
            encode_kernel_value_unchecked(value, encoder, context)?;
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for BoundedObject {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let length = decoder.array()?.ok_or_else(|| decode_error(position))?;
        let length = usize::try_from(length).map_err(|_| decode_error(position))?;
        let mut budget = DecodeBudget::new();
        if length > MAX_BOUNDED_OBJECT_ITEMS
            || length > KERNEL_VALUE_MAX_NODES.saturating_sub(budget.nodes)
        {
            return Err(decode_error(position));
        }
        let mut entries = Vec::with_capacity(length);
        for _ in 0..length {
            expect_array(decoder, 2)?;
            let name_position = decoder.position();
            let name = ArgumentName::decode(decoder, &mut ())?;
            budget.charge_text(name.as_str().len(), name_position)?;
            if entries
                .last()
                .is_some_and(|(previous, _): &(ArgumentName, KernelValue)| {
                    !canonical_text_cmp(previous.as_str(), name.as_str()).is_lt()
                })
            {
                return Err(decode_error(position));
            }
            let value = decode_kernel_value(decoder, &mut budget)?;
            entries.push((name, value));
        }
        Ok(Self(entries))
    }
}

impl<C> minicbor::Encode<C> for BoundedArgumentNames {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(
            u64::try_from(self.0.len())
                .map_err(|error| minicbor::encode::Error::message(error.to_string()))?,
        )?;
        for name in &self.0 {
            name.encode(encoder, context)?;
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for BoundedArgumentNames {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let length = decoder.array()?.ok_or_else(|| decode_error(position))?;
        let length = usize::try_from(length).map_err(|_| decode_error(position))?;
        if length > MAX_ARGUMENT_NAMES {
            return Err(decode_error(position));
        }
        let mut values = Vec::with_capacity(length);
        for _ in 0..length {
            let value = ArgumentName::decode(decoder, context)?;
            if values.contains(&value) {
                return Err(decode_error(position));
            }
            values.push(value);
        }
        Ok(Self(values))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveOperation {
    Concatenate,
    NormalizeText,
    SelectObjectField(ArgumentName),
    AssembleList,
    AssembleObject(BoundedArgumentNames),
}

impl<C> minicbor::Encode<C> for DeriveOperation {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?;
        match self {
            Self::Concatenate => {
                encoder.u8(0)?.array(0)?;
            }
            Self::NormalizeText => {
                encoder.u8(1)?.array(0)?;
            }
            Self::SelectObjectField(name) => {
                encoder.u8(2)?;
                name.encode(encoder, context)?;
            }
            Self::AssembleList => {
                encoder.u8(3)?.array(0)?;
            }
            Self::AssembleObject(names) => {
                encoder.u8(4)?;
                names.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for DeriveOperation {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, 2)?;
        match decoder.u8()? {
            0 => {
                expect_array(decoder, 0)?;
                Ok(Self::Concatenate)
            }
            1 => {
                expect_array(decoder, 0)?;
                Ok(Self::NormalizeText)
            }
            2 => Ok(Self::SelectObjectField(ArgumentName::decode(
                decoder, context,
            )?)),
            3 => {
                expect_array(decoder, 0)?;
                Ok(Self::AssembleList)
            }
            4 => Ok(Self::AssembleObject(BoundedArgumentNames::decode(
                decoder, context,
            )?)),
            _ => Err(decode_error(position)),
        }
    }
}
