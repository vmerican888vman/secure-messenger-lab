//! Low-level canonical TLV primitives for the `ClientStateV1` codec
//! (docs/phase2-design-decisions.md section 3).
//!
//! Grammar (all integers big-endian):
//!
//! ```text
//! object =
//!   object_type:u16be
//!   field_count:u16be
//!   repeated:
//!     field_id:u16be
//!     value_len:u32be
//!     value[value_len]
//! ```
//!
//! Every object carries an exact field count and strictly ascending field
//! IDs. Because each object type has a fixed schema, the reader enforces the
//! exact expected ID sequence `1..=field_count`, which rejects unknown,
//! missing, duplicate and out-of-order fields with one check. The reader
//! never allocates from attacker-controlled lengths: a length prefix is
//! checked against the remaining input (and a per-field bound, where one
//! exists) before any bytes are consumed or copied.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{LabError, Result};

/// A non-allocating cursor over an immutable byte slice.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub(crate) const fn is_done(&self) -> bool {
        self.position == self.bytes.len()
    }

    /// Consume exactly `len` bytes. Fails without consuming anything when
    /// fewer than `len` bytes remain; no allocation ever happens here.
    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.remaining() {
            return Err(LabError::Storage);
        }
        let taken = &self.bytes[self.position..self.position + len];
        self.position += len;
        Ok(taken)
    }

    /// Consume exactly `len` bytes, rejecting `len > bound` first. Used for
    /// every attacker-controlled variable-length field so the bound is
    /// enforced before the bytes are touched.
    pub(crate) fn take_bounded(&mut self, len: usize, bound: usize) -> Result<&'a [u8]> {
        if len > bound {
            return Err(LabError::Storage);
        }
        self.take(len)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(fixed::<2>(self.take(2)?)?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(fixed::<4>(self.take(4)?)?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(fixed::<8>(self.take(8)?)?))
    }
}

/// Copy a slice into a fixed-size array, rejecting any other length. This is
/// the fixed-length-field enforcement point.
pub(crate) fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| LabError::Storage)
}

/// A `u32` length prefix converted to `usize`; fails on (hypothetical)
/// platforms where `usize` is narrower than `u32` instead of truncating.
pub(crate) fn length_prefix(raw: u32) -> Result<usize> {
    usize::try_from(raw).map_err(|_| LabError::Storage)
}

/// Stateful reader for one object body. Enforces the exact field-ID
/// sequence `1..=field_count` and complete consumption of the object bytes.
pub(crate) struct ObjectReader<'a> {
    reader: Reader<'a>,
    field_count: u16,
    next_field: u16,
}

impl<'a> ObjectReader<'a> {
    /// Read an object header from `reader` and require `expected_type`.
    pub(crate) fn expect(mut reader: Reader<'a>, expected_type: u16) -> Result<Self> {
        let object_type = reader.u16()?;
        if object_type != expected_type {
            return Err(LabError::Storage);
        }
        let field_count = reader.u16()?;
        if field_count == 0 {
            return Err(LabError::Storage);
        }
        Ok(Self {
            reader,
            field_count,
            next_field: 1,
        })
    }

    fn read_header(&mut self, expected_id: u16) -> Result<usize> {
        if expected_id != self.next_field || self.next_field > self.field_count {
            // Unknown, missing, duplicate or out-of-order field: the schema
            // fixes the exact ID sequence, so any deviation is a rejection.
            return Err(LabError::Storage);
        }
        let actual_id = self.reader.u16()?;
        if actual_id != expected_id {
            return Err(LabError::Storage);
        }
        let length = length_prefix(self.reader.u32()?)?;
        self.next_field += 1;
        Ok(length)
    }

    /// Read the next field, requiring `expected_id` and returning its value.
    pub(crate) fn field(&mut self, expected_id: u16) -> Result<&'a [u8]> {
        let length = self.read_header(expected_id)?;
        self.reader.take(length)
    }

    /// Read the next field like [`ObjectReader::field`], additionally
    /// enforcing `bound` on the value length before consuming any bytes.
    pub(crate) fn field_bounded(&mut self, expected_id: u16, bound: usize) -> Result<&'a [u8]> {
        let length = self.read_header(expected_id)?;
        self.reader.take_bounded(length, bound)
    }

    /// Require that every declared field was read and no trailing bytes
    /// remain inside the object.
    pub(crate) fn finish(&self) -> Result<()> {
        if u32::from(self.next_field) != u32::from(self.field_count) + 1 {
            return Err(LabError::Storage);
        }
        if !self.reader.is_done() {
            return Err(LabError::Storage);
        }
        Ok(())
    }
}

pub(crate) fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Append one `field_id`/ `value_len` / `value` triple.
pub(crate) fn write_field(out: &mut Vec<u8>, id: u16, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| LabError::Storage)?;
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Assemble a complete object from `(field_id, value)` pairs, which the
/// caller must supply in strictly ascending ID order (the schema order).
pub(crate) fn write_object(object_type: u16, fields: &[(u16, Vec<u8>)]) -> Result<Vec<u8>> {
    let field_count = u16::try_from(fields.len()).map_err(|_| LabError::Storage)?;
    if field_count == 0 {
        return Err(LabError::Storage);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&object_type.to_be_bytes());
    out.extend_from_slice(&field_count.to_be_bytes());
    for (id, value) in fields {
        write_field(&mut out, *id, value)?;
    }
    Ok(out)
}

/// Bounded canonical-JSON verification for dependency pickles and keypairs
/// (design section 3): bound first, deserialize, reject trailing data with
/// `Deserializer::end`, reserialize and require byte equality. Byte equality
/// against the compact reserialization rejects whitespace variants, unknown
/// fields, missing or defaulted fields, duplicate keys (serde's derive
/// rejects them first), serde aliases, non-canonical member order and
/// trailing bytes.
pub(crate) fn canonical_json<T>(bytes: &[u8], bound: usize) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > bound {
        return Err(LabError::Storage);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer).map_err(|_| LabError::Storage)?;
    deserializer.end().map_err(|_| LabError::Storage)?;
    let reserialized = serde_json::to_vec(&value).map_err(|_| LabError::Storage)?;
    if reserialized != bytes {
        return Err(LabError::Storage);
    }
    Ok(value)
}
