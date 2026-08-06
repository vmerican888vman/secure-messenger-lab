//! `ClientPayloadV2` — the strict payload format carried inside Olm
//! encryption for façade traffic (design section 4: every Olm encryption,
//! including receipt-only controls, gets a durable session `epoch_id` and
//! `send_seq` from the same per-session counter, starting at 1).
//!
//! Strictness is the codec's canonical-JSON rule, replicated here because
//! the codec's helper is private to `crate::state`: bound first,
//! deserialize, reject trailing data with `Deserializer::end()`,
//! reserialize, require byte equality. The old v1 `PlainMessage` path in
//! `src/client.rs` is untouched.
//!
//! Deviation from the D2a brief: the receipt arm cannot literally reuse
//! `state::records::HighWaterReceipt` because that type (frozen, under
//! review) has no serde derives. [`ReceiptV2`] carries the identical
//! fields (version fixed at 1, implicit) and converts both ways.

use serde::{Deserialize, Serialize};
use vodozemac::{Curve25519PublicKey, Ed25519Signature};
use zeroize::Zeroizing;

use crate::ids::{ConversationId, MessageId};
use crate::state::{HighWaterReceipt, MAX_BODY};
use crate::{LabError, Result};

pub(crate) const PAYLOAD_VERSION: u8 = 2;
pub(crate) const KIND_APPLICATION: u8 = 1;
pub(crate) const KIND_RECEIPT: u8 = 2;
/// Body bound (mirrors the codec's) plus JSON framing slack.
pub(crate) const MAX_PAYLOAD_BYTES: usize = MAX_BODY + 512;

/// The receipt arm's payload-local mirror of
/// `state::records::HighWaterReceipt` (version 1, implicit). The signature
/// is a 64-byte vector (serde supports neither `Ed25519Signature` nor
/// `[u8; 64]`); the length is enforced by `validate_shape`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptV2 {
    pub(crate) conversation_id: ConversationId,
    pub(crate) epoch_id: [u8; 32],
    pub(crate) acknowledged_sender_curve: Curve25519PublicKey,
    pub(crate) issuer_curve: Curve25519PublicKey,
    pub(crate) high_water: u64,
    pub(crate) signature: Vec<u8>,
}

impl From<&HighWaterReceipt> for ReceiptV2 {
    fn from(receipt: &HighWaterReceipt) -> Self {
        Self {
            conversation_id: receipt.conversation_id,
            epoch_id: receipt.epoch_id,
            acknowledged_sender_curve: receipt.acknowledged_sender_curve,
            issuer_curve: receipt.issuer_curve,
            high_water: receipt.high_water,
            signature: receipt.signature.to_bytes().to_vec(),
        }
    }
}

impl ReceiptV2 {
    /// Convert to the codec's stored receipt type.
    ///
    /// Consumed by the D2b receipt-processing path; exercised by unit
    /// tests until then.
    #[allow(dead_code)]
    pub(crate) fn to_stored(&self) -> Result<HighWaterReceipt> {
        Ok(HighWaterReceipt {
            conversation_id: self.conversation_id,
            epoch_id: self.epoch_id,
            acknowledged_sender_curve: self.acknowledged_sender_curve,
            issuer_curve: self.issuer_curve,
            high_water: self.high_water,
            signature: Ed25519Signature::from_slice(&self.signature)
                .map_err(|_| LabError::InvalidPayload)?,
        })
    }
}

/// One strict payload. Both arms are always serialized (`null` when
/// absent); arm consistency is mandatory: `Application` carries
/// `body: Some` and `receipt: None`, `Receipt` the reverse.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ClientPayloadV2 {
    pub(crate) version: u8,
    pub(crate) conversation_id: ConversationId,
    pub(crate) message_id: MessageId,
    pub(crate) epoch_id: [u8; 32],
    pub(crate) send_seq: u64,
    pub(crate) sent_at: u64,
    pub(crate) kind: u8,
    pub(crate) body: Option<String>,
    pub(crate) receipt: Option<ReceiptV2>,
}

/// An application payload; the body is bounded at 65,536 UTF-8 bytes.
/// Escape inflation (D2a carry-over): a legal body can exceed the payload
/// bound after JSON escaping, so the encoded size is computed here and
/// now, and any overflow rejects with [`LabError::InvalidPayload`] before
/// any sequence assignment. The decode path enforces the same bound.
pub(crate) fn application(
    conversation_id: ConversationId,
    message_id: MessageId,
    epoch_id: [u8; 32],
    send_seq: u64,
    sent_at: u64,
    body: String,
) -> Result<ClientPayloadV2> {
    if body.len() > MAX_BODY {
        return Err(LabError::InvalidPayload);
    }
    let payload = ClientPayloadV2 {
        version: PAYLOAD_VERSION,
        conversation_id,
        message_id,
        epoch_id,
        send_seq,
        sent_at,
        kind: KIND_APPLICATION,
        body: Some(body),
        receipt: None,
    };
    let size =
        Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| LabError::InvalidPayload)?).len();
    if size > MAX_PAYLOAD_BYTES {
        return Err(LabError::InvalidPayload);
    }
    Ok(payload)
}

/// Arm, version and size validation, shared by encode and decode.
fn validate_shape(payload: &ClientPayloadV2) -> Result<()> {
    if payload.version != PAYLOAD_VERSION {
        return Err(LabError::InvalidPayload);
    }
    match payload.kind {
        KIND_APPLICATION => match &payload.body {
            Some(body) if body.len() <= MAX_BODY && payload.receipt.is_none() => Ok(()),
            _ => Err(LabError::InvalidPayload),
        },
        KIND_RECEIPT => {
            if let Some(receipt) = &payload.receipt {
                if payload.body.is_none() && receipt.signature.len() == 64 {
                    return Ok(());
                }
            }
            Err(LabError::InvalidPayload)
        }
        _ => Err(LabError::InvalidPayload),
    }
}

/// Serialize a payload to its canonical compact JSON form. The result is
/// plaintext message content and stays zeroized.
pub(crate) fn encode(payload: &ClientPayloadV2) -> Result<Zeroizing<Vec<u8>>> {
    validate_shape(payload)?;
    let bytes = Zeroizing::new(serde_json::to_vec(payload).map_err(|_| LabError::Encoding)?);
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(LabError::Encoding);
    }
    Ok(bytes)
}

/// Strict decode: bound, canonical-JSON rule, arm consistency.
///
/// Consumed by the D2b inbound path; exercised by unit tests until then.
#[allow(dead_code)]
pub(crate) fn decode(bytes: &[u8]) -> Result<ClientPayloadV2> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(LabError::InvalidPayload);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let payload =
        ClientPayloadV2::deserialize(&mut deserializer).map_err(|_| LabError::InvalidPayload)?;
    deserializer.end().map_err(|_| LabError::InvalidPayload)?;
    let reserialized =
        Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| LabError::InvalidPayload)?);
    if reserialized[..] != *bytes {
        return Err(LabError::InvalidPayload);
    }
    validate_shape(&payload)?;
    Ok(payload)
}

/// Decode and bind to the expected conversation, epoch and outer message
/// ID (the façade-layer mismatch checks, mirroring v1's
/// `validate_plaintext`).
///
/// Consumed by the D2b inbound path; exercised by unit tests until then.
#[allow(dead_code)]
pub(crate) fn decode_for(
    bytes: &[u8],
    conversation_id: ConversationId,
    epoch_id: [u8; 32],
    outer_message_id: MessageId,
) -> Result<ClientPayloadV2> {
    let payload = decode(bytes)?;
    if payload.conversation_id != conversation_id {
        return Err(LabError::WrongConversation);
    }
    if payload.epoch_id != epoch_id {
        return Err(LabError::InvalidPayload);
    }
    if payload.message_id != outer_message_id {
        return Err(LabError::MessageIdMismatch);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    fn sample() -> std::result::Result<ClientPayloadV2, Box<dyn Error>> {
        Ok(application(
            ConversationId::random(),
            MessageId::random(),
            [0x07; 32],
            1,
            1_800_000_000,
            "payload body".to_owned(),
        )?)
    }

    fn sample_receipt() -> ReceiptV2 {
        ReceiptV2 {
            conversation_id: ConversationId::random(),
            epoch_id: [0x07; 32],
            acknowledged_sender_curve: Curve25519PublicKey::from([0x11; 32]),
            issuer_curve: Curve25519PublicKey::from([0x22; 32]),
            high_water: 7,
            signature: vec![0x33; 64],
        }
    }

    #[test]
    fn application_round_trips_byte_identically() -> std::result::Result<(), Box<dyn Error>> {
        let payload = sample()?;
        let encoded = encode(&payload)?;
        let decoded = decode(&encoded)?;
        assert_eq!(encode(&decoded)?[..], encoded[..]);
        Ok(())
    }

    #[test]
    fn receipt_round_trips_byte_identically() -> std::result::Result<(), Box<dyn Error>> {
        let mut payload = sample()?;
        payload.kind = KIND_RECEIPT;
        payload.body = None;
        payload.receipt = Some(sample_receipt());
        let encoded = encode(&payload)?;
        let decoded = decode(&encoded)?;
        assert_eq!(encode(&decoded)?[..], encoded[..]);
        Ok(())
    }

    #[test]
    fn bad_version_rejected() -> std::result::Result<(), Box<dyn Error>> {
        for version in [1_u8, 3] {
            let mut payload = sample()?;
            payload.version = version;
            assert!(encode(&payload).is_err(), "version {version} encoded");
            let mut encoded = encode(&sample()?)?.to_vec();
            let position = encoded
                .windows(b"\"version\":2".len())
                .position(|window| window == b"\"version\":2")
                .ok_or("version field not found")?;
            encoded[position + 10] = if version == 1 { b'1' } else { b'3' };
            assert!(decode(&encoded).is_err(), "version {version} decoded");
        }
        Ok(())
    }

    #[test]
    fn invalid_kind_rejected() -> std::result::Result<(), Box<dyn Error>> {
        for kind in [0_u8, 3, 4] {
            let mut payload = sample()?;
            payload.kind = kind;
            assert!(encode(&payload).is_err(), "kind {kind} encoded");
        }
        Ok(())
    }

    #[test]
    fn arm_consistency_enforced() -> std::result::Result<(), Box<dyn Error>> {
        // Application with a receipt.
        let mut payload = sample()?;
        payload.receipt = Some(sample_receipt());
        assert!(encode(&payload).is_err(), "application with receipt");
        // Application without a body.
        let mut payload = sample()?;
        payload.body = None;
        assert!(encode(&payload).is_err(), "application without body");
        // Receipt with a body.
        let mut payload = sample()?;
        payload.kind = KIND_RECEIPT;
        payload.receipt = Some(sample_receipt());
        assert!(encode(&payload).is_err(), "receipt with body");
        // Receipt without a receipt.
        let mut payload = sample()?;
        payload.kind = KIND_RECEIPT;
        payload.body = None;
        assert!(encode(&payload).is_err(), "receipt arm empty");
        Ok(())
    }

    #[test]
    fn body_bound_enforced() -> std::result::Result<(), Box<dyn Error>> {
        let maximum = application(
            ConversationId::random(),
            MessageId::random(),
            [0x07; 32],
            1,
            1,
            "x".repeat(MAX_BODY),
        )?;
        let encoded = encode(&maximum)?;
        decode(&encoded)?;
        let oversized = application(
            ConversationId::random(),
            MessageId::random(),
            [0x07; 32],
            1,
            1,
            "x".repeat(MAX_BODY + 1),
        );
        assert!(oversized.is_err());
        let mut crafted = sample()?;
        crafted.body = Some("x".repeat(MAX_BODY + 1));
        assert!(encode(&crafted).is_err());
        Ok(())
    }

    #[test]
    fn canonical_rule_enforced() -> std::result::Result<(), Box<dyn Error>> {
        let encoded = encode(&sample()?)?;
        // Pretty-printed (whitespace variant) deserializes but is not
        // canonical.
        let pretty = serde_json::to_string_pretty(&sample()?)?;
        assert!(serde_json::from_slice::<ClientPayloadV2>(pretty.as_bytes()).is_ok());
        assert!(decode(pretty.as_bytes()).is_err());
        // Trailing data.
        let mut trailing = encoded.to_vec();
        trailing.extend_from_slice(b" ");
        assert!(decode(&trailing).is_err());
        let mut trailing = encoded.to_vec();
        trailing.extend_from_slice(b"0");
        assert!(decode(&trailing).is_err());
        // Missing field.
        let json = String::from_utf8(encoded.to_vec())?;
        let needle = ",\"sent_at\":";
        let position = json.find(needle).ok_or("sent_at missing")?;
        let end = json[position + 1..].find(',').ok_or("sent_at end")? + position + 1;
        let removed = format!("{}{}", &json[..position], &json[end..]);
        assert!(decode(removed.as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn binding_mismatches_rejected() -> std::result::Result<(), Box<dyn Error>> {
        let payload = sample()?;
        let encoded = encode(&payload)?;
        // Everything agrees: accepted.
        decode_for(
            &encoded,
            payload.conversation_id,
            payload.epoch_id,
            payload.message_id,
        )?;
        assert!(matches!(
            decode_for(
                &encoded,
                ConversationId::random(),
                payload.epoch_id,
                payload.message_id,
            ),
            Err(LabError::WrongConversation)
        ));
        assert!(matches!(
            decode_for(
                &encoded,
                payload.conversation_id,
                [0xFF; 32],
                payload.message_id,
            ),
            Err(LabError::InvalidPayload)
        ));
        assert!(matches!(
            decode_for(
                &encoded,
                payload.conversation_id,
                payload.epoch_id,
                MessageId::random(),
            ),
            Err(LabError::MessageIdMismatch)
        ));
        Ok(())
    }

    #[test]
    fn receipt_v2_conversion_round_trip() -> std::result::Result<(), Box<dyn Error>> {
        let receipt = sample_receipt();
        let stored = receipt.to_stored()?;
        let back = ReceiptV2::from(&stored);
        assert_eq!(back, receipt);
        Ok(())
    }

    #[test]
    fn escape_inflated_body_rejected_as_invalid_payload() -> std::result::Result<(), Box<dyn Error>>
    {
        // A body of 40,000 quotes is within the 65,536-byte body bound but
        // doubles under JSON escaping, exceeding the payload bound.
        let heavy = "\"".repeat(40_000);
        let result = application(
            ConversationId::random(),
            MessageId::random(),
            [0x07; 32],
            1,
            1,
            heavy,
        );
        assert!(matches!(result, Err(LabError::InvalidPayload)));
        // A same-length body without escapes stays under the bound.
        let light = "x".repeat(40_000);
        let ok = application(
            ConversationId::random(),
            MessageId::random(),
            [0x07; 32],
            1,
            1,
            light,
        )?;
        assert!(decode(&encode(&ok)?).is_ok());
        Ok(())
    }
}
