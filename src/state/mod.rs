//! `ClientStateV1` bespoke canonical TLV codec and validation, implementing
//! the frozen design in docs/phase2-design-decisions.md section 3 (with the
//! section 4 high-water invariants it references).
//!
//! This module is crate-private and has no consumers yet; the
//! persistence-owning façade of section 2 is a later slice. The codec
//! contract: successful decoding re-encodes byte-identically; every bound
//! is enforced before allocation; optional fields stay present with zero
//! length meaning absent; arrays are strictly increasing by raw
//! `MessageId`; dependency pickles and keypairs are bounded canonical JSON
//! under the exact pins; and full semantic validation runs after decoding,
//! before any caller can see the state.
//!
//! Error coarseness: every codec and validation failure is
//! [`LabError::Storage`]. The brief permitted adding a `LabError::StateCodec`
//! variant, but that would require editing `src/error.rs`, which this slice
//! is forbidden to touch; `Storage` is the existing persistence-family
//! variant and matches the crate's coarse-error policy.

// The public(crate) API below is the contract the Phase-2 façade will
// consume; until that slice lands it is exercised only by unit tests.
#![allow(dead_code)]

mod records;
mod tlv;
mod validate;

#[cfg(test)]
mod tests;

use records::{
    AckIntent, ActiveSession, DedupRecord, InboundRecord, PeerBinding, PendingPreKey,
    RegistrationRecord, SendRecord,
};
use tlv::{ObjectReader, Reader};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey};
use zeroize::Zeroizing;

use crate::ids::{ConversationId, QueueId};
use crate::{LabError, PROTOCOL_DOMAIN, Result};

// Re-exported for the future façade and the unit tests; the lib target has
// no consumer until the façade slice lands.
#[allow(unused_imports)]
pub(crate) use records::{
    AckState, DedupState, HighWaterReceipt, PeerBundle, Role, SendState, SessionMode,
};

/// Top-level framing magic.
pub(crate) const MAGIC: &[u8; 8] = b"SMSLCSV1";
/// Top-level object type; `ClientStateV1` appears at the top level only.
pub(crate) const CLIENT_STATE_TYPE: u16 = 0x0001;
/// State schema version (field 1).
pub(crate) const SCHEMA_VERSION: u16 = 1;
/// Exact pinned vodozemac version string (field 6). Must match the
/// `=0.10.0` pin in Cargo.toml.
pub(crate) const VODOZEMAC_VERSION: &[u8] = b"0.10.0";
/// Olm session config version (field 7); only version 1 exists.
pub(crate) const SESSION_CONFIG_VERSION: u8 = 1;

// Bounds from the section 3 table. Each is enforced before allocation
// wherever the length is attacker-controlled.
pub(crate) const MAX_TOTAL_PLAINTEXT: usize = 8_388_592;
pub(crate) const MAX_ACCOUNT_PICKLE: usize = 3 * 1024 * 1024;
pub(crate) const MAX_SESSION_PICKLE: usize = 512 * 1024;
pub(crate) const MAX_KEYPAIR_JSON: usize = 512;
pub(crate) const MAX_BODY: usize = 65_536;
pub(crate) const MAX_PACKET: usize = 98_304;
pub(crate) const MAX_INBOUND: usize = 32;
pub(crate) const MAX_SENDS: usize = 32;
pub(crate) const MAX_ACKS: usize = 32;
pub(crate) const MAX_DEDUP: usize = 4_096;
/// Section 3 requires the out-of-order received set to be bounded without
/// naming a number; 64 is this slice's choice (documented in the report).
pub(crate) const MAX_RECEIVED_SET: usize = 64;

const FIELD_COUNT: usize = 19;

/// The decoded, semantically validated client state. Construction outside
/// this module is only possible field-by-field (all fields are
/// `pub(crate)` for the future façade and for tests); `encode` re-runs the
/// full validation, so no invalid state can be serialized through it.
pub(crate) struct ClientStateV1 {
    pub(crate) profile_id: [u8; 16],
    pub(crate) key_ref: [u8; 16],
    pub(crate) generation: u64,
    pub(crate) conversation_id: ConversationId,
    /// Bounded canonical JSON `AccountPickle`; secret-bearing.
    pub(crate) account_pickle: Zeroizing<Vec<u8>>,
    pub(crate) own_ed25519_identity: Ed25519PublicKey,
    pub(crate) own_curve_identity: Curve25519PublicKey,
    pub(crate) mailbox_queue_id: QueueId,
    /// Bounded canonical JSON `Ed25519Keypair`s; secret-bearing.
    pub(crate) send_keypair_json: Zeroizing<Vec<u8>>,
    pub(crate) receive_keypair_json: Zeroizing<Vec<u8>>,
    pub(crate) manage_keypair_json: Zeroizing<Vec<u8>>,
    pub(crate) registration: RegistrationRecord,
    pub(crate) pending_prekey: Option<PendingPreKey>,
    pub(crate) peer_binding: Option<PeerBinding>,
    pub(crate) active_session: Option<ActiveSession>,
    /// Sorted strictly increasing by raw `MessageId`.
    pub(crate) inbound: Vec<InboundRecord>,
    pub(crate) sends: Vec<SendRecord>,
    pub(crate) acks: Vec<AckIntent>,
    pub(crate) dedup: Vec<DedupRecord>,
}

impl ClientStateV1 {
    /// Parse, bound-check and semantically validate a framed
    /// `ClientStateV1`. Any deviation from the canonical grammar, the
    /// constants, the bounds, or the section 3/4 semantic invariants is
    /// rejected with the coarse [`LabError::Storage`].
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] for every structural, canonical-JSON,
    /// cryptographic or semantic validation failure.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TOTAL_PLAINTEXT {
            return Err(LabError::Storage);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(LabError::Storage);
        }
        let mut object = ObjectReader::expect(reader, CLIENT_STATE_TYPE)?;

        // 1: state schema version, exact constant.
        if object.field(1)? != SCHEMA_VERSION.to_be_bytes() {
            return Err(LabError::Storage);
        }
        let profile_id = tlv::fixed::<16>(object.field(2)?)?;
        let key_ref = tlv::fixed::<16>(object.field(3)?)?;
        let generation = u64::from_be_bytes(tlv::fixed::<8>(object.field(4)?)?);
        // 5: exact protocol domain bytes.
        if object.field(5)? != PROTOCOL_DOMAIN {
            return Err(LabError::Storage);
        }
        // 6: exact pinned vodozemac version string.
        if object.field(6)? != VODOZEMAC_VERSION {
            return Err(LabError::Storage);
        }
        // 7: Olm session config, exact constant version 1.
        if object.field(7)? != [SESSION_CONFIG_VERSION] {
            return Err(LabError::Storage);
        }
        let conversation_id =
            ConversationId::from_slice(object.field(8)?).ok_or(LabError::Storage)?;

        // 9: Account pickle, bounded canonical JSON.
        let account_pickle = object.field_bounded(9, MAX_ACCOUNT_PICKLE)?;
        tlv::canonical_json::<vodozemac::olm::AccountPickle>(
            account_pickle,
            MAX_ACCOUNT_PICKLE,
        )?;

        // 10: own public identity, Ed25519 signing || Curve25519.
        let identity = tlv::fixed::<64>(object.field(10)?)?;
        let own_ed25519_identity = Ed25519PublicKey::from_slice(&tlv::fixed::<32>(&identity[..32])?)
            .map_err(|_| LabError::Storage)?;
        let own_curve_identity = Curve25519PublicKey::from_slice(&tlv::fixed::<32>(&identity[32..])?)
            .map_err(|_| LabError::Storage)?;

        // 11: own mailbox and three private keypairs (send, receive,
        // manage), each bounded canonical JSON.
        let (mailbox_queue_id, send_keypair_json, receive_keypair_json, manage_keypair_json) =
            parse_mailbox(object.field(11)?)?;

        // 12: registration intent / current request.
        let registration = RegistrationRecord::parse(object.field(12)?)?;

        // 13-15: optional records, zero length meaning absent.
        let pending_prekey = parse_optional(object.field(13)?, PendingPreKey::parse)?;
        let peer_binding = parse_optional(object.field(14)?, PeerBinding::parse)?;
        let active_session = parse_optional(object.field(15)?, ActiveSession::parse)?;

        // 16-19: sorted arrays.
        let inbound = records::parse_record_array(
            object.field(16)?,
            MAX_INBOUND,
            InboundRecord::parse,
            |record| record.message_id,
        )?;
        let sends = records::parse_record_array(
            object.field(17)?,
            MAX_SENDS,
            SendRecord::parse,
            |record| record.message_id,
        )?;
        let acks = records::parse_record_array(
            object.field(18)?,
            MAX_ACKS,
            AckIntent::parse,
            |record| record.message_id,
        )?;
        let dedup = records::parse_record_array(
            object.field(19)?,
            MAX_DEDUP,
            DedupRecord::parse,
            |record| record.message_id,
        )?;
        object.finish()?;

        let state = Self {
            profile_id,
            key_ref,
            generation,
            conversation_id,
            account_pickle: Zeroizing::new(account_pickle.to_vec()),
            own_ed25519_identity,
            own_curve_identity,
            mailbox_queue_id,
            send_keypair_json,
            receive_keypair_json,
            manage_keypair_json,
            registration,
            pending_prekey,
            peer_binding,
            active_session,
            inbound,
            sends,
            acks,
            dedup,
        };
        validate::validate(&state)?;
        Ok(state)
    }

    /// Serialize the state to the canonical framed form. Runs the complete
    /// semantic validation first, so an invalid in-memory state cannot be
    /// committed. `decode(encode(state)?)?` re-encodes byte-identically.
    ///
    /// The returned buffer is **secret-bearing plaintext**: it contains the
    /// `Account` pickle, the `Session` pickle and all three private mailbox
    /// keypairs. It must stay wrapped in [`Zeroizing`], be wrapped by the
    /// platform key before touching storage, and never be logged.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] when validation fails or any bound
    /// (including the aggregate plaintext bound) is exceeded.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        validate::validate(self)?;

        let mut fields: Vec<(u16, Vec<u8>)> = Vec::with_capacity(FIELD_COUNT);
        fields.push((1, SCHEMA_VERSION.to_be_bytes().to_vec()));
        fields.push((2, self.profile_id.to_vec()));
        fields.push((3, self.key_ref.to_vec()));
        fields.push((4, self.generation.to_be_bytes().to_vec()));
        fields.push((5, PROTOCOL_DOMAIN.to_vec()));
        fields.push((6, VODOZEMAC_VERSION.to_vec()));
        fields.push((7, vec![SESSION_CONFIG_VERSION]));
        fields.push((8, self.conversation_id.as_bytes().to_vec()));
        fields.push((9, self.account_pickle.to_vec()));

        let mut identity = Vec::with_capacity(64);
        identity.extend_from_slice(self.own_ed25519_identity.as_bytes());
        identity.extend_from_slice(self.own_curve_identity.as_bytes());
        fields.push((10, identity));
        fields.push((11, self.encode_mailbox()?));
        fields.push((12, self.registration.encode()?));
        fields.push((13, encode_optional(self.pending_prekey.as_ref())?));
        fields.push((14, encode_optional(self.peer_binding.as_ref())?));
        fields.push((15, encode_optional(self.active_session.as_ref())?));
        fields.push((
            16,
            records::encode_record_array(&self.inbound, MAX_INBOUND, InboundRecord::encode)?,
        ));
        fields.push((
            17,
            records::encode_record_array(&self.sends, MAX_SENDS, SendRecord::encode)?,
        ));
        fields.push((18, records::encode_record_array(&self.acks, MAX_ACKS, AckIntent::encode)?));
        fields.push((
            19,
            records::encode_record_array(&self.dedup, MAX_DEDUP, DedupRecord::encode)?,
        ));

        let object = tlv::write_object(CLIENT_STATE_TYPE, &fields)?;
        let total = MAGIC.len() + object.len();
        if total > MAX_TOTAL_PLAINTEXT {
            return Err(LabError::Storage);
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&object);
        Ok(Zeroizing::new(out))
    }

    /// Field 11: queue ID followed by three length-delimited keypair JSON
    /// documents (send, receive, manage), each bounded at 512 bytes.
    fn encode_mailbox(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(self.mailbox_queue_id.as_bytes());
        for json in [
            &self.send_keypair_json,
            &self.receive_keypair_json,
            &self.manage_keypair_json,
        ] {
            let length = u32::try_from(json.len()).map_err(|_| LabError::Storage)?;
            tlv::write_u32(&mut out, length);
            out.extend_from_slice(json);
        }
        Ok(out)
    }
}

type MailboxMaterial = (QueueId, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

fn parse_mailbox(bytes: &[u8]) -> Result<MailboxMaterial> {
    let mut reader = Reader::new(bytes);
    let queue_id = QueueId::from_slice(reader.take(32)?).ok_or(LabError::Storage)?;
    let read_keypair = |reader: &mut Reader<'_>| -> Result<Zeroizing<Vec<u8>>> {
        let length = tlv::length_prefix(reader.u32()?)?;
        let json = reader.take_bounded(length, MAX_KEYPAIR_JSON)?;
        tlv::canonical_json::<vodozemac::Ed25519Keypair>(json, MAX_KEYPAIR_JSON)?;
        Ok(Zeroizing::new(json.to_vec()))
    };
    let send = read_keypair(&mut reader)?;
    let receive = read_keypair(&mut reader)?;
    let manage = read_keypair(&mut reader)?;
    if !reader.is_done() {
        return Err(LabError::Storage);
    }
    Ok((queue_id, send, receive, manage))
}

fn parse_optional<T>(bytes: &[u8], parse: impl Fn(&[u8]) -> Result<T>) -> Result<Option<T>> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        parse(bytes).map(Some)
    }
}

fn encode_optional<T>(record: Option<&T>) -> Result<Vec<u8>>
where
    T: Encodable,
{
    match record {
        None => Ok(Vec::new()),
        Some(record) => record.encode_record(),
    }
}

/// Local trait so `encode_optional` can stay generic over the record
/// types without exposing their `encode` methods under one name.
trait Encodable {
    fn encode_record(&self) -> Result<Vec<u8>>;
}

impl Encodable for PendingPreKey {
    fn encode_record(&self) -> Result<Vec<u8>> {
        self.encode()
    }
}

impl Encodable for PeerBinding {
    fn encode_record(&self) -> Result<Vec<u8>> {
        self.encode()
    }
}

impl Encodable for ActiveSession {
    fn encode_record(&self) -> Result<Vec<u8>> {
        self.encode()
    }
}
