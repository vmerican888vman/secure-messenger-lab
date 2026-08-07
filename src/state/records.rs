//! Nested record layouts for the `ClientStateV1` codec (design section 3).
//!
//! Field IDs within each object are `1..=N` strictly ascending, one field
//! per item, in the order listed below. Fixed-width integers are
//! big-endian; enums are `u8` starting at 1 (0 invalid); keys, IDs, digests
//! and signatures are fixed-length raw bytes. Optional fields stay present
//! with zero length meaning absent. Variable fields carry the bounds from
//! the section 3 table, enforced before any allocation.
//!
//! Deviation from the task brief, forced by existing types: `QueueId` in
//! this crate is 32 bytes (`src/ids.rs`), not the 16 assumed by the brief's
//! per-record sketches. Every `queue_id` field below is therefore `[32]`.
//! `MessageId`, `ConversationId` and `Nonce` are `[16]` as assumed.

use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};
use zeroize::Zeroizing;

use super::tlv::{self, ObjectReader, Reader};
use super::{
    MAX_APPLICATION_OUTSTANDING, MAX_BODY, MAX_KEYPAIR_JSON, MAX_PACKET, MAX_RECEIVED_SET,
    MAX_SESSION_PICKLE,
};
use crate::ids::{ConversationId, MessageId, Nonce, QueueId};
use crate::{EncryptedPacket, LabError, Result};

pub(crate) const REGISTRATION_TYPE: u16 = 0x0002;
pub(crate) const PENDING_PREKEY_TYPE: u16 = 0x0003;
pub(crate) const PEER_BINDING_TYPE: u16 = 0x0004;
pub(crate) const ACTIVE_SESSION_TYPE: u16 = 0x0005;
pub(crate) const INBOUND_TYPE: u16 = 0x0006;
pub(crate) const SEND_TYPE: u16 = 0x0007;
pub(crate) const ACK_TYPE: u16 = 0x0008;
pub(crate) const DEDUP_TYPE: u16 = 0x0009;

fn ed25519_key(bytes: &[u8]) -> Result<Ed25519PublicKey> {
    Ed25519PublicKey::from_slice(&tlv::fixed::<32>(bytes)?).map_err(|_| LabError::Storage)
}

fn curve_key(bytes: &[u8]) -> Result<Curve25519PublicKey> {
    Curve25519PublicKey::from_slice(&tlv::fixed::<32>(bytes)?).map_err(|_| LabError::Storage)
}

fn signature(bytes: &[u8]) -> Result<Ed25519Signature> {
    Ed25519Signature::from_slice(&tlv::fixed::<64>(bytes)?).map_err(|_| LabError::Storage)
}

fn queue_id(bytes: &[u8]) -> Result<QueueId> {
    QueueId::from_slice(bytes).ok_or(LabError::Storage)
}

fn message_id(bytes: &[u8]) -> Result<MessageId> {
    MessageId::from_slice(bytes).ok_or(LabError::Storage)
}

fn conversation_id(bytes: &[u8]) -> Result<ConversationId> {
    ConversationId::from_slice(bytes).ok_or(LabError::Storage)
}

fn nonce(bytes: &[u8]) -> Result<Nonce> {
    Nonce::from_slice(bytes).ok_or(LabError::Storage)
}

fn epoch_id(bytes: &[u8]) -> Result<[u8; 32]> {
    tlv::fixed::<32>(bytes)
}

fn u64_value(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(tlv::fixed::<8>(bytes)?))
}

fn u8_value(bytes: &[u8]) -> Result<u8> {
    Ok(tlv::fixed::<1>(bytes)?[0])
}

/// Optional fixed-length field: zero length means absent, exact length
/// means present, anything else is malformed.
fn optional<T>(bytes: &[u8], parse: impl Fn(&[u8]) -> Result<T>) -> Result<Option<T>> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        parse(bytes).map(Some)
    }
}

/// Registration intent / current request (object type `0x0002`): the
/// immutable queue and public-key intent plus the exact current nonce,
/// expiry and management signature. Mirrors [`crate::MailboxRegistration`].
pub(crate) struct RegistrationRecord {
    pub(crate) queue_id: QueueId,
    pub(crate) send_key: Ed25519PublicKey,
    pub(crate) receive_key: Ed25519PublicKey,
    pub(crate) manage_key: Ed25519PublicKey,
    pub(crate) nonce: Nonce,
    pub(crate) valid_until: u64,
    pub(crate) signature: Ed25519Signature,
}

impl RegistrationRecord {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut object = ObjectReader::expect(Reader::new(bytes), REGISTRATION_TYPE)?;
        let record = Self {
            queue_id: queue_id(object.field(1)?)?,
            send_key: ed25519_key(object.field(2)?)?,
            receive_key: ed25519_key(object.field(3)?)?,
            manage_key: ed25519_key(object.field(4)?)?,
            nonce: nonce(object.field(5)?)?,
            valid_until: u64_value(object.field(6)?)?,
            signature: signature(object.field(7)?)?,
        };
        object.finish()?;
        Ok(record)
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let valid_until = self.valid_until.to_be_bytes();
        let signature = self.signature.to_bytes();
        let object = tlv::write_object(
            REGISTRATION_TYPE,
            &[
                (1, self.queue_id.as_bytes() as &[u8]),
                (2, self.send_key.as_bytes()),
                (3, self.receive_key.as_bytes()),
                (4, self.manage_key.as_bytes()),
                (5, self.nonce.as_bytes()),
                (6, &valid_until),
                (7, &signature),
            ],
        )?;
        Ok(Zeroizing::new(object))
    }
}

/// The verified peer bundle shared by `PendingPreKey`, `PeerBinding` and
/// the `ActiveSession` establishment transcript. The signature covers the
/// same canonical length-prefixed bytes as `peer_prekey_signing_bytes` in
/// `src/client.rs`; the construction is replicated in `super::validate`
/// through `capability::canonical`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerBundle {
    pub(crate) signing_identity: Ed25519PublicKey,
    pub(crate) curve_identity: Curve25519PublicKey,
    pub(crate) one_time_key: Curve25519PublicKey,
    pub(crate) valid_until: u64,
    pub(crate) signature: Ed25519Signature,
}

impl PeerBundle {
    fn parse_fields(object: &mut ObjectReader<'_>, first_id: u16) -> Result<Self> {
        Ok(Self {
            signing_identity: ed25519_key(object.field(first_id)?)?,
            curve_identity: curve_key(object.field(first_id + 1)?)?,
            one_time_key: curve_key(object.field(first_id + 2)?)?,
            valid_until: u64_value(object.field(first_id + 3)?)?,
            signature: signature(object.field(first_id + 4)?)?,
        })
    }

    /// The five bundle field values borrowed for assembly; the caller owns
    /// the integer temporaries.
    fn fields<'a>(
        &'a self,
        first_id: u16,
        valid_until: &'a [u8; 8],
        signature: &'a [u8; 64],
    ) -> [(u16, &'a [u8]); 5] {
        [
            (first_id, self.signing_identity.as_bytes()),
            (first_id + 1, self.curve_identity.as_bytes()),
            (first_id + 2, self.one_time_key.as_bytes()),
            (first_id + 3, valid_until),
            (first_id + 4, signature),
        ]
    }
}

/// Optional pending prekey (object type `0x0003`): our own signing
/// identity, curve identity, one-time key, creation and expiry, and
/// signature.
pub(crate) struct PendingPreKey {
    pub(crate) signing_identity: Ed25519PublicKey,
    pub(crate) curve_identity: Curve25519PublicKey,
    pub(crate) one_time_key: Curve25519PublicKey,
    pub(crate) created_at: u64,
    pub(crate) valid_until: u64,
    pub(crate) signature: Ed25519Signature,
}

impl PendingPreKey {
    pub(crate) fn bundle(&self) -> PeerBundle {
        PeerBundle {
            signing_identity: self.signing_identity,
            curve_identity: self.curve_identity,
            one_time_key: self.one_time_key,
            valid_until: self.valid_until,
            signature: self.signature,
        }
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut object = ObjectReader::expect(Reader::new(bytes), PENDING_PREKEY_TYPE)?;
        let record = Self {
            signing_identity: ed25519_key(object.field(1)?)?,
            curve_identity: curve_key(object.field(2)?)?,
            one_time_key: curve_key(object.field(3)?)?,
            created_at: u64_value(object.field(4)?)?,
            valid_until: u64_value(object.field(5)?)?,
            signature: signature(object.field(6)?)?,
        };
        object.finish()?;
        Ok(record)
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let created_at = self.created_at.to_be_bytes();
        let valid_until = self.valid_until.to_be_bytes();
        let signature = self.signature.to_bytes();
        let object = tlv::write_object(
            PENDING_PREKEY_TYPE,
            &[
                (1, self.signing_identity.as_bytes() as &[u8]),
                (2, self.curve_identity.as_bytes()),
                (3, self.one_time_key.as_bytes()),
                (4, &created_at),
                (5, &valid_until),
                (6, &signature),
            ],
        )?;
        Ok(Zeroizing::new(object))
    }
}

/// Optional peer binding / send capability (object type `0x0004`): the
/// verified peer bundle, then the send capability for the peer's mailbox.
pub(crate) struct PeerBinding {
    pub(crate) bundle: PeerBundle,
    pub(crate) queue_id: QueueId,
    /// Bounded canonical JSON (`Ed25519Keypair`), secret-bearing.
    pub(crate) send_keypair_json: Zeroizing<Vec<u8>>,
    pub(crate) send_public_key: Ed25519PublicKey,
}

impl PeerBinding {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut object = ObjectReader::expect(Reader::new(bytes), PEER_BINDING_TYPE)?;
        let bundle = PeerBundle::parse_fields(&mut object, 1)?;
        let queue_id = queue_id(object.field(6)?)?;
        let keypair_json = object.field_bounded(7, MAX_KEYPAIR_JSON)?;
        tlv::canonical_json::<vodozemac::Ed25519Keypair>(keypair_json, MAX_KEYPAIR_JSON)?;
        let send_public_key = ed25519_key(object.field(8)?)?;
        object.finish()?;
        Ok(Self {
            bundle,
            queue_id,
            send_keypair_json: Zeroizing::new(keypair_json.to_vec()),
            send_public_key,
        })
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let valid_until = self.bundle.valid_until.to_be_bytes();
        let bundle_signature = self.bundle.signature.to_bytes();
        let bundle_fields = self.bundle.fields(1, &valid_until, &bundle_signature);
        let object = tlv::write_object(
            PEER_BINDING_TYPE,
            &[
                bundle_fields[0],
                bundle_fields[1],
                bundle_fields[2],
                bundle_fields[3],
                bundle_fields[4],
                (6, self.queue_id.as_bytes() as &[u8]),
                (7, &self.send_keypair_json[..]),
                (8, self.send_public_key.as_bytes()),
            ],
        )?;
        Ok(Zeroizing::new(object))
    }
}

/// Session role: `1` = outbound (we initiated), `2` = inbound.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Role {
    Outbound = 1,
    Inbound = 2,
}

/// Session mode from section 4: `1` = `Ready`, `2` = `ControlOnly`,
/// `4` = `RekeyRequired`.
///
/// **§4 control-lane split:** `ReceiptLocked` (value `3`) is RETIRED. It
/// was the terminal state of the old combined 24-application-plus-8-
/// control counter; once the lanes are separate there is no lawful
/// transition from `ControlOnly` to 32 application sends, because
/// `application_outstanding` is bounded at 24 by construction. Stored
/// value `3` is therefore invalid on load. The discriminant is left as a
/// gap rather than renumbered so no persisted value silently changes
/// meaning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SessionMode {
    Ready = 1,
    ControlOnly = 2,
    RekeyRequired = 4,
}

/// `HighWaterReceiptV1` (section 4). The version is fixed at 1 and stored
/// implicitly; the receipt signing construction is in `super::validate`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct HighWaterReceipt {
    pub(crate) conversation_id: ConversationId,
    pub(crate) epoch_id: [u8; 32],
    pub(crate) acknowledged_sender_curve: Curve25519PublicKey,
    pub(crate) issuer_curve: Curve25519PublicKey,
    pub(crate) high_water: u64,
    pub(crate) signature: Ed25519Signature,
}

pub(crate) const RECEIPT_VERSION: u8 = 1;

impl HighWaterReceipt {
    /// Exact encoded length: version, conversation, epoch, two curves,
    /// high water, signature.
    const ENCODED_LEN: usize = 1 + 16 + 32 + 32 + 32 + 8 + 64;

    fn parse(bytes: &[u8]) -> Result<Option<Self>> {
        let Some(bytes) = optional(bytes, tlv::fixed::<{ Self::ENCODED_LEN }>)? else {
            return Ok(None);
        };
        let mut reader = Reader::new(&bytes);
        if reader.u8()? != RECEIPT_VERSION {
            return Err(LabError::Storage);
        }
        let receipt = Self {
            conversation_id: conversation_id(reader.take(16)?)?,
            epoch_id: epoch_id(reader.take(32)?)?,
            acknowledged_sender_curve: curve_key(reader.take(32)?)?,
            issuer_curve: curve_key(reader.take(32)?)?,
            high_water: reader.u64()?,
            signature: signature(reader.take(64)?)?,
        };
        if !reader.is_done() {
            return Err(LabError::Storage);
        }
        Ok(Some(receipt))
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.push(RECEIPT_VERSION);
        out.extend_from_slice(self.conversation_id.as_bytes());
        out.extend_from_slice(&self.epoch_id);
        out.extend_from_slice(self.acknowledged_sender_curve.as_bytes());
        out.extend_from_slice(self.issuer_curve.as_bytes());
        out.extend_from_slice(&self.high_water.to_be_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }
}

/// Optional active session (object type `0x0005`): role, canonical pickle,
/// all three `SessionKeys`, establishment transcript, epoch ID, sequence
/// and high-water state, mode, receipt, and the out-of-order received set.
///
/// **The transcript is role-aware** (remediation decision after review:
/// the earlier single interpretation was wrong for inbound sessions).
/// vodozemac's `SessionKeys.identity_key` is always the session
/// INITIATOR's long-term curve identity and `SessionKeys.one_time_key` is
/// always the RECIPIENT's advertised one-time key, so the same five
/// transcript sub-fields (fields 6-10: signing identity, curve identity,
/// one-time key, `valid_until`, signature — wire layout unchanged) are
/// interpreted per role:
///
/// - `Role::Outbound` (we initiated): the transcript is the verified
///   **peer** bundle. `session_keys.identity_key` is our own identity;
///   `session_keys.one_time_key` must equal the transcript's advertised
///   key; the transcript signature verifies against the pinned peer
///   signing identity.
/// - `Role::Inbound` (the peer initiated): the transcript is **our own**
///   prekey bundle that the peer consumed to establish the session.
///   `session_keys.identity_key` is the peer initiator's identity (bound
///   via the peer binding, which is mandatory whenever a session is
///   present); `session_keys.one_time_key` must equal the transcript's
///   key, which must no longer exist in the account; the transcript
///   signature verifies against our own signing identity.
///
/// `session_keys.base_key` is not cross-checked for either role: it is the
/// initiator's ephemeral base key, for which no stored reference exists.
///
/// **Wire-layout amendment (review v2 remediation):** field 18,
/// `conversation_id[16]`, was added so the conversation binding is
/// provable for every session, receipt or not. It is appended after the
/// original fields 1-17 to keep their numbering stable; the object now
/// declares 18 fields. Validation requires it to equal top-level field 8
/// for both roles, and a present receipt must still also match it.
///
/// **Wire-layout amendments (reviews D2b v3/v4):** field 19,
/// `last_delivered_receipt_high_water: u64`, marks the highest received
/// high water a DELIVERED receipt has reported (0 = none delivered). v3
/// added it as `last_staged_...`; v4 renamed it in place (same wire
/// position, codec still pre-PASS) because the marker now advances only
/// when a receipt send reaches a delivered terminal state, never at
/// staging. Validation requires the marker never to exceed
/// `highest_contiguous_received_seq` — no receipt can have reported a
/// high water never reached.
///
/// **Wire-layout amendment (review D2b v5):** field 20,
/// `receipt_debt_up_to: u64`, is the highest APPLICATION payload
/// sequence CONSUMED so far (this epoch); it is set only by
/// `consume_inbound` (max of the current value and the consumed record's
/// sender sequence). Receipts and other control payloads are never
/// consumed application records, so receipt-only exchanges never raise
/// it — receipt debt exists only where a user-visible body was consumed.
/// A receipt is owed while both this debt and
/// `highest_contiguous_received_seq` exceed the delivered marker (field
/// 19) and no pending receipt already reports the current water.
/// Validation: 0 (nothing consumed), or a value covered by the
/// contiguous received high water or present in the out-of-order
/// received set — nothing can have been consumed before it was
/// received.
///
/// **Wire-layout amendments (reviews D2b v6/v9):** field 21. v6 added
/// `control_debt_armed: u8`; **v9 retypes it in place** (same wire
/// position, codec still pre-PASS) to **`control_debt_up_to: u64`** —
/// control debt as a monotone high water, not a flag. Arming (local
/// congestion or a peer-signaled congestion payload, thresholds
/// unchanged) sets it to `max(current, current HCR)`; it is NEVER
/// cleared or lowered by anything on the wire, so reordered truthful
/// low signals cannot erase a later arm and no signal-freshness
/// versioning is needed (the water only rises; resolution is a
/// water-versus-water comparison). Debt resolves only through confirmed
/// delivery: when the delivered marker (field 19) reaches it. A delayed
/// `Stored` on an older receipt (`hw < control_debt_up_to`) therefore
/// leaves newer debt standing instead of clearing it (v9 finding 4).
/// Validation (amended v11): the control-debt water must be a sequence
/// actually RECEIVED — at or below `highest_contiguous_received_seq`, or
/// present in `received_above_high_water` (0 = none) — because the
/// peer-signaled arm binds to the signaling packet's sequence, which
/// under reordering legitimately sits above the contiguous water.
///
/// **Wire-layout amendment (§4 control-lane split, authorised by the
/// security architect):** fields 22 and 23. The old combined budget
/// counted BOTH send kinds against one peer high water, so every control
/// receipt spent application capacity and a peer that signalled
/// congestion could consume our ability to send. The lanes are now
/// separate.
///
/// Field 22, `unreceipted_application_send_seqs: Vec<u64>`, is the
/// canonical strictly increasing, duplicate-free set of shared sequence
/// numbers assigned to APPLICATION payloads not yet covered by
/// `peer_contiguous_high_water`; `application_outstanding` is its
/// length, bounded at 24. A scalar sent/acknowledged counter pair cannot
/// replace it: the frozen shared high water does not say how many
/// mixed-kind sends it covered once historical `SendRecord`s have been
/// pruned, so the set is the authoritative ledger. The sequence space
/// itself is NOT split — every Olm encryption, control included, still
/// draws one `send_seq` from the single shared stream, and
/// `HighWaterReceiptV1` still acknowledges the highest contiguous shared
/// sequence.
///
/// Assigning an application send appends its sequence atomically with
/// the ratchet advance and `SendRecord`. Assigning a receipt advances
/// the shared sequence and does NOT touch the set. Accepting a valid
/// advancing receipt removes every entry at or below the new high water,
/// atomically, before any new application capacity is exposed. Send
/// results, expiry, `DeliveryUnknown` consumption and record pruning
/// never remove application budget.
///
/// Field 23, `control_send_not_before: u64`, is the durable one-per-
/// second control cooldown boundary; staging a receipt sets it to
/// `checked(now + 1)`. It is a refillable LOCAL rate bound, never a
/// per-epoch cap and never conditioned on the peer acknowledging an
/// earlier control response — that conditioning is exactly what
/// deadlocked an honest peer in v12.
///
/// The object declares 23 fields.
pub(crate) struct ActiveSession {
    pub(crate) role: Role,
    /// Bounded canonical JSON (`SessionPickle`), secret-bearing.
    pub(crate) session_pickle: Zeroizing<Vec<u8>>,
    pub(crate) identity_key: Curve25519PublicKey,
    pub(crate) base_key: Curve25519PublicKey,
    pub(crate) one_time_key: Curve25519PublicKey,
    pub(crate) transcript: PeerBundle,
    pub(crate) epoch_id: [u8; 32],
    pub(crate) last_assigned_send_seq: u64,
    pub(crate) peer_contiguous_high_water: u64,
    pub(crate) highest_contiguous_received_seq: u64,
    pub(crate) mode: SessionMode,
    pub(crate) receipt: Option<HighWaterReceipt>,
    /// Strictly increasing sender sequences accepted above the contiguous
    /// high water; bounded at 64 (see module docs in `mod.rs`).
    pub(crate) received_above_high_water: Vec<u64>,
    /// Conversation binding; must equal top-level field 8 (field 18).
    pub(crate) conversation_id: ConversationId,
    /// Highest received contiguous high water a DELIVERED receipt has
    /// reported; 0 = none delivered (field 19). Never exceeds
    /// `highest_contiguous_received_seq`.
    pub(crate) last_delivered_receipt_high_water: u64,
    /// Highest consumed application sender sequence; 0 = nothing
    /// consumed (field 20). Never exceeds the received water coverage.
    pub(crate) receipt_debt_up_to: u64,
    /// Control-debt high water (field 21): the highest received water
    /// congestion (local or peer-signaled) has armed to date; 0 = none.
    /// Monotone on the wire; resolved only by confirmed delivery.
    pub(crate) control_debt_up_to: u64,
    /// Shared sequences of application payloads the peer's high water
    /// does not yet cover (field 22). Its length IS
    /// `application_outstanding`; bounded at
    /// `MAX_APPLICATION_OUTSTANDING`.
    pub(crate) unreceipted_application_send_seqs: Vec<u64>,
    /// Durable control-send cooldown boundary (field 23); 0 = no
    /// cooldown outstanding.
    pub(crate) control_send_not_before: u64,
}

impl ActiveSession {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut object = ObjectReader::expect(Reader::new(bytes), ACTIVE_SESSION_TYPE)?;
        let role = match u8_value(object.field(1)?)? {
            1 => Role::Outbound,
            2 => Role::Inbound,
            _ => return Err(LabError::Storage),
        };
        let pickle = object.field_bounded(2, MAX_SESSION_PICKLE)?;
        tlv::canonical_json::<vodozemac::olm::SessionPickle>(pickle, MAX_SESSION_PICKLE)?;
        let identity_key = curve_key(object.field(3)?)?;
        let base_key = curve_key(object.field(4)?)?;
        let one_time_key = curve_key(object.field(5)?)?;
        let transcript = PeerBundle::parse_fields(&mut object, 6)?;
        let epoch_id = epoch_id(object.field(11)?)?;
        let last_assigned_send_seq = u64_value(object.field(12)?)?;
        let peer_contiguous_high_water = u64_value(object.field(13)?)?;
        let highest_contiguous_received_seq = u64_value(object.field(14)?)?;
        let mode = match u8_value(object.field(15)?)? {
            1 => SessionMode::Ready,
            2 => SessionMode::ControlOnly,

            4 => SessionMode::RekeyRequired,
            _ => return Err(LabError::Storage),
        };
        let receipt = HighWaterReceipt::parse(object.field(16)?)?;
        let received = parse_u64_set(object.field(17)?, MAX_RECEIVED_SET)?;
        let conversation_id = conversation_id(object.field(18)?)?;
        let last_delivered_receipt_high_water = u64_value(object.field(19)?)?;
        let receipt_debt_up_to = u64_value(object.field(20)?)?;
        let control_debt_up_to = u64_value(object.field(21)?)?;
        let unreceipted_application_send_seqs =
            parse_u64_set(object.field(22)?, MAX_APPLICATION_OUTSTANDING)?;
        let control_send_not_before = u64_value(object.field(23)?)?;
        object.finish()?;
        Ok(Self {
            role,
            session_pickle: Zeroizing::new(pickle.to_vec()),
            identity_key,
            base_key,
            one_time_key,
            transcript,
            epoch_id,
            last_assigned_send_seq,
            peer_contiguous_high_water,
            highest_contiguous_received_seq,
            mode,
            receipt,
            received_above_high_water: received,
            conversation_id,
            last_delivered_receipt_high_water,
            receipt_debt_up_to,
            control_debt_up_to,
            unreceipted_application_send_seqs,
            control_send_not_before,
        })
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let role = [self.role as u8];
        let transcript_valid_until = self.transcript.valid_until.to_be_bytes();
        let transcript_signature = self.transcript.signature.to_bytes();
        let transcript_fields =
            self.transcript
                .fields(6, &transcript_valid_until, &transcript_signature);
        let last_assigned_send_seq = self.last_assigned_send_seq.to_be_bytes();
        let peer_contiguous_high_water = self.peer_contiguous_high_water.to_be_bytes();
        let highest_contiguous_received_seq = self.highest_contiguous_received_seq.to_be_bytes();
        let mode = [self.mode as u8];
        let receipt_bytes = self
            .receipt
            .as_ref()
            .map_or(Vec::new(), HighWaterReceipt::encode);
        let received_bytes = encode_u64_set(&self.received_above_high_water, MAX_RECEIVED_SET)?;
        let last_delivered_receipt_high_water =
            self.last_delivered_receipt_high_water.to_be_bytes();
        let receipt_debt_up_to = self.receipt_debt_up_to.to_be_bytes();
        let control_debt_up_to = self.control_debt_up_to.to_be_bytes();
        let application_seqs = encode_u64_set(
            &self.unreceipted_application_send_seqs,
            MAX_APPLICATION_OUTSTANDING,
        )?;
        let control_send_not_before = self.control_send_not_before.to_be_bytes();
        let object = tlv::write_object(
            ACTIVE_SESSION_TYPE,
            &[
                (1, &role as &[u8]),
                (2, &self.session_pickle[..]),
                (3, self.identity_key.as_bytes()),
                (4, self.base_key.as_bytes()),
                (5, self.one_time_key.as_bytes()),
                transcript_fields[0],
                transcript_fields[1],
                transcript_fields[2],
                transcript_fields[3],
                transcript_fields[4],
                (11, &self.epoch_id),
                (12, &last_assigned_send_seq),
                (13, &peer_contiguous_high_water),
                (14, &highest_contiguous_received_seq),
                (15, &mode),
                (16, &receipt_bytes),
                (17, &received_bytes),
                (18, self.conversation_id.as_bytes()),
                (19, &last_delivered_receipt_high_water),
                (20, &receipt_debt_up_to),
                (21, &control_debt_up_to),
                (22, &application_seqs),
                (23, &control_send_not_before),
            ],
        )?;
        Ok(Zeroizing::new(object))
    }
}

/// Inbound record (object type `0x0006`): message ID, epoch, sender
/// sequence, queue, packet digest, signed expiry, acceptance time and
/// UTF-8 body.
pub(crate) struct InboundRecord {
    pub(crate) message_id: MessageId,
    pub(crate) epoch_id: [u8; 32],
    pub(crate) sender_sequence: u64,
    pub(crate) queue_id: QueueId,
    pub(crate) packet_digest: [u8; 32],
    pub(crate) expires_at: u64,
    pub(crate) accepted_at: u64,
    pub(crate) body: String,
}

impl InboundRecord {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut object = ObjectReader::expect(Reader::new(bytes), INBOUND_TYPE)?;
        let message_id = message_id(object.field(1)?)?;
        let epoch_id = epoch_id(object.field(2)?)?;
        let sender_sequence = u64_value(object.field(3)?)?;
        let queue_id = queue_id(object.field(4)?)?;
        let packet_digest = tlv::fixed::<32>(object.field(5)?)?;
        let expires_at = u64_value(object.field(6)?)?;
        let accepted_at = u64_value(object.field(7)?)?;
        let body_bytes = object.field_bounded(8, MAX_BODY)?;
        let body = std::str::from_utf8(body_bytes).map_err(|_| LabError::Storage)?;
        object.finish()?;
        Ok(Self {
            message_id,
            epoch_id,
            sender_sequence,
            queue_id,
            packet_digest,
            expires_at,
            accepted_at,
            body: body.to_owned(),
        })
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let sender_sequence = self.sender_sequence.to_be_bytes();
        let expires_at = self.expires_at.to_be_bytes();
        let accepted_at = self.accepted_at.to_be_bytes();
        let object = tlv::write_object(
            INBOUND_TYPE,
            &[
                (1, self.message_id.as_bytes() as &[u8]),
                (2, &self.epoch_id),
                (3, &sender_sequence),
                (4, self.queue_id.as_bytes()),
                (5, &self.packet_digest),
                (6, &expires_at),
                (7, &accepted_at),
                (8, self.body.as_bytes()),
            ],
        )?;
        Ok(Zeroizing::new(object))
    }
}

/// Send-record state: `1` = `Pending`, `2` = `DeliveryUnknown`,
/// `3` = `Stored`, `4` = `Duplicate`, `5` = `Expired`.
///
/// **Remediation decision (review v2):** only `Pending` carries the full
/// arm (queue, packet, expiry, signature). `DeliveryUnknown` was
/// reclassified into the digest+expiry arm per the frozen design text:
/// section 3's "terminal alternatives holding only digest and expiry" and
/// section 4's grouping of `Stored`, `Duplicate`, expiry and consuming
/// `DeliveryUnknown` as non-advancing. The original slice brief had it in
/// the full arm; the frozen text wins.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SendState {
    Pending = 1,
    DeliveryUnknown = 2,
    Stored = 3,
    Duplicate = 4,
    Expired = 5,
}

impl SendState {
    /// Only `Pending` carries the full arm (queue, packet, expiry,
    /// signature); every other state holds only digest and expiry.
    pub(crate) const fn carries_full_arm(self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// Send-record kind: `1` = application, `2` = receipt (control).
///
/// **Wire-layout amendment (review D2b v4):** fields 10 (`kind: u8`) and
/// 11 (`receipt_high_water: u64`) were added so the expiry sweep and the
/// owed-receipt rule can identify receipt sends without decrypting. Field
/// 10 is present on every record (both arms). Field 11 carries content
/// only on a full-arm receipt record (exactly 8 bytes, value >= 1); it is
/// zero-length (absent) on application and terminal records. Invalid
/// kind, `hw = 0` on a receipt, nonzero hw on an application record, or
/// an hw field on a terminal record all reject; a full-arm receipt's hw
/// must additionally not exceed the session's
/// `highest_contiguous_received_seq` (semantic validation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SendKind {
    Application = 1,
    Receipt = 2,
}

/// Send record (object type `0x0007`). Both arms are encoded under the
/// same field IDs with zero length meaning absent, per the optional-field
/// rule: `Pending` carries queue, packet and signature (digest absent);
/// `DeliveryUnknown`, `Stored`, `Duplicate` and `Expired` carry only
/// digest and expiry.
pub(crate) struct SendRecord {
    pub(crate) message_id: MessageId,
    pub(crate) state: SendState,
    pub(crate) epoch_id: [u8; 32],
    pub(crate) sequence: u64,
    pub(crate) queue_id: Option<QueueId>,
    pub(crate) packet: Option<EncryptedPacket>,
    pub(crate) expires_at: u64,
    pub(crate) send_signature: Option<Ed25519Signature>,
    pub(crate) packet_digest: Option<[u8; 32]>,
    pub(crate) kind: SendKind,
    /// Present (>= 1) only on a full-arm receipt record (field 11).
    pub(crate) receipt_high_water: Option<u64>,
}

impl SendRecord {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut object = ObjectReader::expect(Reader::new(bytes), SEND_TYPE)?;
        let record = Self {
            message_id: message_id(object.field(1)?)?,
            state: match u8_value(object.field(2)?)? {
                1 => SendState::Pending,
                2 => SendState::DeliveryUnknown,
                3 => SendState::Stored,
                4 => SendState::Duplicate,
                5 => SendState::Expired,
                _ => return Err(LabError::Storage),
            },
            epoch_id: epoch_id(object.field(3)?)?,
            sequence: u64_value(object.field(4)?)?,
            queue_id: optional(object.field(5)?, queue_id)?,
            packet: optional(object.field_bounded(6, MAX_PACKET)?, |value| {
                Ok(EncryptedPacket::from_untrusted(value.to_vec()))
            })?,
            expires_at: u64_value(object.field(7)?)?,
            send_signature: optional(object.field(8)?, signature)?,
            packet_digest: optional(object.field(9)?, tlv::fixed::<32>)?,
            kind: match u8_value(object.field(10)?)? {
                1 => SendKind::Application,
                2 => SendKind::Receipt,
                _ => return Err(LabError::Storage),
            },
            receipt_high_water: optional(object.field(11)?, u64_value)?,
        };
        object.finish()?;
        if !record.arms_consistent() {
            return Err(LabError::Storage);
        }
        Ok(record)
    }

    /// The optional fields must match the state arm and kind exactly.
    pub(crate) fn arms_consistent(&self) -> bool {
        let arm_ok = if self.state.carries_full_arm() {
            self.queue_id.is_some()
                && self.packet.is_some()
                && self.send_signature.is_some()
                && self.packet_digest.is_none()
        } else {
            self.queue_id.is_none()
                && self.packet.is_none()
                && self.send_signature.is_none()
                && self.packet_digest.is_some()
        };
        let kind_ok = match (self.state.carries_full_arm(), self.kind) {
            (true, SendKind::Receipt) => self.receipt_high_water.is_some_and(|hw| hw >= 1),
            // Full-arm application records and every terminal record
            // carry no high water.
            (true, SendKind::Application) | (false, _) => self.receipt_high_water.is_none(),
        };
        arm_ok && kind_ok
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let state = [self.state as u8];
        let sequence = self.sequence.to_be_bytes();
        let expires_at = self.expires_at.to_be_bytes();
        let queue = self
            .queue_id
            .map_or_else(Vec::new, |id| id.as_bytes().to_vec());
        let packet = self
            .packet
            .as_ref()
            .map_or_else(Vec::new, |packet| packet.as_bytes().to_vec());
        let signature_bytes = self
            .send_signature
            .map_or_else(Vec::new, |sig| sig.to_bytes().to_vec());
        let digest = self
            .packet_digest
            .map_or_else(Vec::new, |digest| digest.to_vec());
        let kind = [self.kind as u8];
        let high_water = self
            .receipt_high_water
            .map_or_else(Vec::new, |hw| hw.to_be_bytes().to_vec());
        let object = tlv::write_object(
            SEND_TYPE,
            &[
                (1, self.message_id.as_bytes() as &[u8]),
                (2, &state),
                (3, &self.epoch_id),
                (4, &sequence),
                (5, &queue),
                (6, &packet),
                (7, &expires_at),
                (8, &signature_bytes),
                (9, &digest),
                (10, &kind),
                (11, &high_water),
            ],
        )?;
        Ok(Zeroizing::new(object))
    }
}

/// ACK-intent state: `1` = `Pending`, `2` = `Committed`, `3` = `Failed`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AckState {
    Pending = 1,
    Committed = 2,
    Failed = 3,
}

/// ACK intent (object type `0x0008`): epoch, sequence, queue, digest,
/// expiry and exact terminal state.
pub(crate) struct AckIntent {
    pub(crate) message_id: MessageId,
    pub(crate) epoch_id: [u8; 32],
    pub(crate) sequence: u64,
    pub(crate) queue_id: QueueId,
    pub(crate) packet_digest: [u8; 32],
    pub(crate) valid_until: u64,
    pub(crate) state: AckState,
}

impl AckIntent {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut object = ObjectReader::expect(Reader::new(bytes), ACK_TYPE)?;
        let record = Self {
            message_id: message_id(object.field(1)?)?,
            epoch_id: epoch_id(object.field(2)?)?,
            sequence: u64_value(object.field(3)?)?,
            queue_id: queue_id(object.field(4)?)?,
            packet_digest: tlv::fixed::<32>(object.field(5)?)?,
            valid_until: u64_value(object.field(6)?)?,
            state: match u8_value(object.field(7)?)? {
                1 => AckState::Pending,
                2 => AckState::Committed,
                3 => AckState::Failed,
                _ => return Err(LabError::Storage),
            },
        };
        object.finish()?;
        Ok(record)
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let sequence = self.sequence.to_be_bytes();
        let valid_until = self.valid_until.to_be_bytes();
        let state = [self.state as u8];
        let object = tlv::write_object(
            ACK_TYPE,
            &[
                (1, self.message_id.as_bytes() as &[u8]),
                (2, &self.epoch_id),
                (3, &sequence),
                (4, self.queue_id.as_bytes()),
                (5, &self.packet_digest),
                (6, &valid_until),
                (7, &state),
            ],
        )?;
        Ok(Zeroizing::new(object))
    }
}

/// Deduplication state: `1` = `Accepted`, `2` = `Acked`, `3` = `Expired`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DedupState {
    Accepted = 1,
    Acked = 2,
    Expired = 3,
}

/// Deduplication record (object type `0x0009`): epoch, sequence, queue,
/// digest, expiry and exact terminal state.
///
/// **Wire-layout amendment (review D2b v11):** field 8,
/// `message_digest: [u8; 32]`, is the digest of the INNER Olm
/// `Message`'s canonical bytes, independent of which `OlmMessage`
/// variant carried it. Field 5 (`packet_digest`) remains the raw packet
/// digest and stays the envelope/ACK binding, because that is what the
/// sender signs — but it cannot be the dedup identity on its own. v11
/// made the packet ENCODING canonical, which collapsed the JSON and
/// inner-framing alias classes, but not the VARIANT alias: the same
/// inner `Message` is canonically representable both as a `PreKey`
/// packet and as a `Normal` one, and an established session decrypts
/// both, consuming the same message key. So a `PreKey` packet already
/// accepted could be re-serialized as `Normal`, re-signed under a fresh
/// envelope ID, miss the raw digest, and gap-lock the session. Field 8
/// is the variant-independent identity that closes it. The object
/// declares 8 fields.
pub(crate) struct DedupRecord {
    pub(crate) message_id: MessageId,
    pub(crate) epoch_id: [u8; 32],
    pub(crate) sequence: u64,
    pub(crate) queue_id: QueueId,
    pub(crate) packet_digest: [u8; 32],
    pub(crate) expires_at: u64,
    pub(crate) state: DedupState,
    /// Digest of the inner Olm `Message` bytes, variant-independent
    /// (field 8). The dedup identity; `packet_digest` is the binding.
    pub(crate) message_digest: [u8; 32],
}

impl DedupRecord {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let mut object = ObjectReader::expect(Reader::new(bytes), DEDUP_TYPE)?;
        let record = Self {
            message_id: message_id(object.field(1)?)?,
            epoch_id: epoch_id(object.field(2)?)?,
            sequence: u64_value(object.field(3)?)?,
            queue_id: queue_id(object.field(4)?)?,
            packet_digest: tlv::fixed::<32>(object.field(5)?)?,
            expires_at: u64_value(object.field(6)?)?,
            state: match u8_value(object.field(7)?)? {
                1 => DedupState::Accepted,
                2 => DedupState::Acked,
                3 => DedupState::Expired,
                _ => return Err(LabError::Storage),
            },
            message_digest: tlv::fixed::<32>(object.field(8)?)?,
        };
        object.finish()?;
        Ok(record)
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let sequence = self.sequence.to_be_bytes();
        let expires_at = self.expires_at.to_be_bytes();
        let state = [self.state as u8];
        let object = tlv::write_object(
            DEDUP_TYPE,
            &[
                (1, self.message_id.as_bytes() as &[u8]),
                (2, &self.epoch_id),
                (3, &sequence),
                (4, self.queue_id.as_bytes()),
                (5, &self.packet_digest),
                (6, &expires_at),
                (7, &state),
                (8, &self.message_digest),
            ],
        )?;
        Ok(Zeroizing::new(object))
    }
}

/// Parse a `count:u32be` + length-delimited-object array. The count bound
/// is enforced before the output vector is allocated; elements must be
/// strictly increasing by raw `MessageId` (equal or decreasing fails).
pub(crate) fn parse_record_array<T>(
    bytes: &[u8],
    bound: usize,
    parse: impl Fn(&[u8]) -> Result<T>,
    id_of: impl Fn(&T) -> MessageId,
) -> Result<Vec<T>> {
    let mut reader = Reader::new(bytes);
    let count = tlv::length_prefix(reader.u32()?)?;
    if count > bound {
        return Err(LabError::Storage);
    }
    let mut records = Vec::with_capacity(count);
    let mut previous: Option<[u8; 16]> = None;
    for _ in 0..count {
        let length = tlv::length_prefix(reader.u32()?)?;
        let record = parse(reader.take(length)?)?;
        let id = *id_of(&record).as_bytes();
        if previous.is_some_and(|prev| id <= prev) {
            return Err(LabError::Storage);
        }
        previous = Some(id);
        records.push(record);
    }
    if !reader.is_done() {
        return Err(LabError::Storage);
    }
    Ok(records)
}

/// Encode a record array as `count:u32be` + length-delimited objects.
/// Sortedness is (re)checked by semantic validation on the encode path.
/// The result may carry plaintext record bodies and is zeroized on drop.
pub(crate) fn encode_record_array<T>(
    records: &[T],
    bound: usize,
    encode: impl Fn(&T) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>> {
    if records.len() > bound {
        return Err(LabError::Storage);
    }
    let count = u32::try_from(records.len()).map_err(|_| LabError::Storage)?;
    let mut out = Vec::new();
    tlv::write_u32(&mut out, count);
    for record in records {
        let bytes = encode(record)?;
        let length = u32::try_from(bytes.len()).map_err(|_| LabError::Storage)?;
        tlv::write_u32(&mut out, length);
        out.extend_from_slice(&bytes);
    }
    Ok(Zeroizing::new(out))
}

/// Parse the `received_above_high_water` set: `count:u32be` then
/// `count` big-endian `u64`s, strictly increasing (it is a set).
fn parse_u64_set(bytes: &[u8], bound: usize) -> Result<Vec<u64>> {
    let mut reader = Reader::new(bytes);
    let count = tlv::length_prefix(reader.u32()?)?;
    if count > bound {
        return Err(LabError::Storage);
    }
    let mut values = Vec::with_capacity(count);
    let mut previous: Option<u64> = None;
    for _ in 0..count {
        let value = reader.u64()?;
        if previous.is_some_and(|prev| value <= prev) {
            return Err(LabError::Storage);
        }
        previous = Some(value);
        values.push(value);
    }
    if !reader.is_done() {
        return Err(LabError::Storage);
    }
    Ok(values)
}

fn encode_u64_set(values: &[u64], bound: usize) -> Result<Vec<u8>> {
    if values.len() > bound {
        return Err(LabError::Storage);
    }
    let count = u32::try_from(values.len()).map_err(|_| LabError::Storage)?;
    let mut out = Vec::new();
    tlv::write_u32(&mut out, count);
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
    Ok(out)
}
