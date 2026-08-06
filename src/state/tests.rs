//! Tests for the `ClientStateV1` codec (design section 3) and its semantic
//! validation (sections 3 and 4). Fixtures are built through real
//! vodozemac operations: genuine accounts, one-time keys, sessions and
//! encrypted packets, so every pickle and signature is authentic.
//!
//! Byte-level mutations of `profile_id`, `key_ref` and `generation` are
//! intentionally NOT asserted to fail: nothing inside the plaintext
//! cross-checks them, so the codec cannot detect their mutation. They are
//! authenticated by the outer AEAD/platform binding (design section 1),
//! not by this codec. That gap is documented in the slice report.

use std::error::Error;

use vodozemac::olm::{Account, OlmMessage, SessionConfig};
use vodozemac::{Curve25519PublicKey, Ed25519Keypair, Ed25519Signature};
use zeroize::Zeroizing;

use super::records::{
    self, AckIntent, ActiveSession, DedupRecord, InboundRecord, PeerBinding, PendingPreKey,
    RegistrationRecord, SendRecord,
};
use super::tlv;
use super::validate::{prekey_signing_bytes, receipt_signing_bytes, send_signing_bytes};
use super::{
    AckState, CLIENT_STATE_TYPE, ClientStateV1, DedupState, HighWaterReceipt, MAGIC,
    MAX_ACCOUNT_PICKLE, MAX_BODY, MAX_DEDUP, MAX_INBOUND, MAX_KEYPAIR_JSON, MAX_PACKET,
    MAX_RECEIVED_SET, MAX_SENDS, MAX_SESSION_PICKLE, MAX_TOTAL_PLAINTEXT, PeerBundle, Role,
    SendState, SessionMode,
};
use crate::capability::digest;
use crate::{
    ConversationId, EncryptedPacket, MailboxOwner, MailboxRegistration, MessageId, QueueId,
};

const NOW: u64 = 1_800_000_000;

struct Fixture {
    state: ClientStateV1,
    our_account: Account,
    peer_account: Account,
}

fn keypair_json(keypair: &Ed25519Keypair) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    Ok(Zeroizing::new(serde_json::to_vec(keypair)?))
}

fn sorted_message_ids(count: usize) -> Vec<MessageId> {
    let mut ids: Vec<MessageId> = (0..count).map(|_| MessageId::random()).collect();
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ids
}

fn epoch_of(keys: vodozemac::olm::SessionKeys) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(96);
    preimage.extend_from_slice(keys.identity_key.as_bytes());
    preimage.extend_from_slice(keys.base_key.as_bytes());
    preimage.extend_from_slice(keys.one_time_key.as_bytes());
    digest(&preimage)
}

fn signed_receipt(
    conversation_id: ConversationId,
    epoch_id: [u8; 32],
    our_account: &Account,
    peer_account: &Account,
    high_water: u64,
) -> HighWaterReceipt {
    let mut receipt = HighWaterReceipt {
        conversation_id,
        epoch_id,
        acknowledged_sender_curve: our_account.curve25519_key(),
        issuer_curve: peer_account.curve25519_key(),
        high_water,
        signature: peer_account.sign(b""),
    };
    receipt.signature = peer_account.sign(receipt_signing_bytes(&receipt));
    receipt
}

fn make_pending_prekey(account: &mut Account) -> Result<PendingPreKey, Box<dyn Error>> {
    let one_time_key = *account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("one-time key generation produced nothing")?;
    account.mark_keys_as_published();
    let mut prekey = PendingPreKey {
        signing_identity: account.ed25519_key(),
        curve_identity: account.curve25519_key(),
        one_time_key,
        created_at: NOW,
        valid_until: NOW + 300,
        signature: account.sign(b""),
    };
    prekey.signature = account.sign(prekey_signing_bytes(&prekey.bundle()));
    Ok(prekey)
}

/// A signed peer bundle plus the one-time key it advertises.
fn make_peer_bundle(
    account: &mut Account,
) -> Result<(PeerBundle, Curve25519PublicKey), Box<dyn Error>> {
    let one_time_key = *account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("one-time key generation produced nothing")?;
    account.mark_keys_as_published();
    let mut bundle = PeerBundle {
        signing_identity: account.ed25519_key(),
        curve_identity: account.curve25519_key(),
        one_time_key,
        valid_until: NOW + 300,
        signature: account.sign(b""),
    };
    bundle.signature = account.sign(prekey_signing_bytes(&bundle));
    Ok((bundle, one_time_key))
}

/// Two genuine pending sends and one terminal send, sequences 1..=3.
fn make_send_records(
    session: &mut vodozemac::olm::Session,
    peer_send_keypair: &Ed25519Keypair,
    peer_queue_id: QueueId,
    epoch_id: [u8; 32],
) -> Result<Vec<SendRecord>, Box<dyn Error>> {
    let send_ids = sorted_message_ids(3);
    let mut sends = Vec::new();
    for (index, message_id) in send_ids.iter().take(2).enumerate() {
        let sequence = u64::try_from(index)? + 1;
        let message = session.encrypt(format!("payload-{sequence}"))?;
        let packet = EncryptedPacket::from_untrusted(serde_json::to_vec(&message)?);
        let expires_at = NOW + 3_600;
        let signature = peer_send_keypair.sign(&send_signing_bytes(
            peer_queue_id,
            *message_id,
            &packet.digest(),
            expires_at,
        ));
        sends.push(SendRecord {
            message_id: *message_id,
            state: SendState::Pending,
            epoch_id,
            sequence,
            queue_id: Some(peer_queue_id),
            packet: Some(packet),
            expires_at,
            send_signature: Some(signature),
            packet_digest: None,
        });
    }
    sends.push(SendRecord {
        message_id: send_ids[2],
        state: SendState::Stored,
        epoch_id,
        sequence: 3,
        queue_id: None,
        packet: None,
        expires_at: NOW + 3_600,
        send_signature: None,
        packet_digest: Some(digest(b"stored-packet")),
    });
    Ok(sends)
}

/// One accepted inbound at sender sequence 3 (above the contiguous high
/// water 1, so it sits in the out-of-order set), its ACK intent, and the
/// sorted dedup array (its own record plus one older terminal record).
fn make_inbound_side(
    queue_id: QueueId,
    epoch_id: [u8; 32],
    message_id: MessageId,
) -> Result<(InboundRecord, AckIntent, Vec<DedupRecord>), Box<dyn Error>> {
    let packet_digest = digest(b"inbound-packet");
    let inbound = InboundRecord {
        message_id,
        epoch_id,
        sender_sequence: 3,
        queue_id,
        packet_digest,
        expires_at: NOW + 3_600,
        accepted_at: NOW,
        body: "delivered body".to_owned(),
    };
    let ack = AckIntent {
        message_id,
        epoch_id,
        sequence: 3,
        queue_id,
        packet_digest,
        valid_until: NOW + 3_600,
        state: AckState::Pending,
    };
    let inbound_dedup = DedupRecord {
        message_id,
        epoch_id,
        sequence: 3,
        queue_id,
        packet_digest,
        expires_at: NOW + 3_600,
        state: DedupState::Accepted,
    };
    let old_dedup = DedupRecord {
        message_id: MessageId::from_slice(&[0xAA; 16]).ok_or("bad test id")?,
        epoch_id,
        sequence: 1,
        queue_id,
        packet_digest: digest(b"old-packet"),
        expires_at: NOW + 3_600,
        state: DedupState::Acked,
    };
    let mut dedup = vec![inbound_dedup, old_dedup];
    dedup.sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));
    Ok((inbound, ack, dedup))
}

fn registration_record(registration: &MailboxRegistration) -> RegistrationRecord {
    RegistrationRecord {
        queue_id: registration.queue_id,
        send_key: registration.send_key,
        receive_key: registration.receive_key,
        manage_key: registration.manage_key,
        nonce: registration.nonce,
        valid_until: registration.valid_until,
        signature: registration.signature,
    }
}

type KeypairJsons = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

fn mailbox_jsons(mailbox: &MailboxOwner) -> Result<KeypairJsons, Box<dyn Error>> {
    let keypairs = mailbox.serialized_private_material();
    Ok((
        Zeroizing::new(keypairs.first().ok_or("send keypair")?.clone()),
        Zeroizing::new(keypairs.get(1).ok_or("receive keypair")?.clone()),
        Zeroizing::new(keypairs.get(2).ok_or("manage keypair")?.clone()),
    ))
}

/// Everything `assemble_state` needs beyond the account and mailbox.
struct StateAssembly {
    conversation_id: ConversationId,
    registration: MailboxRegistration,
    pending_prekey: Option<PendingPreKey>,
    peer_binding: Option<PeerBinding>,
    active_session: Option<ActiveSession>,
    inbound: Vec<InboundRecord>,
    sends: Vec<SendRecord>,
    acks: Vec<AckIntent>,
    dedup: Vec<DedupRecord>,
}

fn assemble_state(
    account: &Account,
    mailbox: &MailboxOwner,
    generation: u64,
    parts: StateAssembly,
) -> Result<ClientStateV1, Box<dyn Error>> {
    let (send_json, receive_json, manage_json) = mailbox_jsons(mailbox)?;
    Ok(ClientStateV1 {
        profile_id: [0x11; 16],
        key_ref: [0x22; 16],
        generation,
        conversation_id: parts.conversation_id,
        account_pickle: Zeroizing::new(serde_json::to_vec(&account.pickle())?),
        own_ed25519_identity: account.ed25519_key(),
        own_curve_identity: account.curve25519_key(),
        mailbox_queue_id: mailbox.queue_id(),
        send_keypair_json: send_json,
        receive_keypair_json: receive_json,
        manage_keypair_json: manage_json,
        registration: registration_record(&parts.registration),
        pending_prekey: parts.pending_prekey,
        peer_binding: parts.peer_binding,
        active_session: parts.active_session,
        inbound: parts.inbound,
        sends: parts.sends,
        acks: parts.acks,
        dedup: parts.dedup,
    })
}

/// The shared populated-session shape: two pending sends (sequences 1-2),
/// one terminal send (sequence 3), high water 1, mode `Ready`, receipt.
fn make_active_session(
    role: Role,
    session: &vodozemac::olm::Session,
    transcript: &PeerBundle,
    receipt: HighWaterReceipt,
    conversation_id: ConversationId,
) -> Result<ActiveSession, Box<dyn Error>> {
    let keys = session.session_keys();
    Ok(ActiveSession {
        role,
        session_pickle: Zeroizing::new(serde_json::to_vec(&session.pickle())?),
        identity_key: keys.identity_key,
        base_key: keys.base_key,
        one_time_key: keys.one_time_key,
        transcript: *transcript,
        epoch_id: epoch_of(keys),
        last_assigned_send_seq: 3,
        peer_contiguous_high_water: 1,
        highest_contiguous_received_seq: 1,
        mode: SessionMode::Ready,
        receipt: Some(receipt),
        received_above_high_water: vec![3],
        conversation_id,
    })
}

/// A fully populated valid state: pending prekey, peer binding, outbound
/// session with a receipt, one inbound record, three send records (two
/// `Pending`, one terminal `Stored`), one ACK intent and two dedup records.
///
/// The receive side is GENUINE (review v2 remediation): our outbound
/// session encrypts a bootstrap pre-key message, the peer's real inbound
/// session is created from it and replies, and our session decrypts the
/// reply, so `has_received_message()` is true and every receive-side
/// record reflects real ratchet history.
fn populated_fixture() -> Result<Fixture, Box<dyn Error>> {
    outbound_fixture(true)
}

/// Same as `populated_fixture` but the peer never replies: the session has
/// only ever encrypted. Used by the receive-side provenance negative tests
/// and the receipt-only positive test.
fn send_only_fixture() -> Result<Fixture, Box<dyn Error>> {
    outbound_fixture(false)
}

fn outbound_fixture(genuine_receive: bool) -> Result<Fixture, Box<dyn Error>> {
    let mut our_account = Account::new();
    let mut peer_account = Account::new();
    let our_mailbox = MailboxOwner::new();
    let peer_mailbox = MailboxOwner::new();
    let conversation_id = ConversationId::random();

    let pending_prekey = make_pending_prekey(&mut our_account)?;
    let (peer_bundle, peer_otk) = make_peer_bundle(&mut peer_account)?;
    let mut session = our_account.create_outbound_session(
        SessionConfig::version_1(),
        peer_bundle.curve_identity,
        peer_otk,
    )?;

    if genuine_receive {
        let bootstrap = session.encrypt(b"session bootstrap")?;
        let OlmMessage::PreKey(pre_key_message) = bootstrap else {
            return Err("first message must be a pre-key message".into());
        };
        let mut peer_side = peer_account
            .create_inbound_session(
                SessionConfig::version_1(),
                our_account.curve25519_key(),
                &pre_key_message,
            )?
            .session;
        let reply = peer_side.encrypt(b"peer reply")?;
        let _plaintext = session.decrypt(&reply)?;
    }

    let peer_send_keypair = Ed25519Keypair::new();
    let epoch_id = epoch_of(session.session_keys());
    let sends = make_send_records(
        &mut session,
        &peer_send_keypair,
        peer_mailbox.queue_id(),
        epoch_id,
    )?;
    let inbound_id = sends.first().ok_or("no sends")?.message_id;
    let (inbound, ack, dedup) = make_inbound_side(our_mailbox.queue_id(), epoch_id, inbound_id)?;
    let receipt = signed_receipt(conversation_id, epoch_id, &our_account, &peer_account, 1);
    let active_session = make_active_session(
        Role::Outbound,
        &session,
        &peer_bundle,
        receipt,
        conversation_id,
    )?;

    let state = assemble_state(
        &our_account,
        &our_mailbox,
        1,
        StateAssembly {
            conversation_id,
            registration: our_mailbox.registration(NOW + 3_600),
            pending_prekey: Some(pending_prekey),
            peer_binding: Some(PeerBinding {
                bundle: peer_bundle,
                queue_id: peer_mailbox.queue_id(),
                send_keypair_json: keypair_json(&peer_send_keypair)?,
                send_public_key: peer_send_keypair.public_key(),
            }),
            active_session: Some(active_session),
            inbound: vec![inbound],
            sends,
            acks: vec![ack],
            dedup,
        },
    )?;
    Ok(Fixture {
        state,
        our_account,
        peer_account,
    })
}

/// A fully populated valid state with a GENUINE inbound session: the peer
/// created a real outbound session against our real published one-time key
/// and we accepted the real pre-key message with `create_inbound_session`.
/// The session transcript is our own consumed prekey bundle.
fn inbound_fixture() -> Result<Fixture, Box<dyn Error>> {
    let mut our_account = Account::new();
    let mut peer_account = Account::new();
    let our_mailbox = MailboxOwner::new();
    let peer_mailbox = MailboxOwner::new();
    let conversation_id = ConversationId::random();

    // Our advertised prekey bundle becomes the session transcript.
    let transcript = make_pending_prekey(&mut our_account)?.bundle();
    let consumed_otk = transcript.one_time_key;

    // The peer creates a real outbound session against our published key;
    // we accept the real pre-key message, consuming the key.
    let mut peer_session = peer_account.create_outbound_session(
        SessionConfig::version_1(),
        our_account.curve25519_key(),
        consumed_otk,
    )?;
    let first_message = peer_session.encrypt(b"session bootstrap")?;
    let OlmMessage::PreKey(pre_key_message) = first_message else {
        return Err("first message must be a pre-key message".into());
    };
    let creation = our_account.create_inbound_session(
        SessionConfig::version_1(),
        peer_account.curve25519_key(),
        &pre_key_message,
    )?;
    let mut session = creation.session;
    assert!(!our_account.contains_one_time_key(consumed_otk));

    // Pin the vodozemac initiator/recipient semantics this fixture and the
    // role-aware validation rely on.
    let keys = session.session_keys();
    assert_eq!(keys.identity_key, peer_account.curve25519_key());
    assert_eq!(keys.one_time_key, consumed_otk);

    let (peer_bundle, _) = make_peer_bundle(&mut peer_account)?;
    let peer_send_keypair = Ed25519Keypair::new();
    let epoch_id = epoch_of(keys);
    let sends = make_send_records(
        &mut session,
        &peer_send_keypair,
        peer_mailbox.queue_id(),
        epoch_id,
    )?;
    let inbound_id = sends.first().ok_or("no sends")?.message_id;
    let (inbound, ack, dedup) = make_inbound_side(our_mailbox.queue_id(), epoch_id, inbound_id)?;
    // A second, unconsumed one-time key backs the pending-prekey field.
    let pending_prekey = make_pending_prekey(&mut our_account)?;
    let receipt = signed_receipt(conversation_id, epoch_id, &our_account, &peer_account, 1);
    let active_session = make_active_session(
        Role::Inbound,
        &session,
        &transcript,
        receipt,
        conversation_id,
    )?;

    let state = assemble_state(
        &our_account,
        &our_mailbox,
        1,
        StateAssembly {
            conversation_id,
            registration: our_mailbox.registration(NOW + 3_600),
            pending_prekey: Some(pending_prekey),
            peer_binding: Some(PeerBinding {
                bundle: peer_bundle,
                queue_id: peer_mailbox.queue_id(),
                send_keypair_json: keypair_json(&peer_send_keypair)?,
                send_public_key: peer_send_keypair.public_key(),
            }),
            active_session: Some(active_session),
            inbound: vec![inbound],
            sends,
            acks: vec![ack],
            dedup,
        },
    )?;
    Ok(Fixture {
        state,
        our_account,
        peer_account,
    })
}

/// A minimal valid state: all optional fields absent, all arrays empty
/// except one dedup record (dedup records legitimately outlive a session
/// through their safety window; section 4).
fn minimal_fixture() -> Result<Fixture, Box<dyn Error>> {
    let our_account = Account::new();
    let peer_account = Account::new();
    let our_mailbox = MailboxOwner::new();
    let dedup = DedupRecord {
        message_id: MessageId::from_slice(&[0x55; 16]).ok_or("bad test id")?,
        epoch_id: digest(b"old-epoch"),
        sequence: 7,
        queue_id: our_mailbox.queue_id(),
        packet_digest: digest(b"old-packet"),
        expires_at: NOW + 3_600,
        state: DedupState::Expired,
    };
    let state = assemble_state(
        &our_account,
        &our_mailbox,
        9,
        StateAssembly {
            conversation_id: ConversationId::random(),
            registration: our_mailbox.registration(NOW + 3_600),
            pending_prekey: None,
            peer_binding: None,
            active_session: None,
            inbound: Vec::new(),
            sends: Vec::new(),
            acks: Vec::new(),
            dedup: vec![dedup],
        },
    )?;
    Ok(Fixture {
        state,
        our_account,
        peer_account,
    })
}

// --- byte-level test helpers ---------------------------------------------

fn field_block(id: u16, value: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = Vec::new();
    tlv::write_field(&mut out, id, value)?;
    Ok(out)
}

/// Owned-field wrapper over the borrowed-field `tlv::write_object`, for
/// hand-crafted test objects.
fn owned_object(object_type: u16, fields: &[(u16, Vec<u8>)]) -> Result<Vec<u8>, Box<dyn Error>> {
    let borrowed: Vec<(u16, &[u8])> = fields.iter().map(|(id, value)| (*id, &value[..])).collect();
    Ok(tlv::write_object(object_type, &borrowed)?)
}

/// Split a framed state into its top-level field blocks (ID + length +
/// value each).
fn split_top(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut rest = bytes.get(12..).ok_or("framing too short")?;
    let mut blocks = Vec::new();
    while !rest.is_empty() {
        let length = usize::try_from(u32::from_be_bytes(
            rest.get(2..6).ok_or("field header truncated")?.try_into()?,
        ))?;
        let block_len = 6 + length;
        blocks.push(
            rest.get(..block_len)
                .ok_or("field value truncated")?
                .to_vec(),
        );
        rest = rest.get(block_len..).ok_or("field value truncated")?;
    }
    Ok(blocks)
}

fn join_top(blocks: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    let count = u16::try_from(blocks.len())?;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&CLIENT_STATE_TYPE.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    for block in blocks {
        out.extend_from_slice(block);
    }
    Ok(out)
}

/// Value span (`start`, `end`) of the `index`-th top-level field.
fn field_value_span(bytes: &[u8], index: usize) -> Result<(usize, usize), Box<dyn Error>> {
    let mut position = 12_usize;
    for current in 0..=index {
        let length = usize::try_from(u32::from_be_bytes(
            bytes
                .get(position + 2..position + 6)
                .ok_or("field header truncated")?
                .try_into()?,
        ))?;
        if current == index {
            return Ok((position + 6, position + 6 + length));
        }
        position += 6 + length;
    }
    Err("field index out of range".into())
}

/// Split an array field value into its element blocks (length + object).
fn split_array(value: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let count = u32::from_be_bytes(value.get(..4).ok_or("array count truncated")?.try_into()?);
    let mut rest = value.get(4..).ok_or("array count truncated")?;
    let mut elements = Vec::new();
    for _ in 0..count {
        let length = usize::try_from(u32::from_be_bytes(
            rest.get(..4)
                .ok_or("element length truncated")?
                .try_into()?,
        ))?;
        let total = 4 + length;
        elements.push(rest.get(..total).ok_or("element truncated")?.to_vec());
        rest = rest.get(total..).ok_or("element truncated")?;
    }
    if !rest.is_empty() {
        return Err("array trailing bytes".into());
    }
    Ok(elements)
}

fn join_array(elements: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = u32::try_from(elements.len())?.to_be_bytes().to_vec();
    for element in elements {
        out.extend_from_slice(element);
    }
    Ok(out)
}

/// Replace the `index`-th top-level field block with `block`.
fn splice_top(bytes: &[u8], index: usize, block: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut blocks = split_top(bytes)?;
    let slot = blocks.get_mut(index).ok_or("field index out of range")?;
    *slot = block;
    join_top(&blocks)
}

fn flip_signature(signature: Ed25519Signature) -> Result<Ed25519Signature, Box<dyn Error>> {
    let mut bytes = signature.to_bytes();
    bytes[0] ^= 0x01;
    Ok(Ed25519Signature::from_slice(&bytes)?)
}

fn mailbox_value(
    queue_id: QueueId,
    send: &[u8],
    receive: &[u8],
    manage: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = queue_id.as_bytes().to_vec();
    for json in [send, receive, manage] {
        out.extend_from_slice(&u32::try_from(json.len())?.to_be_bytes());
        out.extend_from_slice(json);
    }
    Ok(out)
}

// --- round trips ----------------------------------------------------------

#[test]
fn populated_state_round_trips_byte_identically() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let decoded = ClientStateV1::decode(&encoded)?;
    let reencoded = decoded.encode()?;
    assert_eq!(&encoded[..], &reencoded[..]);
    Ok(())
}

#[test]
fn minimal_state_round_trips_byte_identically() -> Result<(), Box<dyn Error>> {
    let fixture = minimal_fixture()?;
    let encoded = fixture.state.encode()?;
    // Fields 13-15 (optional) must be present with zero length.
    let blocks = split_top(&encoded)?;
    for index in [12_usize, 13, 14] {
        let block = blocks.get(index).ok_or("optional field missing")?;
        assert_eq!(
            block.len(),
            6,
            "absent optional field must have zero length"
        );
    }
    let decoded = ClientStateV1::decode(&encoded)?;
    let reencoded = decoded.encode()?;
    assert_eq!(&encoded[..], &reencoded[..]);
    Ok(())
}

// --- structural grammar enforcement ---------------------------------------

#[test]
fn wrong_magic_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let mut bytes = fixture.state.encode()?.to_vec();
    let first = bytes.get_mut(0).ok_or("empty encoding")?;
    *first ^= 0x01;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn wrong_top_level_object_type_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let mut bytes = fixture.state.encode()?.to_vec();
    // Object type occupies bytes 8..10.
    let byte = bytes.get_mut(9).ok_or("short encoding")?;
    *byte ^= 0x01;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn trailing_bytes_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let mut bytes = fixture.state.encode()?.to_vec();
    bytes.push(0x00);
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn wrong_field_count_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    for count in [18_u16, 20] {
        let mut bytes = encoded.to_vec();
        bytes[10..12].copy_from_slice(&count.to_be_bytes());
        assert!(
            ClientStateV1::decode(&bytes).is_err(),
            "count {count} accepted"
        );
    }
    Ok(())
}

#[test]
fn out_of_order_fields_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let mut blocks = split_top(&encoded)?;
    blocks.swap(4, 5);
    assert!(ClientStateV1::decode(&join_top(&blocks)?).is_err());
    Ok(())
}

#[test]
fn duplicate_field_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let mut blocks = split_top(&encoded)?;
    let duplicate = blocks.get(4).ok_or("missing field")?.clone();
    blocks.insert(5, duplicate);
    assert!(ClientStateV1::decode(&join_top(&blocks)?).is_err());
    Ok(())
}

#[test]
fn unknown_field_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let mut blocks = split_top(&encoded)?;
    blocks.push(field_block(20, b"nope")?);
    assert!(ClientStateV1::decode(&join_top(&blocks)?).is_err());
    Ok(())
}

#[test]
fn missing_field_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let mut blocks = split_top(&encoded)?;
    blocks.remove(8); // the Account pickle
    assert!(ClientStateV1::decode(&join_top(&blocks)?).is_err());
    Ok(())
}

#[test]
fn fixed_length_field_wrong_length_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    // Profile ID is [16]; fifteen bytes must fail.
    let bytes = splice_top(&encoded, 1, field_block(2, &[0u8; 15])?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    // Seventeen bytes must also fail (incomplete field consumption).
    let bytes = splice_top(&encoded, 1, field_block(2, &[0u8; 17])?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn truncated_input_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    for cut in [1_usize, 10, 100] {
        let truncated = &encoded[..encoded.len() - cut];
        assert!(
            ClientStateV1::decode(truncated).is_err(),
            "cut {cut} accepted"
        );
    }
    Ok(())
}

#[test]
fn huge_value_length_prefix_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    // u32::MAX value length on the protocol-domain field: must fail the
    // remaining-length check before any allocation attempt.
    let mut block = 5_u16.to_be_bytes().to_vec();
    block.extend_from_slice(&u32::MAX.to_be_bytes());
    let bytes = splice_top(&encoded, 4, block)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn optional_field_semantics_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    // Zero length means absent: clearing fields 13-15 must still decode
    // (the rest of the minimal invariants hold for this state too? no:
    // session-dependent records reference the session, so only the prekey
    // can be cleared alone).
    let bytes = splice_top(&encoded, 12, field_block(13, &[])?)?;
    let decoded = ClientStateV1::decode(&bytes)?;
    assert!(decoded.pending_prekey.is_none());
    // A single garbage byte in an optional field is malformed.
    let bytes = splice_top(&encoded, 12, field_block(13, &[0x00])?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    // A required field may not be zero-length.
    let bytes = splice_top(&encoded, 11, field_block(12, &[])?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn nested_object_trailing_byte_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let registration = fixture.state.registration.encode()?;
    let mut padded = registration;
    padded.push(0x00);
    let bytes = splice_top(&encoded, 11, field_block(12, &padded)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn invalid_enums_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let blocks = split_top(&encoded)?;

    // SendRecord.state (field 2 of the object) sits at byte offset 32:
    // 4 header + (6 + 16) field 1 + (6) field 2 header.
    for invalid in [0_u8, 6] {
        let mut elements = split_array(blocks.get(16).ok_or("sends")?.get(6..).ok_or("sends")?)?;
        let record = elements.get_mut(0).ok_or("no send record")?;
        *record.get_mut(4 + 32).ok_or("state byte")? = invalid;
        let value = join_array(&elements)?;
        let bytes = splice_top(&encoded, 16, field_block(17, &value)?)?;
        assert!(
            ClientStateV1::decode(&bytes).is_err(),
            "send state {invalid}"
        );
    }

    // ActiveSession.role is field 1 of the session object: byte offset 10.
    for invalid in [0_u8, 3] {
        let (start, end) = field_value_span(&encoded, 14)?;
        let mut session = encoded.get(start..end).ok_or("session span")?.to_vec();
        *session.get_mut(10).ok_or("role byte")? = invalid;
        let bytes = splice_top(&encoded, 14, field_block(15, &session)?)?;
        assert!(ClientStateV1::decode(&bytes).is_err(), "role {invalid}");
    }

    // AckIntent.state and DedupRecord.state are the last bytes of their
    // objects.
    for invalid in [0_u8, 4] {
        let mut elements = split_array(blocks.get(17).ok_or("acks")?.get(6..).ok_or("acks")?)?;
        let record = elements.get_mut(0).ok_or("no ack")?;
        let last = record.len() - 1;
        *record.get_mut(last).ok_or("ack state")? = invalid;
        let bytes = splice_top(&encoded, 17, field_block(18, &join_array(&elements)?)?)?;
        assert!(
            ClientStateV1::decode(&bytes).is_err(),
            "ack state {invalid}"
        );

        let mut elements = split_array(blocks.get(18).ok_or("dedup")?.get(6..).ok_or("dedup")?)?;
        let record = elements.get_mut(0).ok_or("no dedup")?;
        let last = record.len() - 1;
        *record.get_mut(last).ok_or("dedup state")? = invalid;
        let bytes = splice_top(&encoded, 18, field_block(19, &join_array(&elements)?)?)?;
        assert!(
            ClientStateV1::decode(&bytes).is_err(),
            "dedup state {invalid}"
        );
    }
    Ok(())
}

#[test]
fn total_plaintext_bound_enforced() {
    let oversized = vec![0_u8; MAX_TOTAL_PLAINTEXT + 1];
    assert!(ClientStateV1::decode(&oversized).is_err());
}

#[test]
fn account_pickle_bound_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let oversized = vec![b' '; MAX_ACCOUNT_PICKLE + 1];
    let bytes = splice_top(&encoded, 8, field_block(9, &oversized)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn keypair_bound_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let mailbox = mailbox_value(
        fixture.state.mailbox_queue_id,
        &vec![b' '; MAX_KEYPAIR_JSON + 1],
        &fixture.state.receive_keypair_json,
        &fixture.state.manage_keypair_json,
    )?;
    let bytes = splice_top(&encoded, 10, field_block(11, &mailbox)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn session_pickle_bound_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let session = owned_object(
        records::ACTIVE_SESSION_TYPE,
        &[
            (1, vec![1_u8]),
            (2, vec![b' '; MAX_SESSION_PICKLE + 1]),
            (3, vec![0; 32]),
            (4, vec![0; 32]),
            (5, vec![0; 32]),
        ],
    )?;
    let bytes = splice_top(&encoded, 14, field_block(15, &session)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn body_bound_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let record = owned_object(
        records::INBOUND_TYPE,
        &[
            (1, fixture.state.inbound[0].message_id.as_bytes().to_vec()),
            (2, fixture.state.inbound[0].epoch_id.to_vec()),
            (3, 3_u64.to_be_bytes().to_vec()),
            (4, fixture.state.mailbox_queue_id.as_bytes().to_vec()),
            (5, vec![0; 32]),
            (6, (NOW + 60).to_be_bytes().to_vec()),
            (7, NOW.to_be_bytes().to_vec()),
            (8, vec![b'x'; MAX_BODY + 1]),
        ],
    )?;
    let array = join_array(&[length_prefixed(&record)?])?;
    let bytes = splice_top(&encoded, 15, field_block(16, &array)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn packet_bound_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let record = owned_object(
        records::SEND_TYPE,
        &[
            (1, fixture.state.sends[0].message_id.as_bytes().to_vec()),
            (2, vec![1_u8]),
            (3, fixture.state.sends[0].epoch_id.to_vec()),
            (4, 1_u64.to_be_bytes().to_vec()),
            (5, vec![0; 32]),
            (6, vec![0; MAX_PACKET + 1]),
            (7, (NOW + 60).to_be_bytes().to_vec()),
            (8, vec![0; 64]),
            (9, Vec::new()),
        ],
    )?;
    let array = join_array(&[length_prefixed(&record)?])?;
    let bytes = splice_top(&encoded, 16, field_block(17, &array)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

fn length_prefixed(object: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = u32::try_from(object.len())?.to_be_bytes().to_vec();
    out.extend_from_slice(object);
    Ok(out)
}

#[test]
fn array_count_bounds_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    // Each oversized count must fail before any element parsing.
    for (index, field_id, count) in [
        (15_usize, 16_u16, MAX_INBOUND + 1),
        (16, 17, MAX_SENDS + 1),
        (17, 18, 32 + 1),
        (18, 19, MAX_DEDUP + 1),
    ] {
        let value = u32::try_from(count)?.to_be_bytes().to_vec();
        let bytes = splice_top(&encoded, index, field_block(field_id, &value)?)?;
        assert!(
            ClientStateV1::decode(&bytes).is_err(),
            "field {field_id} count {count}"
        );
    }
    // The received-set bound lives inside the session object (field 17).
    let mut received = u32::try_from(MAX_RECEIVED_SET + 1)?.to_be_bytes().to_vec();
    for value in 0..=MAX_RECEIVED_SET {
        received.extend_from_slice(&u64::try_from(value)?.to_be_bytes());
    }
    let session = owned_object(
        records::ACTIVE_SESSION_TYPE,
        &[
            (1, vec![1_u8]),
            (2, b"{}".to_vec()),
            (3, vec![0; 32]),
            (4, vec![0; 32]),
            (5, vec![0; 32]),
            (6, vec![0; 32]),
            (7, vec![0; 32]),
            (8, vec![0; 32]),
            (9, 1_u64.to_be_bytes().to_vec()),
            (10, vec![0; 64]),
            (11, vec![0; 32]),
            (12, 1_u64.to_be_bytes().to_vec()),
            (13, 0_u64.to_be_bytes().to_vec()),
            (14, 0_u64.to_be_bytes().to_vec()),
            (15, vec![1_u8]),
            (16, Vec::new()),
            (17, received),
        ],
    )?;
    let bytes = splice_top(&encoded, 14, field_block(15, &session)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn unsorted_and_equal_array_ids_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let blocks = split_top(&encoded)?;
    let dedup_value = blocks.get(18).ok_or("dedup")?.get(6..).ok_or("dedup")?;
    let mut elements = split_array(dedup_value)?;
    assert_eq!(
        elements.len(),
        2,
        "fixture dedup array must have two elements"
    );

    // Swapping the two elements breaks the strictly-increasing order.
    elements.swap(0, 1);
    let bytes = splice_top(&encoded, 18, field_block(19, &join_array(&elements)?)?)?;
    assert!(
        ClientStateV1::decode(&bytes).is_err(),
        "decreasing IDs accepted"
    );

    // Duplicating an element creates equal IDs.
    let first = elements.first().ok_or("no element")?.clone();
    let bytes = splice_top(
        &encoded,
        18,
        field_block(19, &join_array(&[first.clone(), first])?)?,
    )?;
    assert!(ClientStateV1::decode(&bytes).is_err(), "equal IDs accepted");
    Ok(())
}

#[test]
fn unsorted_arrays_rejected_on_encode() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    fixture.state.dedup.swap(0, 1);
    assert!(
        fixture.state.encode().is_err(),
        "decreasing dedup IDs accepted"
    );
    fixture.state.dedup.swap(0, 1);
    let duplicate = DedupRecord {
        message_id: fixture.state.dedup[0].message_id,
        epoch_id: fixture.state.dedup[0].epoch_id,
        sequence: fixture.state.dedup[0].sequence,
        queue_id: fixture.state.dedup[0].queue_id,
        packet_digest: fixture.state.dedup[0].packet_digest,
        expires_at: fixture.state.dedup[0].expires_at,
        state: fixture.state.dedup[0].state,
    };
    fixture.state.dedup.push(duplicate);
    assert!(fixture.state.encode().is_err(), "equal dedup IDs accepted");
    Ok(())
}

#[test]
fn invalid_utf8_body_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let record = owned_object(
        records::INBOUND_TYPE,
        &[
            (1, fixture.state.inbound[0].message_id.as_bytes().to_vec()),
            (2, fixture.state.inbound[0].epoch_id.to_vec()),
            (3, 3_u64.to_be_bytes().to_vec()),
            (4, fixture.state.mailbox_queue_id.as_bytes().to_vec()),
            (5, vec![0; 32]),
            (6, (NOW + 60).to_be_bytes().to_vec()),
            (7, NOW.to_be_bytes().to_vec()),
            (8, vec![0xFF, 0xFE]),
        ],
    )?;
    let array = join_array(&[length_prefixed(&record)?])?;
    let bytes = splice_top(&encoded, 15, field_block(16, &array)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn send_record_arm_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let blocks = split_top(&encoded)?;
    let mut elements = split_array(blocks.get(16).ok_or("sends")?.get(6..).ok_or("sends")?)?;

    // The terminal record (index 2) relabeled as Pending keeps the
    // digest-only arm: arm consistency must fail.
    let terminal = elements.get_mut(2).ok_or("no terminal send")?;
    *terminal.get_mut(4 + 32).ok_or("state byte")? = 1;
    let bytes = splice_top(&encoded, 16, field_block(17, &join_array(&elements)?)?)?;
    assert!(
        ClientStateV1::decode(&bytes).is_err(),
        "terminal arm as Pending"
    );

    // A pending record (index 0) relabeled as Stored keeps the full arm.
    let mut elements = split_array(blocks.get(16).ok_or("sends")?.get(6..).ok_or("sends")?)?;
    let pending = elements.get_mut(0).ok_or("no pending send")?;
    *pending.get_mut(4 + 32).ok_or("state byte")? = 3;
    let bytes = splice_top(&encoded, 16, field_block(17, &join_array(&elements)?)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err(), "full arm as Stored");
    Ok(())
}

#[test]
fn byte_flip_in_each_cross_checked_field_fails() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    // Indices 1-3 (profile ID, key reference, generation) are excluded:
    // nothing inside the plaintext cross-checks them, so their mutation is
    // detectable only by the outer AEAD (documented gap). Every other
    // top-level field must fail decode or validation when flipped.
    for index in [
        0_usize, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    ] {
        let (start, end) = field_value_span(&encoded, index)?;
        assert!(end > start, "field {index} unexpectedly empty");
        let mut mutated = encoded.to_vec();
        *mutated.get_mut(start).ok_or("value start")? ^= 0x01;
        assert!(
            ClientStateV1::decode(&mutated).is_err(),
            "first-byte flip in field {index} accepted"
        );
    }
    Ok(())
}

#[test]
fn byte_flip_in_signature_positions_fails() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    // The last byte of each of these fields sits inside a signature, a
    // public key, an enum or the received set; flipping it must fail. The
    // ACK array ends in the ACK state byte (Pending = 1, flipping bit 0
    // makes the invalid 0).
    for index in [11_usize, 12, 13, 14, 17] {
        let (_, end) = field_value_span(&encoded, index)?;
        let mut mutated = encoded.to_vec();
        *mutated.get_mut(end - 1).ok_or("value end")? ^= 0x01;
        assert!(
            ClientStateV1::decode(&mutated).is_err(),
            "last-byte flip in field {index} accepted"
        );
    }
    Ok(())
}

// --- canonical JSON --------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct TinyDoc {
    a: u8,
    b: String,
}

#[test]
fn canonical_json_properties_hold_empirically() -> Result<(), Box<dyn Error>> {
    let canonical = br#"{"a":1,"b":"x"}"#;
    tlv::canonical_json::<TinyDoc>(canonical, 64)?;

    // Whitespace variants deserialize fine but are not canonical.
    let spaced = br#"{ "a": 1, "b": "x" }"#;
    assert!(serde_json::from_slice::<TinyDoc>(spaced).is_ok());
    assert!(tlv::canonical_json::<TinyDoc>(spaced, 64).is_err());

    // Non-canonical member order (serde derives are order-insensitive on
    // reads, so byte equality is what rejects this).
    let reordered = br#"{"b":"x","a":1}"#;
    assert!(serde_json::from_slice::<TinyDoc>(reordered).is_ok());
    assert!(tlv::canonical_json::<TinyDoc>(reordered, 64).is_err());

    // Unknown fields are ignored by default serde derives; byte equality
    // rejects them.
    let unknown = br#"{"a":1,"b":"x","c":0}"#;
    assert!(serde_json::from_slice::<TinyDoc>(unknown).is_ok());
    assert!(tlv::canonical_json::<TinyDoc>(unknown, 64).is_err());

    // Missing fields.
    assert!(tlv::canonical_json::<TinyDoc>(br#"{"a":1}"#, 64).is_err());

    // Duplicate keys: serde's derive rejects them outright.
    let duplicate = br#"{"a":1,"a":2,"b":"x"}"#;
    assert!(serde_json::from_slice::<TinyDoc>(duplicate).is_err());
    assert!(tlv::canonical_json::<TinyDoc>(duplicate, 64).is_err());

    // Trailing data, whitespace and garbage alike.
    assert!(tlv::canonical_json::<TinyDoc>(br#"{"a":1,"b":"x"} "#, 64).is_err());
    assert!(tlv::canonical_json::<TinyDoc>(br#"{"a":1,"b":"x"}0"#, 64).is_err());

    // The bound is enforced before deserialization.
    assert!(tlv::canonical_json::<TinyDoc>(canonical, 4).is_err());
    Ok(())
}

#[test]
fn keypair_json_duplicate_key_rejected_empirically() -> Result<(), Box<dyn Error>> {
    let json = serde_json::to_string(&Ed25519Keypair::new())?;
    let pair = json
        .get(1..json.len() - 1)
        .ok_or("unexpected keypair JSON shape")?;
    let duplicated = format!("{{{pair},{pair}}}");
    assert!(serde_json::from_str::<Ed25519Keypair>(&duplicated).is_err());
    assert!(
        tlv::canonical_json::<Ed25519Keypair>(duplicated.as_bytes(), MAX_KEYPAIR_JSON).is_err()
    );
    Ok(())
}

#[test]
fn account_pickle_whitespace_variant_rejected() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    let pretty = serde_json::to_string_pretty(&fixture.our_account.pickle())?;
    assert!(serde_json::from_str::<vodozemac::olm::AccountPickle>(&pretty).is_ok());
    fixture.state.account_pickle = Zeroizing::new(pretty.into_bytes());
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn session_pickle_defaulted_member_rejected() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    let json = String::from_utf8(active.session_pickle.to_vec())?;
    let needle = ",\"config\":{\"version\":\"V1\"}";
    let position = json
        .find(needle)
        .ok_or("config member not found in session pickle")?;
    let mut shortened = json;
    shortened.replace_range(position..position + needle.len(), "");
    // The member deserializes via serde's default, so only canonical byte
    // equality can reject the document.
    assert!(serde_json::from_str::<vodozemac::olm::SessionPickle>(&shortened).is_ok());
    active.session_pickle = Zeroizing::new(shortened.into_bytes());
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn account_pickle_serde_alias_rejected() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    let json = String::from_utf8(fixture.state.account_pickle.to_vec())?;
    let needle = "\"next_key_id\"";
    if !json.contains(needle) {
        return Err("next_key_id not found in account pickle".into());
    }
    // vodozemac declares `key_id` as a serde alias for `next_key_id`, so
    // this deserializes; only canonical byte equality rejects it.
    let aliased = json.replacen(needle, "\"key_id\"", 1);
    assert!(serde_json::from_str::<vodozemac::olm::AccountPickle>(&aliased).is_ok());
    fixture.state.account_pickle = Zeroizing::new(aliased.into_bytes());
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn noncanonical_keypair_json_rejected_on_decode() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let mut padded = fixture.state.send_keypair_json.to_vec();
    padded.insert(1, b' ');
    assert!(serde_json::from_slice::<Ed25519Keypair>(&padded).is_ok());
    let mailbox = mailbox_value(
        fixture.state.mailbox_queue_id,
        &padded,
        &fixture.state.receive_keypair_json,
        &fixture.state.manage_keypair_json,
    )?;
    let bytes = splice_top(&encoded, 10, field_block(11, &mailbox)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn top_level_constants_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    // Schema version must be exactly 1.
    let bytes = splice_top(&encoded, 0, field_block(1, &2_u16.to_be_bytes())?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    // Session config must be exactly version 1.
    let bytes = splice_top(&encoded, 6, field_block(7, &[2])?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

// --- semantic validation ---------------------------------------------------

#[test]
fn registration_and_capability_cross_checks() -> Result<(), Box<dyn Error>> {
    // Management signature must verify over the exact intent and request.
    let mut fixture = populated_fixture()?;
    fixture.state.registration.signature = flip_signature(fixture.state.registration.signature)?;
    assert!(fixture.state.encode().is_err());

    // Capability public keys must match the registration intent.
    let mut fixture = populated_fixture()?;
    fixture.state.registration.send_key = Ed25519Keypair::new().public_key();
    assert!(fixture.state.encode().is_err());

    // The mailbox queue must be the registered queue.
    let mut fixture = populated_fixture()?;
    fixture.state.mailbox_queue_id = QueueId::random();
    assert!(fixture.state.encode().is_err());

    // The stored own public identity must equal the account's.
    let mut fixture = populated_fixture()?;
    fixture.state.own_ed25519_identity = fixture.peer_account.ed25519_key();
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn pending_prekey_cross_checks() -> Result<(), Box<dyn Error>> {
    // Signature must verify.
    let mut fixture = populated_fixture()?;
    let prekey = fixture.state.pending_prekey.as_mut().ok_or("no prekey")?;
    prekey.signature = flip_signature(prekey.signature)?;
    assert!(fixture.state.encode().is_err());

    // Identities must be the account's own, even with a valid re-signature
    // by the impostor.
    let mut fixture = populated_fixture()?;
    let prekey = fixture.state.pending_prekey.as_mut().ok_or("no prekey")?;
    prekey.signing_identity = fixture.peer_account.ed25519_key();
    prekey.signature = fixture
        .peer_account
        .sign(prekey_signing_bytes(&prekey.bundle()));
    assert!(fixture.state.encode().is_err());

    // `created_at < valid_until` is required.
    let mut fixture = populated_fixture()?;
    let valid_until = {
        let prekey = fixture.state.pending_prekey.as_mut().ok_or("no prekey")?;
        prekey.created_at = prekey.valid_until;
        prekey.signature = fixture
            .our_account
            .sign(prekey_signing_bytes(&prekey.bundle()));
        prekey.valid_until
    };
    assert!(
        fixture.state.encode().is_err(),
        "created_at == valid_until ({valid_until})"
    );

    // The exact one-time key must still exist in the account: swap in a
    // key that is not ours and re-sign.
    let mut fixture = populated_fixture()?;
    let foreign = *fixture
        .peer_account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("no foreign one-time key")?;
    let prekey = fixture.state.pending_prekey.as_mut().ok_or("no prekey")?;
    prekey.one_time_key = foreign;
    prekey.signature = fixture
        .our_account
        .sign(prekey_signing_bytes(&prekey.bundle()));
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn consumed_one_time_key_fails_validation() -> Result<(), Box<dyn Error>> {
    let mut fixture = minimal_fixture()?;
    let mut account = Account::new();
    let one_time_key = *account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("no one-time key")?;
    account.mark_keys_as_published();
    let mut prekey = PendingPreKey {
        signing_identity: account.ed25519_key(),
        curve_identity: account.curve25519_key(),
        one_time_key,
        created_at: NOW,
        valid_until: NOW + 300,
        signature: account.sign(b""),
    };
    prekey.signature = account.sign(prekey_signing_bytes(&prekey.bundle()));
    fixture.state.own_ed25519_identity = account.ed25519_key();
    fixture.state.own_curve_identity = account.curve25519_key();
    fixture.state.account_pickle = Zeroizing::new(serde_json::to_vec(&account.pickle())?);
    fixture.state.pending_prekey = Some(prekey);

    // The present, published key validates and round-trips.
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;

    // Consume the key through a real inbound session, then require
    // validation to fail against the updated account pickle.
    let consumer = Account::new();
    let mut consumer_session = consumer.create_outbound_session(
        SessionConfig::version_1(),
        account.curve25519_key(),
        one_time_key,
    )?;
    let message = consumer_session.encrypt(b"consume")?;
    let OlmMessage::PreKey(pre_key_message) = message else {
        return Err("first message must be a pre-key message".into());
    };
    let _result = account.create_inbound_session(
        SessionConfig::version_1(),
        consumer.curve25519_key(),
        &pre_key_message,
    )?;
    assert!(!account.contains_one_time_key(one_time_key));
    fixture.state.account_pickle = Zeroizing::new(serde_json::to_vec(&account.pickle())?);
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn peer_binding_cross_checks() -> Result<(), Box<dyn Error>> {
    // The stored send public key must be the reconstructed keypair's.
    let mut fixture = populated_fixture()?;
    let binding = fixture.state.peer_binding.as_mut().ok_or("no binding")?;
    binding.send_public_key = Ed25519Keypair::new().public_key();
    assert!(fixture.state.encode().is_err());

    // The bundle signature must verify under the pinned identity.
    let mut fixture = populated_fixture()?;
    let binding = fixture.state.peer_binding.as_mut().ok_or("no binding")?;
    binding.bundle.signature = flip_signature(binding.bundle.signature)?;
    assert!(fixture.state.encode().is_err());

    // The binding bundle must equal the session transcript, even when the
    // changed bundle is validly re-signed by the peer.
    let mut fixture = populated_fixture()?;
    let binding = fixture.state.peer_binding.as_mut().ok_or("no binding")?;
    binding.bundle.valid_until += 300;
    binding.bundle.signature = fixture
        .peer_account
        .sign(prekey_signing_bytes(&binding.bundle));
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn active_session_cross_checks() -> Result<(), Box<dyn Error>> {
    // Transcript signature must verify.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.transcript.signature = flip_signature(active.transcript.signature)?;
    assert!(fixture.state.encode().is_err());

    // Epoch ID must be SHA-256(identity || base || one-time key).
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.epoch_id[0] ^= 0x01;
    assert!(fixture.state.encode().is_err());

    // Relabeling an outbound session as inbound must fail: an inbound
    // transcript must be our own bundle signed by our own identity, but
    // this transcript is the peer's bundle. (A genuine inbound session is
    // covered by `genuine_inbound_session_round_trips_byte_identically`
    // and the inbound negative tests below.)
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.role = Role::Inbound;
    assert!(fixture.state.encode().is_err());

    // The stored establishment keys must equal `session_keys()`.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.base_key = active.one_time_key;
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn send_cross_checks_enforced() -> Result<(), Box<dyn Error>> {
    // Send signature must verify under the bound send capability.
    let mut fixture = populated_fixture()?;
    let signature = fixture.state.sends[0]
        .send_signature
        .ok_or("no signature")?;
    fixture.state.sends[0].send_signature = Some(flip_signature(signature)?);
    assert!(fixture.state.encode().is_err());

    // The send queue must be the peer's mailbox.
    let mut fixture = populated_fixture()?;
    fixture.state.sends[0].queue_id = Some(fixture.state.mailbox_queue_id);
    assert!(fixture.state.encode().is_err());

    // Send sequences may not exceed `last_assigned_send_seq`.
    let mut fixture = populated_fixture()?;
    fixture.state.sends[0].sequence = 4;
    assert!(fixture.state.encode().is_err());

    // Send sequences must be distinct.
    let mut fixture = populated_fixture()?;
    fixture.state.sends[1].sequence = 1;
    assert!(fixture.state.encode().is_err());

    // Non-terminal sends require the peer binding.
    let mut fixture = populated_fixture()?;
    fixture.state.peer_binding = None;
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn inbound_cross_checks_enforced() -> Result<(), Box<dyn Error>> {
    // The queue must be our own mailbox.
    let mut fixture = populated_fixture()?;
    fixture.state.inbound[0].queue_id = QueueId::random();
    assert!(fixture.state.encode().is_err());

    // The envelope must have been unexpired at acceptance.
    let mut fixture = populated_fixture()?;
    fixture.state.inbound[0].expires_at = NOW;
    assert!(fixture.state.encode().is_err());

    // A sequence above the contiguous high water must be in the received
    // set.
    let mut fixture = populated_fixture()?;
    fixture.state.inbound[0].sender_sequence = 4;
    assert!(fixture.state.encode().is_err());

    // Every inbound record needs its dedup record.
    let mut fixture = populated_fixture()?;
    fixture.state.inbound[0].message_id = MessageId::random();
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn ack_requires_matching_dedup_record() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    fixture.state.acks[0].message_id = MessageId::random();
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn session_absence_requires_session_records_absent() -> Result<(), Box<dyn Error>> {
    // Dedup records without a session are fine and round-trip.
    let fixture = minimal_fixture()?;
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;

    for case in ["inbound", "send", "ack"] {
        let mut fixture = populated_fixture()?;
        fixture.state.active_session = None;
        match case {
            "inbound" => {
                fixture.state.sends.clear();
                fixture.state.acks.clear();
            }
            "send" => {
                fixture.state.inbound.clear();
                fixture.state.acks.clear();
            }
            _ => {
                fixture.state.inbound.clear();
                fixture.state.sends.clear();
            }
        }
        assert!(
            fixture.state.encode().is_err(),
            "{case} record without a session"
        );
    }
    Ok(())
}

fn set_water(
    fixture: &mut Fixture,
    last_assigned: u64,
    high_water: u64,
    mode: SessionMode,
) -> Result<(), Box<dyn Error>> {
    let conversation_id = fixture.state.conversation_id;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.last_assigned_send_seq = last_assigned;
    active.peer_contiguous_high_water = high_water;
    active.mode = mode;
    active.receipt = if high_water == 0 {
        None
    } else {
        Some(signed_receipt(
            conversation_id,
            active.epoch_id,
            &fixture.our_account,
            &fixture.peer_account,
            high_water,
        ))
    };
    Ok(())
}

#[test]
fn high_water_may_not_exceed_last_assigned() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    set_water(&mut fixture, 3, 4, SessionMode::Ready)?;
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn outstanding_budget_and_mode_consistency() -> Result<(), Box<dyn Error>> {
    // More than 32 outstanding is malformed: reject in every mode.
    let mut fixture = populated_fixture()?;
    set_water(&mut fixture, 33, 0, SessionMode::ReceiptLocked)?;
    assert!(fixture.state.encode().is_err());

    // Exactly 32: ReceiptLocked only among the BUDGET modes;
    // RekeyRequired dominates and is accepted (covered explicitly by
    // `rekey_required_dominates_budget_at_any_outstanding`).
    for (mode, valid) in [
        (SessionMode::Ready, false),
        (SessionMode::ControlOnly, false),
        (SessionMode::ReceiptLocked, true),
        (SessionMode::RekeyRequired, true),
    ] {
        let mut fixture = populated_fixture()?;
        set_water(&mut fixture, 32, 0, mode)?;
        assert_eq!(
            fixture.state.encode().is_ok(),
            valid,
            "outstanding 32, {mode:?}"
        );
    }

    // 24..=31: ControlOnly or ReceiptLocked; RekeyRequired dominates.
    for (mode, valid) in [
        (SessionMode::Ready, false),
        (SessionMode::ControlOnly, true),
        (SessionMode::ReceiptLocked, true),
        (SessionMode::RekeyRequired, true),
    ] {
        let mut fixture = populated_fixture()?;
        set_water(&mut fixture, 24, 0, mode)?;
        assert_eq!(
            fixture.state.encode().is_ok(),
            valid,
            "outstanding 24, {mode:?}"
        );
    }

    // 0..=23 outstanding: any mode, and each round-trips.
    for mode in [
        SessionMode::Ready,
        SessionMode::ControlOnly,
        SessionMode::ReceiptLocked,
        SessionMode::RekeyRequired,
    ] {
        let mut fixture = populated_fixture()?;
        set_water(&mut fixture, 3, 1, mode)?;
        let encoded = fixture.state.encode()?;
        ClientStateV1::decode(&encoded)?;
    }
    Ok(())
}

#[test]
fn receipt_rules_enforced() -> Result<(), Box<dyn Error>> {
    // A nonzero high water without the latest receipt is malformed.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.receipt = None;
    assert!(fixture.state.encode().is_err());

    // The receipt high water must equal `peer_contiguous_high_water`.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.peer_contiguous_high_water = 2;
    assert!(fixture.state.encode().is_err());

    // The receipt must bind this conversation.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.receipt = Some(signed_receipt(
        ConversationId::random(),
        active.epoch_id,
        &fixture.our_account,
        &fixture.peer_account,
        1,
    ));
    assert!(fixture.state.encode().is_err());

    // The receipt signature must verify under the peer's pinned identity.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    let receipt = active.receipt.as_mut().ok_or("no receipt")?;
    receipt.signature = flip_signature(receipt.signature)?;
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn received_set_gap_rules_enforced() -> Result<(), Box<dyn Error>> {
    // An element exactly at `hcr + 1` would have advanced the contiguous
    // high water.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.received_above_high_water = vec![2, 3];
    assert!(fixture.state.encode().is_err());

    // An element at or below the contiguous high water is inconsistent.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.received_above_high_water = vec![1, 3];
    assert!(fixture.state.encode().is_err());

    // The set is strictly increasing.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.received_above_high_water = vec![4, 3];
    assert!(fixture.state.encode().is_err());

    // The set is bounded at 64.
    let mut fixture = populated_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.received_above_high_water = (3..=67).collect();
    assert!(fixture.state.encode().is_err());
    Ok(())
}

// --- role-aware transcript (remediation regression tests) ------------------

/// The reviewers' reproduction, now passing: a genuine inbound session
/// (peer initiated against our real published one-time key; we accepted
/// the real pre-key message) encodes, validates and round-trips
/// byte-identically.
#[test]
fn genuine_inbound_session_round_trips_byte_identically() -> Result<(), Box<dyn Error>> {
    let fixture = inbound_fixture()?;
    let encoded = fixture.state.encode()?;
    let decoded = ClientStateV1::decode(&encoded)?;
    let reencoded = decoded.encode()?;
    assert_eq!(&encoded[..], &reencoded[..]);
    Ok(())
}

#[test]
fn inbound_transcript_otk_must_match_session_keys() -> Result<(), Box<dyn Error>> {
    let mut fixture = inbound_fixture()?;
    // A foreign key our account never held, re-signed by us, so only the
    // `session_keys.one_time_key` mismatch can fail validation.
    let foreign = *fixture
        .peer_account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("no foreign key")?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.transcript.one_time_key = foreign;
    active.transcript.signature = fixture
        .our_account
        .sign(prekey_signing_bytes(&active.transcript));
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn inbound_consumed_otk_must_not_remain_in_account() -> Result<(), Box<dyn Error>> {
    let mut our_account = Account::new();
    let mut peer_account = Account::new();
    let our_mailbox = MailboxOwner::new();
    let peer_mailbox = MailboxOwner::new();
    let conversation_id = ConversationId::random();

    let transcript = make_pending_prekey(&mut our_account)?.bundle();
    let consumed_otk = transcript.one_time_key;
    // Account snapshot taken BEFORE consumption; the session is after.
    let stale_pickle = Zeroizing::new(serde_json::to_vec(&our_account.pickle())?);

    let mut peer_session = peer_account.create_outbound_session(
        SessionConfig::version_1(),
        our_account.curve25519_key(),
        consumed_otk,
    )?;
    let first_message = peer_session.encrypt(b"session bootstrap")?;
    let OlmMessage::PreKey(pre_key_message) = first_message else {
        return Err("first message must be a pre-key message".into());
    };
    let creation = our_account.create_inbound_session(
        SessionConfig::version_1(),
        peer_account.curve25519_key(),
        &pre_key_message,
    )?;
    let mut session = creation.session;

    // Sanity: the stale snapshot still holds the consumed key.
    let stale_account = Account::from_pickle(serde_json::from_slice::<
        vodozemac::olm::AccountPickle,
    >(&stale_pickle)?);
    assert!(stale_account.contains_one_time_key(consumed_otk));

    let (peer_bundle, _) = make_peer_bundle(&mut peer_account)?;
    let peer_send_keypair = Ed25519Keypair::new();
    let epoch_id = epoch_of(session.session_keys());
    let sends = make_send_records(
        &mut session,
        &peer_send_keypair,
        peer_mailbox.queue_id(),
        epoch_id,
    )?;
    let inbound_id = sends.first().ok_or("no sends")?.message_id;
    let (inbound, ack, dedup) = make_inbound_side(our_mailbox.queue_id(), epoch_id, inbound_id)?;
    let receipt = signed_receipt(conversation_id, epoch_id, &our_account, &peer_account, 1);
    let active_session = make_active_session(
        Role::Inbound,
        &session,
        &transcript,
        receipt,
        conversation_id,
    )?;

    let mut state = assemble_state(
        &our_account,
        &our_mailbox,
        1,
        StateAssembly {
            conversation_id,
            registration: our_mailbox.registration(NOW + 3_600),
            pending_prekey: None,
            peer_binding: Some(PeerBinding {
                bundle: peer_bundle,
                queue_id: peer_mailbox.queue_id(),
                send_keypair_json: keypair_json(&peer_send_keypair)?,
                send_public_key: peer_send_keypair.public_key(),
            }),
            active_session: Some(active_session),
            inbound: vec![inbound],
            sends,
            acks: vec![ack],
            dedup,
        },
    )?;
    state.account_pickle = stale_pickle;
    assert!(state.encode().is_err());
    Ok(())
}

#[test]
fn inbound_transcript_signature_must_verify_with_own_identity() -> Result<(), Box<dyn Error>> {
    // Flipped signature byte.
    let mut fixture = inbound_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.transcript.signature = flip_signature(active.transcript.signature)?;
    assert!(fixture.state.encode().is_err());

    // Impostor transcript signed by the PEER: the signature verifies
    // against the bundle's own identity, but that identity is not ours.
    let mut fixture = inbound_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.transcript.signing_identity = fixture.peer_account.ed25519_key();
    active.transcript.signature = fixture
        .peer_account
        .sign(prekey_signing_bytes(&active.transcript));
    assert!(fixture.state.encode().is_err());
    Ok(())
}

#[test]
fn session_requires_peer_binding_for_either_role() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    fixture.state.peer_binding = None;
    assert!(fixture.state.encode().is_err(), "outbound without binding");

    let mut fixture = inbound_fixture()?;
    fixture.state.peer_binding = None;
    assert!(fixture.state.encode().is_err(), "inbound without binding");
    Ok(())
}

#[test]
fn session_identity_must_match_peer_binding_curve_for_either_role() -> Result<(), Box<dyn Error>> {
    for use_inbound in [false, true] {
        let mut fixture = if use_inbound {
            inbound_fixture()?
        } else {
            populated_fixture()?
        };
        // Replace the bound peer curve identity with an impostor's and
        // re-sign the bundle under the peer's pinned signing identity, so
        // the bundle itself still verifies and only the session-identity
        // binding can fail.
        let impostor = Account::new();
        let binding = fixture.state.peer_binding.as_mut().ok_or("no binding")?;
        binding.bundle.curve_identity = impostor.curve25519_key();
        binding.bundle.signature = fixture
            .peer_account
            .sign(prekey_signing_bytes(&binding.bundle));
        assert!(
            fixture.state.encode().is_err(),
            "impostor binding curve accepted (inbound={use_inbound})"
        );
    }
    Ok(())
}

// --- review v2 remediation tests -------------------------------------------

/// Finding 1: receive-side state must be provable by the restored ratchet.
/// A session that only ever encrypted rejects any receive-side state.
#[test]
fn receive_side_state_requires_a_receiving_ratchet() -> Result<(), Box<dyn Error>> {
    // (a) A contiguous receive high water without any received message.
    let mut fixture = send_only_fixture()?;
    set_water(&mut fixture, 3, 1, SessionMode::Ready)?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.highest_contiguous_received_seq = 1;
    assert!(fixture.state.encode().is_err(), "(a) fabricated high water");

    // (b) An out-of-order received set on a send-only ratchet.
    let mut fixture = send_only_fixture()?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.received_above_high_water = vec![1];
    assert!(
        fixture.state.encode().is_err(),
        "(b) fabricated received set"
    );

    // (c) One inbound record on a send-only ratchet (dedup record present
    // and consistent; only the ratchet provenance can fail).
    let mut fixture = send_only_fixture()?;
    fixture.state.acks.clear();
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.highest_contiguous_received_seq = 0;
    active.received_above_high_water.clear();
    assert!(
        fixture.state.encode().is_err(),
        "(c) fabricated inbound record"
    );

    // (d) One ACK intent on a send-only ratchet (matching dedup present).
    let mut fixture = send_only_fixture()?;
    fixture.state.inbound.clear();
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.highest_contiguous_received_seq = 0;
    active.received_above_high_water.clear();
    assert!(fixture.state.encode().is_err(), "(d) fabricated ACK intent");
    Ok(())
}

/// Finding 1, converse: a receipt is send-side. A receipt-only session
/// (never received, receipt present, all receive-side state empty) must
/// still validate. Review v3: its dedup records are retired-epoch (any
/// epoch ≠ the session's), since current-epoch dedup is
/// receive-authoritative and would require a receiving ratchet.
#[test]
fn receipt_only_session_validates() -> Result<(), Box<dyn Error>> {
    let mut fixture = send_only_fixture()?;
    fixture.state.inbound.clear();
    fixture.state.acks.clear();
    for record in &mut fixture.state.dedup {
        record.epoch_id = digest(b"retired-epoch");
    }
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.highest_contiguous_received_seq = 0;
    active.received_above_high_water.clear();
    // peer_contiguous_high_water stays 1 with its genuine receipt.
    let encoded = fixture.state.encode()?;
    let decoded = ClientStateV1::decode(&encoded)?;
    let reencoded = decoded.encode()?;
    assert_eq!(&encoded[..], &reencoded[..]);
    Ok(())
}

/// Finding 2: the conversation binding holds receipt-free. Positive: a
/// receipt-free populated session validates when the IDs agree. Negative
/// (Sol's repro): mutating field 8 on the encoded receipt-free state must
/// fail decode, and building a mismatched `active.conversation_id` must
/// fail encode.
#[test]
fn conversation_binding_does_not_depend_on_receipt() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    set_water(&mut fixture, 3, 0, SessionMode::Ready)?; // receipt now None
    let encoded = fixture.state.encode()?;
    let decoded = ClientStateV1::decode(&encoded)?;
    assert_eq!(&encoded[..], &decoded.encode()?[..]);

    // Sol's repro: flip a conversation_id byte in field 8 of the
    // receipt-free encoding; decode must fail.
    let (start, _) = field_value_span(&encoded, 7)?;
    let mut mutated = encoded.to_vec();
    *mutated.get_mut(start).ok_or("conversation field")? ^= 0x01;
    assert!(
        ClientStateV1::decode(&mutated).is_err(),
        "field-8 flip accepted"
    );

    // Build-time mismatch: the session record claims another conversation.
    let mut fixture = populated_fixture()?;
    set_water(&mut fixture, 3, 0, SessionMode::Ready)?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.conversation_id = ConversationId::random();
    assert!(
        fixture.state.encode().is_err(),
        "mismatched session conversation"
    );
    Ok(())
}

/// Finding 3: a Pending -> `DeliveryUnknown` transition drops the full arm
/// and keeps only digest and expiry; it must encode and round-trip.
#[test]
fn delivery_unknown_transition_uses_digest_arm_and_round_trips() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    let pending = &fixture.state.sends[0];
    let packet_digest = pending.packet.as_ref().ok_or("no packet")?.digest();
    let transitioned = SendRecord {
        message_id: pending.message_id,
        state: SendState::DeliveryUnknown,
        epoch_id: pending.epoch_id,
        sequence: pending.sequence,
        queue_id: None,
        packet: None,
        expires_at: pending.expires_at,
        send_signature: None,
        packet_digest: Some(packet_digest),
    };
    fixture.state.sends[0] = transitioned;
    let encoded = fixture.state.encode()?;
    let decoded = ClientStateV1::decode(&encoded)?;
    let reencoded = decoded.encode()?;
    assert_eq!(&encoded[..], &reencoded[..]);
    assert!(matches!(decoded.sends[0].state, SendState::DeliveryUnknown));
    Ok(())
}

/// Finding 3: a `DeliveryUnknown` record still carrying the full arm is
/// rejected, on both the encode and the decode path.
#[test]
fn delivery_unknown_with_full_arm_rejected() -> Result<(), Box<dyn Error>> {
    // Encode path: relabel a Pending record, keeping its full arm.
    let mut fixture = populated_fixture()?;
    fixture.state.sends[0].state = SendState::DeliveryUnknown;
    assert!(fixture.state.encode().is_err());

    // Decode path: same relabel on the wire bytes (state byte at object
    // offset 32 inside the array element).
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    let blocks = split_top(&encoded)?;
    let mut elements = split_array(blocks.get(16).ok_or("sends")?.get(6..).ok_or("sends")?)?;
    let pending = elements.get_mut(0).ok_or("no pending send")?;
    *pending.get_mut(4 + 32).ok_or("state byte")? = 2;
    let bytes = splice_top(&encoded, 16, field_block(17, &join_array(&elements)?)?)?;
    assert!(ClientStateV1::decode(&bytes).is_err());
    Ok(())
}

/// Finding 3: bound accounting across mixed arms — 32 records of mixed
/// `Pending`/`DeliveryUnknown`/terminal states validate; a 33rd record
/// breaks the array bound.
#[test]
fn send_bound_accounting_across_mixed_arms() -> Result<(), Box<dyn Error>> {
    let mut fixture = send_only_fixture()?;
    // Clear the receive side so only the outbox is under test, and make
    // room for 32 outstanding sequences (mode ReceiptLocked at exactly 32).
    // The dedup records are retired-epoch: current-epoch dedup is
    // receive-authoritative (review v3 finding 1) and this ratchet only
    // ever sent.
    fixture.state.inbound.clear();
    fixture.state.acks.clear();
    for record in &mut fixture.state.dedup {
        record.epoch_id = digest(b"retired-epoch");
    }
    set_water(&mut fixture, 32, 0, SessionMode::ReceiptLocked)?;
    let active = fixture.state.active_session.as_mut().ok_or("no session")?;
    active.highest_contiguous_received_seq = 0;
    active.received_above_high_water.clear();

    // Keep the two genuine Pending records (sequences 1-2), drop the
    // terminal one, then add 30 digest-arm records (sequences 3..=32,
    // alternating DeliveryUnknown/Stored) with fresh sorted IDs.
    fixture.state.sends.truncate(2);
    let epoch_id = fixture.state.sends[0].epoch_id;
    let mut extra_ids = sorted_message_ids(29);
    for (index, message_id) in extra_ids.drain(..).enumerate() {
        let sequence = u64::try_from(index)? + 4;
        let state = if index % 2 == 0 {
            SendState::DeliveryUnknown
        } else {
            SendState::Stored
        };
        fixture.state.sends.push(SendRecord {
            message_id,
            state,
            epoch_id,
            sequence,
            queue_id: None,
            packet: None,
            expires_at: NOW + 3_600,
            send_signature: None,
            packet_digest: Some(digest(b"packet")),
        });
    }
    // Re-add a terminal record at sequence 3 and sort by message ID.
    fixture.state.sends.push(SendRecord {
        message_id: MessageId::from_slice(&[0x01; 16]).ok_or("bad test id")?,
        state: SendState::Stored,
        epoch_id,
        sequence: 3,
        queue_id: None,
        packet: None,
        expires_at: NOW + 3_600,
        send_signature: None,
        packet_digest: Some(digest(b"stored-packet")),
    });
    fixture
        .state
        .sends
        .sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));
    assert_eq!(fixture.state.sends.len(), 32);
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;

    // A 33rd record exceeds the bound regardless of arm.
    fixture.state.sends.push(SendRecord {
        message_id: MessageId::from_slice(&[0xF0; 16]).ok_or("bad test id")?,
        state: SendState::DeliveryUnknown,
        epoch_id,
        sequence: 3,
        queue_id: None,
        packet: None,
        expires_at: NOW + 3_600,
        send_signature: None,
        packet_digest: Some(digest(b"another")),
    });
    assert!(fixture.state.encode().is_err());
    Ok(())
}

/// Finding 4: the pending prekey must reference a PUBLISHED one-time key.
/// Held-but-unpublished is rejected; marked-published still passes.
#[test]
fn pending_prekey_must_be_marked_published() -> Result<(), Box<dyn Error>> {
    let mut fixture = minimal_fixture()?;
    let mut account = Account::new();
    let one_time_key = *account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("no one-time key")?;
    // Deliberately NOT marked as published.
    let mut prekey = PendingPreKey {
        signing_identity: account.ed25519_key(),
        curve_identity: account.curve25519_key(),
        one_time_key,
        created_at: NOW,
        valid_until: NOW + 300,
        signature: account.sign(b""),
    };
    prekey.signature = account.sign(prekey_signing_bytes(&prekey.bundle()));
    assert!(account.contains_one_time_key(one_time_key));
    assert!(
        account
            .one_time_keys()
            .values()
            .any(|key| *key == one_time_key)
    );

    fixture.state.own_ed25519_identity = account.ed25519_key();
    fixture.state.own_curve_identity = account.curve25519_key();
    fixture.state.account_pickle = Zeroizing::new(serde_json::to_vec(&account.pickle())?);
    fixture.state.pending_prekey = Some(prekey);
    assert!(fixture.state.encode().is_err(), "unpublished OTK accepted");

    // Marking it published (and re-pickling) makes the state valid again.
    account.mark_keys_as_published();
    fixture.state.account_pickle = Zeroizing::new(serde_json::to_vec(&account.pickle())?);
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;
    Ok(())
}

// --- review v3 remediation tests -------------------------------------------

/// Finding 1: a dedup record for the CURRENT epoch is
/// receive-authoritative; retired-epoch records stay exempt.
#[test]
fn current_epoch_dedup_requires_receive_provenance() -> Result<(), Box<dyn Error>> {
    // Current-epoch dedup on a never-received ratchet (the receipt-only
    // shape with a current-epoch dedup record) ⇒ reject.
    let mut fixture = send_only_fixture()?;
    fixture.state.inbound.clear();
    fixture.state.acks.clear();
    {
        let active = fixture.state.active_session.as_mut().ok_or("no session")?;
        active.highest_contiguous_received_seq = 0;
        active.received_above_high_water.clear();
    }
    assert!(
        fixture.state.encode().is_err(),
        "current-epoch dedup accepted on a never-received ratchet"
    );

    // Current-epoch dedup with sequence above the contiguous high water
    // and absent from the received set ⇒ reject, even on a genuinely
    // receiving ratchet.
    let mut fixture = populated_fixture()?;
    let epoch_id = fixture
        .state
        .active_session
        .as_ref()
        .ok_or("no session")?
        .epoch_id;
    fixture.state.dedup.push(DedupRecord {
        message_id: MessageId::from_slice(&[0xEE; 16]).ok_or("bad test id")?,
        epoch_id,
        sequence: 4,
        queue_id: fixture.state.mailbox_queue_id,
        packet_digest: digest(b"phantom"),
        expires_at: NOW + 3_600,
        state: DedupState::Accepted,
    });
    fixture
        .state
        .dedup
        .sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));
    assert!(
        fixture.state.encode().is_err(),
        "uncovered current-epoch dedup accepted"
    );

    // Current-epoch dedup at or below the contiguous high water (the
    // genuine fixture already carries one inside the received set) ⇒
    // accept and round-trip.
    let mut fixture = populated_fixture()?;
    let epoch_id = fixture
        .state
        .active_session
        .as_ref()
        .ok_or("no session")?
        .epoch_id;
    fixture.state.dedup.push(DedupRecord {
        message_id: MessageId::from_slice(&[0x01; 16]).ok_or("bad test id")?,
        epoch_id,
        sequence: 1,
        queue_id: fixture.state.mailbox_queue_id,
        packet_digest: digest(b"contiguous"),
        expires_at: NOW + 3_600,
        state: DedupState::Acked,
    });
    fixture
        .state
        .dedup
        .sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;
    Ok(())
}

/// Finding 2: `RekeyRequired` dominates the budget mode — accepted at any
/// non-malformed outstanding count; more than 32 outstanding rejects in
/// every mode.
#[test]
fn rekey_required_dominates_budget_at_any_outstanding() -> Result<(), Box<dyn Error>> {
    // (last_assigned, high_water): outstanding 0, 24, 31, 32.
    for (last_assigned, high_water) in [(3, 3), (24, 0), (31, 0), (32, 0)] {
        let mut fixture = populated_fixture()?;
        set_water(
            &mut fixture,
            last_assigned,
            high_water,
            SessionMode::RekeyRequired,
        )?;
        let encoded = fixture.state.encode()?;
        ClientStateV1::decode(&encoded)?;
    }
    let mut fixture = populated_fixture()?;
    set_water(&mut fixture, 33, 0, SessionMode::RekeyRequired)?;
    assert!(fixture.state.encode().is_err());
    Ok(())
}

/// Finding 3: a duplicated one-time-key secret collapses the
/// `key_ids_by_key` index and must be rejected on both paths.
#[test]
fn duplicate_one_time_key_secret_rejected() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    let json = String::from_utf8(fixture.state.account_pickle.to_vec())?;
    // The fixture's account holds exactly one published one-time key:
    // `private_keys` is `{"0":[...32 bytes...]}`. Duplicate the exact
    // secret entry under the next key id, keeping the canonical order.
    let marker = "\"private_keys\":{";
    let entry_start = json.find(marker).ok_or("private_keys missing")? + marker.len();
    let entry_end = json[entry_start..]
        .find('}')
        .ok_or("unterminated private_keys")?;
    let entry_text = &json[entry_start..entry_start + entry_end];
    let duplicate = entry_text.replacen("\"0\"", "\"1\"", 1);
    let spliced = format!(
        "{}{},{}{}",
        &json[..entry_start],
        entry_text,
        duplicate,
        &json[entry_start + entry_end..]
    );
    fixture.state.account_pickle = Zeroizing::new(spliced.clone().into_bytes());
    // The splice stays canonical (typed re-serialization is byte-equal),
    // so only the duplicate-secret check can be rejecting.
    let typed: vodozemac::olm::AccountPickle = serde_json::from_slice(spliced.as_bytes())?;
    assert_eq!(
        serde_json::to_vec(&typed)?,
        spliced.as_bytes(),
        "splice broke canonical form"
    );
    assert!(
        fixture.state.encode().is_err(),
        "encode accepted duplicate secret"
    );

    // Decode path: splice the mutated pickle into the encoding of the
    // valid state.
    let valid = populated_fixture()?;
    let encoded = valid.state.encode()?;
    let bytes = splice_top(&encoded, 8, field_block(9, spliced.as_bytes())?)?;
    assert!(
        ClientStateV1::decode(&bytes).is_err(),
        "decode accepted duplicate secret"
    );
    Ok(())
}

/// Finding 3: an unpublished-map entry whose key id does not exist in
/// `private_keys` is an orphan and must be rejected.
#[test]
fn unpublished_otk_with_unknown_key_id_rejected() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    let json = String::from_utf8(fixture.state.account_pickle.to_vec())?;
    // The fixture marked its keys published, so `public_keys` is `{}`.
    let other = Account::new();
    let public_text = serde_json::to_string(&other.curve25519_key())?;
    let spliced = json.replacen(
        "\"public_keys\":{}",
        &format!("\"public_keys\":{{\"7\":{public_text}}}"),
        1,
    );
    assert_ne!(spliced, json, "public_keys was not empty as expected");
    let typed: vodozemac::olm::AccountPickle = serde_json::from_slice(spliced.as_bytes())?;
    assert_eq!(
        serde_json::to_vec(&typed)?,
        spliced.as_bytes(),
        "splice broke canonical form"
    );
    fixture.state.account_pickle = Zeroizing::new(spliced.into_bytes());
    assert!(fixture.state.encode().is_err());
    Ok(())
}

/// Finding 3: an unpublished entry whose stored public key does not match
/// the private key's derived public is rejected.
#[test]
fn unpublished_otk_public_mismatch_rejected() -> Result<(), Box<dyn Error>> {
    let mut fixture = minimal_fixture()?;
    // An account with one UNPUBLISHED one-time key.
    let mut account = Account::new();
    let _created = account.generate_one_time_keys(1);
    fixture.state.own_ed25519_identity = account.ed25519_key();
    fixture.state.own_curve_identity = account.curve25519_key();
    let json = String::from_utf8(serde_json::to_vec(&account.pickle())?)?;

    // Swap the unpublished map's stored public for another key's.
    let marker = "\"public_keys\":{\"0\":";
    let start = json.find(marker).ok_or("unpublished entry missing")? + marker.len();
    let end = json[start..].find(']').ok_or("unterminated entry")? + start;
    let impostor_text = serde_json::to_string(&Account::new().curve25519_key())?;
    let spliced = format!("{}{}{}", &json[..start], impostor_text, &json[end + 1..]);
    let typed: vodozemac::olm::AccountPickle = serde_json::from_slice(spliced.as_bytes())?;
    assert_eq!(
        serde_json::to_vec(&typed)?,
        spliced.as_bytes(),
        "splice broke canonical form"
    );
    fixture.state.account_pickle = Zeroizing::new(spliced.into_bytes());
    assert!(fixture.state.encode().is_err());
    Ok(())
}

/// Finding 3, positive: a genuine account with a mixed published and
/// unpublished one-time-key set validates and round-trips.
#[test]
fn mixed_published_and_unpublished_otks_accepted() -> Result<(), Box<dyn Error>> {
    let mut fixture = minimal_fixture()?;
    let mut account = Account::new();
    let _published = account.generate_one_time_keys(1);
    account.mark_keys_as_published();
    let _unpublished = account.generate_one_time_keys(1);
    fixture.state.own_ed25519_identity = account.ed25519_key();
    fixture.state.own_curve_identity = account.curve25519_key();
    fixture.state.account_pickle = Zeroizing::new(serde_json::to_vec(&account.pickle())?);
    let encoded = fixture.state.encode()?;
    let decoded = ClientStateV1::decode(&encoded)?;
    assert_eq!(&encoded[..], &decoded.encode()?[..]);
    Ok(())
}

// --- review v4 remediation tests -------------------------------------------

/// Splice `one_time_keys.next_key_id` in the canonical account pickle
/// JSON from one exact value to another.
fn splice_next_key_id(json: &str, from: u64, to: u64) -> Result<String, Box<dyn Error>> {
    let needle = format!("\"next_key_id\":{from}");
    if !json.contains(&needle) {
        return Err(format!("{needle} not in account pickle").into());
    }
    Ok(json.replacen(&needle, &format!("\"next_key_id\":{to}"), 1))
}

/// Assert the spliced pickle is still canonical (typed re-serialization
/// is byte-equal), so only the semantic counter check can reject it.
fn assert_canonical_pickle(json: &str) -> Result<(), Box<dyn Error>> {
    let typed: vodozemac::olm::AccountPickle = serde_json::from_slice(json.as_bytes())?;
    assert_eq!(
        serde_json::to_vec(&typed)?,
        json.as_bytes(),
        "splice broke canonical form"
    );
    Ok(())
}

/// Review v4: `next_key_id` at or below a retained key id must reject,
/// even though the pickle stays canonical.
#[test]
fn next_key_id_collision_with_retained_key_rejected() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    // The fixture's account retains one published one-time key under id 0
    // with the counter at 1; force the counter onto the retained id.
    let json = String::from_utf8(fixture.state.account_pickle.to_vec())?;
    let colliding = splice_next_key_id(&json, 1, 0)?;
    assert_canonical_pickle(&colliding)?;
    fixture.state.account_pickle = Zeroizing::new(colliding.clone().into_bytes());
    assert!(
        fixture.state.encode().is_err(),
        "encode accepted the collision"
    );

    // Decode path: splice the hostile pickle into the valid encoding.
    let valid = populated_fixture()?;
    let encoded = valid.state.encode()?;
    let bytes = splice_top(&encoded, 8, field_block(9, colliding.as_bytes())?)?;
    assert!(
        ClientStateV1::decode(&bytes).is_err(),
        "decode accepted the collision"
    );
    Ok(())
}

/// Review v4 boundary: counter == max retained id rejects; max + 1 (and
/// larger, gaps are legitimate) accepts; an empty store accepts any
/// counter.
#[test]
fn next_key_id_boundary_rules() -> Result<(), Box<dyn Error>> {
    // max + 1: the unmodified populated fixture (retained id 0, counter 1).
    let fixture = populated_fixture()?;
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;

    // A gap (counter 2 over retained id 0) also accepts.
    let mut fixture = populated_fixture()?;
    let json = String::from_utf8(fixture.state.account_pickle.to_vec())?;
    let gapped = splice_next_key_id(&json, 1, 2)?;
    assert_canonical_pickle(&gapped)?;
    fixture.state.account_pickle = Zeroizing::new(gapped.into_bytes());
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;

    // Empty store: counter 0 accepts (minimal fixture has no one-time
    // keys), and a larger counter with an empty store accepts too.
    let fixture = minimal_fixture()?;
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;
    let mut fixture = minimal_fixture()?;
    let json = String::from_utf8(fixture.state.account_pickle.to_vec())?;
    let ahead = splice_next_key_id(&json, 0, 42)?;
    assert_canonical_pickle(&ahead)?;
    fixture.state.account_pickle = Zeroizing::new(ahead.into_bytes());
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;
    Ok(())
}

/// Review v4: the accepted max-plus-one pickle cannot eat a retained key
/// on the next generation — verified through a real `Account`.
#[test]
fn accepted_boundary_pickle_generates_without_key_loss() -> Result<(), Box<dyn Error>> {
    let fixture = populated_fixture()?;
    let retained = fixture
        .state
        .pending_prekey
        .as_ref()
        .ok_or("no pending prekey")?
        .one_time_key;
    let pickle: vodozemac::olm::AccountPickle =
        serde_json::from_slice(&fixture.state.account_pickle)?;
    let mut account = Account::from_pickle(pickle);
    assert!(account.contains_one_time_key(retained));

    let created = account.generate_one_time_keys(1).created;
    let new_key = *created.first().ok_or("no key generated")?;
    assert!(new_key != retained, "generation reused the retained key");
    assert!(
        account.contains_one_time_key(retained),
        "retained key was replaced"
    );
    assert!(account.contains_one_time_key(new_key));
    Ok(())
}

// --- review v5 remediation tests -------------------------------------------

/// Review v5 finding 1: a counter near the `wrapping_add` wrap is hostile
/// and rejects; exactly `u64::MAX - 1_000_000_000` leaves the full
/// headroom and accepts.
#[test]
fn next_key_id_wrap_headroom_enforced() -> Result<(), Box<dyn Error>> {
    for hostile in [u64::MAX, u64::MAX - 5, u64::MAX - 999_999_999] {
        let mut fixture = populated_fixture()?;
        let json = String::from_utf8(fixture.state.account_pickle.to_vec())?;
        let spliced = splice_next_key_id(&json, 1, hostile)?;
        assert_canonical_pickle(&spliced)?;
        fixture.state.account_pickle = Zeroizing::new(spliced.into_bytes());
        assert!(
            fixture.state.encode().is_err(),
            "next_key_id {hostile} accepted"
        );
    }
    // Exactly at the boundary the full headroom remains: accepted.
    let mut fixture = populated_fixture()?;
    let json = String::from_utf8(fixture.state.account_pickle.to_vec())?;
    let boundary = splice_next_key_id(&json, 1, u64::MAX - 1_000_000_000)?;
    assert_canonical_pickle(&boundary)?;
    fixture.state.account_pickle = Zeroizing::new(boundary.into_bytes());
    let encoded = fixture.state.encode()?;
    ClientStateV1::decode(&encoded)?;
    Ok(())
}

/// Build a minimal state with explicit mailbox keypairs and a matching
/// manage-signed registration, for the capability-collapse fixtures.
fn state_with_raw_keypairs(
    send: &vodozemac::Ed25519Keypair,
    receive: &vodozemac::Ed25519Keypair,
    manage: &vodozemac::Ed25519Keypair,
) -> Result<ClientStateV1, Box<dyn Error>> {
    state_with_key_material(&Account::new(), send, receive, manage)
}

/// Same, with an explicit account (identity-alias fixtures need the
/// account's own signing keypair to coincide with the stored identity).
fn state_with_key_material(
    account: &Account,
    send: &vodozemac::Ed25519Keypair,
    receive: &vodozemac::Ed25519Keypair,
    manage: &vodozemac::Ed25519Keypair,
) -> Result<ClientStateV1, Box<dyn Error>> {
    let queue_id = QueueId::random();
    let mut registration = crate::MailboxRegistration {
        queue_id,
        send_key: send.public_key(),
        receive_key: receive.public_key(),
        manage_key: manage.public_key(),
        nonce: crate::Nonce::random(),
        valid_until: NOW + 3_600,
        signature: manage.sign(b""),
    };
    registration.signature = manage.sign(&registration.signing_bytes());
    Ok(ClientStateV1 {
        profile_id: [0x33; 16],
        key_ref: [0x44; 16],
        generation: 1,
        conversation_id: ConversationId::random(),
        account_pickle: Zeroizing::new(serde_json::to_vec(&account.pickle())?),
        own_ed25519_identity: account.ed25519_key(),
        own_curve_identity: account.curve25519_key(),
        mailbox_queue_id: queue_id,
        send_keypair_json: Zeroizing::new(serde_json::to_vec(send)?),
        receive_keypair_json: Zeroizing::new(serde_json::to_vec(receive)?),
        manage_keypair_json: Zeroizing::new(serde_json::to_vec(manage)?),
        registration: RegistrationRecord {
            queue_id: registration.queue_id,
            send_key: registration.send_key,
            receive_key: registration.receive_key,
            manage_key: registration.manage_key,
            nonce: registration.nonce,
            valid_until: registration.valid_until,
            signature: registration.signature,
        },
        pending_prekey: None,
        peer_binding: None,
        active_session: None,
        inbound: Vec::new(),
        sends: Vec::new(),
        acks: Vec::new(),
        dedup: Vec::new(),
    })
}

/// Review v5 finding 3: the three mailbox capability public keys must be
/// distinct and correspond to the registration intent.
#[test]
fn mailbox_capability_collapse_rejected() -> Result<(), Box<dyn Error>> {
    // Genuine state (three distinct keypairs) is accepted.
    let genuine = state_with_raw_keypairs(
        &vodozemac::Ed25519Keypair::new(),
        &vodozemac::Ed25519Keypair::new(),
        &vodozemac::Ed25519Keypair::new(),
    )?;
    let encoded = genuine.encode()?;
    ClientStateV1::decode(&encoded)?;

    // One keypair serving all three capabilities.
    let shared = vodozemac::Ed25519Keypair::new();
    let collapsed = state_with_raw_keypairs(&shared, &shared, &shared)?;
    assert!(collapsed.encode().is_err(), "all-same-key mailbox accepted");

    // Two capabilities sharing a keypair.
    let shared = vodozemac::Ed25519Keypair::new();
    let collapsed = state_with_raw_keypairs(&shared, &shared, &vodozemac::Ed25519Keypair::new())?;
    assert!(collapsed.encode().is_err(), "two-same-key mailbox accepted");

    // Permuted slots: the receive slot holds the send keypair while the
    // registration keeps the genuine correspondence.
    let send = vodozemac::Ed25519Keypair::new();
    let receive = vodozemac::Ed25519Keypair::new();
    let manage = vodozemac::Ed25519Keypair::new();
    let mut permuted = state_with_raw_keypairs(&send, &receive, &manage)?;
    permuted.send_keypair_json = Zeroizing::new(serde_json::to_vec(&receive)?);
    permuted.receive_keypair_json = Zeroizing::new(serde_json::to_vec(&send)?);
    assert!(permuted.encode().is_err(), "permuted keypairs accepted");
    Ok(())
}

// --- review v6 remediation tests -------------------------------------------

/// Extract the canonical `signing_key` (an `Ed25519Keypair` JSON
/// document) from an account's canonical pickle.
fn account_signing_keypair(account: &Account) -> Result<vodozemac::Ed25519Keypair, Box<dyn Error>> {
    let pickle = serde_json::to_vec(&account.pickle())?;
    let value: serde_json::Value = serde_json::from_slice(&pickle)?;
    let signing_key = value.get("signing_key").ok_or("signing_key missing")?;
    Ok(serde_json::from_slice(&serde_json::to_vec(signing_key)?)?)
}

/// Review v6 blocker 1, the reviewer's reproduction: the account's own
/// signing keypair reused as the mailbox send capability must reject on
/// both paths.
#[test]
fn identity_key_must_not_alias_mailbox_send_capability() -> Result<(), Box<dyn Error>> {
    let fixture = minimal_fixture()?;
    let account = &fixture.our_account;
    let identity_keypair = account_signing_keypair(account)?;
    let aliased = state_with_key_material(
        account,
        &identity_keypair,
        &vodozemac::Ed25519Keypair::new(),
        &vodozemac::Ed25519Keypair::new(),
    )?;
    assert!(
        aliased.encode().is_err(),
        "encode accepted an identity-aliased send keypair"
    );

    // Decode path: splice the aliased mailbox (field 11) and registration
    // (field 12) into the genuine state's encoding.
    let encoded = fixture.state.encode()?;
    let mailbox = mailbox_value(
        aliased.mailbox_queue_id,
        &aliased.send_keypair_json,
        &aliased.receive_keypair_json,
        &aliased.manage_keypair_json,
    )?;
    let bytes = splice_top(&encoded, 10, field_block(11, &mailbox)?)?;
    let registration = aliased.registration.encode()?;
    let bytes = splice_top(&bytes, 11, field_block(12, &registration)?)?;
    assert!(
        ClientStateV1::decode(&bytes).is_err(),
        "decode accepted an identity-aliased send keypair"
    );
    Ok(())
}

/// Review v6 blocker 1: receive and manage must not alias the identity
/// either.
#[test]
fn identity_key_must_not_alias_receive_or_manage() -> Result<(), Box<dyn Error>> {
    for slot in ["receive", "manage"] {
        let fixture = minimal_fixture()?;
        let account = &fixture.our_account;
        let identity_keypair = account_signing_keypair(account)?;
        let fresh_a = vodozemac::Ed25519Keypair::new();
        let fresh_b = vodozemac::Ed25519Keypair::new();
        let aliased = if slot == "receive" {
            state_with_key_material(account, &fresh_a, &identity_keypair, &fresh_b)?
        } else {
            state_with_key_material(account, &fresh_a, &fresh_b, &identity_keypair)?
        };
        assert!(
            aliased.encode().is_err(),
            "identity-aliased {slot} keypair accepted"
        );
    }
    Ok(())
}

/// Review v6 blocker 1: the peer's send capability must differ from the
/// peer's pinned signing identity.
#[test]
fn peer_send_capability_must_not_alias_peer_identity() -> Result<(), Box<dyn Error>> {
    let mut fixture = populated_fixture()?;
    let identity_keypair = account_signing_keypair(&fixture.peer_account)?;
    {
        let binding = fixture.state.peer_binding.as_mut().ok_or("no binding")?;
        binding.send_keypair_json = Zeroizing::new(serde_json::to_vec(&identity_keypair)?);
        binding.send_public_key = fixture.peer_account.ed25519_key();
    }
    assert!(
        fixture.state.encode().is_err(),
        "aliased peer capability encoded"
    );

    // Decode path: splice the aliased peer binding (field 14) into the
    // genuine encoding.
    let valid = populated_fixture()?;
    let encoded = valid.state.encode()?;
    let binding_bytes = fixture
        .state
        .peer_binding
        .as_ref()
        .ok_or("no binding")?
        .encode()?;
    let bytes = splice_top(&encoded, 13, field_block(14, &binding_bytes)?)?;
    assert!(
        ClientStateV1::decode(&bytes).is_err(),
        "aliased peer capability decoded"
    );
    Ok(())
}

/// Review v6 blocker 2: a matching dedup record must agree with the
/// inbound record on expiry.
#[test]
fn dedup_expiry_must_match_inbound_record() -> Result<(), Box<dyn Error>> {
    // Encode path.
    let mut fixture = populated_fixture()?;
    let inbound_id = fixture.state.inbound[0].message_id;
    let dedup = fixture
        .state
        .dedup
        .iter_mut()
        .find(|record| record.message_id == inbound_id)
        .ok_or("matching dedup missing")?;
    dedup.expires_at = 0;
    assert!(
        fixture.state.encode().is_err(),
        "encode accepted expiry mismatch"
    );

    // Decode path: encode a genuine state, then splice in the dedup array
    // with only the matching record's expiry zeroed.
    let mut fixture = populated_fixture()?;
    let inbound_id = fixture.state.inbound[0].message_id;
    let encoded = fixture.state.encode()?;
    let dedup = fixture
        .state
        .dedup
        .iter_mut()
        .find(|record| record.message_id == inbound_id)
        .ok_or("matching dedup missing")?;
    dedup.expires_at = 0;
    let array = records::encode_record_array(
        &fixture.state.dedup,
        MAX_DEDUP,
        records::DedupRecord::encode,
    )?;
    let bytes = splice_top(&encoded, 18, field_block(19, &array)?)?;
    assert!(
        ClientStateV1::decode(&bytes).is_err(),
        "decode accepted expiry mismatch"
    );
    Ok(())
}
