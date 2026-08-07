//! In-crate façade tests: payload-generation tracking assertions (they
//! read private façade fields) and Sol's finding-2 reproductions, which
//! need a forged-but-authentic envelope. The forge is possible because the
//! test protector's wrap is a known XOR mask; the AAD construction is a
//! replica of `persistence/envelope.rs` (private there).

use std::error::Error;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::{PersistentClient, RegistrationOutcome};
use crate::persistence::{KeyStatus, ProfileBinding, ProtectionLevel, StateKeyProtector};
use crate::{LabError, PrivateStoreDir, StoreKind};

const NOW: u64 = 1_800_000_000;
const DEK_BYTES: usize = 32;

/// The XOR test protector, mirrored from `persistence/sqlite.rs` tests.
struct TestProtector {
    binding: ProfileBinding,
    mask: [u8; DEK_BYTES],
}

fn protector() -> TestProtector {
    TestProtector {
        binding: ProfileBinding::new([0x42; 16], [0x24; 16]),
        mask: [0x24; DEK_BYTES],
    }
}

impl StateKeyProtector for TestProtector {
    fn expected_binding(&self) -> crate::Result<ProfileBinding> {
        Ok(self.binding)
    }

    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::SoftwareBacked
    }

    fn wrap_dek(&self, dek: &Zeroizing<[u8; DEK_BYTES]>) -> crate::Result<Vec<u8>> {
        let mut wrapped = b"state-wrap/v1".to_vec();
        wrapped.extend_from_slice(self.binding.profile_id());
        wrapped.extend_from_slice(self.binding.key_ref());
        wrapped.extend(dek.iter().zip(self.mask).map(|(value, mask)| value ^ mask));
        Ok(wrapped)
    }

    fn unwrap_dek(
        &self,
        wrapped_dek: &[u8],
        output: &mut Zeroizing<[u8; DEK_BYTES]>,
    ) -> crate::Result<()> {
        const PREFIX: &[u8] = b"state-wrap/v1";
        let expected = PREFIX.len() + 16 + 16 + DEK_BYTES;
        if wrapped_dek.len() != expected
            || &wrapped_dek[..PREFIX.len()] != PREFIX
            || &wrapped_dek[PREFIX.len()..PREFIX.len() + 16] != self.binding.profile_id()
            || &wrapped_dek[PREFIX.len() + 16..PREFIX.len() + 32] != self.binding.key_ref()
        {
            return Err(LabError::Storage);
        }
        for (target, (value, mask)) in output.iter_mut().zip(
            wrapped_dek[PREFIX.len() + 32..]
                .iter()
                .zip(self.mask.iter()),
        ) {
            *target = value ^ mask;
        }
        Ok(())
    }

    /// Static test protector: lifecycle operations are unsupported and
    /// fail closed; the fixed binding is always present.
    fn provision_key(&self, _binding: ProfileBinding) -> crate::Result<()> {
        Err(LabError::Storage)
    }

    fn key_status(&self, _binding: ProfileBinding) -> crate::Result<KeyStatus> {
        Ok(KeyStatus::Present)
    }

    fn select_binding(&self, binding: ProfileBinding) -> crate::Result<()> {
        if binding != self.binding {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    fn delete_key(&self, _binding: ProfileBinding) -> crate::Result<()> {
        Err(LabError::Storage)
    }
}

fn store_path(temp: &TempDir) -> PathBuf {
    temp.path().join("client")
}

fn create_client(
    temp: &TempDir,
) -> std::result::Result<PersistentClient<TestProtector>, Box<dyn Error>> {
    let dir = PrivateStoreDir::create(&store_path(temp), StoreKind::ClientState)?;
    Ok(PersistentClient::create(dir, protector(), NOW)?)
}

fn open_client(
    temp: &TempDir,
) -> std::result::Result<PersistentClient<TestProtector>, Box<dyn Error>> {
    let dir = crate::private_store_dir::open_with_release_grace(
        &store_path(temp),
        StoreKind::ClientState,
    )?;
    Ok(PersistentClient::open(dir, protector())?)
}

/// Replica of the envelope AAD in `persistence/envelope.rs`.
fn envelope_aad(binding: &ProfileBinding, generation: u64, wrapped_dek: &[u8]) -> Vec<u8> {
    let wrapped_dek_hash: [u8; 32] = Sha256::digest(wrapped_dek).into();
    let mut encoded = Vec::new();
    for part in [
        b"secure-messenger-lab/client-state".as_slice(),
        &1_i64.to_be_bytes(),
        &1_i64.to_be_bytes(),
        binding.profile_id().as_slice(),
        &generation.to_be_bytes(),
        binding.key_ref().as_slice(),
        &wrapped_dek_hash,
        crate::PROTOCOL_DOMAIN,
        b"0.10.0",
        &1_i64.to_be_bytes(),
    ] {
        encoded.extend_from_slice(&u32::try_from(part.len()).unwrap_or(0).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    encoded
}

/// Decrypt the stored payload, mutate it, re-encrypt authentically (the
/// test protector's mask makes the DEK recoverable), and write it back.
/// The outer envelope stays valid for the row's stored generation.
fn rewrite_payload(
    database: &Path,
    mutate: impl FnOnce(&mut [u8]),
) -> std::result::Result<(), Box<dyn Error>> {
    let connection = Connection::open(database)?;
    let (generation, wrapped_dek, nonce, ciphertext): (i64, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT generation, wrapped_dek, nonce, ciphertext FROM client_state WHERE slot = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let generation = u64::try_from(generation)?;
    let protector = protector();
    let mut dek = Zeroizing::new([0_u8; DEK_BYTES]);
    protector.unwrap_dek(&wrapped_dek, &mut dek)?;
    let aad = envelope_aad(&protector.binding, generation, &wrapped_dek);
    let cipher = XChaCha20Poly1305::new_from_slice(&*dek).map_err(|_| LabError::Storage)?;
    let nonce = XNonce::from_slice(&nonce);
    let mut payload = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext[..],
                aad: &aad,
            },
        )
        .map_err(|_| "envelope decrypt failed")?;
    mutate(&mut payload);
    let forged = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &payload[..],
                aad: &aad,
            },
        )
        .map_err(|_| "envelope encrypt failed")?;
    connection.execute(
        "UPDATE client_state SET ciphertext = ?1 WHERE slot = 1",
        params![forged],
    )?;
    Ok(())
}

// Top-level payload offsets (magic 8 + type 2 + count 2, then
// field 1: 6+2, field 2 profile_id: 6+16, field 3 key_ref: 6+16,
// field 4 generation: 6+8).
const PROFILE_ID_VALUE: usize = 26;
const KEY_REF_VALUE: usize = 48;
const GENERATION_VALUE: usize = 70;

#[test]
fn payload_generation_tracks_store_generation() -> std::result::Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    assert_eq!(client.state.generation, 1);
    assert_eq!(client.store.generation()?, 1);

    client.prekey_action(NOW + 300)?;
    assert_eq!(client.state.generation, client.store.generation()?);
    assert_eq!(client.state.generation, 2);

    let action = client.registration_action(NOW + 60, NOW)?;
    client.record_registration_result(&action, RegistrationOutcome::Confirmed)?;
    assert_eq!(client.state.generation, client.store.generation()?);
    assert_eq!(client.state.generation, 4);

    drop(client);
    let client = open_client(&temp)?;
    assert_eq!(client.state.generation, 4);
    assert_eq!(client.state.generation, client.store.generation()?);
    Ok(())
}

#[test]
fn rewritten_payload_roundtrip_sanity() -> std::result::Result<(), Box<dyn Error>> {
    // The forge pipeline is authentic: a no-op rewrite leaves a perfectly
    // openable store, so the mismatch tests below reject because of the
    // finding-2 comparisons, not envelope damage.
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    client.prekey_action(NOW + 300)?;
    drop(client);
    rewrite_payload(&store_path(&temp).join("client-state.sqlite3"), |_| {})?;
    let client = open_client(&temp)?;
    assert_eq!(client.state.generation, 2);
    Ok(())
}

#[test]
fn outer_generation_two_with_payload_generation_one_rejected()
-> std::result::Result<(), Box<dyn Error>> {
    // Sol's repro: outer generation 2, payload generation 1.
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    client.prekey_action(NOW + 300)?;
    drop(client);
    rewrite_payload(&store_path(&temp).join("client-state.sqlite3"), |payload| {
        payload[GENERATION_VALUE..GENERATION_VALUE + 8].copy_from_slice(&1_u64.to_be_bytes());
    })?;
    assert!(open_client(&temp).is_err());
    Ok(())
}

#[test]
fn payload_profile_or_key_ref_mismatch_rejected_on_reopen()
-> std::result::Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let client = create_client(&temp)?;
    drop(client);
    rewrite_payload(&store_path(&temp).join("client-state.sqlite3"), |payload| {
        payload[PROFILE_ID_VALUE] ^= 0x01;
    })?;
    assert!(open_client(&temp).is_err());

    let temp = TempDir::new()?;
    let client = create_client(&temp)?;
    drop(client);
    rewrite_payload(&store_path(&temp).join("client-state.sqlite3"), |payload| {
        payload[KEY_REF_VALUE] ^= 0x01;
    })?;
    assert!(open_client(&temp).is_err());
    Ok(())
}

// --- D2a: mode-block fixtures ------------------------------------------------

use vodozemac::Ed25519Keypair;
use vodozemac::olm::Account;

use super::RedactedContactOffer;
use crate::capability::canonical;
use crate::ids::QueueId;
use crate::state::SessionMode;

fn in_crate_prekey_signing_bytes(
    signing_identity: &vodozemac::Ed25519PublicKey,
    curve_identity: &vodozemac::Curve25519PublicKey,
    one_time_key: &vodozemac::Curve25519PublicKey,
    valid_until: u64,
) -> Vec<u8> {
    canonical(
        b"peer-prekey",
        &[
            signing_identity.as_bytes(),
            curve_identity.as_bytes(),
            one_time_key.as_bytes(),
            &valid_until.to_be_bytes(),
        ],
    )
}

/// Commit a genuine peer contact and establish the outbound session.
fn establish_session(
    client: &mut PersistentClient<TestProtector>,
) -> std::result::Result<(), Box<dyn Error>> {
    let mut peer_account = Account::new();
    let one_time_key = *peer_account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("no peer one-time key")?;
    peer_account.mark_keys_as_published();
    let mut offer = RedactedContactOffer {
        signing_identity: peer_account.ed25519_key(),
        curve_identity: peer_account.curve25519_key(),
        one_time_key,
        valid_until: NOW + 300,
        signature: peer_account.sign(b""),
    };
    offer.signature = peer_account.sign(in_crate_prekey_signing_bytes(
        &offer.signing_identity,
        &offer.curve_identity,
        &offer.one_time_key,
        NOW + 300,
    ));
    let keypair = Ed25519Keypair::new();
    client.commit_verified_contact(
        offer.signing_identity,
        offer,
        crate::ConversationId::random(),
        QueueId::random(),
        Zeroizing::new(serde_json::to_vec(&keypair)?),
        NOW,
    )?;
    client.establish_outbound_session(NOW)?;
    Ok(())
}

#[test]
fn receipt_locked_blocks_all_staging() -> std::result::Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    establish_session(&mut client)?;
    // Drive the in-memory record to the ReceiptLocked corner (outstanding
    // 32). Staging is rejected before anything commits, so the store is
    // untouched by this fixture.
    let active = client
        .state
        .active_session
        .as_mut()
        .ok_or("no active session")?;
    active.last_assigned_send_seq = 32;
    active.mode = SessionMode::ReceiptLocked;
    assert!(client.stage_send("blocked", NOW, NOW + 3_600, NOW).is_err());
    Ok(())
}

#[test]
fn rekey_required_blocks_all_staging() -> std::result::Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    establish_session(&mut client)?;
    client
        .state
        .active_session
        .as_mut()
        .ok_or("no active session")?
        .mode = SessionMode::RekeyRequired;
    assert!(client.stage_send("blocked", NOW, NOW + 3_600, NOW).is_err());
    // RekeyRequired is never recomputed away: even at zero outstanding it
    // stays and keeps blocking.
    client
        .state
        .active_session
        .as_mut()
        .ok_or("no active session")?
        .last_assigned_send_seq = 0;
    assert!(
        client
            .stage_send("still blocked", NOW, NOW + 3_600, NOW)
            .is_err()
    );
    Ok(())
}

// --- D2b: inbound path, receipts, ACKs --------------------------------------

use vodozemac::olm::SessionConfig;

use super::{AcceptOutcome, AckOutcomeView, SendOutcome};
use crate::payload;
use crate::state::DedupState;
use crate::{ConversationId, EncryptedPacket, MessageId, Relay};

/// Share a conversation ID and exchange verified contacts both ways, then
/// establish B's outbound session to A.
fn connect(
    a: &mut PersistentClient<TestProtector>,
    b: &mut PersistentClient<TestProtector>,
    conversation_id: ConversationId,
) -> std::result::Result<(), Box<dyn Error>> {
    let offer_a = a.prekey_action(NOW + 300)?;
    let offer_b = b.prekey_action(NOW + 300)?;
    let identity_a = a.public_identity()?;
    let identity_b = b.public_identity()?;
    let queue_a = a.state.mailbox_queue_id;
    let queue_b = b.state.mailbox_queue_id;
    b.commit_verified_contact(
        identity_a.ed25519,
        offer_a,
        conversation_id,
        queue_a,
        Zeroizing::new(serde_json::to_vec(&a.keypairs.send)?),
        NOW,
    )?;
    a.commit_verified_contact(
        identity_b.ed25519,
        offer_b,
        conversation_id,
        queue_b,
        Zeroizing::new(serde_json::to_vec(&b.keypairs.send)?),
        NOW,
    )?;
    b.establish_outbound_session(NOW)?;
    Ok(())
}

/// Register both clients on the in-memory relay and confirm.
fn register_on_relay(
    client: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
) -> std::result::Result<(), Box<dyn Error>> {
    let action = client.registration_action(NOW + 60, NOW)?;
    relay.register(&action.request, NOW)?;
    client.record_registration_result(&action, RegistrationOutcome::Confirmed)?;
    Ok(())
}

/// Stage an application body, requiring the `Staged` outcome (review D2b
/// v5 P1-3: sites that want the action assert no receipt flush happened
/// in its place).
fn stage_app(
    client: &mut PersistentClient<TestProtector>,
    body: &str,
    sent_at: u64,
    expires_at: u64,
    now: u64,
) -> std::result::Result<super::DurableAction<crate::capability::SendRequest>, Box<dyn Error>> {
    match client.stage_send(body, sent_at, expires_at, now)? {
        super::StageSendOutcome::Staged(action) => Ok(action),
        super::StageSendOutcome::ReceiptFlushedRetry => {
            Err("stage_send flushed a receipt instead of staging".into())
        }
    }
}

/// Accept one fixture message by mailbox index and consume it (review
/// D2b v5 debt model: receipt debt comes only from CONSUMED application
/// records). Interleaving accept/consume per message stages one receipt
/// per consumed water, the v5 receipt fixtures' new shape.
fn accept_and_consume(
    a: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    index: usize,
    body: &str,
) -> std::result::Result<(), Box<dyn Error>> {
    let outcomes = deliver(a, relay, &[index])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let inbound = a.pending_inbound()?;
    let message_id = inbound
        .iter()
        .find(|view| view.body == body)
        .ok_or("message missing")?
        .message_id;
    a.consume_inbound(message_id, NOW + 300, NOW)?;
    Ok(())
}

/// B stages `count` application sends to A's mailbox through the real
/// relay, confirming each as stored.
fn stage_to_relay(
    b: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    bodies: &[&str],
) -> std::result::Result<(), Box<dyn Error>> {
    for body in bodies {
        let action = stage_app(b, body, NOW, NOW + 3_600, NOW)?;
        relay.enqueue(&action.request, NOW)?;
        b.record_send_result(&action, SendOutcome::Stored)?;
    }
    Ok(())
}

/// Fetch A's mailbox through the real relay and accept the envelopes in
/// the given order, returning per-envelope results (Err entries keep
/// going so out-of-order and duplicate cases can assert per envelope).
fn deliver(
    a: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    order: &[usize],
) -> std::result::Result<Vec<std::result::Result<AcceptOutcome, LabError>>, Box<dyn Error>> {
    let fetch = a.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let mut outcomes = Vec::new();
    for &index in order {
        let envelope = envelopes.get(index).ok_or("missing envelope")?;
        outcomes.push(a.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            NOW,
        ));
    }
    Ok(outcomes)
}

fn active_mode(
    client: &PersistentClient<TestProtector>,
) -> std::result::Result<SessionMode, Box<dyn Error>> {
    Ok(client
        .state
        .active_session
        .as_ref()
        .ok_or("no active session")?
        .mode)
}

/// The durable delivered-receipt marker (codec field 19).
fn delivered_marker(
    client: &PersistentClient<TestProtector>,
) -> std::result::Result<u64, Box<dyn Error>> {
    Ok(client
        .state
        .active_session
        .as_ref()
        .ok_or("no active session")?
        .last_delivered_receipt_high_water)
}

/// Two registered, contact-bound clients on an in-memory relay with B's
/// outbound session to A established, plus four staged-and-stored
/// application messages from B.
type ConversationFixture = (
    TempDir,
    TempDir,
    PersistentClient<TestProtector>,
    PersistentClient<TestProtector>,
    Relay,
);

fn conversation_fixture() -> std::result::Result<ConversationFixture, Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;
    stage_to_relay(&mut b, &mut relay, &["m1", "m2", "m3", "m4"])?;
    Ok((a_dir, b_dir, a, b, relay))
}

#[test]
fn two_client_conversation_over_real_relay() -> std::result::Result<(), Box<dyn Error>> {
    let (a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;

    // A accepts 1, then 3, then 4, then 2 (out-of-order), then a
    // duplicate of 2.
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(matches!(
        outcomes.first(),
        Some(Ok(AcceptOutcome::Application(_)))
    ));
    // Crash/reopen mid-spine: only committed state survives.
    drop(a);
    let mut a = open_client(&a_dir)?;
    let outcomes = deliver(&mut a, &mut relay, &[2, 3])?;
    assert!(
        outcomes.iter().all(Result::is_ok),
        "out-of-order accepts failed: {outcomes:?}"
    );
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.highest_contiguous_received_seq, 1);
        assert_eq!(active.received_above_high_water, vec![3, 4]);
    }
    let outcomes = deliver(&mut a, &mut relay, &[1])?;
    assert!(matches!(outcomes.first(), Some(Ok(_))));
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.highest_contiguous_received_seq, 4);
        assert!(active.received_above_high_water.is_empty());
    }
    // Duplicate envelope: rejected, no ratchet touch.
    let outcomes = deliver(&mut a, &mut relay, &[1])?;
    assert!(matches!(
        outcomes.first(),
        Some(Err(LabError::DuplicateMessage))
    ));

    // Inbound views carry the bodies in acceptance order.
    let inbound = a.pending_inbound()?;
    assert_eq!(inbound.len(), 4);
    let mut bodies: Vec<&str> = inbound.iter().map(|view| view.body.as_str()).collect();
    bodies.sort_unstable();
    assert_eq!(bodies, ["m1", "m2", "m3", "m4"]);
    Ok(())
}

#[test]
fn ack_and_receipt_flow_over_real_relay() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;

    // Accept and consume each message in turn (v5 debt model: debt comes
    // from consumed applications only): four ACK intents and four owed
    // receipts, one per consumed water 1..=4.
    for (index, body) in ["m1", "m2", "m3", "m4"].iter().enumerate() {
        accept_and_consume(&mut a, &mut relay, index, body)?;
    }
    assert!(a.pending_inbound()?.is_empty());
    assert_eq!(a.state.acks.len(), 4);
    assert_eq!(
        a.pending_send_actions()?.len(),
        4,
        "one receipt per consume, high waters 1..=4"
    );

    // The ACK for m1 (sender sequence 1) flows through the real relay
    // and its result lands.
    let ack_actions = a.ack_actions(NOW)?;
    assert_eq!(ack_actions.len(), 4);
    let m1_intent = a
        .state
        .acks
        .iter()
        .find(|intent| intent.sequence == 1)
        .ok_or("no m1 intent")?
        .message_id;
    let ack_action = ack_actions
        .into_iter()
        .find(|action| action.request.message_id == m1_intent)
        .ok_or("no ack action for m1")?;
    relay.acknowledge(&ack_action.request, NOW)?;
    a.record_ack_result(&ack_action, AckOutcomeView::Deleted)?;
    assert_eq!(a.ack_actions(NOW)?.len(), 3);
    assert!(
        a.state
            .dedup
            .iter()
            .any(|record| record.message_id == ack_action.request.message_id
                && record.state == DedupState::Acked),
        "dedup record not Acked"
    );
    assert!(
        a.record_ack_result(&ack_action, AckOutcomeView::Deleted)
            .is_err(),
        "replayed ack result accepted"
    );

    // Deliver all four staged receipts to B through the relay IN
    // send-sequence order (review D2b v4: the normal case; this test
    // previously dodged the quiescence rule by delivering only the
    // newest receipt out of order). Each applies, B's high water walks
    // 1..=4 and the send budget recovers; none stages a counter-receipt,
    // and the Stored results walk A's delivered marker to 4.
    let mut receipt_actions = a.pending_send_actions()?;
    receipt_actions.sort_by_key(|action| {
        a.state
            .sends
            .iter()
            .find(|record| record.message_id == action.request.message_id)
            .map_or(u64::MAX, |record| record.sequence)
    });
    assert_eq!(receipt_actions.len(), 4);
    for action in &receipt_actions {
        relay.enqueue(&action.request, NOW)?;
        a.record_send_result(action, SendOutcome::Stored)?;
    }
    assert_eq!(delivered_marker(&a)?, 4);
    let fetch = b.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    assert_eq!(envelopes.len(), 4);
    for envelope in &envelopes {
        let outcome = b.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            NOW,
        )?;
        assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
        assert!(
            b.pending_send_actions()?.is_empty(),
            "an in-order receipt staged a counter-receipt"
        );
    }
    {
        let active = b.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.peer_contiguous_high_water, 4);
        assert_eq!(active.last_assigned_send_seq, 4);
        assert_eq!(active.highest_contiguous_received_seq, 4);
        // B consumed nothing, so B has no receipt debt (v5 model): no
        // counter-receipt ever staged, and B's delivered marker moves
        // only when B's OWN receipts deliver — never on an accept.
        assert_eq!(active.last_delivered_receipt_high_water, 0);
        assert_eq!(active.receipt_debt_up_to, 0);
    }

    // Re-accepting the newest receipt envelope rejects as a duplicate.
    let receipt_envelope = envelopes.last().ok_or("no receipt envelope")?;
    let outcome = b.accept_envelope(
        receipt_envelope.queue_id,
        receipt_envelope.message_id,
        receipt_envelope.packet.clone(),
        receipt_envelope.expires_at,
        receipt_envelope.sender_signature,
        NOW,
    );
    assert!(matches!(outcome, Err(LabError::DuplicateMessage)));
    Ok(())
}

#[test]
fn second_receipt_at_same_high_water_is_idempotent() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;

    // Consume m1 and m2 (v5 debt model: debt comes from consumed
    // application records only): one owed receipt each, for waters 1
    // and 2.
    accept_and_consume(&mut a, &mut relay, 0, "m1")?;
    accept_and_consume(&mut a, &mut relay, 1, "m2")?;
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].high_water, Some(1));
    assert_eq!(receipts[1].high_water, Some(2));
    let second_receipt_id = receipts[1].message_id;

    // Drive both to Stored in send-sequence order; the delivered marker
    // reaches 2 only now, on the Stored results.
    let mut actions = a.pending_send_actions()?;
    actions.sort_by_key(|action| {
        a.state
            .sends
            .iter()
            .find(|record| record.message_id == action.request.message_id)
            .map_or(u64::MAX, |record| record.sequence)
    });
    for action in &actions {
        relay.enqueue(&action.request, NOW)?;
        a.record_send_result(action, SendOutcome::Stored)?;
    }
    assert!(a.pending_send_actions()?.is_empty());
    assert_eq!(delivered_marker(&a)?, 2, "marker after drive");

    // Rewinding the delivered marker in-crate re-arms the owed rule: the
    // old hw-2 receipts are terminal (not in flight), so the next
    // mutator stages a DISTINCT receipt envelope reporting the same
    // water.
    a.state
        .active_session
        .as_mut()
        .ok_or("no session")?
        .last_delivered_receipt_high_water = 0;
    let trigger = stage_app(&mut a, "trigger", NOW, NOW + 3_600, NOW)?;
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1);
    let replacement = receipts.first().ok_or("no replacement receipt")?;
    assert_ne!(replacement.message_id, second_receipt_id);
    assert_eq!(replacement.high_water, Some(2));
    assert_eq!(replacement.sequence, 3);
    let replacement_action = a
        .pending_send_actions()?
        .into_iter()
        .find(|action| action.request.message_id == replacement.message_id)
        .ok_or("no replacement action")?;
    relay.enqueue(&replacement_action.request, NOW)?;
    relay.enqueue(&trigger.request, NOW)?;
    a.record_send_result(&replacement_action, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 2);
    a.record_send_result(&trigger, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 2);

    // B accepts everything in send-sequence order (= enqueue order): the
    // two waters apply, the second hw-2 receipt is idempotent, the
    // trigger body is a plain application. Nothing stages a
    // counter-receipt — B consumed nothing, so B has no debt.
    let fetch = b.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    assert_eq!(envelopes.len(), 4);
    let mut outcomes = Vec::new();
    for envelope in &envelopes {
        outcomes.push(b.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            NOW,
        )?);
    }
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == AcceptOutcome::ReceiptApplied)
            .count(),
        2
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AcceptOutcome::Application(_)))
            .count(),
        1
    );
    assert!(outcomes.contains(&AcceptOutcome::ReceiptIdempotent));
    assert!(b.pending_send_actions()?.is_empty());
    assert_eq!(delivered_marker(&b)?, 0);
    Ok(())
}

#[test]
fn accept_envelope_rejects_forgery_expiry_and_wrong_variant()
-> std::result::Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;
    stage_to_relay(&mut b, &mut relay, &["genuine"])?;

    let fetch = a.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let envelope = envelopes.first().ok_or("no envelope")?;

    // Forged outer signature.
    let forged = Ed25519Keypair::new().sign(b"wrong bytes");
    assert!(matches!(
        a.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            forged,
            NOW,
        ),
        Err(LabError::Unauthorized)
    ));
    // Expired envelope.
    assert!(matches!(
        a.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            NOW,
            envelope.sender_signature,
            NOW,
        ),
        Err(LabError::RequestExpired)
    ));
    // The failures mutated nothing: the genuine envelope still accepts.
    let outcome = a.accept_envelope(
        envelope.queue_id,
        envelope.message_id,
        envelope.packet.clone(),
        envelope.expires_at,
        envelope.sender_signature,
        NOW,
    )?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    Ok(())
}

/// Signed envelope around a genuine payload from a raw peer session.
/// `issuer_outstanding` is the congestion signal the payload carries
/// (review D2b v7); callers pass the honest sample or a test override.
fn raw_peer_envelope(
    peer_session: &mut vodozemac::olm::Session,
    a: &PersistentClient<TestProtector>,
    conversation_id: ConversationId,
    seq: u64,
    issuer_outstanding: u64,
) -> std::result::Result<(MessageId, EncryptedPacket, vodozemac::Ed25519Signature), Box<dyn Error>>
{
    let epoch_id = super::epoch_of(peer_session.session_keys());
    let queue_a = a.state.mailbox_queue_id;
    let message_id = MessageId::random();
    let outgoing = payload::application(
        conversation_id,
        message_id,
        epoch_id,
        seq,
        NOW,
        format!("gap-message-{seq}"),
        issuer_outstanding,
    )?;
    let encoded = payload::encode(&outgoing)?;
    let message = peer_session.encrypt(&encoded[..])?;
    let packet = EncryptedPacket::from_untrusted(serde_json::to_vec(&message)?);
    let signature = a.keypairs.send.sign(&super::send_signing_bytes(
        queue_a,
        message_id,
        &packet.digest(),
        NOW + 3_600,
    ));
    Ok((message_id, packet, signature))
}

/// A raw test peer (no façade budget on its side) with a verified
/// contact committed at A, plus its outbound session to A's published
/// one-time key.
fn establish_raw_peer_session(
    a: &mut PersistentClient<TestProtector>,
    offer_a: &super::RedactedContactOffer,
    conversation_id: ConversationId,
) -> std::result::Result<vodozemac::olm::Session, Box<dyn Error>> {
    let mut peer_account = Account::new();
    let peer_otk = *peer_account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("no peer one-time key")?;
    peer_account.mark_keys_as_published();
    let mut peer_offer = RedactedContactOffer {
        signing_identity: peer_account.ed25519_key(),
        curve_identity: peer_account.curve25519_key(),
        one_time_key: peer_otk,
        valid_until: NOW + 300,
        signature: peer_account.sign(b""),
    };
    peer_offer.signature = peer_account.sign(in_crate_prekey_signing_bytes(
        &peer_offer.signing_identity,
        &peer_offer.curve_identity,
        &peer_offer.one_time_key,
        NOW + 300,
    ));
    a.commit_verified_contact(
        peer_offer.signing_identity,
        peer_offer,
        conversation_id,
        QueueId::random(),
        Zeroizing::new(serde_json::to_vec(&Ed25519Keypair::new())?),
        NOW,
    )?;
    Ok(peer_account.create_outbound_session(
        SessionConfig::version_1(),
        offer_a.curve_identity,
        offer_a.one_time_key,
    )?)
}

/// A raw vodozemac peer drives a genuine message gap past vodozemac's
/// 40-retained-skipped-keys horizon; the accept must fail AND durably
/// commit `RekeyRequired`.
#[test]
fn gap_failure_commits_rekey_required() -> std::result::Result<(), Box<dyn Error>> {
    let a_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let conversation_id = ConversationId::random();
    let offer_a = a.prekey_action(NOW + 300)?;
    let queue_a = a.state.mailbox_queue_id;
    let mut peer_session = establish_raw_peer_session(&mut a, &offer_a, conversation_id)?;

    // Message 1 establishes A's inbound session.
    let (id1, packet1, sig1) = raw_peer_envelope(&mut peer_session, &a, conversation_id, 1, 0)?;
    let outcome = a.accept_envelope(queue_a, id1, packet1, NOW + 3_600, sig1, NOW)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));

    // Consume it: the ACK intent exists for the relay-level assertions
    // below (ACK actions never touch the ratchet).
    a.consume_inbound(id1, NOW + 300, NOW)?;
    assert_eq!(a.ack_actions(NOW)?.len(), 1);

    // The peer keeps encrypting through seq 45. Deliver seq 45 first: the
    // 43-message gap is within vodozemac's 2000-gap tolerance, so it
    // decrypts and lands in the out-of-order set — but its chain advance
    // evicts the oldest skipped keys (only 40 retained).
    let mut second = None;
    let mut last = None;
    for seq in 2..=45 {
        let envelope = raw_peer_envelope(&mut peer_session, &a, conversation_id, seq, 0)?;
        if seq == 2 {
            second = Some(envelope);
        } else if seq == 45 {
            last = Some(envelope);
        }
    }
    let (id45, packet45, sig45) = last.ok_or("no seq-45 envelope")?;
    let outcome = a.accept_envelope(queue_a, id45, packet45, NOW + 3_600, sig45, NOW)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .received_above_high_water,
        vec![45]
    );

    // Now deliver the previously-unseen seq 2: its skipped key was
    // evicted, a genuine MissingMessageKey — RekeyRequired commits.
    let (id2, packet2, sig2) = second.ok_or("no seq-2 envelope")?;
    let generation_before = a.store.generation()?;
    let result = a.accept_envelope(queue_a, id2, packet2.clone(), NOW + 3_600, sig2, NOW);
    assert!(result.is_err(), "gap packet accepted");

    // The failure committed RekeyRequired (generation advanced by one).
    assert_eq!(active_mode(&a)?, SessionMode::RekeyRequired);
    assert_eq!(a.store.generation()?, generation_before + 1);
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .highest_contiguous_received_seq,
        1,
        "the failed message moved the receive high water"
    );

    // Inbound lock (review D2b v8 P1-1): replaying the EXACT gap packet
    // rejects at the top of the bounds — no decrypt, no dedup write, and
    // generation does NOT advance again.
    let result = a.accept_envelope(queue_a, id2, packet2.clone(), NOW + 3_600, sig2, NOW);
    assert!(result.is_err(), "gap packet replay accepted under the lock");
    assert_eq!(
        a.store.generation()?,
        generation_before + 1,
        "the replay committed again"
    );

    // A later VALID application packet on the same session rejects too,
    // and is never exposed through `pending_inbound`.
    let (id46, packet46, sig46) = raw_peer_envelope(&mut peer_session, &a, conversation_id, 46, 0)?;
    let result = a.accept_envelope(queue_a, id46, packet46, NOW + 3_600, sig46, NOW);
    assert!(result.is_err(), "a post-lock application was accepted");
    assert_eq!(a.store.generation()?, generation_before + 1);
    let inbound: Vec<MessageId> = a
        .pending_inbound()?
        .iter()
        .map(|view| view.message_id)
        .collect();
    assert_eq!(inbound, vec![id45], "the post-lock packet was exposed");

    // Relay-level actions are unaffected by the lock: pending send
    // actions (the consumed message's owed receipt) and ACK actions
    // still work per the ReceiptLocked/RekeyRequired relay semantics.
    assert_eq!(a.pending_send_actions()?.len(), 1);
    assert_eq!(a.ack_actions(NOW)?.len(), 1);

    // Durable across reopen; all staging stays blocked, and the inbound
    // lock still rejects the replay with no commit.
    drop(a);
    let mut a = open_client(&a_dir)?;
    assert_inbound_lock_holds(
        &mut a,
        queue_a,
        id2,
        &packet2,
        sig2,
        id45,
        generation_before + 1,
    )?;
    Ok(())
}

/// After reopen: the `RekeyRequired` mode persisted, application staging
/// is blocked, and the gap-packet replay still rejects without a commit
/// and without reaching `pending_inbound` (review D2b v8 P1-1).
fn assert_inbound_lock_holds(
    a: &mut PersistentClient<TestProtector>,
    queue_a: QueueId,
    gap_id: MessageId,
    gap_packet: &EncryptedPacket,
    gap_sig: vodozemac::Ed25519Signature,
    exposed_id: MessageId,
    expected_generation: u64,
) -> std::result::Result<(), Box<dyn Error>> {
    assert_eq!(active_mode(a)?, SessionMode::RekeyRequired);
    assert!(a.stage_send("blocked", NOW, NOW + 3_600, NOW).is_err());
    let result = a.accept_envelope(
        queue_a,
        gap_id,
        gap_packet.clone(),
        NOW + 3_600,
        gap_sig,
        NOW,
    );
    assert!(result.is_err(), "gap packet replay accepted after reopen");
    assert_eq!(a.store.generation()?, expected_generation);
    let inbound: Vec<MessageId> = a
        .pending_inbound()?
        .iter()
        .map(|view| view.message_id)
        .collect();
    assert_eq!(inbound, vec![exposed_id]);
    Ok(())
}

#[test]
fn terminal_send_records_are_pruned_after_the_tombstone_window()
-> std::result::Result<(), Box<dyn Error>> {
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    connect(&mut a, &mut b, ConversationId::random())?;

    // Record 1: staged with a short expiry, terminally stored.
    let first = stage_app(&mut b, "terminal", NOW, NOW + 60, NOW)?;
    b.record_send_result(&first, SendOutcome::Stored)?;
    assert_eq!(b.state.sends.len(), 1, "terminal record retained in window");

    // Inside the tombstone window the record survives a send-path
    // mutator.
    let second = stage_app(&mut b, "in window", NOW + 120, NOW + 120 + 3_600, NOW + 120)?;
    assert_eq!(b.state.sends.len(), 2);

    // Past the window, the next send-path mutator prunes record 1. Record
    // 2's own expiry passes first (swept to Expired), but ITS tombstone
    // window has not, so only record 1 leaves.
    let past_window = NOW + 60 + 7 * 24 * 60 * 60 + 1;
    let third = stage_app(
        &mut b,
        "after window",
        past_window,
        past_window + 3_600,
        past_window,
    )?;
    let records = &b.state.sends;
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.message_id != first.request.message_id),
        "record 1 not pruned"
    );
    assert!(
        records
            .iter()
            .any(|record| record.message_id == second.request.message_id)
    );
    assert!(
        records
            .iter()
            .any(|record| record.message_id == third.request.message_id)
    );
    // The high-water state is untouched by pruning.
    let active = b.state.active_session.as_ref().ok_or("no session")?;
    assert_eq!(active.peer_contiguous_high_water, 0);
    assert_eq!(active.last_assigned_send_seq, 3);
    let _ = a;
    Ok(())
}

#[test]
fn accept_path_reconcile_required_on_commit_failure() -> std::result::Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;
    stage_to_relay(&mut b, &mut relay, &["doomed-accept"])?;

    let fetch = a.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let envelope = envelopes.first().ok_or("no envelope")?;

    let connection = Connection::open(a_dir.path().join("client").join("client-state.sqlite3"))?;
    let nonce: Vec<u8> =
        connection.query_row("SELECT nonce FROM client_state WHERE slot = 1", [], |row| {
            row.get(0)
        })?;
    let mut tampered = nonce.clone();
    *tampered.first_mut().ok_or("empty nonce")? ^= 0x01;
    connection.execute(
        "UPDATE client_state SET nonce = ?1 WHERE slot = 1",
        params![tampered],
    )?;

    assert!(
        a.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            NOW,
        )
        .is_err()
    );
    assert!(a.pending_inbound().is_err());
    assert!(a.ack_actions(NOW).is_err());
    assert!(a.fetch_request(NOW + 60, NOW).is_err());

    connection.execute(
        "UPDATE client_state SET nonce = ?1 WHERE slot = 1",
        params![nonce],
    )?;
    drop(connection);
    drop(a);
    let mut a = open_client(&a_dir)?;
    // The envelope was never committed; accepting it now succeeds.
    let outcome = a.accept_envelope(
        envelope.queue_id,
        envelope.message_id,
        envelope.packet.clone(),
        envelope.expires_at,
        envelope.sender_signature,
        NOW,
    )?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    Ok(())
}

// --- combined review round: ACK binding + expiry sweep -----------------------

#[test]
fn ack_result_requires_full_request_binding() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0, 1])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let inbound = a.pending_inbound()?;
    let id1 = inbound
        .iter()
        .find(|view| view.body == "m1")
        .ok_or("m1 missing")?
        .message_id;
    let id2 = inbound
        .iter()
        .find(|view| view.body == "m2")
        .ok_or("m2 missing")?
        .message_id;
    a.consume_inbound(id1, NOW + 300, NOW)?;
    a.consume_inbound(id2, NOW + 300, NOW)?;
    let actions = a.ack_actions(NOW)?;
    let action = actions
        .iter()
        .find(|candidate| candidate.request.message_id == id1)
        .ok_or("m1 ack missing")?
        .clone();
    let action_two = actions
        .iter()
        .find(|candidate| candidate.request.message_id == id2)
        .ok_or("m2 ack missing")?
        .clone();

    // Wrong message ID in the request, right token.
    let mut wrong_id = action.clone();
    wrong_id.request.message_id = MessageId::random();
    assert!(
        a.record_ack_result(&wrong_id, AckOutcomeView::Deleted)
            .is_err(),
        "foreign message_id accepted"
    );

    // Wrong signature over otherwise-correct fields.
    let mut wrong_sig = action.clone();
    let mut signature_bytes = wrong_sig.request.signature.to_bytes();
    signature_bytes[0] ^= 0x01;
    wrong_sig.request.signature = vodozemac::Ed25519Signature::from_slice(&signature_bytes)?;
    assert!(
        a.record_ack_result(&wrong_sig, AckOutcomeView::Deleted)
            .is_err(),
        "forged signature accepted"
    );

    // Right token, wrong durable field (validity).
    let mut wrong_field = action.clone();
    wrong_field.request.valid_until += 1;
    assert!(
        a.record_ack_result(&wrong_field, AckOutcomeView::Deleted)
            .is_err(),
        "field mismatch accepted"
    );

    // Cross-action: a token that matches nothing, and a token from a
    // different intent with this request.
    let cross = super::DurableAction {
        token: action_two.token,
        request: action.request.clone(),
    };
    assert!(
        a.record_ack_result(&cross, AckOutcomeView::Deleted)
            .is_err(),
        "cross-action accepted"
    );

    // Nothing mutated: both genuine actions consume, and replay rejects.
    a.record_ack_result(&action, AckOutcomeView::Deleted)?;
    a.record_ack_result(&action_two, AckOutcomeView::AlreadyGone)?;
    assert!(
        a.record_ack_result(&action, AckOutcomeView::Deleted)
            .is_err(),
        "replay accepted"
    );
    Ok(())
}

#[test]
fn expired_ack_intents_are_swept() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0, 1])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let inbound = a.pending_inbound()?;
    let expired_id = inbound
        .iter()
        .find(|view| view.body == "m1")
        .ok_or("m1 missing")?
        .message_id;
    let fresh_id = inbound
        .iter()
        .find(|view| view.body == "m2")
        .ok_or("m2 missing")?
        .message_id;
    // One intent expires soon, one stays valid.
    a.consume_inbound(expired_id, NOW + 60, NOW)?;
    a.consume_inbound(fresh_id, NOW + 300, NOW)?;
    assert_eq!(a.state.acks.len(), 2);

    // The next clock-taking mutator at NOW+120 sweeps the expired intent
    // and expires its dedup record; the unexpired intent is untouched.
    a.stage_send("trigger", NOW + 120, NOW + 120 + 3_600, NOW + 120)?;
    assert_eq!(a.state.acks.len(), 1);
    assert_eq!(a.state.acks[0].message_id, fresh_id);
    let expired = a
        .state
        .dedup
        .iter()
        .find(|record| record.message_id == expired_id)
        .ok_or("expired dedup missing")?;
    assert_eq!(expired.state, DedupState::Expired);
    let fresh = a
        .state
        .dedup
        .iter()
        .find(|record| record.message_id == fresh_id)
        .ok_or("fresh dedup missing")?;
    assert_eq!(fresh.state, DedupState::Accepted);
    Ok(())
}

#[test]
fn full_bound_of_expired_ack_intents_is_swept() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;
    // One genuine accept so the ratchet has received (current-epoch dedup
    // is receive-authoritative).
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));

    // Fabricate a full bound of 32 self-consistent pending intents with
    // matching dedup records, all expired. Sequences are distinct
    // (codec: one durable send_seq per encryption) and each sits in the
    // out-of-order received set (codec: current-epoch dedup is
    // receive-authoritative), above the genuine accept's HCR of 1.
    let epoch_id = a
        .state
        .active_session
        .as_ref()
        .ok_or("no session")?
        .epoch_id;
    let queue_id = a.state.mailbox_queue_id;
    for sequence in 3..=34_u64 {
        let message_id = MessageId::random();
        let packet_digest = crate::capability::digest(&sequence.to_be_bytes());
        a.state.acks.push(crate::state::AckIntent {
            message_id,
            epoch_id,
            sequence,
            queue_id,
            packet_digest,
            valid_until: NOW + 60,
            state: crate::state::AckState::Pending,
        });
        a.state.dedup.push(crate::state::DedupRecord {
            message_id,
            epoch_id,
            sequence,
            queue_id,
            packet_digest,
            expires_at: NOW + 3_600,
            state: DedupState::Accepted,
        });
    }
    a.state
        .active_session
        .as_mut()
        .ok_or("no session")?
        .received_above_high_water = (3..=34).collect();
    a.state
        .acks
        .sort_by(|x, y| x.message_id.as_bytes().cmp(y.message_id.as_bytes()));
    a.state
        .dedup
        .sort_by(|x, y| x.message_id.as_bytes().cmp(y.message_id.as_bytes()));
    assert_eq!(a.state.acks.len(), 32);

    a.stage_send("trigger", NOW + 120, NOW + 120 + 3_600, NOW + 120)?;
    assert!(a.state.acks.is_empty(), "expired intents not swept");
    assert!(
        a.state
            .dedup
            .iter()
            .filter(|record| record.message_id != a.state.inbound[0].message_id)
            .all(|record| record.state == DedupState::Expired),
        "swept dedup records not Expired"
    );
    Ok(())
}

/// Sol's outbox shape (D2b v2/v3 repros): the accept-staged receipt is
/// cleared, then 32 terminal send records over sequences 1..=32 with the
/// receipt high water at 24 and a genuine peer-signed receipt.
fn fill_outbox(
    a: &mut PersistentClient<TestProtector>,
    b: &PersistentClient<TestProtector>,
) -> std::result::Result<(), Box<dyn Error>> {
    let epoch_id = a
        .state
        .active_session
        .as_ref()
        .ok_or("no session")?
        .epoch_id;
    a.state.sends.clear();
    let mut receipt = crate::state::HighWaterReceipt {
        conversation_id: a.state.conversation_id,
        epoch_id,
        acknowledged_sender_curve: a.account.curve25519_key(),
        issuer_curve: b.account.curve25519_key(),
        high_water: 24,
        signature: b.account.sign(b""),
    };
    receipt.signature = b.account.sign(super::receipt_signing_bytes(&receipt));
    for sequence in 1..=32_u64 {
        a.state.sends.push(crate::state::SendRecord {
            message_id: MessageId::random(),
            state: crate::state::SendState::Stored,
            epoch_id,
            sequence,
            queue_id: None,
            packet: None,
            expires_at: NOW + 3_600,
            send_signature: None,
            packet_digest: Some(crate::capability::digest(&sequence.to_be_bytes())),
            kind: crate::state::SendKind::Application,
            receipt_high_water: None,
        });
    }
    a.state
        .sends
        .sort_by(|x, y| x.message_id.as_bytes().cmp(y.message_id.as_bytes()));
    let active = a.state.active_session.as_mut().ok_or("no session")?;
    active.last_assigned_send_seq = 32;
    active.peer_contiguous_high_water = 24;
    active.receipt = Some(receipt);
    Ok(())
}

/// Give B one GENUINE received send from A: the codec's receive-side
/// provenance rule (receive-side records require a ratchet that has
/// actually received) makes any later in-crate receive-water fabrication
/// uncommittable without it. The body lands in order (B.HCR 1); with
/// the v8 arm-first tail B's congestion (24 outstanding) discharges one
/// counter-receipt on the fresh water — drive it through the relay so
/// the fixture's outbox is clean afterwards (the Stored result also
/// clears B's flag, v8 P1-2a).
fn give_b_a_genuine_receive(
    a: &mut PersistentClient<TestProtector>,
    b: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
) -> std::result::Result<(), Box<dyn Error>> {
    let ping = stage_app(a, "ping", NOW, NOW + 3_600, NOW)?;
    relay.enqueue(&ping.request, NOW)?;
    a.record_send_result(&ping, SendOutcome::Stored)?;
    let fetch = b.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let envelope = envelopes.first().ok_or("no ping envelope")?;
    let outcome = b.accept_envelope(
        envelope.queue_id,
        envelope.message_id,
        envelope.packet.clone(),
        envelope.expires_at,
        envelope.sender_signature,
        NOW,
    )?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    drive_pending(b, relay, NOW)?;
    assert!(b.pending_send_actions()?.is_empty());
    Ok(())
}

// --- D2b v2 remediation tests ------------------------------------------------

/// Blocker 1: outcome `Failed` gets the full binding verification too.
#[test]
fn failed_ack_result_is_verified() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let inbound = a.pending_inbound()?;
    let message_id = inbound.first().ok_or("no inbound")?.message_id;
    a.consume_inbound(message_id, NOW + 300, NOW)?;
    let action = a
        .ack_actions(NOW)?
        .into_iter()
        .next()
        .ok_or("no ack action")?;

    // A forged token with outcome Failed rejects.
    let forged = super::DurableAction {
        token: [0xAB; 16],
        request: action.request.clone(),
    };
    assert!(
        a.record_ack_result(&forged, AckOutcomeView::Failed)
            .is_err()
    );
    // A bad signature with outcome Failed rejects.
    let mut bad_sig = action.clone();
    let mut signature_bytes = bad_sig.request.signature.to_bytes();
    signature_bytes[0] ^= 0x01;
    bad_sig.request.signature = vodozemac::Ed25519Signature::from_slice(&signature_bytes)?;
    assert!(
        a.record_ack_result(&bad_sig, AckOutcomeView::Failed)
            .is_err()
    );

    // A genuine Failed: accepted, no mutation, intent stays Pending.
    let generation_before = a.store.generation()?;
    a.record_ack_result(&action, AckOutcomeView::Failed)?;
    assert_eq!(a.store.generation()?, generation_before);
    assert_eq!(a.state.acks.len(), 1);
    assert_eq!(a.state.acks[0].state, crate::state::AckState::Pending);
    Ok(())
}

/// Blocker 2, Sol's exact repro shape: 24 terminal sends with the receipt
/// high water at 24, then 8 more terminal sends; the send array is full,
/// so the consume must succeed with the ACK intent created and NO receipt
/// staged. After pruning, a consume stages a receipt normally.
#[test]
fn receipt_staging_never_blocks_consume() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, b, mut relay) = conversation_fixture()?;
    // A accepts the first message, establishing its inbound session.
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));

    fill_outbox(&mut a, &b)?;

    // Accept a second application message and consume it: the send array
    // is at the bound, so the receipt is skipped but the consume commits.
    let outcomes = deliver(&mut a, &mut relay, &[1])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let inbound = a.pending_inbound()?;
    let second_id = inbound
        .iter()
        .find(|view| view.body == "m2")
        .ok_or("m2 missing")?
        .message_id;
    a.consume_inbound(second_id, NOW + 300, NOW)?;
    assert_eq!(a.state.acks.len(), 1, "ACK intent not created");
    assert_eq!(a.state.sends.len(), 32, "a receipt was staged at the bound");
    // The receipt stayed owed the whole time: the delivered marker never
    // moved from 0 while the array was full (it advances only when a
    // receipt reaches Stored/Duplicate, v4).
    assert_eq!(delivered_marker(&a)?, 0, "the marker moved while full");

    // Advance the clock past the tombstone window; the next mutator
    // prunes the terminal records and stages the OWED receipt in the same
    // commit (review D2b v3) — no new inbound needed. The marker still
    // does not move: staging is not delivery (review D2b v4).
    let past_window = NOW + 3_600 + 7 * 24 * 60 * 60 + 1;
    a.stage_send(
        "trigger prune",
        past_window,
        past_window + 3_600,
        past_window,
    )?;
    assert_eq!(
        a.state.sends.len(),
        2,
        "expected the trigger send plus the owed receipt"
    );
    assert!(
        a.state.sends.iter().any(|record| {
            record.state == crate::state::SendState::Pending
                && record.kind == crate::state::SendKind::Receipt
                && record.receipt_high_water == Some(2)
        }),
        "the owed hw-2 receipt did not stage"
    );
    assert_eq!(
        delivered_marker(&a)?,
        0,
        "the marker moved at staging, before any delivery"
    );
    // The staged hw-2 receipt is Pending (in flight), so nothing new is
    // owed and a further consume stages nothing.
    let first_id = inbound
        .iter()
        .find(|view| view.body == "m1")
        .ok_or("m1 missing")?
        .message_id;
    a.consume_inbound(first_id, past_window + 300, past_window)?;
    assert_eq!(a.state.sends.len(), 2, "no new receipt should be owed");
    Ok(())
}

/// Blocker 3: an expired pending prekey must not be consumed by the
/// pre-key accept path.
#[test]
fn expired_pending_prekey_cannot_be_consumed() -> std::result::Result<(), Box<dyn Error>> {
    let a_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let conversation_id = ConversationId::random();
    // Our offer is valid only until NOW+60.
    let offer_a = a.prekey_action(NOW + 60)?;
    let queue_a = a.state.mailbox_queue_id;

    let mut peer_account = Account::new();
    let peer_otk = *peer_account
        .generate_one_time_keys(1)
        .created
        .first()
        .ok_or("no peer one-time key")?;
    peer_account.mark_keys_as_published();
    let mut peer_offer = RedactedContactOffer {
        signing_identity: peer_account.ed25519_key(),
        curve_identity: peer_account.curve25519_key(),
        one_time_key: peer_otk,
        valid_until: NOW + 300,
        signature: peer_account.sign(b""),
    };
    peer_offer.signature = peer_account.sign(in_crate_prekey_signing_bytes(
        &peer_offer.signing_identity,
        &peer_offer.curve_identity,
        &peer_offer.one_time_key,
        NOW + 300,
    ));
    a.commit_verified_contact(
        peer_offer.signing_identity,
        peer_offer,
        conversation_id,
        QueueId::random(),
        Zeroizing::new(serde_json::to_vec(&Ed25519Keypair::new())?),
        NOW,
    )?;
    let mut peer_session = peer_account.create_outbound_session(
        SessionConfig::version_1(),
        offer_a.curve_identity,
        offer_a.one_time_key,
    )?;

    // Fresh outer expiry, correctly capability-signed, at NOW+120 — past
    // the offer's validity. Rejected; nothing is consumed or mutated.
    let (id1, packet1, sig1) = raw_peer_envelope(&mut peer_session, &a, conversation_id, 1, 0)?;
    let result = a.accept_envelope(queue_a, id1, packet1.clone(), NOW + 3_600, sig1, NOW + 120);
    assert!(matches!(result, Err(LabError::PeerVerificationFailed)));
    assert!(a.state.active_session.is_none());
    assert!(
        a.state.pending_prekey.is_some(),
        "expired offer was consumed"
    );

    // The same envelope at NOW+30, within the offer's validity, still
    // establishes.
    let outcome = a.accept_envelope(queue_a, id1, packet1, NOW + 3_600, sig1, NOW + 30)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    assert!(a.state.active_session.is_some());
    Ok(())
}

/// Blocker 4: façade-minted requests stay inside the relay's windows.
#[test]
fn request_windows_match_the_relay() -> std::result::Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;

    // Registration: the relay's request window is 300 seconds.
    assert!(client.registration_action(NOW + 301, NOW).is_err());
    assert!(client.registration_action(NOW, NOW).is_err());
    client.registration_action(NOW + 300, NOW)?;

    // Fetch: same window.
    assert!(client.fetch_request(NOW + 301, NOW).is_err());
    assert!(client.fetch_request(NOW, NOW).is_err());
    client.fetch_request(NOW + 300, NOW)?;

    // Consume (ACK minting): same window, and the rejection mutates
    // nothing.
    let (_a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let inbound_before = a.pending_inbound()?.len();
    let acks_before = a.state.acks.len();
    let message_id = a.pending_inbound()?.first().ok_or("no inbound")?.message_id;
    assert!(a.consume_inbound(message_id, NOW + 3_600, NOW).is_err());
    assert!(a.consume_inbound(message_id, NOW, NOW).is_err());
    assert_eq!(a.pending_inbound()?.len(), inbound_before);
    assert_eq!(a.state.acks.len(), acks_before);
    a.consume_inbound(message_id, NOW + 300, NOW)?;
    Ok(())
}

/// Review D2b v3, Sol's exact closure, carried through the v4 marker
/// semantics: every inbound is consumed while the send array is full (32
/// terminal sends); no receipt stages; the DELIVERED marker stays at 0;
/// after the clock passes the tombstone window the next mutator stages
/// the owed receipt with no new inbound; the Stored result advances the
/// marker, and the receipt drives the peer's high water forward IN ORDER
/// and unblocks its budget without a counter-receipt.
#[test]
fn owed_receipt_stages_after_capacity_returns_and_unlocks_peer()
-> std::result::Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;

    // B stages 24 application sends and becomes ControlOnly.
    let bodies: Vec<String> = (1..=24).map(|index| format!("m{index}")).collect();
    stage_to_relay(
        &mut b,
        &mut relay,
        &bodies.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    assert!(b.stage_send("blocked", NOW, NOW + 3_600, NOW).is_err());

    // A establishes by accepting the first message.
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));

    give_b_a_genuine_receive(&mut a, &mut b, &mut relay)?;

    fill_outbox(&mut a, &b)?;

    // A accepts and consumes ALL remaining 23 messages while full.
    let order: Vec<usize> = (1..=23).collect();
    let outcomes = deliver(&mut a, &mut relay, &order)?;
    assert!(outcomes.iter().all(Result::is_ok));
    assert_eq!(a.pending_inbound()?.len(), 24);
    let inbound_ids: Vec<MessageId> = a
        .pending_inbound()?
        .iter()
        .map(|view| view.message_id)
        .collect();
    for message_id in inbound_ids {
        a.consume_inbound(message_id, NOW + 300, NOW)?;
    }
    // Every consume committed; no receipt was ever stageable, and the
    // delivered marker never moved from 0 (it advances only on
    // Stored/Duplicate, review D2b v4 — not at staging).
    assert_eq!(a.state.sends.len(), 32, "a receipt staged at the bound");
    assert_eq!(a.state.acks.len(), 24);
    assert_eq!(delivered_marker(&a)?, 0, "the marker moved while full");

    // Past the tombstone window, one mutator prunes the terminal records
    // and stages the owed receipt in the same commit — still without
    // moving the marker (staging is not delivery).
    let past_window = NOW + 3_600 + 7 * 24 * 60 * 60 + 1;
    let trigger = stage_app(
        &mut a,
        "trigger",
        past_window,
        past_window + 3_600,
        past_window,
    )?;
    let sends = &a.state.sends;
    assert_eq!(sends.len(), 2, "expected trigger send plus owed receipt");
    assert!(
        sends.iter().any(|record| {
            record.state == crate::state::SendState::Pending
                && record.kind == crate::state::SendKind::Receipt
                && record.receipt_high_water == Some(24)
        }),
        "the owed hw-24 receipt did not stage"
    );
    assert_eq!(delivered_marker(&a)?, 0, "the marker moved at staging");

    drive_receipt_to_b_and_assert_unlock(&mut a, &mut b, &mut relay, &trigger, past_window)?;
    Ok(())
}

/// Drive A's staged receipt (everything pending that is not `trigger`)
/// to B through the real relay — the Stored result advancing A's
/// delivered marker to 24 — and prove B applies it IN ORDER: budget
/// recovered, B's armed control debt discharging exactly one
/// counter-receipt (the v6 drain path — B's local congestion re-arms
/// even as A's low signal clears), application traffic unlocked.
fn drive_receipt_to_b_and_assert_unlock(
    a: &mut PersistentClient<TestProtector>,
    b: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    trigger: &super::DurableAction<crate::capability::SendRequest>,
    past_window: u64,
) -> std::result::Result<(), Box<dyn Error>> {
    let receipt_action = a
        .pending_send_actions()?
        .into_iter()
        .find(|action| action.request.message_id != trigger.request.message_id)
        .ok_or("no receipt action")?;
    relay.enqueue(&receipt_action.request, past_window)?;
    a.record_send_result(&receipt_action, SendOutcome::Stored)?;
    assert_eq!(
        delivered_marker(a)?,
        24,
        "the marker did not advance on the Stored result"
    );
    // The receipt rides A's send sequence 33 while B's only genuine
    // receive from A sits in the out-of-order set (the 32 outbox records
    // were fabricated without envelopes). Move B's receive water in-crate
    // so this delivery exercises the in-order receipt path (review D2b
    // v4: the v4 receipt-delivery tests previously dodged it out of
    // order); the ping above makes the fabrication ratchet-provable, and
    // draining the gap set keeps the water self-consistent.
    {
        let active = b.state.active_session.as_mut().ok_or("no session")?;
        active.highest_contiguous_received_seq = 32;
        active.received_above_high_water.clear();
    }
    let fetch = b.fetch_request(past_window + 300, past_window)?;
    let envelopes = relay.fetch(&fetch.request, past_window)?;
    let receipt_envelope = envelopes.first().ok_or("no receipt envelope")?;
    let outcome = b.accept_envelope(
        receipt_envelope.queue_id,
        receipt_envelope.message_id,
        receipt_envelope.packet.clone(),
        receipt_envelope.expires_at,
        receipt_envelope.sender_signature,
        past_window,
    )?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    {
        let active = b.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.peer_contiguous_high_water, 24);
        assert_eq!(active.highest_contiguous_received_seq, 33);
        // B consumed nothing, so B has no APPLICATION debt (v5 model);
        // its marker is 1 from the ping counter-receipt's Stored result.
        assert_eq!(active.receipt_debt_up_to, 0);
        assert_eq!(active.last_delivered_receipt_high_water, 1);
    }
    // B armed its control debt back at the ping accept (its outstanding
    // was 24) and never delivered anything since; A's receipt reports
    // fresh water (HCR 33) and B's entry congestion RAISES the debt
    // water to 33 (v9 water model: signals only raise, never lower).
    // Exactly one counter-receipt reports HCR 33 (the v6 drain path),
    // bounded by the in-flight rule.
    let b_receipts = pending_receipts(b);
    assert_eq!(b_receipts.len(), 1, "the armed control debt did not stage");
    assert_eq!(b_receipts[0].high_water, Some(33));
    assert_eq!(
        b.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .control_debt_up_to,
        33,
        "local congestion should raise the debt water to the HCR"
    );
    // The unlock proof: B can stage application traffic again.
    b.stage_send("unlocked", past_window, past_window + 3_600, past_window)?;
    Ok(())
}

// --- D2b v4 remediation tests ------------------------------------------------

/// A copied view of a `Pending` receipt-kind send record.
struct ReceiptView {
    message_id: MessageId,
    sequence: u64,
    high_water: Option<u64>,
    expires_at: u64,
}

/// Every `Pending` receipt-kind send record, in send-sequence order.
fn pending_receipts(client: &PersistentClient<TestProtector>) -> Vec<ReceiptView> {
    let mut records: Vec<ReceiptView> = client
        .state
        .sends
        .iter()
        .filter(|record| {
            record.state == crate::state::SendState::Pending
                && record.kind == crate::state::SendKind::Receipt
        })
        .map(|record| ReceiptView {
            message_id: record.message_id,
            sequence: record.sequence,
            high_water: record.receipt_high_water,
            expires_at: record.expires_at,
        })
        .collect();
    records.sort_by_key(|record| record.sequence);
    records
}

/// Blocker 1 liveness: staged receipts that expire unstored (the relay
/// purges them) re-stage automatically at the next mutator with a fresh
/// envelope and a fresh 7-day expiry; driving the replacement to Stored
/// advances both the delivered marker and the peer's high water.
#[test]
fn lost_receipt_re_stages_after_expiry() -> std::result::Result<(), Box<dyn Error>> {
    const TTL: u64 = 7 * 24 * 60 * 60;
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;
    // Accept and consume each message in turn (v5 debt model): four
    // receipts stage (one per consumed water), each carrying the 7-day
    // message TTL — never the 300-second request window — and the
    // delivered marker does not move at staging.
    for (index, body) in ["m1", "m2", "m3", "m4"].iter().enumerate() {
        accept_and_consume(&mut a, &mut relay, index, body)?;
    }
    let staged = pending_receipts(&a);
    assert_eq!(staged.len(), 4);
    for (index, record) in staged.iter().enumerate() {
        assert_eq!(record.expires_at, NOW + TTL);
        assert_eq!(record.high_water, Some(u64::try_from(index)? + 1));
    }
    assert_eq!(delivered_marker(&a)?, 0);

    // The clock passes their expiry with no send result ever recorded
    // (the relay purged them): the next mutator sweeps all four to
    // Expired and re-stages ONE fresh receipt for the current high water
    // with a fresh 7-day expiry.
    let past = NOW + TTL + 1;
    a.stage_send("trigger", past, past + 3_600, past)?;
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1, "the lost receipts did not re-stage");
    let replacement = receipts.first().ok_or("no replacement")?;
    assert_eq!(replacement.high_water, Some(4));
    assert_eq!(replacement.expires_at, past + TTL);
    assert_eq!(replacement.sequence, 5);
    assert_eq!(delivered_marker(&a)?, 0, "staging is not delivery");

    // Drive the replacement to Stored through the real relay: the marker
    // finally advances, and the peer's high water follows on accept.
    let action = a
        .pending_send_actions()?
        .into_iter()
        .find(|action| action.request.message_id == replacement.message_id)
        .ok_or("no replacement action")?;
    relay.enqueue(&action.request, past)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 4);
    let fetch = b.fetch_request(past + 300, past)?;
    let envelopes = relay.fetch(&fetch.request, past)?;
    let envelope = envelopes.first().ok_or("no receipt envelope")?;
    let outcome = b.accept_envelope(
        envelope.queue_id,
        envelope.message_id,
        envelope.packet.clone(),
        envelope.expires_at,
        envelope.sender_signature,
        past,
    )?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    let active = b.state.active_session.as_ref().ok_or("no session")?;
    assert_eq!(active.peer_contiguous_high_water, 4);
    Ok(())
}

/// Blocker 1 crash variant: stage a receipt, die without
/// `record_send_result`, reopen after the expiry — the owed rule
/// re-stages a fresh receipt on the first mutator after reopen.
#[test]
fn lost_receipt_re_stages_after_crash_reopen() -> std::result::Result<(), Box<dyn Error>> {
    const TTL: u64 = 7 * 24 * 60 * 60;
    let (a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;
    // Consume m1 to create the debt whose receipt is then lost.
    accept_and_consume(&mut a, &mut relay, 0, "m1")?;
    assert_eq!(pending_receipts(&a).len(), 1);

    // Crash mid-lifecycle; only committed state survives the reopen.
    drop(a);
    let mut a = open_client(&a_dir)?;
    assert_eq!(pending_receipts(&a).len(), 1, "staged receipt not durable");
    assert_eq!(delivered_marker(&a)?, 0);

    // Past the expiry, the first mutator sweeps the dead receipt and
    // re-stages a fresh one for the same high water.
    let past = NOW + TTL + 1;
    a.stage_send("trigger", past, past + 3_600, past)?;
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1, "no fresh receipt after reopen");
    let replacement = receipts.first().ok_or("no replacement")?;
    assert_eq!(replacement.high_water, Some(1));
    assert_eq!(replacement.expires_at, past + TTL);
    assert_eq!(replacement.sequence, 2);
    Ok(())
}

/// Sol's unknown-delivery recovery: a receipt whose send result is
/// `DeliveryUnknown` never advances the marker, and consuming the
/// `DeliveryUnknown` record re-stages the receipt in the same pass.
#[test]
fn receipt_re_stages_after_delivery_unknown() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;
    // Consume m1 to create the debt whose receipt then goes unknown.
    accept_and_consume(&mut a, &mut relay, 0, "m1")?;
    let action = a
        .pending_send_actions()?
        .into_iter()
        .next()
        .ok_or("no receipt action")?;

    a.record_send_result(&action, SendOutcome::DeliveryUnknown)?;
    assert_eq!(
        delivered_marker(&a)?,
        0,
        "DeliveryUnknown advanced the marker"
    );

    a.consume_delivery_unknown(action.request.message_id, NOW)?;
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1, "no re-staged receipt after consume");
    let replacement = receipts.first().ok_or("no replacement")?;
    assert_eq!(replacement.high_water, Some(1));
    assert_eq!(replacement.sequence, 2);
    Ok(())
}

/// The delivered marker moves ONLY when a receipt-kind record reaches a
/// delivered terminal state: `Stored` and `Duplicate` advance it;
/// `DeliveryUnknown`, expiry and application-kind terminals never do.
#[test]
fn receipt_marker_advances_only_on_delivered_terminal() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;

    // Stored advances: consume m1 (creating the debt), drive its hw-1
    // receipt to Stored.
    accept_and_consume(&mut a, &mut relay, 0, "m1")?;
    let action = a
        .pending_send_actions()?
        .into_iter()
        .next()
        .ok_or("no receipt action")?;
    relay.enqueue(&action.request, NOW)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 1, "Stored did not advance");

    // Duplicate advances: consume m2, record Duplicate on the hw-2
    // receipt (the relay already holds a copy — that is delivery).
    accept_and_consume(&mut a, &mut relay, 1, "m2")?;
    let action = a
        .pending_send_actions()?
        .into_iter()
        .next()
        .ok_or("no hw-2 receipt action")?;
    a.record_send_result(&action, SendOutcome::Duplicate)?;
    assert_eq!(delivered_marker(&a)?, 2, "Duplicate did not advance");

    // DeliveryUnknown does not: consume m3, record DeliveryUnknown on
    // the hw-3 receipt.
    accept_and_consume(&mut a, &mut relay, 2, "m3")?;
    let unknown = a
        .pending_send_actions()?
        .into_iter()
        .next()
        .ok_or("no hw-3 receipt action")?;
    a.record_send_result(&unknown, SendOutcome::DeliveryUnknown)?;
    assert_eq!(delivered_marker(&a)?, 2, "DeliveryUnknown advanced");

    // The owed rule re-stages hw 3 alongside the next application send;
    // its Stored advances the marker, and the application's own Stored
    // does not.
    let app = stage_app(&mut a, "app", NOW, NOW + 3_600, NOW)?;
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].high_water, Some(3));
    let receipt_action = a
        .pending_send_actions()?
        .into_iter()
        .find(|action| action.request.message_id == receipts[0].message_id)
        .ok_or("no hw-3 replacement action")?;
    a.record_send_result(&receipt_action, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 3);
    a.record_send_result(&app, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 3, "application Stored advanced");

    // Consuming the stranded DeliveryUnknown record frees its slot and
    // stages nothing (the hw-3 replacement already delivered).
    a.consume_delivery_unknown(unknown.request.message_id, NOW)?;
    assert!(pending_receipts(&a).is_empty());
    Ok(())
}

/// Blocker 2 quiescence (v5 debt model): a receipt-driven HCR advance
/// creates no debt — debt comes only from CONSUMED application records —
/// so an in-order receipt exchange never stages a counter-receipt, and
/// afterwards both peers drain to idle: mutators with no new traffic
/// produce no new send or dedup records.
#[test]
fn receipts_do_not_trigger_counter_receipts() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;

    // A accepts B's four application sends (no debt: nothing consumed),
    // then sends one application body of its own (seq 1).
    let outcomes = deliver(&mut a, &mut relay, &[0, 1, 2, 3])?;
    assert!(outcomes.iter().all(Result::is_ok));
    assert!(
        a.pending_send_actions()?.is_empty(),
        "accepts staged without consumed debt"
    );
    let ping = stage_app(&mut a, "ping", NOW, NOW + 3_600, NOW)?;
    relay.enqueue(&ping.request, NOW)?;
    a.record_send_result(&ping, SendOutcome::Stored)?;

    // B accepts the ping (no debt yet — nothing stages) and consumes it:
    // the consume creates B's only debt, so exactly one receipt stages.
    let fetch = b.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    assert_eq!(envelopes.len(), 1);
    let envelope = envelopes.first().ok_or("no ping envelope")?;
    let outcome = b.accept_envelope(
        envelope.queue_id,
        envelope.message_id,
        envelope.packet.clone(),
        envelope.expires_at,
        envelope.sender_signature,
        NOW,
    )?;
    let AcceptOutcome::Application(ping_id) = outcome else {
        return Err("ping was not accepted as an application".into());
    };
    assert!(
        b.pending_send_actions()?.is_empty(),
        "the accept staged without consumed debt"
    );
    b.consume_inbound(ping_id, NOW + 300, NOW)?;
    assert_eq!(
        b.pending_send_actions()?.len(),
        1,
        "the consume did not stage the owed receipt"
    );

    // Drive B's receipt to Stored: B's marker reaches its water and B's
    // debt (1) is covered.
    let b_receipt = b
        .pending_send_actions()?
        .into_iter()
        .next()
        .ok_or("no b receipt action")?;
    relay.enqueue(&b_receipt.request, NOW)?;
    b.record_send_result(&b_receipt, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&b)?, 1);

    // A accepts B's receipt IN ORDER (B.seq 5 is exactly A's HCR 4 + 1):
    // it applies and stages NO counter-receipt — A consumed nothing, so
    // A has no debt. (The relay still holds the consumed fixture
    // envelopes; select the receipt by its message ID.)
    let fetch = a.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let envelope = envelopes
        .iter()
        .find(|envelope| envelope.message_id == b_receipt.request.message_id)
        .ok_or("no receipt envelope")?;
    let outcome = a.accept_envelope(
        envelope.queue_id,
        envelope.message_id,
        envelope.packet.clone(),
        envelope.expires_at,
        envelope.sender_signature,
        NOW,
    )?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    assert!(
        a.pending_send_actions()?.is_empty(),
        "A staged a counter-receipt"
    );
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.highest_contiguous_received_seq, 5);
        assert_eq!(active.receipt_debt_up_to, 0);
        assert_eq!(active.last_delivered_receipt_high_water, 0);
    }

    // Two peers drain to idle: mutators past every tombstone window
    // prune and stage nothing but the requested application body.
    let a_dedup = a.state.dedup.len();
    let b_dedup = b.state.dedup.len();
    let idle = NOW + 15 * 24 * 60 * 60 + 1;
    a.stage_send("a-idle", idle, idle + 3_600, idle)?;
    b.stage_send("b-idle", idle, idle + 3_600, idle)?;
    assert_eq!(a.state.sends.len(), 1, "A did not drain to idle");
    assert_eq!(b.state.sends.len(), 1, "B did not drain to idle");
    assert_eq!(a.state.dedup.len(), a_dedup);
    assert_eq!(b.state.dedup.len(), b_dedup);
    Ok(())
}

/// Sol's P1-3 closure (control priority, honest outcome): when a prune
/// frees exactly one slot, the owed receipt COMMITS into it and the
/// application attempt returns `ReceiptFlushedRetry` — no discarded
/// candidate, no loop; the retry succeeds once another slot frees.
#[test]
fn owed_receipt_wins_freed_slot_over_application_send() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, b, mut relay) = conversation_fixture()?;
    // Consume m1 to create the debt whose receipt must win the slot.
    accept_and_consume(&mut a, &mut relay, 0, "m1")?;
    fill_outbox(&mut a, &b)?;

    // Stagger two terminal records' tombstones; every other record
    // outlives the test window, so exactly one slot frees at t1 and a
    // second at t2. The receipt for A's consumed water of 1 stays owed
    // (the delivered marker is 0).
    for record in &mut a.state.sends {
        match record.sequence {
            31 => record.expires_at = NOW + 3_600,
            32 => record.expires_at = NOW + 3_600 + 100,
            _ => record.expires_at = NOW + 90 * 24 * 60 * 60,
        }
    }
    let t1 = NOW + 3_600 + 7 * 24 * 60 * 60 + 1;

    // One slot frees: the owed receipt claims it AND COMMITS (review D2b
    // v5 P1-3); the application body gets the honest, retryable outcome
    // instead of a discarded candidate.
    let outcome = a.stage_send("app-1", t1, t1 + 3_600, t1)?;
    assert!(
        matches!(outcome, super::StageSendOutcome::ReceiptFlushedRetry),
        "expected ReceiptFlushedRetry"
    );
    assert_eq!(a.state.sends.len(), 32, "the flush did not commit");
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1, "the flushed receipt is not pending");
    assert_eq!(receipts[0].high_water, Some(1));
    assert_eq!(receipts[0].sequence, 33);

    // The retry (past the second tombstone) finds the receipt already in
    // flight, stages nothing new, and admits the application body.
    let t2 = t1 + 100;
    let app = stage_app(&mut a, "app-1", t2, t2 + 3_600, t2)?;
    assert_eq!(a.state.sends.len(), 32);
    let app_record = a
        .state
        .sends
        .iter()
        .find(|record| record.message_id == app.request.message_id)
        .ok_or("no app record")?;
    assert_eq!(app_record.sequence, 34);
    assert_eq!(
        pending_receipts(&a).len(),
        1,
        "the in-flight receipt was replaced"
    );
    Ok(())
}

/// A forged-but-authentic receipt envelope from B to A: a genuine
/// B-signed `HighWaterReceipt` payload, encrypted with B's real session
/// and signed for A's mailbox exactly like `stage_receipt` does.
/// `issuer_outstanding` is the congestion signal the payload carries
/// (review D2b v7); callers pass the honest sample or a test override.
fn forge_receipt_envelope(
    b: &mut PersistentClient<TestProtector>,
    a: &PersistentClient<TestProtector>,
    high_water: u64,
    send_seq: u64,
    now: u64,
    issuer_outstanding: u64,
) -> std::result::Result<
    (MessageId, EncryptedPacket, vodozemac::Ed25519Signature, u64),
    Box<dyn Error>,
> {
    let session = b.session.as_mut().ok_or("no b session")?;
    let epoch_id = super::epoch_of(session.session_keys());
    let mut receipt = crate::state::HighWaterReceipt {
        conversation_id: a.state.conversation_id,
        epoch_id,
        acknowledged_sender_curve: a.account.curve25519_key(),
        issuer_curve: b.account.curve25519_key(),
        high_water,
        signature: b.account.sign(b""),
    };
    receipt.signature = b.account.sign(super::receipt_signing_bytes(&receipt));
    let message_id = MessageId::random();
    let outgoing = payload::ClientPayloadV2 {
        version: payload::PAYLOAD_VERSION,
        conversation_id: a.state.conversation_id,
        message_id,
        epoch_id,
        send_seq,
        sent_at: now,
        kind: payload::KIND_RECEIPT,
        body: None,
        receipt: Some(payload::ReceiptV2::from(&receipt)),
        issuer_outstanding,
    };
    let encoded = payload::encode(&outgoing)?;
    let message = session.encrypt(&encoded[..])?;
    let packet = EncryptedPacket::from_untrusted(serde_json::to_vec(&message)?);
    let queue_a = a.state.mailbox_queue_id;
    let expires_at = now + 3_600;
    let signature = a.keypairs.send.sign(&super::send_signing_bytes(
        queue_a,
        message_id,
        &packet.digest(),
        expires_at,
    ));
    Ok((message_id, packet, signature, expires_at))
}

/// Blocker 4 fixture: A has accepted one message (HCR 1, the hw-1
/// receipt record dropped in-crate), then is driven to the given mode
/// with outstanding 32 — owed, unlocked capacity, only the mode blocks.
fn locked_fixture(mode: SessionMode) -> std::result::Result<ConversationFixture, Box<dyn Error>> {
    let (a_dir, b_dir, mut a, b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    a.state.sends.clear();
    let active = a.state.active_session.as_mut().ok_or("no session")?;
    active.last_assigned_send_seq = 32;
    active.mode = mode;
    Ok((a_dir, b_dir, a, b, relay))
}

/// Blocker 4: a `ReceiptLocked` peer whose budget is freed by an inbound
/// receipt stages its previously owed receipt in the SAME accept pass —
/// the mode is recomputed from the fresh high water BEFORE owed staging.
#[test]
fn receipt_locked_recovery_stages_owed_receipt_in_accept_pass()
-> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, _relay) = locked_fixture(SessionMode::ReceiptLocked)?;

    // While locked, a clock-taking mutator commits but stages nothing.
    let inbound = a.pending_inbound()?;
    let message_id = inbound.first().ok_or("no inbound")?.message_id;
    a.consume_inbound(message_id, NOW + 300, NOW)?;
    assert!(a.state.sends.is_empty(), "staged while ReceiptLocked");

    // The peer's receipt covering all 32 outstanding sends arrives IN
    // ORDER (B.seq 2 == A's HCR + 1): the accept applies it, recomputes
    // the mode, and stages the owed receipt in this same pass.
    let b_signal = outstanding(&b)?;
    let (message_id, packet, signature, expires_at) =
        forge_receipt_envelope(&mut b, &a, 32, 2, NOW, b_signal)?;
    let queue_id = a.state.mailbox_queue_id;
    let outcome = a.accept_envelope(queue_id, message_id, packet, expires_at, signature, NOW)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    assert_eq!(active_mode(&a)?, SessionMode::Ready);
    let receipts = pending_receipts(&a);
    assert_eq!(
        receipts.len(),
        1,
        "the owed receipt did not stage in the accept pass"
    );
    let receipt = receipts.first().ok_or("no receipt")?;
    assert_eq!(receipt.high_water, Some(2));
    assert_eq!(receipt.sequence, 33);
    assert_eq!(delivered_marker(&a)?, 0, "staging is not delivery");
    Ok(())
}

/// Blocker 4 dominance, updated for the v8 inbound lock: under
/// `RekeyRequired` the same forged receipt now REJECTS at the top of
/// the bounds (review D2b v8 P1-1) — no application, no staging, no
/// commit — and the mode is never recomputed away.
#[test]
fn rekey_required_still_blocks_owed_staging_after_receipt()
-> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, _relay) = locked_fixture(SessionMode::RekeyRequired)?;
    let b_signal = outstanding(&b)?;
    let (message_id, packet, signature, expires_at) =
        forge_receipt_envelope(&mut b, &a, 32, 2, NOW, b_signal)?;
    let queue_id = a.state.mailbox_queue_id;
    let generation_before = a.store.generation()?;
    let result = a.accept_envelope(queue_id, message_id, packet, expires_at, signature, NOW);
    assert!(result.is_err(), "a packet was accepted under RekeyRequired");
    assert_eq!(
        active_mode(&a)?,
        SessionMode::RekeyRequired,
        "RekeyRequired was recomputed away"
    );
    assert!(a.state.sends.is_empty(), "staged while RekeyRequired");
    assert_eq!(
        a.store.generation()?,
        generation_before,
        "the locked accept committed"
    );
    Ok(())
}

// --- D2b v5 remediation tests (Sol's four P1 interleavings) -------------------

/// P1-1: a newer receipt arriving before an older one applies its high
/// water; the older one then lands as a content no-op (`ReceiptIdempotent`)
/// and COMMITS its sequence/dedup progress — while a future high water
/// still hard-errors and discards everything.
#[test]
fn reordered_receipts_commit_sequence_progress() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;

    // A accepts B's four sends (HCR 4), then sends two application
    // bodies to B (A.seq 1..=2).
    let outcomes = deliver(&mut a, &mut relay, &[0, 1, 2, 3])?;
    assert!(outcomes.iter().all(Result::is_ok));
    for body in ["app-1", "app-2"] {
        let action = stage_app(&mut a, body, NOW, NOW + 3_600, NOW)?;
        relay.enqueue(&action.request, NOW)?;
        a.record_send_result(&action, SendOutcome::Stored)?;
    }

    // B accepts both (HCR 2) and consumes both: two owed receipts
    // (B.seq 5 hw 1, B.seq 6 hw 2).
    let fetch = b.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    assert_eq!(envelopes.len(), 2);
    for envelope in &envelopes {
        let outcome = b.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            NOW,
        )?;
        let AcceptOutcome::Application(message_id) = outcome else {
            return Err("application not accepted".into());
        };
        b.consume_inbound(message_id, NOW + 300, NOW)?;
    }
    assert_eq!(b.pending_send_actions()?.len(), 2);
    let mut receipt_actions = b.pending_send_actions()?;
    receipt_actions.sort_by_key(|action| {
        b.state
            .sends
            .iter()
            .find(|record| record.message_id == action.request.message_id)
            .map_or(u64::MAX, |record| record.sequence)
    });
    let older_receipt_id = receipt_actions[0].request.message_id;
    let newer_receipt_id = receipt_actions[1].request.message_id;
    for action in &receipt_actions {
        relay.enqueue(&action.request, NOW)?;
        b.record_send_result(action, SendOutcome::Stored)?;
    }

    // A takes the NEWER receipt (B.seq 6) first: its high water (2)
    // applies while the packet sits in the out-of-order set.
    let fetch = a.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let accept = |a: &mut PersistentClient<TestProtector>, id: MessageId| {
        let envelope = envelopes
            .iter()
            .find(|envelope| envelope.message_id == id)
            .ok_or(LabError::Storage)?;
        a.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            NOW,
        )
    };
    let outcome = accept(&mut a, newer_receipt_id)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.peer_contiguous_high_water, 2);
        assert_eq!(active.highest_contiguous_received_seq, 4);
        assert_eq!(active.received_above_high_water, vec![6]);
    }

    // The OLDER receipt (B.seq 5) then drains the water: its high water
    // (1) regresses against the applied 2, so it is a content no-op —
    // but the packet's sequence and dedup progress COMMIT (P1-1).
    let outcome = accept(&mut a, older_receipt_id)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptIdempotent);
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.peer_contiguous_high_water, 2);
        assert_eq!(active.highest_contiguous_received_seq, 6);
        assert!(active.received_above_high_water.is_empty());
    }
    assert!(
        a.state
            .dedup
            .iter()
            .any(|record| record.message_id == older_receipt_id),
        "the reordered receipt's dedup record did not commit"
    );

    // A future high water remains a forgery class: hard error, and
    // nothing (not even the sequence insert) commits.
    let (forged_id, forged_packet, forged_sig, forged_exp) =
        forge_receipt_envelope(&mut b, &a, 99, 7, NOW, 0)?;
    let queue_id = a.state.mailbox_queue_id;
    let outcome = a.accept_envelope(
        queue_id,
        forged_id,
        forged_packet,
        forged_exp,
        forged_sig,
        NOW,
    );
    assert!(matches!(outcome, Err(LabError::InvalidPayload)));
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.highest_contiguous_received_seq, 6);
        assert!(active.received_above_high_water.is_empty());
    }
    Ok(())
}

/// P1-2/P1-3: at 23 outstanding with receipt debt, the owed receipt
/// stages and its sequence advance pushes the session to `ControlOnly` —
/// the application body is refused with `ReceiptFlushedRetry` (the
/// receipt commits); after a peer receipt frees the budget, the retry
/// stages.
#[test]
fn owed_receipt_crossing_control_threshold_rejects_application()
-> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;
    // Consume m1 to create the debt, then drive the session to 23
    // outstanding with no pending receipt record (the debt is owed).
    accept_and_consume(&mut a, &mut relay, 0, "m1")?;
    a.state.sends.clear();
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 23;
    }

    // The application attempt stages the owed receipt first (sequence
    // 24), which pushes outstanding to 24 (`ControlOnly`): the body is
    // refused with the honest flush outcome and the receipt commits.
    let outcome = a.stage_send("body", NOW, NOW + 3_600, NOW)?;
    assert!(
        matches!(outcome, super::StageSendOutcome::ReceiptFlushedRetry),
        "expected ReceiptFlushedRetry"
    );
    assert_eq!(active_mode(&a)?, SessionMode::ControlOnly);
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1, "the receipt did not commit");
    assert_eq!(receipts[0].sequence, 24);
    assert_eq!(receipts[0].high_water, Some(1));

    // A peer receipt covering all 24 outstanding sends frees the budget;
    // the retry stages the body (mode recomputed before the decision).
    let b_signal = outstanding(&b)?;
    let (message_id, packet, signature, expires_at) =
        forge_receipt_envelope(&mut b, &a, 24, 2, NOW, b_signal)?;
    let queue_id = a.state.mailbox_queue_id;
    let outcome = a.accept_envelope(queue_id, message_id, packet, expires_at, signature, NOW)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    assert_eq!(active_mode(&a)?, SessionMode::Ready);
    let outcome = a.stage_send("body", NOW, NOW + 3_600, NOW)?;
    assert!(
        matches!(outcome, super::StageSendOutcome::Staged(_)),
        "the retry did not stage the body"
    );
    Ok(())
}

/// P1-4, Sol's exact scenario: an application consumed while a receipt
/// payload is missing creates debt that nothing can report yet; when the
/// receipt arrives and drains the water, the SAME accept pass stages the
/// receipt reporting the new water — and a pure receipt-only exchange
/// still stages nothing.
#[test]
fn gap_filling_receipt_stages_consumed_debt_in_same_pass() -> std::result::Result<(), Box<dyn Error>>
{
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;

    // Baseline: consume m1 and deliver its receipt to Stored — the books
    // are balanced (debt 1, delivered marker 1, contiguous water 1).
    accept_and_consume(&mut a, &mut relay, 0, "m1")?;
    let action = a
        .pending_send_actions()?
        .into_iter()
        .next()
        .ok_or("no receipt action")?;
    relay.enqueue(&action.request, NOW)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 1);

    // B's seq-3 application arrives while seq 2 (a receipt payload) is
    // missing: it lands in the out-of-order set. Consuming it creates
    // debt 3, but nothing stages — the contiguous water (1) is not
    // ahead of the marker (1), so there is nothing new to report.
    let queue_id = a.state.mailbox_queue_id;
    let conversation_id = a.state.conversation_id;
    let b_signal = outstanding(&b)?;
    let (app_id, app_packet, app_sig) = {
        let session = b.session.as_mut().ok_or("no b session")?;
        raw_peer_envelope(session, &a, conversation_id, 3, b_signal)?
    };
    let outcome = a.accept_envelope(queue_id, app_id, app_packet, NOW + 3_600, app_sig, NOW)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    a.consume_inbound(app_id, NOW + 300, NOW)?;
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.highest_contiguous_received_seq, 1);
        assert_eq!(active.received_above_high_water, vec![3]);
        assert_eq!(active.receipt_debt_up_to, 3);
    }
    assert!(
        pending_receipts(&a).is_empty(),
        "staged while the water was not ahead of the marker"
    );

    // B's seq-2 receipt arrives (hw 1, applied): the water drains to 3,
    // and the SAME accept pass stages the receipt reporting HCR 3 —
    // debt 3 ahead of the marker 1, water 3 ahead of the marker.
    let b_signal = outstanding(&b)?;
    let (rcpt_id, rcpt_packet, rcpt_sig, rcpt_exp) =
        forge_receipt_envelope(&mut b, &a, 1, 2, NOW, b_signal)?;
    let outcome = a.accept_envelope(queue_id, rcpt_id, rcpt_packet, rcpt_exp, rcpt_sig, NOW)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.highest_contiguous_received_seq, 3);
        assert!(active.received_above_high_water.is_empty());
    }
    let receipts = pending_receipts(&a);
    assert_eq!(
        receipts.len(),
        1,
        "the consumed debt did not stage in the same accept pass"
    );
    assert_eq!(receipts[0].high_water, Some(3));
    assert_eq!(receipts[0].sequence, 2);

    // Pure receipt-only exchange still stages nothing: once the hw-3
    // receipt is Stored, another in-order receipt creates no debt and
    // no staging (quiescence by construction).
    let action = a
        .pending_send_actions()?
        .into_iter()
        .next()
        .ok_or("no hw-3 action")?;
    relay.enqueue(&action.request, NOW)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 3);
    let b_signal = outstanding(&b)?;
    let (id2, packet2, sig2, exp2) = forge_receipt_envelope(&mut b, &a, 1, 4, NOW, b_signal)?;
    let outcome = a.accept_envelope(queue_id, id2, packet2, exp2, sig2, NOW)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptIdempotent);
    assert!(
        pending_receipts(&a).is_empty(),
        "a receipt-only accept staged a receipt"
    );
    Ok(())
}

// --- D2b v6 remediation tests (threshold-armed control debt) ------------------

/// Outstanding = `last_assigned_send_seq - peer_contiguous_high_water`.
fn outstanding(
    client: &PersistentClient<TestProtector>,
) -> std::result::Result<u64, Box<dyn Error>> {
    let active = client.state.active_session.as_ref().ok_or("no session")?;
    Ok(active.last_assigned_send_seq - active.peer_contiguous_high_water)
}

/// Drive every pending send action through the relay in send-sequence
/// order, recording `Stored` for each; returns how many were driven.
fn drive_pending(
    client: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    now: u64,
) -> std::result::Result<usize, Box<dyn Error>> {
    let mut actions = client.pending_send_actions()?;
    actions.sort_by_key(|action| {
        client
            .state
            .sends
            .iter()
            .find(|record| record.message_id == action.request.message_id)
            .map_or(u64::MAX, |record| record.sequence)
    });
    let count = actions.len();
    for action in &actions {
        relay.enqueue(&action.request, now)?;
        client.record_send_result(action, SendOutcome::Stored)?;
    }
    Ok(count)
}

/// Fetch and accept every waiting envelope in relay order. The relay
/// holds envelopes until expiry, so already-accepted backlog comes back
/// as duplicates and is skipped; every other error propagates.
fn fetch_and_accept_all(
    client: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    now: u64,
) -> std::result::Result<Vec<AcceptOutcome>, Box<dyn Error>> {
    let fetch = client.fetch_request(now + 60, now)?;
    let envelopes = relay.fetch(&fetch.request, now)?;
    let mut outcomes = Vec::new();
    for envelope in &envelopes {
        match client.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            now,
        ) {
            Ok(outcome) => outcomes.push(outcome),
            Err(LabError::DuplicateMessage) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(outcomes)
}

/// One round of the one-directional flood: B stages applications until
/// its budget refuses more (driving each, including any armed
/// receipt-flush), then A accepts and consumes everything, and the
/// receipt exchanges both ways are driven. Returns the number of
/// receipts each side drove this round `(a_drove, b_drove)`.
fn flood_round(
    a: &mut PersistentClient<TestProtector>,
    b: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    now: u64,
    round: u64,
) -> std::result::Result<(usize, usize), Box<dyn Error>> {
    // B floods applications until its budget refuses more. After EVERY
    // stage_send, drive everything pending in send-sequence order: an
    // armed control receipt may have staged inside the operation AHEAD
    // of the application body, and the peer must see envelopes in
    // sequence order (a skipped sequence gaps the receiver's water).
    let mut staged_this_round = 0_u32;
    for index in 0..40_u32 {
        let body = format!("r{round}-m{index}");
        match b.stage_send(&body, now, now + 3_600, now) {
            Ok(super::StageSendOutcome::Staged(_)) => {
                drive_pending(b, relay, now)?;
                staged_this_round += 1;
            }
            Ok(super::StageSendOutcome::ReceiptFlushedRetry) => {
                drive_pending(b, relay, now)?;
            }
            Err(_) => break,
        }
    }
    assert!(
        staged_this_round > 0,
        "B made no application progress in round {round}"
    );
    // A accepts and consumes one envelope at a time, so each consume
    // can stage for the freshest water.
    let outcomes = fetch_and_accept_all(a, relay, now)?;
    for outcome in outcomes {
        if let AcceptOutcome::Application(message_id) = outcome {
            a.consume_inbound(message_id, now + 300, now)?;
        }
    }
    let a_drove = drive_pending(a, relay, now)?;
    fetch_and_accept_all(b, relay, now)?;
    let b_drove = drive_pending(b, relay, now)?;
    fetch_and_accept_all(a, relay, now)?;
    drive_pending(a, relay, now)?;
    Ok((a_drove, b_drove))
}

/// Sol's one-directional reproduction (P1): B floods A with
/// application traffic across 15-day clock jumps. The v6 head wedged A
/// permanently at `ReceiptLocked`; with threshold-armed control debt
/// neither side ever locks, A keeps staging receipts, B keeps
/// draining, and B's armed counter-receipts give A's own sends their
/// drain path (B has zero application debt throughout).
#[test]
fn one_directional_traffic_never_deadlocks_budget() -> std::result::Result<(), Box<dyn Error>> {
    const ROUND_SECONDS: u64 = 15 * 24 * 60 * 60;
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;

    let mut last_hcr = 0_u64;
    let mut b_counter_receipted = false;
    for round in 0..8_u64 {
        // Round 0 runs at NOW: A's inbound session is established from
        // B's first envelope and the prekey bundle (valid_until NOW+300)
        // must still be live. Later rounds jump 15 days for pruning.
        let now = NOW + round * ROUND_SECONDS;
        let (a_drove, _b_drove) = flood_round(&mut a, &mut b, &mut relay, now, round)
            .map_err(|error| format!("round {round}: {error:?}"))?;
        assert_ne!(
            active_mode(&a)?,
            SessionMode::ReceiptLocked,
            "A locked in {round}"
        );
        assert_ne!(
            active_mode(&b)?,
            SessionMode::ReceiptLocked,
            "B locked in {round}"
        );
        assert!(
            outstanding(&a)? < 32,
            "A's outstanding hit the lock in {round}"
        );
        assert!(
            outstanding(&b)? < 32,
            "B's outstanding hit the lock in {round}"
        );
        let hcr = a
            .state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .highest_contiguous_received_seq;
        assert!(hcr > last_hcr, "no water progress in round {round}");
        last_hcr = hcr;
        // A is the receiver: it consumes and keeps staging receipts.
        assert!(a_drove > 0, "A staged no receipt in round {round}");
        // The control-arm proof: B NEVER consumes (application debt 0),
        // so any receipt-kind record in B's outbox can only come from
        // the armed control debt — and A's peer high water advancing is
        // the end-to-end proof that B's counter-receipts drain A.
        assert_eq!(
            b.state
                .active_session
                .as_ref()
                .ok_or("no session")?
                .receipt_debt_up_to,
            0,
            "B acquired application debt"
        );
        if b.state
            .sends
            .iter()
            .any(|record| record.kind == crate::state::SendKind::Receipt)
        {
            b_counter_receipted = true;
        }
    }
    assert!(
        b_counter_receipted,
        "B never counter-receipted: the armed control debt never fired"
    );
    let a_peer_hw = a
        .state
        .active_session
        .as_ref()
        .ok_or("no session")?
        .peer_contiguous_high_water;
    assert!(
        a_peer_hw > 0,
        "A's own sends were never acknowledged: no drain path back"
    );
    Ok(())
}

/// Convergence (P1 quiescence arm): after congested rounds, stop all
/// application traffic and let the receipt exchange run — both sides
/// drain below the `ControlOnly` threshold, arming stops, and NO
/// further receipts stage (no counter-receipt storm: record counts
/// stabilize).
#[test]
fn control_debt_converges_without_counter_receipt_storm() -> std::result::Result<(), Box<dyn Error>>
{
    const ROUND_SECONDS: u64 = 15 * 24 * 60 * 60;
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;

    // Congest: four flooded rounds (round 0 at NOW so A's inbound
    // session establishes inside the prekey bundle's validity).
    for round in 0..4_u64 {
        let now = NOW + round * ROUND_SECONDS;
        flood_round(&mut a, &mut b, &mut relay, now, round)?;
    }

    // Quiesce: no new application bodies, only the receipt exchange.
    let mut drained_below_threshold = false;
    for round in 4..7_u64 {
        let now = NOW + round * ROUND_SECONDS;
        // Only fetches and drives — no stage_send attempts at all.
        let outcomes = fetch_and_accept_all(&mut a, &mut relay, now)?;
        for outcome in outcomes {
            if let AcceptOutcome::Application(message_id) = outcome {
                a.consume_inbound(message_id, now + 300, now)?;
            }
        }
        let a_drove = drive_pending(&mut a, &mut relay, now)?;
        fetch_and_accept_all(&mut b, &mut relay, now)?;
        let b_drove = drive_pending(&mut b, &mut relay, now)?;
        fetch_and_accept_all(&mut a, &mut relay, now)?;
        drive_pending(&mut a, &mut relay, now)?;
        if outstanding(&a)? < 24 && outstanding(&b)? < 24 {
            drained_below_threshold = true;
            assert_eq!(
                a_drove + b_drove,
                0,
                "a receipt staged while both sides were uncongested"
            );
        }
    }
    assert!(
        drained_below_threshold,
        "the exchange never drained below the threshold"
    );
    // Record counts stabilize once the water is reported: one more
    // quiet round changes nothing on either side.
    let now = NOW + 8 * ROUND_SECONDS;
    let (a_sends, b_sends, a_dedup, b_dedup) = (
        a.state.sends.len(),
        b.state.sends.len(),
        a.state.dedup.len(),
        b.state.dedup.len(),
    );
    fetch_and_accept_all(&mut a, &mut relay, now)?;
    drive_pending(&mut a, &mut relay, now)?;
    fetch_and_accept_all(&mut b, &mut relay, now)?;
    drive_pending(&mut b, &mut relay, now)?;
    assert_eq!(a.state.sends.len(), a_sends, "A kept staging");
    assert_eq!(b.state.sends.len(), b_sends, "B kept staging");
    assert_eq!(a.state.dedup.len(), a_dedup);
    assert_eq!(b.state.dedup.len(), b_dedup);
    Ok(())
}

/// `ReceiptLocked` recovery (P1 + v8 P1-3b): with zero application
/// debt, A's congested accept arms the control debt AND flushes it in
/// the SAME pass (arm-first tail); at the lock, a genuine peer receipt
/// lowers outstanding and its fresh low signal supersedes the arm — no
/// replacement stages while the first is in flight.
#[test]
fn receipt_locked_recovers_and_armed_control_debt_stages() -> std::result::Result<(), Box<dyn Error>>
{
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;

    // A accepts m1 (uncongested — no arming), then m2 with its send
    // counter fabricated to 24 outstanding: the congested accept arms
    // the control debt with ZERO application debt (nothing consumed) —
    // and the v8 arm-first tail flushes it in THIS SAME accept pass.
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 24;
        // Keep the stored mode consistent with the fabricated water:
        // `stage()` re-validates the current state before every mutator.
        active.mode = SessionMode::ControlOnly;
    }
    let outcomes = deliver(&mut a, &mut relay, &[1])?;
    assert!(outcomes.iter().all(Result::is_ok));
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(
            active.control_debt_up_to, 2,
            "the congested accept did not raise the debt water"
        );
        assert_eq!(active.receipt_debt_up_to, 0);
        assert_eq!(active.last_delivered_receipt_high_water, 0);
    }
    let receipts = pending_receipts(&a);
    assert_eq!(
        receipts.len(),
        1,
        "the newly armed debt did not flush in the same accept pass"
    );
    assert_eq!(receipts[0].high_water, Some(2));
    assert_eq!(receipts[0].sequence, 25);

    // Drive the session to the lock; §4 gates all staging there, and the
    // in-flight receipt blocks any replacement anyway.
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 32;
        active.mode = SessionMode::ReceiptLocked;
    }

    // A genuine peer receipt covering all 32 sends arrives IN ORDER
    // (B.seq 3): it applies, the mode recomputes to Ready, and A's entry
    // congestion sample (32) re-arms in the same pass even as B's low
    // signal clears — locally congested means locally armed. The
    // in-flight receipt blocks any replacement regardless.
    let b_signal = outstanding(&b)?;
    let (message_id, packet, signature, expires_at) =
        forge_receipt_envelope(&mut b, &a, 32, 3, NOW, b_signal)?;
    let queue_id = a.state.mailbox_queue_id;
    let outcome = a.accept_envelope(queue_id, message_id, packet, expires_at, signature, NOW)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    assert_eq!(active_mode(&a)?, SessionMode::Ready);
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(
            active.control_debt_up_to, 3,
            "local entry congestion (32) should raise the debt water to the HCR"
        );
        assert_eq!(active.last_delivered_receipt_high_water, 0);
    }
    let receipts = pending_receipts(&a);
    assert_eq!(
        receipts.len(),
        1,
        "a replacement staged while the first receipt was in flight"
    );
    assert_eq!(receipts[0].high_water, Some(2));
    Ok(())
}

// --- D2b v7 remediation tests (peer-signaled congestion) ----------------------

/// Signal-vs-local independence (P1): the two arming sources fire
/// independently — a peer reporting 0 does not suppress the local arm,
/// and a peer reporting congestion arms an uncongested acceptor.
#[test]
fn congestion_signal_and_local_arm_are_independent() -> std::result::Result<(), Box<dyn Error>> {
    // Part 1: local arm with a SILENT peer — A at 24 outstanding accepts
    // a payload reporting issuer_outstanding 0; the local sample arms.
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 24;
        active.mode = SessionMode::ControlOnly;
    }
    let queue_id = a.state.mailbox_queue_id;
    let conversation_id = a.state.conversation_id;
    let (app_id, app_packet, app_sig) = {
        let session = b.session.as_mut().ok_or("no b session")?;
        raw_peer_envelope(session, &a, conversation_id, 2, 0)?
    };
    let outcome = a.accept_envelope(queue_id, app_id, app_packet, NOW + 3_600, app_sig, NOW)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .control_debt_up_to,
        2,
        "the local arm did not fire past a silent (0) peer signal"
    );

    // Part 2: signal arm with an UNCONGESTED acceptor — a fresh pair; A
    // at 0 outstanding accepts a payload reporting issuer_outstanding
    // 24; the peer signal arms.
    let (_a2_dir, _b2_dir, mut a2, mut b2, mut relay2) = conversation_fixture()?;
    let outcomes = deliver(&mut a2, &mut relay2, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    assert_eq!(outstanding(&a2)?, 0);
    let queue_id = a2.state.mailbox_queue_id;
    let conversation_id = a2.state.conversation_id;
    let (app_id, app_packet, app_sig) = {
        let session = b2.session.as_mut().ok_or("no b2 session")?;
        raw_peer_envelope(session, &a2, conversation_id, 2, 24)?
    };
    let outcome = a2.accept_envelope(queue_id, app_id, app_packet, NOW + 3_600, app_sig, NOW)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    assert_eq!(
        a2.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .control_debt_up_to,
        2,
        "the peer signal did not arm an uncongested acceptor"
    );
    Ok(())
}

/// The staged payload's congestion signal equals the local outstanding
/// (`last_assigned_send_seq - peer_contiguous_high_water`) sampled as
/// the POST-advance count at staging time (v8 P1-3: the send's own
/// sequence counts, so the 24th send reports 24 and signals) — verified
/// by decrypting the wire packets with a CLONE of the peer's session
/// (its ratchet is left untouched).
#[test]
fn staged_payloads_carry_the_local_outstanding() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let mut peer_clone =
        vodozemac::olm::Session::from_pickle(b.session.as_ref().ok_or("no b session")?.pickle());
    let mut decode_next = |packet: &EncryptedPacket| -> std::result::Result<u64, Box<dyn Error>> {
        let olm_message: vodozemac::olm::OlmMessage = serde_json::from_slice(packet.as_bytes())?;
        let plaintext = peer_clone
            .decrypt(&olm_message)
            .map_err(|_| "clone decrypt failed")?;
        Ok(payload::decode(&plaintext)?.issuer_outstanding)
    };

    // Uncongested: A's first send carries 1 (its own sequence counts).
    let first = stage_app(&mut a, "ping", NOW, NOW + 3_600, NOW)?;
    assert_eq!(decode_next(&first.request.packet)?, 1);

    // Fabricate 8 outstanding: the next send carries 9 (8 + its own
    // advance).
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 8;
    }
    let second = stage_app(&mut a, "ping2", NOW, NOW + 3_600, NOW)?;
    assert_eq!(decode_next(&second.request.packet)?, 9);

    // The threshold case (v8 P1-3): at 23 outstanding the next send is
    // the 24th and REPORTS 24 — it signals, where the pre-advance
    // sample (23) never would have.
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 23;
    }
    let third = stage_app(&mut a, "ping3", NOW, NOW + 3_600, NOW)?;
    assert_eq!(decode_next(&third.request.packet)?, 24);
    Ok(())
}

/// Fable's lockstep reproduction (P1): one staged body per round with a
/// prompt consume and receipt, ~60 rounds with 8-day clock jumps. The v7
/// head (local-only arm) wedged A at `ReceiptLocked` permanently; with
/// the peer-signaled arm, A's receipts signal the congestion, B arms and
/// counter-receipts, and A drains back below the threshold.
#[test]
fn lockstep_traffic_never_deadlocks_budget() -> std::result::Result<(), Box<dyn Error>> {
    const ROUND_SECONDS: u64 = 6 * 24 * 60 * 60;
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;

    let mut last_hcr = 0_u64;
    for round in 0..60_u64 {
        // Round 0 runs at NOW so A's inbound session establishes inside
        // the prekey bundle's validity. Each round jumps 6 days — under
        // the 7-day message TTL, so a receipt staged late in a round
        // still reaches the peer next round; tombstone pruning then
        // keeps the arrays small every other round.
        let now = NOW + round * ROUND_SECONDS;
        // One staged body per round (B's budget is drained each round).
        // Drive EVERYTHING pending in sequence order right after the
        // stage: an armed counter-receipt may precede the body in
        // sequence, and the peer must see envelopes in order.
        let _action = stage_app(&mut b, &format!("lockstep-{round}"), now, now + 3_600, now)?;
        drive_pending(&mut b, &mut relay, now)?;
        // A accepts and consumes it; its owed receipt is driven back.
        let outcomes = fetch_and_accept_all(&mut a, &mut relay, now)?;
        for outcome in outcomes {
            if let AcceptOutcome::Application(message_id) = outcome {
                a.consume_inbound(message_id, now + 300, now)?;
            }
        }
        drive_pending(&mut a, &mut relay, now)?;
        // B accepts A's receipt(s); if A's payload now signals
        // congestion, B arms and counter-receipts; drive everything.
        let _b_outcomes = fetch_and_accept_all(&mut b, &mut relay, now)?;
        drive_pending(&mut b, &mut relay, now)?;
        // A accepts B's counter-receipt(s); A drains.
        fetch_and_accept_all(&mut a, &mut relay, now)?;
        drive_pending(&mut a, &mut relay, now)?;

        assert_ne!(
            active_mode(&a)?,
            SessionMode::ReceiptLocked,
            "A locked in {round}"
        );
        assert_ne!(
            active_mode(&b)?,
            SessionMode::ReceiptLocked,
            "B locked in {round}"
        );
        assert!(
            outstanding(&a)? < 32,
            "A's outstanding hit the lock in {round}"
        );
        assert!(
            outstanding(&b)? < 32,
            "B's outstanding hit the lock in {round}"
        );
        let hcr = a
            .state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .highest_contiguous_received_seq;
        assert!(hcr > last_hcr, "no water progress in round {round}");
        last_hcr = hcr;
        // In lockstep B is never locally congested, so every
        // counter-receipt B produces is driven by A's SIGNAL alone.
        assert!(
            outstanding(&b)? < 24,
            "B congested locally in round {round} — the signal proof is gone"
        );
    }
    // A's receipt sends crossed the signal threshold (its 24th send
    // reports 24, v8 P1-3), B counter-receipted on that signal (never
    // on its own budget), and the same-pass flush kept A below the lock
    // at every round end.
    let active = a.state.active_session.as_ref().ok_or("no session")?;
    assert!(
        active.last_assigned_send_seq >= 24,
        "A's receipt sends never reached the signal threshold"
    );
    assert!(
        active.peer_contiguous_high_water > 0,
        "B never counter-receipted on A's congestion signal"
    );
    Ok(())
}

/// The action of the newest pending receipt-kind send (by sequence).
fn newest_receipt_action(
    client: &PersistentClient<TestProtector>,
) -> std::result::Result<super::DurableAction<crate::capability::SendRequest>, Box<dyn Error>> {
    let receipts = pending_receipts(client);
    let newest = receipts.last().ok_or("no pending receipt")?;
    client
        .pending_send_actions()?
        .into_iter()
        .find(|action| action.request.message_id == newest.message_id)
        .ok_or("no receipt action".into())
}

/// Phase 1 of the both-stuck corner: 24 interleaved rounds of B staging
/// one application body and A accepting+consuming it, so A's 24 wire
/// receipts are staged BEFORE A congests. The first 23 are enqueued
/// (never confirmed — A's delivered marker stays 0 and B never
/// fetches); the 24th is left off the wire on purpose: with POST-advance
/// sampling (v8 P1-3) it would report 24 and put a signal on the wire,
/// and this test must prove the local arm works with NO signal.
fn interleaved_flood_24(
    a: &mut PersistentClient<TestProtector>,
    b: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
) -> std::result::Result<(), Box<dyn Error>> {
    for index in 0..24_u32 {
        let action = stage_app(b, &format!("flood-{index}"), NOW, NOW + 3_600, NOW)?;
        relay.enqueue(&action.request, NOW)?;
        b.record_send_result(&action, SendOutcome::Stored)?;
        let outcomes = fetch_and_accept_all(a, relay, NOW)?;
        for outcome in outcomes {
            if let AcceptOutcome::Application(message_id) = outcome {
                a.consume_inbound(message_id, NOW + 300, NOW)?;
            }
        }
        if index < 23 {
            relay.enqueue(&newest_receipt_action(a)?.request, NOW)?;
        }
    }
    Ok(())
}

/// Both-stuck corner (P1, local-arm backstop): A is driven to
/// `ReceiptLocked` through real mutators while B never accepts A's
/// receipts, so the wire carries NO congestion signal (proved by
/// decrypting the newest wire receipt). B's next accept at its own
/// 24-outstanding fires the LOCAL arm alone; B's counter-receipt
/// recovers A below the lock, and the exchange resumes both ways.
#[test]
fn both_stuck_corner_recovers_via_local_arm() -> std::result::Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;

    interleaved_flood_24(&mut a, &mut b, &mut relay)?;
    assert_eq!(outstanding(&b)?, 24);

    // Churn A's counter to the lock through real mutators: report
    // DeliveryUnknown on the newest pending receipt, consume the record,
    // and the owed rule re-stages it (+1 advance per cycle) until 32.
    // The churn receipts are never enqueued — nothing new reaches the
    // wire, and the wire receipts still carry their pre-congestion
    // signals.
    for _ in 0..8 {
        let action = newest_receipt_action(&a)?;
        a.record_send_result(&action, SendOutcome::DeliveryUnknown)?;
        a.consume_delivery_unknown(action.request.message_id, NOW)?;
    }
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.last_assigned_send_seq, 32);
        assert_eq!(active.mode, SessionMode::ReceiptLocked);
        assert_eq!(active.last_delivered_receipt_high_water, 0);
    }

    // The wire carries NO signal: the newest live receipt was staged at
    // outstanding 22 and reports 23 (post-advance). Prove it by
    // decrypting the envelope with a clone of B's session (the real
    // ratchet is untouched).
    let fetch = b.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    assert_eq!(envelopes.len(), 23, "unexpected wire traffic");
    {
        let envelope = envelopes.last().ok_or("no wire receipt")?;
        let olm_message: vodozemac::olm::OlmMessage =
            serde_json::from_slice(envelope.packet.as_bytes())?;
        let mut clone = vodozemac::olm::Session::from_pickle(
            b.session.as_ref().ok_or("no b session")?.pickle(),
        );
        // Walk the clone's ratchet across the whole wire batch so the
        // last envelope decrypts in chain order.
        for skipped in envelopes.iter().take(envelopes.len() - 1) {
            let message: vodozemac::olm::OlmMessage =
                serde_json::from_slice(skipped.packet.as_bytes())?;
            let _ = clone.decrypt(&message).map_err(|_| "clone walk failed")?;
        }
        let plaintext = clone
            .decrypt(&olm_message)
            .map_err(|_| "clone decrypt failed")?;
        let parsed = payload::decode(&plaintext)?;
        assert!(
            parsed.issuer_outstanding < 24,
            "the wire carried a congestion signal: {}",
            parsed.issuer_outstanding
        );
    }

    // B accepts the whole stale batch in order at its own 24
    // outstanding: the FIRST accept fires the LOCAL arm (alone — the
    // wire has no signal) and the armed debt stages exactly one
    // counter-receipt at the next accept's tail.
    for envelope in &envelopes {
        let outcome = b.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            NOW,
        )?;
        assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    }
    assert!(outstanding(&b)? < 24, "the stale receipts did not drain B");
    let b_receipts = pending_receipts(&b);
    assert_eq!(
        b_receipts.len(),
        1,
        "the local arm did not stage B's counter-receipt"
    );

    // A applies B's first counter-receipt (hw 1, staged at the first
    // accept's tail under the v8 arm-first order): §4's recovery begins
    // and A RESUMES receipting in the same pass (its debt and water are
    // both ahead of the delivered marker). A's own resume-receipts
    // briefly re-advance its counter, so full recovery lands only on the
    // next counter-receipt — asserted at the end.
    drive_pending(&mut b, &mut relay, NOW)?;
    let outcomes = fetch_and_accept_all(&mut a, &mut relay, NOW)?;
    assert!(outcomes.contains(&AcceptOutcome::ReceiptApplied));
    assert!(
        !pending_receipts(&a).is_empty(),
        "A did not resume receipting on recovery"
    );

    // The exchange resumes both ways: A's fresh receipts signal B, B
    // counter-receipts again (hw 24), and both sides end below the
    // threshold with A out of the lock for good.
    drive_pending(&mut a, &mut relay, NOW)?;
    fetch_and_accept_all(&mut b, &mut relay, NOW)?;
    drive_pending(&mut b, &mut relay, NOW)?;
    fetch_and_accept_all(&mut a, &mut relay, NOW)?;
    drive_pending(&mut a, &mut relay, NOW)?;
    assert!(
        outstanding(&a)? < 24,
        "A did not recover below the threshold"
    );
    assert_ne!(
        active_mode(&a)?,
        SessionMode::ReceiptLocked,
        "A never left the lock"
    );
    assert!(outstanding(&b)? < 24, "B did not drain");
    Ok(())
}

// --- D2b v8 remediation tests ------------------------------------------------

/// P1-2: armed control debt is preserved until CONFIRMED delivery —
/// `DeliveryUnknown`, expiry sweeps and crashes never lose it (it
/// re-stages at the next mutator), and only a `Stored` result or a
/// fresh low-signal payload clears it.
#[test]
fn control_debt_re_stages_after_unknown_expiry_and_reopen()
-> std::result::Result<(), Box<dyn Error>> {
    const TTL: u64 = 7 * 24 * 60 * 60;
    let (a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;

    // A accepts m1, then m2 with its counter fabricated to 24
    // outstanding: the arm-first tail arms and flushes in the same
    // pass — one receipt (hw 2, seq 25), zero application debt.
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 24;
        active.mode = SessionMode::ControlOnly;
    }
    let outcomes = deliver(&mut a, &mut relay, &[1])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].high_water, Some(2));
    assert_eq!(receipts[0].sequence, 25);

    // DeliveryUnknown does NOT clear the debt water (v9: signals and
    // failures never lower it): consuming the record re-stages the
    // receipt in the same pass.
    let action = newest_receipt_action(&a)?;
    a.record_send_result(&action, SendOutcome::DeliveryUnknown)?;
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .control_debt_up_to,
        2,
        "DeliveryUnknown lowered the debt water"
    );
    a.consume_delivery_unknown(action.request.message_id, NOW)?;
    let receipts = pending_receipts(&a);
    assert_eq!(
        receipts.len(),
        1,
        "the debt did not re-stage after DeliveryUnknown"
    );
    assert_eq!(receipts[0].sequence, 26);

    // Expiry without delivery: a consume past the receipt's TTL sweeps
    // it, and the still-armed debt re-stages with a fresh envelope.
    let past = NOW + TTL + 1;
    let inbound = a.pending_inbound()?;
    let message_id = inbound.first().ok_or("no inbound")?.message_id;
    a.consume_inbound(message_id, past + 300, past)?;
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1, "the debt did not re-stage after expiry");
    assert_eq!(receipts[0].high_water, Some(2));
    assert_eq!(receipts[0].sequence, 27);
    assert_eq!(receipts[0].expires_at, past + TTL);

    // Crash between stage and outcome: the water is durable, and the
    // debt still re-stages after reopen.
    drop(a);
    let mut a = open_client(&a_dir)?;
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .control_debt_up_to,
        2,
        "the debt water did not survive reopen"
    );
    let action = newest_receipt_action(&a)?;
    a.record_send_result(&action, SendOutcome::DeliveryUnknown)?;
    a.consume_delivery_unknown(action.request.message_id, past)?;
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1, "the debt did not re-stage after reopen");
    assert_eq!(receipts[0].sequence, 28);

    // Confirmed delivery RESOLVES the debt: the marker reaches the
    // water (2), which itself is never lowered (v9).
    let action = newest_receipt_action(&a)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.last_delivered_receipt_high_water, 2);
        assert_eq!(
            active.control_debt_up_to, 2,
            "delivery must never lower the debt water"
        );
    }
    // Resolved: nothing further stages on the next mutator.
    let action = newest_receipt_action(&a);
    assert!(action.is_err(), "a receipt staged past resolution");
    Ok(())
}

/// V9 water-model lifecycle (dissolving findings 2 and 4): delivery
/// RESOLVES debt when the marker reaches the water; signals never
/// clear it; and a delayed `Stored` on an OLDER receipt leaves newer
/// debt standing until a delivery reaches the water.
#[test]
fn control_debt_resolves_on_delivery_never_on_signals() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 24;
        active.mode = SessionMode::ControlOnly;
    }
    let outcomes = deliver(&mut a, &mut relay, &[1])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].high_water, Some(2));

    // Confirmed delivery RESOLVES the debt (marker reaches water 2);
    // the water itself is never lowered.
    let action = newest_receipt_action(&a)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.last_delivered_receipt_high_water, 2);
        assert_eq!(
            active.control_debt_up_to, 2,
            "delivery must never lower the debt water"
        );
    }

    // A peer receipt covering all 25 sends drains A; the entry sample
    // (25) re-arms the water to the new HCR (3) and one fresh receipt
    // flushes in the same pass.
    let b_signal = outstanding(&b)?;
    let (message_id, packet, signature, expires_at) =
        forge_receipt_envelope(&mut b, &a, 25, 3, NOW, b_signal)?;
    let queue_id = a.state.mailbox_queue_id;
    let outcome = a.accept_envelope(queue_id, message_id, packet, expires_at, signature, NOW)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.control_debt_up_to, 3);
    }
    assert_eq!(pending_receipts(&a).len(), 1);

    // A SIGNALING packet (issuer_outstanding 24) raises the water to
    // the new HCR (4); the in-flight hw-3 receipt blocks replacement.
    let conversation_id = a.state.conversation_id;
    let (app_id, app_packet, app_sig) = {
        let session = b.session.as_mut().ok_or("no b session")?;
        raw_peer_envelope(session, &a, conversation_id, 4, 24)?
    };
    let outcome = a.accept_envelope(queue_id, app_id, app_packet, NOW + 3_600, app_sig, NOW)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .control_debt_up_to,
        4,
        "the signal did not raise the debt water"
    );

    // INVERTED v9 rule (finding 2 immunity): a reordered truthful LOW
    // signal NEVER clears or lowers the debt water.
    let (app_id, app_packet, app_sig) = {
        let session = b.session.as_mut().ok_or("no b session")?;
        raw_peer_envelope(session, &a, conversation_id, 5, 0)?
    };
    let outcome = a.accept_envelope(queue_id, app_id, app_packet, NOW + 3_600, app_sig, NOW)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .control_debt_up_to,
        4,
        "a low signal lowered the debt water"
    );

    // Finding 4 shape: a delayed `Stored` on the OLDER receipt (hw 3 <
    // water 4) leaves the newer debt standing — the next mutator
    // re-stages (any pending inbound consume drives it).
    let action = newest_receipt_action(&a)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.last_delivered_receipt_high_water, 3);
    }
    let inbound = a.pending_inbound()?;
    let message_id = inbound.first().ok_or("no inbound")?.message_id;
    a.consume_inbound(message_id, NOW + 300, NOW)?;
    let receipts = pending_receipts(&a);
    assert_eq!(
        receipts.len(),
        1,
        "the older delivery wrongly resolved the newer debt"
    );
    assert_eq!(receipts[0].high_water, Some(5));

    // A delivery at or above the water finally resolves it.
    let action = newest_receipt_action(&a)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.last_delivered_receipt_high_water, 5);
        assert_eq!(active.control_debt_up_to, 4);
    }
    assert!(
        pending_receipts(&a).is_empty(),
        "a receipt staged past resolution"
    );
    Ok(())
}

/// P1-4, Sol's 33-packet probe: a malicious peer streams authenticated
/// receipt-only packets with idempotent `high_water=0` and
/// `issuer_outstanding >= 24`. The any-pending guard bounds the victim
/// to ≈ one receipt per delivery cycle: never more than one pending
/// victim receipt, the mode never leaves `Ready`, and the victim's own
/// application sends are unaffected.
#[test]
fn over_signaling_cannot_lock_the_victim() -> std::result::Result<(), Box<dyn Error>> {
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let queue_id = a.state.mailbox_queue_id;

    // Wave 1 (20 packets): each arms on the forged signal; at most ONE
    // victim receipt is ever pending.
    for seq in 2..=21_u64 {
        let (message_id, packet, signature, expires_at) =
            forge_receipt_envelope(&mut b, &a, 0, seq, NOW, 32)?;
        let outcome =
            a.accept_envelope(queue_id, message_id, packet, expires_at, signature, NOW)?;
        assert_eq!(outcome, AcceptOutcome::ReceiptIdempotent);
        assert!(
            pending_receipts(&a).len() <= 1,
            "more than one victim receipt pending at seq {seq}"
        );
    }
    assert_eq!(pending_receipts(&a).len(), 1);
    assert_eq!(active_mode(&a)?, SessionMode::Ready);
    assert!(outstanding(&a)? < 24);

    // The victim's application sends are unaffected.
    let _app = stage_app(&mut a, "victim app", NOW, NOW + 3_600, NOW)?;

    // Deliver the in-flight receipt; the marker advances to its hw (2)
    // but the debt water (21) is never lowered — newer debt stands
    // (v9 finding 4), so wave 2 stages exactly one replacement.
    let action = newest_receipt_action(&a)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.last_delivered_receipt_high_water, 2);
        assert_eq!(active.control_debt_up_to, 21);
    }

    // Wave 2 (13 packets): after the delivery, at most one more stages.
    for seq in 22..=34_u64 {
        let (message_id, packet, signature, expires_at) =
            forge_receipt_envelope(&mut b, &a, 0, seq, NOW, 32)?;
        let outcome =
            a.accept_envelope(queue_id, message_id, packet, expires_at, signature, NOW)?;
        assert_eq!(outcome, AcceptOutcome::ReceiptIdempotent);
        assert!(
            pending_receipts(&a).len() <= 1,
            "more than one victim receipt pending after delivery at seq {seq}"
        );
    }
    assert_eq!(pending_receipts(&a).len(), 1);
    assert_eq!(active_mode(&a)?, SessionMode::Ready);
    assert!(outstanding(&a)? < 24);
    Ok(())
}

// --- D2b v9 remediation tests ------------------------------------------------

/// Finding 1: a packet whose ciphertext was already accepted cannot be
/// re-encapsulated under a fresh outer ID/signature — the dedup bounds
/// match the packet digest across ALL epochs before any ratchet touch,
/// so the replay never reaches decrypt (no gap error, no
/// `RekeyRequired`, no generation commit), and the retention is durable
/// across reopen.
#[test]
fn cross_epoch_digest_replay_rejected_before_ratchet() -> std::result::Result<(), Box<dyn Error>> {
    let (a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;

    // A accepts m1; its ciphertext and digest are durably in the dedup
    // picture. Recover the exact packet from the relay.
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let fetch = a.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let packet = envelopes.first().ok_or("no m1 envelope")?.packet.clone();
    let queue_a = a.state.mailbox_queue_id;

    // Re-encapsulate the SAME ciphertext under a fresh outer ID and
    // signature, at two apparent ages: fresh-looking and older. Both
    // must reject at dedup without a commit or a ratchet touch.
    for apparent_expiry in [NOW + 3_600, NOW + 60] {
        let generation_before = a.store.generation()?;
        let message_id = MessageId::random();
        let signature = a.keypairs.send.sign(&super::send_signing_bytes(
            queue_a,
            message_id,
            &packet.digest(),
            apparent_expiry,
        ));
        let outcome = a.accept_envelope(
            queue_a,
            message_id,
            packet.clone(),
            apparent_expiry,
            signature,
            NOW,
        );
        assert!(
            matches!(outcome, Err(LabError::DuplicateMessage)),
            "the replayed digest was not rejected"
        );
        assert_eq!(
            a.store.generation()?,
            generation_before,
            "the replay committed"
        );
        assert_eq!(
            active_mode(&a)?,
            SessionMode::Ready,
            "the replay touched the ratchet"
        );
        assert_eq!(
            a.state
                .active_session
                .as_ref()
                .ok_or("no session")?
                .highest_contiguous_received_seq,
            1,
            "the replay moved the receive water"
        );
    }

    // Durable retention: after a drop/reopen the same replay still
    // rejects at the bounds with no commit.
    drop(a);
    let mut a = open_client(&a_dir)?;
    let generation_before = a.store.generation()?;
    let message_id = MessageId::random();
    let signature = a.keypairs.send.sign(&super::send_signing_bytes(
        queue_a,
        message_id,
        &packet.digest(),
        NOW + 3_600,
    ));
    let outcome = a.accept_envelope(queue_a, message_id, packet, NOW + 3_600, signature, NOW);
    assert!(
        matches!(outcome, Err(LabError::DuplicateMessage)),
        "the replayed digest was not rejected after reopen"
    );
    assert_eq!(a.store.generation()?, generation_before);
    assert_eq!(active_mode(&a)?, SessionMode::Ready);
    Ok(())
}

/// Finding 3: the accept's `now` sweeps expired sends before the
/// staging tail — an expired Pending control receipt is swept AND
/// replaced in the same receipt-only accept pass (pre-fix it squatted
/// in the any-pending guard forever).
#[test]
fn expired_control_receipt_re_stages_on_receipt_only_traffic()
-> std::result::Result<(), Box<dyn Error>> {
    const TTL: u64 = 7 * 24 * 60 * 60;
    let (_a_dir, _b_dir, mut a, mut b, mut relay) = conversation_fixture()?;

    // A accepts m1, then m2 with its counter fabricated to 24
    // outstanding: the arm-first tail raises the debt water (2) and
    // flushes one control receipt (hw 2, seq 25) in the same pass.
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    {
        let active = a.state.active_session.as_mut().ok_or("no session")?;
        active.last_assigned_send_seq = 24;
        active.mode = SessionMode::ControlOnly;
    }
    let outcomes = deliver(&mut a, &mut relay, &[1])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].high_water, Some(2));
    assert_eq!(receipts[0].sequence, 25);

    // The receipt expires undelivered (the relay purges it). A receipt-
    // only packet then arrives: the accept sweeps the corpse to Expired
    // AND stages the fresh replacement in the same pass.
    let past = NOW + TTL + 1;
    let b_signal = outstanding(&b)?;
    let (message_id, packet, signature, expires_at) =
        forge_receipt_envelope(&mut b, &a, 2, 3, past, b_signal)?;
    let queue_id = a.state.mailbox_queue_id;
    let outcome = a.accept_envelope(queue_id, message_id, packet, expires_at, signature, past)?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    assert!(
        a.state
            .sends
            .iter()
            .any(|record| record.state == crate::state::SendState::Expired
                && record.kind == crate::state::SendKind::Receipt
                && record.sequence == 25),
        "the expired receipt was not swept"
    );
    let receipts = pending_receipts(&a);
    assert_eq!(
        receipts.len(),
        1,
        "the swept receipt was not replaced in the same pass"
    );
    assert_eq!(receipts[0].high_water, Some(3));
    assert_eq!(receipts[0].sequence, 26);
    assert_eq!(receipts[0].expires_at, past + TTL);
    Ok(())
}

// --- D2b v11 remediation tests (Sol's v10 P1-1 and P1-2) ---------------------

/// Sol's v10 P1-1: JSON aliases must not bypass global packet dedup.
///
/// `EncryptedPacket::digest` hashes the RAW bytes, but the `OlmMessage`
/// deserializer is permissive — it ignores unknown fields and accepts any
/// field order and any whitespace. So an already-accepted packet can be
/// re-encoded to a byte-different alias that decrypts to the SAME message
/// but carries a DIFFERENT digest. Pre-fix each alias slipped past the
/// global digest dedup on its new digest and reached ratchet `decrypt`,
/// which returned `MissingMessageKey` and durably committed
/// `RekeyRequired` — closing the conversation for good.
///
/// Every alias below is first proven to be a genuine alias (it decodes to
/// exactly the canonical packet's `OlmMessage`), then proven to be
/// rejected before dedup and before any ratchet touch: no generation
/// commit, mode still `Ready`, receive water unmoved. The canonical
/// encoding itself still rejects as a plain duplicate.
#[test]
fn json_aliased_packet_replay_is_rejected_before_dedup() -> std::result::Result<(), Box<dyn Error>>
{
    let (_a_dir, _b_dir, mut a, _b, mut relay) = conversation_fixture()?;

    // A accepts m1; its digest is durably in the dedup picture.
    let outcomes = deliver(&mut a, &mut relay, &[0])?;
    assert!(outcomes.iter().all(Result::is_ok));
    let fetch = a.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let packet = envelopes.first().ok_or("no m1 envelope")?.packet.clone();
    let queue_a = a.state.mailbox_queue_id;

    let canonical = packet.as_bytes().to_vec();
    let value: serde_json::Value = serde_json::from_slice(&canonical)?;
    let object = value.as_object().ok_or("packet is not a JSON object")?;

    // Three encodings of the same Olm message, none byte-equal to the
    // canonical one: key-sorted (serde_json's Value map is a BTreeMap, so
    // this reorders "type"/"body"), pretty-printed (whitespace), and one
    // carrying an extra field the deserializer ignores.
    let mut with_unknown = object.clone();
    with_unknown.insert("unknown".to_owned(), serde_json::Value::from(1));
    let aliases: Vec<(&str, Vec<u8>)> = vec![
        ("reordered keys", serde_json::to_vec(&value)?),
        ("added whitespace", serde_json::to_vec_pretty(&value)?),
        (
            "ignored extra field",
            serde_json::to_vec(&serde_json::Value::Object(with_unknown))?,
        ),
    ];

    for (label, bytes) in aliases {
        assert_ne!(bytes, canonical, "{label} is not actually a re-encoding");
        // It really is an alias: same decoded Olm message, different digest.
        let decoded: vodozemac::olm::OlmMessage = serde_json::from_slice(&bytes)?;
        let original: vodozemac::olm::OlmMessage = serde_json::from_slice(&canonical)?;
        assert_eq!(
            decoded.to_parts(),
            original.to_parts(),
            "{label} does not decode to the same Olm message"
        );
        let alias = EncryptedPacket::from_untrusted(bytes);
        assert_ne!(
            alias.digest(),
            packet.digest(),
            "{label} did not change the digest, so it cannot test the bypass"
        );

        // Re-encapsulated under a fresh message ID and a fresh VALID
        // signature over the alias's own digest — the exact shape that
        // slipped through pre-fix.
        let generation_before = a.store.generation()?;
        let message_id = MessageId::random();
        let signature = a.keypairs.send.sign(&super::send_signing_bytes(
            queue_a,
            message_id,
            &alias.digest(),
            NOW + 3_600,
        ));
        let outcome = a.accept_envelope(queue_a, message_id, alias, NOW + 3_600, signature, NOW);
        assert!(
            matches!(outcome, Err(LabError::InvalidPayload)),
            "{label} was not rejected as non-canonical: {outcome:?}"
        );
        assert_eq!(
            a.store.generation()?,
            generation_before,
            "{label} committed"
        );
        assert_eq!(
            active_mode(&a)?,
            SessionMode::Ready,
            "{label} reached the ratchet and gap-locked the session"
        );
        assert_eq!(
            a.state
                .active_session
                .as_ref()
                .ok_or("no session")?
                .highest_contiguous_received_seq,
            1,
            "{label} moved the receive water"
        );
    }

    // The canonical encoding is unaffected: it still rejects as a plain
    // duplicate, on the digest it legitimately matches.
    let message_id = MessageId::random();
    let signature = a.keypairs.send.sign(&super::send_signing_bytes(
        queue_a,
        message_id,
        &packet.digest(),
        NOW + 3_600,
    ));
    assert!(matches!(
        a.accept_envelope(queue_a, message_id, packet, NOW + 3_600, signature, NOW),
        Err(LabError::DuplicateMessage)
    ));
    Ok(())
}

/// Sol's v10 P1-2: a truthful congestion signal that arrives out of order
/// must not be lost.
///
/// The peer's signal rides a specific sender sequence. Pre-fix the arm
/// raised the control-debt water to the acceptor's contiguous high water
/// instead, so a signal riding sequence 25 that arrived while HCR was
/// still 1 recorded debt at 1. A delayed older receipt then advanced the
/// delivered marker to 1, the debt read as resolved, and when the missing
/// packets later drained HCR to 25 no receipt was owed at all — leaving
/// the peer wedged in `ControlOnly` at 24+ outstanding forever.
///
/// This drives the real façade over the real relay end to end: reordered
/// arrival, the delayed receipt that advances the marker, the drain, and
/// then the receipt that must cover HCR — and asserts the peer actually
/// recovers below the threshold.
/// Stage and store `count` applications from B to A's mailbox, one per
/// sender sequence, failing with the index that broke.
fn stage_applications_to_the_budget(
    b: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    count: u64,
) -> std::result::Result<(), Box<dyn Error>> {
    for index in 1..=count {
        let staged = b
            .stage_send(&format!("m{index}"), NOW, NOW + 3_600, NOW)
            .map_err(|error| format!("stage {index}: {error:?}"))?;
        let action = match staged {
            super::StageSendOutcome::Staged(action) => action,
            super::StageSendOutcome::ReceiptFlushedRetry => {
                return Err(format!("stage {index} flushed a receipt").into());
            }
        };
        relay
            .enqueue(&action.request, NOW)
            .map_err(|error| format!("enqueue {index}: {error:?}"))?;
        b.record_send_result(&action, SendOutcome::Stored)
            .map_err(|error| format!("result {index}: {error:?}"))?;
    }
    Ok(())
}

/// Drive owed control receipts to `Stored` until the debt water is
/// covered by the delivered marker, asserting the loop terminates and
/// that exactly one receipt is owed on each pass.
///
/// Delivery alone does not re-stage; the owed receipt flushes at the next
/// clock-taking mutator, which is the documented retry path (control
/// priority means it outranks the application). Receipts stage at the
/// CURRENT high water, so one staged mid-drain covers only the water of
/// that moment — convergence is a bounded loop, not a single shot.
fn converge_control_debt(
    a: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    max_rounds: usize,
) -> std::result::Result<(), Box<dyn Error>> {
    let mut rounds = 0;
    loop {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        if active.control_debt_up_to <= active.last_delivered_receipt_high_water {
            return Ok(());
        }
        if pending_receipts(a).is_empty() {
            a.stage_send("retry trigger", NOW, NOW + 3_600, NOW)?;
        }
        let receipts = pending_receipts(a);
        assert_eq!(
            receipts.len(),
            1,
            "debt stands at round {rounds} but no receipt is owed"
        );
        let action = a
            .pending_send_actions()?
            .into_iter()
            .find(|action| action.request.message_id == receipts[0].message_id)
            .ok_or("no receipt action")?;
        relay.enqueue(&action.request, NOW)?;
        a.record_send_result(&action, SendOutcome::Stored)?;
        rounds += 1;
        assert!(rounds <= max_rounds, "the control debt never converged");
    }
}

#[test]
fn reordered_congestion_signal_survives_a_delayed_receipt()
-> std::result::Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let a_dir = TempDir::new()?;
    let b_dir = TempDir::new()?;
    let mut a = create_client(&a_dir)?;
    let mut b = create_client(&b_dir)?;
    register_on_relay(&mut a, &mut relay)?;
    register_on_relay(&mut b, &mut relay)?;
    connect(&mut a, &mut b, ConversationId::random())?;

    // B sends applications until §4's budget locks it. Nothing is
    // receipted, so B's outstanding climbs with its sequence and the 24th
    // payload truthfully reports 24 — exactly the threshold — after which
    // B is `ControlOnly` and can stage no more applications. So sequence
    // 24 is the highest-numbered packet that can carry a truthful signal.
    stage_applications_to_the_budget(&mut b, &mut relay, 24)?;
    assert_eq!(outstanding(&b)?, 24);
    assert_eq!(active_mode(&b)?, SessionMode::ControlOnly);

    // A receives sequence 1, then the SIGNALLING packet at sequence 24,
    // out of order: 24 waits in the bounded out-of-order set and the
    // contiguous water is still 1.
    let outcomes = deliver(&mut a, &mut relay, &[0, 23])?;
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.highest_contiguous_received_seq, 1);
        assert!(active.received_above_high_water.contains(&24));
        // The fix: debt is bound to the SIGNALLING sequence, not the
        // lagging contiguous water. Pre-fix this was 1.
        assert_eq!(
            active.control_debt_up_to, 24,
            "the debt was armed to the contiguous water, losing the signal"
        );
    }

    // The arm flushed one receipt in the same pass, covering the water it
    // could actually report (1). Drive it to Stored: the delivered marker
    // advances to 1 — the step that pre-fix silently retired the debt.
    let receipts = pending_receipts(&a);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].high_water, Some(1));
    let action = a
        .pending_send_actions()?
        .into_iter()
        .find(|action| action.request.message_id == receipts[0].message_id)
        .ok_or("no receipt action")?;
    relay.enqueue(&action.request, NOW)?;
    a.record_send_result(&action, SendOutcome::Stored)?;
    assert_eq!(delivered_marker(&a)?, 1);
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .control_debt_up_to,
        24,
        "a delivery below the debt water resolved it"
    );

    // The missing packets 2..=23 arrive and drain the water to 24.
    let order: Vec<usize> = (1..23).collect();
    let outcomes = deliver(&mut a, &mut relay, &order)?;
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
    {
        let active = a.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.highest_contiguous_received_seq, 24);
        assert!(active.received_above_high_water.is_empty());
    }

    // The debt still stands and is still owed, and converges. Pre-fix
    // nothing was owed here at all: the loop exited on its first pass
    // with the marker far below 24 — the wedge.
    converge_control_debt(&mut a, &mut relay, 4)?;
    assert!(
        delivered_marker(&a)? >= 24,
        "the debt resolved without ever delivering a receipt covering the signalling sequence"
    );

    // B applies every receipt A produced: its high water reaches 24,
    // outstanding falls to 0, the ControlOnly lock lifts, and it can send
    // applications again.
    let fetch = b.fetch_request(NOW + 300, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    assert!(!envelopes.is_empty(), "no receipt envelopes for B");
    for envelope in &envelopes {
        b.accept_envelope(
            envelope.queue_id,
            envelope.message_id,
            envelope.packet.clone(),
            envelope.expires_at,
            envelope.sender_signature,
            NOW,
        )?;
    }
    assert_eq!(
        b.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .peer_contiguous_high_water,
        24,
        "the covering receipt never reached B"
    );
    assert!(
        outstanding(&b)? < 24,
        "B did not recover below the threshold: {} outstanding",
        outstanding(&b)?
    );
    assert_eq!(active_mode(&b)?, SessionMode::Ready);
    b.stage_send("unwedged", NOW, NOW + 3_600, NOW)?;
    Ok(())
}
