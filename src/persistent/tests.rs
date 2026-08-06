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

/// B stages `count` application sends to A's mailbox through the real
/// relay, confirming each as stored.
fn stage_to_relay(
    b: &mut PersistentClient<TestProtector>,
    relay: &mut Relay,
    bodies: &[&str],
) -> std::result::Result<(), Box<dyn Error>> {
    for body in bodies {
        let action = b.stage_send(body, NOW, NOW + 3_600, NOW)?;
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
    let outcomes = deliver(&mut a, &mut relay, &[0, 1, 2, 3])?;
    assert!(outcomes.iter().all(Result::is_ok));

    // Consume m1: the ACK intent is created; no new receipt stages
    // because each accept already staged its owed receipt (v3 rule), so
    // four are pending for high waters 1..=4.
    let inbound = a.pending_inbound()?;
    let message_id = inbound
        .iter()
        .find(|view| view.body == "m1")
        .ok_or("m1 missing")?
        .message_id;
    a.consume_inbound(message_id, NOW + 60, NOW)?;
    assert_eq!(a.pending_inbound()?.len(), 3);
    assert_eq!(
        a.pending_send_actions()?.len(),
        4,
        "one receipt per accept, high waters 1..=4"
    );

    // The ACK flows through the real relay and its result lands.
    let ack_actions = a.ack_actions(NOW)?;
    assert_eq!(ack_actions.len(), 1);
    let ack_action = ack_actions.first().ok_or("no ack action")?;
    relay.acknowledge(&ack_action.request, NOW)?;
    a.record_ack_result(ack_action, AckOutcomeView::Deleted)?;
    assert!(a.ack_actions(NOW)?.is_empty());
    assert!(
        a.state
            .dedup
            .iter()
            .any(|record| record.message_id == message_id && record.state == DedupState::Acked),
        "dedup record not Acked"
    );
    assert!(
        a.record_ack_result(ack_action, AckOutcomeView::Deleted)
            .is_err(),
        "replayed ack result accepted"
    );

    // Deliver the newest staged receipt (highest send sequence) to B
    // through the relay: B's high water advances to 4 and the send budget
    // recovers.
    let receipt_id = a
        .state
        .sends
        .iter()
        .filter(|record| record.state == crate::state::SendState::Pending)
        .max_by_key(|record| record.sequence)
        .ok_or("no pending receipt")?
        .message_id;
    let receipt_action = a
        .pending_send_actions()?
        .into_iter()
        .find(|action| action.request.message_id == receipt_id)
        .ok_or("no receipt action")?;
    relay.enqueue(&receipt_action.request, NOW)?;
    a.record_send_result(&receipt_action, SendOutcome::Stored)?;
    let fetch = b.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    let receipt_envelope = envelopes.first().ok_or("no receipt envelope")?;
    let outcome = b.accept_envelope(
        receipt_envelope.queue_id,
        receipt_envelope.message_id,
        receipt_envelope.packet.clone(),
        receipt_envelope.expires_at,
        receipt_envelope.sender_signature,
        NOW,
    )?;
    assert_eq!(outcome, AcceptOutcome::ReceiptApplied);
    {
        let active = b.state.active_session.as_ref().ok_or("no session")?;
        assert_eq!(active.peer_contiguous_high_water, 4);
        assert_eq!(active.last_assigned_send_seq, 4);
    }

    // Re-accepting the same receipt envelope rejects as a duplicate; a
    // second consume-driven receipt with the same water is idempotent.
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
    let outcomes = deliver(&mut a, &mut relay, &[0, 1])?;
    assert!(outcomes.iter().all(Result::is_ok));

    // Each accept eagerly staged its owed receipt (v3 rule): one for HCR
    // 1 and one for HCR 2.
    assert_eq!(a.pending_send_actions()?.len(), 2);
    // Rewinding the owed marker in-crate makes the next consume stage a
    // DISTINCT receipt envelope reporting the same high water (2).
    a.state
        .active_session
        .as_mut()
        .ok_or("no session")?
        .last_staged_receipt_high_water = 0;
    let inbound = a.pending_inbound()?;
    let first = inbound.first().ok_or("no inbound")?.message_id;
    a.consume_inbound(first, NOW + 60, NOW)?;
    assert_eq!(a.pending_send_actions()?.len(), 3);
    // Receipts regress-reject if a stale one lands after a newer one, so
    // deliver in send-sequence order (the outbox array is ID-sorted).
    let mut actions = a.pending_send_actions()?;
    actions.sort_by_key(|action| {
        a.state
            .sends
            .iter()
            .find(|record| record.message_id == action.request.message_id)
            .map_or(u64::MAX, |record| record.sequence)
    });
    let mut outcomes = Vec::new();
    for action in &actions {
        relay.enqueue(&action.request, NOW)?;
        a.record_send_result(action, SendOutcome::Stored)?;
    }
    let fetch = b.fetch_request(NOW + 60, NOW)?;
    let envelopes = relay.fetch(&fetch.request, NOW)?;
    assert_eq!(envelopes.len(), 3);
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
    // HCR 1 applies, HCR 2 applies, the second HCR-2 receipt is
    // idempotent.
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == AcceptOutcome::ReceiptApplied)
            .count(),
        2
    );
    assert!(outcomes.contains(&AcceptOutcome::ReceiptIdempotent));
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
fn raw_peer_envelope(
    peer_session: &mut vodozemac::olm::Session,
    a: &PersistentClient<TestProtector>,
    conversation_id: ConversationId,
    seq: u64,
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

    // A raw test peer (no façade budget on its side) establishes a real
    // outbound session against A's published one-time key. A commits the
    // peer's verified contact first (the accept path needs the binding).
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

    // Message 1 establishes A's inbound session.
    let (id1, packet1, sig1) = raw_peer_envelope(&mut peer_session, &a, conversation_id, 1)?;
    let outcome = a.accept_envelope(queue_a, id1, packet1, NOW + 3_600, sig1, NOW)?;
    assert!(matches!(outcome, AcceptOutcome::Application(_)));

    // The peer keeps encrypting through seq 45. Deliver seq 45 first: the
    // 43-message gap is within vodozemac's 2000-gap tolerance, so it
    // decrypts and lands in the out-of-order set — but its chain advance
    // evicts the oldest skipped keys (only 40 retained).
    let mut second = None;
    let mut last = None;
    for seq in 2..=45 {
        let envelope = raw_peer_envelope(&mut peer_session, &a, conversation_id, seq)?;
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
    let result = a.accept_envelope(queue_a, id2, packet2, NOW + 3_600, sig2, NOW);
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

    // Durable across reopen; all staging stays blocked.
    drop(a);
    let mut a = open_client(&a_dir)?;
    assert_eq!(active_mode(&a)?, SessionMode::RekeyRequired);
    assert!(a.stage_send("blocked", NOW, NOW + 3_600, NOW).is_err());

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
    let first = b.stage_send("terminal", NOW, NOW + 60, NOW)?;
    b.record_send_result(&first, SendOutcome::Stored)?;
    assert_eq!(b.state.sends.len(), 1, "terminal record retained in window");

    // Inside the tombstone window the record survives a send-path
    // mutator.
    let second = b.stage_send("in window", NOW + 120, NOW + 120 + 3_600, NOW + 120)?;
    assert_eq!(b.state.sends.len(), 2);

    // Past the window, the next send-path mutator prunes record 1. Record
    // 2's own expiry passes first (swept to Expired), but ITS tombstone
    // window has not, so only record 1 leaves.
    let past_window = NOW + 60 + 7 * 24 * 60 * 60 + 1;
    let third = b.stage_send(
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
    // The receipt stayed owed the whole time: the marker never moved
    // past the m1 accept's 1 while the array was full.
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .last_staged_receipt_high_water,
        1
    );

    // Advance the clock past the tombstone window; the next mutator
    // prunes the terminal records and stages the OWED receipt in the same
    // commit (review D2b v3) — no new inbound needed.
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
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .last_staged_receipt_high_water,
        2,
        "the owed receipt did not stage"
    );
    // Nothing new is owed, so a further consume stages nothing.
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
    let (id1, packet1, sig1) = raw_peer_envelope(&mut peer_session, &a, conversation_id, 1)?;
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

/// Review D2b v3, Sol's exact closure: every inbound is consumed while
/// the send array is full (32 terminal sends); no receipt stages; the
/// owed marker stays behind; after the clock passes the tombstone window
/// the next mutator stages the owed receipt with no new inbound; the
/// receipt drives the peer's high water forward and unblocks its budget.
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
    // Every consume committed; no receipt was ever stageable.
    assert_eq!(a.state.sends.len(), 32, "a receipt staged at the bound");
    assert_eq!(a.state.acks.len(), 24);
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .last_staged_receipt_high_water,
        1,
        "the owed marker moved while full"
    );

    // Past the tombstone window, one mutator prunes the terminal records
    // and stages the owed receipt in the same commit.
    let past_window = NOW + 3_600 + 7 * 24 * 60 * 60 + 1;
    let trigger = a.stage_send("trigger", past_window, past_window + 3_600, past_window)?;
    let sends = &a.state.sends;
    assert_eq!(sends.len(), 2, "expected trigger send plus owed receipt");
    assert_eq!(
        a.state
            .active_session
            .as_ref()
            .ok_or("no session")?
            .last_staged_receipt_high_water,
        24,
        "the owed receipt did not stage"
    );

    // Drive the receipt through the relay; the peer accepts it and its
    // high water advances, recovering its budget.
    let receipt_action = a
        .pending_send_actions()?
        .into_iter()
        .find(|action| action.request.message_id != trigger.request.message_id)
        .ok_or("no receipt action")?;
    relay.enqueue(&receipt_action.request, past_window)?;
    a.record_send_result(&receipt_action, SendOutcome::Stored)?;
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
    }
    // The unlock proof: B can stage application traffic again.
    b.stage_send("unlocked", past_window, past_window + 3_600, past_window)?;
    Ok(())
}
