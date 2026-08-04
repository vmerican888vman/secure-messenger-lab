use std::error::Error;
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use rusqlite::Connection;
use secure_messenger_lab::{
    AckOutcome, ConversationId, EncryptedPacket, EnqueueOutcome, LabError, MailboxOwner, MessageId,
    OlmClient, Relay, VerifiedPeerPreKey,
};

const NOW: u64 = 1_800_000_000;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn paired_clients() -> Result<(OlmClient, OlmClient, VerifiedPeerPreKey), Box<dyn Error>> {
    let conversation = ConversationId::random();
    let mut alice = OlmClient::new(conversation);
    let mut bob = OlmClient::new(conversation);
    let alice_bundle = alice.prekey_bundle(NOW + 60)?;
    let bob_bundle = bob.prekey_bundle(NOW + 60)?;
    let verified_alice = alice_bundle.verify(alice.signing_identity(), NOW)?;
    let verified_bob = bob_bundle.verify(bob.signing_identity(), NOW)?;
    alice.start_outbound_session(&verified_bob, NOW)?;
    Ok((alice, bob, verified_alice))
}

#[test]
fn ciphertext_is_stored_then_logically_erased_after_recipient_ack() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("relay.sqlite");
    let mut relay = Relay::open(&database)?;
    let (mut alice, mut bob, verified_alice) = paired_clients()?;
    let bob_inbox = MailboxOwner::new();
    relay.register(&bob_inbox.registration(NOW + 60), NOW)?;

    let canary = "PT-A-7f3-relay-must-never-see-this";
    let (message_id, packet) = alice.seal(canary, NOW)?;
    relay.enqueue(
        &bob_inbox
            .sender_capability()
            .authorize(message_id, packet.clone(), NOW + 3_600),
        NOW,
    )?;

    let before_ack = fs::read(&database)?;
    assert!(!contains(&before_ack, canary.as_bytes()));
    assert!(contains(&before_ack, packet.as_bytes()));
    assert_eq!(relay.queued_message_count()?, 1);

    let fetch = bob_inbox.receiver_capability().authorize_fetch(NOW + 60);
    let fetched = relay.fetch(&fetch, NOW)?;
    assert_eq!(
        relay.queued_message_count()?,
        1,
        "fetch alone must not delete"
    );
    let envelope = fetched.first().ok_or("missing fetched envelope")?;
    let receiver = bob_inbox.receiver_capability();
    let verified_envelope = receiver.verify_envelope(envelope, NOW)?;
    let opened = bob.open_initial(verified_envelope, &verified_alice, NOW)?;
    assert_eq!(opened.message().body, canary);
    let ack = receiver.authorize_ack(&opened, NOW + 60);
    assert_eq!(relay.acknowledge(&ack, NOW)?, AckOutcome::Deleted);
    assert_eq!(relay.queued_message_count()?, 0);
    assert_eq!(
        relay.tombstone_count()?,
        1,
        "bounded opaque replay tombstone remains"
    );

    let after_ack = fs::read(&database)?;
    assert!(!contains(&after_ack, canary.as_bytes()));
    assert!(
        !contains(&after_ack, packet.as_bytes()),
        "secure_delete must remove the current DB file's ciphertext bytes"
    );
    let joined_events = relay.audit_events().join("\n");
    assert!(!joined_events.contains(canary));
    assert!(!contains(joined_events.as_bytes(), packet.as_bytes()));
    drop(relay);
    let mut reopened = Relay::open_at(&database, NOW + 1)?;
    assert_eq!(reopened.queued_message_count_at(NOW + 1)?, 0);
    assert_eq!(reopened.tombstone_count()?, 1);
    Ok(())
}

#[test]
fn retries_are_idempotent_and_conflicting_ciphertext_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let (mut alice, _bob, _verified_alice) = paired_clients()?;
    let bob_inbox = MailboxOwner::new();
    relay.register(&bob_inbox.registration(NOW + 60), NOW)?;

    let (message_id, packet) = alice.seal("one", NOW)?;
    let sender = bob_inbox.sender_capability();
    let request = sender.authorize(message_id, packet, NOW + 3_600);
    assert_eq!(relay.enqueue(&request, NOW)?, EnqueueOutcome::Stored);
    assert_eq!(relay.enqueue(&request, NOW)?, EnqueueOutcome::Duplicate);
    assert_eq!(relay.queued_message_count()?, 1);

    let (_, different_packet) = alice.seal("different", NOW + 1)?;
    let conflict = sender.authorize(message_id, different_packet, NOW + 3_600);
    assert!(matches!(
        relay.enqueue(&conflict, NOW),
        Err(LabError::MessageConflict)
    ));
    assert_eq!(relay.queued_message_count()?, 1);
    Ok(())
}

#[test]
fn wrong_capabilities_cannot_send_fetch_or_manage() -> Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let target = MailboxOwner::new();
    let attacker = MailboxOwner::new();
    relay.register(&target.registration(NOW + 60), NOW)?;

    let fake_packet = EncryptedPacket::from_untrusted(b"opaque-test-packet".to_vec());
    let mut unauthorized_send =
        attacker
            .sender_capability()
            .authorize(MessageId::random(), fake_packet, NOW + 60);
    unauthorized_send.queue_id = target.queue_id();
    assert!(matches!(
        relay.enqueue(&unauthorized_send, NOW),
        Err(LabError::Unauthorized)
    ));

    let mut unauthorized_fetch = attacker.receiver_capability().authorize_fetch(NOW + 60);
    unauthorized_fetch.queue_id = target.queue_id();
    assert!(matches!(
        relay.fetch(&unauthorized_fetch, NOW),
        Err(LabError::Unauthorized)
    ));

    let mut unauthorized_delete = attacker.manager_capability().authorize_delete(NOW + 60);
    unauthorized_delete.queue_id = target.queue_id();
    assert!(matches!(
        relay.delete_mailbox(&unauthorized_delete, NOW),
        Err(LabError::Unauthorized)
    ));
    Ok(())
}

#[test]
fn tamper_wrong_recipient_and_missing_session_all_fail_closed() -> Result<(), Box<dyn Error>> {
    let (mut alice, mut bob, verified_alice) = paired_clients()?;
    let mut charlie = OlmClient::new(ConversationId::random());
    let mailbox = MailboxOwner::new();
    let mut relay = Relay::open_in_memory()?;
    relay.register(&mailbox.registration(NOW + 60), NOW)?;
    let (message_id, packet) = alice.seal("tamper-canary", NOW)?;
    relay.enqueue(
        &mailbox
            .sender_capability()
            .authorize(message_id, packet, NOW + 60),
        NOW,
    )?;
    let fetched = relay.fetch(
        &mailbox.receiver_capability().authorize_fetch(NOW + 60),
        NOW,
    )?;
    let envelope = fetched.first().ok_or("missing fetched envelope")?;
    let receiver = mailbox.receiver_capability();

    let mut tampered = envelope.clone();
    let mut tampered_bytes = tampered.packet.as_bytes().to_vec();
    let index = tampered_bytes.len() / 2;
    let byte = tampered_bytes
        .get_mut(index)
        .ok_or("empty encrypted packet")?;
    *byte ^= 1;
    tampered.packet = EncryptedPacket::from_untrusted(tampered_bytes);
    assert!(matches!(
        receiver.verify_envelope(&tampered, NOW),
        Err(LabError::Unauthorized)
    ));

    let mut changed_outer_id = envelope.clone();
    changed_outer_id.message_id = MessageId::random();
    assert!(matches!(
        receiver.verify_envelope(&changed_outer_id, NOW),
        Err(LabError::Unauthorized)
    ));

    let verified = receiver.verify_envelope(envelope, NOW)?;
    assert!(
        charlie
            .open_initial(verified.clone(), &verified_alice, NOW)
            .is_err()
    );
    let opened = bob.open_initial(verified, &verified_alice, NOW)?;
    assert_eq!(opened.message().body, "tamper-canary");

    let mut no_session = OlmClient::new(ConversationId::random());
    assert!(matches!(
        no_session.seal("must-not-send", NOW),
        Err(LabError::MissingSession)
    ));
    Ok(())
}

#[test]
fn forged_curve_prekey_bundle_is_rejected_by_pinned_signing_identity() -> Result<(), Box<dyn Error>>
{
    let conversation = ConversationId::random();
    let mut bob = OlmClient::new(conversation);
    let mut attacker = OlmClient::new(conversation);
    let mut claimed_bob_bundle = bob.prekey_bundle(NOW + 60)?;
    let attacker_bundle = attacker.prekey_bundle(NOW + 60)?;

    claimed_bob_bundle.curve_identity = attacker_bundle.curve_identity;
    claimed_bob_bundle.one_time_key = attacker_bundle.one_time_key;
    assert!(matches!(
        claimed_bob_bundle.verify(bob.signing_identity(), NOW),
        Err(LabError::PeerVerificationFailed)
    ));
    Ok(())
}

#[test]
fn ack_is_bound_to_message_and_ciphertext_and_replay_is_harmless() -> Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let (mut alice, mut bob, verified_alice) = paired_clients()?;
    let bob_inbox = MailboxOwner::new();
    relay.register(&bob_inbox.registration(NOW + 60), NOW)?;

    let sender = bob_inbox.sender_capability();
    let (first_id, first_packet) = alice.seal("first", NOW)?;
    relay.enqueue(&sender.authorize(first_id, first_packet, NOW + 3_600), NOW)?;
    let second_id = MessageId::random();
    relay.enqueue(
        &sender.authorize(
            second_id,
            EncryptedPacket::from_untrusted(b"second-opaque-packet".to_vec()),
            NOW + 3_600,
        ),
        NOW,
    )?;

    let receiver = bob_inbox.receiver_capability();
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let first = fetched
        .iter()
        .find(|envelope| envelope.message_id == first_id)
        .ok_or("missing first envelope")?;
    let opened = bob.open_initial(receiver.verify_envelope(first, NOW)?, &verified_alice, NOW)?;
    let valid = receiver.authorize_ack(&opened, NOW + 60);

    let mut substituted = valid.clone();
    substituted.message_id = second_id;
    assert!(matches!(
        relay.acknowledge(&substituted, NOW),
        Err(LabError::Unauthorized)
    ));
    assert_eq!(relay.queued_message_count()?, 2);

    let mut changed_digest = valid.clone();
    changed_digest.packet_hash = [0_u8; 32];
    assert!(matches!(
        relay.acknowledge(&changed_digest, NOW),
        Err(LabError::Unauthorized)
    ));
    assert_eq!(relay.acknowledge(&valid, NOW)?, AckOutcome::Deleted);
    assert_eq!(relay.acknowledge(&valid, NOW)?, AckOutcome::AlreadyDeleted);
    assert_eq!(relay.queued_message_count()?, 1);
    Ok(())
}

#[test]
fn replayed_fetch_is_rejected_and_expired_ciphertext_is_purged() -> Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let mailbox = MailboxOwner::new();
    relay.register(&mailbox.registration(NOW + 60), NOW)?;
    let packet = EncryptedPacket::from_untrusted(b"synthetic-ciphertext".to_vec());
    let request = mailbox
        .sender_capability()
        .authorize(MessageId::random(), packet, NOW + 1);
    relay.enqueue(&request, NOW)?;

    let fetch = mailbox.receiver_capability().authorize_fetch(NOW + 60);
    assert_eq!(relay.fetch(&fetch, NOW)?.len(), 1);
    assert!(matches!(
        relay.fetch(&fetch, NOW),
        Err(LabError::Unauthorized)
    ));
    assert_eq!(relay.purge_expired(NOW + 1)?, 1);
    assert_eq!(relay.queued_message_count()?, 0);
    Ok(())
}

#[test]
fn restart_sweeps_idle_expired_ciphertext_without_a_recipient_fetch() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("relay.sqlite");
    let mailbox = MailboxOwner::new();
    let packet = EncryptedPacket::from_untrusted(b"restart-expiry-ciphertext".to_vec());
    let packet_bytes = packet.as_bytes().to_vec();

    let mut relay = Relay::open_at(&database, NOW)?;
    relay.register(&mailbox.registration(NOW + 60), NOW)?;
    relay.enqueue(
        &mailbox
            .sender_capability()
            .authorize(MessageId::random(), packet, NOW + 1),
        NOW,
    )?;
    drop(relay);
    assert!(contains(&fs::read(&database)?, &packet_bytes));

    let relay = Relay::open_at(&database, NOW + 2)?;
    drop(relay);
    let connection = Connection::open(&database)?;
    let queued = connection.query_row("SELECT COUNT(*) FROM messages", [], |row| {
        row.get::<_, i64>(0)
    })?;
    assert_eq!(queued, 0);
    assert!(!contains(&fs::read(&database)?, &packet_bytes));
    Ok(())
}

#[test]
fn deleted_mailbox_cannot_be_resurrected_by_registration_or_send_replay()
-> Result<(), Box<dyn Error>> {
    let mut relay = Relay::open_in_memory()?;
    let mailbox = MailboxOwner::new();
    let registration = mailbox.registration(NOW + 60);
    relay.register(&registration, NOW)?;
    let send = mailbox.sender_capability().authorize(
        MessageId::random(),
        EncryptedPacket::from_untrusted(b"captured-ciphertext".to_vec()),
        NOW + 3_600,
    );
    relay.enqueue(&send, NOW)?;
    relay.delete_mailbox(
        &mailbox.manager_capability().authorize_delete(NOW + 60),
        NOW + 1,
    )?;

    assert!(matches!(
        relay.register(&registration, NOW + 1),
        Err(LabError::MailboxConflict)
    ));
    assert!(matches!(
        relay.enqueue(&send, NOW + 1),
        Err(LabError::MailboxNotFound)
    ));
    Ok(())
}

#[test]
fn concurrent_identical_sends_resolve_to_stored_plus_duplicate() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("relay.sqlite");
    let mailbox = MailboxOwner::new();
    let mut setup_relay = Relay::open_at(&database, NOW)?;
    setup_relay.register(&mailbox.registration(NOW + 60), NOW)?;
    drop(setup_relay);

    let request = mailbox.sender_capability().authorize(
        MessageId::random(),
        EncryptedPacket::from_untrusted(b"concurrent-ciphertext".to_vec()),
        NOW + 60,
    );
    let mut relay_one = Relay::open_at(&database, NOW)?;
    let mut relay_two = Relay::open_at(&database, NOW)?;
    let barrier = Arc::new(Barrier::new(3));
    let request_one = request.clone();
    let request_two = request;

    let (first, second) = thread::scope(|scope| {
        let barrier_one = Arc::clone(&barrier);
        let barrier_two = Arc::clone(&barrier);
        let one = scope.spawn(move || {
            barrier_one.wait();
            relay_one.enqueue(&request_one, NOW)
        });
        let two = scope.spawn(move || {
            barrier_two.wait();
            relay_two.enqueue(&request_two, NOW)
        });
        barrier.wait();
        let first = one.join().map_err(|_| LabError::Storage)??;
        let second = two.join().map_err(|_| LabError::Storage)??;
        Ok::<_, LabError>((first, second))
    })?;

    assert!(
        matches!(first, EnqueueOutcome::Stored) && matches!(second, EnqueueOutcome::Duplicate)
            || matches!(first, EnqueueOutcome::Duplicate)
                && matches!(second, EnqueueOutcome::Stored)
    );
    let mut verification = Relay::open_at(&database, NOW)?;
    assert_eq!(verification.queued_message_count_at(NOW)?, 1);
    Ok(())
}

#[test]
fn relay_schema_has_no_users_contacts_conversations_or_plaintext_columns()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("relay.sqlite");
    let relay = Relay::open(&database)?;
    drop(relay);
    let connection = Connection::open(database)?;
    let mut statement = connection.prepare(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND sql IS NOT NULL ORDER BY name",
    )?;
    let schema = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join("\n")
        .to_lowercase();
    for prohibited in [
        "plaintext",
        "contact",
        "conversation",
        "phone",
        "email",
        "username",
    ] {
        assert!(
            !schema.contains(prohibited),
            "prohibited schema term: {prohibited}"
        );
    }
    Ok(())
}
