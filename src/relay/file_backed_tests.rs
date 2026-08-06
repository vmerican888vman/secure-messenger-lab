//! File-backed (path-using) relay tests, moved in-crate from
//! `tests/e2e_relay.rs` when the raw-path constructors became
//! `#[cfg(test)] pub(crate)`. Every test is behaviorally identical to its
//! integration-test original; only the import path changed
//! (`secure_messenger_lab::` -> `crate::`). The in-memory end-to-end tests
//! remain in `tests/e2e_relay.rs`.

use std::error::Error;
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use rusqlite::Connection;

use crate::capability::MailboxOwner;
use crate::client::{OlmClient, VerifiedPeerPreKey};
use crate::{
    AckOutcome, ConversationId, EncryptedPacket, EnqueueOutcome, LabError, MessageId, Relay,
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
    let mut relay = Relay::open_with_path_for_test(&database)?;
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
    let mut reopened = Relay::open_at_with_path_for_test(&database, NOW + 1)?;
    assert_eq!(reopened.queued_message_count_at(NOW + 1)?, 0);
    assert_eq!(reopened.tombstone_count()?, 1);
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

    let mut relay = Relay::open_at_with_path_for_test(&database, NOW)?;
    relay.register(&mailbox.registration(NOW + 60), NOW)?;
    relay.enqueue(
        &mailbox
            .sender_capability()
            .authorize(MessageId::random(), packet, NOW + 1),
        NOW,
    )?;
    drop(relay);
    assert!(contains(&fs::read(&database)?, &packet_bytes));

    let relay = Relay::open_at_with_path_for_test(&database, NOW + 2)?;
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
fn concurrent_identical_sends_resolve_to_stored_plus_duplicate() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("relay.sqlite");
    let mailbox = MailboxOwner::new();
    let mut setup_relay = Relay::open_at_with_path_for_test(&database, NOW)?;
    setup_relay.register(&mailbox.registration(NOW + 60), NOW)?;
    drop(setup_relay);

    let request = mailbox.sender_capability().authorize(
        MessageId::random(),
        EncryptedPacket::from_untrusted(b"concurrent-ciphertext".to_vec()),
        NOW + 60,
    );
    let mut relay_one = Relay::open_at_with_path_for_test(&database, NOW)?;
    let mut relay_two = Relay::open_at_with_path_for_test(&database, NOW)?;
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
    let mut verification = Relay::open_at_with_path_for_test(&database, NOW)?;
    assert_eq!(verification.queued_message_count_at(NOW)?, 1);
    Ok(())
}

#[test]
fn concurrent_conflicting_sends_resolve_to_stored_plus_conflict() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("relay.sqlite");
    let mailbox = MailboxOwner::new();
    let mut setup_relay = Relay::open_at_with_path_for_test(&database, NOW)?;
    setup_relay.register(&mailbox.registration(NOW + 60), NOW)?;
    drop(setup_relay);

    let sender = mailbox.sender_capability();
    let message_id = MessageId::random();
    let request_one = sender.authorize(
        message_id,
        EncryptedPacket::from_untrusted(b"concurrent-conflict-one".to_vec()),
        NOW + 60,
    );
    let request_two = sender.authorize(
        message_id,
        EncryptedPacket::from_untrusted(b"concurrent-conflict-two".to_vec()),
        NOW + 60,
    );
    let mut relay_one = Relay::open_at_with_path_for_test(&database, NOW)?;
    let mut relay_two = Relay::open_at_with_path_for_test(&database, NOW)?;
    let barrier = Arc::new(Barrier::new(3));

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
        let first = one.join().map_err(|_| LabError::Storage)?;
        let second = two.join().map_err(|_| LabError::Storage)?;
        Ok::<_, LabError>((first, second))
    })?;

    let outcomes = [first, second];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(EnqueueOutcome::Stored)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(LabError::MessageConflict)))
            .count(),
        1
    );
    let mut verification = Relay::open_at_with_path_for_test(&database, NOW)?;
    assert_eq!(verification.queued_message_count_at(NOW)?, 1);
    Ok(())
}

#[test]
fn relay_schema_has_no_users_contacts_conversations_or_plaintext_columns()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("relay.sqlite");
    let relay = Relay::open_with_path_for_test(&database)?;
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
