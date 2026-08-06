use std::error::Error;

use crate::capability::MailboxOwner;
use crate::client::{OlmClient, VerifiedPeerPreKey};
use crate::{
    AckOutcome, ConversationId, EncryptedPacket, EnqueueOutcome, LabError, MessageId, Relay,
};

const NOW: u64 = 1_800_000_000;

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
    let target_registration = target.registration(NOW + 60);
    assert!(relay.register(&target_registration, NOW)?);
    assert!(!relay.register(&target_registration, NOW)?);

    let mut unauthorized_registration = attacker.registration(NOW + 60);
    unauthorized_registration.queue_id = target.queue_id();
    assert!(matches!(
        relay.register(&unauthorized_registration, NOW),
        Err(LabError::Unauthorized)
    ));

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

    let other_mailbox = MailboxOwner::new();
    assert!(matches!(
        other_mailbox
            .receiver_capability()
            .verify_envelope(envelope, NOW),
        Err(LabError::Unauthorized)
    ));

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

    let mut changed_expiry = envelope.clone();
    changed_expiry.expires_at += 1;
    assert!(matches!(
        receiver.verify_envelope(&changed_expiry, NOW),
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
fn ack_binding_and_lost_request_or_response_retries_are_safe() -> Result<(), Box<dyn Error>> {
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
    let retained_ack = receiver.authorize_ack(&opened, NOW + 60);

    let mut substituted = retained_ack.clone();
    substituted.message_id = second_id;
    assert!(matches!(
        relay.acknowledge(&substituted, NOW),
        Err(LabError::Unauthorized)
    ));
    assert_eq!(relay.queued_message_count()?, 2);

    let mut changed_digest = retained_ack.clone();
    changed_digest.packet_hash = [0_u8; 32];
    assert!(matches!(
        relay.acknowledge(&changed_digest, NOW),
        Err(LabError::Unauthorized)
    ));
    // The signed request was retained but its first transmission was lost.
    assert_eq!(relay.acknowledge(&retained_ack, NOW)?, AckOutcome::Deleted);
    // The deletion committed but its response was lost, so the same request
    // reaches the tombstone and confirms the prior result.
    assert_eq!(
        relay.acknowledge(&retained_ack, NOW)?,
        AckOutcome::AlreadyDeleted
    );
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
