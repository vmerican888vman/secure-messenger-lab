use std::error::Error;

use secure_messenger_lab::{
    AckOutcome, ConversationId, EncryptedPacket, LabError, MailboxOwner, MessageId, OlmClient,
    Relay,
};

const NOW: u64 = 1_800_000_000;
const MAX_MESSAGE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

#[test]
fn signed_request_time_boundaries_fail_closed_for_every_command() -> Result<(), Box<dyn Error>> {
    let conversation = ConversationId::random();
    let mut alice = OlmClient::new(conversation);
    let mut bob = OlmClient::new(conversation);
    let alice_bundle = alice.prekey_bundle(NOW + 60)?;
    let bob_bundle = bob.prekey_bundle(NOW + 60)?;
    let verified_alice = alice_bundle.verify(alice.signing_identity(), NOW)?;
    let verified_bob = bob_bundle.verify(bob.signing_identity(), NOW)?;
    alice.start_outbound_session(&verified_bob, NOW)?;

    let mailbox = MailboxOwner::new();
    let mut relay = Relay::open_in_memory()?;
    for invalid_until in [NOW - 1, NOW, NOW + 301] {
        assert!(matches!(
            relay.register(&mailbox.registration(invalid_until), NOW),
            Err(LabError::RequestExpired)
        ));
    }
    relay.register(&mailbox.registration(NOW + 60), NOW)?;

    let receiver = mailbox.receiver_capability();
    let manager = mailbox.manager_capability();
    for invalid_until in [NOW - 1, NOW, NOW + 301] {
        assert!(matches!(
            relay.fetch(&receiver.authorize_fetch(invalid_until), NOW),
            Err(LabError::RequestExpired)
        ));
        assert!(matches!(
            relay.delete_mailbox(&manager.authorize_delete(invalid_until), NOW),
            Err(LabError::RequestExpired)
        ));
    }

    let (message_id, packet) = alice.seal("request-boundary", NOW)?;
    relay.enqueue(
        &mailbox
            .sender_capability()
            .authorize(message_id, packet, NOW + 60),
        NOW,
    )?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let envelope = fetched.first().ok_or("missing request-boundary envelope")?;
    let opened = bob.open_initial(
        receiver.verify_envelope(envelope, NOW)?,
        &verified_alice,
        NOW,
    )?;
    for invalid_until in [NOW - 1, NOW, NOW + 301] {
        assert!(matches!(
            relay.acknowledge(&receiver.authorize_ack(&opened, invalid_until), NOW),
            Err(LabError::RequestExpired)
        ));
    }

    let maximum_window = receiver.authorize_fetch(NOW + 300);
    assert_eq!(relay.fetch(&maximum_window, NOW)?.len(), 1);
    assert!(matches!(
        relay.fetch(&maximum_window, NOW),
        Err(LabError::Unauthorized)
    ));

    assert_eq!(
        relay.acknowledge(&receiver.authorize_ack(&opened, NOW + 60), NOW)?,
        AckOutcome::Deleted
    );
    Ok(())
}

#[test]
fn message_retention_expiry_bounds_fail_closed() -> Result<(), Box<dyn Error>> {
    let mailbox = MailboxOwner::new();
    let sender = mailbox.sender_capability();
    let mut relay = Relay::open_in_memory()?;
    relay.register(&mailbox.registration(NOW + 60), NOW)?;

    for invalid_expiry in [NOW, NOW + MAX_MESSAGE_TTL_SECONDS + 1] {
        let request = sender.authorize(
            MessageId::random(),
            EncryptedPacket::from_untrusted(b"synthetic-ciphertext".to_vec()),
            invalid_expiry,
        );
        assert!(matches!(
            relay.enqueue(&request, NOW),
            Err(LabError::InvalidExpiry)
        ));
    }
    assert_eq!(relay.queued_message_count_at(NOW)?, 0);
    Ok(())
}
