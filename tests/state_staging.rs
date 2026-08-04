use std::error::Error;

use secure_messenger_lab::{
    AckOutcome, ConversationId, LabError, MailboxOwner, MessageId, OlmClient, Relay,
    VerifiedPeerPreKey,
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

fn different_message_id(inner: MessageId) -> MessageId {
    loop {
        let candidate = MessageId::random();
        if candidate != inner {
            return candidate;
        }
    }
}

#[test]
fn rejected_initial_binding_does_not_consume_the_one_time_key() -> Result<(), Box<dyn Error>> {
    let (mut alice, mut bob, verified_alice) = paired_clients()?;
    let mailbox = MailboxOwner::new();
    let sender = mailbox.sender_capability();
    let receiver = mailbox.receiver_capability();
    let mut relay = Relay::open_in_memory()?;
    relay.register(&mailbox.registration(NOW + 60), NOW)?;

    let (inner_id, packet) = alice.seal("binding-invalid-initial", NOW)?;
    let wrong_outer_id = different_message_id(inner_id);
    relay.enqueue(&sender.authorize(wrong_outer_id, packet, NOW + 60), NOW)?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let invalid = fetched
        .iter()
        .find(|envelope| envelope.message_id == wrong_outer_id)
        .ok_or("missing binding-invalid initial envelope")?;
    assert!(matches!(
        bob.open_initial(
            receiver.verify_envelope(invalid, NOW)?,
            &verified_alice,
            NOW,
        ),
        Err(LabError::MessageIdMismatch)
    ));

    let (valid_id, valid_packet) = alice.seal("valid-after-rejected-initial", NOW + 1)?;
    relay.enqueue(&sender.authorize(valid_id, valid_packet, NOW + 60), NOW)?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let valid = fetched
        .iter()
        .find(|envelope| envelope.message_id == valid_id)
        .ok_or("missing valid initial envelope")?;
    let opened = bob.open_initial(receiver.verify_envelope(valid, NOW)?, &verified_alice, NOW)?;
    assert_eq!(opened.message().body, "valid-after-rejected-initial");
    Ok(())
}

#[test]
fn rejected_established_binding_does_not_advance_the_ratchet() -> Result<(), Box<dyn Error>> {
    let (mut alice, mut bob, verified_alice) = paired_clients()?;
    let mailbox = MailboxOwner::new();
    let sender = mailbox.sender_capability();
    let receiver = mailbox.receiver_capability();
    let mut relay = Relay::open_in_memory()?;
    relay.register(&mailbox.registration(NOW + 60), NOW)?;

    let (initial_id, initial_packet) = alice.seal("initial", NOW)?;
    relay.enqueue(&sender.authorize(initial_id, initial_packet, NOW + 60), NOW)?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let initial = fetched
        .iter()
        .find(|envelope| envelope.message_id == initial_id)
        .ok_or("missing initial envelope")?;
    let opened = bob.open_initial(
        receiver.verify_envelope(initial, NOW)?,
        &verified_alice,
        NOW,
    )?;
    let initial_ack = receiver.authorize_ack(&opened, NOW + 60);
    assert_eq!(relay.acknowledge(&initial_ack, NOW)?, AckOutcome::Deleted);

    let (inner_id, packet) = alice.seal("binding-invalid-established", NOW + 1)?;
    let wrong_outer_id = different_message_id(inner_id);
    relay.enqueue(&sender.authorize(wrong_outer_id, packet, NOW + 60), NOW)?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let invalid = fetched
        .iter()
        .find(|envelope| envelope.message_id == wrong_outer_id)
        .ok_or("missing binding-invalid established envelope")?;
    let verified_invalid = receiver.verify_envelope(invalid, NOW)?;
    assert!(matches!(
        bob.open(verified_invalid.clone(), NOW),
        Err(LabError::MessageIdMismatch)
    ));
    assert!(matches!(
        bob.open(verified_invalid, NOW),
        Err(LabError::MessageIdMismatch)
    ));

    let (valid_id, valid_packet) = alice.seal("valid-after-rejected-established", NOW + 2)?;
    relay.enqueue(&sender.authorize(valid_id, valid_packet, NOW + 60), NOW)?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let valid = fetched
        .iter()
        .find(|envelope| envelope.message_id == valid_id)
        .ok_or("missing valid established envelope")?;
    let opened = bob.open(receiver.verify_envelope(valid, NOW)?, NOW)?;
    assert_eq!(opened.message().body, "valid-after-rejected-established");
    Ok(())
}
