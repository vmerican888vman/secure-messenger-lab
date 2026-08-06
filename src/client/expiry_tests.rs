use std::error::Error;

use crate::capability::MailboxOwner;
use crate::client::OlmClient;
use crate::{ConversationId, LabError, Relay};

const NOW: u64 = 1_800_000_000;

#[test]
fn expired_verified_prekey_cannot_create_an_outbound_session() -> Result<(), Box<dyn Error>> {
    let conversation = ConversationId::random();
    let mut alice = OlmClient::new(conversation);
    let mut bob = OlmClient::new(conversation);
    let bob_bundle = bob.prekey_bundle(NOW + 1)?;
    let verified_bob = bob_bundle.verify(bob.signing_identity(), NOW)?;

    assert!(matches!(
        alice.start_outbound_session(&verified_bob, NOW + 1),
        Err(LabError::PeerVerificationFailed)
    ));
    assert!(matches!(
        alice.seal("must-not-send", NOW + 1),
        Err(LabError::MissingSession)
    ));
    Ok(())
}

#[test]
fn expired_verified_envelopes_cannot_advance_initial_or_existing_sessions()
-> Result<(), Box<dyn Error>> {
    let conversation = ConversationId::random();
    let mut alice = OlmClient::new(conversation);
    let mut bob = OlmClient::new(conversation);
    let alice_bundle = alice.prekey_bundle(NOW + 60)?;
    let bob_bundle = bob.prekey_bundle(NOW + 60)?;
    let verified_alice = alice_bundle.verify(alice.signing_identity(), NOW)?;
    let verified_bob = bob_bundle.verify(bob.signing_identity(), NOW)?;
    alice.start_outbound_session(&verified_bob, NOW)?;

    let mut relay = Relay::open_in_memory()?;
    let mailbox = MailboxOwner::new();
    relay.register(&mailbox.registration(NOW + 60), NOW)?;
    let sender = mailbox.sender_capability();
    let receiver = mailbox.receiver_capability();

    let (expired_initial_id, expired_initial_packet) = alice.seal("expired-initial", NOW)?;
    relay.enqueue(
        &sender.authorize(expired_initial_id, expired_initial_packet, NOW + 1),
        NOW,
    )?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let expired_initial = fetched
        .iter()
        .find(|envelope| envelope.message_id == expired_initial_id)
        .ok_or("missing initial envelope")?;
    assert!(matches!(
        bob.open_initial(
            receiver.verify_envelope(expired_initial, NOW)?,
            &verified_alice,
            NOW + 1,
        ),
        Err(LabError::Unauthorized)
    ));

    let (fresh_initial_id, fresh_initial_packet) = alice.seal("fresh-initial", NOW)?;
    relay.enqueue(
        &sender.authorize(fresh_initial_id, fresh_initial_packet, NOW + 60),
        NOW,
    )?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let fresh_initial = fetched
        .iter()
        .find(|envelope| envelope.message_id == fresh_initial_id)
        .ok_or("missing fresh initial envelope")?;
    bob.open_initial(
        receiver.verify_envelope(fresh_initial, NOW)?,
        &verified_alice,
        NOW,
    )?;

    let (expired_message_id, expired_packet) = alice.seal("expired-established", NOW)?;
    relay.enqueue(
        &sender.authorize(expired_message_id, expired_packet, NOW + 1),
        NOW,
    )?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let expired_message = fetched
        .iter()
        .find(|envelope| envelope.message_id == expired_message_id)
        .ok_or("missing established envelope")?;
    assert!(matches!(
        bob.open(receiver.verify_envelope(expired_message, NOW)?, NOW + 1),
        Err(LabError::Unauthorized)
    ));

    let (fresh_message_id, fresh_packet) = alice.seal("fresh-established", NOW)?;
    relay.enqueue(
        &sender.authorize(fresh_message_id, fresh_packet, NOW + 60),
        NOW,
    )?;
    let fetched = relay.fetch(&receiver.authorize_fetch(NOW + 60), NOW)?;
    let fresh_message = fetched
        .iter()
        .find(|envelope| envelope.message_id == fresh_message_id)
        .ok_or("missing fresh established envelope")?;
    let opened = bob.open(receiver.verify_envelope(fresh_message, NOW)?, NOW)?;
    assert_eq!(opened.message().body, "fresh-established");

    Ok(())
}
