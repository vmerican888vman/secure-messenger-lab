use std::time::{SystemTime, UNIX_EPOCH};

use secure_messenger_lab::{
    AckOutcome, ConversationId, EnqueueOutcome, LabError, MailboxOwner, OlmClient, PrivateStoreDir,
    Relay, Result, StoreKind,
};

fn main() {
    if let Err(error) = run_demo() {
        eprintln!("Phase 0 demo failed: {error}");
        std::process::exit(1);
    }
}

fn run_demo() -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LabError::InvalidPayload)?
        .as_secs();
    let directory = tempfile::tempdir().map_err(|_| LabError::Storage)?;
    let store_dir = PrivateStoreDir::create(&directory.path().join("relay"), StoreKind::Relay)?;
    let mut relay = Relay::create(store_dir)?;

    let conversation = ConversationId::random();
    let mut alice = OlmClient::new(conversation);
    let mut bob = OlmClient::new(conversation);
    let alice_pre_key = alice.prekey_bundle(now + 60)?;
    let bob_pre_key = bob.prekey_bundle(now + 60)?;
    let verified_alice = alice_pre_key.verify(alice.signing_identity(), now)?;
    let verified_bob = bob_pre_key.verify(bob.signing_identity(), now)?;

    let alice_inbox = MailboxOwner::new();
    let bob_inbox = MailboxOwner::new();
    relay.register(&alice_inbox.registration(now + 60), now)?;
    relay.register(&bob_inbox.registration(now + 60), now)?;

    alice.start_outbound_session(&verified_bob, now)?;
    let (first_id, first_packet) = alice.seal("phase-zero-demo-message", now)?;
    let first_request =
        bob_inbox
            .sender_capability()
            .authorize(first_id, first_packet.clone(), now + 3_600);
    if relay.enqueue(&first_request, now)? != EnqueueOutcome::Stored {
        return Err(LabError::Storage);
    }

    let fetched = relay.fetch(
        &bob_inbox.receiver_capability().authorize_fetch(now + 60),
        now,
    )?;
    let Some(first) = fetched.first() else {
        return Err(LabError::MessageNotFound);
    };
    let bob_receiver = bob_inbox.receiver_capability();
    let verified_first = bob_receiver.verify_envelope(first, now)?;
    let received = bob.open_initial(verified_first, &verified_alice, now)?;
    if received.message().body != "phase-zero-demo-message" {
        return Err(LabError::InvalidPayload);
    }
    let ack = bob_receiver.authorize_ack(&received, now + 60);
    if relay.acknowledge(&ack, now)? != AckOutcome::Deleted {
        return Err(LabError::Storage);
    }

    let (reply_id, reply_packet) = bob.seal("phase-zero-demo-reply", now + 1)?;
    let reply_request =
        alice_inbox
            .sender_capability()
            .authorize(reply_id, reply_packet.clone(), now + 3_600);
    relay.enqueue(&reply_request, now + 1)?;
    let replies = relay.fetch(
        &alice_inbox.receiver_capability().authorize_fetch(now + 61),
        now + 1,
    )?;
    let Some(reply) = replies.first() else {
        return Err(LabError::MessageNotFound);
    };
    let alice_receiver = alice_inbox.receiver_capability();
    let verified_reply = alice_receiver.verify_envelope(reply, now + 1)?;
    let received_reply = alice.open(verified_reply, now + 1)?;
    if received_reply.message().body != "phase-zero-demo-reply" {
        return Err(LabError::InvalidPayload);
    }
    relay.acknowledge(
        &alice_receiver.authorize_ack(&received_reply, now + 61),
        now + 1,
    )?;

    if relay.queued_message_count()? != 0 {
        return Err(LabError::Storage);
    }
    println!(
        "PASS: two clients exchanged encrypted messages; relay queue is empty after authenticated ACKs"
    );
    Ok(())
}
