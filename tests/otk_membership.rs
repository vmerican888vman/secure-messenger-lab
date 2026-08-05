//! Behavioral checks for local vodozemac patch 0001
//! (`Account::contains_one_time_key`), the pinned API required by
//! docs/phase2-design-decisions.md section 3. The patch is UNREVIEWED until the
//! independent reviewers sign off; these tests pin the exact membership
//! semantics the Phase-2 validation will rely on.

use std::error::Error;

use vodozemac::olm::{Account, OlmMessage, SessionConfig};

#[test]
fn generated_one_time_keys_are_found_published_or_not() {
    let mut account = Account::new();
    let created = account.generate_one_time_keys(2).created;
    assert_eq!(created.len(), 2);

    for key in &created {
        assert!(account.contains_one_time_key(*key));
    }

    // Marking keys as published must not remove them from the store.
    account.mark_keys_as_published();
    assert!(account.one_time_keys().is_empty());
    for key in &created {
        assert!(account.contains_one_time_key(*key));
    }
}

#[test]
fn fallback_keys_are_never_found() {
    let mut account = Account::new();
    account.generate_fallback_key();

    for key in account.fallback_key().values() {
        assert!(!account.contains_one_time_key(*key));
    }
}

#[test]
fn foreign_account_keys_are_not_found() {
    let alice = Account::new();
    let mut bob = Account::new();

    let bob_keys = bob.generate_one_time_keys(1).created;
    for key in &bob_keys {
        assert!(!alice.contains_one_time_key(*key));
        assert!(bob.contains_one_time_key(*key));
    }
}

#[test]
fn consumed_one_time_key_is_no_longer_found() -> Result<(), Box<dyn Error>> {
    let alice = Account::new();
    let mut bob = Account::new();

    let bob_otk = bob.generate_one_time_keys(1).created[0];
    bob.mark_keys_as_published();
    assert!(bob.contains_one_time_key(bob_otk));

    // Alice starts an outbound session against Bob's one-time key; Bob accepts
    // the inbound pre-key message, which consumes the key.
    let mut alice_session =
        alice.create_outbound_session(SessionConfig::version_1(), bob.curve25519_key(), bob_otk)?;
    let plaintext = b"membership probe";
    let message = alice_session.encrypt(plaintext)?;
    let pre_key_message = match message {
        OlmMessage::PreKey(pre_key) => pre_key,
        OlmMessage::Normal(_) => return Err("first message must be a pre-key message".into()),
    };

    let result =
        bob.create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &pre_key_message)?;
    assert_eq!(result.plaintext, plaintext);

    // The consumed one-time key must be gone; an unused one must remain.
    assert!(!bob.contains_one_time_key(bob_otk));
    let surviving = bob.generate_one_time_keys(1).created[0];
    assert!(bob.contains_one_time_key(surviving));

    Ok(())
}
