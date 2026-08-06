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

    let result = bob.create_inbound_session(
        SessionConfig::version_1(),
        alice.curve25519_key(),
        &pre_key_message,
    )?;
    assert_eq!(result.plaintext, plaintext);

    // The consumed one-time key must be gone; an unused one must remain.
    assert!(!bob.contains_one_time_key(bob_otk));
    let surviving = bob.generate_one_time_keys(1).created[0];
    assert!(bob.contains_one_time_key(surviving));

    Ok(())
}

/// Sol's blocking reproduction from the patch-0001 re-review: a hand-edited
/// pickle holding the same private key under two key IDs. The derived reverse
/// map collapses the aliases, so after one alias is consumed a map-based
/// membership check reports `false` while a private copy is still stored.
/// Membership must instead agree with the authoritative private-key store.
#[test]
fn duplicate_secret_pickle_membership_stays_consistent_with_held_keys() -> Result<(), Box<dyn Error>>
{
    use vodozemac::olm::AccountPickle;

    let mut account = Account::new();
    let created = account.generate_one_time_keys(2).created;
    let aliased_public = created[0];
    let vanished_public = created[1];
    account.mark_keys_as_published();

    // Duplicate the first private key over the second key ID in the pickle.
    let mut json: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&account.pickle())?)?;
    let private_keys = json
        .pointer_mut("/one_time_keys/private_keys")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| String::from("account pickle JSON shape changed"))?;
    let entries: Vec<(String, serde_json::Value)> = private_keys
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let [(_, first_secret), (second_id, _)] = entries.as_slice() else {
        return Err("expected exactly two one-time keys".into());
    };
    private_keys.insert(second_id.clone(), first_secret.clone());

    let pickle: AccountPickle = serde_json::from_value(json)?;
    let mut account = Account::from_pickle(pickle);
    assert_eq!(account.stored_one_time_key_count(), 2);
    assert!(account.contains_one_time_key(aliased_public));
    assert!(!account.contains_one_time_key(vanished_public));

    // Consume one alias through a real inbound session.
    let alice = Account::new();
    let mut alice_session = alice.create_outbound_session(
        SessionConfig::version_1(),
        account.curve25519_key(),
        aliased_public,
    )?;
    let plaintext = b"alias probe";
    let message = alice_session.encrypt(plaintext)?;
    let pre_key_message = match message {
        OlmMessage::PreKey(pre_key) => pre_key,
        OlmMessage::Normal(_) => return Err("first message must be a pre-key message".into()),
    };
    let result = account.create_inbound_session(
        SessionConfig::version_1(),
        alice.curve25519_key(),
        &pre_key_message,
    )?;
    assert_eq!(result.plaintext, plaintext);

    // One aliased private copy remains stored (the reverse map removed the
    // entry it pointed at). Membership must agree with the store: true.
    assert_eq!(account.stored_one_time_key_count(), 1);
    assert!(account.contains_one_time_key(aliased_public));

    Ok(())
}
