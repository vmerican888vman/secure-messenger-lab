//! Integration tests for the D1 persistence-owning façade
//! (`PersistentClient`, design section 2). These tests touch only the
//! public API; the protector mirrors the XOR test protector in
//! `src/persistence/sqlite.rs`.

use std::error::Error;
use std::path::PathBuf;

use rusqlite::{Connection, params};
use secure_messenger_lab::{
    MailboxRegistration, PROTOCOL_DOMAIN, PersistentClient, PrivateStoreDir, ProfileBinding,
    ProtectionLevel, QueueId, RedactedContactOffer, RegistrationOutcome, StateKeyProtector,
    StoreKind,
};
use tempfile::TempDir;
use vodozemac::olm::Account;
use vodozemac::{Ed25519Keypair, Ed25519Signature};
use zeroize::Zeroizing;

const NOW: u64 = 1_800_000_000;
const DEK_BYTES: usize = 32;

/// XOR test protector with an independently held binding, mirroring the
/// one in `src/persistence/sqlite.rs` tests.
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
    fn expected_binding(&self) -> secure_messenger_lab::Result<ProfileBinding> {
        Ok(self.binding)
    }

    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::SoftwareBacked
    }

    fn wrap_dek(&self, dek: &Zeroizing<[u8; DEK_BYTES]>) -> secure_messenger_lab::Result<Vec<u8>> {
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
    ) -> secure_messenger_lab::Result<()> {
        const PREFIX: &[u8] = b"state-wrap/v1";
        let expected = PREFIX.len() + 16 + 16 + DEK_BYTES;
        if wrapped_dek.len() != expected
            || &wrapped_dek[..PREFIX.len()] != PREFIX
            || &wrapped_dek[PREFIX.len()..PREFIX.len() + 16] != self.binding.profile_id()
            || &wrapped_dek[PREFIX.len() + 16..PREFIX.len() + 32] != self.binding.key_ref()
        {
            return Err(secure_messenger_lab::LabError::Storage);
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
}

/// Replica of `capability::canonical` (crate-private); the signing-byte
/// constructions are re-derived here so the tests can verify signatures
/// through the public API only.
fn canonical(action: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut append = |part: &[u8]| {
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(part);
    };
    append(PROTOCOL_DOMAIN);
    append(action);
    for part in parts {
        append(part);
    }
    encoded
}

fn prekey_signing_bytes(
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

fn registration_signing_bytes(request: &MailboxRegistration) -> Vec<u8> {
    canonical(
        b"register",
        &[
            request.queue_id.as_bytes(),
            request.send_key.as_bytes(),
            request.receive_key.as_bytes(),
            request.manage_key.as_bytes(),
            request.nonce.as_bytes(),
            &request.valid_until.to_be_bytes(),
        ],
    )
}

/// A genuine peer contact offer plus the peer's send capability material.
struct PeerMaterial {
    offer: RedactedContactOffer,
    queue_id: QueueId,
    send_keypair: Ed25519Keypair,
}

fn peer_material(valid_until: u64) -> Result<PeerMaterial, Box<dyn Error>> {
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
        valid_until,
        signature: peer_account.sign(b""),
    };
    offer.signature = peer_account.sign(prekey_signing_bytes(
        &offer.signing_identity,
        &offer.curve_identity,
        &offer.one_time_key,
        valid_until,
    ));
    Ok(PeerMaterial {
        offer,
        queue_id: QueueId::random(),
        send_keypair: Ed25519Keypair::new(),
    })
}

fn store_path(temp: &TempDir) -> PathBuf {
    temp.path().join("client")
}

fn database_path(temp: &TempDir) -> PathBuf {
    store_path(temp).join("client-state.sqlite3")
}

fn create_dir(temp: &TempDir) -> Result<PrivateStoreDir, Box<dyn Error>> {
    Ok(PrivateStoreDir::create(
        &store_path(temp),
        StoreKind::ClientState,
    )?)
}

fn open_dir(temp: &TempDir) -> Result<PrivateStoreDir, Box<dyn Error>> {
    // Grace window for the macOS vnode release lag on immediate
    // drop-then-reopen (see the boundary's module docs).
    for _ in 0..50 {
        match PrivateStoreDir::open(&store_path(temp), StoreKind::ClientState) {
            Ok(dir) => return Ok(dir),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    Ok(PrivateStoreDir::open(
        &store_path(temp),
        StoreKind::ClientState,
    )?)
}

fn create_client(temp: &TempDir) -> Result<PersistentClient<TestProtector>, Box<dyn Error>> {
    Ok(PersistentClient::create(
        create_dir(temp)?,
        protector(),
        NOW,
    )?)
}

fn open_client(temp: &TempDir) -> Result<PersistentClient<TestProtector>, Box<dyn Error>> {
    Ok(PersistentClient::open(open_dir(temp)?, protector())?)
}

/// Commit a verified contact and establish the outbound session with a
/// genuine peer bundle.
fn commit_contact_and_establish(
    client: &mut PersistentClient<TestProtector>,
) -> Result<(), Box<dyn Error>> {
    let peer = peer_material(NOW + 300)?;
    client.commit_verified_contact(
        peer.offer.signing_identity,
        peer.offer,
        peer.queue_id,
        Zeroizing::new(serde_json::to_vec(&peer.send_keypair)?),
        NOW,
    )?;
    client.establish_outbound_session(NOW)?;
    Ok(())
}

#[test]
fn create_requires_absent_and_open_requires_present() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    // Open requires an existing non-empty database.
    assert!(PersistentClient::open(create_dir(&temp)?, protector()).is_err());
    // Create works on the absent database.
    let client = PersistentClient::create(open_dir(&temp)?, protector(), NOW)?;
    drop(client);
    // A second create over the existing database fails.
    assert!(PersistentClient::create(open_dir(&temp)?, protector(), NOW).is_err());
    // And open now succeeds.
    open_client(&temp)?;
    Ok(())
}

#[test]
fn create_mutate_reopen_round_trips() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    let identity = client.public_identity()?;

    // Prekey action: the offer is the redacted view of the durable bundle.
    let offer = client.prekey_action(NOW + 300)?;
    assert_eq!(offer.signing_identity, identity.ed25519);
    assert_eq!(offer.curve_identity, identity.curve25519);
    identity
        .ed25519
        .verify(
            &prekey_signing_bytes(
                &offer.signing_identity,
                &offer.curve_identity,
                &offer.one_time_key,
                offer.valid_until,
            ),
            &offer.signature,
        )
        .map_err(|_| "offer signature did not verify")?;
    // A second prekey action is bounded out while one is pending.
    assert!(client.prekey_action(NOW + 300).is_err());

    // Peer binding and outbound session.
    let peer = peer_material(NOW + 300)?;
    client.commit_verified_contact(
        peer.offer.signing_identity,
        peer.offer,
        peer.queue_id,
        Zeroizing::new(serde_json::to_vec(&peer.send_keypair)?),
        NOW,
    )?;
    client.establish_outbound_session(NOW)?;
    assert!(client.establish_outbound_session(NOW).is_err());

    // Registration action and confirmed result.
    let action = client.registration_action(NOW + 3_600)?;
    assert_eq!(action.request.nonce.as_bytes(), &action.token);
    action
        .request
        .manage_key
        .verify(
            &registration_signing_bytes(&action.request),
            &action.request.signature,
        )
        .map_err(|_| "registration signature did not verify")?;
    client.record_registration_result(&action, RegistrationOutcome::Confirmed)?;

    drop(client);
    let mut client = open_client(&temp)?;
    assert_eq!(client.public_identity()?, identity);
    // Every committed record survived the reopen, proven behaviorally.
    assert!(
        client.prekey_action(NOW + 300).is_err(),
        "pending prekey lost"
    );
    let peer2 = peer_material(NOW + 300)?;
    assert!(
        client
            .commit_verified_contact(
                peer2.offer.signing_identity,
                peer2.offer,
                peer2.queue_id,
                Zeroizing::new(serde_json::to_vec(&peer2.send_keypair)?),
                NOW,
            )
            .is_err(),
        "peer binding lost"
    );
    assert!(
        client.establish_outbound_session(NOW).is_err(),
        "active session lost"
    );
    assert!(
        client
            .record_registration_result(&action, RegistrationOutcome::Confirmed)
            .is_err(),
        "consumed token replayed"
    );

    // Terminal-failed registration also round-trips.
    let failed = client.registration_action(NOW + 3_600)?;
    client.record_registration_result(&failed, RegistrationOutcome::Failed)?;
    drop(client);
    let mut client = open_client(&temp)?;
    assert_eq!(client.public_identity()?, identity);
    let third = client.registration_action(NOW + 3_600)?;
    client.record_registration_result(&third, RegistrationOutcome::Confirmed)?;
    Ok(())
}

#[test]
fn crash_reopen_discipline_between_every_mutator() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let client = create_client(&temp)?;
    let identity = client.public_identity()?;
    drop(client);

    let mut client = open_client(&temp)?;
    let offer = client.prekey_action(NOW + 300)?;
    drop(client);

    let mut client = open_client(&temp)?;
    assert_eq!(client.public_identity()?, identity);
    assert!(client.prekey_action(NOW + 300).is_err());
    commit_contact_and_establish(&mut client)?;
    drop(client);

    let mut client = open_client(&temp)?;
    assert!(client.establish_outbound_session(NOW).is_err());
    // The durable action token survives the reopen: mint now, consume
    // after the next reopen.
    let action = client.registration_action(NOW + 3_600)?;
    drop(client);

    let mut client = open_client(&temp)?;
    client.record_registration_result(&action, RegistrationOutcome::Confirmed)?;
    drop(client);

    let mut client = open_client(&temp)?;
    assert_eq!(client.public_identity()?, identity);
    assert!(client.prekey_action(NOW + 300).is_err());
    assert!(client.establish_outbound_session(NOW).is_err());
    assert!(
        client
            .record_registration_result(&action, RegistrationOutcome::Confirmed)
            .is_err()
    );
    let _ = offer;
    Ok(())
}

#[test]
fn reconcile_required_rejects_everything_until_reopen() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    let identity = client.public_identity()?;
    let offer = client.prekey_action(NOW + 300)?;
    let pending_action = client.registration_action(NOW + 3_600)?;

    // Tamper with the stored nonce through a second connection so the
    // next commit's exact-generation CAS fails (simulating an authentic
    // rollback / concurrent modification).
    let connection = Connection::open(database_path(&temp))?;
    let nonce: Vec<u8> =
        connection.query_row("SELECT nonce FROM client_state WHERE slot = 1", [], |row| {
            row.get(0)
        })?;
    let mut tampered = nonce.clone();
    let first = tampered.first_mut().ok_or("empty nonce")?;
    *first ^= 0x01;
    connection.execute(
        "UPDATE client_state SET nonce = ?1 WHERE slot = 1",
        params![tampered],
    )?;

    // The next mutator fails at commit (CAS) and enters ReconcileRequired.
    assert!(client.registration_action(NOW + 3_600).is_err());
    // ReconcileRequired: every operation rejects, including reads of
    // secret state; only the non-failing protection level stays.
    assert!(client.public_identity().is_err());
    assert!(client.pending_prekey_offer().is_err());
    assert!(client.prekey_action(NOW + 300).is_err());
    let peer = peer_material(NOW + 300)?;
    assert!(
        client
            .commit_verified_contact(
                peer.offer.signing_identity,
                peer.offer,
                peer.queue_id,
                Zeroizing::new(serde_json::to_vec(&peer.send_keypair)?),
                NOW,
            )
            .is_err()
    );
    assert!(client.establish_outbound_session(NOW).is_err());
    assert!(client.registration_action(NOW + 3_600).is_err());
    assert!(
        client
            .record_registration_result(&pending_action, RegistrationOutcome::Confirmed)
            .is_err()
    );
    assert_eq!(client.protection_level(), ProtectionLevel::SoftwareBacked);

    // Restore the authentic last-committed bytes, drop and reopen: the
    // last committed generation is recovered exactly.
    connection.execute(
        "UPDATE client_state SET nonce = ?1 WHERE slot = 1",
        params![nonce],
    )?;
    drop(connection);
    drop(client);
    let mut client = open_client(&temp)?;
    assert_eq!(client.public_identity()?, identity);
    assert_eq!(client.pending_prekey_offer()?, Some(offer));
    assert!(
        client.prekey_action(NOW + 300).is_err(),
        "last committed state (pending prekey) not recovered"
    );
    // The action minted before the crash is still the durable record and
    // remains consumable.
    client.record_registration_result(&pending_action, RegistrationOutcome::Confirmed)?;
    Ok(())
}

#[test]
fn action_token_and_digest_both_verified() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    let action_a = client.registration_action(NOW + 3_600)?;
    // Minting a second action while the first is unconsumed REPLACES the
    // durable record (crash recovery: a lost token must not brick
    // registration).
    let action_b = client.registration_action(NOW + 3_600)?;

    // Sol's scenario: presenting the superseded action A rejects, both as
    // a whole and in each cross-case.
    assert!(
        client
            .record_registration_result(&action_a, RegistrationOutcome::Confirmed)
            .is_err(),
        "superseded action accepted"
    );
    let token_a_request_b = secure_messenger_lab::DurableAction {
        token: action_a.token,
        request: action_b.request.clone(),
    };
    assert!(
        client
            .record_registration_result(&token_a_request_b, RegistrationOutcome::Confirmed)
            .is_err(),
        "token-right/request-wrong accepted"
    );
    let token_b_request_a = secure_messenger_lab::DurableAction {
        token: action_b.token,
        request: action_a.request.clone(),
    };
    assert!(
        client
            .record_registration_result(&token_b_request_a, RegistrationOutcome::Confirmed)
            .is_err(),
        "request-right/token-wrong accepted"
    );

    // The current action consumes.
    client.record_registration_result(&action_b, RegistrationOutcome::Confirmed)?;
    // And its replay rejects.
    assert!(
        client
            .record_registration_result(&action_b, RegistrationOutcome::Confirmed)
            .is_err()
    );

    // A token that matches nothing at all rejects without mutation; the
    // durable record is unaffected and a fresh action still consumes.
    let mut wrong_token = client.registration_action(NOW + 3_600)?;
    wrong_token.token = [0xAB; 16];
    assert!(
        client
            .record_registration_result(&wrong_token, RegistrationOutcome::Confirmed)
            .is_err()
    );
    let fresh = client.registration_action(NOW + 3_600)?;
    client.record_registration_result(&fresh, RegistrationOutcome::Failed)?;
    Ok(())
}

#[test]
fn verification_failures_do_not_mutate() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    let identity = client.public_identity()?;
    let peer = peer_material(NOW + 300)?;

    // Wrong pinned identity.
    let impostor = Account::new();
    assert!(
        client
            .commit_verified_contact(
                impostor.ed25519_key(),
                peer.offer,
                peer.queue_id,
                Zeroizing::new(serde_json::to_vec(&Ed25519Keypair::new())?),
                NOW,
            )
            .is_err()
    );
    // Expired offer.
    assert!(
        client
            .commit_verified_contact(
                peer.offer.signing_identity,
                peer.offer,
                peer.queue_id,
                Zeroizing::new(serde_json::to_vec(&Ed25519Keypair::new())?),
                NOW + 300,
            )
            .is_err()
    );
    // Validity window too wide.
    let wide = peer_material(NOW + 301)?;
    assert!(
        client
            .commit_verified_contact(
                wide.offer.signing_identity,
                wide.offer,
                wide.queue_id,
                Zeroizing::new(serde_json::to_vec(&wide.send_keypair)?),
                NOW,
            )
            .is_err()
    );
    // Bad signature.
    let mut broken = peer.offer;
    let mut signature_bytes = broken.signature.to_bytes();
    signature_bytes[0] ^= 0x01;
    broken.signature = Ed25519Signature::from_slice(&signature_bytes)?;
    assert!(
        client
            .commit_verified_contact(
                broken.signing_identity,
                broken,
                peer.queue_id,
                Zeroizing::new(serde_json::to_vec(&Ed25519Keypair::new())?),
                NOW,
            )
            .is_err()
    );
    // Establish without any binding.
    assert!(client.establish_outbound_session(NOW).is_err());

    // None of the failures touched the state: the genuine contact still
    // commits and establishes, against the same client.
    commit_contact_and_establish(&mut client)?;
    assert_eq!(client.public_identity()?, identity);

    // Establishing against an expired binding fails too (fresh client).
    let temp2 = TempDir::new()?;
    let mut client2 = create_client(&temp2)?;
    let expiring = peer_material(NOW + 300)?;
    client2.commit_verified_contact(
        expiring.offer.signing_identity,
        expiring.offer,
        expiring.queue_id,
        Zeroizing::new(serde_json::to_vec(&expiring.send_keypair)?),
        NOW,
    )?;
    assert!(client2.establish_outbound_session(NOW + 300).is_err());
    Ok(())
}

/// Finding 3: a committed prekey whose returned offer was lost to a crash
/// is retrievable through the recovery view, byte-identical.
#[test]
fn pending_prekey_offer_recovers_committed_offer() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    // None before any prekey exists.
    assert_eq!(client.pending_prekey_offer()?, None);

    let offer = client.prekey_action(NOW + 300)?;
    assert_eq!(client.pending_prekey_offer()?, Some(offer));

    // Crash without using the returned offer; the committed offer is
    // retrievable, identical, and re-running the action still rejects.
    drop(client);
    let mut client = open_client(&temp)?;
    assert_eq!(client.pending_prekey_offer()?, Some(offer));
    assert!(client.prekey_action(NOW + 300).is_err());
    Ok(())
}

#[test]
fn persistent_client_is_neither_sync_nor_clone() {
    // static_assertions-style negative check without a dependency: if
    // `PersistentClient` ever implements `Sync` or `Clone`, method
    // resolution below becomes ambiguous and this file stops compiling.
    trait AmbiguousIfImpl<T> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfImpl<fn()> for T {}
    impl<T: Clone> AmbiguousIfImpl<fn(fn())> for T {}
    let _ = <PersistentClient<TestProtector> as AmbiguousIfImpl<_>>::check;
}
