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

    /// Static test protector: lifecycle operations are unsupported and
    /// fail closed; the fixed binding is always present.
    fn provision_key(&self, _binding: ProfileBinding) -> secure_messenger_lab::Result<()> {
        Err(secure_messenger_lab::LabError::Storage)
    }

    fn key_status(
        &self,
        _binding: ProfileBinding,
    ) -> secure_messenger_lab::Result<secure_messenger_lab::KeyStatus> {
        Ok(secure_messenger_lab::KeyStatus::Present)
    }

    fn select_binding(&self, binding: ProfileBinding) -> secure_messenger_lab::Result<()> {
        if binding != self.binding {
            return Err(secure_messenger_lab::LabError::Storage);
        }
        Ok(())
    }

    fn delete_key(&self, _binding: ProfileBinding) -> secure_messenger_lab::Result<()> {
        Err(secure_messenger_lab::LabError::Storage)
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

/// A genuine peer contact offer plus the peer's send capability material
/// and the account behind them (kept for decrypting staged packets).
struct PeerMaterial {
    account: Account,
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
        account: peer_account,
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
/// genuine peer bundle; returns the peer material for packet inspection.
fn commit_contact_and_establish(
    client: &mut PersistentClient<TestProtector>,
) -> Result<PeerMaterial, Box<dyn Error>> {
    let peer = peer_material(NOW + 300)?;
    client.commit_verified_contact(
        peer.offer.signing_identity,
        peer.offer,
        secure_messenger_lab::ConversationId::random(),
        peer.queue_id,
        Zeroizing::new(serde_json::to_vec(&peer.send_keypair)?),
        NOW,
    )?;
    client.establish_outbound_session(NOW)?;
    Ok(peer)
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
        secure_messenger_lab::ConversationId::random(),
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
                secure_messenger_lab::ConversationId::random(),
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
                secure_messenger_lab::ConversationId::random(),
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
                secure_messenger_lab::ConversationId::random(),
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
                secure_messenger_lab::ConversationId::random(),
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
                secure_messenger_lab::ConversationId::random(),
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
                secure_messenger_lab::ConversationId::random(),
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
        secure_messenger_lab::ConversationId::random(),
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

// --- D2a: outbound send path ------------------------------------------------

use secure_messenger_lab::{DurableAction, LabError, SendOutcome};
use vodozemac::olm::{OlmMessage, SessionConfig};

fn send_signing_bytes(
    queue_id: QueueId,
    message_id: secure_messenger_lab::MessageId,
    packet_digest: &[u8; 32],
    expires_at: u64,
) -> Vec<u8> {
    canonical(
        b"send",
        &[
            queue_id.as_bytes(),
            message_id.as_bytes(),
            packet_digest,
            &expires_at.to_be_bytes(),
        ],
    )
}

/// A client with a committed contact and an established outbound session,
/// plus the peer material for packet inspection.
fn send_ready_client(
    temp: &TempDir,
) -> Result<(PersistentClient<TestProtector>, PeerMaterial), Box<dyn Error>> {
    let mut client = create_client(temp)?;
    let peer = commit_contact_and_establish(&mut client)?;
    Ok((client, peer))
}

fn assert_same_request(
    action: &DurableAction<secure_messenger_lab::capability::SendRequest>,
    request: &secure_messenger_lab::capability::SendRequest,
) {
    assert_eq!(action.request.queue_id, request.queue_id);
    assert_eq!(action.request.message_id, request.message_id);
    assert_eq!(action.request.packet.as_bytes(), request.packet.as_bytes());
    assert_eq!(action.request.expires_at, request.expires_at);
    assert_eq!(
        action.request.signature.to_bytes(),
        request.signature.to_bytes()
    );
}

#[test]
fn send_round_trip_and_crash_recovery() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (mut client, mut peer) = send_ready_client(&temp)?;
    let identity = client.public_identity()?;

    let action = client.stage_send("hello d2a", NOW, NOW + 3_600, NOW)?;
    assert_eq!(action.request.queue_id, peer.queue_id);
    // The exact request verifies against the peer's send capability.
    peer.send_keypair
        .public_key()
        .verify(
            &send_signing_bytes(
                action.request.queue_id,
                action.request.message_id,
                &action.request.packet.digest(),
                action.request.expires_at,
            ),
            &action.request.signature,
        )
        .map_err(|_| "send signature did not verify")?;
    // The peer really decrypts the first (pre-key) packet; the payload is
    // a v2 Application with the durable epoch/sequence/message ID.
    let olm_message: OlmMessage = serde_json::from_slice(action.request.packet.as_bytes())?;
    let OlmMessage::PreKey(pre_key) = olm_message else {
        return Err("first staged packet must be a pre-key message".into());
    };
    let creation = peer.account.create_inbound_session(
        SessionConfig::version_1(),
        identity.curve25519,
        &pre_key,
    )?;
    let payload: serde_json::Value = serde_json::from_slice(&creation.plaintext)?;
    assert_eq!(payload["version"], 2);
    assert_eq!(payload["kind"], 1);
    assert_eq!(payload["body"], "hello d2a");
    assert_eq!(payload["send_seq"], 1);
    assert_eq!(
        payload["message_id"],
        serde_json::to_value(action.request.message_id)?,
    );

    // Crash recovery: the identical durable request is reconstructible.
    drop(client);
    let mut client = open_client(&temp)?;
    let pending = client.pending_send_actions()?;
    assert_eq!(pending.len(), 1);
    let recovered = pending.first().ok_or("no pending action")?;
    assert_eq!(recovered.token, action.token);
    assert_same_request(recovered, &action.request);

    client.record_send_result(&action, SendOutcome::Stored)?;
    assert!(client.pending_send_actions()?.is_empty());

    drop(client);
    let client = open_client(&temp)?;
    assert!(client.pending_send_actions()?.is_empty());
    Ok(())
}

#[test]
fn send_token_discipline() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (mut client, _peer) = send_ready_client(&temp)?;
    let action_a = client.stage_send("first", NOW, NOW + 3_600, NOW)?;
    let action_b = client.stage_send("second", NOW, NOW + 3_600, NOW)?;

    // Token matches nothing.
    let wrong_token = DurableAction {
        token: [0xAB; 16],
        request: action_a.request.clone(),
    };
    assert!(
        client
            .record_send_result(&wrong_token, SendOutcome::Stored)
            .is_err()
    );
    // Token right, request wrong.
    let cross = DurableAction {
        token: action_a.token,
        request: action_b.request.clone(),
    };
    assert!(
        client
            .record_send_result(&cross, SendOutcome::Stored)
            .is_err()
    );
    // Request right, token wrong.
    let cross = DurableAction {
        token: action_b.token,
        request: action_a.request.clone(),
    };
    assert!(
        client
            .record_send_result(&cross, SendOutcome::Stored)
            .is_err()
    );
    // Both still consumable (no mutation happened).
    client.record_send_result(&action_a, SendOutcome::Stored)?;
    // Replay rejects (no longer Pending).
    assert!(
        client
            .record_send_result(&action_a, SendOutcome::Stored)
            .is_err()
    );
    // A Duplicate outcome lands in the digest arm too.
    client.record_send_result(&action_b, SendOutcome::Duplicate)?;
    Ok(())
}

#[test]
fn send_budget_and_mode_boundaries() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (mut client, _peer) = send_ready_client(&temp)?;
    // 24 application sends are allowed; the 25th hits ControlOnly and
    // application staging is blocked.
    for index in 0..24 {
        client
            .stage_send(&format!("message-{index}"), NOW, NOW + 3_600, NOW)
            .map_err(|error| format!("send {index} failed: {error}"))?;
    }
    assert!(client.stage_send("blocked", NOW, NOW + 3_600, NOW).is_err());
    // The mode persists across reopen.
    drop(client);
    let mut client = open_client(&temp)?;
    assert_eq!(client.pending_send_actions()?.len(), 24);
    assert!(client.stage_send("blocked", NOW, NOW + 3_600, NOW).is_err());
    Ok(())
}

#[test]
fn send_expiry_sweep() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (mut client, _peer) = send_ready_client(&temp)?;
    client.stage_send("short-lived", NOW, NOW + 10, NOW)?;
    // The next send-path mutator at a later clock sweeps the expired
    // record to Expired.
    let action = client.stage_send("current", NOW + 20, NOW + 3_600, NOW + 20)?;
    let pending = client.pending_send_actions()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.first().ok_or("no pending")?.token, action.token);
    // The swept record stays swept across reopen.
    drop(client);
    let client = open_client(&temp)?;
    let pending = client.pending_send_actions()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.first().ok_or("no pending")?.token, action.token);
    Ok(())
}

#[test]
fn delivery_unknown_flow() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (mut client, _peer) = send_ready_client(&temp)?;
    let action = client.stage_send("uncertain", NOW, NOW + 3_600, NOW)?;
    client.record_send_result(&action, SendOutcome::DeliveryUnknown)?;

    let unknowns = client.delivery_unknowns()?;
    assert_eq!(unknowns.len(), 1);
    let view = *unknowns.first().ok_or("no delivery unknown")?;
    assert_eq!(view.message_id, action.request.message_id);
    assert_eq!(view.packet_digest, action.request.packet.digest());
    assert_eq!(view.expires_at, action.request.expires_at);

    // Consuming a Pending-or-unknown ID rejects; the genuine one removes
    // the record and frees the slot without touching the high water.
    assert!(
        client
            .consume_delivery_unknown(secure_messenger_lab::MessageId::random(), NOW)
            .is_err()
    );
    let pending = client.stage_send("still pending", NOW, NOW + 3_600, NOW)?;
    assert!(
        client
            .consume_delivery_unknown(pending.request.message_id, NOW)
            .is_err()
    );
    client.consume_delivery_unknown(action.request.message_id, NOW)?;
    assert!(client.delivery_unknowns()?.is_empty());

    drop(client);
    let client = open_client(&temp)?;
    assert!(client.delivery_unknowns()?.is_empty());
    assert_eq!(client.pending_send_actions()?.len(), 1);
    Ok(())
}

#[test]
fn send_crash_discipline_between_every_mutator() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let client = create_client(&temp)?;
    drop(client);
    let mut client = open_client(&temp)?;
    let peer = commit_contact_and_establish(&mut client)?;
    drop(client);

    let mut client = open_client(&temp)?;
    let action = client.stage_send("durable", NOW, NOW + 3_600, NOW)?;
    drop(client);

    let mut client = open_client(&temp)?;
    assert_eq!(client.pending_send_actions()?.len(), 1);
    client.record_send_result(&action, SendOutcome::Stored)?;
    drop(client);

    let mut client = open_client(&temp)?;
    assert!(client.pending_send_actions()?.is_empty());
    let _ = peer;

    // A result for a send this profile never staged rejects after reopen
    // (foreign action from a different client).
    let temp2 = TempDir::new()?;
    let (mut foreign, _foreign_peer) = send_ready_client(&temp2)?;
    let foreign_action = foreign.stage_send("not yours", NOW, NOW + 3_600, NOW)?;
    assert!(
        client
            .record_send_result(&foreign_action, SendOutcome::Stored)
            .is_err()
    );
    Ok(())
}

#[test]
fn send_reconcile_required_on_commit_failure() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (mut client, _peer) = send_ready_client(&temp)?;
    let action = client.stage_send("committed", NOW, NOW + 3_600, NOW)?;

    let connection = Connection::open(database_path(&temp))?;
    let nonce: Vec<u8> =
        connection.query_row("SELECT nonce FROM client_state WHERE slot = 1", [], |row| {
            row.get(0)
        })?;
    let mut tampered = nonce.clone();
    *tampered.first_mut().ok_or("empty nonce")? ^= 0x01;
    connection.execute(
        "UPDATE client_state SET nonce = ?1 WHERE slot = 1",
        params![tampered],
    )?;

    assert!(client.stage_send("doomed", NOW, NOW + 3_600, NOW).is_err());
    assert!(client.pending_send_actions().is_err());
    assert!(client.public_identity().is_err());
    assert!(
        client
            .record_send_result(&action, SendOutcome::Stored)
            .is_err()
    );
    assert!(client.delivery_unknowns().is_err());

    connection.execute(
        "UPDATE client_state SET nonce = ?1 WHERE slot = 1",
        params![nonce],
    )?;
    drop(connection);
    drop(client);
    let client = open_client(&temp)?;
    let pending = client.pending_send_actions()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.first().ok_or("no pending")?.token, action.token);
    Ok(())
}

// --- D2b additions testable at the public API --------------------------------

/// A fetch request signed by the façade verifies against the real relay
/// (empty mailbox), and expiry sanity is enforced before signing.
#[test]
fn fetch_request_verifies_against_real_relay() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut relay = secure_messenger_lab::Relay::open_in_memory()?;
    let mut client = create_client(&temp)?;
    let registration = client.registration_action(NOW + 60)?;
    relay.register(&registration.request, NOW)?;
    client.record_registration_result(&registration, RegistrationOutcome::Confirmed)?;

    let action = client.fetch_request(NOW + 60, NOW)?;
    assert_eq!(action.request.nonce.as_bytes(), &action.token);
    let envelopes = relay.fetch(&action.request, NOW)?;
    assert!(envelopes.is_empty());

    // Non-future validity rejects before any signing.
    assert!(client.fetch_request(NOW, NOW).is_err());
    Ok(())
}

/// Escape-inflation carry-over: a quote-heavy body within the body bound
/// exceeds the payload bound after JSON escaping and must reject with
/// `InvalidPayload` before any sequence assignment.
#[test]
fn escape_inflated_body_rejected_as_invalid_payload() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (mut client, mut peer) = send_ready_client(&temp)?;
    let heavy = "\"".repeat(40_000);
    assert!(matches!(
        client.stage_send(&heavy, NOW, NOW + 3_600, NOW),
        Err(LabError::InvalidPayload)
    ));
    // The rejection assigned nothing: the next send still gets sequence 1.
    let action = client.stage_send("clean", NOW, NOW + 3_600, NOW)?;
    let olm_message: OlmMessage = serde_json::from_slice(action.request.packet.as_bytes())?;
    let OlmMessage::PreKey(pre_key) = olm_message else {
        return Err("first staged packet must be a pre-key message".into());
    };
    let creation = peer.account.create_inbound_session(
        SessionConfig::version_1(),
        client.public_identity()?.curve25519,
        &pre_key,
    )?;
    let payload: serde_json::Value = serde_json::from_slice(&creation.plaintext)?;
    assert_eq!(payload["send_seq"], 1);
    Ok(())
}

// --- combined review round additions -----------------------------------------

/// Finding 6: every type appearing in the façade's public signatures is
/// reachable from the crate root. Each line fails compilation if an
/// export disappears.
#[test]
fn public_signature_types_are_exported() {
    let _: Option<secure_messenger_lab::AcceptOutcome> = None;
    let _: Option<secure_messenger_lab::AckOutcomeView> = None;
    let _: Option<secure_messenger_lab::InboundView> = None;
    let _: Option<secure_messenger_lab::DeliveryUnknownView> = None;
    let _: Option<secure_messenger_lab::SendOutcome> = None;
    let _: Option<secure_messenger_lab::RegistrationOutcome> = None;
    let _: Option<secure_messenger_lab::DurableAction<secure_messenger_lab::SendRequest>> = None;
    let _: Option<secure_messenger_lab::DurableAction<secure_messenger_lab::FetchRequest>> = None;
    let _: Option<secure_messenger_lab::DurableAction<secure_messenger_lab::AckRequest>> = None;
    let _: Option<secure_messenger_lab::DurableAction<secure_messenger_lab::MailboxRegistration>> =
        None;
    let _: Option<secure_messenger_lab::PublicIdentity> = None;
    let _: Option<secure_messenger_lab::RedactedContactOffer> = None;
    let _: Option<secure_messenger_lab::PersistentClient<TestProtector>> = None;
}

/// Finding 4 (D2a): the presented request's message ID must bind to the
/// token and the durable record.
#[test]
fn send_result_requires_message_id_binding() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let (mut client, _peer) = send_ready_client(&temp)?;
    let action = client.stage_send("bound", NOW, NOW + 3_600, NOW)?;

    // Foreign message ID in the request, correct token.
    let mut foreign = action.clone();
    foreign.request.message_id = secure_messenger_lab::MessageId::random();
    assert!(
        client
            .record_send_result(&foreign, SendOutcome::Stored)
            .is_err(),
        "foreign message_id accepted"
    );

    // Untouched by the rejection: the genuine action consumes.
    client.record_send_result(&action, SendOutcome::Stored)?;
    Ok(())
}
