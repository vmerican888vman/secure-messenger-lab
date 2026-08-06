//! The Phase-2 persistence-owning façade, leg D1 (design
//! docs/phase2-design-decisions.md section 2).
//!
//! [`PersistentClient`] is the sole consumer of the `ClientStateV1` codec
//! (`crate::state`) and exclusively owns the store handle, the decoded
//! state, the `Account`, the optional `Session`, the mailbox capability
//! keypairs, the peer binding, inbound records and every outbox. No
//! reference into façade state ever escapes; callers receive only owned
//! identities, IDs, views, exact durable requests, action tokens and the
//! redacted contact offer.
//!
//! # Mutator discipline (§2 steps 1-8)
//!
//! Every mutator runs through [`PersistentClient::mutate`], in explicit
//! phases with the frozen ordering:
//!
//! 1. require `Ready`, enter `Mutating` (`FacadeState`);
//! 2. `bounds`: the operation's known-bounds checks against the CURRENT
//!    committed state, before any staging (includes the durable-action
//!    token+digest verification for result recorders);
//! 3. `stage`: clone the complete candidate logical and crypto state
//!    (state bytes via encode/decode, `Account`/`Session` via pickle
//!    round-trips — they are not `Clone`);
//! 4. `operation` mutates the candidate (ALL input validation lives here,
//!    never before the Ready gate), `sync_pickles` re-serializes the
//!    crypto state and requires crypto/logical agreement, the payload
//!    generation is pinned to `store.generation() + 1` (the generation
//!    the commit will become), and `ClientStateV1::encode` re-runs the
//!    full codec semantic validation and every aggregate bound;
//! 5. the complete snapshot commits through the store's generation-CAS,
//!    after which the store generation must equal the payload generation;
//! 6. install happens by infallible moves and the artifact is returned
//!    only after the commit succeeds;
//! 7. any pre-commit failure discards the candidate and returns to
//!    `Ready` (nothing in the installed state was touched);
//! 8. any commit/CAS/uncertain-storage failure enters
//!    `ReconcileRequired`: every operation except the non-failing
//!    `protection_level()` rejects until drop and reopen. The store
//!    poisons itself on the same failure, so its handle is unusable too.
//!
//! All operations are synchronous `&mut self`; no callbacks, transport,
//! UI, logging or await points occur while staging.
//!
//! # D1 scope boundaries and deviations (all deliberate, for review)
//!
//! - **Platform-key lifecycle out of scope.** The §4 lifecycle manager
//!   (`Provisional`/`Expected`/`Locked`/`Deleting`, registry, CAS) is not
//!   implemented in D1. The existing [`StateKeyProtector`] contract is
//!   assumed: an independently stored expected binding, wrap/unwrap, and
//!   honest `protection_level()` evidence. This is the documented gap for
//!   the review brief.
//! - **Action token + request digest (review finding 1).** The frozen
//!   `ClientStateV1` grammar has no action-token or digest field. The
//!   durable action record is realized through the registration record
//!   itself: the action token IS the freshly minted random 16-byte
//!   registration nonce, and the stored request digest IS the record —
//!   SHA-256 is recomputed over the canonical bytes of both the durable
//!   record and the presented request, and byte equality of the records
//!   is exactly digest equality. `record_registration_result` takes the
//!   full `DurableAction` back and requires BOTH token equality and
//!   digest equality; any mismatch rejects without mutation, before
//!   staging (step 2). Minting a new registration action while one is
//!   unconsumed REPLACES the durable record (new nonce/token): required
//!   for crash recovery, since a token lost to a crash must not brick
//!   registration. An authentic rollback restores the OLD record, so a
//!   newer action is rejected even when the generation repeats (the §2
//!   property). Recording a result consumes the action by re-minting the
//!   nonce, which makes replays and cross-action tokens fail.
//! - **Registration terminal marker.** The record has no terminal-state
//!   field either. D1 convention: `Confirmed` keeps the exact request's
//!   `valid_until` (the confirmed request remains the durable one) with a
//!   fresh nonce; `Failed` re-signs the intent with `valid_until = 0` and
//!   a fresh nonce. Both consume the presented action.
//! - **Payload generation tracks the store generation (review finding
//!   2).** Every commit writes `payload.generation == store generation +
//!   1`; reconstruction (`from_store`) requires the payload generation,
//!   `profile_id` and `key_ref` to equal the authenticated store
//!   generation and independently held binding exactly.
//! - **Crash-orphaned committed prekey (review finding 3).**
//!   `prekey_action` returns the offer only after commit; a death between
//!   COMMIT and return leaves the pending prekey committed with the offer
//!   unretrieved. `pending_prekey_offer` is the recovery view: it returns
//!   the committed redacted offer so the caller resumes with it instead
//!   of re-running `prekey_action` (which rejects while one is pending).
//! - **Send-capability exclusivity (review finding 4).**
//!   `commit_verified_contact` takes the serialized canonical keypair
//!   bytes, not a typed `Ed25519Keypair` (which is `Clone` + `Serialize`
//!   in the vendored crate), so the natural transfer handle is consumable
//!   bytes and the typed keypair exists only inside the façade. The
//!   caller received the capability out of band; erasing its own copy is
//!   the caller's duty. The façade never exports a typed capability
//!   owner.
//! - **`MailboxOwner` is not reused.** Its keypairs are not extractable
//!   outside `cfg(test)` (only `serialized_private_material` exists, test
//!   gated), and this leg may not modify `capability.rs`. The façade
//!   builds the mailbox triple from `Ed25519Keypair` directly and signs
//!   with the `pub(crate)` `MailboxRegistration::signing_bytes`, the same
//!   canonical construction `MailboxOwner::registration` uses.
//! - **`create` re-validation without a physical reopen.** §1 asks for a
//!   reopen-and-revalidate after writing generation 1. `P` is not
//!   `Clone`, the store consumes the protector, and the store holds the
//!   `PrivateStoreDir` lock, so a physical close/reopen is impossible
//!   within this signature. D1 instead re-validates fully — a fresh
//!   `ClientStateV1::decode` (parse + complete semantic validation) of the
//!   authenticated committed snapshot read back through the same handle.
//! - **`PendingPreKey.created_at` is 0.** `prekey_action` receives no
//!   clock; the codec only requires `created_at < valid_until`.

use std::marker::PhantomData;

#[cfg(test)]
mod tests;

use serde::Deserialize;
use vodozemac::olm::{Account, Session, SessionConfig};
use vodozemac::{Curve25519PublicKey, Ed25519Keypair, Ed25519PublicKey, Ed25519Signature};
use zeroize::Zeroizing;

use crate::capability::{canonical, digest};
use crate::ids::{ConversationId, Nonce, QueueId};
use crate::persistence::{ClientStateStore, ProtectionLevel, StateKeyProtector};
use crate::private_store_dir::PrivateStoreDir;
use crate::state::{
    ActiveSession, ClientStateV1, MAX_KEYPAIR_JSON, PeerBinding, PeerBundle, PendingPreKey,
    RegistrationRecord, Role, SessionMode,
};
use crate::{LabError, MailboxRegistration, Result};

/// Validity window for a contact offer, mirroring
/// `CONTACT_BUNDLE_MAX_VALIDITY_SECONDS` in `src/client.rs` (private
/// there; replicated, not edited).
const CONTACT_OFFER_MAX_VALIDITY_SECONDS: u64 = 5 * 60;

const PREKEY_ACTION: &[u8] = b"peer-prekey";

/// Canonical length-prefixed signing bytes for a peer bundle; identical
/// construction to `peer_prekey_signing_bytes` in `src/client.rs`.
fn prekey_signing_bytes(bundle: &PeerBundle) -> Vec<u8> {
    canonical(
        PREKEY_ACTION,
        &[
            bundle.signing_identity.as_bytes(),
            bundle.curve_identity.as_bytes(),
            bundle.one_time_key.as_bytes(),
            &bundle.valid_until.to_be_bytes(),
        ],
    )
}

/// An externally transmitted request paired with its opaque action token.
/// The request is returned only after the exact request and the candidate
/// state have committed; presenting a result requires both the token and
/// the durable request binding to match (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableAction<T> {
    pub token: [u8; 16],
    pub request: T,
}

/// Owned view of the client's own public identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicIdentity {
    pub ed25519: Ed25519PublicKey,
    pub curve25519: Curve25519PublicKey,
}

/// The transferable, redacted contact offer: everything a peer needs to
/// pin and verify this client out of band, and nothing else. It never
/// contains the `Account`, a pickle, or any private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactedContactOffer {
    pub signing_identity: Ed25519PublicKey,
    pub curve_identity: Curve25519PublicKey,
    pub one_time_key: Curve25519PublicKey,
    pub valid_until: u64,
    pub signature: Ed25519Signature,
}

/// Outcome of a durable registration action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationOutcome {
    Confirmed,
    Failed,
}

/// Bookkeeping for the §2 mutator discipline. `Mutating` is never
/// observable across operations because everything is synchronous
/// `&mut self`; it exists to make the discipline explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FacadeState {
    Ready,
    Mutating,
    ReconcileRequired,
}

/// The three mailbox capability keypairs. Immutable after `create`.
struct MailboxKeypairs {
    send: Ed25519Keypair,
    receive: Ed25519Keypair,
    manage: Ed25519Keypair,
}

/// A complete cloned candidate: logical state plus crypto state. Mutated,
/// cross-validated, serialized and committed as one snapshot; installed by
/// infallible moves only after the commit succeeds.
struct Candidate {
    state: ClientStateV1,
    account: Account,
    session: Option<Session>,
}

/// Mint a manage-signed registration record (the exact current request).
/// The nonce is the durable random action ID for the action that issued
/// this request (see module docs).
fn mint_registration(
    keypairs: &MailboxKeypairs,
    queue_id: QueueId,
    nonce: Nonce,
    valid_until: u64,
) -> (RegistrationRecord, MailboxRegistration) {
    let mut request = MailboxRegistration {
        queue_id,
        send_key: keypairs.send.public_key(),
        receive_key: keypairs.receive.public_key(),
        manage_key: keypairs.manage.public_key(),
        nonce,
        valid_until,
        signature: keypairs.manage.sign(b""),
    };
    request.signature = keypairs.manage.sign(&request.signing_bytes());
    let record = RegistrationRecord {
        queue_id: request.queue_id,
        send_key: request.send_key,
        receive_key: request.receive_key,
        manage_key: request.manage_key,
        nonce: request.nonce,
        valid_until: request.valid_until,
        signature: request.signature,
    };
    (record, request)
}

/// `epoch_id = SHA-256(identity_key || base_key || one_time_key)`.
fn epoch_of(keys: vodozemac::olm::SessionKeys) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(96);
    preimage.extend_from_slice(keys.identity_key.as_bytes());
    preimage.extend_from_slice(keys.base_key.as_bytes());
    preimage.extend_from_slice(keys.one_time_key.as_bytes());
    digest(&preimage)
}

/// The single-actor, persistence-owning client. Not `Clone` (no
/// implementation is provided and the store connection is not `Clone`)
/// and not `Sync`/`Send` (the marker field plus the naturally `!Sync`
/// store connection).
pub struct PersistentClient<P: StateKeyProtector> {
    store: ClientStateStore<P>,
    state: ClientStateV1,
    account: Account,
    session: Option<Session>,
    keypairs: MailboxKeypairs,
    facade_state: FacadeState,
    _not_sync: PhantomData<*mut ()>,
}

impl<P: StateKeyProtector> PersistentClient<P> {
    /// Create a fresh profile: new `Account` and mailbox, generation 1,
    /// committed atomically through the store's create path (which
    /// requires [`crate::MainDatabase::Absent`]), then fully re-validated
    /// (decode + complete semantic validation) before anything is
    /// exposed. See the module docs for the reopen deviation.
    ///
    /// `now` seeds the initial registration intent's expiry; no
    /// registration request has been issued yet at creation.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when the directory is not absent of
    /// a database, the platform binding is unavailable, the initial commit
    /// fails, or the committed state fails re-validation.
    pub fn create(dir: PrivateStoreDir, protector: P, now: u64) -> Result<Self> {
        let binding = protector.expected_binding()?;
        let account = Account::new();
        let keypairs = MailboxKeypairs {
            send: Ed25519Keypair::new(),
            receive: Ed25519Keypair::new(),
            manage: Ed25519Keypair::new(),
        };
        let queue_id = QueueId::random();
        let (registration, _request) = mint_registration(&keypairs, queue_id, Nonce::random(), now);
        let state = ClientStateV1 {
            profile_id: *binding.profile_id(),
            key_ref: *binding.key_ref(),
            generation: 1,
            conversation_id: ConversationId::random(),
            account_pickle: Zeroizing::new(
                serde_json::to_vec(&account.pickle()).map_err(|_| LabError::Storage)?,
            ),
            own_ed25519_identity: account.ed25519_key(),
            own_curve_identity: account.curve25519_key(),
            mailbox_queue_id: queue_id,
            send_keypair_json: Zeroizing::new(
                serde_json::to_vec(&keypairs.send).map_err(|_| LabError::Storage)?,
            ),
            receive_keypair_json: Zeroizing::new(
                serde_json::to_vec(&keypairs.receive).map_err(|_| LabError::Storage)?,
            ),
            manage_keypair_json: Zeroizing::new(
                serde_json::to_vec(&keypairs.manage).map_err(|_| LabError::Storage)?,
            ),
            registration,
            pending_prekey: None,
            peer_binding: None,
            active_session: None,
            inbound: Vec::new(),
            sends: Vec::new(),
            acks: Vec::new(),
            dedup: Vec::new(),
        };
        let snapshot = state.encode()?;
        let store = ClientStateStore::create(dir, protector, &snapshot)?;
        // Full re-validation of the committed snapshot before exposure
        // (see the module docs for why this is not a physical reopen):
        // `from_store` decodes and validates the authenticated committed
        // bytes and reconstructs the crypto state from the pickles.
        Self::from_store(store)
    }

    /// Open an existing profile: the store authenticates and decrypts the
    /// snapshot, `ClientStateV1::decode` re-runs the complete §3
    /// validation, and the `Account`/`Session` are reconstructed from
    /// their canonical pickles.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when no authentic validated database
    /// exists or the decoded state fails validation.
    pub fn open(dir: PrivateStoreDir, protector: P) -> Result<Self> {
        let store = ClientStateStore::open(dir, protector)?;
        Self::from_store(store)
    }

    /// Build the façade from an authenticated store: decode and validate,
    /// require the payload generation and profile metadata to equal the
    /// authenticated store generation and the independently held binding
    /// (review finding 2), then reconstruct the crypto state from the
    /// canonical pickles.
    fn from_store(store: ClientStateStore<P>) -> Result<Self> {
        let state = ClientStateV1::decode(store.state()?)?;
        if state.generation != store.generation()?
            || state.profile_id != *store.binding()?.profile_id()
            || state.key_ref != *store.binding()?.key_ref()
        {
            return Err(LabError::Storage);
        }
        let account = Account::from_pickle(
            serde_json::from_slice(&state.account_pickle).map_err(|_| LabError::Storage)?,
        );
        let session = match &state.active_session {
            Some(active) => Some(Session::from_pickle(
                serde_json::from_slice(&active.session_pickle).map_err(|_| LabError::Storage)?,
            )),
            None => None,
        };
        let keypairs = MailboxKeypairs {
            send: serde_json::from_slice(&state.send_keypair_json)
                .map_err(|_| LabError::Storage)?,
            receive: serde_json::from_slice(&state.receive_keypair_json)
                .map_err(|_| LabError::Storage)?,
            manage: serde_json::from_slice(&state.manage_keypair_json)
                .map_err(|_| LabError::Storage)?,
        };
        Ok(Self {
            store,
            state,
            account,
            session,
            keypairs,
            facade_state: FacadeState::Ready,
            _not_sync: PhantomData,
        })
    }

    /// Owned view of the client's own public identities.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error while the façade is not `Ready`
    /// (after a failed commit, until drop and reopen).
    pub fn public_identity(&self) -> Result<PublicIdentity> {
        self.ensure_ready()?;
        Ok(PublicIdentity {
            ed25519: self.account.ed25519_key(),
            curve25519: self.account.curve25519_key(),
        })
    }

    /// Protection evidence reported by the platform adapter. Non-failing
    /// passthrough; it stays available even in `ReconcileRequired` so the
    /// actor can report why recovery is needed.
    #[must_use]
    pub fn protection_level(&self) -> ProtectionLevel {
        self.store.protection_level()
    }

    /// Generate one one-time key, sign the contact bundle, record the
    /// pending prekey, mark the key published, commit, and only then
    /// return the transferable redacted offer.
    ///
    /// Recovery: if the process dies between the commit and the return,
    /// the committed offer is retrievable through
    /// [`Self::pending_prekey_offer`] — do not re-run this action.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when a pending prekey already exists, key
    /// generation or signing fails, or the commit fails.
    pub fn prekey_action(&mut self, valid_until: u64) -> Result<RedactedContactOffer> {
        self.mutate(
            |current| {
                // Known bound: at most one pending prekey.
                if current.state.pending_prekey.is_some() {
                    return Err(LabError::Crypto);
                }
                Ok(())
            },
            |candidate, _keypairs| {
                let one_time_key = *candidate
                    .account
                    .generate_one_time_keys(1)
                    .created
                    .first()
                    .ok_or(LabError::Crypto)?;
                let mut bundle = PeerBundle {
                    signing_identity: candidate.account.ed25519_key(),
                    curve_identity: candidate.account.curve25519_key(),
                    one_time_key,
                    valid_until,
                    signature: candidate.account.sign(b""),
                };
                bundle.signature = candidate.account.sign(prekey_signing_bytes(&bundle));
                candidate.account.mark_keys_as_published();
                candidate.state.pending_prekey = Some(PendingPreKey {
                    signing_identity: bundle.signing_identity,
                    curve_identity: bundle.curve_identity,
                    one_time_key,
                    created_at: 0,
                    valid_until,
                    signature: bundle.signature,
                });
                Ok(RedactedContactOffer {
                    signing_identity: bundle.signing_identity,
                    curve_identity: bundle.curve_identity,
                    one_time_key,
                    valid_until,
                    signature: bundle.signature,
                })
            },
        )
    }

    /// The committed pending-prekey offer, if one exists — the recovery
    /// view for a crash between a prekey commit and the caller receiving
    /// the returned offer. Owned and redacted; never the account.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error while the façade is not `Ready`.
    pub fn pending_prekey_offer(&self) -> Result<Option<RedactedContactOffer>> {
        self.ensure_ready()?;
        Ok(self
            .state
            .pending_prekey
            .as_ref()
            .map(|prekey| RedactedContactOffer {
                signing_identity: prekey.signing_identity,
                curve_identity: prekey.curve_identity,
                one_time_key: prekey.one_time_key,
                valid_until: prekey.valid_until,
                signature: prekey.signature,
            }))
    }

    /// Verify a peer's contact offer against the separately pinned peer
    /// signing identity (identity match, short validity window, signature
    /// — the same rules as `PeerPreKey::verify` in `src/client.rs`,
    /// replicated) and commit the peer binding: the verified bundle plus
    /// the send capability for the peer's mailbox. The capability arrives
    /// as serialized canonical keypair bytes (bounded at 512 bytes); the
    /// typed keypair is constructed only inside the façade and never
    /// exported (see the module docs).
    ///
    /// All validation runs inside the mutator, after the Ready gate.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::PeerVerificationFailed`] for an identity,
    /// window or signature mismatch, [`LabError::Unauthorized`] when a
    /// peer binding already exists, or a coarse storage error.
    pub fn commit_verified_contact(
        &mut self,
        pinned_signing_identity: Ed25519PublicKey,
        offer: RedactedContactOffer,
        peer_queue_id: QueueId,
        peer_send_keypair: Zeroizing<Vec<u8>>,
        now: u64,
    ) -> Result<()> {
        self.mutate(
            |current| {
                // Known bound: at most one peer binding.
                if current.state.peer_binding.is_some() {
                    return Err(LabError::Unauthorized);
                }
                Ok(())
            },
            |candidate, _keypairs| {
                if offer.signing_identity != pinned_signing_identity
                    || offer.valid_until <= now
                    || offer.valid_until > now.saturating_add(CONTACT_OFFER_MAX_VALIDITY_SECONDS)
                {
                    return Err(LabError::PeerVerificationFailed);
                }
                let bundle = PeerBundle {
                    signing_identity: offer.signing_identity,
                    curve_identity: offer.curve_identity,
                    one_time_key: offer.one_time_key,
                    valid_until: offer.valid_until,
                    signature: offer.signature,
                };
                pinned_signing_identity
                    .verify(&prekey_signing_bytes(&bundle), &offer.signature)
                    .map_err(|_| LabError::PeerVerificationFailed)?;
                let send_public_key = parse_capability_keypair(&peer_send_keypair)?.public_key();
                candidate.state.peer_binding = Some(PeerBinding {
                    bundle,
                    queue_id: peer_queue_id,
                    send_keypair_json: peer_send_keypair,
                    send_public_key,
                });
                Ok(())
            },
        )
    }

    /// Establish the outbound session from the committed peer binding and
    /// commit the `ActiveSession` record (role outbound, transcript = the
    /// peer bundle, fresh epoch, zero sequence and high-water state, mode
    /// `Ready`, no receipt, empty received set, conversation from state).
    ///
    /// # Errors
    ///
    /// Returns [`LabError::SessionAlreadyExists`] when a session exists,
    /// [`LabError::MissingSession`] when no peer binding is committed,
    /// [`LabError::PeerVerificationFailed`] when the bundle expired, or a
    /// coarse error when Olm rejects the bundle or the commit fails.
    pub fn establish_outbound_session(&mut self, now: u64) -> Result<()> {
        self.mutate(
            |current| {
                // Known bound: at most one active session.
                if current.session.is_some() || current.state.active_session.is_some() {
                    return Err(LabError::SessionAlreadyExists);
                }
                if current.state.peer_binding.is_none() {
                    return Err(LabError::MissingSession);
                }
                Ok(())
            },
            |candidate, _keypairs| {
                let binding = candidate
                    .state
                    .peer_binding
                    .as_ref()
                    .ok_or(LabError::MissingSession)?;
                if binding.bundle.valid_until <= now {
                    return Err(LabError::PeerVerificationFailed);
                }
                let session = candidate
                    .account
                    .create_outbound_session(
                        SessionConfig::version_1(),
                        binding.bundle.curve_identity,
                        binding.bundle.one_time_key,
                    )
                    .map_err(|_| LabError::Crypto)?;
                let keys = session.session_keys();
                candidate.state.active_session = Some(ActiveSession {
                    role: Role::Outbound,
                    session_pickle: Zeroizing::new(
                        serde_json::to_vec(&session.pickle()).map_err(|_| LabError::Storage)?,
                    ),
                    identity_key: keys.identity_key,
                    base_key: keys.base_key,
                    one_time_key: keys.one_time_key,
                    transcript: binding.bundle,
                    epoch_id: epoch_of(keys),
                    last_assigned_send_seq: 0,
                    peer_contiguous_high_water: 0,
                    highest_contiguous_received_seq: 0,
                    mode: SessionMode::Ready,
                    receipt: None,
                    received_above_high_water: Vec::new(),
                    conversation_id: candidate.state.conversation_id,
                });
                candidate.session = Some(session);
                Ok(())
            },
        )
    }

    /// Mint the exact current registration request (fresh nonce = the
    /// action token), record it durably, commit, and only then return the
    /// action. Minting while an action is unconsumed REPLACES the durable
    /// record (new nonce/token); a token lost to a crash must not brick
    /// registration.
    ///
    /// # Errors
    ///
    /// Returns a coarse error when signing or the commit fails.
    pub fn registration_action(
        &mut self,
        valid_until: u64,
    ) -> Result<DurableAction<MailboxRegistration>> {
        self.mutate(
            |_current| Ok(()),
            |candidate, keypairs| {
                let nonce = Nonce::random();
                let (record, request) = mint_registration(
                    keypairs,
                    candidate.state.mailbox_queue_id,
                    nonce,
                    valid_until,
                );
                candidate.state.registration = record;
                Ok(DurableAction {
                    token: *nonce.as_bytes(),
                    request,
                })
            },
        )
    }

    /// Record the relay's answer to a durable registration action. The
    /// presented token must equal the durable record's nonce (the random
    /// action ID), and the durable request binding — the manage signature
    /// over the exact request plus the canonical-bytes digest — is
    /// re-verified. On a match the action is consumed (the nonce is
    /// re-minted) and the record marked terminal: `Confirmed` keeps the
    /// exact request's expiry, `Failed` re-signs with `valid_until = 0`.
    /// Any mismatch rejects without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Unauthorized`] for a wrong, replayed or
    /// cross-action token, or a coarse storage error when the commit
    /// fails.
    /// Record the relay's answer to a durable registration action. The
    /// full action is presented back: BOTH the token must equal the
    /// durable record's nonce (the random action ID) AND SHA-256 over the
    /// canonical bytes of the presented request must equal the digest of
    /// the durable record's canonical bytes (review finding 1 — the
    /// digest is stored durably AS the record itself; see the module
    /// docs). Verification runs before any staging. On a match the action
    /// is consumed (the nonce is re-minted) and the record marked
    /// terminal: `Confirmed` keeps the exact request's expiry, `Failed`
    /// re-signs with `valid_until = 0`. Any mismatch rejects without
    /// mutation.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Unauthorized`] for a wrong, replayed or
    /// cross-action token or a mismatched request, or a coarse storage
    /// error when the commit fails.
    pub fn record_registration_result(
        &mut self,
        action: &DurableAction<MailboxRegistration>,
        outcome: RegistrationOutcome,
    ) -> Result<()> {
        self.mutate(
            |current| {
                let record = &current.state.registration;
                if record.nonce.as_bytes() != &action.token {
                    return Err(LabError::Unauthorized);
                }
                let presented = RegistrationRecord {
                    queue_id: action.request.queue_id,
                    send_key: action.request.send_key,
                    receive_key: action.request.receive_key,
                    manage_key: action.request.manage_key,
                    nonce: action.request.nonce,
                    valid_until: action.request.valid_until,
                    signature: action.request.signature,
                };
                if digest(&presented.encode()?) != digest(&record.encode()?) {
                    return Err(LabError::Unauthorized);
                }
                Ok(())
            },
            |candidate, keypairs| {
                let valid_until = match outcome {
                    RegistrationOutcome::Confirmed => candidate.state.registration.valid_until,
                    RegistrationOutcome::Failed => 0,
                };
                let (successor, _request) = mint_registration(
                    keypairs,
                    candidate.state.mailbox_queue_id,
                    Nonce::random(),
                    valid_until,
                );
                candidate.state.registration = successor;
                Ok(())
            },
        )
    }

    fn ensure_ready(&self) -> Result<()> {
        if self.facade_state != FacadeState::Ready {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    /// Clone the complete candidate logical and crypto state (step 3).
    fn stage(&self) -> Result<Candidate> {
        let state = ClientStateV1::decode(&self.state.encode()?)?;
        let account = Account::from_pickle(self.account.pickle());
        let session = self
            .session
            .as_ref()
            .map(|session| Session::from_pickle(session.pickle()));
        Ok(Candidate {
            state,
            account,
            session,
        })
    }

    /// Install the candidate by infallible moves (step 6).
    fn install(&mut self, candidate: Candidate) {
        self.state = candidate.state;
        self.account = candidate.account;
        self.session = candidate.session;
    }

    /// The §2 mutator sequence in explicit phases; see the module docs for
    /// the step mapping. `bounds` runs the operation's known-bounds checks
    /// against the CURRENT committed state (step 2) before any staging;
    /// `operation` runs all input validation and the mutation itself
    /// against the cloned candidate (step 4).
    fn mutate<T>(
        &mut self,
        bounds: impl FnOnce(&Self) -> Result<()>,
        operation: impl FnOnce(&mut Candidate, &MailboxKeypairs) -> Result<T>,
    ) -> Result<T> {
        // Step 1: require Ready, enter Mutating.
        self.ensure_ready()?;
        self.facade_state = FacadeState::Mutating;
        match self.pre_commit(bounds, operation) {
            Err(error) => {
                // Step 7: pre-commit failure discards the candidate.
                self.facade_state = FacadeState::Ready;
                Err(error)
            }
            Ok((artifact, candidate, snapshot)) => {
                // Step 5: commit the complete snapshot through the
                // generation-CAS.
                match self.store.commit(&snapshot) {
                    Ok(()) => {
                        // The payload generation must have landed exactly
                        // one ahead of the pre-commit store generation.
                        let committed = self.store.generation().map_err(|_| LabError::Storage)?;
                        if committed != candidate.state.generation {
                            self.facade_state = FacadeState::ReconcileRequired;
                            return Err(LabError::Storage);
                        }
                        // Step 6: install by infallible moves, then return.
                        self.install(candidate);
                        self.facade_state = FacadeState::Ready;
                        Ok(artifact)
                    }
                    Err(error) => {
                        // Step 8: commit/CAS/uncertain-storage failure.
                        self.facade_state = FacadeState::ReconcileRequired;
                        Err(error)
                    }
                }
            }
        }
    }

    /// Steps 2-4: bounds against the current state, candidate staging,
    /// mutation, crypto/logical agreement, payload-generation pinning,
    /// full codec validation and serialization.
    fn pre_commit<T>(
        &mut self,
        bounds: impl FnOnce(&Self) -> Result<()>,
        operation: impl FnOnce(&mut Candidate, &MailboxKeypairs) -> Result<T>,
    ) -> Result<(T, Candidate, Zeroizing<Vec<u8>>)> {
        // Step 2: known bounds checks against the current state.
        bounds(self)?;
        // Step 3: clone the complete candidate state.
        let mut candidate = self.stage()?;
        // Step 4: mutate (all input validation lives in the operation),
        // agree crypto/logical state, pin the payload generation to the
        // generation the commit will become, then cross-validate and
        // serialize with aggregate bounds.
        let artifact = operation(&mut candidate, &self.keypairs)?;
        sync_pickles(&mut candidate)?;
        candidate.state.generation = self
            .store
            .generation()?
            .checked_add(1)
            .ok_or(LabError::Storage)?;
        let snapshot = candidate.state.encode()?;
        Ok((artifact, candidate, snapshot))
    }
}

/// Re-serialize the candidate's crypto state into the candidate's logical
/// state and require the two to agree (part of step 4).
fn sync_pickles(candidate: &mut Candidate) -> Result<()> {
    candidate.state.account_pickle = Zeroizing::new(
        serde_json::to_vec(&candidate.account.pickle()).map_err(|_| LabError::Storage)?,
    );
    match (&candidate.session, candidate.state.active_session.as_mut()) {
        (Some(session), Some(active)) => {
            active.session_pickle = Zeroizing::new(
                serde_json::to_vec(&session.pickle()).map_err(|_| LabError::Storage)?,
            );
        }
        (None, None) => {}
        _ => return Err(LabError::Storage),
    }
    Ok(())
}

/// Parse a serialized capability keypair exactly as the codec's canonical
/// JSON rule requires (review finding 4): bound first, deserialize, reject
/// trailing data, reserialize, require byte equality. The typed keypair
/// exists only inside the façade.
fn parse_capability_keypair(bytes: &Zeroizing<Vec<u8>>) -> Result<Ed25519Keypair> {
    if bytes.len() > MAX_KEYPAIR_JSON {
        return Err(LabError::Storage);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let keypair = Ed25519Keypair::deserialize(&mut deserializer).map_err(|_| LabError::Storage)?;
    deserializer.end().map_err(|_| LabError::Storage)?;
    let reserialized = Zeroizing::new(serde_json::to_vec(&keypair).map_err(|_| LabError::Storage)?);
    if reserialized[..] != bytes[..] {
        return Err(LabError::Storage);
    }
    Ok(keypair)
}
