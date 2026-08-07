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
//!
//! # D2b decisions (inbound path, receipts, ACKs)
//!
//! - **Fetch and ACK minting keep no durable record.** §2 defines result
//!   recorders only for registration, send and ACK intents; a fetch
//!   mutates no crypto state and `ack_actions` re-signs the durable
//!   intent's exact request. Both are read-only operations that require
//!   `Ready` and never commit. Their tokens (the fetch nonce / the
//!   message ID) are purely correlational.
//! - **Receipt staging follows the durable owed rule (review D2b v5
//!   debt model).** Receipt debt is the highest CONSUMED application
//!   sequence (`receipt_debt_up_to`, codec field 20), set only by
//!   `consume_inbound` — receipts and other control payloads never
//!   create it, so receipt-only exchanges never stage (quiescence by
//!   construction; no marker bookkeeping in the accept tail). A receipt
//!   reporting the contiguous received high water is owed ⇔ the debt
//!   AND that water both exceed `last_delivered_receipt_high_water`
//!   (codec field 19) AND no `Pending` receipt-kind send for the current
//!   water is in flight: a delivered receipt reports the water, covering
//!   exactly the debt at or below it, so both comparisons are required.
//!   The marker advances only in `record_send_result` when a
//!   receipt-kind record reaches `Stored`/`Duplicate` — never at
//!   staging, never on `DeliveryUnknown`/expiry — so a lost receipt
//!   re-owes automatically and the next eligible mutator re-stages it
//!   with a fresh envelope and a fresh 7-day expiry (the same TTL rule
//!   as `stage_send`, not the 300 s request window). Staging runs in
//!   every clock-taking mutator (accept, consume, `stage_send`,
//!   `consume_delivery_unknown`), at most one receipt per pass, only in
//!   `Ready`/`ControlOnly`, with the budget mode recomputed from the
//!   fresh high water BEFORE staging in the accept path (`RekeyRequired`
//!   dominance preserved). In `stage_send` an owed receipt takes
//!   priority over the new application body: when it leaves no slot or
//!   crosses a budget threshold, the receipt COMMITS and the result is
//!   `ReceiptFlushedRetry` (v5 P1-3) — an honest retry signal, never a
//!   discarded candidate. A receipt payload whose high water regresses
//!   or repeats is a content no-op (`ReceiptIdempotent`): the §4
//!   rejection applies to the high-water UPDATE, not the authenticated
//!   packet, so reordered legitimate receipts commit their
//!   sequence/dedup progress (v5 P1-1); only future values
//!   (`hw > last_assigned_send_seq`) still hard-error.
//! - **Threshold-armed control debt (review D2b v6-v9, codec field 21 —
//!   a high water since v9).**
//!   Receipts consume the shared send counter but (per the v5 debt
//!   model) never create application debt, so sustained one-directional
//!   traffic stranded the receiver: its own receipt sends raised its
//!   outstanding with no drain, ending in a permanently unrecoverable
//!   `ReceiptLocked`. The flag arms at the end of any successful
//!   `accept_envelope` on EITHER congestion source:
//!
//!   - **Local sample (v6):** the acceptor's own outstanding at or above
//!     the `ControlOnly` threshold (24), sampled at accept ENTRY (before
//!     the ratchet step) as well as at the end — a receipt that drains
//!     its own sender's budget in that very pass still arms the
//!     acceptor. This source must stay: it is the backstop for the
//!     both-stuck corner (the peer locked with all its receipts expired
//!     undelivered, so no signal is on the wire — the other side
//!     eventually congests locally and arms at its next accept).
//!   - **Peer signal (v7/v8):** the just-accepted payload's
//!     `issuer_outstanding` at or above the threshold. Payloads carry
//!     the issuer's POST-advance outstanding on BOTH arms (this leg's
//!     format; the frozen `HighWaterReceipt` is untouched): the send's
//!     own sequence counts, so the 24th send reports 24 and actually
//!     signals (v8 P1-3). The value is PEER-REPORTED and informational:
//!     no validation. A stale out-of-order payload can over-arm; that is
//!     bounded, and under-arming — the dangerous direction — cannot
//!     come from a truthful signal.
//!
//!   The accept tail arms FIRST, then attempts owed staging — a debt
//!   armed by the accept itself flushes in the SAME pass (v8 P1-3b),
//!   including when the accept crossed the threshold. Water lifecycle
//!   (v9, dissolving findings 2 and 4): arming RAISES
//!   `control_debt_up_to` to the current HCR via `max`; NOTHING on the
//!   wire ever clears or lowers it — no signal-based clearing exists
//!   (the v9 finding-2 bug), and none is needed: because resolution is
//!   a water-versus-water comparison (`control_debt_up_to` vs the
//!   delivered marker) rather than a recency contest, a reordered
//!   truthful low signal is simply inert — it raises nothing and erases
//!   nothing, which is exactly why no signal-freshness versioning is
//!   required. Resolution happens only through confirmed delivery:
//!   debt stands while the water exceeds the delivered marker, so a
//!   delayed `Stored` on an OLDER receipt (`hw < control_debt_up_to`)
//!   leaves newer debt standing (v9 finding 4), and a delivery at or
//!   above the water resolves it. Guards (v8 P1-4): the
//!   application-debt arm keeps the per-current-water in-flight rule
//!   (honest path), while the peer-signaled/control arm stages only
//!   when NO receipt-kind send is `Pending` AT ALL — a malicious peer
//!   streaming authenticated `hw=0` receipts that each occupy a sender
//!   sequence (each arming anew) gets ≈ one victim receipt per
//!   delivery-or-expiry cycle regardless of attack rate. The freshness
//!   gate (`HCR > marker`) applies to both arms: if we already reported
//!   everything, the peer's congestion is not ours to fix with empty
//!   receipts. Below the threshold on both sources nothing changes: v6
//!   quiescence holds exactly.
//!
//!   Why this cannot ping-pong (protocol decision for the security
//!   authority), and how it closes the lockstep: application debt still
//!   comes only from consumed bodies. In one-directional lockstep the
//!   receiver's receipts start carrying `issuer_outstanding >= 24` the
//!   moment its receipt sends congest; the sender arms on the SIGNAL
//!   regardless of its own (drained) budget and counter-receipts,
//!   reporting its high water over the receiver's sends — which include
//!   those receipts — so the receiver drains below the threshold, its
//!   next receipts carry low outstanding, and the sender stops arming.
//!   The counter-receipt itself carries the sender's LOW outstanding,
//!   so the receiver never counter-counter-receipts: convergence in one
//!   round trip, no storm. Every staged receipt (a) reports the FRESHEST
//!   contiguous water — staging requires `HCR > marker`, so a receipt
//!   carrying no new information cannot exist — and (b) costs its
//!   sender exactly one counter advance. When both sides sit at or
//!   above the threshold, one exchange round drains both below it
//!   (coalescing: each receipt typically covers many sequences), after
//!   which arming stops. `ReceiptLocked`/`RekeyRequired` still gate
//!   staging, so the §4 recovery path (a valid receipt lowers
//!   outstanding, the mode recomputes, the armed debt stages once
//!   control is allowed) is what actually un-wedges the corner.
//! - **Gap failure commits; `RekeyRequired` closes inbound.** A
//!   previously unseen, peer-authenticated
//!   packet on the current session whose decrypt fails with
//!   `TooBigMessageGap`/`MissingMessageKey` commits `RekeyRequired` and
//!   only then reports `LabError::Crypto` — the mode change IS the
//!   durable outcome (§4). "Current-epoch" is structural: the façade
//!   keeps exactly one session, so every accepted candidate packet is
//!   current-epoch by construction. Once the mode is `RekeyRequired`,
//!   EVERY further packet on that session rejects at the top of
//!   `accept_envelope`'s bounds — no decrypt, no dedup write, no commit
//!   (review D2b v8 P1-1): inbound is closed until the future
//!   rebootstrap leg, so a replayed gap packet cannot re-commit and no
//!   later application can be accepted and exposed. Relay-level ACK
//!   actions are unaffected (they never touch the ratchet).
//!
//!   Provenance of the committed `RekeyRequired` (review D2b v9 finding
//!   1): the dedup bounds reject a packet whose digest matches ANY
//!   retained record across ALL epochs before any ratchet touch, so a
//!   retired-epoch packet re-encapsulated with a fresh outer
//!   ID/signature can never reach `decrypt` (vodozemac classifies
//!   large gaps before MAC — it would gap-lock the new session). With
//!   global digest dedup in place, the only packets that can still
//!   produce gap errors are (a) genuine current-chain packets, where
//!   the gap is real loss and `RekeyRequired` is correct per §4, and
//!   (b) never-accepted foreign packets, which MAC-fail rather than
//!   gap-fail because they ride a different chain. "Authenticated
//!   current-epoch provenance" is therefore established BY
//!   CONSTRUCTION in the single-session world, and post-rebootstrap
//!   epoch separation is the rebootstrap leg's problem (out of scope).
//!   The same `now`-taking accept also sweeps expired sends and prunes
//!   terminal records before any staging (v9 finding 3), so an expired
//!   Pending control receipt re-stages on receipt-only traffic instead
//!   of squatting in the in-flight guard forever.
//! - **Terminal-record pruning** runs in the send-path mutators that take
//!   a clock (`stage_send`, `consume_inbound`): terminal records
//!   (`Stored`/`Duplicate`/`Expired`) are removed once
//!   `expires_at + tombstone TTL` has passed. `record_send_result` has no
//!   clock and never prunes.
//! - **Conversation binding is adopted at contact commit.** The
//!   out-of-band offer carries no conversation ID, so
//!   `commit_verified_contact` takes it as a parameter (single-assignment:
//!   a peer binding exists at most once). Without this, two façade
//!   clients could never share a conversation binding.

use std::marker::PhantomData;

#[cfg(test)]
mod tests;

use serde::Deserialize;
use vodozemac::olm::{Account, DecryptionError, OlmMessage, Session, SessionConfig};
use vodozemac::{Curve25519PublicKey, Ed25519Keypair, Ed25519PublicKey, Ed25519Signature};
use zeroize::Zeroizing;

use crate::capability::{AckRequest, FetchRequest, SendRequest, canonical, digest};
use crate::ids::{ConversationId, MessageId, Nonce, QueueId};
use crate::payload;
use crate::persistence::{ClientStateStore, ProtectionLevel, StateKeyProtector};
use crate::private_store_dir::PrivateStoreDir;
use crate::state::{
    AckIntent, AckState, ActiveSession, ClientStateV1, DedupRecord, DedupState, HighWaterReceipt,
    InboundRecord, MAX_ACKS, MAX_APPLICATION_OUTSTANDING, MAX_APPLICATION_SENDS, MAX_BODY,
    MAX_CONTROL_SENDS, MAX_DEDUP, MAX_KEYPAIR_JSON, MAX_PACKET, MAX_RECEIVED_SET, PeerBinding,
    PeerBundle, PendingPreKey, RegistrationRecord, Role, SendKind, SendRecord, SendState,
    SessionMode,
};
use crate::{EncryptedPacket, LabError, MailboxRegistration, Result};

/// Validity window for a contact offer, mirroring
/// `CONTACT_BUNDLE_MAX_VALIDITY_SECONDS` in `src/client.rs` (private
/// there; replicated, not edited).
const CONTACT_OFFER_MAX_VALIDITY_SECONDS: u64 = 5 * 60;

const PREKEY_ACTION: &[u8] = b"peer-prekey";
const SEND_ACTION: &[u8] = b"send";
const FETCH_ACTION: &[u8] = b"fetch";
const ACK_ACTION: &[u8] = b"ack";
const RECEIPT_ACTION: &[u8] = b"session-high-water/v1";
const RECEIPT_VERSION: u8 = 1;

/// The relay's per-message TTL bound (private in `relay.rs`; mirrored).
const MAX_MESSAGE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// The relay's tombstone TTL (private in `relay.rs`; mirrored) — terminal
/// send records are pruned this long after their expiry.
const TOMBSTONE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// The relay's request-validity window (`validate_request_time` in
/// relay.rs: registration, fetch, ACK and delete-mailbox requests must
/// satisfy `now < valid_until <= now + 300`). Mirrored so the façade
/// never mints a durable request the relay deterministically rejects
/// (review blocker 4).
const REQUEST_WINDOW_SECONDS: u64 = 5 * 60;
/// Section 4 budget: 24 application advances, then `ControlOnly`.
const CONTROL_ONLY_THRESHOLD: u64 = 24;

/// Canonical length-prefixed signing bytes for a send request; identical
/// construction to `send_signing_bytes` in `src/capability.rs`.
fn send_signing_bytes(
    queue_id: QueueId,
    message_id: MessageId,
    packet_digest: &[u8; 32],
    expires_at: u64,
) -> Vec<u8> {
    canonical(
        SEND_ACTION,
        &[
            queue_id.as_bytes(),
            message_id.as_bytes(),
            packet_digest,
            &expires_at.to_be_bytes(),
        ],
    )
}

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
///
/// Post-commit-crash retry semantics: if the process dies between the
/// commit and the return of a minting call, the returned action is lost
/// but the durable record is not — after reopen, the exact committed
/// action is reconstructed by the family's recovery view
/// (`pending_send_actions`, `pending_prekey_offer`, `ack_actions`), and
/// re-minting replaces the durable record per each family's documented
/// replacement rule.
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

/// Outcome of a durable send action, as reported by the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Stored,
    Duplicate,
    DeliveryUnknown,
}

/// The outcome of `accept_envelope`: a minimal owned view — the decrypted
/// body reaches callers only through `pending_inbound` after the commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// An application payload was accepted; the message ID indexes
    /// `pending_inbound`.
    Application(MessageId),
    /// A peer receipt advanced our peer-contiguous high water.
    ReceiptApplied,
    /// A peer receipt at or below the current high water (a repeat or a
    /// reordered legitimate receipt): accepted as a content no-op — the
    /// packet's sequence/dedup progress commits, only the high-water
    /// update is skipped — and deduped so its replay is rejected.
    ReceiptIdempotent,
}

/// The outcome of `stage_send` (review D2b v5 P1-3).
#[derive(Clone)]
pub enum StageSendOutcome {
    /// The application body was staged; the durable action rides the
    /// relay as usual.
    Staged(DurableAction<SendRequest>),
    /// No application was staged: an owed receipt took priority this
    /// pass and WAS committed (the send array was full afterwards, or
    /// the receipt's own sequence advance pushed outstanding across a
    /// budget-mode threshold). The application is retryable — call
    /// `stage_send` again after the receipt delivers or more capacity
    /// frees. Receipts were the silent-loss case; applications error
    /// honestly and can never starve.
    ReceiptFlushedRetry,
}

/// Owned view of an unconsumed inbound record. The frozen `InboundRecord`
/// layout has no `sent_at`, so the view carries the persisted times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundView {
    pub message_id: MessageId,
    pub body: String,
    pub sender_sequence: u64,
    pub accepted_at: u64,
    pub expires_at: u64,
}

/// The relay's answer to a durable ACK action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcomeView {
    /// Relay confirmed the deletion.
    Deleted,
    /// The message was already gone; terminal handling is identical.
    AlreadyGone,
    /// Transport failure: the intent stays `Pending` (retryable); no
    /// mutation and no commit happen for this outcome.
    Failed,
}

/// Owned view of a `DeliveryUnknown` send record (digest+expiry arm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryUnknownView {
    pub message_id: MessageId,
    pub packet_digest: [u8; 32],
    pub expires_at: u64,
}

/// Bookkeeping for the §2 mutator discipline. `Mutating` is never
/// observable across operations because everything is synchronous
/// `&mut self`; it exists to make the discipline explicit. Because no
/// observer can ever see it, `ensure_ready` intentionally collapses
/// `Mutating` and `ReconcileRequired` into one rejection path — that
/// branch is unreachable-by-construction for `Mutating`, not dead.
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
    /// `conversation_id` (D2b amendment): the contact exchange is
    /// out-of-band and the offer carries no conversation ID, so the
    /// verified-contact commit is where the shared conversation binding
    /// is adopted. It can be committed at most once (a peer binding
    /// exists at most once), so the adoption is single-assignment.
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
        conversation_id: ConversationId,
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
                candidate.state.conversation_id = conversation_id;
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
                    last_delivered_receipt_high_water: 0,
                    receipt_debt_up_to: 0,
                    control_debt_up_to: 0,
                    unreceipted_application_send_seqs: Vec::new(),
                    control_send_not_before: 0,
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
    /// registration. `valid_until` must fall inside the relay's request
    /// window (`now < valid_until <= now + 300`, review blocker 4) so no
    /// durable request is minted that the relay deterministically
    /// rejects.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::InvalidExpiry`] for a validity outside the
    /// relay's window, or a coarse error when signing or the commit
    /// fails.
    pub fn registration_action(
        &mut self,
        valid_until: u64,
        now: u64,
    ) -> Result<DurableAction<MailboxRegistration>> {
        self.mutate(
            |_current| {
                if valid_until <= now || valid_until > now.saturating_add(REQUEST_WINDOW_SECONDS) {
                    return Err(LabError::InvalidExpiry);
                }
                Ok(())
            },
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

    /// Sign a fetch request for our mailbox with the receive-capability
    /// keypair. §2 defines no result recorder for fetches and a fetch
    /// mutates no crypto state, so this D1-pattern action keeps NO durable
    /// record (documented reading of §2): the token is the fresh random
    /// fetch nonce and is purely correlational for the caller.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::InvalidExpiry`] for a non-future expiry, or a
    /// coarse storage error while the façade is not `Ready`.
    pub fn fetch_request(&self, valid_until: u64, now: u64) -> Result<DurableAction<FetchRequest>> {
        self.ensure_ready()?;
        // The relay's request window: `now < valid_until <= now + 300`.
        if valid_until <= now || valid_until > now.saturating_add(REQUEST_WINDOW_SECONDS) {
            return Err(LabError::InvalidExpiry);
        }
        let nonce = Nonce::random();
        let queue_id = self.state.mailbox_queue_id;
        let signing_bytes = canonical(
            FETCH_ACTION,
            &[
                queue_id.as_bytes(),
                nonce.as_bytes(),
                &valid_until.to_be_bytes(),
            ],
        );
        let signature = self.keypairs.receive.sign(&signing_bytes);
        Ok(DurableAction {
            token: *nonce.as_bytes(),
            request: FetchRequest {
                queue_id,
                nonce,
                valid_until,
                signature,
            },
        })
    }

    /// Accept a fetched envelope: authenticate, establish or advance the
    /// ratchet, strictly decode the payload, track the sender sequence,
    /// and durably record the outcome. Once the session is
    /// `RekeyRequired`, EVERY packet rejects at the top of the bounds —
    /// inbound is closed until the future rebootstrap leg (review D2b v8
    /// P1-1). The lettered steps of the D2b
    /// specification map onto the mutator discipline as: (a) bounds, then
    /// (c) envelope signature verification and (b) dedup, in THAT order —
    /// signature before dedup, the stronger order — in the step-2 bounds
    /// closure (rejection there touches nothing); (d) ratchet, (e) strict
    /// payload decode, (f) sequence tracking, (h) record writes inside
    /// step 4; (g) the gap-failure durable `RekeyRequired` commit is the
    /// one path where the commit succeeds and the error is reported
    /// afterwards (the mode change IS the durable outcome, per §4); (i)
    /// mode recompute from the fresh high water runs BEFORE any owed
    /// receipt staging (review D2b v4 blocker 4). A receipt payload
    /// whose high water regresses or repeats is a content no-op
    /// (`ReceiptIdempotent`) whose sequence/dedup progress commits —
    /// the §4 rejection applies to the update, not the authenticated
    /// packet; only future values (`hw > last_assigned_send_seq`)
    /// hard-error (review D2b v5 P1-1). Staging is unconditional over
    /// payload kinds: receipt debt comes only from CONSUMED application
    /// records (codec field 20, review D2b v5), so receipt-only
    /// exchanges never stage — quiescence by construction, with no
    /// marker bookkeeping in this tail.
    ///
    /// # Errors
    ///
    /// Returns coarse errors for envelope authentication failure
    /// ([`LabError::Unauthorized`]), duplicates
    /// ([`LabError::DuplicateMessage`]), decoding and crypto failures, or
    /// storage failures — including [`LabError::Storage`] for every
    /// packet on a `RekeyRequired` session. A gap failure returns
    /// [`LabError::Crypto`] AFTER
    /// the `RekeyRequired` mode change has committed.
    // The packet arrives by value per the frozen family signature; only
    // its digest is persisted (the inbound record holds digest+expiry).
    #[allow(clippy::needless_pass_by_value)]
    pub fn accept_envelope(
        &mut self,
        queue_id: QueueId,
        message_id: MessageId,
        packet: EncryptedPacket,
        expires_at: u64,
        sender_signature: Ed25519Signature,
        now: u64,
    ) -> Result<AcceptOutcome> {
        let packet_digest = packet.digest();
        // The `MAX_PACKET` bound is re-checked here, ahead of the
        // canonical parse below, so an oversized packet is still
        // rejected before anything parses it — the in-transaction bounds
        // check (which stays, and is the authoritative one) would
        // otherwise now run after the parse.
        if packet.as_bytes().len() > MAX_PACKET {
            return Err(LabError::InvalidPayload);
        }
        // (a0) Canonical Olm encoding, BEFORE the transaction (review
        // D2b v10, Sol's P1-1). The raw-byte digest computed above is
        // the dedup identity, so admitting two byte-different encodings
        // of the SAME Olm message would let an already-accepted packet
        // re-enter under a fresh digest and gap-lock the session. This
        // gate makes the encoding unique, so the raw digest is the
        // semantic identity. It touches no session state, so hoisting it
        // above the signature check leaks nothing (see
        // `EncryptedPacket::parse_canonical`).
        let olm_message = packet.parse_canonical()?;
        // The variant-independent dedup identity (review D2b v11, Sol's
        // P1-1). Computed here, from the already-parsed message, so both
        // the bounds closure and the record writes see the same value.
        let identity = PacketIdentity {
            packet_digest,
            message_digest: crate::client::inner_message_digest(&olm_message),
        };
        let message_digest = identity.message_digest;
        let artifact = self.mutate(
            |current| {
                // Inbound lock (review D2b v8 P1-1): once the session is
                // `RekeyRequired`, the conversation is closed until the
                // (future, out-of-scope) rebootstrap leg. Reject EVERY
                // packet here, at the top of the step-2 bounds — no
                // decrypt, no dedup write, no generation commit — so a
                // replayed gap packet cannot re-commit and no later
                // application can be accepted and exposed. Relay-level
                // ACK actions are unaffected (they never touch the
                // ratchet).
                if let Some(active) = &current.state.active_session {
                    if active.mode == SessionMode::RekeyRequired {
                        return Err(LabError::Storage);
                    }
                }
                // (a) bounds.
                if expires_at <= now {
                    return Err(LabError::RequestExpired);
                }
                if packet.as_bytes().len() > MAX_PACKET {
                    return Err(LabError::InvalidPayload);
                }
                if queue_id != current.state.mailbox_queue_id {
                    return Err(LabError::Unauthorized);
                }
                // (c) the outer envelope signature against OUR mailbox's
                // send public key (the capability we issued the peer).
                current
                    .state
                    .registration
                    .send_key
                    .verify(
                        &send_signing_bytes(queue_id, message_id, &packet_digest, expires_at),
                        &sender_signature,
                    )
                    .map_err(|_| LabError::Unauthorized)?;
                // (b) dedup: a matching message ID, or a matching
                // packet digest within ANY retained record, across ALL
                // epochs, rejects without any ratchet touch (review D2b
                // v9 finding 1: a retired-epoch packet re-encapsulated
                // with a fresh outer ID/signature must never reach
                // decrypt — vodozemac classifies large gaps before MAC,
                // so it would gap-lock the new session; the dedup
                // retention window is exactly what makes global matching
                // sound). Message-ID matching is unchanged. NOTE the
                // code verifies the signature (c) BEFORE dedup (b) —
                // deliberately, the stronger order: an unauthentic
                // packet is rejected before it can probe the dedup
                // picture (both reviewers flagged the old "dedup first"
                // comment; the code wins).
                for record in &current.state.dedup {
                    if record.message_id == message_id {
                        return Err(LabError::DuplicateMessage);
                    }
                    if record.packet_digest == packet_digest {
                        return Err(LabError::DuplicateMessage);
                    }
                    // Review D2b v11 (Sol's P1-1): the raw digest alone
                    // is not an identity. The SAME inner Olm message is
                    // canonically representable as both a `PreKey` and a
                    // `Normal` packet, and an established session
                    // decrypts both, consuming the same message key — so
                    // an accepted PreKey packet re-serialized as Normal
                    // has a fresh raw digest and would reach the ratchet
                    // and gap-lock the session. The inner-message digest
                    // is variant-independent and closes it.
                    if record.message_digest == message_digest {
                        return Err(LabError::DuplicateMessage);
                    }
                }
                // Dedup capacity, BEFORE decrypt (review D2b v12, Sol's
                // P1-2). An accepted packet unconditionally appends a
                // dedup record, and the codec refuses record 4,097 only
                // at serialization — after the ratchet has already
                // advanced on the candidate. The design's rule is
                // explicit: "While no record is eligible, new inbound
                // processing blocks before decrypt rather than weakening
                // replay protection." So refuse here when the set is
                // full and nothing is reclaimable, exactly as the ACK
                // bound does in `consume_inbound`.
                if current.state.dedup.len() >= MAX_DEDUP
                    && reclaimable_dedup_count(&current.state, now) == 0
                {
                    return Err(LabError::Storage);
                }
                // Session or pre-key establishment must be possible.
                if current.state.active_session.is_none()
                    && (current.state.peer_binding.is_none()
                        || current.state.pending_prekey.is_none())
                {
                    return Err(LabError::MissingSession);
                }
                Ok(())
            },
            |candidate, _keypairs| {
                accept_envelope_operation(
                    candidate,
                    queue_id,
                    message_id,
                    &olm_message,
                    identity,
                    expires_at,
                    now,
                )
            },
        )?;
        match artifact {
            AcceptArtifact::Outcome(outcome) => Ok(outcome),
            AcceptArtifact::GapFailure => Err(LabError::Crypto),
        }
    }

    /// Owned views of every unconsumed inbound record.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error while the façade is not `Ready`.
    pub fn pending_inbound(&self) -> Result<Vec<InboundView>> {
        self.ensure_ready()?;
        Ok(self
            .state
            .inbound
            .iter()
            .map(|record| InboundView {
                message_id: record.message_id,
                body: record.body.clone(),
                sender_sequence: record.sender_sequence,
                accepted_at: record.accepted_at,
                expires_at: record.expires_at,
            })
            .collect())
    }

    /// The displayed transition: remove the inbound record (freeing the
    /// 32-slot bound), create a `Pending` ACK intent, and record the
    /// receipt debt (codec field 20, review D2b v5): the highest CONSUMED
    /// application sequence — the only source of receipt debt, so
    /// receipt-only exchanges never obligate anything. Receipt staging
    /// follows the owed rule: a receipt reporting the current contiguous
    /// received high water is staged when the debt AND that water both
    /// exceed the DELIVERED marker (`last_delivered_receipt_high_water`,
    /// codec field 19) and no `Pending` receipt for the current water is
    /// in flight, the mode allows control traffic
    /// (`Ready`/`ControlOnly`; `ReceiptLocked`/`RekeyRequired` block all
    /// encryption per §4), and the send array has capacity; otherwise it
    /// stays owed and the next clock-taking mutator retries — a skipped
    /// receipt is never lost. The receipt rides the unchanged D2a send
    /// machinery as a `Pending` send record whose payload is a `Receipt`
    /// kind.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::MessageNotFound`] for an unknown or already
    /// Drive deferred control and receipt debt (§4 control-lane split).
    ///
    /// Coalescing plus the one-per-second cooldown means an owed receipt
    /// is often DEFERRED rather than staged in the pass that created the
    /// debt. §4's liveness story for that is a local wake at the
    /// cooldown boundary or when an unresolved send resolves, so the
    /// caller needs a mutator whose only job is to sweep and flush.
    /// Without one, deferred debt escapes only as a side effect of an
    /// unrelated call such as `stage_send` — precisely the hidden
    /// coupling that produced this leg's liveness defects, and it would
    /// leave a quiescent receiver unable to ever answer a congested
    /// peer.
    ///
    /// Returns whether a receipt staged. Idempotent and safe to call on
    /// a timer: with nothing owed, nothing eligible, or the cooldown
    /// still closed it stages nothing.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error while the façade is not `Ready`,
    /// or on commit failure.
    pub fn flush_control(&mut self, now: u64) -> Result<bool> {
        self.ensure_ready()?;
        let mut staged = false;
        self.mutate(
            |_current| Ok(()),
            |candidate, _keypairs| {
                sweep_expired_sends(candidate, now)?;
                prune_terminal_sends(candidate, now);
                sweep_expired_acks(candidate, now)?;
                staged = maybe_stage_owed_receipt(candidate, now)?;
                if let Some(active) = candidate.state.active_session.as_mut() {
                    recompute_mode(active);
                }
                Ok(())
            },
        )?;
        Ok(staged)
    }

    /// Consume one accepted inbound record: remove it, create the ACK
    /// intent, and stage the coalesced receipt when the lane allows.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::MessageNotFound`] for an unknown or already
    /// consumed ID, [`LabError::InvalidExpiry`] for a non-future ACK
    /// expiry, or a coarse error for crypto/commit failures.
    pub fn consume_inbound(
        &mut self,
        message_id: MessageId,
        valid_until: u64,
        now: u64,
    ) -> Result<()> {
        self.mutate(
            |current| {
                if !current
                    .state
                    .inbound
                    .iter()
                    .any(|record| record.message_id == message_id)
                {
                    return Err(LabError::MessageNotFound);
                }
                // The ACK request must fall inside the relay's request
                // window, or the relay deterministically rejects it.
                if valid_until <= now || valid_until > now.saturating_add(REQUEST_WINDOW_SECONDS) {
                    return Err(LabError::InvalidExpiry);
                }
                // Fail clearly BEFORE mutation when the ACK bound is full
                // with nothing sweepable (review blocker 2).
                let sweepable = current
                    .state
                    .acks
                    .iter()
                    .filter(|record| record.state == AckState::Pending && record.valid_until <= now)
                    .count();
                if current.state.acks.len() >= MAX_ACKS && sweepable == 0 {
                    return Err(LabError::Storage);
                }
                Ok(())
            },
            |candidate, _keypairs| {
                consume_inbound_operation(candidate, message_id, valid_until, now)
            },
        )
    }

    /// The exact ACK requests for every `Pending` ACK intent, signed with
    /// the receive-capability keypair (mirroring `authorize_ack`).
    /// Read-only signing: no mutation, no commit. Intents at or past their
    /// validity are skipped (the relay would reject them); they are swept
    /// by the expiry machinery.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error while the façade is not `Ready`.
    pub fn ack_actions(&self, now: u64) -> Result<Vec<DurableAction<AckRequest>>> {
        self.ensure_ready()?;
        let mut actions = Vec::new();
        for record in &self.state.acks {
            if record.state != AckState::Pending || record.valid_until <= now {
                continue;
            }
            let signing_bytes = canonical(
                ACK_ACTION,
                &[
                    record.queue_id.as_bytes(),
                    record.message_id.as_bytes(),
                    &record.packet_digest,
                    &record.valid_until.to_be_bytes(),
                ],
            );
            let signature = self.keypairs.receive.sign(&signing_bytes);
            actions.push(DurableAction {
                token: *record.message_id.as_bytes(),
                request: AckRequest {
                    queue_id: record.queue_id,
                    message_id: record.message_id,
                    packet_hash: record.packet_digest,
                    valid_until: record.valid_until,
                    signature,
                },
            });
        }
        Ok(actions)
    }

    /// Record the relay's answer to a durable ACK action. The full action
    /// is presented back and the COMPLETE binding verification (message
    /// ID to token and durable intent, queue/digest/expiry equality, and
    /// the signature against our receive-capability public key over the
    /// exact ACK signing bytes) runs for EVERY outcome, including
    /// `Failed` — a transport failure is only accepted once the action is
    /// proven to be the current durable one. `Deleted` and `AlreadyGone`
    /// share the terminal handling: the intent is removed and the
    /// matching dedup record becomes `Acked`. A verified `Failed` leaves
    /// the intent untouched — no mutation, no commit.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::MessageNotFound`] for an unknown token,
    /// [`LabError::MessageGone`] when the intent is no longer `Pending`,
    /// [`LabError::Unauthorized`] on any request mismatch, or a coarse
    /// storage error when the commit fails.
    pub fn record_ack_result(
        &mut self,
        action: &DurableAction<AckRequest>,
        outcome: AckOutcomeView,
    ) -> Result<()> {
        self.ensure_ready()?;
        // Full binding verification for every outcome (review blocker:
        // previously `Failed` skipped it).
        verify_ack_action(&self.state, action)?;
        if matches!(outcome, AckOutcomeView::Failed) {
            return Ok(());
        }
        self.mutate(
            |current| verify_ack_action(&current.state, action),
            |candidate, _keypairs| {
                let index = candidate
                    .state
                    .acks
                    .binary_search_by(|probe| probe.message_id.as_bytes().cmp(&action.token))
                    .map_err(|_| LabError::MessageNotFound)?;
                let record = candidate.state.acks.remove(index);
                let dedup_index = candidate
                    .state
                    .dedup
                    .binary_search_by(|probe| {
                        probe
                            .message_id
                            .as_bytes()
                            .cmp(record.message_id.as_bytes())
                    })
                    .map_err(|_| LabError::Storage)?;
                candidate.state.dedup[dedup_index].state = DedupState::Acked;
                if let Some(active) = candidate.state.active_session.as_mut() {
                    recompute_mode(active);
                }
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

    /// Stage an application send (D2a): expiry sweep, the owed receipt
    /// (control priority, review D2b v4 blocker 3), a budget-mode
    /// recompute from the NEW outstanding (review D2b v5 P1-2), payload
    /// v2, Olm encryption with the candidate session, packet bound,
    /// signature with the peer-binding send capability for the peer's
    /// queue, `Pending` record, commit — then the outcome is returned.
    ///
    /// Application staging is allowed iff the current mode is `Ready`
    /// (§4) and the send array has capacity after the sweeps and the owed
    /// receipt. An owed receipt outranks the new body: when it leaves no
    /// slot, or its own sequence advance pushed outstanding across a
    /// budget threshold, the receipt is COMMITTED and the result is
    /// [`StageSendOutcome::ReceiptFlushedRetry`] — an honest, retryable
    /// "no application staged" rather than a discarded candidate
    /// (review D2b v5 P1-3). On [`StageSendOutcome::Staged`] the token is
    /// the fresh random `message_id`; the durable request binding is the
    /// record's canonical digest (see the module docs).
    ///
    /// # Errors
    ///
    /// Returns [`LabError::MissingSession`] without a session or binding,
    /// [`LabError::Storage`] when the mode blocks staging or the send
    /// array is full with no owed receipt to flush,
    /// [`LabError::InvalidExpiry`] for an expired or overlong TTL,
    /// [`LabError::InvalidPayload`] for an oversized body, or a coarse
    /// error for crypto/commit failures.
    pub fn stage_send(
        &mut self,
        body: &str,
        sent_at: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<StageSendOutcome> {
        self.mutate(
            |current| {
                let active = current
                    .state
                    .active_session
                    .as_ref()
                    .ok_or(LabError::MissingSession)?;
                if current.state.peer_binding.is_none() {
                    return Err(LabError::MissingSession);
                }
                // §4: application bodies stage only in Ready.
                if active.mode != SessionMode::Ready {
                    return Err(LabError::Storage);
                }
                if expires_at <= now || expires_at - now > MAX_MESSAGE_TTL_SECONDS {
                    return Err(LabError::InvalidExpiry);
                }
                if body.len() > MAX_BODY {
                    return Err(LabError::InvalidPayload);
                }
                Ok(())
            },
            |candidate, _keypairs| stage_send_operation(candidate, body, sent_at, expires_at, now),
        )
    }

    /// Owned reconstruction of every `Pending` record's exact durable
    /// request, for crash retry. Each action's token is its message ID.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error while the façade is not `Ready`.
    pub fn pending_send_actions(&self) -> Result<Vec<DurableAction<SendRequest>>> {
        self.ensure_ready()?;
        let mut actions = Vec::new();
        for record in &self.state.sends {
            if record.state != SendState::Pending {
                continue;
            }
            let (Some(queue_id), Some(packet), Some(signature)) =
                (record.queue_id, &record.packet, &record.send_signature)
            else {
                return Err(LabError::Storage);
            };
            actions.push(DurableAction {
                token: *record.message_id.as_bytes(),
                request: SendRequest {
                    queue_id,
                    message_id: record.message_id,
                    packet: packet.clone(),
                    expires_at: record.expires_at,
                    signature: *signature,
                },
            });
        }
        Ok(actions)
    }

    /// Record the relay's answer to a durable send action. The full action
    /// is presented back: token (message ID) lookup plus the digest check
    /// against the durable record's canonical bytes run before staging;
    /// transitions are allowed only from `Pending`. Every outcome maps to
    /// its codec digest+expiry arm (codec v3: `DeliveryUnknown` is
    /// body-free). Per §4 none of these transitions advances the peer high
    /// water or recovers send budget.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::MessageNotFound`] for an unknown token,
    /// [`LabError::MessageGone`] when the record is no longer `Pending`,
    /// [`LabError::Unauthorized`] on a request digest mismatch, or a
    /// coarse storage error when the commit fails.
    pub fn record_send_result(
        &mut self,
        action: &DurableAction<SendRequest>,
        outcome: SendOutcome,
    ) -> Result<()> {
        self.mutate(
            |current| {
                let index = current
                    .state
                    .sends
                    .binary_search_by(|probe| probe.message_id.as_bytes().cmp(&action.token))
                    .map_err(|_| LabError::MessageNotFound)?;
                let record = &current.state.sends[index];
                if record.state != SendState::Pending {
                    return Err(LabError::MessageGone);
                }
                // The presented request's message ID must bind to the
                // token AND the durable record (review finding: no
                // substitution of the stored ID).
                if action.request.message_id.as_bytes() != &action.token
                    || action.request.message_id != record.message_id
                {
                    return Err(LabError::Unauthorized);
                }
                let presented = SendRecord {
                    message_id: record.message_id,
                    state: SendState::Pending,
                    epoch_id: record.epoch_id,
                    sequence: record.sequence,
                    queue_id: Some(action.request.queue_id),
                    packet: Some(action.request.packet.clone()),
                    expires_at: action.request.expires_at,
                    send_signature: Some(action.request.signature),
                    packet_digest: None,
                    kind: record.kind,
                    receipt_high_water: record.receipt_high_water,
                };
                if digest(&presented.encode()?) != digest(&record.encode()?) {
                    return Err(LabError::Unauthorized);
                }
                Ok(())
            },
            |candidate, _keypairs| {
                let index = candidate
                    .state
                    .sends
                    .binary_search_by(|probe| probe.message_id.as_bytes().cmp(&action.token))
                    .map_err(|_| LabError::MessageNotFound)?;
                let record = &mut candidate.state.sends[index];
                let packet_digest = record.packet.as_ref().ok_or(LabError::Storage)?.digest();
                // The receipt marker advances only here: a receipt-kind
                // record reaching a delivered-to-relay terminal state
                // (Stored or Duplicate). Never at staging, never on
                // DeliveryUnknown/Expired/consume (review D2b v4).
                let delivered_receipt_hw = if record.kind == SendKind::Receipt
                    && matches!(outcome, SendOutcome::Stored | SendOutcome::Duplicate)
                {
                    record.receipt_high_water
                } else {
                    None
                };
                record.state = match outcome {
                    SendOutcome::Stored => SendState::Stored,
                    SendOutcome::Duplicate => SendState::Duplicate,
                    SendOutcome::DeliveryUnknown => SendState::DeliveryUnknown,
                };
                record.queue_id = None;
                record.packet = None;
                record.send_signature = None;
                record.packet_digest = Some(packet_digest);
                // Terminal arms carry no high water (codec: field 11 is
                // present only on a full-arm receipt); the marker above
                // has already captured the delivered value.
                record.receipt_high_water = None;
                if let Some(active) = candidate.state.active_session.as_mut() {
                    if let Some(high_water) = delivered_receipt_hw {
                        // Monotone: an older receipt finishing after a
                        // newer one never moves the marker backward. This
                        // advance is also the ONLY resolution of control
                        // debt (review D2b v9 water model): debt stands
                        // while `control_debt_up_to` exceeds the marker,
                        // so a delayed `Stored` on an OLDER receipt
                        // (`hw < control_debt_up_to`) leaves newer debt
                        // standing instead of clearing it — there is no
                        // explicit clearing anywhere.
                        active.last_delivered_receipt_high_water =
                            active.last_delivered_receipt_high_water.max(high_water);
                    }
                    recompute_mode(active);
                }
                Ok(())
            },
        )
    }

    /// Owned views of every `DeliveryUnknown` record.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error while the façade is not `Ready`.
    pub fn delivery_unknowns(&self) -> Result<Vec<DeliveryUnknownView>> {
        self.ensure_ready()?;
        self.state
            .sends
            .iter()
            .filter(|record| record.state == SendState::DeliveryUnknown)
            .map(|record| {
                Ok(DeliveryUnknownView {
                    message_id: record.message_id,
                    packet_digest: record.packet_digest.ok_or(LabError::Storage)?,
                    expires_at: record.expires_at,
                })
            })
            .collect()
    }

    /// Resolve a `DeliveryUnknown` record by REMOVING it from the send
    /// array, freeing the bounded slot (D2a decision, documented in the
    /// module docs: the alternative — keeping a consumed marker — would
    /// exhaust the 32-record bound under churn; the digest is durably
    /// present in the dedup picture only on the receive side, and §4 says
    /// consuming a `DeliveryUnknown` never advances the peer high water
    /// nor recovers send budget by itself). Unknown or wrong-state IDs
    /// reject without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::MessageNotFound`] for an unknown ID,
    /// [`LabError::MessageGone`] when the record is not
    /// `DeliveryUnknown`, or a coarse storage error when the commit
    /// fails.
    pub fn consume_delivery_unknown(&mut self, message_id: MessageId, now: u64) -> Result<()> {
        self.mutate(
            |current| {
                let index = current
                    .state
                    .sends
                    .binary_search_by(|probe| {
                        probe.message_id.as_bytes().cmp(message_id.as_bytes())
                    })
                    .map_err(|_| LabError::MessageNotFound)?;
                if current.state.sends[index].state != SendState::DeliveryUnknown {
                    return Err(LabError::MessageGone);
                }
                Ok(())
            },
            |candidate, _keypairs| {
                sweep_expired_sends(candidate, now)?;
                let index = candidate
                    .state
                    .sends
                    .binary_search_by(|probe| {
                        probe.message_id.as_bytes().cmp(message_id.as_bytes())
                    })
                    .map_err(|_| LabError::MessageNotFound)?;
                // The sweep may have transitioned the target to Expired.
                if candidate.state.sends[index].state != SendState::DeliveryUnknown {
                    return Err(LabError::MessageGone);
                }
                candidate.state.sends.remove(index);
                // Freeing a slot can make an owed receipt stageable.
                maybe_stage_owed_receipt(candidate, now)?;
                if let Some(active) = candidate.state.active_session.as_mut() {
                    recompute_mode(active);
                }
                Ok(())
            },
        )
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

/// §4 expiry sweep at the top of every send-path mutator: `Pending` and
/// `DeliveryUnknown` records at or past their expiry become `Expired`
/// (digest+expiry arm). `Expired` never advances the peer high water and
/// never recovers send budget.
fn sweep_expired_sends(candidate: &mut Candidate, now: u64) -> Result<()> {
    for record in &mut candidate.state.sends {
        if matches!(
            record.state,
            SendState::Pending | SendState::DeliveryUnknown
        ) && record.expires_at <= now
        {
            let packet_digest = match &record.packet_digest {
                Some(digest) => *digest,
                None => record.packet.as_ref().ok_or(LabError::Storage)?.digest(),
            };
            record.state = SendState::Expired;
            record.queue_id = None;
            record.packet = None;
            record.send_signature = None;
            record.packet_digest = Some(packet_digest);
            // Terminal arms carry no high water (codec: field 11 is
            // present only on a full-arm receipt); an expired receipt
            // never delivered, so the marker does not move and the owed
            // rule re-arms automatically.
            record.receipt_high_water = None;
        }
    }
    Ok(())
}

/// The complete ACK-action binding verification, run for EVERY outcome
/// of `record_ack_result` (review blocker 1): token lookup, the intent
/// still `Pending`, the request's message ID bound to the token and the
/// intent, queue/digest/expiry equal to the durable fields, and the
/// signature verified against our receive-capability public key over the
/// exact ACK signing bytes (mirroring `authorize_ack`).
fn verify_ack_action(state: &ClientStateV1, action: &DurableAction<AckRequest>) -> Result<()> {
    let index = state
        .acks
        .binary_search_by(|probe| probe.message_id.as_bytes().cmp(&action.token))
        .map_err(|_| LabError::MessageNotFound)?;
    let record = &state.acks[index];
    if record.state != AckState::Pending {
        return Err(LabError::MessageGone);
    }
    let request = &action.request;
    if request.message_id.as_bytes() != &action.token
        || request.message_id != record.message_id
        || request.queue_id != record.queue_id
        || request.packet_hash != record.packet_digest
        || request.valid_until != record.valid_until
    {
        return Err(LabError::Unauthorized);
    }
    let signing_bytes = canonical(
        ACK_ACTION,
        &[
            record.queue_id.as_bytes(),
            record.message_id.as_bytes(),
            &record.packet_digest,
            &record.valid_until.to_be_bytes(),
        ],
    );
    state
        .registration
        .receive_key
        .verify(&signing_bytes, &request.signature)
        .map_err(|_| LabError::Unauthorized)?;
    Ok(())
}

/// D2b: sweep expired `Pending` ACK intents in clock-taking mutators
/// (same pattern as the send expiry sweep): the intent is removed and its
/// dedup record becomes `Expired`. Unexpired intents are never swept;
/// high-water and budget state are never touched.
fn sweep_expired_acks(candidate: &mut Candidate, now: u64) -> Result<()> {
    let mut expired = Vec::new();
    for record in &candidate.state.acks {
        if record.state == AckState::Pending && record.valid_until <= now {
            expired.push(record.message_id);
        }
    }
    for message_id in expired {
        let index = candidate
            .state
            .acks
            .iter()
            .position(|record| record.message_id == message_id)
            .ok_or(LabError::Storage)?;
        let record = candidate.state.acks.remove(index);
        let dedup_index = candidate
            .state
            .dedup
            .binary_search_by(|probe| {
                probe
                    .message_id
                    .as_bytes()
                    .cmp(record.message_id.as_bytes())
            })
            .map_err(|_| LabError::Storage)?;
        candidate.state.dedup[dedup_index].state = DedupState::Expired;
    }
    Ok(())
}

/// §4 mode recomputation after each committed mutation: the budget modes
/// derive from outstanding = `last_assigned_send_seq` −
/// `peer_contiguous_high_water`; `RekeyRequired` dominates and is never
/// recomputed away by this leg (it exits only via the §4 rebootstrap,
/// which is out of scope for D2).
fn recompute_mode(active: &mut ActiveSession) {
    if active.mode == SessionMode::RekeyRequired {
        return;
    }
    // §4 control-lane split: the budget mode keys off the APPLICATION
    // lane only — the length of the unreceipted application sequence
    // set — not the shared sequence distance. Control sends advance the
    // shared sequence but cost no application capacity, so a peer that
    // signals congestion can no longer consume our ability to send.
    active.mode = if application_outstanding(active) >= MAX_APPLICATION_OUTSTANDING {
        SessionMode::ControlOnly
    } else {
        SessionMode::Ready
    };
}

/// §4 control-lane split: `application_outstanding` is exactly the count
/// of application sequences the peer's contiguous high water does not
/// yet cover.
fn application_outstanding(active: &ActiveSession) -> usize {
    active.unreceipted_application_send_seqs.len()
}

/// The step-4 body of `stage_send` (extracted to keep the public method
/// readable): sweep, stage the owed receipt (control priority, v4
/// blocker 3), recompute the mode from the new outstanding (v5 P1-2),
/// then admit the application — or, when it cannot be admitted, commit
/// the flushed receipt and report `ReceiptFlushedRetry` (v5 P1-3).
fn stage_send_operation(
    candidate: &mut Candidate,
    body: &str,
    sent_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<StageSendOutcome> {
    sweep_expired_sends(candidate, now)?;
    prune_terminal_sends(candidate, now);
    sweep_expired_acks(candidate, now)?;
    // Control priority (review D2b v4 blocker 3): an owed receipt
    // outranks the new application body for any slot the sweeps freed,
    // so it stages BEFORE the application decision.
    let receipt_staged = maybe_stage_owed_receipt(candidate, now)?;
    // Review D2b v5 P1-2: recompute the budget mode from the NEW
    // outstanding BEFORE deciding the application — the receipt's own
    // sequence advance may have pushed the session across the
    // `ControlOnly`/`ReceiptLocked` threshold.
    let mode = {
        let active = candidate
            .state
            .active_session
            .as_mut()
            .ok_or(LabError::MissingSession)?;
        recompute_mode(active);
        active.mode
    };
    let application_records = candidate
        .state
        .sends
        .iter()
        .filter(|record| record.kind == SendKind::Application)
        .count();
    if application_records >= MAX_APPLICATION_SENDS || mode != SessionMode::Ready {
        // Review D2b v5 P1-3: when the application cannot be admitted
        // after owed staging (slot or mode), the staged receipt IS this
        // pass's progress — commit it (the operation returns `Ok`, so
        // the §2 mutate discipline stages, validates and commits the
        // candidate exactly as usual) and honestly report that no
        // application was staged. Without a staged receipt there is
        // nothing to flush: discard and error as before.
        if receipt_staged {
            return Ok(StageSendOutcome::ReceiptFlushedRetry);
        }
        return Err(LabError::Storage);
    }
    Ok(StageSendOutcome::Staged(admit_application_send(
        candidate, body, sent_at, expires_at,
    )?))
}

/// Admit the application body (extracted to keep the operation
/// readable): payload v2, Olm encryption with the candidate session,
/// packet bound, signature with the peer-binding send capability for the
/// peer's queue, `Pending` record, mode recompute — then the action.
fn admit_application_send(
    candidate: &mut Candidate,
    body: &str,
    sent_at: u64,
    expires_at: u64,
) -> Result<DurableAction<SendRequest>> {
    let (epoch_id, send_seq, conversation_id, issuer_outstanding) = {
        let active = candidate
            .state
            .active_session
            .as_ref()
            .ok_or(LabError::MissingSession)?;
        let send_seq = active
            .last_assigned_send_seq
            .checked_add(1)
            .ok_or(LabError::Storage)?;
        (
            active.epoch_id,
            send_seq,
            candidate.state.conversation_id,
            // §4 control-lane split: `issuer_outstanding` now means the
            // issuer's APPLICATION outstanding. An application payload
            // carries the POST-application-advance value — this send's
            // own sequence counted — so the 24th application send
            // reports 24 and actually signals (the v8 P1-3 property,
            // preserved under the new accounting).
            application_outstanding(active) as u64 + 1,
        )
    };
    let message_id = MessageId::random();
    let outgoing = payload::application(
        conversation_id,
        message_id,
        epoch_id,
        send_seq,
        sent_at,
        body.to_owned(),
        issuer_outstanding,
    )?;
    let encoded = payload::encode(&outgoing)?;
    let session = candidate.session.as_mut().ok_or(LabError::MissingSession)?;
    let message = session
        .encrypt(&encoded[..])
        .map_err(|_| LabError::Crypto)?;
    let packet = EncryptedPacket::from_untrusted(
        serde_json::to_vec(&message).map_err(|_| LabError::Encoding)?,
    );
    if packet.as_bytes().len() > MAX_PACKET {
        return Err(LabError::Encoding);
    }
    let binding = candidate
        .state
        .peer_binding
        .as_ref()
        .ok_or(LabError::MissingSession)?;
    let keypair = parse_capability_keypair(&binding.send_keypair_json)?;
    let queue_id = binding.queue_id;
    let signature = keypair.sign(&send_signing_bytes(
        queue_id,
        message_id,
        &packet.digest(),
        expires_at,
    ));
    let request = SendRequest {
        queue_id,
        message_id,
        packet: packet.clone(),
        expires_at,
        signature,
    };
    candidate.state.sends.push(SendRecord {
        message_id,
        state: SendState::Pending,
        epoch_id,
        sequence: send_seq,
        queue_id: Some(queue_id),
        packet: Some(packet),
        expires_at,
        send_signature: Some(signature),
        packet_digest: None,
        kind: SendKind::Application,
        receipt_high_water: None,
    });
    candidate
        .state
        .sends
        .sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));
    {
        let active = candidate
            .state
            .active_session
            .as_mut()
            .ok_or(LabError::MissingSession)?;
        active.last_assigned_send_seq = send_seq;
        // §4 control-lane split: an APPLICATION send appends its shared
        // sequence to the durable ledger, atomically with the ratchet
        // advance and the SendRecord above. This is the only site that
        // grows `application_outstanding`.
        active.unreceipted_application_send_seqs.push(send_seq);
        recompute_mode(active);
    }
    Ok(DurableAction {
        token: *message_id.as_bytes(),
        request,
    })
}

/// Internal artifact of `accept_envelope`: either an accepted outcome or
/// the §4 gap failure (which commits the `RekeyRequired` mode change and
/// reports the failure afterwards).
enum AcceptArtifact {
    Outcome(AcceptOutcome),
    GapFailure,
}

/// Canonical length-prefixed receipt signing bytes; the SAME part order
/// the codec's `validate.rs` verifies (version, conversation, epoch,
/// acknowledged sender curve, issuer curve, high water) over the
/// `session-high-water/v1` domain.
fn receipt_signing_bytes(receipt: &HighWaterReceipt) -> Vec<u8> {
    canonical(
        RECEIPT_ACTION,
        &[
            &[RECEIPT_VERSION],
            receipt.conversation_id.as_bytes(),
            &receipt.epoch_id,
            receipt.acknowledged_sender_curve.as_bytes(),
            receipt.issuer_curve.as_bytes(),
            &receipt.high_water.to_be_bytes(),
        ],
    )
}

/// The ratchet step's product: the decrypted plaintext, or the §4 gap
/// failure (whose mode change is the durable outcome).
enum RatchetStep {
    Plaintext(Vec<u8>),
    GapFailure,
}

/// Step (d) of accept: decode the Olm message and establish or advance
/// the ratchet on the candidate. The pre-key path first requires our own
/// pending offer to be unexpired at `now` (review blocker 3): an expired
/// offer's one-time key must not be consumed.
fn ratchet_step(
    candidate: &mut Candidate,
    olm_message: &OlmMessage,
    now: u64,
) -> Result<RatchetStep> {
    if candidate.state.active_session.is_none() {
        let OlmMessage::PreKey(pre_key) = olm_message else {
            return Err(LabError::ExpectedPreKey);
        };
        let binding = candidate
            .state
            .peer_binding
            .as_ref()
            .ok_or(LabError::MissingSession)?;
        let pending = candidate
            .state
            .pending_prekey
            .as_ref()
            .ok_or(LabError::MissingSession)?;
        if pending.valid_until <= now {
            return Err(LabError::PeerVerificationFailed);
        }
        let creation = candidate
            .account
            .create_inbound_session(
                SessionConfig::version_1(),
                binding.bundle.curve_identity,
                pre_key,
            )
            .map_err(|_| LabError::Crypto)?;
        let session = creation.session;
        let plaintext = creation.plaintext;
        let keys = session.session_keys();
        // The transcript is OUR consumed prekey bundle; its advertised
        // one-time key must be the one the session consumed.
        if keys.one_time_key != pending.one_time_key {
            return Err(LabError::Crypto);
        }
        let transcript = pending.bundle();
        // The one-time key is consumed; the pending-prekey record must go.
        candidate.state.pending_prekey = None;
        candidate.state.active_session = Some(ActiveSession {
            role: Role::Inbound,
            session_pickle: Zeroizing::new(
                serde_json::to_vec(&session.pickle()).map_err(|_| LabError::Storage)?,
            ),
            identity_key: keys.identity_key,
            base_key: keys.base_key,
            one_time_key: keys.one_time_key,
            transcript,
            epoch_id: epoch_of(keys),
            last_assigned_send_seq: 0,
            peer_contiguous_high_water: 0,
            highest_contiguous_received_seq: 0,
            mode: SessionMode::Ready,
            receipt: None,
            received_above_high_water: Vec::new(),
            last_delivered_receipt_high_water: 0,
            receipt_debt_up_to: 0,
            control_debt_up_to: 0,
            unreceipted_application_send_seqs: Vec::new(),
            control_send_not_before: 0,
            conversation_id: candidate.state.conversation_id,
        });
        candidate.session = Some(session);
        return Ok(RatchetStep::Plaintext(plaintext));
    }
    // On an established session, vodozemac decrypts both message
    // variants (the initiator keeps sending PreKey messages until it
    // receives a reply), mirroring `OlmClient::open`.
    let session = candidate.session.as_mut().ok_or(LabError::MissingSession)?;
    match session.decrypt(olm_message) {
        Ok(bytes) => Ok(RatchetStep::Plaintext(bytes)),
        Err(DecryptionError::MissingMessageKey(_) | DecryptionError::TooBigMessageGap(..)) => {
            // (g) §4: a previously unseen, peer-authenticated packet on
            // the current session failing with a gap error moves the
            // session durably to RekeyRequired. The candidate commits;
            // the caller reports the failure after commit.
            let active = candidate
                .state
                .active_session
                .as_mut()
                .ok_or(LabError::MissingSession)?;
            active.mode = SessionMode::RekeyRequired;
            Ok(RatchetStep::GapFailure)
        }
        Err(_) => Err(LabError::Crypto),
    }
}

/// The two digests an accepted packet carries. The raw `packet_digest`
/// is what the sender signs, so it stays the envelope and ACK binding;
/// `message_digest` is the variant-independent inner-Olm-message
/// identity and is what dedup keys on (review D2b v11, Sol's P1-1).
#[derive(Clone, Copy)]
struct PacketIdentity {
    packet_digest: [u8; 32],
    message_digest: [u8; 32],
}

/// Envelope fields carried through the accept record writes.
struct EnvelopeContext {
    message_id: MessageId,
    epoch_id: [u8; 32],
    send_seq: u64,
    queue_id: QueueId,
    packet_digest: [u8; 32],
    expires_at: u64,
    /// Variant-independent inner-message identity (review D2b v11).
    message_digest: [u8; 32],
}

/// The receipt arm of accept: verify, apply §4 acceptance, record dedup.
fn apply_receipt(
    candidate: &mut Candidate,
    receipt_v2: &payload::ReceiptV2,
    context: &EnvelopeContext,
) -> Result<AcceptOutcome> {
    let receipt = receipt_v2.to_stored()?;
    let binding = candidate
        .state
        .peer_binding
        .as_ref()
        .ok_or(LabError::MissingSession)?;
    if receipt.conversation_id != candidate.state.conversation_id
        || receipt.epoch_id != context.epoch_id
        || receipt.issuer_curve != binding.bundle.curve_identity
        || receipt.acknowledged_sender_curve != candidate.account.curve25519_key()
    {
        return Err(LabError::PeerVerificationFailed);
    }
    binding
        .bundle
        .signing_identity
        .verify(&receipt_signing_bytes(&receipt), &receipt.signature)
        .map_err(|_| LabError::PeerVerificationFailed)?;
    // The dedup record is written for both receipt outcomes.
    push_dedup(candidate, context);
    let active = candidate
        .state
        .active_session
        .as_mut()
        .ok_or(LabError::MissingSession)?;
    let old_high_water = active.peer_contiguous_high_water;
    if receipt.high_water > active.last_assigned_send_seq {
        // Future values remain a forgery class: hard error, the whole
        // candidate (sequence, dedup, ratchet) is discarded.
        return Err(LabError::InvalidPayload);
    }
    if receipt.high_water <= old_high_water {
        // Regression or repeat (review D2b v5 P1-1): the §4 rejection of
        // regressing high waters rejects the UPDATE, not the
        // authenticated packet — a reordered legitimate receipt is a
        // content no-op whose sequence/dedup/ACK progress COMMITS
        // normally; only the high-water update is skipped. (The §3
        // codec requires receipt high-water consistency only as `<=`,
        // so no codec change is needed.)
        Ok(AcceptOutcome::ReceiptIdempotent)
    } else {
        // §4 control-lane split: commit the new high water, prune every
        // application sequence it covers, and recompute the mode BEFORE
        // any new application permission is exposed. Pruning here is the
        // ONLY site that shrinks `application_outstanding` — send
        // results, expiry, `DeliveryUnknown` consumption and record
        // pruning never return application budget.
        active.peer_contiguous_high_water = receipt.high_water;
        active
            .unreceipted_application_send_seqs
            .retain(|sequence| *sequence > receipt.high_water);
        active.receipt = Some(receipt);
        recompute_mode(active);
        Ok(AcceptOutcome::ReceiptApplied)
    }
}

/// Step 4 of `accept_envelope`: ratchet, payload, sequence, records.
fn accept_envelope_operation(
    candidate: &mut Candidate,
    queue_id: QueueId,
    message_id: MessageId,
    olm_message: &OlmMessage,
    identity: PacketIdentity,
    expires_at: u64,
    now: u64,
) -> Result<AcceptArtifact> {
    // Clock-taking mutator: the send expiry sweep and terminal pruning
    // run first (review D2b v9 finding 3 — accept takes `now`, and an
    // expired Pending control receipt would otherwise stay "in flight"
    // under the any-pending guard forever, so receipt-only recovery
    // traffic could never re-stage it), then expired pending ACK
    // intents.
    sweep_expired_sends(candidate, now)?;
    prune_terminal_sends(candidate, now);
    sweep_expired_acks(candidate, now)?;
    // Reclaim eligible dedup records before the ratchet runs (review
    // D2b v12, Sol's P1-2), so a full-but-drainable set does not block
    // legitimate inbound traffic. The bounds step already refused the
    // full-and-nothing-eligible case; this is the drain that makes the
    // refusal temporary rather than permanent.
    reclaim_dedup(candidate, now);
    if candidate.state.dedup.len() >= MAX_DEDUP {
        return Err(LabError::Storage);
    }
    // Congestion sample for the control-debt arm (review D2b v6, codec
    // field 21), taken at accept ENTRY before the ratchet step: a
    // receipt that drains its own sender's budget inside THIS accept
    // must still arm the acceptor — a peer that always drains fully at
    // the accept would otherwise never counter-receipt and the
    // one-directional deadlock stands.
    let congested_at_entry = candidate
        .state
        .active_session
        .as_ref()
        .is_some_and(|active| {
            active.last_assigned_send_seq - active.peer_contiguous_high_water
                >= CONTROL_ONLY_THRESHOLD
        });
    // (d) Establish or advance the ratchet. The Olm message was decoded
    // and canonicality-checked by the caller before the transaction
    // opened (review D2b v10, Sol's P1-1), so no non-canonical encoding
    // can reach here.
    let plaintext = match ratchet_step(candidate, olm_message, now)? {
        RatchetStep::Plaintext(plaintext) => plaintext,
        RatchetStep::GapFailure => return Ok(AcceptArtifact::GapFailure),
    };

    // (e) Strict payload decode with conversation/epoch/message binding.
    let epoch_id = candidate
        .state
        .active_session
        .as_ref()
        .ok_or(LabError::MissingSession)?
        .epoch_id;
    let parsed = payload::decode_for(
        &plaintext,
        candidate.state.conversation_id,
        epoch_id,
        message_id,
    )?;

    // (f) Sender-sequence tracking against the contiguous high water and
    // the bounded out-of-order set.
    let send_seq = parsed.send_seq;
    if send_seq == 0 {
        return Err(LabError::InvalidPayload);
    }
    track_sender_sequence(
        candidate
            .state
            .active_session
            .as_mut()
            .ok_or(LabError::MissingSession)?,
        send_seq,
    )?;

    // (h) Record writes per payload kind.
    let context = EnvelopeContext {
        message_id,
        epoch_id,
        send_seq,
        queue_id,
        packet_digest: identity.packet_digest,
        expires_at,
        message_digest: identity.message_digest,
    };
    let outcome = match parsed.kind {
        payload::KIND_APPLICATION => {
            let body = parsed.body.ok_or(LabError::InvalidPayload)?;
            candidate.state.inbound.push(InboundRecord {
                message_id,
                epoch_id,
                sender_sequence: send_seq,
                queue_id,
                packet_digest: identity.packet_digest,
                expires_at,
                accepted_at: now,
                body,
            });
            candidate
                .state
                .inbound
                .sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));
            push_dedup(candidate, &context);
            AcceptOutcome::Application(message_id)
        }
        payload::KIND_RECEIPT => apply_receipt(
            candidate,
            &parsed.receipt.ok_or(LabError::InvalidPayload)?,
            &context,
        )?,
        _ => return Err(LabError::InvalidPayload),
    };

    // (i) Mode recompute from the FRESH high water BEFORE any staging
    // (review D2b v4 blocker 4): an applied receipt that drops
    // outstanding below the lock threshold makes a previously owed
    // receipt stageable in THIS pass; recomputing afterwards would skip
    // it with the stale mode. `RekeyRequired` dominance is preserved by
    // `recompute_mode`. The accept path is the only mutator that both
    // moves a high water and stages; every other stager recomputes from
    // values it just set itself.
    //
    // Control debt (review D2b v6/v7, codec field 21): the water arms on
    // EITHER congestion source — the local sample (acceptor's own
    // outstanding at accept ENTRY or END, arming to HCR) or the peer
    // signal (the just-accepted payload's `issuer_outstanding` at or
    // above the threshold, arming to THIS packet's sender sequence per
    // v10 / Sol's P1-2). See `accept_staging_tail`.
    accept_staging_tail(
        candidate,
        congested_at_entry,
        parsed.issuer_outstanding,
        send_seq,
        now,
    )?;
    Ok(AcceptArtifact::Outcome(outcome))
}

/// Step (i) of accept: recompute the budget mode from the FRESH high
/// water BEFORE any staging (review D2b v4 blocker 4): an applied receipt
/// that drops outstanding below the lock threshold makes a previously
/// owed receipt stageable in THIS pass; recomputing afterwards would
/// skip it with the stale mode. `RekeyRequired` dominance is preserved by
/// `recompute_mode`. The accept path is the only mutator that both moves
/// a high water and stages; every other stager recomputes from values it
/// just set itself.
///
/// Staging is unconditional over payload kinds (review D2b v5 debt
/// model): receipt debt comes only from CONSUMED application records
/// (codec field 20), never from receipts, so receipt-only exchanges have
/// no debt and stage nothing — quiescence by construction, with no
/// marker bookkeeping in this tail. A consumed-application debt that
/// predates an inbound receipt stages here with the freshly recomputed
/// mode (Sol's P1-4: a gap-filling receipt drains the water past the
/// debt in the same pass).
///
/// Control debt (review D2b v6-v9, codec field 21 — a high water, not a
/// flag, since v9): debt is armed FIRST in this tail — the LOCAL sample
/// (acceptor's own outstanding at or above the `ControlOnly` threshold
/// at accept ENTRY or END) and the PEER-SIGNALED sample (the
/// just-accepted payload's `issuer_outstanding` at or above the
/// threshold) are applied BEFORE the owed-staging attempt, so debt
/// armed by THIS accept flushes in the SAME pass (v8 P1-3b). Arming
/// RAISES the water via `max`; nothing on the wire ever lowers or clears
/// it (v9 finding 2: reordered truthful low signals cannot erase a later
/// arm, and no signal-freshness versioning is needed — the water is
/// monotone and resolution is a water-versus-water comparison).
/// Resolution happens only through confirmed delivery: debt stands while
/// `control_debt_up_to` exceeds the delivered marker (v9 finding 4: a
/// delayed `Stored` on an older receipt leaves newer debt standing).
///
/// The two arms raise the water to DIFFERENT values, and this is the
/// v10 correction (Sol's P1-2). The LOCAL arm answers our own
/// congestion, so the receipt we owe is one covering what we have
/// actually received contiguously: it raises to HCR. The PEER-SIGNALED
/// arm answers the PEER's congestion as of the sequence that carried the
/// signal, so it raises to that packet's `send_seq` — NOT to HCR. Under
/// reordering those differ: a truthful `issuer_outstanding >= 24` riding
/// sequence 25 that arrives while HCR is still 1 must record debt at 25,
/// because only a receipt covering 25 drains the peer. Arming to HCR
/// instead recorded a prematurely LOW water (1); a delayed older receipt
/// then advanced the delivered marker past it, the debt read as
/// resolved, and when the missing packets later drained HCR to 25 no
/// receipt was owed — leaving the peer permanently `ControlOnly` at 24
/// outstanding. The signaling sequence is either already contiguous or
/// sitting in the bounded out-of-order set (`track_sender_sequence` ran
/// first and rejected duplicates), so the debt water is always a
/// sequence we have genuinely received; `check_session_waters` permits
/// exactly that pair of positions.
///
/// The peer signal remains informational: a stale out-of-order payload
/// can over-arm, which costs at most one idempotent receipt (bounded by
/// the any-pending guard, v8 P1-4, and one-staged-per-pass) —
/// over-arming is harmless; under-arming is the dangerous direction and
/// is what P1-2 was. The LOCAL sample stays as the backstop for the
/// both-stuck corner (the peer locked with all its receipts expired
/// undelivered, so no signal is on the wire: the other side eventually
/// congests locally and raises its water at its next accept). The
/// freshness gate (`HCR > marker`) applies to both arms — if we already
/// reported everything, the peer's congestion is not ours to fix with
/// empty receipts.
fn accept_staging_tail(
    candidate: &mut Candidate,
    congested_at_entry: bool,
    issuer_outstanding: u64,
    signal_seq: u64,
    now: u64,
) -> Result<()> {
    {
        let active = candidate
            .state
            .active_session
            .as_mut()
            .ok_or(LabError::MissingSession)?;
        recompute_mode(active);
        // Arm FIRST (v8 P1-3b, v9 water model): the staging attempt
        // below sees the debt this accept raised, so newly armed debt
        // flushes in this same pass. Arming RAISES the control-debt
        // water via `max` — it is NEVER cleared or lowered by anything
        // on the wire (v9 finding 2: reordered truthful low signals
        // cannot erase a later arm; the water is monotone and
        // resolution is a water-versus-water comparison, not a recency
        // contest).
        //
        // The peer-signaled arm binds to the SIGNALING PACKET's sequence
        // (v10, Sol's P1-2): under reordering, HCR can lag far behind
        // the sequence that carried a truthful congestion report, and
        // arming to the lagging HCR loses the signal permanently once a
        // delayed older receipt advances the marker past it.
        //
        // OPEN, and deliberately so as of v13 (Sol's v12 P1-1). This arm
        // is UNBOUNDED over a session's lifetime: the
        // `any_receipt_pending` guard below bounds only CONCURRENT
        // responses, so a peer streaming high signals extracts roughly
        // one receipt per delivery cycle, and because receipts share the
        // application send counter that walks our own outstanding toward
        // `ReceiptLocked`.
        //
        // The v12 reciprocity gate that tried to bound it — answer a
        // signal only once `peer_contiguous_high_water` covers our last
        // answer — was REVERTED here: it deadlocks an honest peer. An
        // UNCONGESTED peer has no reason to counter-receipt, and
        // receipt-only acceptance creates no receipt debt by design (the
        // v5 quiescence property), so the gate can latch shut forever
        // against a peer that has done nothing wrong. Gating on our OWN
        // congestion instead does not work either: above the threshold
        // the ungated LOCAL arm takes over and continues the escalation.
        //
        // Bounding this needs a §4 decision about whether control
        // receipts may share the application send budget, not another
        // local guard. See the v13 note in
        // `reviews/PROMPT-independent-phase2-facade-d2b.md`.
        let peer_signal = issuer_outstanding >= CONTROL_ONLY_THRESHOLD;
        if peer_signal {
            active.control_debt_up_to = active.control_debt_up_to.max(signal_seq);
        }
        // The local arm answers OUR congestion, so it owes a receipt for
        // what we have contiguously received: HCR is the right water. It
        // is deliberately NOT reciprocity-gated — it is the both-stuck
        // backstop, and it cannot be driven by the peer.
        if congested_at_entry
            || active.last_assigned_send_seq - active.peer_contiguous_high_water
                >= CONTROL_ONLY_THRESHOLD
        {
            active.control_debt_up_to = active
                .control_debt_up_to
                .max(active.highest_contiguous_received_seq);
        }
    }
    maybe_stage_owed_receipt(candidate, now)?;
    let active = candidate
        .state
        .active_session
        .as_mut()
        .ok_or(LabError::MissingSession)?;
    recompute_mode(active);
    Ok(())
}

/// Step (f) of accept: advance the contiguous high water, draining the
/// out-of-order set, or record a gap element; duplicates reject.
fn track_sender_sequence(active: &mut ActiveSession, send_seq: u64) -> Result<()> {
    if send_seq <= active.highest_contiguous_received_seq
        || active.received_above_high_water.contains(&send_seq)
    {
        return Err(LabError::DuplicateMessage);
    }
    if send_seq == active.highest_contiguous_received_seq + 1 {
        active.highest_contiguous_received_seq = send_seq;
        while let Some(position) = active
            .received_above_high_water
            .iter()
            .position(|seq| *seq == active.highest_contiguous_received_seq + 1)
        {
            active.received_above_high_water.remove(position);
            active.highest_contiguous_received_seq += 1;
        }
    } else {
        if active.received_above_high_water.len() >= MAX_RECEIVED_SET {
            return Err(LabError::Storage);
        }
        active.received_above_high_water.push(send_seq);
        active.received_above_high_water.sort_unstable();
    }
    Ok(())
}

/// Whether a dedup record may be reclaimed (review D2b v12, Sol's P1-2).
///
/// The frozen rule (`docs/persistence-spike-design.md`, "Bounded
/// capacity and backpressure"): a record with no pending body/ACK
/// reference becomes eligible by exactly one of two paths — (a) at least
/// seven days after the observed `Deleted`/`AlreadyDeleted`, which is
/// what `DedupState::Acked` records, and after message expiry; or (b)
/// when the ACK became terminal solely because message retention
/// expired, which is what `DedupState::Expired` records, at least seven
/// days after that signed expiry. Both reduce to the same test because
/// the state itself records which path was taken. `Accepted` is never
/// reclaimable — that envelope is still live.
///
/// Why reclaiming does not weaken replay protection: the only party who
/// can re-present a reclaimed packet is one holding our mailbox SEND
/// capability, because the outer envelope must carry a fresh valid
/// signature over `(queue, message_id, packet_digest, expires_at)`. That
/// party is the peer, and per §4 a peer-authenticated gap failure is
/// designed behaviour — it can already drive the session to
/// `RekeyRequired` at will with a fresh message past the chain gap,
/// without any replay. So reclamation grants no capability the peer
/// lacks. A relay, which holds no send capability, cannot re-present
/// anything.
fn dedup_reclaimable(
    inbound: &[InboundRecord],
    acks: &[AckIntent],
    record: &DedupRecord,
    now: u64,
) -> bool {
    record.state != DedupState::Accepted
        && record.expires_at.saturating_add(TOMBSTONE_TTL_SECONDS) <= now
        && !inbound
            .iter()
            .any(|pending| pending.message_id == record.message_id)
        && !acks.iter().any(|ack| ack.message_id == record.message_id)
}

/// How many dedup records are reclaimable right now, without mutating.
/// Used by the pre-decrypt bounds check, which runs on the authoritative
/// state before any candidate exists.
fn reclaimable_dedup_count(state: &ClientStateV1, now: u64) -> usize {
    state
        .dedup
        .iter()
        .filter(|record| dedup_reclaimable(&state.inbound, &state.acks, record, now))
        .count()
}

/// Drop every reclaimable dedup record, freeing capacity for new inbound
/// work. `retain` preserves order, so the sorted-by-message-ID invariant
/// survives.
fn reclaim_dedup(candidate: &mut Candidate, now: u64) {
    let state = &mut candidate.state;
    let inbound = &state.inbound;
    let acks = &state.acks;
    state
        .dedup
        .retain(|record| !dedup_reclaimable(inbound, acks, record, now));
}

/// Insert a dedup record (`Accepted`), keeping the array sorted.
fn push_dedup(candidate: &mut Candidate, context: &EnvelopeContext) {
    candidate.state.dedup.push(DedupRecord {
        message_id: context.message_id,
        epoch_id: context.epoch_id,
        sequence: context.send_seq,
        queue_id: context.queue_id,
        packet_digest: context.packet_digest,
        expires_at: context.expires_at,
        state: DedupState::Accepted,
        message_digest: context.message_digest,
    });
    candidate
        .state
        .dedup
        .sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));
}

/// Step 4 of `consume_inbound`: remove the inbound record, create the
/// ACK intent, and stage the coalesced receipt when the mode allows.
fn consume_inbound_operation(
    candidate: &mut Candidate,
    message_id: MessageId,
    valid_until: u64,
    now: u64,
) -> Result<()> {
    sweep_expired_sends(candidate, now)?;
    prune_terminal_sends(candidate, now);
    sweep_expired_acks(candidate, now)?;
    // After the sweep the ACK bound must still have room: the intent is
    // the point of the consume, so a full bound is a clear pre-mutation
    // error (the candidate is discarded, nothing installs).
    if candidate.state.acks.len() >= MAX_ACKS {
        return Err(LabError::Storage);
    }
    let index = candidate
        .state
        .inbound
        .iter()
        .position(|record| record.message_id == message_id)
        .ok_or(LabError::MessageNotFound)?;
    let record = candidate.state.inbound.remove(index);
    // Receipt debt (codec field 20, review D2b v5): the highest CONSUMED
    // application sequence. Debt is created only here — receipts and
    // other control payloads are never consumed application records, so
    // receipt-only exchanges never create debt (quiescence by
    // construction). The consumed record's sequence is already covered
    // by the contiguous water or the out-of-order set (codec
    // `check_inbound`), so the debt stays codec-valid.
    {
        let active = candidate
            .state
            .active_session
            .as_mut()
            .ok_or(LabError::MissingSession)?;
        active.receipt_debt_up_to = active.receipt_debt_up_to.max(record.sender_sequence);
    }
    candidate.state.acks.push(AckIntent {
        message_id,
        epoch_id: record.epoch_id,
        sequence: record.sender_sequence,
        queue_id: record.queue_id,
        packet_digest: record.packet_digest,
        valid_until,
        state: AckState::Pending,
    });
    candidate
        .state
        .acks
        .sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));

    // Owed-receipt staging (review D2b v5): a receipt is owed while the
    // consumed-application debt AND the contiguous received high water
    // both exceed the delivered marker and no `Pending` receipt for the
    // current water is in flight; it stages here when the mode allows
    // control traffic and the send array has capacity, and stays owed
    // otherwise (a skipped receipt is never lost). See
    // `maybe_stage_owed_receipt`.
    maybe_stage_owed_receipt(candidate, now)?;
    let active = candidate
        .state
        .active_session
        .as_mut()
        .ok_or(LabError::MissingSession)?;
    recompute_mode(active);
    Ok(())
}

/// Stage one receipt send (a control advance on the shared send
/// counter): a `HighWaterReceipt` signed with our account Ed25519
/// identity, encrypted as a `Receipt` payload, signed for the peer's
/// mailbox like any other send.
fn stage_receipt(candidate: &mut Candidate, high_water: u64, now: u64) -> Result<()> {
    // Receipt envelopes carry the 7-day message TTL, identical to
    // `stage_send`'s expiry rule (review D2b v4: the 300 s request
    // window wedged receipts that outlived it unstored).
    let expires_at = now.saturating_add(MAX_MESSAGE_TTL_SECONDS);
    let (epoch_id, send_seq, peer_curve, conversation_id, issuer_outstanding) = {
        let active = candidate
            .state
            .active_session
            .as_ref()
            .ok_or(LabError::MissingSession)?;
        let peer_curve = match active.role {
            // The acknowledged sender is the peer: the session initiator's
            // identity for an inbound session, the transcript's identity
            // for an outbound one.
            Role::Inbound => active.identity_key,
            Role::Outbound => active.transcript.curve_identity,
        };
        let send_seq = active
            .last_assigned_send_seq
            .checked_add(1)
            .ok_or(LabError::Storage)?;
        (
            active.epoch_id,
            send_seq,
            peer_curve,
            candidate.state.conversation_id,
            // §4 control-lane split: `issuer_outstanding` now means the
            // issuer's APPLICATION outstanding. A receipt payload
            // carries the UNCHANGED current value — a control send costs
            // no application capacity, so there is nothing to advance
            // past.
            application_outstanding(active) as u64,
        )
    };
    let mut receipt = HighWaterReceipt {
        conversation_id,
        epoch_id,
        acknowledged_sender_curve: peer_curve,
        issuer_curve: candidate.account.curve25519_key(),
        high_water,
        signature: candidate.account.sign(b""),
    };
    receipt.signature = candidate.account.sign(receipt_signing_bytes(&receipt));
    let outgoing = payload::ClientPayloadV2 {
        version: payload::PAYLOAD_VERSION,
        conversation_id,
        message_id: MessageId::random(),
        epoch_id,
        send_seq,
        sent_at: now,
        kind: payload::KIND_RECEIPT,
        body: None,
        receipt: Some(payload::ReceiptV2::from(&receipt)),
        issuer_outstanding,
    };
    let message_id = outgoing.message_id;
    let encoded = payload::encode(&outgoing)?;
    let session = candidate.session.as_mut().ok_or(LabError::MissingSession)?;
    let message = session
        .encrypt(&encoded[..])
        .map_err(|_| LabError::Crypto)?;
    let packet = EncryptedPacket::from_untrusted(
        serde_json::to_vec(&message).map_err(|_| LabError::Encoding)?,
    );
    if packet.as_bytes().len() > MAX_PACKET {
        return Err(LabError::Encoding);
    }
    let binding = candidate
        .state
        .peer_binding
        .as_ref()
        .ok_or(LabError::MissingSession)?;
    let keypair = parse_capability_keypair(&binding.send_keypair_json)?;
    let queue_id = binding.queue_id;
    let signature = keypair.sign(&send_signing_bytes(
        queue_id,
        message_id,
        &packet.digest(),
        expires_at,
    ));
    candidate.state.sends.push(SendRecord {
        message_id,
        state: SendState::Pending,
        epoch_id,
        sequence: send_seq,
        queue_id: Some(queue_id),
        packet: Some(packet),
        expires_at,
        send_signature: Some(signature),
        packet_digest: None,
        kind: SendKind::Receipt,
        receipt_high_water: Some(high_water),
    });
    candidate
        .state
        .sends
        .sort_by(|a, b| a.message_id.as_bytes().cmp(b.message_id.as_bytes()));
    let active = candidate
        .state
        .active_session
        .as_mut()
        .ok_or(LabError::MissingSession)?;
    active.last_assigned_send_seq = send_seq;
    // §4 control-lane split: arm the durable one-per-second control
    // cooldown. This is a LOCAL refillable rate bound — never a per-epoch
    // cap, and never conditioned on the peer acknowledging this receipt.
    active.control_send_not_before = now.checked_add(1).ok_or(LabError::Storage)?;
    // The delivered-marker deliberately does NOT move at staging (v4):
    // it advances only when the receipt reaches a delivered terminal
    // state in record_send_result.
    Ok(())
}

/// Stage the owed receipt, if any; returns true when one staged (review
/// D2b v5 debt model, v6 control arm, v9 water model).
///
/// A receipt is owed ⇔ the freshness gate
/// (`highest_contiguous_received_seq > last_delivered_receipt_high_water`
/// — there is a NEW contiguous water worth reporting; a receipt carrying
/// nothing new is pointless traffic) AND EITHER debt arm fires, each
/// with its OWN in-flight guard (review D2b v8 P1-4 asymmetry):
///
/// - **Application debt** (v5, honest path): `receipt_debt_up_to >
///   marker` AND no `Pending` receipt with `receipt_high_water` equal to
///   the CURRENT high water in flight. A delivered receipt reports the
///   contiguous water (never the debt), so it covers exactly the debt at
///   or below that water; debt ABOVE the water (an out-of-order
///   consumption) stays owed until the water drains past it. Debt comes
///   only from `consume_inbound` (codec field 20), so receipt-only
///   exchanges never create it (quiescence by construction).
/// - **Control debt** (v6-v9, codec field 21 — a high water since v9):
///   `control_debt_up_to > marker` AND NO receipt-kind send record
///   `Pending` AT ALL (any high water). The peer-signaled arm answers
///   REPORTED congestion, which a malicious peer can fabricate
///   continuously (each signaling packet occupies a sender sequence, so
///   a per-current-water guard passes every time — Sol's 33-packet
///   probe); the any-pending guard bounds the response to ≈ one victim
///   receipt per delivery-or-expiry cycle regardless of attack rate.
///   The water is monotone: arming raises it to the current HCR and
///   nothing on the wire ever lowers it (v9 finding 2); resolution is
///   implicit — debt stands only while it exceeds the delivered marker,
///   so a delayed `Stored` on an older receipt leaves newer debt
///   standing (v9 finding 4) and a delivery at or above the water
///   resolves it.
///
/// It stages at most one receipt per mutator pass; otherwise the debt
/// stays owed and the next clock-taking mutator retries, so a skipped or
/// lost receipt is never silently satisfied.
///
/// **§4 control-lane split — the control bound.** Control is bounded
/// independently of the application budget, by four LOCAL rules: at most
/// one UNRESOLVED receipt send (`Pending` or `DeliveryUnknown`), at most
/// `MAX_CONTROL_SENDS` durable receipt-kind records, at most one new
/// receipt per session per second (`control_send_not_before`), and
/// water-coalesced debt so one later receipt reports the freshest
/// contiguous water.
///
/// This is a refillable rate bound, not a per-epoch cap, and — critically
/// — control eligibility NEVER depends on the peer acknowledging an
/// earlier control response. That conditioning is what deadlocked an
/// honest peer in v12: an uncongested peer has no reason to
/// counter-receipt, and receipt-only acceptance creates no debt by
/// design. Here, after `Stored`/`Duplicate` later coalesced debt becomes
/// eligible when the local cooldown expires, and `DeliveryUnknown`
/// becomes eligible after local consumption or expiry — so an honest
/// peer eventually gets a fresh congestion response with no
/// receipt-of-receipt, while quiescent receipt-only traffic stays
/// quiescent.
///
/// A gated receipt must never block an otherwise admissible application
/// send; only `RekeyRequired` blocks new control encryption.
fn maybe_stage_owed_receipt(candidate: &mut Candidate, now: u64) -> Result<bool> {
    let Some(active) = candidate.state.active_session.as_ref() else {
        return Ok(false);
    };
    let high_water = active.highest_contiguous_received_seq;
    let marker = active.last_delivered_receipt_high_water;
    let fresh = high_water > marker;
    // Only `RekeyRequired` blocks new control encryption; `ControlOnly`
    // is an APPLICATION restriction and must never gate control.
    let mode_allows = active.mode != SessionMode::RekeyRequired;
    // The one-per-second local cooldown (field 23).
    let cooldown_open = now >= active.control_send_not_before;
    let hcr_receipt_pending = candidate.state.sends.iter().any(|record| {
        record.state == SendState::Pending
            && record.kind == SendKind::Receipt
            && record.receipt_high_water == Some(high_water)
    });
    // At most ONE unresolved control send, where unresolved means
    // `Pending` OR `DeliveryUnknown`.
    let any_receipt_unresolved = candidate.state.sends.iter().any(|record| {
        record.kind == SendKind::Receipt
            && matches!(
                record.state,
                SendState::Pending | SendState::DeliveryUnknown
            )
    });
    let debt_owed = active.receipt_debt_up_to > marker && !hcr_receipt_pending;
    let control_owed = active.control_debt_up_to > marker;
    if !(debt_owed || control_owed) || !fresh || !mode_allows {
        return Ok(false);
    }
    if any_receipt_unresolved || !cooldown_open {
        // Gated, not discarded: the debt water stays durable and the
        // next clock-taking mutator retries at the cooldown boundary or
        // once the unresolved send resolves.
        return Ok(false);
    }
    if !ensure_control_slot(candidate) {
        return Ok(false);
    }
    stage_receipt(candidate, high_water, now)?;
    Ok(true)
}

/// Make room for one more control record within `MAX_CONTROL_SENDS`.
///
/// §4 control-lane split: `Pending` and `DeliveryUnknown` control records
/// are NEVER evicted — their terminal effect has not yet been folded into
/// `ActiveSession`. Terminal control records (`Stored`/`Duplicate`/
/// `Expired`) may be recycled oldest `(expires_at, message_id)` first.
/// Returns whether a slot is available afterwards.
fn ensure_control_slot(candidate: &mut Candidate) -> bool {
    let control_count = candidate
        .state
        .sends
        .iter()
        .filter(|record| record.kind == SendKind::Receipt)
        .count();
    if control_count < MAX_CONTROL_SENDS {
        return true;
    }
    let victim = candidate
        .state
        .sends
        .iter()
        .filter(|record| {
            record.kind == SendKind::Receipt
                && matches!(
                    record.state,
                    SendState::Stored | SendState::Duplicate | SendState::Expired
                )
        })
        .min_by_key(|record| (record.expires_at, *record.message_id.as_bytes()))
        .map(|record| record.message_id);
    let Some(victim) = victim else {
        return false;
    };
    candidate
        .state
        .sends
        .retain(|record| record.message_id != victim);
    true
}

/// D2a carry-over: prune terminal send records (`Stored`/`Duplicate`/
/// `Expired`) whose tombstone window (`expires_at` + the relay's
/// tombstone TTL, mirrored) has passed. `Pending`/`DeliveryUnknown` are
/// never pruned this way. Pruning frees bounded slots only; it never
/// touches the high-water or budget invariants.
fn prune_terminal_sends(candidate: &mut Candidate, now: u64) {
    candidate.state.sends.retain(|record| {
        !(matches!(
            record.state,
            SendState::Stored | SendState::Duplicate | SendState::Expired
        ) && record.expires_at.saturating_add(TOMBSTONE_TTL_SECONDS) <= now)
    });
}
