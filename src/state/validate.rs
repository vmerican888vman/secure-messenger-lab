//! Semantic validation for `ClientStateV1` (design section 3's long
//! paragraph plus the section 4 high-water invariants). Runs after
//! structural decoding and before any caller sees the state; `encode`
//! re-runs it so an invalid in-memory state can never be serialized.
//!
//! Signature byte constructions replicated here (the originals are private
//! to `src/client.rs` / `src/capability.rs`; the canonical length-prefixed
//! framer `capability::canonical` is shared):
//!
//! - peer bundle: action `peer-prekey`, parts signing identity, curve
//!   identity, one-time key, `valid_until` — identical to
//!   `peer_prekey_signing_bytes` in `src/client.rs`.
//! - send request: action `send`, parts queue, message ID, packet digest,
//!   `expires_at` — identical to `send_signing_bytes` in
//!   `src/capability.rs`.
//! - high-water receipt: action `session-high-water/v1`, parts version
//!   byte, conversation ID, epoch ID, acknowledged sender curve, issuer
//!   curve, high water. Section 4 fixes the domain and the carried fields;
//!   the part order within the canonical frame is this slice's choice
//!   (no prior construction exists to replicate).
//!
//! No wall-clock `now` is available to a pure codec, so expiry checks are
//! limited to internal consistency (`created_at < valid_until`,
//! `expires_at > accepted_at`, receipt regression rules). Freshness at
//! load is a façade/platform concern and is documented as a gap.
//!
//! The active-session transcript is role-aware (remediation decision after
//! independent review): for an outbound session it is the verified peer
//! bundle, for an inbound session it is our own consumed prekey bundle.
//! See the `ActiveSession` docs in `records.rs` and `check_active_session`
//! below. A peer binding is mandatory whenever an active session is
//! present; receipts are always verified against the peer binding's pinned
//! identity, never the transcript's.

use std::collections::BTreeMap;

use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};
use vodozemac::{
    Curve25519PublicKey, Curve25519SecretKey, Ed25519Keypair, Ed25519PublicKey, Ed25519Signature,
    KeyId,
};
use zeroize::Zeroizing;

use super::records::{
    ActiveSession, HighWaterReceipt, PeerBundle, RECEIPT_VERSION, Role, SessionMode,
};
use super::tlv::canonical_json;
use super::{
    ClientStateV1, MAX_ACCOUNT_PICKLE, MAX_ACKS, MAX_BODY, MAX_DEDUP, MAX_INBOUND,
    MAX_KEYPAIR_JSON, MAX_PACKET, MAX_RECEIVED_SET, MAX_SENDS, MAX_SESSION_PICKLE,
};
use crate::capability::{canonical, digest};
use crate::ids::{MessageId, QueueId};
use crate::{LabError, MailboxRegistration, Result};

const PREKEY_ACTION: &[u8] = b"peer-prekey";
const SEND_ACTION: &[u8] = b"send";
const RECEIPT_ACTION: &[u8] = b"session-high-water/v1";

/// Section 4 budget: 24 application advances, 8 reserved control
/// advances, 32 absolute maximum; more is malformed and rejected on load.
const MAX_OUTSTANDING: u64 = 32;
const CONTROL_ONLY_THRESHOLD: u64 = 24;

/// Canonical length-prefixed signing bytes for a peer bundle; identical
/// construction to `peer_prekey_signing_bytes` in `src/client.rs`.
pub(super) fn prekey_signing_bytes(bundle: &PeerBundle) -> Vec<u8> {
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

pub(super) fn send_signing_bytes(
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

pub(super) fn receipt_signing_bytes(receipt: &HighWaterReceipt) -> Vec<u8> {
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

fn verify(key: Ed25519PublicKey, message: &[u8], signature: &Ed25519Signature) -> Result<()> {
    key.verify(message, signature)
        .map_err(|_| LabError::Storage)
}

pub(super) fn validate(state: &ClientStateV1) -> Result<()> {
    check_structure(state)?;
    let account = check_account(state)?;
    check_mailbox(state)?;
    check_registration(state)?;
    check_pending_prekey(state, &account)?;
    check_peer_binding(state)?;
    check_records(state, &account)?;
    Ok(())
}

/// Re-check the structural invariants on the encode path: array bounds
/// and ordering, send-record arm consistency, and every variable-length
/// bound. (The decode path enforces these during parsing.)
fn check_structure(state: &ClientStateV1) -> Result<()> {
    check_sorted(&state.inbound, MAX_INBOUND, |record| record.message_id)?;
    check_sorted(&state.sends, MAX_SENDS, |record| record.message_id)?;
    check_sorted(&state.acks, MAX_ACKS, |record| record.message_id)?;
    check_sorted(&state.dedup, MAX_DEDUP, |record| record.message_id)?;
    for send in &state.sends {
        if !send.arms_consistent() {
            return Err(LabError::Storage);
        }
        if let Some(packet) = &send.packet {
            let length = packet.as_bytes().len();
            if length == 0 || length > MAX_PACKET {
                return Err(LabError::Storage);
            }
        }
    }
    for record in &state.inbound {
        if record.body.len() > MAX_BODY {
            return Err(LabError::Storage);
        }
    }
    if state.account_pickle.len() > MAX_ACCOUNT_PICKLE {
        return Err(LabError::Storage);
    }
    for json in [
        &state.send_keypair_json,
        &state.receive_keypair_json,
        &state.manage_keypair_json,
    ] {
        if json.len() > MAX_KEYPAIR_JSON {
            return Err(LabError::Storage);
        }
    }
    if let Some(binding) = &state.peer_binding {
        if binding.send_keypair_json.len() > MAX_KEYPAIR_JSON {
            return Err(LabError::Storage);
        }
    }
    if let Some(active) = &state.active_session {
        if active.session_pickle.len() > MAX_SESSION_PICKLE {
            return Err(LabError::Storage);
        }
        let received = &active.received_above_high_water;
        if received.len() > MAX_RECEIVED_SET {
            return Err(LabError::Storage);
        }
        for pair in received.windows(2) {
            if pair[0] >= pair[1] {
                return Err(LabError::Storage);
            }
        }
    }
    Ok(())
}

fn check_sorted<T>(items: &[T], bound: usize, id_of: impl Fn(&T) -> MessageId) -> Result<()> {
    if items.len() > bound {
        return Err(LabError::Storage);
    }
    for pair in items.windows(2) {
        if id_of(&pair[0]).as_bytes() >= id_of(&pair[1]).as_bytes() {
            return Err(LabError::Storage);
        }
    }
    Ok(())
}

/// Canonical `Account` pickle, re-pickle byte equality, the stored own
/// public identity against the reconstructed account, and the one-time-key
/// store consistency (review v3 finding 3).
fn check_account(state: &ClientStateV1) -> Result<Account> {
    let pickle: AccountPickle = canonical_json(&state.account_pickle, MAX_ACCOUNT_PICKLE)?;
    let account = Account::from_pickle(pickle);
    let reencoded =
        Zeroizing::new(serde_json::to_vec(&account.pickle()).map_err(|_| LabError::Storage)?);
    if reencoded[..] != state.account_pickle[..] {
        return Err(LabError::Storage);
    }
    if account.ed25519_key() != state.own_ed25519_identity
        || account.curve25519_key() != state.own_curve_identity
    {
        return Err(LabError::Storage);
    }
    check_one_time_key_consistency(&state.account_pickle)?;
    Ok(account)
}

/// Wrap headroom for `next_key_id` (see `check_one_time_key_consistency`).
const NEXT_KEY_ID_HEADROOM: u64 = 1_000_000_000;

/// One-time-key store consistency, checked against the already-canonical
/// account pickle bytes (review v3 finding 3; vodozemac's pickle field
/// types are private, so the JSON is navigated directly):
///
/// - the public keys derived from all `private_keys` entries must be
///   unique — a duplicated secret would silently collapse the
///   `key_ids_by_key` index;
/// - every `public_keys` (unpublished) entry's key id must exist in
///   `private_keys` and its stored public key must equal the derived
///   public for that id. The reverse need not hold: published keys are
///   absent from the unpublished map by design;
/// - `next_key_id` must be strictly greater than every retained key id in
///   `private_keys` ∪ `public_keys` (review v4: a counter at or below a
///   retained id makes the next generation select the occupied id and
///   silently replace its secret). Gaps are legitimate (consumption and
///   eviction leave them), so larger values are never rejected; an empty
///   store accepts any `next_key_id`;
/// - `next_key_id` must also leave wrap headroom (review v5): vodozemac
///   generates with `wrapping_add`, so a counter near `u64::MAX` wraps to
///   small ids and can replace retained key 0. The rule rejects counters
///   above `u64::MAX - NEXT_KEY_ID_HEADROOM`. The headroom is arbitrary
///   but safe: one billion generations vastly exceeds anything a
///   peer-scoped account can legitimately produce (each conversation
///   consumes a handful of one-time keys), so a counter that close to the
///   wrap is hostile, never real.
fn check_one_time_key_consistency(canonical_pickle: &[u8]) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(canonical_pickle).map_err(|_| LabError::Storage)?;
    let one_time_keys = value.get("one_time_keys").ok_or(LabError::Storage)?;
    let private_keys: BTreeMap<KeyId, Curve25519SecretKey> = serde_json::from_value(
        one_time_keys
            .get("private_keys")
            .ok_or(LabError::Storage)?
            .clone(),
    )
    .map_err(|_| LabError::Storage)?;
    let unpublished: BTreeMap<KeyId, Curve25519PublicKey> = serde_json::from_value(
        one_time_keys
            .get("public_keys")
            .ok_or(LabError::Storage)?
            .clone(),
    )
    .map_err(|_| LabError::Storage)?;

    let mut derived_publics: Vec<Curve25519PublicKey> = Vec::with_capacity(private_keys.len());
    for secret in private_keys.values() {
        let public = Curve25519PublicKey::from(secret);
        if derived_publics.contains(&public) {
            return Err(LabError::Storage);
        }
        derived_publics.push(public);
    }
    for (key_id, stored_public) in &unpublished {
        let secret = private_keys.get(key_id).ok_or(LabError::Storage)?;
        if &Curve25519PublicKey::from(secret) != stored_public {
            return Err(LabError::Storage);
        }
    }

    // The counter must sit strictly above every retained key id. The map
    // keys are decimal strings (`KeyId` serializes as its inner `u64`).
    let next_key_id = one_time_keys
        .get("next_key_id")
        .and_then(serde_json::Value::as_u64)
        .ok_or(LabError::Storage)?;
    if next_key_id > u64::MAX - NEXT_KEY_ID_HEADROOM {
        return Err(LabError::Storage);
    }
    for map_name in ["private_keys", "public_keys"] {
        let entries = one_time_keys
            .get(map_name)
            .and_then(serde_json::Value::as_object)
            .ok_or(LabError::Storage)?;
        for key in entries.keys() {
            let id = key.parse::<u64>().map_err(|_| LabError::Storage)?;
            if id >= next_key_id {
                return Err(LabError::Storage);
            }
        }
    }
    Ok(())
}

/// The three reconstructed capability public keys must match the
/// registration intent, the mailbox queue must be the registered one, and
/// the three capability public keys must be DISTINCT from each other
/// (review v5 finding 3: a collapsed mailbox where one keypair serves
/// send, receive and manage destroys the capability separation the
/// mailbox design exists for). Each mailbox key must also differ from the
/// long-term `own_ed25519_identity` (review v6 blocker 1): the send key is
/// transferable to the peer, and none of the mailbox capabilities may
/// alias the pinned identity.
fn check_mailbox(state: &ClientStateV1) -> Result<()> {
    let send = keypair(&state.send_keypair_json)?;
    let receive = keypair(&state.receive_keypair_json)?;
    let manage = keypair(&state.manage_keypair_json)?;
    if send.public_key() != state.registration.send_key
        || receive.public_key() != state.registration.receive_key
        || manage.public_key() != state.registration.manage_key
    {
        return Err(LabError::Storage);
    }
    let mailbox_keys = [
        state.registration.send_key,
        state.registration.receive_key,
        state.registration.manage_key,
    ];
    for key in &mailbox_keys {
        if *key == state.own_ed25519_identity {
            return Err(LabError::Storage);
        }
    }
    if mailbox_keys[0] == mailbox_keys[1]
        || mailbox_keys[0] == mailbox_keys[2]
        || mailbox_keys[1] == mailbox_keys[2]
    {
        return Err(LabError::Storage);
    }
    if state.mailbox_queue_id != state.registration.queue_id {
        return Err(LabError::Storage);
    }
    Ok(())
}

fn keypair(json: &Zeroizing<Vec<u8>>) -> Result<Ed25519Keypair> {
    canonical_json(json, MAX_KEYPAIR_JSON)
}

/// The registration management signature must verify over the exact
/// intent and current request (queue, keys, nonce, expiry).
fn check_registration(state: &ClientStateV1) -> Result<()> {
    let record = &state.registration;
    let registration = MailboxRegistration {
        queue_id: record.queue_id,
        send_key: record.send_key,
        receive_key: record.receive_key,
        manage_key: record.manage_key,
        nonce: record.nonce,
        valid_until: record.valid_until,
        signature: record.signature,
    };
    verify(
        record.manage_key,
        &registration.signing_bytes(),
        &record.signature,
    )
}

/// Pending prekey: identities must be the account's own, the signature
/// must verify, and the exact PUBLISHED one-time key's private part must
/// still exist in the account. "Published" (review v2 remediation) means
/// both: held in the OTK store (pinned `Account::contains_one_time_key`,
/// which deliberately also finds unpublished keys) AND absent from
/// `Account::one_time_keys()` (the unpublished set), proving the key was
/// marked published and is still held.
fn check_pending_prekey(state: &ClientStateV1, account: &Account) -> Result<()> {
    let Some(prekey) = &state.pending_prekey else {
        return Ok(());
    };
    if prekey.signing_identity != account.ed25519_key()
        || prekey.curve_identity != account.curve25519_key()
    {
        return Err(LabError::Storage);
    }
    if prekey.created_at >= prekey.valid_until {
        return Err(LabError::Storage);
    }
    verify(
        prekey.signing_identity,
        &prekey_signing_bytes(&prekey.bundle()),
        &prekey.signature,
    )?;
    if !account.contains_one_time_key(prekey.one_time_key) {
        return Err(LabError::Storage);
    }
    if account
        .one_time_keys()
        .values()
        .any(|key| *key == prekey.one_time_key)
    {
        return Err(LabError::Storage);
    }
    Ok(())
}

/// Peer binding: the stored send public key must be the reconstructed
/// keypair's public key, and the bundle signature must verify under the
/// bundle's pinned signing identity. The relationship between the binding
/// and an active session is role-dependent and checked in
/// `check_active_session`.
fn check_peer_binding(state: &ClientStateV1) -> Result<()> {
    let Some(binding) = &state.peer_binding else {
        return Ok(());
    };
    let keypair = keypair(&binding.send_keypair_json)?;
    if keypair.public_key() != binding.send_public_key {
        return Err(LabError::Storage);
    }
    // The send capability must not alias the peer's pinned signing
    // identity (review v6 blocker 1): the capability is transferable, the
    // identity is not.
    if binding.send_public_key == binding.bundle.signing_identity {
        return Err(LabError::Storage);
    }
    verify(
        binding.bundle.signing_identity,
        &prekey_signing_bytes(&binding.bundle),
        &binding.bundle.signature,
    )?;
    Ok(())
}

/// Session presence/absence rules and all record cross-checks.
fn check_records(state: &ClientStateV1, account: &Account) -> Result<()> {
    let Some(active) = &state.active_session else {
        // Session absence requires all session-dependent records absent.
        // Dedup records are not session-dependent: section 4 retains them
        // through their safety window across rekey, including while no
        // session is installed. With no active session there is no current
        // epoch, so every dedup record is retired-exempt (review v3
        // finding 1).
        if !state.inbound.is_empty() || !state.sends.is_empty() || !state.acks.is_empty() {
            return Err(LabError::Storage);
        }
        check_dedup(state, None)?;
        return Ok(());
    };
    let session = restore_session(active)?;
    check_active_session(state, account, active, &session)?;
    check_inbound(state, active)?;
    check_sends(state, active)?;
    check_acks(state, active)?;
    check_dedup(state, Some((active, &session)))?;
    Ok(())
}

/// Restore the session from its canonical pickle and require the
/// re-pickle to be byte-identical.
fn restore_session(active: &ActiveSession) -> Result<Session> {
    let pickle: SessionPickle = canonical_json(&active.session_pickle, MAX_SESSION_PICKLE)?;
    let session = Session::from_pickle(pickle);
    let reencoded =
        Zeroizing::new(serde_json::to_vec(&session.pickle()).map_err(|_| LabError::Storage)?);
    if reencoded[..] != active.session_pickle[..] {
        return Err(LabError::Storage);
    }
    Ok(session)
}

fn check_active_session(
    state: &ClientStateV1,
    account: &Account,
    active: &ActiveSession,
    session: &Session,
) -> Result<()> {
    if session.session_config().version() != super::SESSION_CONFIG_VERSION {
        return Err(LabError::Storage);
    }

    // `session_keys()` must equal the stored establishment keys, and the
    // epoch ID is `SHA-256(identity_key || base_key || one_time_key)`.
    let keys = session.session_keys();
    if keys.identity_key != active.identity_key
        || keys.base_key != active.base_key
        || keys.one_time_key != active.one_time_key
    {
        return Err(LabError::Storage);
    }
    let mut epoch_preimage = Vec::with_capacity(96);
    epoch_preimage.extend_from_slice(keys.identity_key.as_bytes());
    epoch_preimage.extend_from_slice(keys.base_key.as_bytes());
    epoch_preimage.extend_from_slice(keys.one_time_key.as_bytes());
    if digest(&epoch_preimage) != active.epoch_id {
        return Err(LabError::Storage);
    }

    // Conversation binding (review v2 remediation): the session record's
    // `conversation_id` (field 18) must equal top-level field 8 for every
    // session, receipt or not; a present receipt additionally still must
    // match it in `check_receipt`.
    if active.conversation_id != state.conversation_id {
        return Err(LabError::Storage);
    }

    // Receive-side state must be provable by the restored ratchet: if any
    // receive-side state is present, the session must actually have
    // received and decrypted a message. The converse is not required — a
    // session whose receive-side records were all consumed is legitimate —
    // and a receipt is send-side, so a receipt-only session does not
    // require this.
    let receive_side_present = active.highest_contiguous_received_seq > 0
        || !active.received_above_high_water.is_empty()
        || !state.inbound.is_empty()
        || !state.acks.is_empty();
    if receive_side_present && !session.has_received_message() {
        return Err(LabError::Storage);
    }

    // Role-aware transcript (remediation decision, recorded here and in
    // records.rs). vodozemac's `SessionKeys.identity_key` is always the
    // session INITIATOR's long-term curve identity and
    // `SessionKeys.one_time_key` is always the RECIPIENT's advertised
    // one-time key. The transcript bundle is therefore interpreted per
    // role:
    //
    // - outbound (we initiated): the transcript is the verified PEER
    //   bundle. `identity_key` is our own identity, `one_time_key` is the
    //   peer's advertised key.
    // - inbound (the peer initiated): the transcript is OUR OWN prekey
    //   bundle that the peer consumed. `identity_key` is the peer
    //   initiator's identity, `one_time_key` is our consumed key, which
    //   must no longer exist in the account.
    //
    // Whenever an active session is present, the peer binding (field 14)
    // MUST be present. For inbound it carries the only peer-identity
    // binding (`identity_key == binding.curve_identity`); for outbound the
    // peer-identity binding is the equality of the binding bundle and the
    // transcript. The receipt is always signed by the PEER, so it is
    // verified against the binding's pinned identity, not the transcript's
    // (which for inbound is our own).
    let binding = state.peer_binding.as_ref().ok_or(LabError::Storage)?;
    match active.role {
        Role::Outbound => {
            // Transcript = the verified peer bundle; its signature verifies
            // against the pinned peer signing identity over the same
            // signing-bytes construction used for peer prekeys.
            verify(
                active.transcript.signing_identity,
                &prekey_signing_bytes(&active.transcript),
                &active.transcript.signature,
            )?;
            if keys.identity_key != state.own_curve_identity
                || keys.one_time_key != active.transcript.one_time_key
                || binding.bundle != active.transcript
            {
                return Err(LabError::Storage);
            }
        }
        Role::Inbound => {
            // Transcript = our own consumed prekey bundle: identities must
            // be the account's own, the signature must verify against our
            // own signing identity, the session's one-time key must be the
            // advertised one, and that consumed key must no longer exist in
            // the account (otherwise account and session state disagree).
            if active.transcript.signing_identity != state.own_ed25519_identity
                || active.transcript.curve_identity != state.own_curve_identity
            {
                return Err(LabError::Storage);
            }
            verify(
                active.transcript.signing_identity,
                &prekey_signing_bytes(&active.transcript),
                &active.transcript.signature,
            )?;
            if keys.one_time_key != active.transcript.one_time_key
                || keys.identity_key != binding.bundle.curve_identity
                || account.contains_one_time_key(active.transcript.one_time_key)
            {
                return Err(LabError::Storage);
            }
        }
    }

    check_high_water(active)?;
    check_receipt(state, account, active, binding)?;
    Ok(())
}

/// Section 4 high-water invariants and mode consistency.
///
/// Review v3 finding 2 (recorded amendment): the §4 budget matrix
/// constrains the three BUDGET modes only — `Ready` below 24 outstanding,
/// `ControlOnly` at 24-31, `ReceiptLocked` at 32, more than 32 malformed.
/// `RekeyRequired` is orthogonal and DOMINATES the budget mode: an
/// authenticated current-epoch gap failure moves the session to
/// `RekeyRequired` at ANY outstanding count in 0..=32 (it exits only via
/// the §4 user-confirmed rebootstrap), so validation accepts
/// `RekeyRequired` for every non-malformed outstanding count.
fn check_high_water(active: &ActiveSession) -> Result<()> {
    if active.peer_contiguous_high_water > active.last_assigned_send_seq {
        return Err(LabError::Storage);
    }
    let outstanding = active.last_assigned_send_seq - active.peer_contiguous_high_water;
    if outstanding > MAX_OUTSTANDING {
        return Err(LabError::Storage);
    }
    if active.mode != SessionMode::RekeyRequired {
        if outstanding == MAX_OUTSTANDING && active.mode != SessionMode::ReceiptLocked {
            return Err(LabError::Storage);
        }
        if (CONTROL_ONLY_THRESHOLD..MAX_OUTSTANDING).contains(&outstanding)
            && !matches!(
                active.mode,
                SessionMode::ControlOnly | SessionMode::ReceiptLocked
            )
        {
            return Err(LabError::Storage);
        }
    }
    // Every out-of-order received sequence must sit strictly above the
    // implied contiguous high water; an element exactly at `hcr + 1` would
    // have advanced the contiguous high water, so it is a gap inconsistency.
    for &sequence in &active.received_above_high_water {
        if sequence <= active.highest_contiguous_received_seq.saturating_add(1) {
            return Err(LabError::Storage);
        }
    }
    // Review D2b v3 (field 19): no receipt can have been staged for a
    // high water never reached.
    if active.last_staged_receipt_high_water > active.highest_contiguous_received_seq {
        return Err(LabError::Storage);
    }
    Ok(())
}

fn check_receipt(
    state: &ClientStateV1,
    account: &Account,
    active: &ActiveSession,
    binding: &super::records::PeerBinding,
) -> Result<()> {
    match &active.receipt {
        None => {
            // The high water only ever advances through a receipt, so a
            // nonzero high water without the latest receipt is malformed.
            if active.peer_contiguous_high_water != 0 {
                return Err(LabError::Storage);
            }
            Ok(())
        }
        Some(receipt) => {
            // The receipt is always issued and signed by the PEER, so both
            // the issuer binding and the signature verification use the
            // peer binding's pinned identities (for an inbound session the
            // transcript is our own bundle, not the peer's).
            if receipt.conversation_id != state.conversation_id
                || receipt.epoch_id != active.epoch_id
                || receipt.issuer_curve != binding.bundle.curve_identity
                || receipt.acknowledged_sender_curve != account.curve25519_key()
                || receipt.high_water != active.peer_contiguous_high_water
                || receipt.high_water > active.last_assigned_send_seq
            {
                return Err(LabError::Storage);
            }
            verify(
                binding.bundle.signing_identity,
                &receipt_signing_bytes(receipt),
                &receipt.signature,
            )
        }
    }
}

fn check_inbound(state: &ClientStateV1, active: &ActiveSession) -> Result<()> {
    for record in &state.inbound {
        if record.epoch_id != active.epoch_id
            || record.queue_id != state.mailbox_queue_id
            || record.sender_sequence == 0
            || record.expires_at <= record.accepted_at
        {
            return Err(LabError::Storage);
        }
        // An accepted sequence above the contiguous high water must be in
        // the bounded out-of-order set.
        if record.sender_sequence > active.highest_contiguous_received_seq
            && !active
                .received_above_high_water
                .contains(&record.sender_sequence)
        {
            return Err(LabError::Storage);
        }
        let dedup = find_dedup(state, &record.message_id)?;
        if dedup.epoch_id != record.epoch_id
            || dedup.sequence != record.sender_sequence
            || dedup.queue_id != record.queue_id
            || dedup.packet_digest != record.packet_digest
            || dedup.expires_at != record.expires_at
        {
            return Err(LabError::Storage);
        }
    }
    Ok(())
}

fn check_sends(state: &ClientStateV1, active: &ActiveSession) -> Result<()> {
    let mut sequences = Vec::with_capacity(state.sends.len());
    for record in &state.sends {
        if record.epoch_id != active.epoch_id
            || record.sequence == 0
            || record.sequence > active.last_assigned_send_seq
        {
            return Err(LabError::Storage);
        }
        sequences.push(record.sequence);
        if record.state.carries_full_arm() {
            // Pending sends need the peer binding: the queue must be the
            // peer's mailbox and the send signature must verify under the
            // bound send capability. (`DeliveryUnknown` and the terminal
            // states hold only digest and expiry; nothing remains to
            // verify.)
            let binding = state.peer_binding.as_ref().ok_or(LabError::Storage)?;
            let (Some(queue_id), Some(packet), Some(signature)) =
                (record.queue_id, &record.packet, &record.send_signature)
            else {
                return Err(LabError::Storage);
            };
            if queue_id != binding.queue_id {
                return Err(LabError::Storage);
            }
            verify(
                binding.send_public_key,
                &send_signing_bytes(
                    queue_id,
                    record.message_id,
                    &packet.digest(),
                    record.expires_at,
                ),
                signature,
            )?;
        }
    }
    // Send sequences are unique across the outbox.
    sequences.sort_unstable();
    for pair in sequences.windows(2) {
        if pair[0] == pair[1] {
            return Err(LabError::Storage);
        }
    }
    Ok(())
}

fn check_acks(state: &ClientStateV1, active: &ActiveSession) -> Result<()> {
    for record in &state.acks {
        if record.epoch_id != active.epoch_id
            || record.queue_id != state.mailbox_queue_id
            || record.sequence == 0
        {
            return Err(LabError::Storage);
        }
        let dedup = find_dedup(state, &record.message_id)?;
        if dedup.epoch_id != record.epoch_id
            || dedup.sequence != record.sequence
            || dedup.queue_id != record.queue_id
            || dedup.packet_digest != record.packet_digest
        {
            return Err(LabError::Storage);
        }
    }
    Ok(())
}

fn check_dedup(state: &ClientStateV1, current: Option<(&ActiveSession, &Session)>) -> Result<()> {
    for record in &state.dedup {
        if record.queue_id != state.mailbox_queue_id || record.sequence == 0 {
            return Err(LabError::Storage);
        }
        // Review v3 finding 1: a dedup record for the CURRENT epoch is
        // receive-authoritative — the restored ratchet must actually have
        // received, and the record's sequence must be covered by the
        // contiguous high water or sit in the out-of-order received set.
        // Dedup records for retired epochs stay exempt (section 4
        // retention across rekey); with no active session there is no
        // current epoch and every record is retired-exempt.
        if let Some((active, session)) = current {
            if record.epoch_id == active.epoch_id {
                let covered = record.sequence <= active.highest_contiguous_received_seq
                    || active.received_above_high_water.contains(&record.sequence);
                if !session.has_received_message() || !covered {
                    return Err(LabError::Storage);
                }
            }
        }
    }
    Ok(())
}

/// Dedup records are sorted by raw `MessageId`; an ACK intent or inbound
/// record references exactly one of them.
fn find_dedup<'a>(
    state: &'a ClientStateV1,
    message_id: &MessageId,
) -> Result<&'a super::records::DedupRecord> {
    state
        .dedup
        .binary_search_by(|probe| probe.message_id.as_bytes().cmp(message_id.as_bytes()))
        .map(|index| &state.dedup[index])
        .map_err(|_| LabError::Storage)
}
