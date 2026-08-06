# Independent review — `ClientStateV1` TLV codec and validation

Review `secure-messenger-lab` at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Fable and Sol; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own.

This is an adversarial review of the `ClientStateV1` codec leg (`src/state/`) of Phase-2 design
decision §3 (`docs/phase2-design-decisions.md`). The module is crate-private and has no consumer
yet; the façade is a later leg. Do not return it merely because no consumer exists. Do return any
codec or validation flaw that would make the façade unsafe to build on it, and any deviation from
the frozen design that is not documented as a deviation.

## In scope

- `src/state/tlv.rs` — canonical TLV primitives: exact field count, exact ascending field-ID
  sequence, unknown/missing/duplicate/out-of-order rejection, bound-before-consume, allocation
  safety, complete-consumption and trailing-byte rejection, bounded canonical-JSON verification.
- `src/state/records.rs` — object types 0x0002–0x0009 and all nested record layouts.
- `src/state/mod.rs` — top-level framing (magic `SMSLCSV1`, object type 0x0001, nineteen fields),
  the §3 bounds table, `ClientStateV1::decode`/`encode`.
- `src/state/validate.rs` — the §3 post-unpickle semantic validation and the §4 high-water/mode
  invariants it cites.
- `src/state/tests.rs` — 49 tests, including fixtures built from real vodozemac operations.

## Remediation history

Version 6 (head `eb2020e8beb178b2e933ef4d62fb9f0b5d1637e1`) was RETURNED
(verdict in `reviews/REVIEW-codec-v6.md`) with two blockers, both fixed in
the head under review:

1. Identity keys can no longer alias transferable capabilities: every
   mailbox public key (send/receive/manage) must differ from
   `own_ed25519_identity`, and the peer's send capability public key must
   differ from the peer's pinned signing identity. The reviewer's exact
   reproduction (account `signing_key` reused as `send_keypair_json`) is a
   regression test on both encode and decode paths.
2. Matching inbound and dedup records must now agree on `expires_at`
   (§3's expiry/dedup cross-check). The ACK-intent side was examined and
   intentionally not changed: an ACK intent's `valid_until` is its own
   value, not a duplicate of the message expiry.

Version 5 (head `d8795fabb0bb5f9fb685c7a0f12e33ac2039b174`) was dual-RETURNED
(verdicts transcribed in `reviews/REVIEW-combined-codec-v5-d2a-d2b.md`):
Fable found the `u64::MAX` counter wrap (`wrapping_add` onto retained key id
0); Sol found a non-zeroizing full-plaintext copy and mailbox capability
collapse. The amended head under review now: requires
`next_key_id <= u64::MAX - 1_000_000_000` (wrap headroom, documented);
Zeroizing-wraps the one full-plaintext assembly in `ClientStateV1::encode`
(all other copies audited — none remain); and requires the three mailbox
capability public keys pairwise distinct in addition to keypair/registration
correspondence.

Version 4 (head `eb9d26f1fe59a9b51fa347b18f0ca45f53985222`) was RETURNED by
Sol with one blocker (verdict in `reviews/REVIEW-sol-client-state-codec-v4.md`):
`check_one_time_key_consistency` ignored `next_key_id`, so a canonical pickle
could point the counter at a retained key and the next generation would
silently replace its secret. The amended head under review now requires
`next_key_id` to be strictly greater than every retained key id (in
`private_keys` ∪ `public_keys`); gaps are legitimate and never rejected.
Regression tests cover a canonicality-preserving splice on both encode and
decode paths, the max/max+1 boundary, and real subsequent key generation
without key loss.

Version 3 (head `235ccfb854ba0d8def87a612d68c9948adb2719f`) was PASSed by
Fable and RETURNED by Sol with four further blockers (verdicts in
`reviews/REVIEW-fable-client-state-codec-v3.md` and
`reviews/REVIEW-sol-client-state-codec-v3.md`). The amended head under review
now fixes all four:

1. Current-epoch dedup records now require `has_received_message()` and a
   sequence ≤ `highest_contiguous_received_seq` or present in
   `received_above_high_water`; retired-epoch dedup stays exempt (§4
   retention). The `receipt_only_session_validates` fixture uses
   retired-epoch dedup records.
2. `RekeyRequired` dominates the budget mode: accepted at any outstanding
   count 0..=32 (the Ready/ControlOnly/ReceiptLocked matrix still governs
   the three budget modes; >32 rejects regardless). This supersedes Fable's
   v3 non-blocking carry-over note.
3. Account validation now requires all derived OTK public keys unique and
   every unpublished-map entry consistent with the private-key store (key id
   exists, stored public equals derived public), closing the
   duplicate-secret acceptance the vendored patch documents validators must
   reject.
4. Secret intermediates under this crate's control are `Zeroizing` (or never
   materialize — record encodes write borrowed fields). Dependency-owned
   buffers (serde_json internals, vodozemac pickle types, façade `Candidate`
   clones) are documented as out of reach, not hacked around.

Also: the head now passes `cargo fmt --check` (v3's CI formatting failure);
the fmt pass reflowed some non-state files with zero semantic change.

Version 2 (head `eaebebe4e6aef7c1a024e8f2a3ef6bebd7061bd4`) made the
transcript role-aware and was RETURNED by Sol with four blockers
(verdict in `reviews/REVIEW-sol-client-state-codec-v2.md`), all fixed in v3:

1. Receive-side state (`highest_contiguous_received_seq > 0`, non-empty
   received set, inbound records, or ACK intents) now requires
   `Session::has_received_message()` on the restored ratchet. The populated
   fixture is genuine end-to-end (real encrypt → real inbound accept → real
   reply → real decrypt). A receipt alone does not require it (send-side).
2. ActiveSession carries `conversation_id[16]` as new field 18 (a
   review-authorized wire-layout amendment; prior field numbering unchanged);
   validation requires it to equal field 8 for both roles, receipt or not.
3. `DeliveryUnknown` moved to the digest+expiry arm per the frozen design
   (`docs/persistence-spike-design.md`); only `Pending` carries
   queue/packet/expiry/signature.
4. A pending prekey must now reference a *published* OTK: held
   (`contains_one_time_key`) AND absent from `account.one_time_keys()` (the
   unpublished set).

Confirm you are reviewing the amended head, not any returned one.

The role-aware transcript model from v2 (unchanged by v3):

- **outbound (we initiated):** transcript = the verified peer bundle;
  signature verifies with the peer's pinned identity; `identity_key` == our
  own curve identity; `one_time_key` == peer's advertised OTK; peer binding
  bundle == transcript bundle (whole-bundle equality).
- **inbound (peer initiated):** transcript = our own consumed prekey bundle;
  identities == our stored own identities; signature verifies with our own
  signing identity; `one_time_key` == our consumed OTK, which must NOT still
  exist in the account (`contains_one_time_key` must be false);
  `identity_key` == peer binding's curve identity (the only peer-identity
  binding).
- **both roles:** peer binding (field 14) is mandatory when an active session
  is present; the high-water receipt is always peer-signed, so it verifies
  against the peer binding's pinned identity (not the transcript's).
- A genuine inbound-session regression fixture
  (`genuine_inbound_session_round_trips_byte_identically`) now exists, built
  from real vodozemac session establishment in both directions.

## Documented decisions taken within the frozen constraints (attack these)

1. Nested object-type IDs 0x0002–0x0009 and per-object field layouts as written in code — the
   frozen design fixes content and ordering requirements, not these IDs.
2. `queue_id` fields are 32 bytes (the crate's real `QueueId` width).
3. Field 11 (mailbox + three keypairs) is a packed layout `queue_id[32] || 3×(u32be len +
   canonical JSON)` with exact-consumption checking.
4. Received-above-high-water set bounded at 64 (§3 says bounded, no number).
5. Send-array bound 32 applies to the whole array including terminal records (stricter than the
   table row).
6. Receipt present ⇒ `receipt.high_water == peer_contiguous_high_water`; receipt absent ⇒ high
   water must be 0. The receipt verifies against the peer binding's pinned identity for both
   roles (it is always peer-signed; the inbound transcript is our own bundle).
7. Every inbound record and ACK intent requires a matching dedup record (message ID, epoch,
   sequence, queue, digest); the converse is not required. Dedup epochs may reference retired
   epochs (§4 retention); session absence ⇒ inbound/send/ACK arrays empty, dedup allowed.
8. Receipt signature part order: `canonical("session-high-water/v1", [version, conversation_id,
   epoch_id, acknowledged_sender_curve, issuer_curve, high_water])`.
9. Pending prekey enforces `created_at < valid_until` but not the 300 s contact-bundle window
   (that rule governs peer bundles at verification time, not load time).

## Declared gaps (judge whether each is acceptable at this leg)

- No freshness checks at load (no trusted `now`); internal consistency only. The façade must
  supply time.
- `profile_id`/`key_ref`/`generation` are not cross-checked by the codec; they rely on the outer
  AEAD/platform binding (§1).
- Terminal send digests are unverifiable by design (packet erased).
- Inbound "signed expiry" authenticity at load is structural only (record layout carries no
  envelope signature).
- Outbox transition legality over time is not decidable from a snapshot; arm consistency,
  distinct sequences, and `sequence <= last_assigned_send_seq` are enforced instead.

## Required attacks

Attempt concrete failure sequences for at least:

1. every structural rejection class: wrong magic, wrong object type, field-count mismatch,
   unknown/missing/duplicate/out-of-order fields, invalid enum (including 0), wrong fixed length,
   truncated values, trailing bytes, `u32::MAX` and bound+1 length prefixes, zero-length optional
   semantics, array count bound+1, unsorted and equal-ID arrays;
2. canonical-JSON violations against every pickle/keypair field: whitespace variants, duplicate
   keys, unknown fields, missing or defaulted fields, serde aliases (vodozemac has at least one),
   non-canonical order, trailing data, bound+1 documents;
3. byte-flip mutations in each top-level field (excluding only the documented
   profile/key-ref/generation exception) — decode or validation must fail;
4. semantic mismatches: account/session re-pickle inequality, identity mismatch, capability key
   vs registration intent mismatch, forged or swapped registration/prekey/session transcript
   signatures, consumed OTK (via a real inbound session), wrong epoch_id, session-absent with
   session-dependent records present;
5. high-water/mode matrix: outstanding > 32 must be rejected outright; 32 only ReceiptLocked;
   24–31 only ControlOnly or ReceiptLocked; receipt regression, future receipt, receipt/high-water
   divergence, receipt/epoch divergence;
6. cross-record attacks: send sequence above `last_assigned_send_seq`, duplicate send sequences,
   inbound/ACK records without matching dedup, dedup field mismatches;
7. re-encode byte-identity violations: any accepted document that does not round-trip
   byte-identically is a finding.

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Return `PASS` or `RETURN` against the exact head SHA. A `RETURN` must list blocking findings only,
each with a concrete reproduction or source reference.
