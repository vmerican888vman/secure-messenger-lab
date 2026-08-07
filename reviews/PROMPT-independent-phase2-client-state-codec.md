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
  the §3 bounds table and the SPLIT send quotas, `ClientStateV1::decode`/`encode`.
- `src/state/validate.rs` — the §3 post-unpickle semantic validation and the §4 high-water/mode
  invariants it cites.
- `src/state/tests.rs` — 87 tests, including fixtures built from real vodozemac operations.

## Remediation history (v9 — RE-PINNED after façade drift)

**Read this first: the previously circulated codec head `11a32aa` is
dead.** It was pinned for review and never dispatched, and `src/state/`
has since moved under it by ten commits and ~840 lines while the façade
leg D2b was remediated. Reviewing `11a32aa` would have certified a layout
that no longer exists. This brief is re-pinned to the current head, which
carries a **dual PASS on façade D2b** (`a33d2ba`) — so the codec is now
being reviewed against the shape its only consumer actually uses.

Nothing in the v7/v8 remediation below was reverted; the entries still
stand. What follows is the accumulated delta you must review IN ADDITION.

### Layout changes since `11a32aa`

- **`ActiveSession` 21 → 23 fields.** Field 22
  `unreceipted_application_send_seqs: Vec<u64>` (canonical strictly
  increasing, duplicate-free, bounded 24) and field 23
  `control_send_not_before: u64`. These implement the §4 control-lane
  split authorised by the security architect: the application budget is
  now the LENGTH of field 22, not the shared sequence distance. A field
  22 was briefly added and reverted at v12/v13 for a different purpose
  (`control_signal_response_at`) — the current field 22 is unrelated to
  that and the wire position was reused deliberately while the codec is
  pre-PASS.
- **`DedupRecord` 7 → 8 fields.** Field 8 `message_digest: [u8; 32]` is
  the digest of the INNER Olm `Message`'s canonical bytes,
  variant-independent, and is now the dedup identity. Field 5
  `packet_digest` is unchanged and remains the envelope/ACK binding.
- **`SessionMode::ReceiptLocked` (discriminant 3) is RETIRED.** The
  discriminant is left as a numbering gap so no persisted value silently
  changes meaning; stored value 3 must be rejected on load. Modes are
  `Ready` below 24 application outstanding, `ControlOnly` at exactly 24,
  more malformed, `RekeyRequired` orthogonal and dominant across 0..=24.
- **Send quotas split:** `MAX_SENDS` 32 → 40, with independent
  `MAX_APPLICATION_SENDS` = 32 and `MAX_CONTROL_SENDS` = 8, plus at most
  one UNRESOLVED (`Pending` or `DeliveryUnknown`) control record.

### Validation changes since `11a32aa`

- `check_high_water` now keys the budget on the application ledger, not
  the shared sequence distance. **The old `outstanding > MAX_OUTSTANDING`
  malformed-state check is GONE** — nothing now bounds how far
  `last_assigned_send_seq` may run ahead of `peer_contiguous_high_water`
  in a persisted state. Both independent reviewers of the façade leg
  ruled this non-blocking THERE, and both warned specifically against
  re-adding any bound that gates control encryption (that reintroduces a
  deadlock family that cost seven review rounds). **A load-time-only
  ceiling is still open for you to rule on as a CODEC question**, which
  is the right place for it.
- New `check_application_ledger`: every retained application record above
  the peer high water must appear in the ledger; no receipt-kind sequence
  may appear; no record at or below the high water may appear; and a
  ledger entry need NOT retain a record, because pruning is precisely why
  the durable ledger exists.
- Ledger entries must be nonzero and satisfy
  `peer_contiguous_high_water < seq <= last_assigned_send_seq`.
- `control_debt_up_to` may now sit ABOVE the contiguous received water
  when it is present in `received_above_high_water` — the peer-signalled
  arm binds debt to the signalling packet's sequence, which under
  reordering legitimately leads the contiguous water.
- `control_send_not_before <= last_assigned_send_seq` is required only in
  the weak sense that a nonzero cooldown implies at least one assigned
  sequence.
- Per-kind send quotas and the one-unresolved-control rule are enforced
  structurally.

### What I most want attacked

1. **Is the ledger a sound authority?** It outlives its records by
   design. Construct a persisted state that validation ACCEPTS but whose
   ledger misrepresents real capacity in a way the façade would act on.
2. **The retired discriminant.** Confirm stored `SessionMode` byte 3 is
   rejected, and that no other value aliases a live mode.
3. **The removed ceiling.** Rule on whether a load-time-only bound on the
   shared sequence distance belongs in the codec, given the explicit
   warning against anything that gates control encryption at runtime.
4. **Field 22's reuse.** The wire position previously held a different
   `u64` field that was added and reverted. The codec is pre-PASS so no
   persisted state should exist, but say whether the reuse is safe to
   leave undocumented in the frozen text.
5. **`SCHEMA_VERSION` is still 1** across three layout changes. Both
   façade reviewers called this non-blocking-but-migration-debt. It is
   squarely a codec decision — rule on it.
6. **Carried P3 from an earlier façade round:** the ACCEPT direction of
   the relaxed `control_debt_up_to` rule (a debt water sitting in the
   out-of-order set decodes cleanly) is currently proven only via
   persistent-layer commits. A companion splice case in `src/state/tests.rs`
   would pin it directly. Say whether that gap should block.

## Remediation history (v8)

**v7 split verdict:** one reviewer PASSed `89027ea`
(`reviews/REVIEW-codec-v7-pass.md`); the other RETURNed it
(`reviews/REVIEW-codec-v7-return.md`) with two blockers, both fixed in the
head under review:

1. Current-epoch records now enforce unique sequences: dedup records
   sharing the active epoch must have distinct `sequence` values (retired
   epochs exempt), and no two inbound records or two ACK intents may share
   `(epoch, sequence)`. The test that unknowingly required acceptance of
   the impossible snapshot was inverted; its fixture's "old" dedup record
   is now genuinely retired-epoch.
2. No retained OTK may alias the long-term Curve25519 identity: every
   derived private-key public and every unpublished-map public must differ
   from the account's `diffie_hellman_key` public. The reviewer's repro
   (identity secret spliced into the OTK store, prekey re-signed, real 3DH
   session establishment) is a regression test on both paths, including
   after a genuine inbound session.

**Late amendment (façade D2b v4):** ActiveSession gained field 19
`last_staged_receipt_high_water: u64` (ascending order preserved, field
count 19; validation: never exceeds `highest_contiguous_received_seq`, 0 =
none staged). This is the durable owed-receipt marker from the D2b v3
remediation; see `reviews/PROMPT-independent-phase2-facade-d2b.md` for the
motivation. Codec-side rules and tests are in this leg's scope.

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
