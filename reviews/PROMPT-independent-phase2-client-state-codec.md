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
   water must be 0.
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
