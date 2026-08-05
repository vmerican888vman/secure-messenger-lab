# Independent review — `ClientStateV1` TLV codec and validation — Fable

- Reviewed SHA: `a630f9a7b8b7c379330332d48e87239651944fb6` (verified via `git rev-parse HEAD`; worktree clean at review start)
- Reviewer: Fable (independent; the other reviewer's output was not read, sought, or referenced)
- Brief: `reviews/PROMPT-independent-phase2-client-state-codec.md`
- Design basis: `docs/phase2-design-decisions.md` §3 and §4

## Verdict

**RETURN**

## Gates

Both run from the repo root at the pinned SHA, on the unmodified worktree:

| Gate | Result |
|---|---|
| `cargo test --locked --all-targets` | PASS (exit 0; all suites green, including the 49 `state::` tests) |
| `cargo clippy --locked --all-targets -- -D warnings` | PASS (exit 0) |

Probe code was written and executed in a separate git worktree at the same SHA
(never in this worktree, which was left untouched apart from this file). All
probe results below were reproduced by real `cargo test` runs against real
vodozemac operations; probe sources are inlined in the reproduction sections.

## Blocking findings

### F1. Inbound-role sessions are unrepresentable with honest protocol artifacts

`check_active_session` (src/state/validate.rs:360–377) requires, for
`Role::Inbound`:

- `keys.identity_key == active.transcript.curve_identity` (validate.rs:371), and
- `keys.one_time_key == active.transcript.one_time_key` (validate.rs:376), and
- the transcript signature to verify under `transcript.signing_identity`
  (validate.rs:355–359).

Per vodozemac (`vendor/vodozemac-0.10.0/src/olm/session_keys.rs:24–34`),
`identity_key` is the **initiator's** long-term key and `one_time_key` is the
**recipient's** consumed OTK. So for an inbound session (peer initiated), the
transcript must be a bundle whose `curve_identity` is the *peer's* and whose
`one_time_key` is *ours*, signed by the peer. No such artifact exists anywhere
in the protocol:

- Our own published prekey bundle (self-signed; `OlmClient::prekey_bundle`,
  src/client.rs:187–210) carries *our* curve identity → fails the
  identity-key check.
- The peer's contact bundle (`PeerPreKey`, the only peer-signed bundle in the
  protocol) carries the *peer's own* OTK → fails the one-time-key check.

The only satisfying transcript is a peer-signed bundle over **our** consumed
OTK, which no protocol message produces. Consequently the façade cannot
persist any peer-initiated (`open_initial`-style) session: `ClientStateV1`
with an honest inbound session always fails validation, on both encode and
decode. `check_receipt` (validate.rs:430, `issuer_curve !=
active.transcript.curve_identity`) bakes in the same peer-shaped-transcript
assumption. Note the test suite contains **no positive `Role::Inbound`
fixture** — the only inbound-role test is the mislabeling rejection
(src/state/tests.rs:1273–1279) — so this hole is invisible to the 49 tests.

This is a validation flaw that makes the façade unsafe (in fact impossible) to
build on this leg for half of all sessions, and the inbound-transcript
convention is not among the nine documented decisions.

Reproduction (probe run at the pinned SHA in a scratch worktree; passed):

```rust
// Build a REAL inbound session: our account publishes one OTK, the peer
// establishes an outbound session consuming it, we create_inbound_session
// from the resulting pre-key message. Then attempt validation with each
// candidate transcript in an otherwise-valid ClientStateV1
// (role: Inbound, keys/epoch from session.session_keys()):
//   A. our self-signed prekey bundle (honest)      -> encode() Err  (identity check)
//   B. peer's self-signed contact bundle (honest)  -> encode() Err  (OTK check)
//   C. peer-signed bundle over OUR consumed OTK    -> encode() Ok
//      (artifact C is producible only in a test that owns the peer's
//       account; no protocol message ever creates it)
#[test] fn probe_inbound_role_transcripts() { /* full source in review worktree;
    asserts exactly A=Err, B=Err, C=Ok — all three assertions held */ }
```

### F2. §4's mandated durable `RekeyRequired` transition is unpersistable and unloadable at outstanding ≥ 24

`check_high_water` (src/state/validate.rs:394–399) allows only
`ReceiptLocked` at outstanding == 32 and only `ControlOnly`/`ReceiptLocked`
at 24–31, rejecting `RekeyRequired` in both bands (asserted by the slice's own
tests, src/state/tests.rs:1426 and :1438). But the frozen design §4 states:

- `ReceiptLocked` (outstanding 32): "inbound decrypt, exact outbox retry,
  relay ACK and receipt processing **continue**";
- "A previously unseen, peer-authenticated current-epoch packet producing
  `TooBigMessageGap` or `MissingMessageKey` **moves the session durably to
  `RekeyRequired`**".

So a session at 32 (or 24–31) outstanding that receives a gap packet must
durably record `RekeyRequired` — and that exact snapshot fails validation.
Because `encode` re-runs validation, the §2 mutator sequence can never commit
the transition (commit fails → `ReconcileRequired` → reopen → same state →
same failure on the next gap packet); and if such bytes ever existed, `decode`
rejects them, locking the profile. Outstanding cannot first be reduced:
"`Stored`, `Duplicate`, expiry and consuming `DeliveryUnknown` never advance
peer high-water or recover budget", so only a receipt could, and nothing
guarantees one arrives after gap evidence. The restriction is also
directionally inconsistent with the rest of the check: modes *more*
restrictive than the band (e.g. `ReceiptLocked` at 0 outstanding) are
accepted, yet `RekeyRequired` — the most restrictive mode — is refused.
§4's table does not contain this constraint; it is an undocumented deviation
that makes a design-mandated durable transition unrepresentable.

Reproduction (probe run at the pinned SHA in a scratch worktree; passed):

```rust
// Valid ReceiptLocked snapshot at outstanding 32 encodes and decodes.
// Flipping the session-object mode byte (field 15) from 3 to 4
// (RekeyRequired) makes the same bytes unloadable; same at outstanding 24
// with ControlOnly -> RekeyRequired.
#[test] fn probe_rekey_required_unloadable_at_high_outstanding() { /* full
    source in review worktree; both decode attempts returned Err */ }
```

Either the validation must admit `RekeyRequired` at any outstanding ≤ 32, or
the frozen design must be explicitly amended to define how a gap packet at
outstanding ≥ 24 is durably recorded. As the code and design stand together,
the façade cannot implement §4 on this leg.

## Non-blocking observations

These are not return causes; they are recorded for the façade slice and the
maintainers.

1. **Duplicate sender/ACK sequences accepted.** Two inbound records (distinct
   `MessageId`s, each with a matching dedup record) claiming the same
   `(epoch_id, sender_sequence)`, plus two ACK intents with the same sequence,
   validate and round-trip (probe `probe_duplicate_inbound_sender_sequence_accepted`,
   passed). Honest operation cannot produce this (a sequence names one Olm
   message), and the brief's required cross-checks list only *send*-sequence
   uniqueness, so it is not a deviation — but the façade must not assume the
   codec enforces inbound/dedup sequence uniqueness.
2. **Zero-high-water receipt accepted.** A present, peer-signed receipt with
   `high_water == 0` and `peer_contiguous_high_water == 0` loads (probe
   `probe_receipt_high_water_zero_accepted`, passed), although §4's runtime
   acceptance rule (`old < new`) can never produce one. Requires a valid peer
   signature, so harmless; slightly widens the loadable-state space.
3. **Secret-bearing reserialization buffers are not zeroized.** The
   `reserialized` vector in `tlv::canonical_json` (src/state/tlv.rs:211) and
   the `reencoded` vectors in `check_account` / `check_active_session`
   (src/state/validate.rs:195, :329) hold complete account/session/keypair
   secret JSON in ordinary heap allocations (as do serde_json internals).
   This is inherent to the frozen reserialize-and-compare design and heap
   remanence is arguably out of scope, but the module elsewhere is strict
   about `Zeroizing`; worth wrapping the owned buffers and documenting the
   serde-internal residue.
4. **Two canonical secret-key representations.** vodozemac's
   `Ed25519KeypairPickle` wraps an externally tagged `SecretKeys` enum
   (`Normal`/`Expanded`); both forms of the same key round-trip
   byte-identically, so "canonical JSON" admits two encodings of one logical
   keypair. Public-key cross-checks make this harmless under the outer AEAD.
5. **Fixture quirk.** `populated_fixture` reuses a send record's `MessageId`
   as the inbound record's ID (src/state/tests.rs:261); cross-array
   message-ID uniqueness is not validated by the codec (arrays are only
   internally strictly increasing). Cosmetic, but a cleaner fixture would not
   encode an impossible ID collision.
6. **Determinism of pickles verified.** Account/session pickles serialize
   only `BTreeMap`s, `Option`s and fixed structs (checked in
   `vendor/vodozemac-0.10.0`); an account with 75 one-time keys across
   published/unpublished stores round-trips byte-identically (probe
   `probe_multi_otk_account_round_trips`, passed). The vendored
   `Account::contains_one_time_key` inspects only the OTK store, not fallback
   keys, matching the §3 requirement.

## What was checked and held

- Structural rejection classes (required attack 1) all verified: wrong magic,
  wrong object type, field-count mismatch, unknown/missing/duplicate/
  out-of-order fields, enum 0 and enum max+1 for every enum, wrong fixed
  lengths (short and long), truncation at multiple depths, trailing bytes at
  top level and inside nested objects, `u32::MAX` and bound+1 length prefixes
  for every bounded field, zero-length optional semantics, array count
  bound+1 for all four arrays and the received set, unsorted and equal-ID
  arrays on both decode and encode paths. Bounds are enforced before
  consumption over a non-allocating cursor; no allocation from
  attacker-controlled lengths exists on the decode path.
- Canonical-JSON verification (required attack 2): whitespace, member
  reorder, unknown members, missing members, serde-defaulted member
  (session `config`), the real vodozemac `key_id` alias, duplicate keys,
  trailing data and bound enforcement all rejected; exercised against the
  account pickle, session pickle and keypair fields.
- Byte-flip mutations in every top-level field except the documented
  profile/key-ref/generation exception fail decode or validation.
- Semantic mismatches (required attack 4): re-pickle inequality, identity
  mismatch, capability/registration mismatch, forged and validly re-signed
  swapped bundles, consumed OTK via a real inbound session, wrong epoch_id,
  session-absent-with-dependent-records all rejected; documented decisions
  2, 3, 6, 7 (dedup direction and retired-epoch allowance), 8 and 9 verified
  as implemented; decision 5 (send bound including terminals) verified.
- Round-trip byte identity (required attack 7) holds for both fixtures and
  for every accepted probe variant.
- The declared gaps (no load-time freshness, outer-AEAD binding of
  profile/key-ref/generation, unverifiable terminal digests, structural-only
  inbound expiry, snapshot-undecidable outbox transitions) are acceptable at
  this leg and are documented in code and tests.
