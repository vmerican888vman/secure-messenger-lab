# Independent review — façade leg D2b: inbound path, receipts, ACKs

## Remediation history (v12)

Version 11 (head `b3825fa30980c797dfad4de3d1a4729c132f3506`): Fable PASS
(`reviews/REVIEW-fable-facade-d2b-v11.md`), Sol RETURN with two P1
blockers (`reviews/REVIEW-sol-facade-d2b-v11.md`), both fixed in the head
under review. **This round changes the codec** — two new fields — so it
supersedes any earlier codec-leg pin.

1. **Dedup keys on a variant-independent inner-message identity** (Sol's
   P1-1). v11's canonical-encoding gate collapsed the JSON and
   inner-framing alias classes but not the VARIANT alias: a
   `PreKeyMessage` wraps a `Message`, an established session decrypts
   both `OlmMessage` variants, and both consume the same inner message
   key. So an accepted `PreKey` packet's inner message re-serialized as
   `Normal` is a perfectly canonical packet with a different raw digest,
   which slipped dedup and reached the ratchet. `DedupRecord` gains
   **field 8, `message_digest`** — the digest of the inner `Message`'s
   canonical bytes, computed by `client::inner_message_digest`, which
   unwraps `PreKey` to its inner message. The bounds closure rejects on
   it alongside the message ID and the raw digest. Field 5
   (`packet_digest`) is unchanged and remains the envelope/ACK binding,
   because it is what the sender signs — exactly the split Sol asked
   for. The inner message fixes the ratchet key, chain index, ciphertext
   and MAC, which is precisely what determines the consumed message key;
   the `PreKey` session-key preamble establishes a session but does not
   change that, so it is correctly outside the identity.
2. **Peer-signaled control responses are bounded by reciprocity, not by
   concurrency** (Sol's P1-2). `ActiveSession` gains **field 22,
   `control_signal_response_at`** — our own `last_assigned_send_seq` as
   of the last receipt issued in answer to a peer signal. The
   peer-signaled arm fires only while `peer_contiguous_high_water >=
   control_signal_response_at`. The reasoning: our outstanding falls
   only when the PEER acknowledges our sends, so `Stored` is the wrong
   completion signal — it means the relay took it, not that the peer
   consumed it. Requiring the peer's reported water to cover the answer
   we already sent makes the bound durable across `Stored`. An honest
   congested peer receipts promptly and is never throttled; a peer that
   never reciprocates extracts exactly ONE control receipt however many
   signals it sends. The LOCAL congestion arm is deliberately NOT gated —
   it answers our own congestion, cannot be driven by the peer, and is
   the both-stuck backstop. Validation:
   `control_signal_response_at <= last_assigned_send_seq`.

Both fixes carry regression tests confirmed to FAIL against `b3825fa`
(transplanted into a disposable worktree at that SHA, since the fixes are
codec changes):

- `prekey_normal_variant_alias_is_deduplicated` accepts the session's
  establishing `PreKey` packet, rewraps its inner message as `Normal`,
  and first asserts the alias is genuinely canonical (so v11's gate
  cannot see it) and carries a different raw digest (so raw-digest dedup
  cannot see it either) — then requires `DuplicateMessage` with no
  generation commit, mode still `Ready`, and the receive water unmoved,
  including after a reopen. Pre-fix it returned `Err(Crypto)`: past
  dedup, into the ratchet.
- `over_signaling_cannot_lock_the_victim` is rewritten to Sol's shape: 32
  FULL delivery cycles, each driving the staged receipt to `Stored`
  before the next signal — the completion that defeated the v11 guard. It
  asserts the victim never leaves `Ready`, outstanding never reaches the
  threshold, and, as the lifetime bound, that exactly ONE control receipt
  was issued across all 32 cycles. Pre-fix the victim left `Ready` for
  `ControlOnly` at cycle 25, en route to `ReceiptLocked` at 32.

Note for reviewers: `invalid_enums_rejected` in `src/state/tests.rs` was
adjusted because the dedup record's state enum is no longer its trailing
byte (field 8 now follows it); the test indexes back past the new field
rather than assuming the last byte.

The v2–v11 histories follow unchanged.

## Remediation history (v11)

Version 10 (head `dad8bcc5fbb2c3e2014190b1aef1a83345b13f08`): Fable PASS
(`reviews/REVIEW-fable-facade-d2b-v10.md`), Sol RETURN with two P1
blockers (`reviews/REVIEW-sol-facade-d2b-v10.md`), both fixed in the head
under review. Note for this round: the implementer changed hands at v11 —
Kimi K3 wrote v1–v10, this remediation is Opus's. The review contract is
unchanged.

1. **Canonical Olm encoding is enforced at the boundary** (Sol's P1-1).
   `EncryptedPacket::digest` hashes RAW bytes and that raw digest is both
   the dedup identity and what the sender signs, but the `OlmMessage`
   deserializer is permissive — ignored unknown fields, any field order,
   any whitespace, base64 padding variants, non-canonical inner framing.
   The same message therefore had many encodings, each with a different
   digest, so an accepted packet could be re-encapsulated under a fresh
   ID and a fresh valid signature, miss dedup on its new digest, and
   reach the ratchet. `EncryptedPacket::parse_canonical` now decodes the
   packet and requires it to be byte-identical to the re-serialization of
   what it decoded to; `accept_envelope` calls it BEFORE the transaction
   opens, so no alias reaches dedup or the ratchet. Of the two closures
   Sol offered, this is the first: making the encoding unique means the
   raw digest IS the semantic identity, so no second dedup digest is
   needed and the persisted `ClientStateV1` layout is untouched. The
   check is a pure function of the packet bytes and reads no session
   state, so running it ahead of the signature check gives an
   unauthenticated sender no oracle. The `MAX_PACKET` bound is re-checked
   ahead of it so oversized input is still rejected before any parse; the
   in-transaction bounds check remains authoritative.
2. **Peer-signaled control debt binds to the signaling sequence** (Sol's
   P1-2). `accept_staging_tail` took a single arm that raised the debt to
   HCR. It is now split: the LOCAL arm still raises to HCR (it answers
   our own congestion, so it owes a receipt for what we contiguously
   received), while the PEER-SIGNALED arm raises to the accepted
   payload's `send_seq`. Under reordering those differ, and that gap was
   the bug. `check_session_waters` correspondingly permits a debt water
   that sits in `received_above_high_water`, mirroring the existing
   `receipt_debt_up_to` rule — the admissible positions are exactly the
   two that mean "received".

Both fixes carry regression tests that were confirmed to FAIL against
`dad8bcc` and pass at this head:

- `json_aliased_packet_replay_is_rejected_before_dedup` builds three
  genuine aliases of an accepted packet (reordered keys, added
  whitespace, an ignored extra field), proves each decodes to the same
  `OlmMessage` and carries a different digest, then requires each to be
  rejected as `InvalidPayload` with no generation commit, the mode still
  `Ready`, and the receive water unmoved. Pre-fix the first alias
  returned `Err(Crypto)` — i.e. it had already passed dedup and reached
  ratchet `decrypt`, which is the bypass. (The test demonstrates the
  bypass reaching the ratchet; whether a given alias then produces a
  durable `RekeyRequired` or a plain crypto error depends on its chain
  position. The gate closes the class either way.)
- `reordered_congestion_signal_survives_a_delayed_receipt` drives the
  real façade over the real relay: B fills §4's budget to exactly 24
  outstanding (the highest sequence that can carry a truthful signal,
  since ControlOnly then blocks further applications), A accepts sequence
  1 and then the signaling sequence 24 out of order, the debt must record
  24 (pre-fix: 1), a delivered older receipt at water 1 must NOT resolve
  it, the missing packets drain HCR to 24, and the still-standing debt
  must converge to a receipt covering 24 — after which B's high water
  reaches 24, its outstanding falls below the threshold, it returns to
  `Ready`, and it can stage applications again.

Convergence is a bounded loop rather than a single shot, and the test
asserts it as one: the any-pending guard (v8 P1-4) stages at most one
receipt at a time and receipts stage at the CURRENT high water, so a
receipt staged mid-drain covers only the water of that moment and the
next mutator stages at the drained water.

The v2–v10 histories follow unchanged.

## Remediation history (v10)

Version 9 (head `7eab05bb0cd887e49b9cbff7f4a4dd2b2047b9a2`): Fable PASS, Sol
RETURN with four P1 blockers (verdict in
`reviews/REVIEW-sol-facade-d2b-v9.md`), all fixed in the head under review:

1. **Global digest dedup before any ratchet touch** — a retired-epoch packet
   re-encapsulated with a fresh outer ID/signature is rejected across ALL
   retained dedup records, so it can never gap-lock the session. Provenance
   analysis in the module docs: remaining gap-error producers are genuine
   current-chain packets (RekeyRequired correct per §4) or never-accepted
   foreign packets (MAC-fail, not gap-fail).
2+4. **Control debt is now a high-water, not a flag** (field 21 retyped
   `control_debt_armed: u8` → `control_debt_up_to: u64`). Arming raises it to
   `max(current, HCR)`; NOTHING on the wire ever clears it; it resolves only
   when the delivered marker reaches it. Reordered low signals cannot erase
   an arm (finding 2), and a delayed `Stored` on an older receipt leaves
   newer debt standing (finding 4). The v9 signal-based clear rule is
   deleted as the bug it was.
3. **`accept_envelope` sweeps send expiry and prunes before the staging
   tail**, so an expired in-flight control receipt no longer blocks
   receipt-only recovery traffic (Sol's repro is the regression test).

The v2–v9 histories follow unchanged.

## Remediation history (v9)

Version 8 (head `a3d96c35c10c655ddfa0e10c1d0d5e38644b762a`): Fable PASS, Sol
RETURN with four P1 blockers (verdict in
`reviews/REVIEW-sol-facade-d2b-v8.md`), all fixed in the head under review
(façade + payload-sampling only; the codec layouts are untouched):

1. **`RekeyRequired` locks inbound.** `accept_envelope` rejects any packet
   on a rekey-locked session before any ratchet touch — no decrypt, dedup,
   or commit; replayed gap packets cannot bump generation; post-gap
   applications are not exposed. Relay-level ACK actions unaffected.
2. **Control debt survives failure.** `control_debt_armed` no longer clears
   on staging; it clears only on confirmed delivery (`Stored`/`Duplicate`)
   or on a fresh peer payload reporting recovery (`issuer_outstanding < 24`
   — with the documented ordering that local congestion always re-arms, so
   the clear sticks only when the acceptor is itself below threshold).
   DeliveryUnknown/expiry/reopen re-stage at the next mutator.
3. **Post-advance signal + same-pass flush.** `issuer_outstanding` is now
   sampled AFTER the send's own advance (the 24th send reports 24 and
   signals), and the accept tail arms before staging, so newly armed debt
   flushes in the same pass — including outbound threshold crossings.
4. **Over-signaling cannot lock the victim.** Peer-signaled staging now
   requires NO receipt-kind send Pending at all (any high water), bounding
   an attacker to roughly one victim receipt per delivery-or-expiry cycle
   (the application-debt arm keeps the per-HCR rule — documented asymmetry).
   Sol's 33-packet probe is the regression test: at most one pending victim
   receipt at any time.

The v2–v8 histories follow unchanged.

## Remediation history (v8)

Version 7 (head `2d88375a7b166197f3ac3129aa97ea11d2b313bb`) was RETURNED by
Fable with one P1 (verdict in `reviews/REVIEW-fable-facade-d2b-v7.md`): the
control-debt arm keys off LOCAL congestion, but in natural lockstep traffic
the application sender is never locally congested (the receiver receipts
promptly), so Sol's v6 deadlock survives — arming needs the PEER's
congestion, which the wire didn't carry. The head under review fixes it
structurally:

- **`ClientPayloadV2` gains `issuer_outstanding: u64`** on both arms,
  sampled as `last_assigned_send_seq - peer_contiguous_high_water` at
  staging. Peer-reported, informational; lying is self-harming. The frozen
  HighWaterReceipt is untouched.
- **Dual arming of `control_debt_armed` (field 21):** local (v7, kept as
  the backstop for the both-stuck corner where no signal is on the wire)
  plus peer-signaled (any accepted payload reporting `issuer_outstanding
  >= 24` arms the acceptor). Staging, clearing, freshness gate, one-per-pass
  all unchanged.
- Lockstep convergence (in the module docs and proven by Fable's own repro
  as a 60-round test): once the receiver's receipts carry `>= 24`, the
  sender arms and counter-receipts, the receiver drains below 24 in one
  round trip, and low-signal payloads stop the arming. The both-stuck
  corner recovers via the local arm (test proves the wire is signal-free).
- Lying is bounded: over-signaling costs one idempotent receipt (in-flight
  guard, one-per-pass); under-signaling wedges only the liar's own budget.

The v2–v7 histories follow unchanged.

## Remediation history (v7)

Version 6 (head `2b8c0b758817766d04007163bfea6c36751a505f`) was RETURNED by
Sol with one P1 (verdict in `reviews/REVIEW-sol-facade-d2b-v6.md`): the v6
debt model made ReceiptLocked permanently unrecoverable under
one-directional traffic — receipt sends consume the budget but were never
acknowledged, so the receiving side wedged at 32 and its peer with it,
reproduced over a real relay. The head under review adds a bounded drain:

- **Threshold-armed control debt** (codec field 21 `control_debt_armed`):
  any successful accept (application or receipt) while the acceptor's
  outstanding is ≥ 24 — sampled at accept ENTRY or end — arms the flag.
  The owed rule gains a second arm: armed ∧ `HCR > marker` ∧ mode allows
  control ∧ capacity ∧ no in-flight coverage ⇒ stage one receipt and clear
  the flag. Uncongested sessions (outstanding < 24) behave exactly like v6
  (receipts never create debt). Ping-pong is impossible by construction
  (receipts with no new information cannot stage; one congested exchange
  round drains both sides below threshold and arming stops). Sol's
  reproduction now runs many rounds with progress each round and neither
  side ever locks.
- The entry-congestion sample is a documented, empirically forced
  deviation: post-drain-only sampling is vacuous (an ideal peer always ends
  accepts at 0 outstanding and never counter-receipts — the deadlock
  stands).
- §4 recovery is preserved: ReceiptLocked recovers through a valid receipt,
  and armed control debt stages once the mode recomputes.
- The stale accept-order comment is fixed (signature runs BEFORE dedup, as
  both reviewers noted; the stronger order).

The v2–v6 histories follow unchanged.

## Remediation history (v6)

Version 5 (head `e3849849b0bac34ed66d4eee2a5b6b5fd3723f3c`) was RETURNED by
Sol with four P1 interleaving blockers (verdict in
`reviews/REVIEW-sol-facade-d2b-v5.md`). The head under review replaces the
v5 quiescence mechanism with an explicit debt model and fixes all four:

- **Debt model (codec field 20 `receipt_debt_up_to`):** the highest consumed
  APPLICATION sequence; set only by `consume_inbound`, never by receipts —
  quiescence by construction, no marker-bump heuristics. Owed ⇔ debt >
  marker AND HCR > marker AND no in-flight receipt covering HCR. The marker
  (field 19) still advances only on Stored/Duplicate.
- **P1-1 reordered receipts:** a receipt whose high water regresses or
  repeats is a content no-op (`ReceiptIdempotent`) whose sequence/dedup
  progress COMMITS; only the update is rejected. Future high water still
  hard-errors. Sequence tracking can no longer wedge.
- **P1-2:** `stage_send` recomputes the mode from the new outstanding
  immediately after owed staging, before the application decision.
- **P1-3:** `stage_send` now returns `StageSendOutcome`
  (`Staged(action)` / `ReceiptFlushedRetry`) — when the application cannot
  be admitted after owed staging, the receipt-bearing candidate COMMITS and
  the caller gets an explicit retry outcome (public signature change,
  exported).
- **P1-4:** falls out of the debt model — a gap-filling receipt drains HCR
  past pre-existing consumed debt and the owed rule stages in the same
  pass; receipt-only exchanges still stage nothing.

The v2–v5 histories follow unchanged.

## Remediation history (v5)

Version 4 (head `844f6b1229a1a9ed275138725cf94bc08b008d4c`) was RETURNED by
BOTH reviewers (verdicts in `reviews/REVIEW-fable-facade-d2b-v4.md` and
`reviews/REVIEW-sol-facade-d2b-v4.md`) with four P1 blockers, all fixed in
the head under review:

1. **Lost receipts re-arm.** The marker (ActiveSession field 19, renamed
   `last_delivered_receipt_high_water`) now advances ONLY on
   `Stored`/`Duplicate` in `record_send_result` — never at staging, expiry,
   or DeliveryUnknown. Expiry or unknown-delivery of a pending receipt
   automatically re-owes it; the next eligible mutator re-stages with a
   fresh envelope at the 7-day send TTL (the 300 s window was wrong for
   receipts). SendRecord gained `kind` and `receipt_high_water` fields
   (codec amendment) so receipts are identifiable through their lifecycle.
2. **Quiescence.** Receipt-kind accepts never create receipt debt (the
   marker covers the receipt's own sequence); only debt that PREDATES the
   receipt may stage in an accept pass. Ping-pong is impossible by
   construction; an in-order exchange test proves both peers drain to idle.
3. **Control priority.** In `stage_send`, owed-receipt staging runs BEFORE
   the application insert; the body is inserted only if capacity remains
   (it errors immediately and is retryable — receipts were the silent-loss
   case).
4. **Fresh mode before staging.** Accept recomputes the budget mode from
   the fresh high water before owed staging (RekeyRequired dominance
   preserved), so `ReceiptLocked → ControlOnly` recovery stages in the same
   pass.

The v2–v4 histories follow unchanged.

## Remediation history (v4)

Version 3 (head `af78462718ddcd5bff5ccd8212fa08ed2fb499c6`): Fable PASS, Sol
RETURN (verdict in `reviews/REVIEW-sol-facade-d2b-v3.md`) — best-effort
receipt staging had no durable "receipt owed" marker, so a peer could wedge
in ControlOnly indefinitely. The head under review fixes it:

- Codec wire amendment: ActiveSession field 19
  `last_staged_receipt_high_water: u64` (ascending order preserved; codec
  validation requires it never exceeds `highest_contiguous_received_seq`).
- A receipt is owed iff `highest_contiguous_received_seq >
  last_staged_receipt_high_water`; every clock-taking mutator stages the
  owed receipt once capacity and mode allow (coalesced; one per current
  HCR). The marker updates on staging. Skipped receipts can no longer be
  lost.
- Sol's closure regression exists: consume every inbound while full →
  prune → owed receipt stages → drives through the real relay → the peer's
  high water advances and it stages again.
- Behavior note for review: the owed rule also stages receipts eagerly at
  accept time when capacity exists (accept_envelope is a staging point),
  subsuming the old per-consume staging — strictly better coalescing.

The v2/v3 histories follow unchanged.

## Remediation history (v3)

Version 2 (head `eb2020e8beb178b2e933ef4d62fb9f0b5d1637e1`) was RETURNED by
Sol with four blockers (verdict in `reviews/REVIEW-sol-facade-d2b-v2.md`),
all fixed in the head under review:

1. `record_ack_result` runs the FULL binding verification (token, fields,
   signature) for every outcome including `Failed` — a forged action can no
   longer be accepted as a failed result.
2. Receipt staging inside `consume_inbound` is best-effort: skipped
   silently when the mode blocks control or the send array is at the bound,
   so a consume can never roll back at the 32-send limit (receipts are
   coalesced control; the next HCR advance stages a newer one). The ACK
   bound is checked before mutation and re-checked after the expiry sweep.
3. The pre-key path requires `pending.valid_until > now` before consuming
   the OTK — an expired offer can no longer establish a session.
4. All façade-minted requests now match the relay's acceptance windows:
   300 s for registration/fetch/ACK (registration_action gained a `now`
   parameter — a public-signature change to a D1-passed family, flagged for
   your attention), 7-day TTL for sends.

The v2 history follows unchanged.

## Remediation history (v2)

Version 1 (head `cf891ea336573869dc51efd6f632af2fcd01392f`) was dual-RETURNED
(verdicts transcribed in `reviews/REVIEW-combined-codec-v5-d2a-d2b.md`):

1. Both reviewers: `record_ack_result` removed the ACK intent without
   validating the presented request. The amended head requires
   `message_id == token == intent message_id`, exact
   queue/packet_hash/valid_until equality with the durable fields, and a
   valid `AckRequest` signature against the receive-capability public key,
   all in the step-2 bounds before staging.
2. Sol: missing public exports — lib.rs now re-exports every type appearing
   in the façade's public signatures, with a compile-level test naming each
   from the external crate path.
3. Sol: expired pending ACK intents were never swept, exhausting the bounded
   ACK slots — clock-taking mutators now remove expired Pending intents and
   transition their dedup records to `Expired` (high-water/budget state
   untouched).

Review `secure-messenger-lab` at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Fable and Sol; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own. Untracked `reviews/REVIEW-*` / `RESULTS-*` files may be visible — they
are reviewer artifacts for other legs; ignore them, do not open them.

This is an adversarial review of the façade's inbound leg: `fetch_request`, `accept_envelope`,
`pending_inbound`, `consume_inbound`, `ack_actions`, `record_ack_result`, receipt issuance and
processing, terminal-record pruning, and the escape-inflation pre-check. Prior legs: boundary
(dual-PASS `f056cac`), façade D1 (dual-PASS `1434452`), D2a (Fable PASS `16adc90`; Sol pending).
The codec is under review at `d8795fa` — it is NOT in scope here; build assumptions on it are.

## In scope

- `src/persistent/mod.rs` — the six new families and their operations.
- `src/payload.rs` — the escape-inflation pre-check (D2a carry-over).
- `src/persistent/tests.rs` — the in-crate spine: full two-client conversation over a real
  in-memory relay, receipt/ACK flows, gap-induced `RekeyRequired`, pruning.
- `tests/persistent_client.rs` — integration additions.

## §4 claims under review (attack each)

1. `accept_envelope` ordering: bounds → dedup (no ratchet touch on duplicates) → outer signature
   against our mailbox send public key → Olm decode → pre-key establishment (transcript = our
   consumed prekey bundle, pending-prekey record cleared) or established decrypt → strict payload
   decode (conversation/epoch/outer message ID) → sequence tracking (HCR advance + contiguous
   drain; bounded out-of-order set; duplicate reject) → record writes → mode recompute with
   `RekeyRequired` dominating.
2. Gap failures: a previously unseen, peer-authenticated, current-epoch packet producing
   `TooBigMessageGap`/`MissingMessageKey` durably commits `RekeyRequired`; ordinary MAC/encoding
   failures never do. The in-crate test engineers a genuine `MissingMessageKey` (past the 40-key
   horizon) and asserts mode, generation+1, untouched HCR, persistence across reopen, and staging
   lockout.
3. Receipts: issued on consume when HCR advances (control advance, Ready/ControlOnly only,
   coalescing limit documented); signed with our Ed25519 over `session-high-water/v1` in the
   codec's part order; accepted per `old < high_water <= last_assigned_send_seq`, equality
   idempotent (dedup still written), regression/future rejected; the new high water commits in the
   same mutation before any unlocked send permission is exposed.
4. ACKs: `consume_inbound` frees the inbound slot and creates the ACK intent; `ack_actions` signs
   exact requests (token = message_id); `record_ack_result` Deleted/AlreadyGone ⇒ intent removed,
   dedup → Acked; Failed ⇒ no mutation.
5. `fetch_request` is read-only signing (no durable record, no result family in §2) — documented
   reading.
6. Pruning: terminal send records removed only after `expires_at + 7 days`; Pending/DeliveryUnknown
   never pruned; budget/high-water invariants untouched.

## Documented decisions / deviations

- `commit_verified_contact` gained a `conversation_id` parameter (the offer carries none; two
  façade clients could not otherwise agree on one). Single-assignment at verified-contact commit.
- Inbound tests live in-crate: crafting envelopes into a client's mailbox needs its send keypair,
  which the façade never exports. The spine uses real façades + real relay; the gap test's sender
  is a raw vodozemac peer (the §4 budget makes the 40-key horizon unreachable via honest staging).
- `InboundView` carries `accepted_at`/`expires_at` (the frozen InboundRecord layout has no
  `sent_at`).
- Receipts ride the D2a send machinery as ordinary Pending SendRecords with receipt payloads.

## Required attacks

1. duplicate/replay: same message ID, same packet digest, cross-epoch digest — none may touch the
   ratchet;
2. forgery: wrong sender signature, expired envelope, wrong variant, non-pre-key without session,
   pre-key with session;
3. sequence confusion: out-of-order within and beyond the set bound, HCR drain correctness,
   duplicate sequence;
4. receipt confusion: regression, future, wrong epoch/conversation/issuer, replayed receipt
   (idempotent path must still dedup), receipt processing while ReceiptLocked/RekeyRequired;
5. gap → RekeyRequired → recovery attempt: everything stays locked (rebootstrap is out of scope);
6. crash between every mutator pair; token confusion on ACK results; commit-failure →
   ReconcileRequired;
7. pruning edges: exactly at `expires_at + 7d`, Pending never pruned, pruning under the 32-slot
   bound pressure.

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Return `PASS` or `RETURN` against the exact head SHA. A `RETURN` must list blocking findings only,
each with a concrete reproduction or source reference.
