# Independent review — façade leg D2b: inbound path, receipts, ACKs

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
