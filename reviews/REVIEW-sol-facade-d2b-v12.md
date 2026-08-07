# Sol review — façade D2b v12 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), detached worktree
  `sml-review-d2b-v12-sol-5dbcca7`, clean at the requested SHA. No
  reviewer artifact informed the verdict; a worker that accidentally
  exposed an artifact snippet was discarded. The disposable repro archive
  was moved to Trash. Transcribed from the user's paste.
- **Head SHA reviewed:** `5dbcca73d2c918420747bf222e44383439b5b30e`.
- **Verdict: RETURN** — two P1 blockers.
- **Gates:** `cargo test --locked --all-targets` (280), Clippy, fmt and
  `git diff --check` all passed. Evidence integrity only.

**Confirmed good:** the v12 `message_digest` split itself holds —
canonical inner `Message` bytes correctly collapse PreKey/Normal aliases
while `packet_digest` remains the signed envelope/ACK binding. Sol found
no v12-specific false reject absent a cryptographic hash/RNG collision.

## Blocking findings

### P1-1 — the reciprocity gate can deadlock a gap-free, honest peer

`accept_staging_tail` suppresses a new peer signal until the peer's
contiguous receipt water covers the prior response sequence
(`mod.rs:2529`), then records that response sequence (`mod.rs:2560`). But
receipt-only acceptance intentionally creates no receipt debt
(`mod.rs:2637`).

Reproduced over the real in-memory relay in a disposable archive:

1. B truthfully signals at 24 outstanding; packet 24 is delayed.
2. A consumes packets 1–23 and receipts them, so B recovers before A sees
   the stale signal.
3. A then accepts packet 24, sends response sequence 2, and sets
   `control_signal_response_at = 2`.
4. B accepts that response while uncongested, so it legitimately sends no
   counter-receipt; A only sees B's earlier receipt at water 1.
5. B later reaches 24 outstanding again. A suppresses the new truthful
   signal (`1 < 2`), has no local congestion, and — before application
   consumption — stages no receipt. B remains `ControlOnly`.

**Closure offered:** add this delayed-signal/quiescence regression and
redesign the response proof so an honest peer can acknowledge the exact
response without creating recursive control traffic.

### P1-2 — dedup capacity permanently blocks fresh legitimate inbound after 4,096 records

There is no `MAX_DEDUP` precheck or eligible-record reclamation before
ratchet work (`mod.rs:1170`); accepted packets unconditionally append a
dedup record (`mod.rs:2596`). The candidate is serialized only afterward
(`mod.rs:1755`), where the codec rejects record 4,097
(`state/mod.rs:262`). ACK completion only changes the state to `Acked`;
it never removes the record (`mod.rs:1377`). This violates the stated
before-decrypt backpressure and seven-day eligible-reclamation rule
(`docs/persistence-spike-design.md:138`).

**Closure offered:** add pre-decrypt full-set refusal plus safe
expiry/ACK reclamation and drain/resume tests.

## Round outcome

Fable returned `PASS` at the same head
(`reviews/REVIEW-fable-facade-d2b-v12.md`); this RETURN carries the round.

P1-2 is fixed in v13. **P1-1 is deliberately NOT fixed** — the v12
reciprocity gate is reverted rather than replaced, because three
successive local bounds have failed on this arm for the same structural
reason, and bounding it needs a §4 decision. See the v13 note at the top
of `reviews/PROMPT-independent-phase2-facade-d2b.md`.
