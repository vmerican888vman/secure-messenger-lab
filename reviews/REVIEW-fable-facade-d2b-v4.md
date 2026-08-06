# Fable review — façade D2b v4 — VERDICT: RETURN

- **Reviewer:** Fable (claude-fable-5; write-up named
  `REVIEW-claude-facade-d2b-v4.md` in the review worktree). Head verified,
  worktree clean; transcribed from the user's paste.
- **Head SHA reviewed:** `844f6b1229a1a9ed275138725cf94bc08b008d4c`.
- **Verdict: RETURN**

The v2/v3 remediations are correctly in place (field 19 encoded and
validated, full ACK binding for every outcome, expired-prekey path closed,
Sol's closure regression exists and passes). But the v4 owed-receipt rule
itself has two blocking defects.

## Blocker 1 — a lost staged receipt permanently satisfies the owed marker

`maybe_stage_owed_receipt` stages receipts with a hardcoded 300-second
validity (the registration/fetch/ACK window, not the 7-day send TTL), and
`stage_receipt` advances `last_staged_receipt_high_water` at staging time
with no path that ever rolls it back; the expiry sweep just marks the
record Expired, and SendRecord has no kind field so it couldn't identify a
receipt anyway. Deterministic repro, no crash needed: A accepts B's 24
sends promptly and enqueues its receipts (relay expiry = staging+300s);
B polls 6 minutes later; the relay has purged them; A's marker equals its
HCR forever, nothing is ever re-staged, B is permanently wedged in
ControlOnly — the exact liveness class the v3 head was returned for, moved
one lifecycle step later. The crash-between-mutators variant (stage, die,
reopen after 300s) hits the same hole.

## Blocker 2 — receipts acknowledge receipts, with no quiescent state

Receipts consume tracked sequences, `track_sender_sequence` runs for every
payload kind, and accept stages owed receipts — so every in-order delivered
receipt advances the receiver's HCR and triggers a counter-receipt,
forever. Each round appends a DedupRecord on both sides; the façade never
prunes dedup and MAX_DEDUP is 4,096, so an idle-but-syncing pair eventually
makes encode fail inside every accept_envelope — permanent inbound death
with rebootstrap out of scope. Both v4 receipt-delivery tests dodged this
by delivering receipts out of order; in-order delivery — the normal case —
is untested. The reviewer's closure note: dropping the receipt-arm of
accept as a staging point closes the loop without reopening the v3 wedge.

## Non-blocking notes

- Signature-before-dedup ordering deviates from the documented claim
  (harmless, arguably better).
- "Strictly better coalescing" overstates the eager rule (N accepts → N
  receipts).
- Regression-rejected receipts are redelivered by the relay until TTL since
  they're never deduped or ACKed.
