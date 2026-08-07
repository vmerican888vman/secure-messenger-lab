# Sol review — façade D2b v8 — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), clean detached head; transcribed from the
  user's paste.
- **Head SHA reviewed:** `a3d96c35c10c655ddfa0e10c1d0d5e38644b762a`.
- **Verdict: RETURN** — four P1 blockers.

1. **`RekeyRequired` does not lock the inbound ratchet.** `accept_envelope`
   continues into decrypt after rekey is set, and gap failure commits no
   dedup entry — a probe replayed the same gap packet and incremented
   generation again; a later valid application was also accepted and
   exposed through `pending_inbound` while still `RekeyRequired`. Closure:
   gate inbound processing before ratchet once rekey is set; add replay and
   post-gap packet regressions.
2. **Control-only receipt debt is lost on failure.**
   `control_debt_armed` clears on staging, while only `Stored`/`Duplicate`
   advances confirmed coverage; `DeliveryUnknown`, expiry, or removal
   leaves no debt that can re-stage the required counter-receipt. Closure:
   preserve control debt until confirmed delivery; cover unknown/expiry/
   reopen paths.
3. **Honest traffic can strand at the `Ready → ControlOnly` boundary.**
   Payloads sample `issuer_outstanding` before their own send advance (the
   24th receipt reports 23), and the accept tail stages before arming, so
   a newly armed debt flushes only at the next mutator — a 24-round
   real-relay probe left the sender `ControlOnly` and unable to reverse
   direction. Closure: signal the post-send count and flush newly armed
   debt in the same pass, including outbound threshold crossings.
4. **Peer-reported over-signaling can lock the victim.** Fresh
   authenticated receipt-only packets with idempotent `high_water=0` and
   `issuer_outstanding >= 24` repeatedly arm control debt, and the
   in-flight guard only matches the current HCR — a 33-packet probe
   produced 32 pending victim receipts and `ReceiptLocked` with no
   application debt, contradicting the brief's "self-harming" claim.
   Closure: coalesce peer-signaled control debt across in-flight receipts
   and add the regression.

## Evidence

`cargo test --locked --all-targets`, Clippy `-D warnings`,
`cargo fmt --check`, `git diff --check` all passed. No `reviews/REVIEW-*`
artifacts opened.
