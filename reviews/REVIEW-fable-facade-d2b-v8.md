# Fable review — façade D2b v8 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), worktree clean and pinned at the
  exact SHA. Transcribed from the user's paste.
- **Head SHA reviewed:** `a3d96c35c10c655ddfa0e10c1d0d5e38644b762a`.
- **Verdict: PASS** — no blocking findings.

## Coverage (per the reviewer)

- Gates: 272 tests green, clippy `-D warnings` clean, `cargo fmt --check`
  clean; no reviewer artifacts opened.
- The v7→v8 diff is tightly scoped to the returned P1. `issuer_outstanding`
  sampling cannot underflow (`apply_receipt` hard-errors
  `high_water > last_assigned_send_seq`); the field is required with strict
  canonical decode (missing/renamed/extra all reject); the frozen
  `HighWaterReceipt` is untouched; the escape-inflation pre-check still
  holds.
- Dual arming: peer-signal and local samples compose by OR (independence
  test proves neither suppresses the other). Trust analysis confirmed: the
  value rides inside Olm encryption under the peer's outer signature;
  over-signaling is bounded 1:1 by the freshness gate and in-flight guard;
  under-signaling only starves the liar; a flooding peer gains nothing not
  already possible in prior versions. Gap-failure path never processes the
  signal, preserving `RekeyRequired` dominance.
- The v7 P1: the application sender now arms off the receiver's reported
  congestion, counter-receipts over its receipt sequences, and drains it in
  one round trip; the counter-receipt's low outstanding prevents ping-pong.
  The 60-round lockstep test asserts per-round progress, no ReceiptLocked,
  and an actual threshold crossing (cannot pass vacuously). The both-stuck
  test proves the local arm alone recovers the pair with a provably
  signal-free wire. Quiescence below threshold is identical to v6.

## Residual corner (judged non-blocking)

A peer reaching ReceiptLocked with all congested-era sends expiring
undelivered (a 7-day total transport outage) tears the contiguous water
permanently — RekeyRequired/rebootstrap territory by the §4 design and
explicitly out of scope for this leg; a property of the frozen model, not
a v8 defect.
