# Fable review — façade D2b v9 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), worktree clean at the exact SHA;
  full verdict also in their own `REVIEW-fable-facade-d2b-v9.md` artifact.
  Transcribed from the user's paste.
- **Head SHA reviewed:** `7eab05bb0cd887e49b9cbff7f4a4dd2b2047b9a2`.
- **Verdict: PASS** — no blocking findings.

All four v8 blockers confirmed genuinely fixed, each with a real regression
test:

1. The `RekeyRequired` inbound lock sits at the top of `accept_envelope`'s
   bounds — before decrypt, dedup, or any commit. The gap test engineers a
   real `MissingMessageKey` past the 40-key horizon and asserts durable
   mode, generation+1 exactly once, replay-no-recommit, post-lock
   applications never exposed, and persistence across reopen.
2. Control debt survives failure: the flag clears only on
   `Stored`/`Duplicate` of a receipt-kind send or a fresh low-signal
   payload, with the local-congestion clause running after the signal
   clause so the clear sticks only when the acceptor is actually drained.
   Proven through DeliveryUnknown, expiry, and crash/reopen.
3. Post-advance sampling at both staging sites; the accept tail arms
   before staging so newly armed debt flushes same-pass. The 60-round
   lockstep test proves signal-driven convergence; the both-stuck test
   proves the local-arm backstop against a provably signal-free wire.
4. The control arm's no-receipt-pending-at-all guard holds against Sol's
   33-packet probe: at most one pending victim receipt, mode stays Ready,
   victim's application sends unaffected.

The full §4 claim set was re-attacked (accept ordering, receipt confusion,
ACK token binding including the Failed-never-mutates path, fetch read-only,
pruning edges, crash windows) — no blockers found.

## Non-blocking observations

- No dedup pruning exists in this leg; the codec's 4,096-record cap is a
  conversation-lifetime inbound ceiling until rebootstrap lands (the design
  defers dedup retention to that leg) — worth tracking.
- `consume_delivery_unknown` skips terminal pruning (documented asymmetry).
- A peer sending a future-high-water receipt permanently wedges only its
  own inbound stream (self-harming, no victim impact).

Gates at the head: 275 tests across four binaries, 0 failed; clippy
`-D warnings` clean; fmt clean.
