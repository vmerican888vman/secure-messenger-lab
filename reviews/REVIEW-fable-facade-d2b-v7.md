# Fable review — façade D2b v7 — VERDICT: RETURN

- **Reviewer:** Fable (claude-fable-5), worktree clean at the exact SHA;
  transcribed from the user's paste.
- **Head SHA reviewed:** `2d88375a7b166197f3ac3129aa97ea11d2b313bb`.
- **Verdict: RETURN** — one P1 blocker.

## P1 — threshold-armed control debt does not drain lockstep one-directional traffic; Sol's v6 deadlock survives

The v7 arm fires on the acceptor's OWN outstanding (entry and end
samples). But the party that must counter-receipt to drain the receiver is
the application sender, whose outstanding is held near zero precisely
because the receiver receipts promptly. In the ordinary interactive
pattern (consume each message as it arrives), the sender never arms,
never counter-receipts, and the receiver's receipt sends accumulate one
per round against a `peer_contiguous_high_water` that never moves.

Reproduced (one staged body per round, real façades, real relay): A walks
Ready → ControlOnly (24) → ReceiptLocked (32) with `armed 0`
throughout; B ends ControlOnly at 24 refusing sends. No application
traffic possible in either direction, permanently — verbatim the v6 P1
under a more natural traffic pattern than the shipped repro. The shipped
test misses it because `flood_round` has B batch up to 40 sends before A
reads anything, so B is congested at its accepts and arms; the fix is
only effective in that bursty regime.

**Structural gap:** arming is conditioned on the arming side's congestion,
but the information needed is the peer's. Nothing on the wire tells the
sender the receiver is starving, and nothing lets a starving receiver
ask. The reviewer's closure direction: the receipt (or payload) should
carry the issuer's own outstanding/needs-receipt signal, so the peer arms
on that rather than a local sample — or the marker/debt accounting must
stop charging receipts against the same budget they exist to drain.

## Non-blocking notes

- Field 21 is validated as a bit; the
  `last_assigned_send_seq - peer_contiguous_high_water` subtractions
  cannot underflow (apply_receipt and the load-time re-validation).
- The accept-order comment fix is correct (signature genuinely runs
  before dedup).
- Two v7 assertions pin the entry sample's re-arm as intended; the flag's
  steady state under congestion is "always armed" — worth stating plainly
  in the security narrative.
