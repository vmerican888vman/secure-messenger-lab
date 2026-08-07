# Sol review — façade D2b v6 — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), worktree clean at the exact SHA; transcribed
  from the user's paste.
- **Head SHA reviewed:** `2b8c0b758817766d04007163bfea6c36751a505f`.
- **Verdict: RETURN** — one P1 blocker.

All four v5 P1s confirmed genuinely fixed (quiescence by construction,
`ReceiptIdempotent` commits progress while rejecting only the update, mode
recomputed before the application decision, `ReceiptFlushedRetry` commits
honestly). Forgery, replay, cross-epoch digest, sequence confusion,
future/regressed/wrong-issuer receipts, gap→RekeyRequired, ACK token
confusion and pruning edges all held.

## P1 — the debt model makes ReceiptLocked permanently unrecoverable under one-directional traffic

§4 states ReceiptLocked recovers through a valid receipt. In this head, a
client that only receives application traffic reaches ReceiptLocked and can
never leave it: every staged receipt consumes the shared send counter
(`last_assigned_send_seq`), outstanding decreases only via an applied
receipt moving `peer_contiguous_high_water`, and the peer stages a receipt
only when it has debt — which receipts never create. So the receiver's
receipt sends are never acknowledged; it walks to ControlOnly at 24 and
ReceiptLocked at 32, where receipt staging itself blocks; durable across
reopen, and the peer wedges too since no receipt can ever be staged to it.
Reproduced with real façades over a real in-memory relay (clock advanced
15 days per round so tombstone pruning keeps arrays clear): A ends
ReceiptLocked, assigned 32, peer_hw 0, HCR 40, debt 40, marker 32; B never
counter-receipts. Batching consumes changes only the constant.

Why the suite missed it: the budget tests reach the corner by hand-editing
state and always leave a fabricated peer receipt available to unlock; no
test drives to the lock through the real relay.

**Closure direction given:** give control advances a drain path — e.g. let
a received receipt owe a counter-receipt when the receiver's own
outstanding has crossed a threshold (bounded, so it cannot ping-pong), or
stop letting control sends consume the drainable budget — rather than more
marker bookkeeping.

## Non-blocking observations

- Dedup records are never pruned (MAX_DEDUP 4,096 becomes a hard encode
  failure on a long enough session; out of this leg's claims).
- The brief's stated accept ordering is inverted in code (signature before
  dedup — the stronger order; claim/doc mismatch only).
