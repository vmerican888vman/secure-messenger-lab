# Sol review — façade D2b v4 — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), quoted worktree `sml-review-d2b-v4-844f6b1`
  detached and clean before review. Transcribed from the user's paste.
- **Head SHA reviewed:** `844f6b1229a1a9ed275138725cf94bc08b008d4c`.
- **Verdict: RETURN** — four P1 blockers.

1. **Field 19 marks a receipt as covered when merely staged.** After expiry
   or `DeliveryUnknown`, its retransmittable packet is removed but the
   marker suppresses replacement, leaving a ControlOnly peer permanently
   wedged. Closure: track confirmed receipt coverage or re-arm on
   expiry/removal; test offline and unknown-delivery recovery.
2. **Receipts acknowledge receipts forever.** Every receipt advances
   inbound sequence, then the common accept tail stages an owed receipt
   again; the ping-pong fills both 32-slot outboxes and prevents normal
   sends until pruning. Closure: define non-recursive receipt/control
   semantics and prove two peers drain to idle.
3. **One-at-a-time pruning can starve an owed receipt.** `stage_send`
   prunes, inserts the application, then attempts the receipt; when one
   slot opens, the application refills it and the receipt remains skipped.
   Closure: reserve/prioritize a control slot and test staggered expiry
   under continuous application traffic.
4. **ReceiptLocked recovery uses stale mode.** Receipt processing lowers
   outstanding traffic, but owed staging runs before mode recomputation, so
   it skips an otherwise stageable receipt after `ReceiptLocked →
   ControlOnly`. Closure: recompute before owed staging while preserving
   `RekeyRequired`.

Checks passed (`cargo test --locked --all-targets`, Clippy `-D warnings`,
`cargo fmt --check`, `git diff --check`); they do not address these semantic
failures. No tracked files were changed.
