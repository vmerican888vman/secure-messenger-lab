# Sol review — façade D2b v9 — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), clean pinned worktree at the exact SHA;
  transcribed from the user's paste.
- **Head SHA reviewed:** `7eab05bb0cd887e49b9cbff7f4a4dd2b2047b9a2`.
- **Verdict: RETURN** — four P1 blockers.

1. **Cross-epoch packet digests are not deduplicated before ratchet use.**
   Digest matching is limited to the active epoch; a retired-epoch packet
   with a fresh outer ID/signature reaches `decrypt`, where a gap error
   permanently locks the new session (vodozemac classifies large gaps
   before MAC verification). Closure: reject retained digests globally and
   require authenticated current-epoch provenance before committing
   `RekeyRequired`.
2. **Reordered truthful low congestion signals erase a later high-signal
   arm.** The flag is overwritten for every accepted payload while bounded
   reordering is accepted. Reproduced: deliver receipt seqs 2–24 first
   (24 arms), then delayed seq 1 (low signal) — HCR drains to 24, the arm
   is cleared, no counter-receipt is owed, the peer remains `ControlOnly`.
   Closure: version the signal/arm by sender-sequence freshness.
3. **`accept_envelope` does not sweep expired sends before receipt
   staging.** An expired Pending control receipt remains "in flight" under
   the any-pending guard, so receipt-only traffic after outage/reopen
   cannot re-stage it. Reproduced in a disposable archive. Closure: sweep
   send expiry before the accept tail, or make coverage clock-aware.
4. **A delayed successful result for an older receipt clears newer control
   debt unconditionally.** If newer congestion arrives while that receipt
   is pending, the older delivery advances only its older marker yet clears
   the global arm; HCR can remain ahead with no replacement receipt.
   Closure: clear only debt covered by the confirmed receipt.

Checks passed (`cargo test --locked --all-targets`, Clippy `-D warnings`,
`cargo fmt --check`, `git diff --check`); integrity evidence, not approval.
