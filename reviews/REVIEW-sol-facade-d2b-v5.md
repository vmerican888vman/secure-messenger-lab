# Sol review — façade D2b v5 — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), worktree clean at the exact SHA; transcribed
  from the user's paste.
- **Head SHA reviewed:** `e3849849b0bac34ed66d4eee2a5b6b5fd3723f3c`.
- **Verdict: RETURN** — four P1 blockers.

1. **Reordered legitimate receipts can permanently wedge sequence
   tracking.** A newer receipt arriving first advances
   `peer_contiguous_high_water`; the older receipt needed to close the
   receive-sequence gap is then rejected as a regression, and because the
   error discards the candidate, its ratchet, dedup, and sequence
   advancement never commit. Retries fail forever; a real-relay probe
   reproduced HCR pinned at 0. Closure: deliver receipt seq 2 before seq 1
   and require sequence progress + receipt idempotence without weakening
   future-receipt rejection.
2. **Receipt staging can cross the `ControlOnly` threshold and still admit
   an application.** `stage_send` checks `Ready` only before staging; an
   owed receipt can raise outstanding 23 → 24, but mode is not recomputed
   until after the application is also inserted at 25. Closure: at 23
   outstanding with receipt debt, the receipt may stage but the application
   must be rejected.
3. **One freed slot does not durably go to the priority receipt.** The
   candidate prunes one record, fills it with the receipt, then returns
   `Storage` because no application slot remains; `mutate` discards the
   whole candidate (the regression explicitly expects no pending receipt
   afterward). Repeating before another tombstone expires loops without
   progress. Closure: the receipt must commit while the application returns
   a retryable failure.
4. **A gap-filling receipt can strand already-consumed application debt.**
   Application seq 2 accepted and consumed before receipt seq 1; accepting
   seq 1 drains HCR to 2, but the quiescence tail sets the marker only to 1
   and skips staging (`owed_before` false), leaving no inbound or pending
   receipt to trigger recovery. Closure: this reordered flow must stage
   HCR 2 while pure receipt-only exchanges still quiesce.

Checks passed (`cargo test --locked --all-targets`, Clippy `-D warnings`,
`cargo fmt --check`, `git diff --check`); they do not cover these
interleavings. No `reviews/REVIEW-*` artifacts were opened.
