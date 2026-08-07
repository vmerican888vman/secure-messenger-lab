# Sol review — façade D2b v16 — VERDICT: PASS

- **Reviewer:** Sol (gpt-5.6-sol), worktree
  `sml-review-d2b-v16-sol-a33d2ba`, clean, detached and pinned to the
  exact SHA throughout. No `reviews/REVIEW-*` artifact was opened.
  Transcribed from the user's paste.
- **Head SHA reviewed:** `a33d2ba5a109a03d6b76fd9f0926e45041441f62`.
- **Verdict: PASS** — no blocking findings.
- **Gates:** fresh source rebuild — 234 library, 5 OTK, 19
  persistent-client, 27 private-store tests; clippy `-D warnings`,
  formatting and `git diff --check` all passed.

## Confirmed by breaking the code

- The shared unresolved-control predicate is correctly used by BOTH the
  pre-flight (`mod.rs:1339`) and receipt staging (`mod.rs:3105`). The
  generation regression covers Pending and `DeliveryUnknown`; removing
  the guard made it fail with generation 9 → 10.
- The seven P2 test holes are closed. The 40/32/8 quotas are enforced by
  validation (`validate.rs:133`), and reverting `MAX_SENDS` to 32 made
  the new quota test fail.
- The field-19 offset correctly derives `60 + 8 × ledger_length`,
  targeting the field's high byte, with the direct-state marker
  assertion confirming the invariant.

## Non-blocking precision note (addressed)

`32+9` totals 41, so that case alone did not isolate the eight-control
limit — it was rejected by the total. The 32-cycle over-signalling
regression independently enforces `<= 8` and fails if the control cap
becomes nine.

**Addressed in the round-closing commit:** the quota test now uses
`31+9` (total 40, so only the control cap can reject it) plus a `31+8`
positive control proving the negative case is not vacuous. Verified to
fail when `MAX_CONTROL_SENDS` is raised to 9.

## Round outcome — D2b CLOSES

Fable PASSed the same head (`reviews/REVIEW-fable-facade-d2b-v16.md`).
**Dual PASS at `a33d2ba`** — the façade D2b leg is closed after sixteen
versions.
