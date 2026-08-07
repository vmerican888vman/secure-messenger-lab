# Sol review — façade D2b v15 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), worktree
  `sml-review-d2b-v15-sol-5843bfa`, detached, exact and clean. No
  `reviews/REVIEW-*` or `RESULTS-*` artifact was opened. Transcribed from
  the user's paste.
- **Head SHA reviewed:** `5843bfa52c202b13bf5b0eebe75b09034ecd1dc2`.
- **Verdict: RETURN** — one P1, one P2.
- **Gates:** all 283 tests, clippy `-D warnings`, formatting and
  `git diff --check` passed.

## P1 — `flush_control` still commits blocked no-op ticks

`control_work_pending` sees eligible debt but does not check for an
unresolved control receipt, so `maybe_stage_owed_receipt` then refuses to
stage while `flush_control` commits anyway. Reproduced at the exact head:

- `DeliveryUnknown` receipt: `flush_control(NOW + 1)` returned `false`,
  generation advanced 8 → 9.
- Pending older receipt with newer debt: returned `false`, generation
  advanced 9 → 10.

This reopens the transient commit failure → `ReconcileRequired` hazard
the short-circuit was added to close.

**Closure offered:** mirror the unresolved-control guard before entering
`mutate`, with Pending and DeliveryUnknown regressions asserting
unchanged generation and no commit attempt.

## P2 — the 66-test migration is not yet a reliable gate

- `over_signaling_cannot_lock_the_victim` makes each response optional;
  answering once and ignoring the remaining 31 cycles passes.
- The promised eight-cycle churn may immediately `break`.
- The 40-record total quota is never exercised — the bound test builds
  only 32 applications, so a total-cap regression to 32 passes.
- Same-second cooldown deferral is not asserted before
  `flush_control(NOW + 1)`.
- The claimed explicit debt substitution is missing at one site.
- The field-19 byte-flip test's `end - 36` offset is stale after fields
  22/23, so it causes structural rejection instead of testing the
  intended invariant.
- The v15 dedup test accepts at `NOW`, not `past`, and explicitly permits
  failure.

## Flagged-item rulings

- **Unbounded shared sequence distance:** non-blocking. Real resources
  remain independently bounded, and both allocation paths use checked
  increment before encryption.
- **`SCHEMA_VERSION == 1`:** non-blocking safety-wise but migration debt.
  Exact required fields/counts make old layouts fail closed without
  silent aliasing. Bump it before promising store compatibility.

Both rulings agree with Fable's independent conclusions at v14/v15.

## Round outcome

Fable PASSed the same head (`reviews/REVIEW-fable-facade-d2b-v15.md`);
this RETURN carries the round. Both findings are remediated in v16 — see
the v16 history in `reviews/PROMPT-independent-phase2-facade-d2b.md`.
