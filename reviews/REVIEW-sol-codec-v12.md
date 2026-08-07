# Sol review — client-state codec v12 — VERDICT: PASS

- **Reviewer:** Sol (gpt-5.6-sol), checkout detached, clean and pinned
  throughout. No `reviews/REVIEW-*` contents were read. Transcribed from
  the user's paste.
- **Head SHA reviewed:** `8fab295e4efb130c43d9107b445bcb7a9fadb31b`.
- **Verdict: PASS** — no blocking findings in `src/state/`.
- **Gates:** 291 tests, clippy `-D warnings`, stable formatting,
  `git diff --check` all passed.

## Findings closed

- **P1 closed.** Commitment verification precedes kind-dependent logic on
  both decode (`records.rs`) and encode validation (`validate.rs`).
- **P2 closed.** The regression selects by retired epoch and asserts both
  twins are retired. Sol ran the hypothetical retired-epoch exemption in
  a disposable copy: it failed deterministically in **50/50 runs** —
  against the old test's measured 2-in-10 catch rate.
- **`363d2b8` claims verified:** corrected documentation, genuinely dead
  helper removal, invalid wire-kind coverage, and field-12 splice
  coverage.

## Scope of the approval

> This PASS applies only to `src/state/` at the exact SHA; it does not
> broaden approval to other legs.

## Round outcome — the codec leg CLOSES

Fable PASSed the same head (`reviews/REVIEW-fable-codec-v12.md`).
**Dual PASS at `8fab295`** — the `ClientStateV1` TLV codec and validation
leg is closed.

Note the Phase 3 ruling (`docs/phase3-post-quantum-decision.md`) retires
this layout in favour of a `ClientStateV2`/MLS path, and states that
existing PASSes remain valid only for their exact Olm code and do not
transfer to MLS. The reviewed V1 path and its tests are preserved until
the MLS replacement independently passes, then retired explicitly.
