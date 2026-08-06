# Sol review — façade D2b v3 — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), pinned worktree `sml-review-d2b-v3-af78462`,
  clean detached at the exact SHA. (Transcribed from the user's paste.)
- **Head SHA reviewed:** `af78462718ddcd5bff5ccd8212fa08ed2fb499c6`.
- **Verdict: RETURN**

## Blocking finding

**P1 availability/liveness:** `consume_inbound` silently skips receipt
staging when the 32-send array is full, and there is no durable "receipt
owed" marker and no other `stage_receipt` caller. Reproduction: A has 32
retained terminal sends but is `Ready`; B sends 24 applications and becomes
`ControlOnly`. A accepts and consumes all 24 while its send array is full,
so every receipt is skipped. After pruning frees capacity, no inbound
remains to trigger staging; B remains `ControlOnly` indefinitely. Reproduced
with a targeted exact-head archive test. The existing regression masks the
defect by deliberately retaining another inbound until after pruning.

**Closure required:** durably retain the latest owed HCR and stage/retry it
when capacity returns. Add a regression that consumes every inbound while
full, prunes, and proves eventual receipt delivery and peer unlock.

## Checks passed

- `cargo test --locked --all-targets`; clippy `-D warnings`;
  `cargo fmt --check`; `git diff --check`.
