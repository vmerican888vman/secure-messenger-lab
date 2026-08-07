# Fable review — façade D2b v16 (remediation) — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-d2b-v16-fable-c60a242`, clean at the
  exact SHA before and after; probes reverted, zero diff.
- **Head SHA reviewed:** `c60a2421f3d6499e5bfb86ce8d36c7668c8c67d5`.
- **Verdict: PASS** — no blocking findings.
- **Gates:** 285 tests pass, 0 failed; clippy `-D warnings` clean;
  `fmt --check` clean.

## Reproduced by reverting production behaviour

Fable proved each fix discriminates by breaking the code, not by reading
the tests:

1. **P1.** Removing `active_has_unresolved_control` from
   `control_work_pending` makes `blocked_control_tick_does_not_commit`
   fail on the Pending arm.
2. **Quotas, both directions.** Removing the per-lane check while keeping
   the 40 total makes `split_send_quotas_are_enforced` fail on the 33+7
   arm — lane borrowing is genuinely detected. Collapsing `MAX_SENDS` to
   32 makes it fail on the 32+8 arm — a total-cap regression is detected.
3. **Byte-flip offset is correct AND semantic.** Disabling only the
   marker rule makes `byte_flip_in_signature_positions_fails` fail with
   "field-19 high-byte flip accepted", so at this head the flip is
   rejected by the marker rule and not by structural damage. Fable also
   re-derived the arithmetic independently against the codec and
   confirmed the offset lands exactly on field 19's big-endian high byte.
4. **Cooldown deferral.** Removing `!cooldown_open` from the staging gate
   makes the new same-second assertion fail.

## Verified by inspection

- **The two sites cannot disagree into a committing no-op.** The three
  `sweepable` disjuncts match the three sweeps exactly, so
  `sweepable ⇒ true` always commits real work; on the staging leg both
  sites now share `active_has_unresolved_control` plus identical
  marker/debt/mode/cooldown terms. The one omitted condition,
  `ensure_control_slot`, cannot fail once the shared guard passes — no
  unresolved receipt means every control record is terminal, so a victim
  always exists at the quota.
- **No false negative.** Every arm returning false is one where staging
  would also decline and no sweep is due. Resolution paths are themselves
  mutators that call `maybe_stage_owed_receipt`, and the regression's
  final leg confirms unblock → re-stage → commit.
- **v14/v15 mechanisms unchanged.** `git diff 5843bfa..HEAD -- src/`
  touches only the 46-line pre-flight change plus the two test files;
  `dedup_reclaimable`, the reference-keyed reclaim, `ensure_control_slot`,
  the sweeps and `recompute_mode` are untouched.

## Non-blocking

1. `hcr_receipt_pending` is now dead at both sites (subsumed by the
   shared guard). Consistently dead is safe, but removing it would shrink
   the surface the "mirror exactly" comment must defend.
2. `control_work_pending`'s staging leg reads committed state while the
   sweeps run first inside `mutate`. Sound today because every divergence
   routes through `sweepable == true`, but the soundness is positional —
   a comment noting the ordering dependency would protect the next
   editor.
3. `flush_control` returns `Ok(false)` on a sweep-only tick that did
   commit. Correct as documented ("whether a receipt staged"), but the
   return value is not a "did anything commit" signal.
