# Fable review — façade D2b v15 (remediation) — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-d2b-v15-fable-5843bfa`, verified clean
  at the exact SHA; probes reverted, tree byte-identical to head.
- **Head SHA reviewed:** `5843bfa52c202b13bf5b0eebe75b09034ecd1dc2`.
- **Verdict: PASS** — no blocking findings.
- **Gates:** 232 + 5 + 19 + 27 tests pass, 0 failed; clippy `-D warnings`
  clean; `fmt --check` clean.

## Reproduced, not assumed

- **Discrimination probe:** reverting `dedup_reclaimable` to the old
  `state != Accepted` predicate makes exactly
  `receipt_dedup_records_are_reclaimable` fail at the
  `reclaimable_dedup_count(..., past) >= 8` assertion, with 231 others
  passing. The regression genuinely discriminates.

## The reference predicate is as strict as the old rule — two independent arguments

1. **The reference chain is gapless.** `state.inbound` is mutated in
   exactly two places; the removal sits inside `consume_inbound_operation`
   which pushes the `AckIntent` in the same candidate, and `mutate`
   discards the candidate on any error — so inbound-removal and
   ACK-creation are atomic. ACK intents leave only via
   `record_ack_result` (dedup → `Acked`) and `sweep_expired_acks`
   (dedup → `Expired`), the old rule's two paths. So for application
   records "unreferenced" ⟺ "Acked or Expired": the predicates are
   extensionally equal. There is no inbound expiry/eviction path, so an
   unconsumed inbound pins its record forever — unchanged conservative
   behaviour. `AckState::Committed/Failed` exist only in the decoder and
   would count as a reference anyway (conservative direction).
2. **The window cannot exist temporally.** Reclaim requires
   `now >= expires_at + 7d`, while `accept_envelope` rejects
   `expires_at <= now` at the top of bounds, before dedup is consulted.
   Replayability and reclaimability are disjoint by seven days for the
   verbatim envelope the relay holds. A peer re-signing with a fresh
   expiry is peer-authenticated, hits `track_sender_sequence`'s duplicate
   rejection and the consumed Olm message key, and per the frozen design
   can already gap-lock at will — gaining nothing. **No replay hole was
   traded in.**

## `control_work_pending` has no false negative

Checked against every mutation `flush_control`'s closure can make: its
three sweep arms exactly match `sweep_expired_sends`,
`prune_terminal_sends` and `sweep_expired_acks` (and `SendState` has
exactly those five variants). The owed branch is a strict SUPERSET of
`maybe_stage_owed_receipt`'s staging conditions — every condition under
which the predicate declines is also a decline there, with identical
comparisons. Sweeps can create staging eligibility, but only when
`sweepable` is already true.

## v14 mechanism unchanged

Fable read the full `HEAD~1..HEAD` diff: five hunks in `mod.rs` plus one
test. Ledger, mode machinery, `ensure_control_slot`, `stage_receipt` and
the quotas are untouched. The v13 drain test still passes under the new
predicate.

## Non-blocking (all three are mine to clean up)

1. **Mangled doc comment** on `control_work_pending`: six stray lines
   copied from `consume_inbound`'s doc, truncated mid-sentence, prepended
   to the real doc. Cosmetic; private fn.
2. **The no-op-commit fix is incomplete in one window.** When a receipt
   is owed and time-eligible but an unresolved receipt is in flight —
   conditions `control_work_pending` does not model — `flush_control`
   still commits a semantically empty snapshot each tick; with a stuck
   `DeliveryUnknown` that window is up to 7 days, exactly the
   caller-negligence scenario now documented. Strictly better than
   before, but the doc's "stages nothing AND commits nothing" overclaims
   for this case.
3. **The new test's drain leg is vacuous** (reproduced). The second
   `deliver` runs at clock `NOW`, and the forged receipts consumed
   send_seqs 2..9, so the fixture's m2 fails `track_sender_sequence` with
   `DuplicateMessage`; the assertion then passes through its
   `|| !accepted_expired` escape hatch, and `flush_control(past)` is also
   a no-op. The comment claims a drain the test does not perform.
   Harmless to the verdict because the core assertion discriminates
   directly through the shared predicate and drain-through-accept is
   proven non-vacuously by the v13 test — but the leg should either
   accept at `past` with a fresh envelope or be deleted.
