# Fable review — façade D2b v14 — VERDICT: RETURN

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-d2b-v14-fable-6d4c922`, verified clean
  at the exact SHA; probes lived in a discarded scratch copy. No
  `reviews/REVIEW-*` artifact was opened.
- **Head SHA reviewed:** `6d4c92271a04cc3f3412802757292f7dc2cf0269`.
- **Verdict: RETURN** — one blocking finding.
- **Gates at the exact head:** 231 + 5 + 19 + 27 tests pass, 0 failed,
  0 ignored; clippy `-D warnings` clean; `fmt --check` clean.

**The control-lane split itself would have PASSED.** Fable states the
mechanism survived every attack it built. The blocker is a carry-over in
the same leg.

## Blocking — receipt dedup records are never reclaimable

`apply_receipt` writes a dedup record for every accepted receipt
(`mod.rs:2346` → `push_dedup`, `mod.rs:2757`) always in state
`DedupState::Accepted` (`mod.rs:2765`), and `dedup_reclaimable` refuses
`Accepted` as its first clause (`mod.rs:2725`). The only transitions out
of `Accepted` are `Acked` (`record_ack_result`) and `Expired`
(`sweep_expired_acks`) — **both keyed on an ACK intent, and ACK intents
are created only by `consume_inbound`, which only handles APPLICATION
inbound records.** A receipt never produces an inbound record, so never
an ACK intent, so its dedup record stays `Accepted` for the life of the
profile.

Each accepted peer receipt therefore costs one permanent slot of
`MAX_DEDUP` = 4,096. Application records drain; receipt records never do.
After 4,096 accepted receipts — ~200 days at 20/day, or minutes for a
peer holding our mailbox send capability streaming authenticated
`high_water = 0` receipts — the pre-decrypt bound refuses EVERY further
packet with `Err(Storage)`, at any future clock, with no path out. That
is strictly worse than the failure §4 designates as designed:
`RekeyRequired` has a defined user-confirmed rebootstrap; this has none,
and rebootstrap explicitly retains old dedup records through their safety
window — a window these records never leave.

**Reproduced.** 40 real accepted receipts drove `dedup` 1 → 41, all
`Accepted`, with `reclaimable_dedup_count(&state, NOW + 100 years) == 0`.
With the set filled, a legitimate application envelope at `NOW` and a
fresh packet at `NOW + 100 years` both returned `Err(Storage)` with no
generation commit.

**Provenance:** not introduced by v14 — `dedup_reclaimable` is unchanged
since `9fe095c`. It means the v13 remediation of Sol's v12 P1-2 closed
only the ACK-referenced arm and left the receipt arm exactly as it was.

**Closure offered:** make receipt-kind dedup records eligible under the
same seven-days-past-signed-expiry rule with no ACK precondition — either
tag them terminal at accept time, or treat `Accepted` records that can
never acquire an ACK reference (no inbound record, no ACK intent) as path
(b). The existing rationale applies verbatim: only a holder of our
mailbox SEND capability can re-present a reclaimed packet, and §4 already
grants that party the ability to gap-lock at will.

## Verified rather than assumed

- **The split removes the lever.** Every write to field 22 enumerated:
  appended at exactly one site (`admit_application_send`), shrunk at
  exactly one (the advancing-receipt arm), no peer-reachable path
  touches it. Attacked with 60 cycles of `issuer_outstanding = u64::MAX`
  and a full delivery cycle each time, interleaved with the victim's own
  sends: the victim's `application_outstanding` tracked only its own
  unacknowledged sends and reached `ControlOnly` on its own 24th body.
  Shared distance grew to 84 with the application lane untouched.
- **Both acceptance tests discriminate.** The 32-cycle test reads
  `issuer_outstanding` off the wire via a peer session clone, not local
  state. In the honest-peer test Fable traced step 6 and confirmed A's
  answer is driven by the CONTROL arm (receipt debt 23 is already below
  the delivered marker 25), so the v12 reciprocity gate would fail at
  exactly that assertion.
- **Ledger integrity:** byte-identical across drop/reopen at every step;
  prunes to empty on a covering receipt; `check_application_ledger`
  enforces its three documented implications; `parse_u64_set` rejects
  non-ascending and duplicate entries; the ledger cannot exceed 24 at
  runtime because staging requires `Ready`.
- **Liveness:** could not build a deadlock. A quiescent receiver whose
  only wake is a `flush_control` timer recovered a congested honest peer
  in 1 tick then stayed quiet for 5. Both peers at the ceiling converged
  in 2 ticks then went fully quiescent. `ensure_control_slot` cannot fail
  by construction.
- **The 66 migrated tests:** the `receipt_debt_up_to` substitution is
  real where counts were dropped; where absent, the replacement is a
  convergence assertion, which is stronger. The `MAX_SENDS` 32→40 sweep
  is complete. The two liveness loops were re-derived UPWARD and now fail
  earlier. `outstanding_budget_and_mode_consistency` is stricter than
  before. The one test that could have passed vacuously was instrumented:
  all 8 cycles execute.
- **`flush_control`** cannot bypass the cooldown, the one-unresolved
  bound, the quota, or `RekeyRequired`.

## Rulings on the two flagged open items — neither blocks

- **Unbounded shared sequence distance:** do not block, and specifically
  do NOT add a ceiling that gates control encryption — that is the v6–v12
  deadlock family in a new costume. Residual exposure is narrow and
  self-limiting (a receipt requires `HCR > marker`, so our sequence
  cannot outrun a ratchet the peer is feeding). What does change is that
  relay-side loss of N control packets presents an unbounded chain gap
  where it was ≤ 32, converting a bounded case into `TooBigMessageGap` →
  `RekeyRequired`, which §4 already designates designed and recoverable.
  Record it in §4 as an accepted outcome; optionally restore a
  LOAD-TIME-ONLY malformed ceiling far above any lawful value.
- **`SCHEMA_VERSION` still 1:** do not block. Fail-closed verified in the
  codec — `ObjectReader::read_header` rejects when `next_field >
  field_count`, so a 21- or 22-field session errors on the field-22 read
  and cannot misparse. Bump it before any shipping build writes a store.

## Non-blocking

1. **New stall class:** an unconsumed `DeliveryUnknown` control record
   blocks the ENTIRE control lane until `consume_delivery_unknown` or the
   7-day TTL. Spec-conformant, but it makes
   `delivery_unknowns()`/`consume_delivery_unknown` a LIVENESS obligation
   on the caller. Belongs in the public docs.
2. `StageSendOutcome::ReceiptFlushedRetry` is no longer asserted by any
   test; still reachable and honest, but a public variant with zero
   positive coverage will rot.
3. `flush_control` commits unconditionally — a no-op tick bumps the
   generation and rewrites the snapshot, and a transient commit failure
   takes a healthy client to `ReconcileRequired`.
4. Untested new validation rules: persisted mode byte 3 rejection, the
   three `check_application_ledger` implications, and the
   `control_send_not_before` rule. Correct by reading; coverage gap only.
5. Dead condition: `hcr_receipt_pending` in `debt_owed` can no longer
   change the outcome — `any_receipt_unresolved` subsumes it.
6. Vacuous assertion: `application_records <= 32` in
   `owed_receipt_does_not_compete_for_application_slots` restates a codec
   invariant.
7. Ledger under-reporting by hostile state is possible once records are
   pruned — inherent to "the ledger outlives its records" and requires
   defeating the AEAD/platform binding (§1 out of scope). Recorded as a
   decision, not an oversight.
