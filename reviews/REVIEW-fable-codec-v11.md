# Fable review — client-state codec v11 (remediation) — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-codec-v11-fable-6d3922f`, confirmed
  clean before and after; sources restored byte-identical.
- **Head SHA reviewed:** `6d3922f`.
- **Verdict: PASS** — no blocking findings.
- **Gates:** 238 + 27 + 19 + 5 tests pass; clippy `-D warnings` clean;
  `fmt --check` clean.

## Reproduced by reverting production behaviour

- **Encode-side check is load-bearing.** Reverting it in
  `check_structure` makes `send_record_relabelling_is_rejected` fail with
  "a relabelled send record was accepted (index 0)".
- **Dedup uniqueness discriminates.** Reverting it makes
  `duplicate_inner_message_digest_is_rejected` fail on its reject arm.
- **The decode-side check in `SendRecord::parse` is REDUNDANT.** Deleting
  it leaves the whole suite green. Fable then built a wire-splice probe
  (record relabelled, stale commitment carried, spliced into a genuine
  encoding) and confirmed `decode` still rejects — because
  `ClientStateV1::decode` runs full `validate`, whose `check_structure`
  recomputes. So there is no behavioural hole, but the parse-side check
  is untested defence-in-depth.

## Verified by reading, exhaustively

- **Ordering.** Decode verifies per-record in `parse` before any
  cross-record logic; on encode, `check_structure` is `validate`'s first
  call and `check_application_ledger` runs later. The lane-quota counting
  does read `kind` before the commitment loop, but every path there is
  rejection-only inside one all-or-nothing `validate`, so no ACCEPTANCE
  ever relies on unverified `kind`.
- **Tuple sufficiency.** Every deliberate exclusion is independently
  constrained: `queue_id` (pending must equal the binding's queue,
  terminal must be `None`), packet bytes (digest recomputed from actual
  bytes on the pending arm), `send_signature` (verifies over the
  committed tuple, absent when terminal). `state` is the one genuinely
  uncommitted mutable, matching the pre-existing declared gap that
  outbox-transition legality is not snapshot-decidable.
- **Terminalization.** Every write to a committed field was enumerated:
  none after staging. All three transition sites preserve the digest
  value.
- **Retained high water is inert.** Every read enumerated — both staging
  gates require `state == Pending`, and the delivered marker advances
  only inside the genuine Pending → Stored/Duplicate transition.
- **The both-arms hw ≤ hcr rule cannot reject a legitimate state:** all
  send records are current-epoch, receipts stage at hw = hcr, hcr is
  monotone within an epoch, and establishment requires session-absent.
- **P1-2's global scope is right.** Identical inner Olm canonical bytes
  across epochs can only be a replay, which acceptance dedups before a
  second record exists; distinct genuine encryptions collide only with
  SHA-256 collision probability.

## Non-blocking

1. **Stale doc block** — `SendKind`'s docs still describe the OLD matrix
   ("an hw field on a terminal record… reject", hw-vs-hcr as full-arm
   only), contradicting the implemented matrix documented correctly a few
   lines below. Doc-only, but it would mislead a future implementer.
2. **Dead, stale test helper** — `decode_with_spliced_send` lost all
   callers in the v11 rewrite and builds 11-field objects that can never
   decode under the 12-field layout. **With it went the only wire-level
   invalid-kind-byte decode test** — a real coverage regression worth
   restoring.
3. **The parse-side commitment check is undiscriminated.** A companion
   decode-splice test would pin both layers.
4. **Blind-spot sweep (self-assessed).** Fable accepts that its v10 PASS
   treated the §1 boundary plus the declared gaps as closing the question
   of locally-authored metadata, without asking which cross-checks key on
   fields nothing constrains — and that both P1s were that one class.
   Sweeping for remaining members, the closest sibling is
   `DedupRecord.message_digest` AFTER its inbound/ACK records are
   consumed: origin-unverifiable and unbound to the record's other
   fields. It does not meet the blocker bar — no legitimate path rewrites
   it, and P1-2 now covers the collision direction — but it is the
   natural next candidate for the same treatment if dedup records ever
   gain a mutation path.
