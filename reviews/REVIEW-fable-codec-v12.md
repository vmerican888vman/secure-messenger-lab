# Fable review — client-state codec v12 (remediation) — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-codec-v12-fable-8fab295`, confirmed
  clean before and after; all probes reverted.
- **Head SHA reviewed:** `8fab295e4efb130c43d9107b445bcb7a9fadb31b`.
- **Verdict: PASS** — no blocking findings.
- **Gates:** 291 tests across 5 suites, 0 failures; clippy `-D warnings`
  clean; `fmt --check` clean.

## Judgement on the ordering disagreement — Fable reversed itself

Fable examined this same spot at v11 and judged it sound. Asked to rule
independently rather than defer, its ruling now, in its own framing:

> Sol's counter-argument is correct, and my v11 reasoning applied the
> wrong standard. My factual claim stands — at `6d3922f` no acceptance
> ever relied on unverified `kind`; there was no exploitable defect. But
> the frozen text is "verify before anything relies on kind," which is a
> POSITIONAL contract, and I defended the weaker BEHAVIOURAL property
> "fails closed under today's control flow." That property is one
> refactor away from silently evaporating — any future kind-keyed branch
> that returns a value, accumulates state used on an accept path, or
> restructures the early returns would void it with no test or contract
> line to catch it. A frozen ordering contract exists precisely so
> conformance survives maintenance without re-derivation; incidental
> fail-closure does not satisfy it.

## Verified rather than assumed

- **Hoist completeness — swept, complete.** Every consumer of `kind`,
  `receipt_high_water`, `epoch_id` or `sequence` on send records was
  enumerated; zero in `mod.rs`/`tlv.rs`. On decode the only prior
  kind-touching operations are the discriminant match (pure parsing —
  `kind` cannot be verified without being parsed) and the commitment
  computation itself. On encode, `check_structure` runs first and the
  hoisted loop precedes every consumer.
- **No new problem from the hoist.** Decode cost is unchanged; parse
  bounds both the array count and packet length before any hashing. On
  encode the worst case is ~40 × 96 KiB hashed before a quota rejection
  that used to come cheap, but `check_sorted` enforces the array bound
  before the loop and encode only ever receives locally-owned state.
  Error precedence is unobservable — every rejection is the same opaque
  `LabError::Storage`.
- **The retired-twin test, and Sol's P2 quantified.** Fable reproduced
  the both-retired exemption mutation: the new test fails
  deterministically. It then ran the OLD `cc33eba` test against the same
  mutant ten times — **it caught the mutant 2/10 and passed 8/10**,
  empirically confirming Sol's finding and matching the predicted escape
  rate from `P(random id < 0xAA…)`.
- **The delegated tests from `363d2b8` hold up.** No assertion weakened;
  the deleted helper had zero callers. Both new tests self-anchor before
  splicing. Mutation probes: deleting the parse-layer check fails only
  the commitment-splice test (92 others green, proving its premise that
  the suite was otherwise blind to that deletion); deleting the
  encode-side loop fails only the relabelling test. Each layer is
  independently mutation-killable.
- **Nothing else changed behaviourally** — `mod.rs` and `tlv.rs` are
  byte-identical across the range.

## Non-blocking

1. `check_sorted(&state.sends, …)` runs before the hoisted loop and
   consumes `message_id`, which IS a committed field. The contract names
   `kind` and the mutable metadata, and sorting by immutable identity is
   order-only, so this conforms — but if the contract is ever restated as
   "before anything relies on any committed field," this is the line to
   revisit. A one-clause note in the hoist comment would inoculate it.
2. On encode the hoisted loop hashes full retained packets before the
   `MAX_PACKET` re-check. Harmless today, but moving that re-check above
   the loop would make encode symmetric with decode's bound-before-
   consume discipline.
3. Decode now verifies each commitment twice (parse, then
   `check_structure`). Redundant but bounded — and it is exactly what
   makes the two layers independently pinnable. Keep it.
