# Sol review — THREAT_MODEL.md post-quantum section — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), clean detached worktree pinned at the
  exact SHA; no repository files changed. Transcribed from the user's
  paste.
- **Head SHA reviewed:** `629753e6f30e6d4cff280e6250ca531f05ef70b9`.
- **Verdict: RETURN** — three P1 findings and four P2.

**Divergence worth recording:** Fable PASSed this same head. It verified
the technical claim rigorously against the vendored key schedule but did
not challenge the claim-release machinery or the scope conflation, which
is where every P1 landed. Both reviews are useful and neither is
redundant — but on a claims document, "is the mechanism described
correctly" and "does this authorize anything it shouldn't" are different
questions, and only the second was load-bearing here.

## P1-1 — the Phase 3 gate presented as SUFFICIENT authorization

The section made the claim "available" after a PQ-specific checklist. But
`SECURITY_STATUS.md` independently blocks *any* public-security claim on
broader unresolved work, and the ruling's "until" condition is
**necessary, not sufficient**. The list also omitted the reviewed
deployed MLS/Delivery Service path, actual migration, persistence/restart
proof, and a verified erasure lifecycle.

## P1-2 — the confidentiality horizon is present in name but unresolved and not gate-bound

With plaintext "not yet decided", the project cannot apply the ruling's
hold-shipment consequence or determine whether pre-migration exposure
violates the product requirement. The narrow cryptographic claim stays
falsifiable; **the product security objective does not.**

Also: "a few years" was invented policy absent from the governing ruling,
and "the cost of hybridising is bounded and known" contradicts the
ruling's own provisional-suite, upstream, mobile and unfrozen-budget
uncertainties. (Fable independently flagged "known" as too generous.)

## P1-3 — the erasure condition is hollow and conflates unrelated scopes

It did not identify which MLS secrets must disappear, when, how delayed
delivery affects retention, or how snapshots, rollback copies, backups,
crashes and platform storage are handled. An authentic old endpoint
snapshot could retain compromise-enabling secrets while every listed gate
passes — and `docs/persistence-spike-design.md` explicitly permits
authentic rollback and disclaims backup/forensic erasure.

Conversely it conflated three different actors: **attacker-retained relay
ciphertext is the PREMISE of HNDL**, not a failure of hybrid-PQ
confidentiality, and **recipient-retained plaintext is an exclusion**,
not an endpoint-erasure invariant.

## P2-4 — the hybrid guarantee is stronger than the ruling

"Must break both" is defensible only for the key-establishment component,
under a finalized robust combiner and conforming implementation, with
X25519 still secure at the time of attack. A CRQC *plus* a broken ML-KEM
assumption defeats both halves.

## P2-5 — compromise timing contradicts the repository's deletion semantics

Seven days is the signed acceptance TTL cap, not relay retention: an idle
live row survives until another sweep, and backups and captures are
unbounded.

## P2-6 — migration wording overclaims in both directions

"Stays classically protected forever" can imply lasting confidentiality;
"permanently exposed" omits the recorded-and-retained predicate.

## P2-7 — the metadata statement is absolute and points at the wrong budget

MLS can encrypt some protocol metadata, so "never metadata" is too
strong. And the existing budget table describes the Olm harness, not the
future MLS/Delivery Service design.

## Direct rulings requested

- **(a) Drift: YES**, on six points — the placeholder horizon, the "few
  years" policy, the known-cost assertion, the unconditional hybrid
  guarantee, the migration wording, and the sufficient-claim gate.
- **(b) "Not yet decided":** acceptable temporarily in a draft **only if
  explicitly fail-closed**. Not acceptable as a completed sequencing step
  1 while shipment and claim gates can pass without resolving it.
- **(c) Claim language:** the one-sentence HNDL claim **passes** and is
  defensible once its prerequisites are testable. The assertion that
  unqualified "post-quantum secure" stays false after migration is
  **correct**. The sentence passes; **the surrounding claim-release
  machinery does not.**

## Closure

All seven addressed in the revision:

- The gate now states explicitly that it is **necessary but not
  sufficient**, and adds reviewed deployment, actual authenticated
  migration, persistence/restart proof, a verified erasure lifecycle, a
  frozen-or-retained horizon, and global `SECURITY_STATUS.md` clearance.
- The horizon adopts an explicit **fail-closed indefinite default** and
  makes horizon approval a prerequisite for both shipment and claim. The
  invented "few years" threshold and the "known" cost claim are removed.
- Erasure is split into three sections by actor: attacker-retained
  ciphertext as premise, endpoint-secret erasure as an UNSPECIFIED
  testable invariant promoted to a gate condition, and
  recipient/endpoint compromise as an exclusion.
- The hybrid rationale is stated conditionally and explicitly not claimed
  before standardization and review.
- A four-row retention table separates acceptance TTL, live-row deletion
  timing, logical ACK deletion, and unbounded attacker copies.
- Migration wording uses the ruling's exact scope.
- The metadata statement is narrowed to "makes no claim to reduce"
  relay/network-visible metadata, and records that the existing budget
  describes the Olm harness only.
