# Fable review — THREAT_MODEL.md post-quantum section, v2 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-threatmodel-v2-fable-eadba87`, clean
  before and after; no reviewed file modified.
- **Head SHA reviewed:** `eadba87ebcc2ce19706b73a1bc128c7f5bdcc7b0`.
- **Verdict: PASS** — no blocking defects.

Fable was told directly that it had PASSed the previous version, that Sol
returned it with three P1s, and that the generalisable lesson is that
"is the mechanism described correctly" and "does this text authorize
anything it shouldn't" are different questions. This review addresses the
second.

## The three P1s, checked against independent sources rather than the section's own prose

**P1-1 (gate presented as sufficient) — closed.** The claim-language
section no longer conditions on the gate at all; it conditions on "once
every prerequisite below has been met", and that list includes global
`SECURITY_STATUS.md` clearance. Fable verified that characterization
against `SECURITY_STATUS.md` itself — verdict NO-GO, blocking list real
and mostly open. It then traced every other conditional in the section
hunting for a quiet re-grant: the intro, the adversaries list, the
mitigation section and the metadata section are all consistent. **Nothing
re-authorizes what the gate withholds.**

**P1-2 (undecided horizon) — closed, and load-bearing rather than
decorative.** The mechanism traced: undecided → INDEFINITE default →
"classical-only key agreement is insufficient by definition, and the
ruling's hold-shipment consequence applies" — verified against the ruling,
which contains exactly that consequence — → horizon approval is a
prerequisite for both gates. The previously-possible failure state, all
gates passing while the horizon stays unresolved, is now structurally
impossible: either a concrete horizon is frozen or the indefinite default
is explicitly retained, and both are decisions.

Fable specifically probed the "explicitly retained indefinite" branch for
a loophole and found none: retention satisfies only the horizon
prerequisite, the other five still block, and the claim stays
adversary-scoped (HNDL/CRQC) rather than promising indefinite
unconditional confidentiality — so retaining indefinite does not
over-commit the hybrid suite.

**P1-3 (erasure conflation) — closed and correct.** Each item is assigned
to the right actor. Fable verified the load-bearing citation against
`docs/persistence-spike-design.md`: it does explicitly permit authentic
rollback and does disclaim backup/forensic erasure. And it confirmed the
concern is real rather than rhetorical — **the Phase 3 ruling RETAINS the
snapshot/generation-CAS storage architecture for MLS, so the rollback
semantics carry forward, and no other gate item would catch it.**

## Other verification

- **Retention table vs actual relay code.** Every row checked in
  `src/relay.rs`: the seven-day TTL is enforced as a cap on the
  sender-requested expiry, so "maximum a sender may request" is exactly
  right; `acknowledge()` deletes and tombstones in one transaction;
  `purge_expired_in` runs at open and inside every operation, so the
  idle-relay row matches both the code and the deletion-semantics
  section.
- **The technical claim re-verified** against `shared_secret.rs` and
  `root_key.rs` — unchanged and still accurate.
- **The earlier precision fix landed accurately** — verified against
  `src/client.rs` that `PeerPreKey` carries the Curve25519 identity
  alongside the one-time key, and that this is precisely the
  bundle-distributed long-term DH input the CRQC needs.
- **New-defect sweep:** the rewrite REMOVED two defects rather than
  adding any — the invented time-to-CRQC policy and the unconditional
  combiner claim. No internal contradiction between subsections, and
  nothing stated more weakly than the ruling requires.

## Non-blocking

1. "Horizon approval" names no approver. The ruling establishes the
   security architect as the deciding authority; naming that role would
   close a small governance ambiguity. Absence of approval blocks, so it
   fails safe.
2. The horizon table's long-term-identity row covers only the
   Ed25519/authenticity dimension; the Curve25519 identity key's
   confidentiality role appears in the adversary section but not the
   table. Harmless — the plaintext row governs the HNDL outcome.
3. "retain an expired row indefinitely until the next sweep" reads
   slightly self-contradictory; the intended meaning (unbounded if no
   operation ever arrives) is correct. Wording only.
4. The erasure subsection cites `persistence-spike-design.md`, an
   Olm-era document the ruling partially retires. The citation is used
   correctly and the text already hedges, but this paragraph should be
   re-pointed once the MLS storage design exists.
