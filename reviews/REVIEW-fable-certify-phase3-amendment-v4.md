# Fable certification — VERDICT: PASS at `6fee27e`

- **Reviewer:** Fable (`claude-fable-5`), cold, pinned detached worktree
  `/private/tmp/sml-amend-fable-6fee27e`, confirmed `git rev-parse HEAD`
  exact match and `git status --porcelain` empty before and after.
  Opened no `reviews/REVIEW-*` file.
- **Verdict: PASS.** The first PASS by either reviewer in this leg,
  across six rounds.
- **This is ONE leg of two.** The leg closes only on a second independent
  PASS at this same SHA. Not yet obtained.

## Implementer's verification of the PASS

A PASS is checked as carefully as a RETURN. Three of its broader claims
were independently re-verified:

- *"No markdown file outside the three documents mentions quantum or
  pre-migration."* Confirmed for product-facing and repository docs:
  only `SECURITY_STATUS.md`, `THREAT_MODEL.md` and
  `docs/phase3-post-quantum-decision.md` match, plus `reviews/` — which
  are review records, not product surfaces. `README.md` and
  `SECURITY.md` are clean, so neither can contradict the amendment.
- *"Every reliance-effect sentence carries its conditions in the same
  sentence."* Confirmed — exactly three exist (ruling's operative test,
  and the two threat-model bullets), all conditioned.
- *"Lapse is self-executing."* Confirmed — present exactly once in each
  document, triggered by evidence rather than by an actor's recording,
  so no actor's inaction can defer it.

## Residual risks the reviewer accepted, restated so they are not lost

1. **"Independently acting" is asserted, not mechanized.** No document
   can stop the product owner appointing a compliant architect. Inherent
   to a documentary control, not a defect in this text.
2. **Recording latency.** Between a condition becoming unverified and an
   architect recording suspension, reliance formally persists. Mitigated
   by the self-executing lapse on any actual violation and by the
   ruling's stricter affirmative-record reliance test.
3. **Pre-existing "Passing in this harness" checkboxes** in
   `SECURITY_STATUS.md` are quotable out of context. Scoped by their
   heading and the NO-GO verdict, predate this leg, unchanged by it.

---

# Verdict: PASS

**Observed state:** worktree `/private/tmp/sml-amend-fable-6fee27e`, detached HEAD `6fee27e89ef854c5105f3e22022eddb193ce174e` (exact match), `git status --porcelain` empty before and after review. Read-only throughout; no `reviews/REVIEW-*` file opened.

## What I verified

**1. Independence, end to end.** I traced every operative step in all three documents against `git diff f7cfdb3..HEAD` (original ruling → candidate) and `1a30f1d..HEAD` (last round → candidate):

- *Gate verification* — "independently acting security architect who is not the product owner must affirmatively verify and record" — present in ruling (`docs/phase3-post-quantum-decision.md:30`) and threat model (`THREAT_MODEL.md:159`).
- *Suspension* — now requires the same independent architect to record it, in all three documents (ruling:43, TM:159, `SECURITY_STATUS.md:77`). Previously any "security architect" sufficed; that hole is closed.
- *Restoration* — "Only such an independently acting security architect may restore reliance, and only after verifying and recording proof of uninterrupted compliance" — identical semantics in all three.
- *Lapse* — self-executing on evidence ("Evidence … makes the acceptance LAPSED from the earliest affected time"), so no actor's refusal to record can defer it; retroactive dating now present in the threat model as well as the ruling, and "traffic created during the breach cannot be retroactively authorized" appears in both.
- *Reactivation* — new dated product-owner acceptance **plus** concurrence from an independent architect who is not the product owner, in all three. The product owner alone cannot reach any step: verification, suspension, restoration, and the concurrence half of reactivation are all closed to them.
- Cross-document agreement: the ruling's reliance test (`:32`, affirmative verified records) is *stricter* than the subordinate documents' "in force and not suspended" formulation — that is the permitted direction, and `THREAT_MODEL.md:173` explicitly cedes control to the ruling wherever they differ. No subordinate document is weaker in a way that survives that clause.

**2. Fail-closed, whole-path.** Every state lands in hold with a defined exit: suspension → operational hold (ruling:45) → exit via independent restoration; lapse → hold + hold-shipment default "applies immediately" (ruling:112) → exit only via reactivation; correction-after-lapse → explicitly still lapsed; lapse-after-launch → hold on releases/onboarding/new ciphertext + data access preserved + corrective disclosure, and "a pre-PQ launch is not authorized unless this operational hold can be enforced" makes enforceability itself a launch precondition; no-architect → "the gate remains closed and no reliance on the exception is permitted." No stall state is permissive; no state lacks an exit.

**3. Surfacing reach.** The re-widened sentence (ruling:41, TM:166) binds the prominent-surfacing requirement "whether or not reliance on this exception is claimed, suspended, or lapsed" — "not claimed" covers the never-relied-on case — and correctly splits the second half: the classical-only-continuation prohibition is delegated to the fail-closed rule (ruling:47), which fires "whenever PQ is required — including whenever this exception is not in force and after authenticated PQ migration." The two clauses tile without a gap: while the exception is in force, surfaced (non-silent) classical continuation is the disclosed accepted risk; in every other state, continuation is prohibited outright.

**4. Overclaim surface.** Every reliance-effect sentence (grepped exhaustively: TM:148, TM:281, ruling:32) carries its conditions in the same sentence and is immediately followed by "This is not launch authorization." The defensible-claim blockquote in both documents is preceded by a labelled amendment declaring it unavailable until all gates pass. The "end-to-end encrypted" allowance is conditioned on `SECURITY_STATUS.md` first authorizing claims. Nothing quotable alone reads as authorization.

**5. Untouched sections and adjacent files.** Read all three documents whole, plus `README.md` and `SECURITY.md`. The authority inventory (ruling:15) is now literal — I diffed the candidate against the original ruling (`f7cfdb3`) and confirmed every amendment falls under exactly one enumerated item (Status paragraph, Authority record, the two named amendment sections, the four labelled paragraphs, in-place steps 1 and 5); the tail after the blockquote is untouched original. No markdown file outside the three documents mentions quantum or pre-migration at all, so README/SECURITY cannot contradict the amendments; both remain accurate and heavily disclaimed.

**6. The blocker** (`SECURITY_STATUS.md:77`) now mirrors the ruling exactly: independence attached to suspension recording, restoration, and reactivation concurrence; the hold must be *proven* to block releases, onboarding, and ciphertext creation while preserving data access and corrective disclosure. It is dischargeable: build the governance record + demonstrate the hold mechanism + verify applicable conditions at the gate; its "re-verify at every gate" clause restates a continuing ruling obligation rather than making the checkbox unsatisfiable.

## What would have made me return

Any operative step still reachable by the product owner or a non-independent architect; a suspension/lapse state whose default was not hold or that lacked an exit; the widened condition-4 sentence failing to cover the never-relied-on case; the authority inventory omitting an amended passage (I checked each against the original); or a reliance-effect sentence anywhere still missing the suspension conjunct — grep confirmed there are none.

## Residual risk accepted, stated plainly

- **"Independently acting" is asserted, not mechanized.** No document can prevent the product owner from appointing a compliant architect; the documents do all that documents can (exclusion by role, required records, concurrence). This is inherent, not a defect in this text.
- **Recording latency.** Between a condition becoming unverified and an architect recording suspension, reliance formally persists for the duty-latency window. Mitigated by the self-executing lapse on any actual violation, by the ruling's stricter affirmative-record reliance test, and by the standing more-rigorous-reading rule; I accept it as irreducible in a record-based governance scheme.
- **The pre-existing "Passing in this harness" checkboxes** in `SECURITY_STATUS.md` (e.g., "End-to-end encrypted two-client round trip") are quotable out of context, but they are scoped by their heading and the NO-GO verdict, predate this leg, and are unchanged by this diff.

The three changes since `1a30f1d` do exactly what they claim, close the defects they target, and introduce no new inconsistency I could find. PASS at `6fee27e89ef854c5105f3e22022eddb193ce174e`.
