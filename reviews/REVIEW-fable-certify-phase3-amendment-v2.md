# Fable review — remediation round at `e751a9e` — VERDICT: RETURN

- **Reviewer:** Fable (`claude-fable-5`), dispatched directly into a
  pinned detached worktree, cold — had not seen the architect's rulings.
- **Head SHA reviewed:** `e751a9ee6aa8c2ab72307f4e0327e8bb154fe382`.
- **Worktree:** `/private/tmp/sml-amend-fable-e751a9e`, confirmed detached
  and clean. Opened no `reviews/REVIEW-*` file. Additionally diffed the
  ruling against its pre-amendment original (`f7cfdb3..HEAD`) to audit
  the labelling invariant — an angle the brief did not ask for.
- **Verdict: RETURN** — one P1, two P2, two P3.
- **All six prior findings ruled CLOSED.** The RETURN is entirely for
  defects the remediation introduced or exposed.

## Implementer's verification

N1, N2 and N3 were each checked against the files before being recorded.
**All three confirmed by direct inspection.**

**N1 corrects the implementer's own flag.** The round-3 brief had already
escalated the F3 placement asymmetry, but characterised it as "the threat
model is marginally stricter than the ruling." That framing was wrong in
the direction that matters. Because `THREAT_MODEL.md` states "the
governing ruling controls wherever the documents differ," a *stricter*
subordinate clause is not stricter in effect — it is **void**. The net
result is that the migration-surfacing requirement carries no lifecycle
consequence anywhere. Fable's reading is the correct one and supersedes
the brief's.

**N2 is the untouched-section trap firing a second time**, and this time
on text the implementer applied. The remediation replaced a
self-executing sentence ("An applicable condition that is unverified
suspends reliance on the acceptance") with a recording *duty* on a named
actor. That was F6's whole point and is right. But it removed the only
thing partially covering `THREAT_MODEL.md`'s untouched one-conjunct
reliance sentence, which now contradicts the ruling's two-conjunct test.
The brief predicted another untouched-section defect existed; it did,
three bullets from remediated text, in a passage the fix made sharper.

---

**Observed state:** worktree `/private/tmp/sml-amend-fable-e751a9e`, detached HEAD `e751a9ee6aa8c2ab72307f4e0327e8bb154fe382`, `git status --porcelain` empty. Read-only throughout; no `reviews/REVIEW-*` file opened. I verified the remediation diff (`4e5637b..HEAD`) and additionally diffed the ruling against its original pre-amendment text (`f7cfdb3..HEAD`) to audit the labelling invariant.

## Verdict: RETURN

One P1 and two P2 findings, all in the seam the remediation itself created. The six prior findings are substantively closed; the RETURN is for what the fixes introduced or left exposed, not for reopened tickets.

## The six remediated findings

**1. Timeless "no production state" — CLOSED.** `THREAT_MODEL.md:273` is now date-scoped, defers to the ruling's V1 production-lifecycle amendment, and keeps the V1→V2 secret-state prohibition unconditional ("remains prohibited regardless") — the invariant survives the premise's termination. Matches `docs/phase3-post-quantum-decision.md:90`. No other timeless assertion of the premise remains (line 60's "do not persist production state under it" is an instruction, not a claim).

**2. Three names for the condition-3 gate — CLOSED.** "Before any migration-capable release ships" is now the uniform trigger at ruling lines 38 and 40 and `THREAT_MODEL.md:163`. Remaining "before the migration" occurrences (THREAT_MODEL 145, 161) name the migration event for claim scope, mirroring the ruling's own condition 1 — they are not the condition-3 gate and are not a third name.

**3. Silent Olm continuation after failed migration — CLOSED as to existence.** The surfacing requirement now appears, in substantively identical words, at ruling line 46 and as `THREAT_MODEL.md` condition 4. The behavior is prohibited in both documents. However, the two placements attach different consequences, and that divergence is not harmless — carried forward as finding N1 below.

**4. Present-tense misstatement — CLOSED.** `THREAT_MODEL.md:116` now reads "policy the governing ruling did not then contain," which is temporally accurate. I checked the surviving present-tense sibling at line 127 ("inventing one would be policy the governing ruling does not contain," re a time-to-CRQC threshold): still true — the ruling sets no threshold.

**5. Labelling-invariant under-count — CLOSED, with a P3 residue.** Verified against the full `f7cfdb3..HEAD` diff: the only unlabelled in-place changes to original architect text are the Status paragraph and sequencing steps 1 and 5 — exactly what line 15 now enumerates. The two paragraphs replaced after the Phase-2 table live under the labelled V1-production-state header. Residue at N4.

**6. Unnamed actors — CLOSED.** Both documents assign: product owner supplies evidence; architect verifies, records, records suspension, may restore only on proof of *uninterrupted* compliance; reactivation after lapse requires a new dated PO acceptance plus architect concurrence. Fail-closed trace: the ruling's operative clause (line 32) conditions reliance on an affirmative architect *record*, so an absent or unavailable architect stalls the mechanism **closed** — default is hold-shipment, which is the correct direction. Restoration-from-suspension is architect-only but bounded: anything actually violated routes through LAPSED into the two-party reactivation path, so the architect cannot self-authorize past a real breach. Checker-checking bottoms out in this dual-review certification process, which is external to the documents and acceptable.

## New findings

**N1 — P1. The migration-failure requirement carries a lapse consequence in the subordinate document but not in the governing ruling, and the supremacy clause resolves the conflict in the weaker direction.**
- `THREAT_MODEL.md:164` places it as numbered condition 4 under "conditional on all of the following" — per line 159, "Evidence of a violation makes the acceptance LAPSED."
- `docs/phase3-post-quantum-decision.md:46` places the identical requirement as a standalone sentence in the fail-closed paragraph, outside the numbered conditions 1–3; the ruling's lapse machinery (line 42) fires only on violation of "an applicable condition."
- `THREAT_MODEL.md:171`: "The governing ruling controls wherever the documents differ."

Concrete failure: a migration-capable release is live under the exception. A conversation's migration is blocked and the client silently continues writing Olm ciphertext, while conditions 1–3 all still verify (no surface overclaims; the per-conversation distinction surface correctly marks the traffic classical). Under `THREAT_MODEL.md` the acceptance lapses and the operational hold fires. Under the ruling, no condition was violated — the exception stays verified and pre-migration ciphertext creation lawfully continues while the client flagrantly violates a hard requirement with no defined lifecycle consequence. Because the documents differ, the supremacy clause voids the stricter subordinate text. This is the exact "subordinate stricter than its ruling" pattern the project was previously burned by, and here it resolves against the standing more-rigorous-reading constraint. Ruling: **not harmless**. The fix belongs in the ruling — adopt the requirement as condition 4 (or attach an explicit suspension/lapse consequence there) — not by weakening `THREAT_MODEL.md`.

**N2 — P2. The remediation removed `THREAT_MODEL.md`'s self-executing suspension backstop and left a one-conjunct reliance claim standing.** The prior text "An applicable condition that is unverified suspends reliance on the acceptance" was actor-independent; the replacement at line 159 is only a recording duty ("The security architect must record suspension whenever…"). The document's sole remaining reliance-scope statement is the untouched `THREAT_MODEL.md:148`: "While the acceptance remains in force, PQ is not by itself a reason to hold shipment." The ruling's operative test (line 32) has two conjuncts — acceptance in force AND every applicable condition *recorded as verified*. Concrete failure: reliance is suspended (a condition unverified at a gate) while the acceptance itself remains in force; a maintainer at a release gate quotes line 148 — the passage most naturally consulted for exactly that question — and concludes PQ does not hold shipment, when under the ruling it does. This is the predicted untouched-section falsehood, sitting three bullets from remediated text, and the fix made it sharper by deleting the automatic-suspension sentence that used to partially cover it. Mitigated to P2 (not P1) because the supremacy clause resolves this one in the rigorous direction and the sentence is immediately chased by "This is not launch authorization." Fix: mirror the two-conjunct test at line 148 (e.g., "While the acceptance remains in force *and reliance is not suspended*…").

**N3 — P2. The threat model's four-condition list has no applicability statement, and the ruling's cannot supply one for condition 4.** Ruling line 40 declares conditions 1–2 continuous and 3 a release gate; `THREAT_MODEL.md:159` pivots verification on "every condition applicable at that gate," but its own list — which includes a condition 4 that does not exist in the ruling's numbered list — never says which conditions apply when. Concrete failure: at a gate the architect must decide whether condition 4 is "applicable"; neither document answers; deeming it inapplicable drops the silent-downgrade control out of verification entirely, and per N1 the supremacy clause backs that reading. Coupled to N1: adding condition 4 to the ruling with "applies continuously once authenticated PQ migration is offered or attempted" resolves both.

**N4 — P3. Labelling-invariant residue.** Line 15's exception quotes the label form "**Architect amendment — 2026-08-08**"; the two amendment *section headers* use variant forms ("…conditional pre-migration exception (2026-08-08)", "…pre-migration V1 production state (2026-08-08)"), and the Authority record section is itself unlabelled, unenumerated amendment text. Fails safe — a literal reader who excludes the mismatched sections falls back to original text, which is strictly more restrictive — hence P3, not higher.

**N5 — P3. `THREAT_MODEL.md:159` drops "from the earliest affected time."** A threat-model-only reader could date a lapse at discovery and treat breach-period traffic as having been covered. Mitigated by the explicit cross-reference to "the governing ruling's fail-closed consequence" and the supremacy clause.

## Rulings on the remaining brief questions

**Fail-closed integrity (Q1):** traced suspension, lapse, correction-after-lapse, and lapse-after-pre-PQ-launch; every path lands in a defined state whose default is hold. No self-authorization path past a real violation; stalls are closed-direction. The only integrity defects are documentary (N1–N3), not mechanical.

**Overclaim surface (Q3):** apart from `THREAT_MODEL.md:148` (N2), no sentence in either amended document or `SECURITY_STATUS.md` reads as launch authorization or an unsupported security claim in isolation; every reliance sentence is immediately disclaimed, `SECURITY_STATUS.md` remains unambiguously NO-GO, and `README.md`/`SECURITY.md` make no PQ claims. Line 279's "only while" is necessary-condition phrasing and safe.

**The new blocker (Q5):** dischargeable as written. "Blocks new releases" and "onboarding" are process/server controls provable by test and rehearsal; "creation of pre-migration message ciphertext," read as a universal fleet guarantee, is not literally provable (an unreachable client can still encrypt), but the harvestable surface the exception governs is wire traffic, and relay-side refusal of new sends plus tested client hold behavior discharges it. Advisory (P3): the discharge evidence should pin the enforcement point so "creation" is not read as an impossible universal guarantee.

Not findings: the condition-1 wording drift ("before the migration" vs "before authenticated PQ migration") and the Signal/SimpleX posture comparison — both are stylistic or long-standing and change no obligation.

**RETURN.** N1 must be fixed in the ruling; N2 and N3 should ride the same amendment. All three are small, localized edits, and nothing found disturbs the six closures.
