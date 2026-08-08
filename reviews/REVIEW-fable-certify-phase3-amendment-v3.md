# Fable review — round 4 at `1a30f1d` — VERDICT: RETURN

- **Reviewer:** Fable (`claude-fable-5`), cold, pinned detached worktree
  `/private/tmp/sml-amend-fable-1a30f1d`, confirmed clean at
  `1a30f1da733b10e79bd7c9e77aa26fb821220d5d`. Opened no `REVIEW-*` file;
  read `reviews/PROMPT-certify-phase3-amendment-v3.md` for prior context.
- **Verdict: RETURN** — two P2, two P3. No P1.
- Both intended changes confirmed to achieve their purpose.

## Implementer's verification

Findings 1, 2 and 4 each checked against the files. **All confirmed.**

**Finding 2 is the significant one, and the reviewer retracted its own
prior reasoning to reach it.** In round 3 it had closed out the
checker-checking question on the grounds that "anything violated routes
through LAPSED into the two-party reactivation path." It now states that
reasoning "predates this amendment and no longer holds cleanly," because
the two-party reactivation collapses to one human when the concurrence
is not independence-qualified. A reviewer overturning its own earlier
close-out is worth more than a fresh finding.

Verified: ruling line 43 uses an unqualified "The security architect" for
suspension, restoration and reactivation concurrence; `SECURITY_STATUS.md`
blocker 77 repeats the unqualified reactivation formula; only
`THREAT_MODEL.md` line 159 carries independence by anaphora within one
paragraph — and the ruling, which governs, is the weaker text.

**Answers to the round-4 brief's open questions**, which the duplicate
relay never delivered:

- *Lapse gap from the move* — real, but P3 not P1. No confidentiality
  exposure, because fail-closed prevents harvestable classical traffic
  and the corrective-disclosure duty covers lapse-after-launch. What was
  lost is the affirmative surfacing duty's unconditional reach.
- *Condition 4's operator-controlled trigger* — **not a defect**, with
  reasoning: a conversation never offered migration is ordinary
  pre-migration classical operation, which is exactly what the acceptance
  covers, and conditions 1–3 still bar any PQ claim while condition 3
  keeps its unprotected status user-visible. "Offered **or attempted**"
  also closes the probe-silently-and-hide-the-offer variant.
- *Independence satisfiability with one human* — **the intended
  fail-closed result, explicitly "do not fix this."** The sentence
  supplies its own consequence and the hold-shipment default simply
  stands.

---

# Certification review — round 4, `1a30f1da733b10e79bd7c9e77aa26fb821220d5d`

**Worktree observed:** `/private/tmp/sml-amend-fable-1a30f1d`, `git rev-parse HEAD` = `1a30f1da733b10e79bd7c9e77aa26fb821220d5d`, `git status --porcelain` empty (clean, detached). Diff reviewed as `e751a9e..HEAD` restricted to the two authority documents (the full diff also adds `REVIEW-*` files, which I did not open). No `REVIEW-*` file was read; `reviews/PROMPT-certify-phase3-amendment-v3.md` was read for prior-round context.

## Verdict: **RETURN**

Both intended changes achieve their stated purpose. The condition-4 consequence chain is now complete in both documents, and the independence requirement fails closed as designed at gates. The return is on two P2s: the one-conjunct reliance sentence flagged as N2 in the round-3 brief is still present verbatim and this round's own change widened its understatement, and the new independence requirement covers only gate verification while suspension, restoration, and reactivation concurrence remain assigned to an unqualified "security architect."

---

## Task 1 — Does condition 4 now attach the consequence? YES, in both documents.

Trace, ruling (`docs/phase3-post-quantum-decision.md`): blocked migration + silent classical continuation → violates condition 4 (line 39) → applicability sentence (line 41) makes it "applicable ... continuously to each conversation from the first time authenticated PQ migration is offered or attempted" → "Evidence that an applicable condition was violated makes the acceptance LAPSED from the earliest affected time" (line 43) → post-launch operational hold + corrective disclosure (line 45) and "the original hold-shipment consequence applies immediately" (line 112). Defined outcome reached.

Trace, `THREAT_MODEL.md`: condition 4 (line 164) → applicability sentence (line 166) → "Evidence of a violation makes the acceptance LAPSED and invokes the governing ruling's fail-closed consequence" (line 159). Defined outcome reached by delegation to the ruling. Round 3's N1 is genuinely fixed; the two condition-4 sentences and the two applicability sentences are byte-identical across the documents.

**Timing coherence / never-offered gaming:** coherent. A conversation never offered migration is simply pre-migration classical operation — exactly what the acceptance covers — and remains governed by conditions 1–3: no PQ claim is possible (1, 2) and condition 3's "That distinction must remain available thereafter" makes the conversation's unprotected status user-visible. Never offering migration therefore gains the operator nothing forbidden; the exposure it prolongs is the disclosed, accepted gap. Sequencing step 6 directs migration but sets no deadline — that is a product-schedule matter the acceptance already prices in, not a certification defect. "Offered **or attempted**" also closes the probe-silently-and-hide-the-offer variant.

## Task 2 — Independence requirement

**Satisfiability:** the solo-operator unsatisfiability is the **intended fail-closed result**, not a defect. The sentence supplies its own consequence: "If no such security architect is available, the gate remains closed and no reliance on the exception is permitted." Under the more-rigorous-reading rule this is correct: with one human, the hold-shipment default simply stands. Do not "fix" this.

**But the qualifier does not travel** — see Finding 2 below.

## Task 3 — What the move broke

Less than feared, but not nothing. Coverage matrix at HEAD:

- **Exception in force, post-offer, blocked:** condition 4 governs; silent continuation → lapse → hold. Covered (the point of the move).
- **Exception not in force (lapsed/suspended/never activated):** fail-closed paragraph (line 47: "Whenever PQ is required — including whenever this exception is not in force ... must fail closed. The client must never silently negotiate down to, continue on, or resume Olm"), plus line 45's prohibition on creating pre-migration ciphertext after lapse, plus unqualified "Never negotiate down to Olm when PQ is required" in step 6. The anti-downgrade rule has **no confidentiality gap**.
- What *was* lost: the affirmative **prominent-surfacing duty** is now scoped to the exception's lifetime — Finding 4 (P3).

## Findings

### Finding 1 — P2 — `THREAT_MODEL.md` line 148: the one-conjunct reliance sentence survives a third round, and this round's change widened the gap

> "While the acceptance remains in force, PQ is not by itself a reason to hold shipment."

The ruling's operative test (line 32) has two conjuncts — "While — and only while — the product-owner acceptance remains in force **and** the security architect has recorded every applicable disclosure condition as verified" — and this round added a third reliance element: with no independent architect, "no reliance on the exception is permitted." Line 148 states one conjunct, and it sits nine lines above the paragraph this round edited. This is the exact sentence the round-3 brief flagged as N2 with a proposed fix; the `e751a9e..HEAD` diff does not touch it. `THREAT_MODEL.md` line 281 is a second instance of the same family: "PQ is not by itself a launch gate only while that acceptance remains in force" — again omitting the verification/reliance conjunct (held at P3, Finding 3).

**Concrete failure:** solo operator, dated acceptance in force, no independent architect exists. The new sentence forbids all reliance. A maintainer asking "does PQ hold shipment?" consults the recorded-risk-acceptance bullets — the passage most naturally consulted for precisely that question — and line 148 answers no. The supremacy clause (line 173) rescues only a reader who cross-checks the ruling; quoted alone, line 148 authorizes exactly what amendment 2 of this round was written to forbid. The brief's instruction that every reliance sentence say the same thing is not met: three sentences state one, two, and three conditions respectively.

**Fix:** mirror the operative test, e.g. "While the acceptance remains in force **and reliance is not suspended**, PQ is not by itself a reason to hold shipment." Same treatment for line 281.

### Finding 2 — P2 — Independence attaches to gate verification only; suspension, restoration, and reactivation concurrence remain with an unqualified "security architect"

`docs/phase3-post-quantum-decision.md` line 30 requires "An independently acting security architect who is not the product owner" **for gate verification**. Line 43 — separated from it by the condition list — then says "**The security architect** must record suspension ... **The security architect** may restore reliance after verifying and recording proof of uninterrupted compliance ... Reactivation requires a new dated product-owner acceptance and **security-architect concurrence**." In the ruling, "the security architect" resolves to the role defined in the Authority record (line 15) — the ruling's own author — which carries no not-the-product-owner constraint. `SECURITY_STATUS.md` blocker 77 repeats the reactivation formula, likewise unqualified.

**Concrete failure:** an independent architect verifies the pre-PQ launch gate, then becomes unavailable. Mid-flight, a continuous condition (say condition 4) goes unverified; the product owner, wearing the architect hat, records suspension and then self-restores reliance by "verifying and recording proof of uninterrupted compliance." The gate-closure sentence fires only "at each release or migration gate," so between gates the restoration path is the operative control — and it is the one path the independence requirement does not reach. The round-3 close-out reasoning ("no path by which the architect self-authorizes past a real violation, since anything violated routes through LAPSED into the two-party reactivation path") predates this amendment and no longer holds cleanly: the "two-party" reactivation collapses to one human holding both roles, because the concurrence is not independence-qualified. In `THREAT_MODEL.md` line 159 the anaphora within a single paragraph arguably carries independence through; the ruling — which controls — is the weaker text. This is the recurring pattern in this leg: the seam the fix itself created.

**Fix:** one sentence in the ruling, e.g. "Suspension recording, restoration of reliance, and the security-architect concurrence required for reactivation are subject to the same independence requirement as gate verification."

### Finding 3 — P3 — `THREAT_MODEL.md` line 281 one-conjunct variant

Covered under Finding 1; listed separately so it is not missed in remediation. "…PQ is not by itself a launch gate only while that acceptance remains in force…" — held at P3 rather than P2 because it sits inside the conjunctive claim-prerequisites list and is immediately bounded by "only once every other item here is met."

### Finding 4 — P3 — The prominent-surfacing duty narrowed from unconditional to exception-scoped

Before this round, "a failed or blocked migration must be prominently surfaced to the user" stood in the ruling's permanent fail-closed paragraph and bound the client unconditionally. At HEAD it exists only as condition 4 of the revocable acceptance. If the acceptance lapses, or is never relied on (the project waits for the PQ gate and ships post-PQ only), no text any longer requires surfacing: a client that fails closed **silently** — conversation just stops sending, no classical ciphertext, no explanation — complies with every remaining sentence. No confidentiality exposure results (fail-closed prevents harvestable classical traffic, and line 45's corrective-disclosure duty covers the lapse-after-launch case), which is why this is P3 and not higher — but it is a real reduction in the requirement's reach that the move silently introduced. **Fix:** restore one unconditional surfacing sentence to the fail-closed paragraph, or record that the narrowing is intentional.

## Task 5 — Overclaim surface

The two quotable-alone authorization sentences are Findings 1 and 3. Ruling line 32 is properly self-caveated ("This is not launch authorization"). `SECURITY_STATUS.md` remains NO-GO with 15 unchecked blockers (count verified), its checked items are harness-scoped, and blocker 77 is consistent with the docs apart from the unqualified reactivation formula noted in Finding 2. "The only defensible claim" sections in both documents remain correctly gated. No new overclaim was introduced by this round's edits.

---

**Summary for the gate:** the two amendments do what they were meant to do — the condition-4 lapse chain is complete and the no-architect case fails closed. RETURN rests on two P2s, both small in fix size: the thrice-flagged one-conjunct reliance sentence at `THREAT_MODEL.md:148` (now contradicting this very round's third reliance element), and the independence qualifier stopping at gate verification while the same actor retains unqualified control of suspension, restoration, and reactivation concurrence. All four findings have single-sentence fixes; nothing found disturbs the amendment architecture itself.
