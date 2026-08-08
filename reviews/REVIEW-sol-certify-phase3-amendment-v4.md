# Sol certification round 4 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), security architect.
- **Head SHA reviewed:** `1a30f1da733b10e79bd7c9e77aa26fb821220d5d` —
  **the correct pin this time.** Clean, detached, no files changed;
  `git diff --check e751a9e..HEAD` passed. This supersedes the duplicate
  recorded in `REVIEW-sol-certify-phase3-amendment-v4-DUPLICATE.md`.
- **Brief:** `reviews/PROMPT-certify-phase3-amendment-v4.md`.
- **Verdict: RETURN** — two P2, two P3. No P1.

## Dispositions

| Brief item | Ruling |
|---|---|
| A4 — surfacing duty narrowed to exception scope | Sustained as **P2-1**, with text |
| A1 / N2 — one-conjunct reliance sentence | **Sustained as P2-2, with text.** Third time of asking; now ruled. |
| A5 / N4 — labelling inventory | Sustained as **P3-1**, with text |
| A6 / N5 — lapse dating | Sustained as **P3-2**, with text |
| A2 — independence does not travel past the gate | **Ruled in substance: "independence governs restoration." NO TEXT SUPPLIED.** |
| A3 — second one-conjunct instance | **NOT ADDRESSED.** |
| Condition-4 trigger | Correct, not a defect |
| Independent-architect requirement unsatisfiable for a one-human project | **Intentionally fails closed** |

## Applied

All four supplied replacements verified present exactly once and
byte-exact.

## NOT closed — verified still present after applying this ruling

**A2 — ruled but not encoded.** Sol ruled that independence governs
restoration. That ruling changes nothing in the documents, because no
replacement text was supplied. Verified after applying:

- The ruling still reads "**The security architect** must record
  suspension whenever an applicable condition is unverified. **The
  security architect** may restore reliance…" — no
  not-the-product-owner constraint.
- `SECURITY_STATUS.md` blocker 77 still reads "…require a new dated
  product-owner acceptance and security-architect concurrence before
  reactivation" — likewise unqualified.

The concrete failure the cold review described is therefore still
reachable: between gates, the product owner wearing the architect hat
records suspension and self-restores reliance. A ruling that the
documents do not carry is not a fix.

**A3 — not addressed.** The second one-conjunct instance in
`THREAT_MODEL.md`'s claim-prerequisites — "PQ is not by itself a launch
gate only while that acceptance remains in force" — received the same
treatment as A1 in neither ruling nor text, and is unchanged.

Neither is patched by the implementer. Both carried to round 5 in
`reviews/PROMPT-certify-phase3-amendment-v5.md`.

---

Relayed to Sol. Sol returned **RETURN** on clean detached SHA `1a30f1da733b10e79bd7c9e77aa26fb821220d5d`. No files changed; `git diff --check e751a9e..HEAD` passed.

- **P1:** none.
- **P2-1:** Moving condition 4 lost the unconditional migration-failure surfacing obligation in `phase3-post-quantum-decision.md:41` and `THREAT_MODEL.md:166`.

  Required replacement:

  ```markdown
  Conditions 1 and 2 apply continuously. Condition 3 becomes a hard release gate before any migration-capable release ships. Condition 4 applies continuously to each conversation from the first time authenticated PQ migration is offered or attempted for that conversation. Its prominent-surfacing requirement remains binding whether or not reliance on this exception is claimed, suspended, or lapsed; its prohibition on classical-only continuation is additionally enforced by the governing fail-closed rule whenever PQ is required.
  ```

- **P2-2:** N2 is valid. `THREAT_MODEL.md:148` retains a one-conjunct reliance test.

  Required replacement:

  ```markdown
  - While the acceptance remains in force and reliance on the exception is not suspended, PQ is not by itself a reason to hold shipment. This is not launch authorization: every unchecked blocker in `SECURITY_STATUS.md` remains independently controlling.
  ```

- **P3-1:** N4 is valid. The authority inventory in `phase3-post-quantum-decision.md:15` does not literally identify all amendment text.

  Required replacement:

  ```markdown
  Original architect text remains authoritative except for the amended Status paragraph, this Authority record, the in-place amendments to sequencing steps 1 and 5, the sections headed **Architect amendment — conditional pre-migration exception (2026-08-08)** and **Architect amendment — pre-migration V1 production state (2026-08-08)**, and paragraphs labelled **Architect amendment — 2026-08-08**, all of which expressly qualify it.
  ```

- **P3-2:** N5 is valid. `THREAT_MODEL.md:159` omits retroactive lapse dating.

  Required replacement:

  ```markdown
  Evidence of a violation makes the acceptance LAPSED from the earliest affected time and invokes the governing ruling's fail-closed consequence; traffic created during the breach cannot be retroactively authorized.
  ```

Sol also ruled that the condition-4 trigger is correct; the independent-architect requirement intentionally fails closed for the one-human project; and independence governs restoration. `SECURITY_STATUS.md` remains **NO-GO** with 15 unchecked blockers.
