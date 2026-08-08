# Certification round 4

# ⚠ REVIEW SHA IS `1a30f1da733b10e79bd7c9e77aa26fb821220d5d`

**NOT `e751a9e`.** A verdict was relayed against `e751a9e` using the
round-3 worktree `/tmp/sml-certify3-sol-e751a9e`. It was a re-delivery of
the round-3 verdict, its two P2s were already applied, and it was
rejected without being applied — recorded in
`reviews/REVIEW-sol-certify-phase3-amendment-v4-DUPLICATE.md`. **Delete
or ignore any existing `/tmp/sml-certify3-sol-e751a9e` worktree and
create a fresh one at the SHA above.** Round 4 is still open.

Your round-3 P2s are applied at `1a30f1d`: condition 4 is adopted into
the ruling's numbered list with an applicability statement, and gate
verification now requires an independently acting security architect who
is not the product owner. Six mandated strings verified byte-exact; the
migration-surfacing sentence was moved, not copied.

**This brief was revised after the cold review returned at `1a30f1d`.**
It carries three findings you have never ruled on plus four new ones.

## Worktree

```
git -C "/Users/new/Cursor local/secure-messenger-lab" worktree add --detach \
    /tmp/sml-certify4-sol-1a30f1d 1a30f1da733b10e79bd7c9e77aa26fb821220d5d
cd /tmp/sml-certify4-sol-1a30f1d
git rev-parse HEAD          # must print 1a30f1da733b10e79bd7c9e77aa26fb821220d5d
git symbolic-ref -q HEAD    # nothing (detached)
git status --porcelain      # empty
```

**Please report the SHA you actually reviewed.** Read-only. Your own
rulings and the cold-review verdicts are readable; no other `REVIEW-*`.
`git diff e751a9e..HEAD` is the round-3 remediation.

---

## A1 — P2. The one-conjunct reliance sentence, flagged three times, now contradicts your own round-3 amendment

This was N2 in the round-3 brief. It received no ruling. The cold review
has now found it independently a second time and shows **your round-3
change made it worse**.

`THREAT_MODEL.md`, recorded-risk-acceptance bullets:

> While the acceptance remains in force, PQ is not by itself a reason to hold shipment.

Reliance now has **three** elements, not one: the acceptance in force,
every applicable condition recorded as verified, and — added by your
P2-2 — an independently acting architect, absent whom "no reliance on the
exception is permitted."

Concrete failure, and note it is this project's actual configuration:
solo operator, dated acceptance in force, no independent architect
exists. Your new sentence forbids all reliance. A maintainer asking "does
PQ hold shipment?" consults these bullets — the passage most naturally
consulted for that question — and gets **no**. Quoted alone, this
sentence authorizes precisely what your P2-2 was written to forbid.

Three reliance sentences currently state one, two and three conditions
respectively.

Proposed: "While the acceptance remains in force **and reliance is not
suspended**, PQ is not by itself a reason to hold shipment."

**This is the third time of asking. Please rule explicitly, even if the
ruling is to decline, and give exact text if you agree.**

## A2 — P2. Your independence qualifier does not travel past the gate

Ruling line 30 requires an independently acting architect **for gate
verification**. Line 43, separated from it by the condition list, then
says: "**The security architect** must record suspension… **The security
architect** may restore reliance after verifying and recording proof of
uninterrupted compliance… Reactivation requires a new dated product-owner
acceptance and **security-architect concurrence**." None of those carry
the not-the-product-owner constraint. `SECURITY_STATUS.md` blocker 77
repeats the unqualified reactivation formula. Verified in all three
files.

Concrete failure: an independent architect verifies the pre-PQ launch
gate, then becomes unavailable. Mid-flight a continuous condition goes
unverified. The product owner, wearing the architect hat, records
suspension and then self-restores reliance by "verifying and recording
proof of uninterrupted compliance." The gate-closure sentence fires only
"at each release or migration gate," so **between gates the restoration
path is the operative control — and it is the one path independence does
not reach.**

The cold reviewer explicitly retracted its own round-3 close-out to reach
this: its earlier reasoning that nothing self-authorizes past a violation
"predates this amendment and no longer holds cleanly," because two-party
reactivation collapses to one human when the concurrence is not
independence-qualified. `THREAT_MODEL.md` may carry independence by
anaphora within its single paragraph; the ruling, which governs, does
not.

Proposed: "Suspension recording, restoration of reliance, and the
security-architect concurrence required for reactivation are subject to
the same independence requirement as gate verification." Consider whether
`SECURITY_STATUS.md` blocker 77 needs matching words.

## A3 — P3. Second one-conjunct instance

`THREAT_MODEL.md` claim-prerequisites: "…PQ is not by itself a launch
gate only while that acceptance remains in force…" Same omission as A1,
held at P3 because it sits inside the conjunctive list and is bounded by
"only once every other item here is met." Listed separately so it is not
missed in remediation.

## A4 — P3. The surfacing duty narrowed from unconditional to exception-scoped

This answers the question the round-4 brief asked, and the answer is that
something real was lost. Before round 3, "a failed or blocked migration
must be prominently surfaced" sat in the permanent fail-closed paragraph
and bound unconditionally. It now exists **only** as condition 4 of a
revocable acceptance. If the acceptance lapses, or is never relied on at
all — the project waits for the PQ gate and ships post-PQ only — no text
requires surfacing. A client that fails closed **silently**, the
conversation simply stopping with no explanation, complies with every
remaining sentence.

Held at P3 because there is no confidentiality exposure: fail-closed
prevents harvestable classical traffic, and the corrective-disclosure
duty covers lapse-after-launch. But it is a real reduction in reach that
the move introduced silently.

Proposed: restore one unconditional surfacing sentence to the fail-closed
paragraph, **or** rule that the narrowing is intentional and record why.

## A5, A6 — still unruled from round 3

- **N4 (P3)** — your F5 sentence quotes the label form "**Architect
  amendment — 2026-08-08**", but the two amendment section headers use
  variant forms and the Authority record is itself unlabelled amendment
  text. Fails safe.
- **N5 (P3)** — your ruling dates a lapse "from the earliest affected
  time"; the threat model's corresponding sentence does not, so a
  threat-model-only reader could date a lapse at discovery and treat
  breach-period traffic as covered.

---

## What the cold review certified at this SHA

So you can weigh what is settled:

- **Condition 4's consequence chain is complete in both documents** and
  the two condition-4 sentences and two applicability sentences are
  byte-identical across them. Round 3's N1 is genuinely fixed.
- **The never-offered trigger is not a defect.** A conversation never
  offered migration is ordinary pre-migration classical operation, which
  the acceptance covers; conditions 1–3 still bar any PQ claim and keep
  its unprotected status visible. "Offered **or attempted**" closes the
  probe-silently variant.
- **The solo-operator unsatisfiability of your independence requirement
  is the intended fail-closed result**, and the reviewer's instruction is
  "do not fix this." The implementer agrees and wants it on the record:
  as written, this requirement is currently met by nobody on this
  project, so the hold-shipment default simply stands. That is a real
  constraint on shipping, accepted deliberately.
- **The anti-downgrade rule has no confidentiality gap** across the
  exception-in-force, lapsed, suspended and never-activated cases.
- **No new overclaim** was introduced by round 3 beyond A1 and A3.

## Verdict format

**PASS** or **RETURN** with findings, exact replacement text where a
change is required. Rule explicitly on A1 through A6 — including any you
decline, and why.

If you reach PASS, say so plainly; do not withhold it because the leg has
run long, and do not grant it to end the leg.

`SECURITY_STATUS.md` remains NO-GO with 15 unchecked blockers. Nothing
here authorizes a launch or a public-security claim.
