# Certification round 4 — at `1a30f1d`

Your two P2s are applied verbatim at
`1a30f1da733b10e79bd7c9e77aa26fb821220d5d`. Six mandated strings verified
present exactly once and byte-exact; the migration-surfacing sentence was
**moved** into condition 4 rather than copied — it occurs exactly once in
each document — and the superseded two-actor gate sentence is verified
absent from both.

## First: three findings you did not rule on

Your verdict said "P1: none. P3: none. Two P2 findings remain." Neither
P2 was **N2**, and no reasoning was given for **N4** or **N5**. "P3:
none" may mean you had no P3 findings of your own rather than that you
dismissed the reported ones. The implementer did not guess, and did not
patch them. They need an explicit ruling.

**N2 — P2, and verified still reachable after your round-3 changes.**
Your P2-2 rewrote the gate paragraph. The sentence at issue is a
different, untouched one in `THREAT_MODEL.md`'s recorded-risk-acceptance
bullets:

> While the acceptance remains in force, PQ is not by itself a reason to hold shipment.

One conjunct. Your ruling's operative test — which this round left intact
— has two: the acceptance in force **and** every applicable condition
recorded as verified.

Failure: reliance is suspended because a condition is unverified at a
gate, while the acceptance itself remains in force. A maintainer consults
this bullet, which is the passage most naturally consulted for exactly
this question, and concludes PQ does not hold shipment. Under your ruling
it does. The cold reviewer held it at P2 rather than P1 because the
supremacy clause resolves it in the rigorous direction and the sentence
is immediately chased by "This is not launch authorization."

Its proposed fix was to mirror the two-conjunct test: "While the
acceptance remains in force *and reliance is not suspended*…". **Rule,
and give exact text if you agree.**

**N4 — P3.** Your F5 sentence quotes the label form "**Architect
amendment — 2026-08-08**", but the two amendment *section headers* use
variant forms, and the Authority record section is itself unlabelled,
unenumerated amendment text. Fails safe.

**N5 — P3.** Your ruling dates a lapse "from the earliest affected time";
the threat model's corresponding sentence does not, so a
threat-model-only reader could date a lapse at discovery and treat
breach-period traffic as covered.

## Worktree

```
git -C "/Users/new/Cursor local/secure-messenger-lab" worktree add --detach \
    /tmp/sml-certify4-sol-1a30f1d 1a30f1da733b10e79bd7c9e77aa26fb821220d5d
cd /tmp/sml-certify4-sol-1a30f1d
git rev-parse HEAD          # 1a30f1da733b10e79bd7c9e77aa26fb821220d5d
git symbolic-ref -q HEAD    # nothing (detached)
git status --porcelain      # empty
```

Read-only. Your own rulings and the cold-review verdicts are readable; no
other `REVIEW-*`. `git diff e751a9e..HEAD` is this round's change.

## What else to certify

1. **Did moving the requirement into condition 4 attach the consequence
   you intended, without losing what the old placement gave?** The two
   are not equivalent: the fail-closed paragraph was a permanent
   prohibition, condition 4 is a condition of a **revocable** exception.
   If the acceptance LAPSES, or if reliance on the exception is never
   claimed at all, does the migration-surfacing requirement still bind?
   The old sentence bound unconditionally; the new one may not.

2. **Condition 4's trigger is an action the operator controls.** It
   applies "from the first time authenticated PQ migration is offered or
   attempted for that conversation." A conversation for which migration
   is never offered never triggers it. Is that correct — the requirement
   is about failure *of an attempt*, so no attempt means nothing to
   surface — or does it leave a shape where declining to offer migration
   indefinitely keeps conversations classical while condition 4 remains
   permanently inapplicable and therefore permanently verified?

3. **P2-2's independence requirement, and whether it is satisfiable.**
   This project has one human operator. "An independently acting security
   architect who is not the product owner" may currently be met by nobody.
   Confirm that is the intended fail-closed result and not an oversight —
   the implementer reads it as intended and as a real constraint on
   shipping, and wants that on the record rather than discovered later.
   Separately: the independence requirement governs the **gate**. Nothing
   states the same independence for the **suspension and restoration**
   decisions, which the same actor controls, and restoration is the step
   that re-enables reliance. Should it?

4. **Anything this round introduced.** Each of the last three rounds
   found a defect in an untouched passage within a few lines of edited
   text, and one was created by the previous fix.

## Verdict format

**PASS** or **RETURN** with P1/P2/P3 findings, each with file, exact
quoted text, and the concrete failure enabled. Exact replacement text
where a change is required.

If you reach PASS, say so plainly — do not withhold it because the leg
has run long. Equally, do not pass to end the leg. A cold merits review
is running independently at this same SHA.

`SECURITY_STATUS.md` remains NO-GO with 15 unchecked blockers. Nothing
here authorizes a launch or a public-security claim.
