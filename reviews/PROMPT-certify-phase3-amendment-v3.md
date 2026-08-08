# Certification round 3 — at `e751a9e`

**This brief was revised before relay.** An earlier version asked you to
rule on one flagged asymmetry. The cold review then returned at the same
SHA and found that asymmetry to be a **P1 that resolves in the weaker
direction**, plus two P2s in the seam the remediation created. All of it
is below. Nothing has been sent to you twice.

Your round-2 rulings are applied verbatim at
`e751a9ee6aa8c2ab72307f4e0327e8bb154fe382`. All six sustained, F3
escalated to P2 as argued. Twelve mandated blocks verified present
exactly once and byte-exact; six superseded passages verified absent.

The cold reviewer **ruled all six of its prior findings CLOSED** and
returned solely on what the fixes introduced or exposed. Its close-out
reasoning on F6 is worth your attention: it traced the absent-architect
case and found the mechanism stalls **closed**, because reliance is
conditioned on an affirmative architect *record* — so a missing architect
defaults to hold-shipment, which is the correct direction. It also found
no path by which the architect self-authorizes past a real violation,
since anything actually violated routes through LAPSED into the two-party
reactivation path.

## Worktree

```
git -C "/Users/new/Cursor local/secure-messenger-lab" worktree add --detach \
    /tmp/sml-certify3-sol-e751a9e e751a9ee6aa8c2ab72307f4e0327e8bb154fe382
cd /tmp/sml-certify3-sol-e751a9e
git rev-parse HEAD          # e751a9ee6aa8c2ab72307f4e0327e8bb154fe382
git symbolic-ref -q HEAD    # nothing (detached)
git status --porcelain      # empty
```

Read-only, change nothing. You may read your own rulings
(`reviews/REVIEW-sol-*`) and the two cold-review verdicts
(`reviews/REVIEW-fable-*`). Do not open other `REVIEW-*` files. Gates
green: `cargo test` (240/5/19/27), clippy, fmt, DCO.
`git diff 4e5637b..HEAD` is the whole remediation.

---

## N1 — P1. Your F3 placement makes the requirement consequence-free, not stricter

This is the item the earlier brief flagged, and the earlier brief
**characterised it wrongly**. It said the threat model had become
"marginally stricter than the ruling." The cold reviewer showed the
opposite is true in effect, and the implementer has verified the
reasoning against the files.

- `THREAT_MODEL.md` obligation 4 sits under "conditional on all of the
  following", and that section says "Evidence of a violation makes the
  acceptance LAPSED."
- The ruling places the identical requirement as a standalone sentence in
  the fail-closed paragraph, **outside** numbered conditions 1–3. The
  ruling's lapse machinery fires only on violation of "an applicable
  condition."
- `THREAT_MODEL.md` also says: "The governing ruling controls wherever
  the documents differ."

A stricter clause in the subordinate document is therefore not stricter.
It is **void**. Net effect: the migration-surfacing requirement has a
hard prohibition and **no lifecycle consequence anywhere**.

Concrete failure, verified as reachable: a migration-capable release is
live under the exception. One conversation's migration is blocked and the
client silently keeps writing Olm ciphertext — while conditions 1–3 all
still verify, because no surface overclaims and the distinguishability
surface correctly marks traffic as classical. Under `THREAT_MODEL.md` the
acceptance lapses and the operational hold fires. Under the ruling no
condition was violated, so the exception stays verified and pre-migration
ciphertext creation lawfully continues while the client is in flagrant
breach of a hard requirement.

The reviewer's ruling, which the implementer endorses: **the fix belongs
in the ruling, not in weakening `THREAT_MODEL.md`.** Adopt the
requirement as condition 4 of the ruling, or attach an explicit
suspension/lapse consequence to it where it stands.

**Needs your exact replacement text.**

## N2 — P2. F6 removed the self-executing suspension backstop, leaving a one-conjunct reliance sentence exposed

Your F6 text correctly replaced passive voice with a named actor. But the
sentence it replaced — "An applicable condition that is unverified
suspends reliance on the acceptance" — was *self-executing*. The
replacement is a recording **duty** on the architect.

That removed the only thing partially covering an untouched sentence,
`THREAT_MODEL.md` in the recorded-risk-acceptance bullets:

> While the acceptance remains in force, PQ is not by itself a reason to hold shipment.

One conjunct. Your ruling's operative test has two — the acceptance in
force **and** every applicable condition recorded as verified.

Concrete failure: reliance is suspended because a condition is unverified
at a gate, while the acceptance itself remains in force. A maintainer at
that gate consults this bullet — the passage most naturally consulted for
exactly this question — and concludes PQ does not hold shipment. Under
your ruling, it does.

The reviewer held this at P2 because the supremacy clause resolves it in
the rigorous direction and the sentence is immediately chased by "This is
not launch authorization." Proposed fix: mirror the two-conjunct test,
e.g. "While the acceptance remains in force *and reliance is not
suspended*…"

Worth recording: this is the untouched-section trap firing a second time
in this leg, and this time it was **created by the remediation**, three
bullets from remediated text.

## N3 — P2. The threat model's four-condition list has no applicability statement, and your ruling cannot supply one for condition 4

Your ruling says conditions 1–2 apply continuously and 3 is a release
gate. `THREAT_MODEL.md` pivots verification on "every condition
applicable at that gate" — but its list now has four items and never says
which apply when, and item 4 has no counterpart in the ruling's numbered
list at all.

Concrete failure: at a gate the architect must decide whether condition 4
is "applicable." Neither document answers. Deeming it inapplicable drops
the silent-downgrade control out of verification entirely — and per N1
the supremacy clause backs that reading.

The reviewer notes N1 and N3 have a single joint fix: add condition 4 to
the ruling with an applicability statement such as "applies continuously
once authenticated PQ migration is offered or attempted."

## N4 — P3. Labelling-invariant residue

Your F5 sentence quotes the label form "**Architect amendment —
2026-08-08**", but the two amendment *section headers* use variant forms
("…conditional pre-migration exception (2026-08-08)", "…pre-migration V1
production state (2026-08-08)"), and the Authority record section is
itself unlabelled, unenumerated amendment text. Fails safe — a literal
reader excluding the mismatched sections falls back to original, stricter
text — hence P3.

## N5 — P3. The threat model's lapse sentence drops "from the earliest affected time"

Your ruling dates a lapse from the earliest affected time. The threat
model's corresponding sentence does not. A threat-model-only reader could
date a lapse at discovery and treat breach-period traffic as covered.
Mitigated by the cross-reference to "the governing ruling's fail-closed
consequence" and the supremacy clause.

---

## Two further questions, and one advisory

1. **Is the new `SECURITY_STATUS.md` blocker dischargeable?** The
   reviewer ruled yes, with a caveat: "creation of pre-migration message
   ciphertext," read as a universal fleet guarantee, is **not literally
   provable** — an unreachable client can still encrypt. It judged the
   blocker discharged by relay-side refusal of new sends plus tested
   client hold behaviour, since the harvestable surface the exception
   governs is wire traffic. Advisory: the blocker or its discharge
   evidence should pin the enforcement point, so a future reader does not
   read "creation" as an impossible universal guarantee and either fake
   the proof or treat the blocker as unmeetable. **Do you want the
   blocker text amended to say so?**

2. **Does anything above change your view that no third independent
   reader is required?**

## Verdict format

**PASS** or **RETURN** with P1/P2/P3 findings. For N1–N5, rule and give
exact replacement text where a change is required; it will be applied
verbatim and byte-checked, then both reviewers certify the resulting SHA.

Neither reviewer has PASSed any SHA in this leg.

`SECURITY_STATUS.md` remains NO-GO with 15 unchecked blockers. Nothing
here authorizes a launch or a public-security claim.
