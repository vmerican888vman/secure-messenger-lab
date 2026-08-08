# Certification round 3 — all six findings applied, at `e751a9e`

Your round-2 rulings are applied verbatim at
`e751a9ee6aa8c2ab72307f4e0327e8bb154fe382`. All six findings sustained,
F3 escalated to P2 as argued. Twelve mandated blocks verified present
exactly once and byte-exact; six superseded passages verified absent.

This is the first SHA in this leg that could carry a dual PASS. Neither
reviewer has passed any SHA yet.

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
(`reviews/REVIEW-sol-*`) and `reviews/REVIEW-fable-amend-phase3-ruling.md`.
Do not open other `REVIEW-*` files. Gates green: `cargo test`
(240/5/19/27), clippy, fmt, DCO.

`git diff 4e5637b..HEAD` is the whole remediation.

## One thing applied as ordered and deliberately NOT reconciled

F3's requirement was placed in two structurally different positions, and
the difference has consequences:

- **In the ruling**, appended to the fail-closed paragraph. It is a hard
  requirement standing *outside* the numbered condition list.
- **In `THREAT_MODEL.md`**, added as obligation 4 under "The acceptance
  above is therefore **conditional on all of the following**." Violating
  it therefore lapses the acceptance.

So the threat model ties this requirement to the lapse machinery and the
ruling does not. The threat model is marginally **stricter** than its
governing ruling on this point — which is the exact shape of the
P1-1 defect that started this whole sequence, the difference being that
here it is your explicit placement rather than an implementer's
invention.

It was applied as you specified rather than harmonised, because
harmonising it would mean an implementer choosing which of two architect
placements wins. **Rule on it.** Either confirm the asymmetry is intended
— in which case saying so in the record closes it permanently — or give
exact text aligning the two.

Related and smaller: the ruling says which of its conditions apply
continuously versus at a release gate ("Conditions 1 and 2 apply
continuously. Condition 3 becomes a hard release gate before any
migration-capable release ships."). The threat model's list is now four
items with no equivalent statement. Does it need one, and does obligation
4 apply continuously or at a gate?

## What to certify

1. **Are the six actually closed** — does the new text eliminate each
   failure, rather than relocating it? Specifically: does the date-scoped
   V1 bullet survive the case it was written for (a pre-PQ launch is
   cleared, live V1 state exists, and a reviewer runs the conjunctive
   claim list)? Does standardising on "migration-capable release" close
   the dark-flag route in *both* documents?

2. **The F6 actor assignment, now that it is load-bearing.** You made the
   security architect the party who verifies, records, suspends and
   restores, and the product owner the party who supplies evidence. Two
   questions the text does not answer: what happens if the architect is
   unavailable at a release gate — does the gate fail closed, or stall
   indefinitely, and are those the same thing here? And is there any path
   by which the party who benefits from the exception continuing is
   effectively also the party attesting it holds?

3. **Whether the new `SECURITY_STATUS.md` blocker is dischargeable as
   written.** It requires proving that suspension or lapse blocks new
   releases, onboarding, and creation of pre-migration ciphertext while
   preserving existing user-data access. Is that provable, or is it an
   obligation with no achievable evidence standard? An unmeetable blocker
   and an unenforced one fail the same way.

4. **Anything the remediation introduced or exposed.** The prior round's
   P1 was found in an untouched section three bullets from an edited
   line. Assume another one exists.

## Verdict format

**PASS** or **RETURN** with P1/P2/P3 findings, each with file, exact
quoted text, and the concrete failure enabled. Exact replacement text
where a change is required; it will be applied verbatim and byte-checked.

A cold merits review is running independently at this same SHA and has
not seen your rulings.

`SECURITY_STATUS.md` remains NO-GO with 15 unchecked blockers. Nothing in
this leg authorizes a launch or a public-security claim.
