# Round-4 relay — DUPLICATE of the round-3 verdict, rejected, not applied

A verdict was relayed in response to
`reviews/PROMPT-certify-phase3-amendment-v4.md`. It is a re-delivery of
the **round-3** verdict already recorded in
`reviews/REVIEW-sol-certify-phase3-amendment-v3.md` and already applied
at `1a30f1d`. It was **not applied** and does not close round 4.

## Evidence

| Marker | Relayed verdict | Round-4 brief specified |
|---|---|---|
| SHA reviewed | `e751a9ee6aa8c2ab72307f4e0327e8bb154fe382` | `1a30f1da733b10e79bd7c9e77aa26fb821220d5d` |
| Worktree cited | `/tmp/sml-certify3-sol-e751a9e` | `/tmp/sml-certify4-sol-1a30f1d` |
| Findings | P2-1, P2-2 — identical text to round 3 | — |

Both mandated changes were verified **already present** in the working
tree before this note was written: ruling condition 4, the condition-4
timing sentence in both documents, and the independence clause in both
documents. Applying the verdict again would have been a no-op at best.

## What remains unanswered

The round-4 brief asked six things, none addressed by this relay:

1. **N2** — the one-conjunct reliance sentence. Verified still present
   and still reachable: `THREAT_MODEL.md` continues to read "While the
   acceptance remains in force, PQ is not by itself a reason to hold
   shipment" against a two-conjunct operative test.
2. **N4** — labelling residue.
3. **N5** — lapse dating omits "from the earliest affected time".
4. **The lapse gap the move created.** The fail-closed paragraph was a
   permanent prohibition; condition 4 is a condition of a revocable
   exception. If the acceptance lapses or reliance is never claimed, the
   migration-surfacing requirement may no longer bind.
5. **Condition 4's operator-controlled trigger.** Never offering
   migration leaves it permanently inapplicable and therefore
   permanently verified.
6. **Whether independence extends to suspension and restoration**, which
   the same actor controls and which re-enable reliance.

## Why this is recorded rather than silently re-relayed

This project's certification discipline rests on verdicts being bound to
exact SHAs. A superseded verdict applied as though current is precisely
the failure that damaged a sibling repository on 2026-08-08, where a
424-line change was justified by a verdict two rounds stale. The guard
that caught it here was checking the SHA and worktree path in the verdict
against the ones the brief pinned. Every future relay gets the same
check.

**Round 4 remains open.** `reviews/PROMPT-certify-phase3-amendment-v4.md`
needs to be relayed against `1a30f1d`.

---

# Second duplicate — round-4 verdict relayed as round 5, rejected, not applied

A second stale verdict was relayed, this time in response to
`reviews/PROMPT-certify-phase3-amendment-v5.md`. It is a re-delivery of
the **round-4** verdict recorded in
`reviews/REVIEW-sol-certify-phase3-amendment-v4.md` and already applied
at `ddf5d34`. **Not applied.** Round 5 remains open.

## Evidence

| Marker | Relayed verdict | Round-5 brief specified |
|---|---|---|
| SHA reviewed | `1a30f1da733b10e79bd7c9e77aa26fb821220d5d` | `ddf5d3468da4aa6885d50db121006e396d3e234b` |
| Worktree cited | `/tmp/sml-certify4-sol-1a30f1d` | `/tmp/sml-certify5-sol-ddf5d34` |
| Findings | P2-1, P2-2, P3-1, P3-2 — identical text to round 4 | — |

All four "required replacements" were verified **already present** in the
working tree before this note was written. B1 and B2 — the only two items
the round-5 brief asked about — are not mentioned, and both were verified
still open.

## Diagnosis — first attempt, and its CORRECTION

**First diagnosis, now known to be wrong.** It was recorded here that the
contributing condition was the four stale Sol worktrees still being on
disk and registered, on the reasoning that `git worktree add` fails when
its target path exists and so invites falling back into an old
directory.

**Evidence contradicting it.** After the four stale worktrees were
removed with the user's approval, inspection showed that
`/private/tmp/sml-certify5-sol-ddf5d34` **already existed, was
registered, was detached at exactly**
`ddf5d3468da4aa6885d50db121006e396d3e234b`, **and was clean.** The
round-5 worktree had been created correctly. The correct tree was present
and readable at the moment the round-4 verdict was returned.

So the stale worktrees were not the cause, and removing them would not
have prevented either duplicate. The verdict was produced without reading
the tree that was in front of it — a reply regenerated from conversational
context rather than from a fresh read.

That distinction matters for the process: **worktree hygiene is not a
control against this failure.** The only control that works is one that
requires evidence of a read.

## Mitigation

A **verification challenge** in the round-5 brief: the reviewer must
quote, verbatim and before reviewing, two strings that exist only at
`ddf5d34`. Both were introduced by the round-4 fixes and are absent from
`e751a9e` and `1a30f1d`. Confirmed retrievable from the round-5 worktree:

1. "Its prominent-surfacing requirement remains binding whether or not
   reliance on this exception is claimed, suspended, or lapsed; its
   prohibition on classical-only continuation is additionally enforced by
   the governing fail-closed rule whenever PQ is required."
2. "…except for the amended Status paragraph, this Authority record, the
   in-place amendments to sequencing steps 1 and 5, …"

A reply regenerated from stale context cannot produce these, so a third
duplicate is detectable from the verdict's opening lines rather than by
diffing its findings against history.

## Worktree removal

Performed with the user's approval: the four stale Sol worktrees from
this leg were removed after each was verified detached, clean, and
stash-free. Count 51 → 47. All four SHAs remain reachable in branch
history and every verdict is recorded under `reviews/`. The 37
pre-existing `sml-review-*` worktrees were **not** touched and remain at
37. `/private/tmp/sml-certify5-sol-ddf5d34` was deliberately kept — it is
the current round's tree and is correct.

This removal was housekeeping, not mitigation. See the correction above.
