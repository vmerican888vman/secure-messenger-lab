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
