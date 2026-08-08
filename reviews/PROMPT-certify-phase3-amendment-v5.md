# Certification round 5 — two items, at `ddf5d34`

# ⚠ REVIEW SHA IS `ddf5d3468da4aa6885d50db121006e396d3e234b` — run `git rev-parse HEAD` and report it

## ⚠ TWO STALE VERDICTS HAVE NOW BEEN RETURNED IN A ROW — READ THIS FIRST

The last two relays were re-deliveries of already-applied verdicts, not
new reviews:

- One reviewed `e751a9e` from `/tmp/sml-certify3-sol-e751a9e`.
- One reviewed `1a30f1d` from `/tmp/sml-certify4-sol-1a30f1d`.

Both were byte-identical to verdicts already recorded and applied, and
neither addressed the items actually asked. Both were rejected without
being applied.

**Those worktree directories still exist on disk.** Do not `cd` into one,
and do not reuse a previous command. `git worktree add` will fail if the
target path already exists — if that happens, use a fresh path rather
than falling back to an existing directory.

### Mandatory verification challenge — answer before reviewing

Two strings below exist **only** at `ddf5d34`. They did not exist at
`e751a9e` or `1a30f1d`. Quote both verbatim from your worktree, at the
top of your reply:

1. From `docs/phase3-post-quantum-decision.md`, the **final sentence** of
   the paragraph beginning "Conditions 1 and 2 apply continuously".
2. From `docs/phase3-post-quantum-decision.md`, the words that appear in
   the Authority record's last sentence **immediately after** "except for
   the amended Status paragraph,".

If you cannot produce both from the tree in front of you, you are not at
the right SHA — stop and re-create the worktree rather than answering
from context.

Your round-4 replacements are applied and verified byte-exact: the
surfacing requirement now binds whether or not reliance is claimed,
suspended or lapsed; the reliance sentence carries the suspension
conjunct; the authority inventory is literal; the threat model has
retroactive lapse dating.

**This brief is short. Two items remain, and both are on you rather than
on the implementer — one is a ruling you made without supplying text, the
other was not addressed.**

## Worktree

```
git -C "/Users/new/Cursor local/secure-messenger-lab" worktree add --detach \
    /tmp/sml-certify5-sol-ddf5d34 ddf5d3468da4aa6885d50db121006e396d3e234b
cd /tmp/sml-certify5-sol-ddf5d34
git rev-parse HEAD          # report this
git symbolic-ref -q HEAD    # nothing (detached)
git status --porcelain      # empty
```

Read-only. `git diff 1a30f1d..HEAD` is the round-4 remediation.

---

## B1 — your A2 ruling is not encoded anywhere

You ruled: **"independence governs restoration."** No replacement text
accompanied it, so the documents did not change. Verified after applying
everything else you sent:

`docs/phase3-post-quantum-decision.md`:

> **The security architect** must record suspension whenever an applicable condition is unverified. **The security architect** may restore reliance after verifying and recording proof of uninterrupted compliance… Reactivation requires a new dated product-owner acceptance and **security-architect concurrence**.

`SECURITY_STATUS.md` blocker 77:

> …after a violation, require a new dated product-owner acceptance and **security-architect concurrence** before reactivation.

Neither carries the not-the-product-owner constraint that your round-3
P2-2 attached to gate verification. So the failure remains exactly as the
cold review described it: an independent architect verifies the launch
gate and then becomes unavailable; a continuous condition goes unverified
mid-flight; the product owner wearing the architect hat records
suspension and self-restores reliance. **Between gates, restoration is
the operative control, and it is the one path independence does not
reach.** The gate-closure sentence fires only "at each release or
migration gate."

The cold reviewer's proposal: "Suspension recording, restoration of
reliance, and the security-architect concurrence required for
reactivation are subject to the same independence requirement as gate
verification."

**Exact text please**, for the ruling and for `SECURITY_STATUS.md`
blocker 77 if you want it there too. The implementer will not draft
either — blocker 77 is in the file that governs launch.

## B2 — A3 was not addressed

You gave exact text for the one-conjunct sentence at
`THREAT_MODEL.md:148` (your P2-2). The same family has a second instance
in the claim-prerequisites list, which was reported as A3 and is
unchanged:

> - The **INDEFINITE confidentiality horizon** honoured for the traffic being claimed about. Under the incorporated conditional acceptance, PQ is not by itself a launch gate only while that acceptance remains in force; the claim remains available only for post-migration traffic and only once every other item here is met.

"only while that acceptance remains in force" — same omission of the
verification/reliance conjunct you just corrected nine lines away. Held
at P3 by the cold review because it sits inside a conjunctive list
bounded by "only once every other item here is met."

**Rule and give exact text, or rule that the surrounding conjunctive
framing makes it harmless and say so** — either closes it permanently.

---

## Notes

- The implementer has **not dispatched the cold reviewer at this SHA**,
  because certifying a tree with two known-open findings wastes the
  round. Both reviewers will certify the SHA that closes B1 and B2.
- If B1 and B2 are the last of it, say so — the next SHA is then the
  dual-PASS candidate.
- Recorded and not re-litigated: the condition-4 trigger is correct, and
  the independent-architect requirement intentionally fails closed for a
  one-human project. The implementer accepts both and has recorded that
  the requirement is currently satisfiable by nobody here, so the
  hold-shipment default stands.

`SECURITY_STATUS.md` remains NO-GO with 15 unchecked blockers. Nothing
here authorizes a launch or a public-security claim.
