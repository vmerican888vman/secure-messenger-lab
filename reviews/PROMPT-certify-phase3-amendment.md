# Certification — applied Phase 3 amendment at `6917bcb`

You ruled SIGN WITH CHANGES on the amendment to
`docs/phase3-post-quantum-decision.md` and specified exact replacement
text plus mandatory companion corrections to `THREAT_MODEL.md` at the
same SHA. That text has been applied and committed. This asks you to
certify the result.

## A declared limitation on what your PASS can mean

You authored the amendment text. A PASS from you is therefore **not an
independent review of that text's merits** — it cannot be, and this brief
does not pretend otherwise. What your PASS certifies is narrower and
still necessary:

1. the mandated text was applied where you directed, and
2. the surrounding documents remained correct once it landed, including
   sections you did not touch.

The independent merits review is being run separately by the other
reviewer, who has **not** seen your ruling and is reviewing the resulting
documents cold. If you believe that split is insufficient and the
amendment needs a third, genuinely independent reader before the leg
closes, say so — that is a legitimate finding and it will be honoured.

## Worktree — create it explicitly

Last round the brief said "pinned detached worktree" and the live
attached checkout was used instead. You compensated by reading committed
objects, and you were right to flag it. This time, please create the
worktree yourself and confirm it:

```
git -C "/Users/new/Cursor local/secure-messenger-lab" worktree add --detach \
    /tmp/sml-certify-sol-6917bcb 6917bcb0b419dea7a766115d752a87df45234dbb
cd /tmp/sml-certify-sol-6917bcb
git rev-parse HEAD          # must print 6917bcb0b419dea7a766115d752a87df45234dbb
git symbolic-ref -q HEAD    # must print nothing (detached)
git status --porcelain      # must be empty
```

Report all four observations. Then:

- **Read-only. Change nothing.** Do not edit, stage, or commit, in the
  worktree or in the live checkout.
- **Do not open any `reviews/REVIEW-*` file** other than
  `reviews/REVIEW-sol-amend-phase3-ruling.md`, which is the transcription
  of your own ruling and is the specification you are certifying against.
  `PROMPT-*` files are briefs and are fine.
- No code tests needed; this is documentation only.

## What landed

Two commits on `docs/phase2-frozen-decisions`:

- `2a07e75` — the amendment: your mandated text applied to both
  documents, plus the brief and your transcribed ruling recorded under
  `reviews/`.
- `6917bcb` — a one-comma correction, described below.

`git show 2a07e75`, `git show 6917bcb`, and
`git diff cf93af6..6917bcb -- docs/phase3-post-quantum-decision.md THREAT_MODEL.md`
give you the whole change. `cf93af6` is the substrate you authenticated.

Gates green at `6917bcb`: `cargo test` (240/5/19/27), `cargo clippy
--all-targets`, `cargo fmt --check`, DCO.

## Two implementer decisions you did not authorize, flagged rather than buried

**1. The amendment text is inserted verbatim and unwrapped.** Your
replacement blocks are single long lines; the surrounding documents are
hard-wrapped at roughly 70 columns. The text was inserted exactly as you
wrote it rather than re-flowed, so that every mandated block can be
diffed against the file mechanically instead of compared by eye. A
verbatim check over all fourteen mandated blocks passes 14/14. The
side effect is that amended passages are visually distinct from original
text, which happens to serve your finding D. If you would rather the text
were re-wrapped to match the documents, say so and it will be re-flowed
and re-verified.

**2. One edit is not in your ruling.** `THREAT_MODEL.md`'s status line
read "amended 2026-08-07", which became false when the 08-08 material
landed. It now reads:

> Status: Phase 0 draft, 2026-08-04; amended 2026-08-07 to model the
> harvest-now-decrypt-later adversary, and 2026-08-08 to record the
> product owner's confidentiality horizon, the conditional pre-migration
> risk acceptance and its disclosure obligation (see "Post-quantum"
> below). Everything outside that section still describes only the
> executable local harness in this repository.

This was treated as bookkeeping falling under your finding D ("record
both authorities and date every architect-authored amendment") rather
than as new policy. If that reads as an implementer amending an authority
document without authorization, rule against it.

Separately: `6917bcb` exists because the horizon claim-gate bullet was
first applied with a comma carried over from the text it replaced —
"post-migration traffic, and only once" where your ruling reads
"post-migration traffic and only once". Semantically identical; corrected
so the byte-exactness premise holds.

## What to certify

1. **Application fidelity.** Is every mandated change present, in the
   place you directed, and does it say what you ruled? Fourteen blocks
   were checked verbatim by string match — confirm nothing was applied to
   the wrong section, applied twice, or applied while silently displacing
   text you intended to retain. In particular confirm the two fail-closed
   defaults you ordered retained are in fact still there and still
   operative: the Ruling section's hold-shipment sentence, and the
   interim-layer section's "the default consequence is to hold shipment".

2. **Global correctness after landing.** You said no substantive change
   was required to Bounds, OpenMLS readiness, the provisional suite, the
   technical rejection of the interim layer, or the existing claim
   exclusions. Now that the amendment is in place, is that still true?
   Does any untouched passage in either document become false,
   misleading, or unreachable because of what landed around it?

3. **The two flagged implementer decisions above.**

4. **Anything the amendment now makes necessary elsewhere.** In
   particular: does `SECURITY_STATUS.md` need a corresponding entry?
   It currently carries 14 unchecked blockers and says nothing about the
   conditional acceptance, the disclosure obligation, or the operational
   hold that a post-launch lapse would require. Your amendment makes a
   pre-PQ launch conditional on that hold being enforceable, and
   `SECURITY_STATUS.md` is the file that governs launch. If it needs a
   blocker or a note, specify the exact text.

## Verdict format

**PASS** or **RETURN** with P1/P2/P3 findings, each with file, exact
quoted text, and the concrete failure it enables. If RETURN, give exact
replacement text as before. It will be transcribed verbatim into
`reviews/REVIEW-sol-certify-phase3-amendment.md`.

`SECURITY_STATUS.md` remains NO-GO. Nothing in this leg authorizes a
launch or a public-security claim.
