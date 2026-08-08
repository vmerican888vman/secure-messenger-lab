# Amendment request — `docs/phase3-post-quantum-decision.md`

**This is not a code review. It is a request for a ruling.** You are
being asked to act as the security architect who issued the Phase 3
decision, and to decide whether to sign, alter, or decline an amendment
to your own frozen document. Nothing has been committed. The working-tree
change described below is held, unreviewed, pending your answer.

## Why you are being asked rather than told

`docs/phase3-post-quantum-decision.md` is marked
`Status: DECIDED by the security architect`. Two product-owner decisions
landed on 2026-08-08 that the ruling's text does not accommodate, and the
threat model now says in two places that the ruling needs "a matching
amendment from the architect."

The implementer drafted that amendment. It is being withheld because of
the finding you yourself returned two rounds ago:

> **A review comment is not an amendment to the frozen ruling.** The
> threat model may not encode policy the ruling lacks, whatever a
> reviewer suggested in passing.
> — `reviews/REVIEW-sol-threat-model-pq-v2.md`, P1-1

The inverse applies here. An implementer may not relax a frozen ruling
because a product decision made relaxation convenient. The closure you
offered on that finding was: *"either amend the governing ruling to adopt
the policy explicitly, or retain an `UNDECIDED` fail-closed state pending
an authorized product/architect decision."* This is the first branch
being exercised. It needs your signature or it does not land.

## Worktree and ground rules

- Pinned detached worktree at exact SHA
  **`cf93af65add55eea967f5981b41be1b6581812e3`** (branch
  `docs/phase2-frozen-decisions`, current HEAD).
- **Read-only. Change nothing.** Do not edit, stage, or commit.
- **Do not open any `reviews/REVIEW-*` file.** Your independence from the
  other reviewer's verdicts is the point of the process. `PROMPT-*` files
  are briefs, not verdicts, and are fine to read.
- The four gates are green at this SHA: `cargo test` (240/5/19/27),
  `cargo clippy --all-targets`, `cargo fmt --check`, and
  `sh scripts/check-dco.sh origin/docs/phase2-frozen-decisions..HEAD`.
  Nothing here touches code; the amendment is documentation only.

**The worktree does NOT contain the proposed amendment.** It is
uncommitted. The exact proposed diff is reproduced in full below so you
are ruling on the actual text, not a paraphrase.

## Read for context, in this order

1. `docs/phase3-post-quantum-decision.md` — your ruling, as it stands
   without the amendment.
2. `THREAT_MODEL.md`, the post-quantum section — specifically
   "Confidentiality horizon", "What the indefinite horizon entails",
   "Recorded risk acceptance for pre-migration traffic", "Disclosure
   obligation", and "What must be true before the claim is available".
3. `SECURITY_STATUS.md` — 14 unchecked blockers, verdict NO-GO. This file
   is the authority on what may be claimed publicly.

## The two product-owner decisions, as recorded

Both are in `THREAT_MODEL.md` at this SHA. Neither is being asked of
you — they are recorded facts. What is being asked is what your ruling
should say in light of them.

**1. Confidentiality horizon — INDEFINITE** (commit `57db7bb`). Message
plaintext must remain confidential without a time limit. The horizon was
always a product decision; the ruling asked the threat model to *state* a
horizon and the owner has now supplied the value.

**2. Pre-migration PQ gap — accepted and disclosed** (commit `cf93af6`).
Traffic sent before the authenticated PQ migration is classically
protected, harvestable, and never acquires the new protection
retroactively. The owner accepts that gap, so that PQ gates the public PQ
claim rather than the launch. The acceptance is narrow — it covers the PQ
gap only and licenses nothing about the contact ceremony, identity
binding, endpoint compromise, metadata, or any other open blocker — and
it is **conditional on a three-part disclosure obligation, and lapses if
any part is unmet**.

Note the sequence this produced. Commit `57db7bb` derived from your
ruling that an indefinite horizon makes PQ a shipping requirement, which
activates your hold-shipment rule, and stated plainly that this was a
hold on shipment and not merely on the claim. Commit `cf93af6` then
recorded an owner acceptance that reverses that consequence. Both are
now in the threat model, and the ruling's own text still says the
default consequence is to hold shipment. **The two documents currently
disagree**, with the threat model itself stating that the ruling governs
where they differ. That is the condition the amendment is meant to end.

## The proposed amendment, in full

Exact `git diff docs/phase3-post-quantum-decision.md` against `cf93af6`
— 39 insertions, 11 deletions:

```diff
@@ -3,6 +3,8 @@
 **Status: DECIDED by the security architect. Route 1 — pull MLS forward.**
 No outer hybrid layer. No Olm fork. No production PQ claim until the
 standardization / upstream / mobile / human-review gate passes.
+Product-owner confidentiality-horizon, pre-migration risk-acceptance and
+disclosure decisions recorded on 2026-08-08 are incorporated below.
 
 This records a ruling, not a proposal. It supersedes the options laid out
 in `reviews/PROMPT-design-phase3-post-quantum.md`.
@@ -13,8 +15,34 @@ Use standardized **hybrid-PQ MLS** for both 1:1 and groups. Post-quantum
 is a reason to start the MLS and Delivery Service work NOW, not a
 separate workstream.
 
-If PQ is a shipping requirement, **shipment waits for the production
-gate** rather than silently falling back to a classical suite.
+Under the product-owner decision below, **PQ gates the public claim, not
+the launch**. This does not permit a silent fallback after authenticated
+migration or relax any non-PQ launch prerequisite.
+
+## Product-owner decisions — horizon, acceptance and disclosure
+
+Recorded on 2026-08-08 in `THREAT_MODEL.md` and incorporated into this
+ruling:
+
+1. The confidentiality horizon for message plaintext is **INDEFINITE**.
+   Messages are intended to remain confidential without a time limit.
+2. The post-quantum gap for traffic sent before the authenticated PQ
+   migration is **accepted and disclosed**. That traffic remains
+   classically protected, is harvestable, and never acquires the new
+   protection retroactively. PQ therefore gates the public PQ claim, not
+   launch by itself. This acceptance covers only the PQ gap and does not
+   clear any other launch or security blocker.
+3. That acceptance is **conditional on the disclosure obligation** below
+   and lapses if any part is unmet:
+   - No product surface — UI, store listing, marketing or documentation —
+     may state or imply post-quantum protection before migration.
+   - Every user-facing encryption description must accurately describe
+     the protection provided. "End-to-end encrypted" is accurate for the
+     current scheme; language stating or implying resistance to future
+     quantum decryption is not.
+   - When migration ships, users must be able to tell that pre-migration
+     traffic does not have the new protection. The upgrade must not imply
+     that earlier history is covered.
 
 ## OpenMLS readiness — the deciding input
 
@@ -72,11 +100,11 @@ keys, authenticated transcript binding, erasure, downgrade resistance,
 retry/replay handling, loss recovery and durable rekey state — in
 substance a second ratchet and a new protocol.
 
-If the harvest-now-decrypt-later window is unacceptable before
-standardized MLS is ready, **the default consequence is to hold
-shipment.** An interim layer would require its own human-authored
-specification and independent audit; this ruling does not pre-authorize
-one.
+The product owner has accepted the disclosed pre-migration
+harvest-now-decrypt-later window, subject to the disclosure obligation
+above, so that window is not by itself a reason to hold shipment. An
+interim layer would still require its own human-authored specification
+and independent audit; this ruling does not pre-authorize one.
 
 ## Bounds
 
@@ -95,10 +123,10 @@ allocation.
 
 ## Sequencing
 
-1. Extend the threat model with the HNDL adversary, confidentiality
-   horizon, compromise timing, erasure assumptions and precise claim
-   language. `THREAT_MODEL.md` is a Phase-0 draft that explicitly
-   excludes post-quantum adversaries.
+1. Maintain `THREAT_MODEL.md` with the HNDL adversary, indefinite
+   confidentiality horizon, compromise timing, erasure assumptions,
+   pre-migration acceptance, disclosure obligation and precise claim
+   language.
 2. Freeze and verify the contact ceremony, identity/authentication
    service, identity-bound envelope handling, and single-use KeyPackage
    publication/claim. **A PQ KEM authenticated to a substituted identity**
```

## The implementer's own concerns with this draft

These are flagged rather than hidden, because a brief that presents a
draft as clean invites a rubber stamp. Rule on them, add to them, or
dismiss them.

**A. The acceptance is revocable; the amendment deletes the default it
would revert to.** The threat model states the acceptance "lapses if any
[disclosure obligation] is not met." Before the amendment, a lapse had a
stated consequence: the ruling's default, hold shipment. The draft
deletes that default outright rather than making it conditional. After
the amendment, the acceptance can lapse into an unstated state. This is
the sharpest defect visible from here. A conditional form — the hold
remains the default and is suspended only while the acceptance is in
force and its disclosure conditions are met — would preserve
fail-closed behaviour. Your call whether that is the right structure.

**B. The no-silent-fallback rule is narrowed.** Your text forbade
silently falling back to a classical suite whenever PQ is a shipping
requirement. The draft rewrites this as "does not permit a silent
fallback **after authenticated migration**." That is defensible, since
everything pre-migration is classical by construction, but it is a
genuine narrowing of your anti-downgrade language and should be narrowed
by you rather than by an implementer's paraphrase.

**C. "PQ gates the public claim, not the launch" is quotable out of
context.** As a standalone bolded sentence it reads like permission to
launch. `SECURITY_STATUS.md` is NO-GO with 14 unchecked blockers. The
draft's following sentence does say it does not "relax any non-PQ launch
prerequisite," but the two sentences will be separated the first time
someone quotes the ruling. Consider whether the operative sentence should
carry its own limitation — e.g. that PQ is not by itself a reason to hold
shipment, while every blocker in `SECURITY_STATUS.md` continues to
independently block launch.

**D. Amended prose is not visibly marked as amended.** The draft adds one
labelled product-owner section, which is legible. But it also silently
rewrites two passages of architect-authored text — the Ruling section and
the interim-layer section. A future reader cannot distinguish your
original ruling from the amendment. For a document marked frozen, that
matters. Should the Status line record dual authority and a date, and
should the two rewritten passages be marked as amended on 2026-08-08?

**E. Sequencing step 1 has no stated completion state.** Your step 1 was
a discrete task ("Extend the threat model with…"). The draft converts it
to a standing obligation ("Maintain `THREAT_MODEL.md` with…"). Separately,
commit `57db7bb` removed the threat model's line "Sequencing step 1 is
INCOMPLETE until the horizon is decided." Between the two, step 1's
status is now unstated in both documents. Is step 1 complete, or is it
open pending something specific?

**F. The draft drops a factual note that is now stale.** Step 1 said
`THREAT_MODEL.md` "is a Phase-0 draft that explicitly excludes
post-quantum adversaries." That is no longer true. Removing it is
probably correct; confirm rather than assume, since it was load-bearing
context for why step 1 existed.

**G. Authority scope on decision 2 specifically.** The horizon is
uncontroversially a product decision. The *acceptability of the HNDL
window* is less clearly so — the original design brief put that question
to you as the architect ("the window's acceptability is a threat-model
call, which is yours"). The owner has accepted the risk, which is
theirs to accept; whether that acceptance is sufficient to rewrite your
ruling's operative text, or whether it requires your concurrence on the
security consequences as well, is precisely what your signature would
settle. Say which.

## What is being asked of you

1. **Do you sign this amendment?** Answer one of:
   - **SIGN** — the amendment lands as drafted.
   - **SIGN WITH CHANGES** — specify the exact replacement text. It will
     be applied verbatim, then dual-reviewed at the resulting SHA.
   - **DECLINE** — the ruling stands unamended. Say what happens then to
     the two threat-model sections that currently contradict it, since
     they cannot both be right.
2. **Rule on A–G**, and on anything they missed.
3. **State the authority record** the amended document should carry: who
   decided what, on what date, and how a reader tells architect text from
   product-owner text.
4. **Is the amendment sufficient?** Does anything else in the ruling
   become wrong or misleading once PQ no longer holds shipment — the
   Bounds section, the "only defensible claim" wording, the retain/retire
   table, or the sequencing order?

## Standing constraints

- The product owner's instruction is: *whatever makes the app more secure,
  use that method.* Where two readings differ on rigour, the more
  rigorous one wins without asking.
- `SECURITY_STATUS.md` and `THREAT_MODEL.md` are the only authorities on
  claims. No product surface may state or imply post-quantum protection
  before migration ships.
- Nothing here may weaken a leg that already carries an independent dual
  PASS.

## Format of your answer

A ruling, in prose, with any replacement text quoted exactly as it should
appear in the file. It will be transcribed verbatim into
`reviews/REVIEW-sol-amend-phase3-ruling.md`. If you rule SIGN WITH
CHANGES, the amended document will then need a fresh dual PASS at the
resulting SHA — this brief authorizes the text, not the landing.
