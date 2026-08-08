# Certification round 2 — Fable's findings on the Phase 3 amendment

Your P1 from round 1 is applied verbatim at `4e5637b`:
`SECURITY_STATUS.md` now carries the conditional pre-migration PQ
exception governance and operational hold blocker. Blockers went 14 → 15.
That finding was reached three ways independently — raised as an open
question in the round-1 brief, found by the cold reviewer as its P2-3,
and ruled by you as the sole blocker.

**This round is not a re-certification of your text.** It carries the
other reviewer's findings, which you have not seen. The round-1 brief was
written before that review returned, so your certification could not have
addressed them.

The cold reviewer returned **RETURN** at `6917bcb` with one P1, two P2
and four P3. One P2 was your P1 and is closed. The remaining six are
below, each verified against the files by the implementer before being
carried here.

**Why these are not simply patched:** most are defects in text you
authored, not in its application. All fourteen mandated blocks were
verified byte-exact and you confirmed that independently. Patching your
wording without your ruling is the failure mode this project has already
been burned by in the other direction.

## Worktree

```
git -C "/Users/new/Cursor local/secure-messenger-lab" worktree add --detach \
    /tmp/sml-certify2-sol-4e5637b 4e5637b4bc12097b1ac9fac120e9934f6c65520e
cd /tmp/sml-certify2-sol-4e5637b
git rev-parse HEAD          # 4e5637b4bc12097b1ac9fac120e9934f6c65520e
git symbolic-ref -q HEAD    # nothing (detached)
git status --porcelain      # empty
```

Read-only, change nothing. You may read
`reviews/REVIEW-sol-amend-phase3-ruling.md` and
`reviews/REVIEW-sol-certify-phase3-amendment.md` (your own rulings) and
`reviews/REVIEW-fable-amend-phase3-ruling.md` (the findings you are being
asked to rule on). Do not open other `REVIEW-*` files. Gates green at
this SHA.

---

## F1 (reviewer P1, implementer CONFIRMED) — the no-production-state premise is terminable in one document and timeless in the other

`THREAT_MODEL.md`, in the conjunctive "What must be true before the claim
is available" list:

> - **No V1→V2 secret-state migration.** There is no production state, so none is to be invented.

Your amended V1 section in the ruling deliberately date-scoped exactly
this premise:

> At the date of this ruling there is no production state. … If a pre-PQ launch is separately cleared by `SECURITY_STATUS.md`, that no-production-state premise ends.

The pre-amendment ruling carried the same unscoped sentence the threat
model still carries. Your companion corrections fixed the ruling's copy
and did not reach this one — it sits three bullets below the horizon
bullet you did correct.

Failure: a pre-PQ launch is cleared under the new exception, users
accumulate live V1 state, and the PQ claim gate later runs this
conjunctive list. A reviewer hits a prerequisite whose stated factual
basis is now false, and the natural reinterpretation — "the premise
ended, so a V1→V2 migration is now needed" — inverts the rule at exactly
the moment it matters. Blast radius is contained because the ruling
governs where they differ, but the deliverable is the correctness of
these texts.

**Needs your exact replacement text.**

## F2 (reviewer P2, implementer CONFIRMED) — condition 3's gate event is named three ways, and the loosest one is in the threat model

- Ruling condition 3: *"Before any **migration-capable release** ships…"*
- Ruling timing sentence: *"Condition 3 becomes a hard release gate before **authenticated PQ migration ships**."*
- `THREAT_MODEL.md` obligation 3: *"**Before migration ships**, users must be able to determine…"*

All three are your text; applying it verbatim preserved the divergence
rather than creating it.

These coincide only if a migration-capable release and migration shipping
are the same event, and they are not. Failure: the capability ships dark
behind a remote flag without the distinguishability UX, which is
compliant on the threat model's reading because "migration hasn't
shipped"; the flag is then flipped remotely; migration is live with no
way for users to see that pre-migration history is uncovered. That is an
instant condition-3 violation, which by your own machinery makes the
acceptance LAPSED and triggers the post-launch operational hold — the
worst outcome, reached by following the weaker of two authorities.

**Needs your ruling on which event is correct, and exact text aligning
all three.**

## F3 (reviewer P3, implementer ESCALATES to P2) — a failed migration can continue on Olm indefinitely, and an adversary can induce that

Your fail-closed sentence covers "whenever PQ is required — including
whenever this exception is not in force and after authenticated PQ
migration." For a pre-migration conversation while the exception IS in
force, PQ is never "required." So a client whose migration ceremony fails
may lawfully continue on Olm indefinitely, and an adversary who can
induce or sustain that failure keeps the victim on classical crypto
without ever triggering a downgrade rule.

The reviewer ruled this P3, reasoning it sits inside the accepted,
disclosed risk, and explicitly invited the gate to disagree upward. The
implementer disagrees upward and records why: this is the only finding
with an active-adversary story, and the standing project constraint is
that where two readings differ on rigour the more rigorous one wins. The
disclosed risk the owner accepted was passive harvest-now-decrypt-later
of pre-migration traffic. It was not "an active adversary can pin a user
to classical crypto indefinitely by suppressing the migration."

The reviewer's proposed closure is one sentence: a failed or blocked
migration attempt must be surfaced to the user, not silently continued on
Olm.

**Rule on the severity and, if you agree, give exact text. If you rule it
correctly P3, say why the adversary-induced case stays inside the
accepted risk** — that reasoning should be in the record either way.

## F4 (reviewer P3, implementer CONFIRMED) — stale present tense misstates the ruling's current content

`THREAT_MODEL.md`, horizon section:

> that was policy the governing ruling **does not contain** and it was correctly withdrawn

Your Authority record now *does* contain the INDEFINITE horizon. The
sentence is historical narrative about a withdrawn revision, but as
written it asserts something false about the governing ruling's present
content. Reviewer's fix: "did not then contain."

## F5 (reviewer P3) — the Authority record's own labelling invariant is not satisfied

Your Authority record states:

> Original architect text remains authoritative except where text labelled **Architect amendment — 2026-08-08** expressly qualifies it.

But three passages were rewritten in place without that label: the Status
line, sequencing step 1 (now marked **COMPLETE**, a substantive status
change), and step 5's gate rename. All are in the tightening direction
and git history disambiguates, so the reviewer ruled it minor — but a
reader auditing the amendment's footprint by label will under-count it,
and the invariant is one you wrote.

**Either label them or narrow the invariant.**

## F6 (reviewer P3) — no actor is named for verification, suspension or restoration

Reactivation names both actors precisely: a new dated product-owner
acceptance plus security-architect concurrence. "Affirmatively verified,"
suspension, and restoration name none. A fail-closed mechanism with an
unnamed operator degrades toward nobody's job — and the blocker now in
`SECURITY_STATUS.md` requires proving the hold works, which is hard to
prove when no role owns it.

---

## What the reviewer certified

Recorded so you can weigh it: the cold reviewer independently found the
fail-closed machinery sound on every path it traced (unverified →
suspended, violated → LAPSED from earliest affected time, no retroactive
authorization, pre-launch lapse → hold shipment, post-launch lapse →
operational hold), found the overclaim surface of the amended text clean
with every dangerous fragment carrying its qualifier in the same sentence
rather than an adjacent one, and ruled the "expressly classical"
construction coherent and load-bearing rather than a verbal move — noting
it *tightens* the anti-downgrade rule, since post-migration fallback is
now banned per-conversation forever. Bounds, OpenMLS readiness, the
retain/retire table, metadata budget and claim language were all checked
and remain consistent.

## Verdict format

**PASS** or **RETURN** with findings. For each of F1–F6, rule and give
exact replacement text where a change is required. Text will be applied
verbatim and byte-checked, then both reviewers certify the resulting SHA.

`SECURITY_STATUS.md` remains NO-GO, now with 15 unchecked blockers.
Nothing in this leg authorizes a launch or a public-security claim.
