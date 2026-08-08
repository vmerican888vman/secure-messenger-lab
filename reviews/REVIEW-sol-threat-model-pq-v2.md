# Sol review — THREAT_MODEL.md post-quantum section, v2 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), clean detached worktree at the exact
  SHA; `git diff --check` passed, no repository files changed, no
  `reviews/REVIEW-*` opened. Transcribed from the user's paste.
- **Head SHA reviewed:** `eadba87ebcc2ce19706b73a1bc128c7f5bdcc7b0`.
- **Verdict: RETURN** — two P1 findings.

Fable PASSed this same head, having specifically probed the horizon
default for a loophole and found none. It was looking for a *loophole*;
Sol found the opposite defect — the document had become **stricter than
the governing ruling authorises**.

## P1-1 — the horizon is load-bearing, but it introduces UNAUTHORIZED policy

The section adopted `INDEFINITE`, applied the shipment hold, and made
horizon approval an unconditional shipment/public-claim prerequisite. The
governing ruling applies the shipment hold only **conditionally**, and
instructs the threat model to *state* a horizon — it never selects
`INDEFINITE` and never creates a separate horizon-approval gate.

Not decorative: a project could satisfy every existing Phase 3 production
condition and still be blocked **solely** because no separate horizon
approval exists.

The trap worth recording: an earlier Sol review comment had itself
suggested "adopt an explicit fail-closed indefinite/lifetime default".
**A review comment is not an amendment to the frozen ruling.** The threat
model may not encode policy the ruling lacks, whatever a reviewer
suggested in passing.

**Closure offered:** either amend the governing ruling to adopt the
policy explicitly, or retain an `UNDECIDED` fail-closed state pending an
authorized product/architect decision.

## P1-2 — the "every prerequisite" checklist is WEAKER than the migration ruling

The section promised "every prerequisite" but required only a reviewed
MLS path and an "actual authenticated migration". The ruling additionally
requires both 1:1 and groups, a separate V2 path, **no V1→V2 secret-state
migration**, rebootstrap through the verified ceremony into **fresh** MLS
groups, and no Olm downgrade.

Concretely: **an authenticated in-place V1→V2 conversion could satisfy
the rewritten checklist literally while violating the ruling.**

**Closure offered:** add full compliance with ruling steps 2–6 as a
conjunctive prerequisite and spell out the migration prohibitions.

## Otherwise holding

The conditional hybrid rationale, the retention distinctions, the erasure
actor split, the earlier-Olm scope, and the narrowed metadata claim all
hold.

## Closure

Both addressed:

- The `INDEFINITE` default is **withdrawn** and recorded as having been
  unauthorized policy. Message plaintext is now `UNDECIDED (fail-closed)`,
  with a note that adopting any standing default would require amending
  the ruling rather than editing this document. The consequence of
  UNDECIDED is stated as consequence rather than as a new gate: the
  ruling's hold is conditional on PQ being a shipping requirement, and
  while the horizon is undecided the project cannot evaluate whether that
  condition is met. Sequencing step 1 is marked INCOMPLETE until the
  authorized owner decides.
- The prerequisite list is now explicitly **conjunctive**, leads with
  full compliance with ruling steps 2–6, states that the ruling governs
  where the two differ, and spells out the migration prohibitions: both
  1:1 and groups, a separate `ClientStateV2` path with no reinterpreted
  V1 fields, no V1→V2 secret-state migration, rebootstrap into FRESH MLS
  groups with in-place conversion explicitly prohibited, and no
  negotiation down to Olm with downgrade rejection tested.
