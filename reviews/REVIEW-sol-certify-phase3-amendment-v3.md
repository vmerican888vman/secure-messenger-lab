# Sol certification round 3 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), security architect. Transcribed from
  the user's relay.
- **Head SHA reviewed:** `e751a9ee6aa8c2ab72307f4e0327e8bb154fe382`,
  detached, clean, read-only. No excluded artifact opened, nothing
  changed.
- **Brief:** `reviews/PROMPT-certify-phase3-amendment-v3.md`.
- **Verdict: RETURN** — two P2. No P1, no P3.

## Dispositions against the findings put to the architect

| Finding | Ruling |
|---|---|
| N1 — condition 4 consequence-free in the ruling | Sustained as **P2-1**, jointly with N3. Condition 4 adopted into the ruling with an applicability statement. |
| N3 — no applicability statement for condition 4 | Sustained, folded into P2-1. |
| **N2 — one-conjunct reliance sentence** | **NOT RULED ON.** See below. |
| **N4 — labelling residue** | **NOT RULED ON** (verdict states "P3: none"). |
| **N5 — lapse dating omits "earliest affected time"** | **NOT RULED ON** (verdict states "P3: none"). |
| Beneficiary/verifier independence | **Raised by the architect unprompted as P2-2.** The revised brief had dropped this question; the architect found it anyway. |

## The unruled findings — carried, not closed and not patched

The verdict states "P1: none. P3: none. Two P2 findings remain." Neither
P2 is N2, and no reasoning is given for declining N4 or N5. Verified
against the files after applying this ruling:

- **N2 stands unfixed.** P2-2 rewrote the gate paragraph; the sentence at
  issue is a different, untouched one in the recorded-risk-acceptance
  bullets — "While the acceptance remains in force, PQ is not by itself a
  reason to hold shipment" — still one conjunct against the ruling's
  two-conjunct operative test, which this ruling left intact. The
  failure the cold reviewer described is still reachable.
- N4 and N5 are unchanged.

These are not patched by the implementer. "P3: none" may mean the
architect had no P3 findings of its own rather than that it dismissed the
reported ones, and the difference matters. Carried to round 4 for an
explicit ruling.

---

# RETURN

Exact SHA `e751a9ee6aa8c2ab72307f4e0327e8bb154fe382` was reviewed detached, clean, and read-only. No excluded reviewer artifact was opened; no repository file or review artifact was changed.

P1: none. P3: none. Two P2 findings remain.

## P2-1 — Condition 4 has inconsistent consequence and timing

The governing ruling says:

> The acceptance is conditional on all of the following:

But its numbered list ends at condition 3, while the migration-failure requirement appears separately at line 46:

> Once authenticated PQ migration is offered or attempted for a conversation, a failed or blocked migration must be prominently surfaced to the user; the client must not silently continue creating Olm or other classical-only ciphertext for that conversation.

In `THREAT_MODEL.md`, the same sentence is numbered condition 4 under:

> The acceptance above is therefore **conditional on all of the following**.

Concrete failure: a migration-capable release can be approved after verifying only the ruling's numbered conditions 1–3. A runtime migration failure can then silently continue classical ciphertext. The threat model says this lapses the acceptance and triggers the operational hold; the governing ruling does not. Its timing sentence also never classifies condition 4.

Replace ruling lines 38–46 with:

```markdown
3. Before any migration-capable release ships, users must be able to determine that pre-migration traffic does not have the new protection. That distinction must remain available thereafter; the upgrade must not imply that earlier history is covered.
4. Once authenticated PQ migration is offered or attempted for a conversation, a failed or blocked migration must be prominently surfaced to the user; the client must not silently continue creating Olm or other classical-only ciphertext for that conversation.

Conditions 1 and 2 apply continuously. Condition 3 becomes a hard release gate before any migration-capable release ships. Condition 4 applies continuously to each conversation from the first time authenticated PQ migration is offered or attempted for that conversation.

The security architect must record suspension whenever an applicable condition is unverified. The security architect may restore reliance after verifying and recording proof of uninterrupted compliance. Evidence that an applicable condition was violated makes the acceptance LAPSED from the earliest affected time. Correction does not automatically revive a lapsed acceptance and cannot retroactively authorize traffic created during the breach. Reactivation requires a new dated product-owner acceptance and security-architect concurrence.

If reliance is suspended or the acceptance lapses after a pre-PQ launch, no new release, onboarding, or creation of pre-migration message ciphertext may proceed under this exception until reliance is restored or reauthorized. Existing user data must remain accessible, and affected users must receive an accurate corrective disclosure. A pre-PQ launch is not authorized unless this operational hold can be enforced.

Pre-migration Olm operation under this exception is expressly classical and is not a fallback from PQ. Whenever PQ is required — including whenever this exception is not in force and after authenticated PQ migration — failure of the production-gated hybrid-PQ MLS path must fail closed. The client must never silently negotiate down to, continue on, or resume Olm or another classical-only suite.
```

Insert after threat-model condition 4:

```markdown
Conditions 1 and 2 apply continuously. Condition 3 becomes a hard release gate before any migration-capable release ships. Condition 4 applies continuously to each conversation from the first time authenticated PQ migration is offered or attempted for that conversation.
```

## P2-2 — The beneficiary can still be the verifier

Both documents currently say:

> At each release or migration gate, the product owner must supply evidence for every condition applicable at that gate, and the security architect must affirmatively verify and record compliance.

The roles are named, but nothing requires different or independently acting actors. The product owner can also occupy or control the security-architect role, supply favorable evidence, and attest that the exception remains valid.

Replace decision line 30 with:

```markdown
At each release or migration gate, the product owner must supply evidence for every disclosure condition applicable at that gate. An independently acting security architect who is not the product owner must affirmatively verify and record compliance. If no such security architect is available, the gate remains closed and no reliance on the exception is permitted.
```

Replace `THREAT_MODEL.md` line 159 with:

```markdown
At each release or migration gate, the product owner must supply evidence for every condition applicable at that gate. An independently acting security architect who is not the product owner must affirmatively verify and record compliance. If no such security architect is available, the gate remains closed and no reliance on the exception is permitted. The security architect must record suspension whenever an applicable condition is unverified and may restore reliance after verifying and recording proof of uninterrupted compliance. Evidence of a violation makes the acceptance LAPSED and invokes the governing ruling's fail-closed consequence. Correction does not automatically revive a lapsed acceptance; reactivation requires a new dated product-owner acceptance and security-architect concurrence.
```

Architect unavailability must therefore stall the release or migration; at a security gate, that stall is the fail-closed result.

## Other certification questions

- F1's date-scoped V1 text survives the live-production-state scenario and still prohibits V1→V2 secret-state migration.
- "Migration-capable release" is now consistent in both documents and closes the dark-flag route.
- The `SECURITY_STATUS.md` blocker is dischargeable. It requires independently reviewed enforcement at the release pipeline, onboarding boundary, and ciphertext-creation boundary, including stale/offline/rollback tests, while separately proving history access and corrective disclosure. It remains unchecked until that executable evidence exists.
- The prompt-reported cargo, Clippy, fmt, and DCO gates were not rerun because the worktree was read-only. `git diff --check` passed, and the worktree remained detached and clean at completion.
- `SECURITY_STATUS.md` remains NO-GO; this verdict authorizes no launch or public-security claim.

---

## Implementer's application note

Six mandated strings verified present exactly once and byte-exact. The
migration-surfacing sentence was **moved** into condition 4 rather than
duplicated — it occurs exactly once in each document — and the superseded
two-actor gate sentence is verified absent from both.

**P2-2 is the strongest finding of this leg.** The cold reviewer had
examined the same machinery and ruled the checker-checking question
acceptable on the grounds that it "bottoms out in this dual-review
certification process." The architect rejected that: a role named in a
document is not a role separated in practice, and a solo operator can
occupy both. The gate now requires an independently acting architect who
is not the product owner, and unavailability stalls the gate closed.
Given this project has one human, that is a real constraint on shipping
rather than a formality — which is the point.
