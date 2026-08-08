# Fable review — applied Phase 3 amendment — VERDICT: RETURN

- **Reviewer:** Fable (`claude-fable-5`), dispatched directly by the
  implementer into a pinned detached worktree.
- **Head SHA reviewed:** `6917bcb0b419dea7a766115d752a87df45234dbb`.
- **Worktree:** `/private/tmp/sml-amend-fable-6917bcb`. Reviewer confirmed
  `git rev-parse HEAD` matched the pinned SHA, `git status --porcelain`
  empty, detached. Opened no `reviews/REVIEW-*` file — it noted one was
  added by `2a07e75` and explicitly excluded it from the diff it read.
- **Independence:** Fable had NOT seen the architect's ruling and
  reviewed the resulting documents cold, on their merits.
- **Verdict: RETURN** — one P1, two P2, four P3.

## Implementer's verification of the findings

Each was checked against the files before being recorded. **P1, P2-2 and
P3-4 are confirmed by direct inspection.** P2-3 was independently raised
in `reviews/PROMPT-certify-phase3-amendment.md` before this review
returned, so two reviewers converged on it separately.

**The important structural point: most of these are defects in the
architect's authored text, not in its application.** All fourteen
mandated blocks were verified byte-exact. P2-2 in particular is an
internal divergence between two passages the architect wrote — ruling
line 36 says "Before any migration-capable release ships", ruling line 38
says "before authenticated PQ migration ships", and `THREAT_MODEL.md`
line 163 says "Before migration ships". Applying them verbatim preserved
the divergence rather than creating it. These therefore return to the
architect rather than being patched by the implementer.

**One finding the implementer would escalate:** Fable ruled P3-5 minor
while explicitly inviting the gate to disagree upward. It should be P2.
It is the only finding with an active-adversary story — an adversary who
can induce migration failure keeps a victim on classical crypto
indefinitely, and the standing project constraint is that where two
readings differ on rigour the more rigorous one wins.

---

## Verification of setup

- `git rev-parse HEAD` → `6917bcb0b419dea7a766115d752a87df45234dbb` — matches the pinned SHA exactly.
- `git status --porcelain` → empty. Clean detached worktree.
- I read both amended documents whole, `SECURITY_STATUS.md`, and the diffs of `57db7bb..HEAD` restricted to the two documents. I did not open any `reviews/REVIEW-*` file (one is added by commit `2a07e75`; I excluded it from the diff and never read it).

# Verdict: **RETURN**

The amendment is well-constructed where it was applied. The fail-closed machinery is genuinely fail-closed, the overclaim surface of the *amended* sentences is clean, and the "expressly classical" move is coherent (analysis below). But the change-set makes a premise terminable in one document while the sibling authority document still asserts that premise as timeless fact — the exact untouched-section failure class this gate exists to catch — plus two P2s.

---

## P1 (blocking)

**1. `THREAT_MODEL.md` claim-prerequisite still asserts the no-production-state premise as unconditional fact; the amendment itself declares that premise terminable.**

- File: `/private/tmp/sml-amend-fable-6917bcb/THREAT_MODEL.md`, line 272, in the conjunctive "What must be true before the claim is available" list:
  > **No V1→V2 secret-state migration.** There is no production state, so none is to be invented.
- The ruling's amended V1 section (`docs/phase3-post-quantum-decision.md` line 88) was carefully rewritten to date-scope this: *"At the date of this ruling there is no production state. … If a pre-PQ launch is separately cleared by `SECURITY_STATUS.md`, that no-production-state premise ends."* The pre-amendment ruling contained the same sentence THREAT_MODEL still carries; the change-set fixed the ruling's copy and missed this one, three lines below a bullet it *did* edit (the INDEFINITE-horizon bullet).
- Concrete failure: a pre-PQ launch is cleared under the new exception; users accumulate live V1 state; the PQ claim gate later runs this conjunctive list. The reviewer reaches a prerequisite whose stated factual basis ("There is no production state") is now false. They must either fail an incoherent item or reinterpret it — and the natural reinterpretation ("the premise ended, so a V1→V2 state migration is now needed") inverts the intended rule at exactly the moment it matters. The security blast radius is contained (the governing ruling and the adjacent FRESH-groups bullet still forbid secret-state migration, and the ruling governs where they differ), but the deliverable under review is the correctness of these texts, and this is a demonstrable contradiction the amendment introduced by omission. One-sentence fix: mirror the ruling's date-scoping ("There is no production state at the date of this ruling; if a pre-PQ launch is cleared, the ruling's V1 production-lifecycle amendment governs — secret-state migration remains prohibited regardless").

## P2 (should fix)

**2. Condition 3's gate event is named three different ways, and the THREAT_MODEL restatement is the loosest one.**

- Ruling condition 3 (`docs/phase3-post-quantum-decision.md` line 36): *"Before any migration-capable release ships…"* — the strict form.
- Ruling timing sentence (line 38): *"Condition 3 becomes a hard release gate before authenticated PQ migration ships."*
- `THREAT_MODEL.md` line 163: *"Before migration ships, users must be able to determine…"*
- These coincide only if a migration-capable release and "migration shipping" are always the same event. They are not: a release can ship with migration capability dark behind a remote flag. Scenario: the capability ships dark without the distinguishability UX, on the THREAT_MODEL reading ("migration hasn't shipped yet"); the flag flips remotely; migration is now live with no way for users to see that pre-migration history is uncovered — an instant condition-3 violation, which by the amendment's own machinery makes the acceptance LAPSED and triggers the post-launch operational hold. The ruling's strict wording prevents this and governs where they differ, but a release-gate mechanism restated more weakly in the second authority document is an invitation to exactly this error. Align both documents (and the ruling's own timing sentence) on "migration-capable release."

**3. The amendment creates launch preconditions that the launch-verdict document cannot see.**

- The ruling now conditions any pre-PQ launch on three new things: enforceability of the operational hold (line 42: *"A pre-PQ launch is not authorized unless this operational hold can be enforced"*), the independently reviewed V1 production-lifecycle and retirement plan (line 88), and — for migration-capable releases — condition 3. None appears in, or is pointed to from, the blocker list in `/private/tmp/sml-amend-fable-6917bcb/SECURITY_STATUS.md`, which presents itself as the verdict document ("Verdict: NO-GO," a checklist that will eventually all be checked).
- Scenario: over months the 14 boxes get checked; the person flipping NO-GO to GO works from that checklist; nobody ever built the hold mechanism; the acceptance later lapses in the field and the mandated consequence ("no new … creation of pre-migration message ciphertext") cannot be enforced — the fail-closed path exists on paper only. Blocker 1 ("Independently reviewed protocol and complete formal threat model") would probably surface the ruling, which is why this is P2 not P1, but the fix is one line: add a blocker (or explicit pointer) in `SECURITY_STATUS.md` for the ruling's pre-PQ-launch conditions. I note `SECURITY_STATUS.md` was outside the stated edit scope; that is a scoping decision this gate should not inherit silently.

## P3 (minor)

**4. Stale present-tense sentence in the horizon section.** `THREAT_MODEL.md` line 115: *"that was policy the governing ruling does not contain and it was correctly withdrawn."* The amended ruling's Authority record now *does* contain the INDEFINITE horizon. Historical narrative, but as written it misstates the governing ruling's current content. Change to "did not then contain."

**5. "Whenever PQ is required" has no defined trigger during the migration rollout window.** Ruling line 44 fail-closes "whenever PQ is required — including whenever this exception is not in force and after authenticated PQ migration." For a conversation that is pre-migration while the exception is in force, PQ is never "required," so a client whose migration ceremony fails (including adversary-induced failure) may lawfully continue on Olm indefinitely. This is within the accepted, disclosed risk — condition 3 gives users visibility, and the acceptance is exactly about pre-migration traffic — so it is not a defect of the amendment, and the pre-existing ruling used the same phrase. But one sentence ("a failed or blocked migration attempt must be surfaced to the user, not silently continued on Olm") would close the only route by which an active adversary converts the exception into a downgrade tool. Flagging explicitly because I ruled it P3 while uncertain; the gate may disagree upward.

**6. The Authority record's labelling invariant is not satisfied.** Line 15: *"Original architect text remains authoritative except where text labelled **Architect amendment — 2026-08-08** expressly qualifies it."* But the Status line, sequencing step 1 (now marked **COMPLETE** — a substantive status change), and step 5's gate rename were rewritten in place without that label. All rewrites are in the tightening direction, and git history disambiguates, so this is minor — but a reader using labels to audit the amendment's footprint will under-count it.

**7. No actor is named for "affirmatively verified" / suspension / restoration.** Reactivation names both actors precisely; verification and restoration name none. Minor, but a fail-closed mechanism with an unnamed operator degrades toward nobody's job.

---

## Answers to the specific questions

1. **Fail-closed integrity:** every path lands somewhere defined — unverified→suspended (restorable by proof of uninterrupted compliance), violated→LAPSED from earliest affected time, no retroactive authorization, reactivation requires new dated acceptance plus architect concurrence, pre-launch lapse→hold shipment, post-launch lapse→operational hold with data accessibility and corrective disclosure. The one enforceability gap (post-launch hold) was correctly converted into a launch precondition; its discoverability problem is finding 3.
2. **Overclaim surface:** clean in the amended text. Every dangerous fragment ("end-to-end encrypted may accurately describe the classical scheme," "PQ is not by itself a launch gate," "does not independently hold shipment") carries its qualifier in the same sentence, not an adjacent one. The Signal/SimpleX comparison is scoped to posture, not security, and is factually accurate.
3. **Consistency:** the deliberate deferrals (THREAT_MODEL omitting the hold mechanics and restoration clause, "the governing ruling controls wherever the documents differ") are fine. The unintended divergences are findings 1, 2, and 4.
4. **"Expressly classical" is coherent and load-bearing, not a verbal move.** It converts fallback (implicit, adversary-influenceable, permanent) into authorization (explicit, revocable, condition-gated, with a defined halt path), and the amendment simultaneously *tightened* the anti-downgrade rule: post-migration fallback to Olm is now banned per-conversation forever, and Olm operation must halt the moment the exception is not in force. The residual (finding 5) is at the boundary of the accepted risk, not a laundering of it.
5. **The untouched-section gap:** found — finding 1, plus 4. Bounds, OpenMLS readiness, the retain/retire table, metadata budget, and claim language were checked and remain consistent with the amendment.
