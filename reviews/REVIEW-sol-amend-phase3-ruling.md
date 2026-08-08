# Sol ruling — amendment to `docs/phase3-post-quantum-decision.md` — VERDICT: SIGN WITH CHANGES

- **Ruling authority:** Sol (gpt-5.6-sol), acting as the security
  architect who issued the Phase 3 decision. Transcribed verbatim from
  the user's paste.
- **Substrate authenticated:** `cf93af65add55eea967f5981b41be1b6581812e3`.
- **Brief:** `reviews/PROMPT-amend-phase3-ruling.md`.
- **Verdict: SIGN WITH CHANGES**, conditional — without the companion
  `THREAT_MODEL.md` corrections at the same resulting SHA, the ruling is
  **DECLINE**.

## Process note recorded by the reviewer

> The exact committed substrate was authenticated as
> `cf93af65add55eea967f5981b41be1b6581812e3`. The live checkout was
> attached and dirty rather than detached as the brief stated, but its
> held amendment matched the stated 39/11 diff. I read the committed
> documents through Git objects, opened no `reviews/REVIEW-*` file, ran
> no code tests, and changed nothing.

**Implementer's note on that:** the brief specified a pinned detached
worktree and the live attached checkout was used instead. The reviewer
compensated by reading committed objects directly and verified the held
diff matched, so the ruling stands on the correct substrate. Future
briefs must make the worktree creation step explicit rather than
assumed.

---

# Ruling: SIGN WITH CHANGES

I do not sign the 39-insertion/11-deletion draft as written. The amendment may land only with the exact changes below and matching `THREAT_MODEL.md` corrections at the same resulting SHA. Without those companion corrections, the ruling is **DECLINE** because the authorities remain internally inconsistent.

`SECURITY_STATUS.md` remains **NO-GO** with 14 unchecked blockers. This amendment grants no launch or public-security-claim authorization.

## A–G

- **A — Sustained.** Preserve the fail-closed shipment default. A disclosure lapse must close the exception.
- **B — Sustained.** Preserve the original anti-downgrade rule. Pre-migration classical operation is an expressly disclosed exception, never a silent fallback.
- **C — Sustained.** The operative sentence itself must state that all `SECURITY_STATUS.md` blockers remain launch-blocking.
- **D — Sustained.** Record both authorities and date every architect-authored amendment.
- **E — Step 1 is COMPLETE as documentation.** Endpoint-secret erasure remains **OPEN** and independently blocks the PQ claim.
- **F — Confirmed.** The statement that the threat model excludes PQ adversaries is now false and must be removed.
- **G — Authority divided as follows:** the product owner decides the confidentiality objective and accepts product risk; the security architect decides whether that acceptance changes a security gate. I concur only with the narrow, conditional exception below.

## Exact changes to `docs/phase3-post-quantum-decision.md`

Replace the Status paragraph with:

```markdown
**Status: DECIDED by the security architect; amended by the security architect on 2026-08-08 to incorporate product-owner decisions dated 2026-08-08. Route 1 — pull MLS forward.**
No outer hybrid layer. No Olm fork. No product surface may state or imply post-quantum protection unless the hybrid-PQ MLS production-and-claim gate, every conjunctive claim prerequisite in `THREAT_MODEL.md`, and global claim clearance in `SECURITY_STATUS.md` have all passed.
```

Insert after the introductory paragraph:

```markdown
## Authority record

The product owner decided on 2026-08-08 that the confidentiality horizon for message plaintext is INDEFINITE and accepted only the disclosed pre-migration post-quantum gap, conditionally on the disclosure obligations below.

The security architect decided on 2026-08-08 that this acceptance creates only the narrow, conditional exception stated below. It does not amend any other launch, security, migration, or claim gate.

The product owner owns the confidentiality objective and risk acceptance. The security architect owns the acceptance's security consequence and any concurrence required to activate or reactivate the exception. Original architect text remains authoritative except where text labelled **Architect amendment — 2026-08-08** expressly qualifies it.
```

Retain the original Ruling text, including its hold-shipment default, and insert immediately after it:

```markdown
## Architect amendment — conditional pre-migration exception (2026-08-08)

The product owner accepts that traffic sent before authenticated PQ migration is classically protected, harvestable, and never acquires post-quantum protection retroactively. The acceptance covers only this PQ gap and clears no other blocker.

While — and only while — that acceptance remains in force and every disclosure condition applicable at the current release or migration gate is affirmatively verified, the pre-migration PQ gap does not independently hold shipment. This is not launch authorization: every unchecked blocker in `SECURITY_STATUS.md` remains independently launch-blocking.

The acceptance is conditional on all of the following:

1. No product surface — UI, store listing, marketing, or documentation — may state or imply post-quantum protection before authenticated PQ migration. After migration, no such claim is permitted until every PQ claim gate has passed.
2. Every user-facing encryption description must accurately describe the protection actually provided. This ruling does not authorize any public-security claim while `SECURITY_STATUS.md` remains NO-GO. If and when that file authorizes such claims, "end-to-end encrypted" may accurately describe the classical scheme; language stating or implying resistance to future quantum decryption remains forbidden until the PQ claim gate passes.
3. Before any migration-capable release ships, users must be able to determine that pre-migration traffic does not have the new protection. That distinction must remain available thereafter; the upgrade must not imply that earlier history is covered.

Conditions 1 and 2 apply continuously. Condition 3 becomes a hard release gate before authenticated PQ migration ships.

An applicable condition that is unverified suspends reliance on the acceptance; proof of uninterrupted compliance may restore reliance. Evidence that an applicable condition was violated makes the acceptance LAPSED from the earliest affected time. Correction does not automatically revive a lapsed acceptance and cannot retroactively authorize traffic created during the breach. Reactivation requires a new dated product-owner acceptance and security-architect concurrence.

If reliance is suspended or the acceptance lapses after a pre-PQ launch, no new release, onboarding, or creation of pre-migration message ciphertext may proceed under this exception until reliance is restored or reauthorized. Existing user data must remain accessible, and affected users must receive an accurate corrective disclosure. A pre-PQ launch is not authorized unless this operational hold can be enforced.

Pre-migration Olm operation under this exception is expressly classical and is not a fallback from PQ. Whenever PQ is required — including whenever this exception is not in force and after authenticated PQ migration — failure of the production-gated hybrid-PQ MLS path must fail closed. The client must never silently negotiate down to, continue on, or resume Olm or another classical-only suite.
```

Replace the two paragraphs below the retain/retire table with:

```markdown
### Architect amendment — pre-migration V1 production state (2026-08-08)

Implement a separate `ClientStateV2`/MLS path. **Do not reinterpret `ClientStateV1` fields or migrate V1/Olm cryptographic or session state into V2.** Preserve the reviewed V1 path and its tests until the MLS replacement and the migration-and-retirement plan independently pass. Rebootstrap each affected conversation through the verified contact ceremony into a fresh MLS group, then retire V1 explicitly.

At the date of this ruling there is no production state. This amendment does not authorize the current V1/Olm path for production. If a pre-PQ launch is separately cleared by `SECURITY_STATUS.md`, that no-production-state premise ends. Before launch, an independently reviewed V1 production-lifecycle and retirement plan must cover live sessions, queued or outstanding Olm messages, retained history, crash and rollback behavior, recovery and support, rebootstrap, and explicit V1 retirement. V1 may not be retired merely because V2 passes.

Existing independent PASSes remain valid only for their exact reviewed Olm code. They neither authorize a pre-migration launch nor transfer to MLS.

Stop adding discretionary Olm-only product features. This does not prohibit security and operational work required to close an independently tracked non-PQ launch blocker. Keeping the harness sound is not a production-readiness standard.
```

Retain the original interim-layer paragraph and append:

```markdown
**Architect amendment — 2026-08-08.** The conditional exception above is the sole exception to this default. If reliance on the acceptance is suspended or the acceptance lapses, the original hold-shipment consequence applies immediately. Nothing in this amendment authorizes an interim outer layer.
```

Under `## Sequencing`, insert:

```markdown
**Architect amendment — 2026-08-08.** This sequence governs the PQ migration and availability of the PQ claim. It does not authorize launch or reorder any independent launch blocker in `SECURITY_STATUS.md`.
```

Replace sequencing step 1 with:

```markdown
1. **COMPLETE on 2026-08-08 as a threat-model documentation step.** `THREAT_MODEL.md` now models the HNDL adversary, indefinite confidentiality horizon, compromise timing, erasure status and required endpoint invariant, pre-migration acceptance, disclosure obligations, and precise claim language. Maintain this material as the design changes. Endpoint-secret erasure remains **OPEN** and independently blocks the PQ claim; completing this documentation step neither mitigates HNDL nor opens any launch or claim gate.
```

In step 5, replace "production gate" with **"PQ production-and-claim gate."** Retain step 6 and append after the numbered sequence:

```markdown
**Architect amendment — 2026-08-08.** In step 6, pre-migration Olm is permitted only under the conditional exception above and remains expressly classical. Once a conversation has completed authenticated PQ migration, it must never negotiate or fall back to Olm.
```

Insert immediately before the claim quotation:

```markdown
**Architect amendment — 2026-08-08.** This claim is unavailable unless the PQ production-and-claim gate, every conjunctive prerequisite in `THREAT_MODEL.md`, and global claim clearance in `SECURITY_STATUS.md` have all passed. Until then, this ruling authorizes no statement or implication that the product has post-quantum protection.
```

## Required companion corrections to `THREAT_MODEL.md`

Replace "What the indefinite horizon entails" items 1–3 with:

```markdown
Derived from the governing ruling, not added by this document:

1. An indefinite horizon **exceeds any plausible time-to-CRQC by construction.** Classical-only key agreement is therefore insufficient for message plaintext by definition, not by estimate.
2. Absent an authorized acceptance of the pre-migration gap, PQ is consequently a shipping requirement and shipment waits for the PQ production-and-claim gate rather than silently falling back to a classical suite.
3. The recorded acceptance below creates a conditional exception to that shipment consequence; it does not make pre-migration traffic satisfy the horizon. Any message sent before authenticated PQ migration remains permanently outside the stated objective.
```

Replace the operative bullets in "Recorded risk acceptance" with:

```markdown
- While the acceptance remains in force, PQ is not by itself a reason to hold shipment. This is not launch authorization: every unchecked blocker in `SECURITY_STATUS.md` remains independently controlling.
- This acceptance covers the post-quantum gap **only**. It licenses nothing about the contact ceremony, identity binding, endpoint compromise, metadata, or any other launch or security blocker.
```

Replace the disclosure-obligation preamble and numbered obligations with:

```markdown
An accepted risk that users are not told about is not an accepted risk; it is an undisclosed one. The acceptance above is therefore **conditional on all of the following**.

At each release or migration gate, every condition applicable at that gate must be affirmatively verified. An applicable condition that is unverified suspends reliance on the acceptance. Evidence of a violation makes the acceptance LAPSED and invokes the governing ruling's fail-closed consequence. Correction does not automatically revive a lapsed acceptance; reactivation requires a new dated product-owner acceptance and security-architect concurrence.

1. **No product surface — UI, store listing, marketing, or documentation — may state or imply post-quantum protection before the migration.** After migration, no such claim is permitted until every post-quantum claim prerequisite has passed.
2. Every user-facing encryption description must accurately describe the protection actually provided, but this document does not authorize any public-security claim while `SECURITY_STATUS.md` remains NO-GO. If and when that file authorizes such claims, "end-to-end encrypted" may describe the classical scheme; language stating or implying resistance to future quantum decryption remains forbidden until the post-quantum claim gate passes.
3. Before migration ships, users must be able to determine that traffic predating it does not carry the new protection. That distinction must remain available thereafter. Silently upgrading and letting users infer that all their history is covered would convert an honest gap into a misleading one.
```

Replace "Amendment required" with:

```markdown
**Amendment recorded:** On 2026-08-08 the security architect amended `docs/phase3-post-quantum-decision.md` to incorporate the product-owner horizon decision, conditional risk acceptance, disclosure obligation, and their security consequences. The governing ruling controls wherever the documents differ.
```

Replace the confidentiality-horizon claim-gate bullet with:

```markdown
- The **INDEFINITE confidentiality horizon** honoured for the traffic being claimed about. Under the incorporated conditional acceptance, PQ is not by itself a launch gate only while that acceptance remains in force; the claim remains available only for post-migration traffic and only once every other item here is met.
```

No substantive change is required to Bounds, OpenMLS readiness, the provisional suite, the technical rejection of the interim layer, or the existing claim exclusions.

The exact committed substrate was authenticated as `cf93af65add55eea967f5981b41be1b6581812e3`. The live checkout was attached and dirty rather than detached as the brief stated, but its held amendment matched the stated 39/11 diff. I read the committed documents through Git objects, opened no `reviews/REVIEW-*` file, ran no code tests, and changed nothing.
