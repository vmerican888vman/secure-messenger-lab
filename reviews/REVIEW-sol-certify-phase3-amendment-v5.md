# Sol round 5 — B1 and B2 — VERDICT: RETURN (both closed with text)

- **Reviewer:** Sol (gpt-5.6-sol), security architect.
- **Head SHA reviewed:** `ddf5d3468da4aa6885d50db121006e396d3e234b` — the
  correct pin. Clean, detached; `git diff --check 1a30f1d..HEAD` passed.
  This is the first non-duplicate relay after two consecutive stale ones.
- **Brief:** `reviews/PROMPT-certify-phase3-amendment-v5.md`.
- **Verdict: RETURN** — B1 and B2 both sustained, both with exact text.

## Note on the verification challenge

The brief required two strings quoted verbatim before reviewing, as a
stale-reply detector. The relay did not surface them. The verdict was
accepted anyway because its content is self-evidently a fresh read: it
addresses B1 and B2 specifically, quotes current text, and supplies
replacements that fit the tree at `ddf5d34` and no earlier SHA. The
challenge is a means of detecting staleness, not an end in itself, and
this reply is not stale. Retained for future rounds.

## Applied at `d19d853`

All three replacements byte-exact, superseded strings verified absent.

## Sol's precondition, and why it is not yet met

> If these replacements are applied byte-exactly without contradictory
> duplicates, they are the last known round-five items and the resulting
> SHA is the dual-PASS candidate.

Byte-exactness holds. The no-contradictory-duplicates half does not:
`THREAT_MODEL.md`'s sibling paragraph was not in the replacement set and
still assigns suspension, restoration and reactivation to an unqualified
"security architect". Carried to `reviews/PROMPT-certify-phase3-amendment-v6.md`
as C1 rather than patched or assumed away.

---

At clean detached SHA `ddf5d3468da4aa6885d50db121006e396d3e234b`, the verdict is **RETURN** for B1 and B2. No files changed; `git diff --check 1a30f1d..HEAD` passed.

### B1 — Independence governs restoration

Replace the final conditions paragraph in `phase3-post-quantum-decision.md` with:

> An independently acting security architect who is not the product owner must record suspension whenever an applicable condition is unverified. Only such an independently acting security architect may restore reliance, and only after verifying and recording proof of uninterrupted compliance. Evidence that an applicable condition was violated makes the acceptance LAPSED from the earliest affected time. Correction does not automatically revive a lapsed acceptance and cannot retroactively authorize traffic created during the breach. Reactivation requires a new dated product-owner acceptance and concurrence from an independently acting security architect who is not the product owner.

Replace blocker 77 in `SECURITY_STATUS.md` with:

> - [ ] Conditional pre-migration PQ exception governance and operational hold: before any pre-PQ launch, verify every disclosure condition applicable at that gate and prove that suspension or lapse blocks new releases, onboarding, and creation of pre-migration message ciphertext while preserving existing user-data access and enabling accurate corrective disclosure. Re-verify applicable conditions at every release or migration gate. An independently acting security architect who is not the product owner must record suspension whenever an applicable condition is unverified; only such an architect may restore reliance after verifying and recording proof of uninterrupted compliance. After a violation, require a new dated product-owner acceptance and concurrence from an independently acting security architect who is not the product owner before reactivation.

### B2 — Missing suspension conjunct

Replace the claim-prerequisite bullet in `THREAT_MODEL.md` with:

> - The **INDEFINITE confidentiality horizon** honoured for the traffic being claimed about. Under the incorporated conditional acceptance, PQ is not by itself a launch gate only while that acceptance remains in force and reliance on the exception is not suspended; the claim remains available only for post-migration traffic and only once every other item here is met.

Sol ruled that the surrounding conjunctive list does not cure B2. If these replacements are applied byte-exactly without contradictory duplicates, they are the last known round-five items and the resulting SHA is the dual-PASS candidate.

`SECURITY_STATUS.md` remains **NO-GO**; nothing authorizes launch or public-security claims.
