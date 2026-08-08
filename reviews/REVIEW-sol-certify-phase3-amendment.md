# Sol certification — applied Phase 3 amendment — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), acting as the security architect who
  authored the amendment text. Transcribed from the user's relay.
- **Head SHA reviewed:** `6917bcb0b419dea7a766115d752a87df45234dbb`.
  Detached worktree confirmed clean at that exact SHA.
- **Brief:** `reviews/PROMPT-certify-phase3-amendment.md`.
- **Verdict: RETURN** — one P1, no P2 or P3.
- **Scope limitation, declared in the brief and accepted:** Sol authored
  the amendment text, so this certifies application fidelity and global
  correctness, not the merits of that text. Sol ruled that no third
  independent reader is required beyond the cold merits review running
  separately.

## P1 — `SECURITY_STATUS.md` lacks the controlling pre-PQ exception gate

Existing section: `SECURITY_STATUS.md`, `## Blocking any app or
public-security claim`.

Concrete failure: the existing 14 blockers could eventually clear without
enforcing the conditional acceptance, disclosure verification, or
operational hold mandated by the Phase 3 ruling.

Sol requires this exact unchecked item:

```markdown
- [ ] Conditional pre-migration PQ exception governance and operational hold: before any pre-PQ launch, verify every disclosure condition applicable at that gate and prove that suspension or lapse blocks new releases, onboarding, and creation of pre-migration message ciphertext while preserving existing user-data access and enabling accurate corrective disclosure. Re-verify applicable conditions at every release or migration gate; after a violation, require a new dated product-owner acceptance and security-architect concurrence before reactivation.
```

## Otherwise certified

- All 14 mandated blocks occur verbatim exactly once in the correct
  sections.
- Both fail-closed shipment defaults remain operative.
- No further changes are required to Bounds, OpenMLS readiness, the
  provisional suite, interim-layer rejection, sequencing, or claim
  exclusions.
- The unwrapped formatting, the dated `THREAT_MODEL.md` status
  correction, and the comma correction are accepted.
- No third independent reader is required.

`SECURITY_STATUS.md` remains **NO-GO**. The relay made no repository
edits.

## Convergence note

This P1 was reached three ways independently: raised as an open question
in the certification brief before either review returned, found by Fable
as its P2-3 while reviewing cold without access to this ruling, and
ruled here as the sole blocker. Applied verbatim at the SHA recorded in
the remediation commit.

## Still open after this verdict

Sol reviewed against the certification brief, which was written **before**
Fable's review returned and therefore does not contain Fable's findings.
Fable's P1, P2-2, P3-4, P3-5, P3-6 and P3-7 have not been ruled on by the
architect. They are carried into
`reviews/PROMPT-certify-phase3-amendment-v2.md`.
