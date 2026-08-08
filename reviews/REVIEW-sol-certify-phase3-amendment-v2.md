# Sol certification round 2 — Fable's findings — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), security architect. Transcribed from
  the user's relay.
- **Head SHA reviewed:** `4e5637b4bc12097b1ac9fac120e9934f6c65520e`.
  Detached, clean, read-only; no files changed. Only the three permitted
  review artifacts were opened.
- **Brief:** `reviews/PROMPT-certify-phase3-amendment-v2.md`.
- **Verdict: RETURN** — all six findings sustained. F3 escalated from P3
  to P2, as the implementer argued.

## Dispositions

| Finding | Ruling |
|---|---|
| F1 — no-production-state premise timeless in `THREAT_MODEL.md` | Sustained, **P1** |
| F2 — condition 3's gate event named three ways | Sustained, **P2** — controlling event is shipment of any migration-capable release |
| F3 — failed migration can silently continue on Olm | Sustained, **escalated to P2** |
| F4 — stale present tense misstates the ruling | Sustained, P3 |
| F5 — Authority record's labelling invariant unsatisfied | Sustained, P3 |
| F6 — no actor named for verification/suspension/restoration | Sustained, P3 |

---

# VERDICT: RETURN

Authenticated SHA: `4e5637b4bc12097b1ac9fac120e9934f6c65520e`. Detached, clean, read-only; no files changed. Only the three permitted review artifacts were opened.

## F1 — Sustained, P1

Replace the `THREAT_MODEL.md` bullet with:

```markdown
- **No V1→V2 secret-state migration.** There is no production state at the date of the governing ruling. If a pre-PQ launch is separately cleared, the ruling's V1 production-lifecycle and retirement amendment governs; migration of V1/Olm cryptographic or session state into V2 remains prohibited regardless.
```

## F2 — Sustained, P2

The controlling event is shipment of any migration-capable release.

Retain condition 3 as:

```markdown
3. Before any migration-capable release ships, users must be able to determine that pre-migration traffic does not have the new protection. That distinction must remain available thereafter; the upgrade must not imply that earlier history is covered.
```

Replace the ruling's timing sentence with:

```markdown
Conditions 1 and 2 apply continuously. Condition 3 becomes a hard release gate before any migration-capable release ships.
```

Replace `THREAT_MODEL.md` obligation 3 with:

```markdown
3. Before any migration-capable release ships, users must be able to determine that traffic predating authenticated PQ migration does not carry the new protection. That distinction must remain available thereafter. Silently upgrading and letting users infer that all their history is covered would convert an honest gap into a misleading one.
```

## F3 — Sustained, escalated to P2

Append to the ruling's fail-closed paragraph:

```markdown
Once authenticated PQ migration is offered or attempted for a conversation, a failed or blocked migration must be prominently surfaced to the user; the client must not silently continue creating Olm or other classical-only ciphertext for that conversation.
```

Add the matching threat-model obligation:

```markdown
4. Once authenticated PQ migration is offered or attempted for a conversation, a failed or blocked migration must be prominently surfaced to the user; the client must not silently continue creating Olm or other classical-only ciphertext for that conversation.
```

## F4 — Sustained, P3

Replace:

```markdown
that was policy the governing ruling does not contain and it was correctly withdrawn
```

with:

```markdown
that was policy the governing ruling did not then contain and it was correctly withdrawn
```

## F5 — Sustained, P3

Replace the final sentence of the Authority record with:

```markdown
Original architect text remains authoritative except for the amended Status paragraph, the in-place amendments to sequencing steps 1 and 5, and text labelled **Architect amendment — 2026-08-08**, which expressly qualify it.
```

## F6 — Sustained, P3

Replace the first sentence of the exception's operative paragraph with:

```markdown
At each release or migration gate, the product owner must supply evidence for every disclosure condition applicable at that gate, and the security architect must affirmatively verify and record compliance.
```

Follow it with:

```markdown
While — and only while — the product-owner acceptance remains in force and the security architect has recorded every applicable disclosure condition as verified, the pre-migration PQ gap does not independently hold shipment. This is not launch authorization: every unchecked blocker in `SECURITY_STATUS.md` remains independently launch-blocking.
```

Replace the suspension/restoration paragraph with:

```markdown
The security architect must record suspension whenever an applicable condition is unverified. The security architect may restore reliance after verifying and recording proof of uninterrupted compliance. Evidence that an applicable condition was violated makes the acceptance LAPSED from the earliest affected time. Correction does not automatically revive a lapsed acceptance and cannot retroactively authorize traffic created during the breach. Reactivation requires a new dated product-owner acceptance and security-architect concurrence.
```

Replace the corresponding `THREAT_MODEL.md` gate paragraph with:

```markdown
At each release or migration gate, the product owner must supply evidence for every condition applicable at that gate, and the security architect must affirmatively verify and record compliance. The security architect must record suspension whenever an applicable condition is unverified and may restore reliance after verifying and recording proof of uninterrupted compliance. Evidence of a violation makes the acceptance LAPSED and invokes the governing ruling's fail-closed consequence. Correction does not automatically revive a lapsed acceptance; reactivation requires a new dated product-owner acceptance and security-architect concurrence.
```

`SECURITY_STATUS.md` remains **NO-GO** with 15 unchecked blockers. This ruling authorizes neither launch nor any public-security claim.

---

## Implementer's application note

All twelve mandated blocks verified present exactly once, byte-exact, and
all six superseded passages verified absent.

**One asymmetry is applied as ordered and flagged rather than
reconciled.** F3's requirement was placed in two structurally different
positions: in the ruling it is appended to the fail-closed paragraph, so
it is a hard requirement standing outside the numbered condition list; in
`THREAT_MODEL.md` it becomes obligation 4 under "the acceptance is
therefore **conditional on all of the following**", so violating it
lapses the acceptance. The threat model is therefore marginally stricter
than the ruling on this point — the same shape as the original P1-1
defect, though here it is the architect's explicit placement rather than
an implementer's invention. Related: the ruling says which of its
conditions apply continuously versus at a release gate; the threat
model's four-item list now says nothing equivalent. Carried to the next
round rather than resolved unilaterally.
