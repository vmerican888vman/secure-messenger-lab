# Phase 3 decision — post-quantum key agreement

**Status: DECIDED by the security architect; amended by the security architect on 2026-08-08 to incorporate product-owner decisions dated 2026-08-08. Route 1 — pull MLS forward.**
No outer hybrid layer. No Olm fork. No product surface may state or imply post-quantum protection unless the hybrid-PQ MLS production-and-claim gate, every conjunctive claim prerequisite in `THREAT_MODEL.md`, and global claim clearance in `SECURITY_STATUS.md` have all passed.

This records a ruling, not a proposal. It supersedes the options laid out
in `reviews/PROMPT-design-phase3-post-quantum.md`.

## Authority record

The product owner decided on 2026-08-08 that the confidentiality horizon for message plaintext is INDEFINITE and accepted only the disclosed pre-migration post-quantum gap, conditionally on the disclosure obligations below.

The security architect decided on 2026-08-08 that this acceptance creates only the narrow, conditional exception stated below. It does not amend any other launch, security, migration, or claim gate.

The product owner owns the confidentiality objective and risk acceptance. The security architect owns the acceptance's security consequence and any concurrence required to activate or reactivate the exception. Original architect text remains authoritative except for the amended Status paragraph, the in-place amendments to sequencing steps 1 and 5, and text labelled **Architect amendment — 2026-08-08**, which expressly qualify it.

## Ruling

Use standardized **hybrid-PQ MLS** for both 1:1 and groups. Post-quantum
is a reason to start the MLS and Delivery Service work NOW, not a
separate workstream.

If PQ is a shipping requirement, **shipment waits for the production
gate** rather than silently falling back to a classical suite.

## Architect amendment — conditional pre-migration exception (2026-08-08)

The product owner accepts that traffic sent before authenticated PQ migration is classically protected, harvestable, and never acquires post-quantum protection retroactively. The acceptance covers only this PQ gap and clears no other blocker.

At each release or migration gate, the product owner must supply evidence for every disclosure condition applicable at that gate. An independently acting security architect who is not the product owner must affirmatively verify and record compliance. If no such security architect is available, the gate remains closed and no reliance on the exception is permitted.

While — and only while — the product-owner acceptance remains in force and the security architect has recorded every applicable disclosure condition as verified, the pre-migration PQ gap does not independently hold shipment. This is not launch authorization: every unchecked blocker in `SECURITY_STATUS.md` remains independently launch-blocking.

The acceptance is conditional on all of the following:

1. No product surface — UI, store listing, marketing, or documentation — may state or imply post-quantum protection before authenticated PQ migration. After migration, no such claim is permitted until every PQ claim gate has passed.
2. Every user-facing encryption description must accurately describe the protection actually provided. This ruling does not authorize any public-security claim while `SECURITY_STATUS.md` remains NO-GO. If and when that file authorizes such claims, "end-to-end encrypted" may accurately describe the classical scheme; language stating or implying resistance to future quantum decryption remains forbidden until the PQ claim gate passes.
3. Before any migration-capable release ships, users must be able to determine that pre-migration traffic does not have the new protection. That distinction must remain available thereafter; the upgrade must not imply that earlier history is covered.
4. Once authenticated PQ migration is offered or attempted for a conversation, a failed or blocked migration must be prominently surfaced to the user; the client must not silently continue creating Olm or other classical-only ciphertext for that conversation.

Conditions 1 and 2 apply continuously. Condition 3 becomes a hard release gate before any migration-capable release ships. Condition 4 applies continuously to each conversation from the first time authenticated PQ migration is offered or attempted for that conversation.

The security architect must record suspension whenever an applicable condition is unverified. The security architect may restore reliance after verifying and recording proof of uninterrupted compliance. Evidence that an applicable condition was violated makes the acceptance LAPSED from the earliest affected time. Correction does not automatically revive a lapsed acceptance and cannot retroactively authorize traffic created during the breach. Reactivation requires a new dated product-owner acceptance and security-architect concurrence.

If reliance is suspended or the acceptance lapses after a pre-PQ launch, no new release, onboarding, or creation of pre-migration message ciphertext may proceed under this exception until reliance is restored or reauthorized. Existing user data must remain accessible, and affected users must receive an accurate corrective disclosure. A pre-PQ launch is not authorized unless this operational hold can be enforced.

Pre-migration Olm operation under this exception is expressly classical and is not a fallback from PQ. Whenever PQ is required — including whenever this exception is not in force and after authenticated PQ migration — failure of the production-gated hybrid-PQ MLS path must fail closed. The client must never silently negotiate down to, continue on, or resume Olm or another classical-only suite.

## OpenMLS readiness — the deciding input

- **Sufficient for a non-shipping spike:** yes. OpenMLS carries an older
  experimental X-Wing implementation.
- **Sufficient for a standardized production pin:** NO. Its documented
  supported-suite list is still classical; the experimental suite uses an
  older draft and a temporary `0x004D` identifier, and the MLS PQ
  ciphersuite specification remains an active Internet-Draft with `TBD`
  identifiers.

Therefore the experimental suite is permitted ONLY for benchmarks,
persistence experiments, wire-size measurement and interoperability
discovery. Do not freeze its wire codepoint, do not persist production
state under it, and do not make a public PQ claim from it.

## Provisional production target

`MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519`

- ML-KEM-768 **plus** X25519 — the classical half is retained.
- Use the final standardized suite identifier, not OpenMLS's `0x004D`.
- Ed25519 remains classical authentication: this target provides
  post-quantum **confidentiality**, not post-quantum **authenticity**. PQ
  signatures would be a separate suite and migration decision.

The suite name is provisional until the standard is finalized.

## What Phase 2 keeps and what it retires

| Element | Ruling |
|---|---|
| Private store, platform-key lifecycle, encrypted atomic snapshots, generation CAS | **Retain** |
| Single-actor façade, candidate-state-before-output discipline, `DurableAction` binding | **Retain the architecture**; re-review its MLS implementation |
| Relay capabilities, idempotent sends, durable outboxes, deletion ACKs, tombstones | **Retain transport invariants**; rebind to MLS messages |
| `ClientStateV1` layout, vodozemac pickles, OTK records, Olm transcript fields | **Retire** |
| Olm epoch derivation, the skipped-key-driven 24/8/32 budget, Olm-specific `RekeyRequired` | **Retire and redesign** against MLS epochs/commits |
| Existing independent PASSes | Valid ONLY for their exact Olm code. **None transfers to MLS.** |

### Architect amendment — pre-migration V1 production state (2026-08-08)

Implement a separate `ClientStateV2`/MLS path. **Do not reinterpret `ClientStateV1` fields or migrate V1/Olm cryptographic or session state into V2.** Preserve the reviewed V1 path and its tests until the MLS replacement and the migration-and-retirement plan independently pass. Rebootstrap each affected conversation through the verified contact ceremony into a fresh MLS group, then retire V1 explicitly.

At the date of this ruling there is no production state. This amendment does not authorize the current V1/Olm path for production. If a pre-PQ launch is separately cleared by `SECURITY_STATUS.md`, that no-production-state premise ends. Before launch, an independently reviewed V1 production-lifecycle and retirement plan must cover live sessions, queued or outstanding Olm messages, retained history, crash and rollback behavior, recovery and support, rebootstrap, and explicit V1 retirement. V1 may not be retired merely because V2 passes.

Existing independent PASSes remain valid only for their exact reviewed Olm code. They neither authorize a pre-migration launch nor transfer to MLS.

Stop adding discretionary Olm-only product features. This does not prohibit security and operational work required to close an independently tracked non-PQ launch blocker. Keeping the harness sound is not a production-readiness standard.

## Why the interim outer layer was rejected

Encapsulating every message to the same ML-KEM key does not create
forward secrecy: a later compromise of that decapsulation key opens every
retained outer ciphertext. Fixing that needs rotating or one-time PQ
keys, authenticated transcript binding, erasure, downgrade resistance,
retry/replay handling, loss recovery and durable rekey state — in
substance a second ratchet and a new protocol.

If the harvest-now-decrypt-later window is unacceptable before
standardized MLS is ready, **the default consequence is to hold
shipment.** An interim layer would require its own human-authored
specification and independent audit; this ruling does not pre-authorize
one.

**Architect amendment — 2026-08-08.** The conditional exception above is the sole exception to this default. If reliance on the acceptance is suspended or the acceptance lapses, the original hold-shipment consequence applies immediately. Nothing in this amendment authorizes an interim outer layer.

## Bounds

FIPS 203 fixes ML-KEM-768 at a 1,184-byte encapsulation key, a 2,400-byte
decapsulation key and a 1,088-byte ciphertext.

Frozen Olm bounds do NOT change: `MAX_PACKET` stays 96 KiB and the sealed
state limit stays 8 MiB. The relay's separate wire limit is 1 MiB. None
of these automatically become MLS bounds.

`ClientStateV2` needs distinct maxima for KeyPackages, Welcomes, Commits,
application messages, credentials/extensions, serialized group state and
member count. Freeze the MLS group-size and extension budgets BEFORE
freezing those bounds, and test exact and one-over decoding before
allocation.

## Sequencing

**Architect amendment — 2026-08-08.** This sequence governs the PQ migration and availability of the PQ claim. It does not authorize launch or reorder any independent launch blocker in `SECURITY_STATUS.md`.

1. **COMPLETE on 2026-08-08 as a threat-model documentation step.** `THREAT_MODEL.md` now models the HNDL adversary, indefinite confidentiality horizon, compromise timing, erasure status and required endpoint invariant, pre-migration acceptance, disclosure obligations, and precise claim language. Maintain this material as the design changes. Endpoint-secret erasure remains **OPEN** and independently blocks the PQ claim; completing this documentation step neither mitigates HNDL nor opens any launch or claim gate.
2. Freeze and verify the contact ceremony, identity/authentication
   service, identity-bound envelope handling, and single-use KeyPackage
   publication/claim. **A PQ KEM authenticated to a substituted identity
   solves nothing.**
3. Run the Delivery Service ordering/fork spike. MLS relies on the DS to
   break simultaneous-Commit ties; the current pairwise-mailbox design
   does not provide that function.
4. Build the non-shipping OpenMLS PQ spike: atomic persistence, restart
   boundaries, wire-size measurement, Android/iOS device checks. OpenMLS
   builds but does not test its listed mobile targets, so mobile
   readiness is unestablished.
5. Open the PQ production-and-claim gate only after standardization,
   matching upstream support, interoperability vectors,
   downgrade/fallback rejection, and human cryptographic review.
6. Migrate conversations through the verified ceremony into fresh MLS
   groups. **Never negotiate down to Olm when PQ is required.**

**Architect amendment — 2026-08-08.** In step 6, pre-migration Olm is permitted only under the conditional exception above and remains expressly classical. Once a conversation has completed authenticated PQ migration, it must never negotiate or fall back to Olm.

## The only defensible claim

**Architect amendment — 2026-08-08.** This claim is unavailable unless the PQ production-and-claim gate, every conjunctive prerequisite in `THREAT_MODEL.md`, and global claim clearance in `SECURITY_STATUS.md` have all passed. Until then, this ruling authorizes no statement or implication that the product has post-quantum protection.

> Hybrid-PQ MLS provides post-quantum confidentiality against
> harvest-now-decrypt-later for messages sent after an authenticated PQ
> migration, subject to correct key handling and erasure.

It does NOT protect earlier Olm ciphertext, metadata, compromised
endpoints, or present-day identity substitution, and it provides no
post-quantum authenticity while Ed25519 remains the signature scheme.
