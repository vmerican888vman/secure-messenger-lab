# Phase 3 decision — post-quantum key agreement

**Status: DECIDED by the security architect. Route 1 — pull MLS forward.**
No outer hybrid layer. No Olm fork. No production PQ claim until the
standardization / upstream / mobile / human-review gate passes.

This records a ruling, not a proposal. It supersedes the options laid out
in `reviews/PROMPT-design-phase3-post-quantum.md`.

## Ruling

Use standardized **hybrid-PQ MLS** for both 1:1 and groups. Post-quantum
is a reason to start the MLS and Delivery Service work NOW, not a
separate workstream.

If PQ is a shipping requirement, **shipment waits for the production
gate** rather than silently falling back to a classical suite.

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

Implement a separate `ClientStateV2`/MLS path. **Do not reinterpret
`ClientStateV1` fields.** Preserve the reviewed V1 path and its tests
until the MLS replacement independently passes, then retire V1
explicitly. There is no production state, so invent no V1→V2 secret-state
migration — rebootstrap through the verified contact ceremony.

Stop adding Olm-specific product features. Close only the defects needed
to keep the existing harness sound.

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

1. Extend the threat model with the HNDL adversary, confidentiality
   horizon, compromise timing, erasure assumptions and precise claim
   language. `THREAT_MODEL.md` is a Phase-0 draft that explicitly
   excludes post-quantum adversaries.
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
5. Open the production gate only after standardization, matching upstream
   support, interoperability vectors, downgrade/fallback rejection, and
   human cryptographic review.
6. Migrate conversations through the verified ceremony into fresh MLS
   groups. **Never negotiate down to Olm when PQ is required.**

## The only defensible claim

> Hybrid-PQ MLS provides post-quantum confidentiality against
> harvest-now-decrypt-later for messages sent after an authenticated PQ
> migration, subject to correct key handling and erasure.

It does NOT protect earlier Olm ciphertext, metadata, compromised
endpoints, or present-day identity substitution, and it provides no
post-quantum authenticity while Ed25519 remains the signature scheme.
