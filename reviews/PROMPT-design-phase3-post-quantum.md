# Design brief — post-quantum key agreement (secure-messenger-lab)

**The decision is made: post-quantum is required.** This brief is not
asking whether. It asks HOW and WHEN, because the current architecture
forecloses the obvious answer and the alternatives have very different
blast radius.

## Where the code actually is

- `Cargo.toml` pins `vodozemac = "=0.10.0"` (Olm) with one reviewed local
  patch. **There is no MLS dependency yet** — OpenMLS is planned but not
  started.
- Phase 2 is mid-flight: façade leg D2b closed with a dual PASS; the
  `ClientStateV1` codec leg is open with one design question outstanding
  (`reviews/PROMPT-design-phase2-send-metadata-binding.md`).
- `SECURITY_STATUS.md` still has thirteen open blockers, including **no
  verified contact ceremony at all** and no written threat model.

## Why Olm cannot simply take a PQ KEM

`vendor/vodozemac-0.10.0/src/olm/shared_secret.rs` defines
`Shared3DHSecret(Box<[u8; 96]>)` — exactly three 32-byte DH outputs, with
no public API to mix additional secret material into the root key.

So hybridising the handshake INSIDE Olm means forking vodozemac's key
schedule: new root-key derivation, new message format, and forfeiting the
Least Authority audit the project currently inherits. That is a new
protocol, not a patch, and it is the same shape as the failure documented
in the BLK audit — correct-looking crypto beside an unverified path.

## The three routes, as I see them

1. **PQ arrives with MLS.** The plan already commits to OpenMLS for both
   1:1 and groups. Take PQ from a standardised MLS ciphersuite rather
   than inventing it, and spend nothing on PQ-ing a protocol that is
   already scheduled for replacement. Implication: post-quantum becomes a
   reason to move the MLS migration EARLIER, not a separate workstream.
2. **An interim outer hybrid layer.** Wrap the Olm ciphertext in an AEAD
   keyed from a hybrid X25519 + ML-KEM secret. Composition, no fork, no
   vendored-crypto change, fails safe (an adversary must break both
   layers). The hard part is not the encapsulation — it is that the outer
   layer needs its own rekey schedule, or a single PQ private-key
   compromise decrypts the entire archive and we have bolted weak forward
   secrecy onto a ratchet that had strong forward secrecy.
3. **Fork Olm's key schedule.** I recommend against it and am recording
   it only so the option is visibly rejected rather than overlooked.

My own reading is (1), with (2) only if the harvest-now-decrypt-later
window before MLS lands is judged unacceptable. But the window's
acceptability is a threat-model call, which is yours.

## What I need specified

1. **Route.** (1), (2), (3), or something I have missed.
2. **If (1): does PQ change the MLS migration timing**, and what happens
   to the Olm-based Phase-2 work already reviewed — is it throwaway
   scaffolding, or does the façade/codec/persistence layer survive the
   protocol swap? That answer changes how much more I should invest in
   the current legs.
3. **If (2): the rekey schedule for the outer layer**, which is the
   substance. Also whether the outer layer is per-session or per-message,
   and how it interacts with the §4 receipt/ACK machinery that just took
   sixteen review rounds to stabilise.
4. **Primitive and parameter set** — presumably hybrid X25519 +
   ML-KEM-768 (FIPS 203), but say so explicitly, including whether the
   classical half is retained (hybrid) or replaced.
5. **Wire and bounds impact.** An ML-KEM-768 ciphertext is ~1088 bytes.
   The frozen §3 bounds table sets `MAX_PACKET` at 96 KiB and the sealed
   ciphertext cap at 8 MiB; a PQ handshake also enlarges the contact
   bundle. Confirm nothing in the frozen bounds needs to move, or say
   what does.
6. **Sequencing against the open blockers.** I raised, and you may
   overrule, the concern that PQ before a verified contact ceremony is a
   vault door on a tent — the practical attack is key substitution during
   an unverified exchange, not Shor's algorithm. Say where PQ sits
   relative to the contact ceremony, identity-bound envelope
   authentication, and the threat model.

## Constraints

- No `vodozemac` fork.
- Nothing may regress the legs already carrying independent PASSes.
- The codec has no trusted `now`.
- A human cryptographer or security firm signs off on the protocol before
  any shipped PQ claim; no model holds final merge on the crypto core.

## Things you should know before ruling

- **I have not verified OpenMLS's PQ ciphersuite readiness** and am not
  asserting it from memory. If route (1) depends on it, that readiness is
  a fact to check, not assume, and it may be the deciding input.
- **PQ buys harvest-now-decrypt-later protection specifically.** It does
  nothing against a present-day adversary, nothing for metadata, and
  nothing for the thirteen open blockers. Worth stating plainly in
  whatever §-text you produce, so the property is not later overclaimed
  in a store listing.
- The MLS Delivery Service seam (MLS needs totally ordered commits;
  SimpleX-style pairwise mailboxes have no serializer) is still an
  unresolved spike in the plan. If PQ accelerates MLS, it accelerates
  that spike too — they are the same decision.
