# Threat model and metadata budget

Status: Phase 0 draft, 2026-08-04; amended 2026-08-07 to model the harvest-now-decrypt-later
adversary, and 2026-08-08 to record the product owner's confidentiality horizon, the conditional
pre-migration risk acceptance and its disclosure obligation (see "Post-quantum" below). Everything
outside that section still describes only the executable local harness in this repository.

## Assets

- Message plaintext and attachments (text only is implemented).
- Olm account, one-time-key, and ratchet secrets.
- Private send, receive, and management mailbox capabilities.
- The relationship between two people or between one person and multiple mailboxes.
- Endpoint history and future recovery material (not implemented).

## Parties and trust

- Sender and recipient endpoints are trusted for the duration of a test.
- The relay is not trusted with content or private key material. The test checks an honest-but-curious
  operator's current database and application events.
- The direct Ed25519 fingerprint exchange is trusted. Short-lived Curve25519/one-time-key bundles are
  signed by that pinned identity, but a real QR verification ceremony is not implemented.
- The operating system, compiler, dependency registry, and build host are assumed uncompromised.

## Adversaries exercised now

- A party that learns a queue ID but not its corresponding capability.
- An unauthorized caller that tries send, fetch, ACK, or mailbox deletion operations.
- A relay that alters ciphertext or the outer message ID, swaps an ACK between messages, replays a
  command/registration, duplicates a message, resurrects a deleted mailbox, or delivers ciphertext to
  the wrong recipient.
- A relay operator inspecting the current SQLite database, schema, and application event stream.
- A network retry after an accepted send whose response was lost.

## Adversaries not yet covered

- A globally observing network adversary or traffic analyst.
- A malicious relay that snapshots ciphertext before deletion, retains hidden logs/backups, withholds
  or selectively orders traffic, substitutes contact bundles, or runs modified code.
- A compromised endpoint, malicious recipient, screenshot, clipboard capture, notification leak,
  rooted device, forensic extraction, or stolen unlocked phone.
- Supply-chain compromise, malicious compiler, signing-key theft, targeted release, or dependency
  confusion.
- Denial of service, mailbox flooding after a leaked send capability, enumeration at network scale,
  proof-of-work bypass, and operational abuse.
- Coercion, legal process, moderation evidence handling, and shutdown continuity.
- Multi-device forks, recovery, revocation, groups, attachments, or calls.
- A cryptographically relevant quantum computer. **This adversary is now MODELLED — see
  "Post-quantum" below — but it is NOT MITIGATED at any current head.** It is listed here rather than
  above because nothing in this repository defends against it today.

## Security properties under test

1. Plaintext enters the client encryption function and never enters a relay API.
2. Missing or unusable session state returns an error; there is no plaintext fallback type or branch.
3. Olm authentication rejects modified ciphertext and ciphertext presented to the wrong account.
4. A short-lived contact bundle binds the Curve25519 identity and one-time key to an independently
   pinned Ed25519 identity. A replacement bundle is rejected before session creation.
5. The queue ID is a locator, not authorization. Separate high-entropy Ed25519 capabilities authorize
   send, receive/ACK, and management operations.
6. Send retries with the same message ID and ciphertext are idempotent. A different ciphertext under
   the same ID is rejected.
7. The fetched outer envelope retains the sender capability signature over queue ID, message ID,
   ciphertext digest, and expiry. The recipient verifies it before Olm runs. Inbound account and
   ratchet changes then occur on staged copies and become authoritative only after the decrypted
   conversation/message binding succeeds.
8. The recipient ACK signature binds the queue ID, message ID, ciphertext digest, action domain, and
   expiry. The client API creates it only from a successfully opened envelope.
9. Fetch alone never deletes. A valid ACK deletes ciphertext in one SQLite transaction.
10. The encrypted inner payload binds the conversation ID and message ID, so relay changes to the
    visible outer message ID fail before display or ACK.
11. Relay events use fixed event names only and never include request bodies, ciphertext, capabilities,
   queue IDs, message IDs, or plaintext.

## Post-quantum: the harvest-now-decrypt-later adversary

Added 2026-08-07 as sequencing step 1 of `docs/phase3-post-quantum-decision.md`; revised after
independent review. **Modelling this adversary does not mitigate it.** No head in this repository
provides any post-quantum protection, and none is claimed.

### The adversary

A passive network or relay observer who records ciphertext and the public key material accompanying
it today, retains it, and decrypts it years later once a cryptographically relevant quantum computer
(CRQC) exists.

What makes it different from every other adversary in this document:

- **It needs no compromise, no interaction, and no privilege.** Its inputs are the ciphertext, the
  handshake public keys carried in pre-key and ratchet messages, and the peer's long-term identity
  public key distributed in the contact bundle — all public by design.
- **It is undetectable.** Recording leaves no trace at either endpoint or at the relay.
- **It is retroactive.** The decision to defend has to be made before the traffic is sent; there is
  no remediation afterwards.
- **Ordinary forward secrecy does not help.** Forward secrecy protects against future *key
  compromise*. It does not protect against the underlying *primitive* being broken. Olm's root and
  chain keys are derived from X25519 outputs; a CRQC recomputes those outputs from the recorded
  public keys, so it recovers the derived keys as well.

**Consequence, stated precisely:** against a CRQC, harvesting one Olm session's recorded traffic
compromises that session's messages generally — not merely a window around a single compromised key.
Ratcheting bounds the damage from a stolen key; it does not bound the damage from a broken
primitive.

This was verified against the vendored schedule rather than asserted: the Olm root and chain
derivation is a deterministic function of X25519 DH outputs plus public constants, with no
pre-shared key, out-of-band secret, or ceremony entropy mixed in.

### Confidentiality horizon

The horizon is *how long a given message must remain confidential*. It is a product decision, not a
cryptographic one.

**Decided by the product owner on 2026-08-08: INDEFINITE for message plaintext.** An earlier
revision of this document adopted that value on its own initiative; that was policy the governing
ruling did not then contain and it was correctly withdrawn. The value below is not this document's
choice — it is a recorded decision by the authorized owner, which is what the ruling asked the threat
model to state.

| Asset | Horizon | Notes |
|---|---|---|
| Message plaintext | **INDEFINITE** (product owner, 2026-08-08) | Messages must remain confidential without a time limit. |
| Contact graph and other metadata | Out of scope for this work | See "Metadata" below — PQ key agreement is not a metadata control. |
| Long-term identity keys | Separate decision | Ed25519 remains classical under the chosen suite; see "Claim language". |

Time-to-CRQC is not predictable from within this project, and this document sets **no threshold** of
its own — inventing one would be policy the governing ruling does not contain.

### What the indefinite horizon entails

Derived from the governing ruling, not added by this document:

1. An indefinite horizon **exceeds any plausible time-to-CRQC by construction.** Classical-only key agreement is therefore insufficient for message plaintext by definition, not by estimate.
2. Absent an authorized acceptance of the pre-migration gap, PQ is consequently a shipping requirement and shipment waits for the PQ production-and-claim gate rather than silently falling back to a classical suite.
3. The recorded acceptance below creates a conditional exception to that shipment consequence; it does not make pre-migration traffic satisfy the horizon. Any message sent before authenticated PQ migration remains permanently outside the stated objective.

### Recorded risk acceptance for pre-migration traffic

**Decided by the product owner on 2026-08-08.** The indefinite horizon above is the objective. It is
not met for traffic sent before the authenticated PQ migration, and that gap is **accepted,
disclosed, and not claimed away.**

Concretely:

- Traffic sent before the migration is classically protected. If recorded and retained, it is
  harvestable and becomes decryptable once the modelled CRQC exists. This is permanent for that
  traffic; migration does not repair it.
- While the acceptance remains in force, PQ is not by itself a reason to hold shipment. This is not launch authorization: every unchecked blocker in `SECURITY_STATUS.md` remains independently controlling.
- This acceptance covers the post-quantum gap **only**. It licenses nothing about the contact ceremony, identity binding, endpoint compromise, metadata, or any other launch or security blocker.

This is the same posture the established messengers took: both Signal and SimpleX shipped for years
on classical key agreement and migrated later, and traffic sent before their migrations remains
harvestable. The posture is defensible **because it is disclosed**, not because the risk is small.

### Disclosure obligation — the condition that makes the acceptance honest

An accepted risk that users are not told about is not an accepted risk; it is an undisclosed one. The acceptance above is therefore **conditional on all of the following**.

At each release or migration gate, the product owner must supply evidence for every condition applicable at that gate, and the security architect must affirmatively verify and record compliance. The security architect must record suspension whenever an applicable condition is unverified and may restore reliance after verifying and recording proof of uninterrupted compliance. Evidence of a violation makes the acceptance LAPSED and invokes the governing ruling's fail-closed consequence. Correction does not automatically revive a lapsed acceptance; reactivation requires a new dated product-owner acceptance and security-architect concurrence.

1. **No product surface — UI, store listing, marketing, or documentation — may state or imply post-quantum protection before the migration.** After migration, no such claim is permitted until every post-quantum claim prerequisite has passed.
2. Every user-facing encryption description must accurately describe the protection actually provided, but this document does not authorize any public-security claim while `SECURITY_STATUS.md` remains NO-GO. If and when that file authorizes such claims, "end-to-end encrypted" may describe the classical scheme; language stating or implying resistance to future quantum decryption remains forbidden until the post-quantum claim gate passes.
3. Before any migration-capable release ships, users must be able to determine that traffic predating authenticated PQ migration does not carry the new protection. That distinction must remain available thereafter. Silently upgrading and letting users infer that all their history is covered would convert an honest gap into a misleading one.
4. Once authenticated PQ migration is offered or attempted for a conversation, a failed or blocked migration must be prominently surfaced to the user; the client must not silently continue creating Olm or other classical-only ciphertext for that conversation.

The project's stated goal is that the app be secure, trusted, and confidential. **Trust here is
produced by the accuracy of what is said, not by the strength of what is claimed** — and an
overstated claim that is later corrected costs more trust than an accurate limitation disclosed up
front.

**Amendment recorded:** On 2026-08-08 the security architect amended `docs/phase3-post-quantum-decision.md` to incorporate the product-owner horizon decision, conditional risk acceptance, disclosure obligation, and their security consequences. The governing ruling controls wherever the documents differ.

### Retention, and what "recorded" means

Four distinct retention notions are involved, and conflating them produces false comfort:

| Notion | Bound |
|---|---|
| Signed acceptance TTL | Capped at seven days — this is the maximum a sender may request, not a deletion guarantee |
| Live-row deletion timing | A valid ACK deletes in one transaction; otherwise removal waits for an expiry sweep, and an idle relay with no operation can retain an expired row **indefinitely** until the next sweep |
| Logical ACK deletion | Removes the row from the current database file; see "Deletion semantics" — this is not forensic erasure |
| Attacker copies, journals, snapshots, backups, packet captures | **Unbounded.** Nothing in this system constrains them |

The last row is the adversary's actual input. Attacker-retained ciphertext is the **premise** of this
threat model, not a failure of any key agreement.

### Compromise timing

- **Recording window:** anything on the wire, plus anything retained per the table above.
- **Decryption event:** at CRQC availability, which may be long after every endpoint, key and
  operator involved is gone.
- **Migration boundary:** post-quantum confidentiality can only apply to traffic sent *after* an
  authenticated migration. Earlier Olm ciphertext **never acquires PQ protection**; if it was
  recorded and retained, it becomes decryptable once the modelled CRQC exists. Delay therefore
  increases the volume of traffic in that category, and the effect is not reversible.

### Erasure and endpoint invariants

Three separate things were previously conflated here. They are not the same and do not belong to the
same actor:

1. **Attacker-retained ciphertext — the premise, not a defect.** Covered above. No key agreement
   addresses it; it is why the adversary exists.
2. **Endpoint-secret erasure — a testable invariant, currently UNSPECIFIED.** A post-quantum
   confidentiality claim depends on endpoint secrets actually ceasing to exist when the protocol says
   they do. This document cannot yet name which MLS secrets must disappear, at what point, how
   delayed delivery extends their required lifetime, or how the existing storage semantics interact —
   `docs/persistence-spike-design.md` explicitly permits authentic rollback and disclaims
   backup/forensic erasure, so an authentic old endpoint snapshot could retain compromise-enabling
   secrets while every other gate passes. **Specifying and enforcing that lifecycle is a gate
   condition, not an assumption.**
3. **Recipient and endpoint compromise — an exclusion, not an invariant.** A recipient can always
   retain plaintext, and a compromised endpoint defeats any key agreement. These are outside the
   claim, not conditions on it.

### Planned mitigation, and its exact limits

Per `docs/phase3-post-quantum-decision.md`: hybrid-PQ MLS, provisionally
`MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519`.

The intended rationale for retaining the classical half is that key establishment should survive the
failure of either assumption alone. **That property is conditional and must not be asserted as
obtained:** it holds for the key-establishment component only, under a finalized robust combiner, a
conforming implementation, and X25519 still being secure at the time of attack. An adversary with
both a CRQC and a break of the lattice assumption defeats both halves. The combiner property will not
be claimed before standardization and review.

This targets post-quantum **confidentiality**. It does **not** provide post-quantum **authenticity**
while Ed25519 remains the signature scheme. PQ signatures are a separate suite and migration
decision.

### Metadata

PQ key agreement is not a metadata control. This migration makes **no claim** to reduce
relay- or network-visible routing, size, timing, or contact-graph metadata. MLS can encrypt some
protocol metadata, so the blanket statement that key agreement "never" protects metadata is too
strong — but nothing in this work is designed or evaluated for that purpose.

The "Metadata budget" table below describes the **Olm harness**, not the future MLS/Delivery Service
design, and does not carry over to it.

### Claim language

The only defensible public claim, once every prerequisite below has been met:

> Hybrid-PQ MLS provides post-quantum confidentiality against harvest-now-decrypt-later for messages
> sent after an authenticated PQ migration, subject to correct key handling and erasure.

It does **not** cover: earlier Olm ciphertext, metadata of any kind, compromised endpoints,
present-day identity substitution, or post-quantum authenticity.

**Until then, the correct statement is that this project has no post-quantum protection.**
"Quantum-safe", "quantum-proof", and an unqualified "post-quantum secure" are all false here, and all
three remain false after migration — because each asserts more than the property obtained, which is
confidentiality only, forward-dated only, and conditional on erasure.

### What must be true before the claim is available

**The Phase 3 gate is necessary but NOT sufficient.** Meeting it authorizes nothing on its own.

From the ruling: a finalized MLS PQ ciphersuite, a matching reviewed OpenMLS release, mobile/device
validation, interoperability vectors, downgrade and fallback rejection tests, and human cryptographer
sign-off.

Additionally required before any public claim, **conjunctively** — every item, not any:

- **Full compliance with sequencing steps 2 through 6 of the governing ruling.** The list below
  elaborates but does not replace them; where this document and the ruling differ, the ruling
  governs.
- A **reviewed, deployed** MLS and Delivery Service path — not a spike — covering **both 1:1 and
  groups**, since the ruling adopts MLS for both.
- A **separate `ClientStateV2` path.** `ClientStateV1` fields must not be reinterpreted.
- **No V1→V2 secret-state migration.** There is no production state at the date of the governing ruling. If a pre-PQ launch is separately cleared, the ruling's V1 production-lifecycle and retirement amendment governs; migration of V1/Olm cryptographic or session state into V2 remains prohibited regardless.
- **Rebootstrap through the verified contact ceremony into FRESH MLS groups** — an authenticated
  in-place conversion of existing Olm sessions does not satisfy this and is prohibited.
- **No negotiation down to Olm when PQ is required**, and downgrade/fallback rejection tested.
- **Persistence and restart proof** for the deployed path.
- A **specified and verified endpoint-secret erasure lifecycle** (see above).
- The **INDEFINITE confidentiality horizon** honoured for the traffic being claimed about. Under the incorporated conditional acceptance, PQ is not by itself a launch gate only while that acceptance remains in force; the claim remains available only for post-migration traffic and only once every other item here is met.
- **Global clearance in `SECURITY_STATUS.md`**, which independently blocks *any* public-security
  claim on work broader than post-quantum — including the contact ceremony, formal threat model, and
  external audit.

A PQ key agreement authenticated to a substituted identity provides nothing, so the contact ceremony
must be frozen and verified regardless.

## Metadata budget

| Relay-visible field | Purpose | Current retention | Delete trigger |
|---|---|---:|---|
| Random 32-byte queue ID | Locate one unidirectional mailbox | Mailbox lifetime | Management delete |
| Three Ed25519 public keys | Verify send, receive, and management commands | Mailbox lifetime | Management delete |
| Random 16-byte message ID | Idempotency and ACK target | While queued; then tombstone | ACK/expiry; tombstone after 7 days |
| Ciphertext and byte length | Offline store-and-forward delivery | Signed expiry is capped at 7 days; physical row remains until the next sweep | Valid ACK or global expiry sweep |
| Message expiry | Bound offline retention | With ciphertext | Valid ACK or TTL |
| Random fetch/manage nonce | Reject command replay | Up to signed request expiry (max 5 minutes) | TTL or mailbox delete |
| Random registration nonce | Make registration retry/replay explicit | Up to signed request expiry (max 5 minutes) | Global expiry sweep |
| SHA-256 of retired queue ID | Prevent deleted-mailbox resurrection | Indefinite in this prototype | Not deleted |
| Event type | Minimal local observability | Process lifetime only | Process exit |

A real network relay would additionally observe source IP, connection time, request size, TLS metadata,
and timing unless another transport layer hides them. None of those are modeled or claimed away here.

## Deletion semantics

`PRAGMA secure_delete=ON`, rollback-journal mode, full synchronous writes, and full auto-vacuum are
enabled. After a valid recipient ACK, the relay transaction deletes the ciphertext and creates a
seven-day tombstone containing only the random queue ID, random message ID, and deletion deadline.
The test verifies that neither plaintext nor the exact ciphertext remains in the current database
file.

This is **logical deletion plus a check of the current file**, not a promise of forensic erasure.
SQLite journal blocks, filesystem snapshots, virtual-machine images, host backups, storage firmware,
RAM, packet captures, or a dishonest operator may retain ciphertext. A recipient can always retain
plaintext. The server cannot cryptographically prove that it deleted every copy.

Expiry is swept globally at relay startup and at every relay operation. An idle process with no
operation can retain an expired row until the next sweep; a real network service must add and test a
periodic scheduler before claiming a wall-clock deletion SLA.

## Identity and linkability constraint

The harness creates a separate Olm `Account` per peer so its Curve25519 identity is not reused as a
global cross-contact identifier. That is only a prototype tactic. A stable user identity, per-device
keys, contact verification, recovery, revocation, and the binding between stable identity and
peer-scoped session keys remain unsolved Phase 0 work.
