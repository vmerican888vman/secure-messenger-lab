# Threat model and metadata budget

Status: Phase 0 draft, 2026-08-04; amended 2026-08-07 to model the harvest-now-decrypt-later
adversary (see "Post-quantum" below). Everything outside that section still describes only the
executable local harness in this repository.

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

Added 2026-08-07 as sequencing step 1 of `docs/phase3-post-quantum-decision.md`. **Modelling this
adversary does not mitigate it.** No head in this repository provides any post-quantum protection,
and none is claimed.

### The adversary

A passive network or relay observer who records ciphertext and the public key material accompanying
it today, retains it, and decrypts it years later once a cryptographically relevant quantum computer
(CRQC) exists.

What makes it different from every other adversary in this document:

- **It needs no compromise, no interaction, and no privilege.** Everything it requires — the
  ciphertext and the handshake public keys — is already on the wire by design.
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

### Confidentiality horizon

The horizon is *how long a given message must remain confidential*. It is a product decision, not a
cryptographic one, and it must be stated per asset rather than assumed:

| Asset | Horizon | Notes |
|---|---|---|
| Message plaintext | **Not yet decided** | Must be set explicitly. If the horizon exceeds time-to-CRQC, classical-only key agreement is insufficient by definition. |
| Contact graph / metadata | Not addressed by post-quantum work at all | See "Metadata budget"; PQ key agreement protects content, never metadata. |
| Long-term identity keys | Separate decision | Ed25519 remains classical under the chosen suite; see "Claim language". |

Time-to-CRQC is unknown and not predictable from within this project. Any horizon longer than "a few
years" should be treated as exceeding it, because the cost of being wrong is unbounded and
unrecoverable while the cost of hybridising is bounded and known.

### Compromise timing

- **Recording window:** anything on the wire, plus anything the relay retains. The relay holds
  ciphertext under a signed expiry capped at seven days, and "Deletion semantics" below already
  states that deletion is logical rather than forensic. Ciphertext that survives in a journal block,
  snapshot, backup or packet capture is exactly this adversary's input.
- **Decryption event:** at CRQC availability, which may be long after every endpoint, key and
  operator involved is gone.
- **Migration boundary:** post-quantum confidentiality can only ever apply to traffic sent *after* an
  authenticated migration. **Everything sent before it stays classically protected forever.** This is
  the single most important operational consequence: delay converts directly into permanently
  exposed traffic.

### Erasure assumptions

A post-quantum confidentiality claim depends on assumptions this repository does not yet enforce:

- Endpoints actually erase key material at the points the protocol says they do. Device seizure with
  retained keys defeats the strongest key agreement.
- The relay's logical deletion is not forensic erasure (see "Deletion semantics"). Retained
  ciphertext remains harvestable regardless of the key agreement used.
- A recipient can always retain plaintext. No key agreement addresses that.

Any claim must therefore be conditioned on correct key handling and erasure, not stated absolutely.

### Planned mitigation, and its exact limits

Per `docs/phase3-post-quantum-decision.md`: hybrid-PQ MLS, provisionally
`MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519`. Hybrid means an adversary must break **both**
X25519 and ML-KEM-768; the classical half is retained deliberately so that a future break of the
lattice assumption does not leave traffic unprotected.

This provides post-quantum **confidentiality**. It does **not** provide post-quantum **authenticity**
while Ed25519 remains the signature scheme — a CRQC could forge signatures, which matters for
identity binding rather than for recorded-traffic confidentiality. PQ signatures are a separate suite
and migration decision.

### Claim language

The only defensible public claim, once the production gate in the Phase 3 ruling has passed:

> Hybrid-PQ MLS provides post-quantum confidentiality against harvest-now-decrypt-later for messages
> sent after an authenticated PQ migration, subject to correct key handling and erasure.

It does **not** cover: earlier Olm ciphertext, metadata of any kind, compromised endpoints,
present-day identity substitution, or post-quantum authenticity.

**Until that gate passes, the correct statement is that this project has no post-quantum protection.**
"Quantum-safe", "quantum-proof", or an unqualified "post-quantum secure" are all false here and would
remain false even after migration, because the third is broader than the property actually obtained.

### What must be true before the claim is available

Restating the ruling's gate so it is enforceable from this document: a finalized MLS PQ ciphersuite,
a matching reviewed OpenMLS release, mobile/device validation, interoperability vectors, downgrade
and fallback rejection tests, and human cryptographer sign-off. A PQ key agreement authenticated to a
substituted identity provides nothing, so the contact ceremony must be frozen and verified first.

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
