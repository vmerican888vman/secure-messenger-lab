# Prototype architecture

## Scope

One device per person, one peer, text only, two unidirectional mailboxes, local process, SQLite relay.
No network server. Phase-2 client state is durable through the persistence-owning façade below; the
Phase-0 in-process client path is retained crate-private for the in-crate proof tests only.

## Phase-2 persistence architecture (current production path)

`PersistentClient` (src/persistent) is the single-actor façade: it exclusively owns the store handle,
the decoded `ClientStateV1`, the vodozemac `Account`, the optional `Session`, the mailbox capability
keypairs, the peer binding, inbound records and every outbox. Every mutation clones a complete
candidate, cross-validates it, serializes it through the bespoke canonical TLV codec (src/state) with
full semantic validation, and commits it as one generation-CAS snapshot; a commit failure locks the
façade into reconcile-until-reopen. Externally transmitted requests are `DurableAction`s whose random
action IDs and request bindings are verified against the durable record when results return.

Payloads are `ClientPayloadV2` (src/payload): strict canonical JSON carrying conversation, epoch,
per-sender sequence and kind (application or high-water receipt). The §4 send-side budget (24
application advances, 8 control, 32 absolute) drives `Ready`/`ControlOnly`/`ReceiptLocked`;
`RekeyRequired` dominates after an authenticated gap failure. Receipts advance the peer-contiguous
high water; out-of-order receives sit in a bounded set.

The platform-key lifecycle manager (src/lifecycle) owns the registry of key state
(`Provisional`/`Expected`/`Locked`/`Deleting`) and drives create/recovery/destructive-reset under the
private-store boundary (src/private_store_dir), which enforces owner-only, no-ACL, exact-content,
single-attempt-locked directories.

`OlmClient` (src/client.rs) and the mailbox capability owners (src/capability.rs) are crate-private:
their public mutations were production bypasses of this discipline and no longer resolve outside the
crate. Only the relay's wire request types and `EncryptedPacket` stay public from that surface.

## Flow

```text
verified direct exchange
Alice client  <---------------------------->  Bob client
     |                                                |
     | signed SEND capability                         | signed RECEIVE capability
     v                                                v
Bob's opaque mailbox  ---- fetch ciphertext ---->  Bob decrypts
     ^                                                |
     |                  signed ACK                    |
     +------------------------------------------------+

Bob replies through a separate Alice-owned mailbox using the same established Olm session.
```

Each mailbox stores three public verification keys. The matching private send key is shared with the
peer through the assumed verified contact exchange; private receive and management keys stay with the
mailbox owner. The relay receives none of them. Short-lived contact bundles sign the Curve25519
identity and one-time key with the separately pinned Ed25519 contact identity.

## Crypto boundary

`PersistentClient::stage_send` is the only application path that creates an `EncryptedPacket` (the
legacy `OlmClient::seal` survives only in the crate-private test surface). It returns an error if a
session is missing or the mode forbids staging. The inner encrypted `ClientPayloadV2` JSON binds:

- payload version;
- conversation ID;
- random message ID;
- session epoch ID;
- per-sender sequence; and
- body (application kind) or receipt (receipt kind).

The relay sees the Olm packet bytes and an outer copy of the random message ID. A recipient compares
the authenticated inner ID with the outer ID before display or ACK. The relay also retains the
sender-capability signature over the outer ID and ciphertext digest; the recipient verifies that
signature before it invokes Olm. Account/session changes are computed on candidate copies and
committed only after the authenticated inner conversation/epoch/message binding succeeds. Relay-only
or binding-invalid metadata therefore cannot consume the authoritative one-time key or ratchet state.
Previously verified pre-key bundles and envelopes are also rechecked against the current time at the
exact session-creation/decryption boundary, so retaining a verified wrapper does not bypass expiry.

The spike uses the high-level `vodozemac` Olm API, not low-level primitives. It uses a separate Olm
account per peer and assumes the complete pre-key bundle was verified directly. This does not solve a
real app's identity hierarchy or pre-key service.

## Relay command binding

Every signed command is length-prefixed and domain-separated by protocol version and action. A send
signature covers queue ID, message ID, SHA-256 of the opaque packet, and retention expiry. An ACK covers
queue ID, message ID, packet digest, and request expiry. Fetch and management requests carry short-lived
random nonces.

SHA-256 is used only to bind an already encrypted packet into the signed command; it is not message
encryption. Ed25519 and Olm operations come from `vodozemac`.

## Atomicity in the current relay

- Send is committed before success is returned.
- Same ID plus same packet/expiry returns a stable duplicate outcome.
- Same ID plus different packet/expiry fails with a conflict.
- Fetch leaves the row present.
- ACK verifies authorization and the stored packet digest, deletes the row, inserts a replay tombstone,
  and commits as one SQLite transaction.
- Mailbox deletion stores a one-way hash of the retired queue ID so a captured or freshly self-signed
  registration cannot recreate that locator.
- Registration and enqueue decisions use immediate write transactions plus a bounded SQLite busy
  timeout, so concurrent identical sends resolve to one stored result and one duplicate.
- Global expiry sweeping runs at startup and every relay operation; an actual service still needs a
  periodic timer for a strict wall-clock deletion SLA while otherwise idle.
- Schema versioning runs in the same immediate startup transaction. A legacy message table without
  sender signatures is securely emptied and rebuilt because those queued packets cannot satisfy the
  current recipient-verification invariant.
- The façade's ACK intents are durable: `ack_actions` reconstructs the exact signed `AckRequest` from
  the committed record, so process loss cannot discard the proof; `record_ack_result` consumes the
  intent only after token, field and signature verification. If deletion committed but the response
  was lost, retry returns `AlreadyDeleted` from the tombstone while the ACK request remains valid.
- If ACK does not commit, the ciphertext remains available. If it commits, the current database has no
  live ciphertext row.

This does not yet inject a process kill inside a transaction or test a replicated/networked relay.

## Why this code is disposable

The relay and protocol seams remain harness-grade (in-process APIs, assumed contact verification, no
network). Those choices make the security seam testable without accidentally creating an
under-designed service. A later production implementation must be built fresh after Phase 0/2
decisions, using the tests and invariants rather than copying this repository wholesale.
