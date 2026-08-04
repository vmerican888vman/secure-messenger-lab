# Prototype architecture

## Scope

One device per person, one peer, text only, two unidirectional mailboxes, local process, SQLite relay.
No network server and no durable client state.

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

`OlmClient::seal` is the only application path that creates an `EncryptedPacket`. It returns an error
if a session is missing. The inner encrypted JSON binds:

- payload version;
- random conversation ID;
- random message ID;
- endpoint timestamp; and
- body.

The relay sees the Olm packet bytes and an outer copy of the random message ID. A recipient compares
the authenticated inner ID with the outer ID before display or ACK. The relay also retains the
sender-capability signature over the outer ID and ciphertext digest; the recipient verifies that
signature before it invokes Olm. Account/session changes are then computed on in-memory staged copies
and committed only after the authenticated inner conversation/message binding succeeds. Relay-only or
binding-invalid metadata therefore cannot consume the authoritative one-time key or ratchet state.
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
- If an ACK request is lost before reaching the relay, the caller can retry the retained signed
  `AckRequest` (or mint another while retaining `OpenedMessage`) until the earlier of its request expiry
  and the message-retention expiry. If deletion committed but the response was lost, retry returns
  `AlreadyDeleted` from the tombstone while the ACK request remains valid. A real client still needs a
  durable ACK outbox so process loss cannot discard that proof.
- If ACK does not commit, the ciphertext remains available. If it commits, the current database has no
  live ciphertext row.

This does not yet inject a process kill inside a transaction or test a replicated/networked relay.

## Why this code is disposable

The code chooses in-process APIs, has no encrypted client persistence, and assumes contact verification.
Those choices make the security seam testable without accidentally creating an under-designed service.
A later production implementation must be built fresh after Phase 0 decisions, using the tests and
invariants rather than copying this repository wholesale.
