# Phase-2 design decisions (frozen)

Status: **frozen, not implemented.** No Phase-2 code exists.

Decided by the project's security authority (Sol / GPT-5.6) reviewing
`906225ba2cfd695b53860b2fc0b605c9107b5680`, which returned RETURN on starting
Phase-2 wiring until these four decisions were settled. This file is a decision
record: it is transcribed from that ruling rather than derived, so that
implementation has a fixed target and any later deviation is visible as a
deviation.

Two things this file is not. It is not a claim that the decisions are
implemented — `ClientStateStore` still has no consumer, and `src/client.rs`
holds its Olm `Account` purely in memory, so keys are lost on restart. And it is
not independently verified; where a claim below is checkable against source it
should be checked before being relied on, per this repository's history of
plausible-but-wrong assertions.

## Why Phase 2 was blocked

`ClientStateStore` is built, hardened and reviewed, and nothing uses it.
`SECURITY_STATUS.md` lists the corresponding item unchecked: *"Encrypted, atomic
persistence of every mutated Olm account and ratchet state."*

The obvious implementation — call `store.commit()` after the existing public
`OlmClient` methods — was rejected, because those methods already mutate live
crypto state and return packets to the caller before any persistence happens.

## 1. Recovery boundary

**Decision: in-place recovery inside an enforced private directory. Do not
promote disposable recovery copies in production.**

Rationale given: a disposable copy cannot establish relay provenance. Client
AEAD authenticates a client snapshot, but the relay has no external MAC or store
identity able to prove that an exact-schema recovered database belongs to this
deployment. Promotion is also not a single atomic file operation while
`-journal`, `-wal` or `-shm` from the old recovery set may remain.

Implement one opaque `PrivateStoreDir` used by both stores:

- Platform-created, local, non-shared, excluded from backup and transfer.
- Fixed crate-owned basenames; raw arbitrary `Path` constructors become private
  or test-only.
- Directory owned by the application UID with no group or other access. Existing
  database and companion files must be regular, owner-only, same-owner, and
  single-link.
- Reject every symlink, hardlink, device, FIFO, socket, dangling path and
  unexpected entry. Use descriptor-relative or no-follow operations where
  available: `canonicalize` followed by a later pathname open is **not** a
  security boundary.
- Acquire an exclusive non-blocking lifecycle lock before examining any database
  or companion, and hold it for the lifetime of the store handle.
- Split create from open: create requires the main database and all companions
  absent; open requires an existing non-empty regular main file.
- Run normal SQLite recovery only after those checks, then validate exact
  schema and integrity. Client state additionally requires platform binding,
  unwrap, AEAD, canonical codec and semantic validation before any application
  work.
- If recovery writes the main database and validation then fails, lock the store
  or profile. Do not claim byte preservation, and do not automatically delete
  companions.

Explicitly out of scope: root or OS compromise, arbitrary code running under the
application UID, same-UID processes that ignore the lock, external SQLite tools,
filesystem or block-level rollback, and copied foreign relay databases.

Note this supersedes the disposable-copy language in
`docs/persistence-spike-design.md`; disposable copies remain for hostile
fixtures and forensic inspection only.

## 2. Persistence-owning façade

**Decision: one non-`Clone`, non-`Sync` `PersistentClient<P>`, owned by a single
actor.** It exclusively owns the store, the decoded `ClientStateV1`, the
`Account`, the optional `Session`, capabilities, bindings, inbound records and
every outbox.

Public operation families:

```rust
create(...)
open(...)
public_identity()
protection_level()

prekey_action(...)
commit_verified_contact(...)
establish_outbound_session(...)

registration_action(...)
record_registration_result(...)

stage_send(...)
pending_send_actions()
record_send_result(...)
delivery_unknowns()
consume_delivery_unknown(...)

fetch_request(...)
accept_envelope(...)
pending_inbound()
consume_inbound(...)

ack_actions(...)
record_ack_result(...)
```

Every externally transmitted request is returned as
`DurableAction<T> { token, request }`, and only after the exact request and the
candidate crypto state have committed. Results must present the opaque action
token; the façade verifies its random action ID and request digest against the
current durable record. **Generation alone is insufficient**, because an
authentic rollback can repeat it.

Callers may retain only owned committed identities, IDs and views;
`FetchRequest`; exact durable registration, send and ACK requests; action
tokens; and the explicitly transferable redacted contact offer. They may never
receive `Account`, `Session`, pickles, `ClientStateV1`, `ClientStateStore`,
candidate crypto state, mutable capability owners, or references into façade
state.

`OlmClient`, `OpenedMessage`, `ClientStateStore` and their mutating methods
become crate-private. The current public mutations in `src/client.rs` and the
raw store commit in `src/persistence/sqlite.rs` cannot coexist with this as
production bypasses.

Every mutator follows a fixed sequence:

1. Require `Ready`; enter `Mutating`.
2. Perform known bounds checks.
3. Clone complete candidate logical and crypto state.
4. Mutate, cross-validate, serialize, enforce aggregate bounds.
5. Commit the complete snapshot.
6. Install by infallible moves; return an artifact only after success.
7. Pre-commit failure discards the candidate and returns to `Ready`.
8. Commit, CAS or uncertain-storage failure enters `ReconcileRequired`: expose
   nothing, reject all further operations until drop and reopen.

All operations are synchronous `&mut self`. No callbacks, transport, UI, logging
or await points occur while staging, which structurally prevents re-entrancy.

## 3. `ClientStateV1` codec and validation

**Decision: a bespoke canonical TLV codec**, frozen before coding.

```text
object =
  object_type:u16be
  field_count:u16be
  repeated:
    field_id:u16be
    value_len:u32be
    value[value_len]
```

Every object has an exact field count and strictly ascending field IDs. Reject
unknown, missing, duplicate or out-of-order fields; invalid enums; incorrect
fixed lengths; incomplete field consumption; allocation overflow; and trailing
bytes. Optional fields remain present, with zero length meaning absent. Arrays
are `count:u32be` followed by length-delimited objects. **Successful decoding
must re-encode byte-identically.**

Top-level framing is `magic = "SMSLCSV1"`, object type `0x0001`, nineteen fields
in this order:

1. state schema version `u16 = 1`
2. profile ID `[16]`
3. key reference `[16]`
4. generation `u64`
5. exact protocol domain
6. exact `vodozemac` version `0.10.0`
7. Olm session config `1`
8. conversation ID `[16]`
9. `Account` pickle
10. own public identity
11. own mailbox and three private keypairs
12. registration intent / current request
13. optional pending prekey
14. optional peer binding / send capability
15. optional active session
16. sorted inbound-record array
17. sorted send / `DeliveryUnknown` array
18. sorted ACK-intent array
19. sorted deduplication array

Nested records retain enough material to revalidate: registration keeps the
immutable queue and public-key intent plus the exact current nonce, expiry and
management signature; pending prekey keeps signing identity, curve identity,
OTK, creation and expiry, and signature; active session keeps role, canonical
pickle, all three `SessionKeys`, establishment transcript, epoch ID, sequence
and high-water state, mode, receipt, and the out-of-order received set; inbound
keeps message ID, epoch, sender sequence, queue, packet digest, signed expiry,
acceptance time and UTF-8 body; send keeps message ID, epoch, sequence and the
exact packet, request and signature, with terminal alternatives holding only
digest and expiry; ACK and dedup records keep epoch, sequence, queue, digest,
expiry and exact terminal state.

Limits:

| Item | Bound |
|---|---|
| Complete plaintext | 8,388,592 bytes |
| `Account` pickle | 3 MiB |
| `Session` pickle | 512 KiB |
| Each serialized capability keypair | 512 bytes |
| Body | 65,536 UTF-8 bytes |
| Packet | 98,304 bytes |
| Pending inbound | 32 |
| Pending send + unconsumed `DeliveryUnknown` | 32 |
| ACK intents | 32 |
| Deduplication records | 4,096 |
| Registration, pending prekey, peer binding, active session | at most one each |

Arrays are strictly increasing by raw `MessageId`; equal or decreasing IDs fail,
and all embedded IDs must match their array key.

Dependency pickles and keypairs serialize as bounded canonical JSON under the
exact pins: bound first, deserialize with `Deserializer::end()`, reserialize,
require byte equality. That rejects whitespace variants, ignored unknown fields,
missing or defaulted fields, duplicates, aliases, non-canonical order and
trailing data.

After `Account::from_pickle` and `Session::from_pickle`, but **before**
installation: re-pickle and require canonical byte equality; account public
Ed25519 and Curve25519 identities must equal the stored identity; reconstructed
capability public keys must match the registration intent; registration and
prekey signatures must verify with all intent, request IDs and keys agreeing;
the exact pending published OTK private key must still exist; session config
must be version 1; `session_keys()` must equal the stored establishment keys;
`epoch_id = SHA-256(identity_key || base_key || one_time_key)`; outbound and
inbound role, peer identity, OTK, transcript signature, validity at
verification, and conversation binding must all match; every request signature,
packet digest, queue, expiry, message ID, ACK reference, dedup reference,
bootstrap state and outbox transition must cross-check; session absence requires
all session-dependent records absent; and the high-water and outbox sequence
invariants in section 4 must hold.

**Upstream blocker.** Pinned `vodozemac` does not publicly expose membership of
a published one-time key. A reviewed pinned API is required:

```rust
pub fn contains_one_time_key(&self, key: Curve25519PublicKey) -> bool
```

It must inspect only the OTK store, not fallback keys. A total-count check is
insufficient.

## 4. Gap / high-water / rekey, and platform-key lifecycle

**Decision.** Every Olm encryption — including receipt-only controls — gets a
durable session `epoch_id` and `send_seq`, starting at 1.

Persist: `last_assigned_send_seq`, `peer_contiguous_high_water`,
`highest_contiguous_received_seq`, `received_above_high_water`, `mode`,
`latest_authenticated_receipt`.

Budget, sized against `vodozemac` retaining only 40 skipped keys while allowing
a receive gap of 2000:

- 24 unreceipted advances for application data
- 8 reserved for receipt and rekey control
- absolute maximum 32, leaving eight keys of headroom

Transitions:

| Mode | Outstanding | Effect |
|---|---|---|
| `Ready` | < 24 | application and control encryption allowed |
| `ControlOnly` | 24–31 | application bodies blocked; coalesced control allowed |
| `ReceiptLocked` | 32 | all encryption blocked; inbound decrypt, exact outbox retry, relay ACK and receipt processing continue |
| malformed | > 32 on load | lock the profile |

`Stored`, `Duplicate`, expiry and consuming `DeliveryUnknown` never advance peer
high-water or recover budget.

A `HighWaterReceiptV1` carries version, conversation ID, epoch ID, acknowledged
sender Curve25519 identity, issuer Curve25519 identity and `high_water:u64`,
signed by the pinned peer Ed25519 identity over the canonical length-prefixed
domain `session-high-water/v1`. It means **highest contiguous sender sequence
durably decrypted and committed** — not highest seen, and not displayed.
Out-of-order accepted sequences above it stay in the bounded set and do not move
the receipt until every gap closes. Accept only
`old_high_water < receipt.high_water <= last_assigned_send_seq`; equality is
idempotent, regression and future values are rejected. Commit the new high-water
before exposing any unlocked send permission.

A previously unseen, peer-authenticated current-epoch packet producing
`TooBigMessageGap` or `MissingMessageKey` moves the session durably to
`RekeyRequired`. Ordinary MAC or encoding failures do not.

There is **no** unilateral, timeout-based or silent Phase-2 rekey.
`ReceiptLocked` recovers through a valid receipt. `RekeyRequired` needs explicit
user-confirmed rebootstrap through the verified-contact channel, a fresh
peer-signed prekey under the pinned identity, no live old packet past
`max_old_packet_expiry`, and terminal old outboxes. Install the new session and
epoch atomically, retaining old dedup records through their safety window.
Otherwise the conversation stays locked.

### Platform-key lifecycle

`StateKeyProtector` remains a per-key wrap/unwrap handle. Add a lifecycle
manager with durable states:

```text
Absent
Provisional { provisioning_id, profile_id, key_ref, protection_level }
Expected    { profile_id, key_ref, protection_level }
Locked      { profile_id, key_ref, reason }
Deleting    { reset_id, profile_id, key_ref }
```

All transitions occur under an exclusive platform lifecycle lock with exact-state
CAS.

Create: atomically create a non-exportable key plus a `Provisional` registry
entry, with random never-reused aliases and key references; wrap the DEK using
`state-wrap/v1`, profile ID and key reference; write generation 1; reopen and
fully authenticate, parse and validate using the provisional handle; CAS
`Provisional -> Expected`; and only then expose identity, registration or prekey
material.

Recovery: provisional plus authentic generation 1 promotes; provisional plus
absent database is `ProvisioningInterrupted` with no automatic deletion;
provisional plus a present but unauthentic or mismatched database locks;
expected plus a missing, corrupt or unauthentic database or key locks and never
creates a replacement; a temporarily locked platform discards the DEK and live
crypto and returns a retryable locked state without changing registry, key or
database.

Delete or reset: require explicit destructive-reset authorization; close and
poison live profile handles; CAS `Expected`/`Locked -> Deleting` with a fresh
reset ID; delete the exact platform key first; delete the exact database and
allowed companions and durably sync the directory; remove the registry record.
Any uncertain step leaves `Deleting` and resumes idempotently, and no
replacement profile may be created first.

A provisional key may be abandoned only with its exact provisioning token, the
exclusive lock, state still `Provisional`, and explicit confirmation. No
age-based or "database missing" automatic cleanup is permitted in Phase 2.

## Remaining blockers before Phase 2 can complete

There is no fifth architecture decision, but all of the following must exist:

- the reviewed `Account::contains_one_time_key` API in pinned `vodozemac`;
- a strict `ClientPayloadV2` adding epoch, sequence, receipt and control
  variants, with strict decoding;
- removal of the raw public mutation and store-commit bypasses;
- the lifecycle manager and the private-store boundary.

## Related open item

The dangling-symlink escape in `reject_anomalous_wal` — where the guard tests a
link name while SQLite uses the target name — is deferred to the
`PrivateStoreDir` boundary in section 1 rather than patched separately, since
that boundary rejects symlinks outright. Measured behavior of the escape today
is recorded in `dangling_symlink_escapes_the_guard_but_cannot_replay`.
