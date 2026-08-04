# Encrypted client persistence and crash-recovery spike

> **Status: PROPOSED FOR TWO INDEPENDENT REVIEWS.** This is a design and acceptance contract, not
> authorization to implement or ship it. Implementation remains blocked until Kimi and Fable return
> independent opinions and every blocking return item is reconciled. The repository remains an
> unaudited disposable lab.

## Question this spike must answer

Can one peer-scoped client survive restart and forced process death without leaking its local secret
state, rolling its Olm ratchet backward, losing an accepted inbound message, acknowledging before a
durable state commit, or encrypting a second packet after an uncertain send?

The answer must come from executable interruption tests, not from a successful clean restart.

## Scope

This spike keeps the Phase 0 assumptions: one device, one directly verified peer, text only, the
existing in-process relay API, and no recovery. It adds only:

- encrypted, versioned persistence of endpoint state;
- atomic inbound and outbound ratchet commits;
- durable send and ACK outboxes;
- a platform key-protection boundary with an explicit fallback policy; and
- real restart and forced-process-death tests.

It does **not** add a network server, mobile UI, QR ceremony, one-time-key service, notifications,
multi-device support, attachments, groups, calls, backup, or production migration. The current direct
verified-contact exchange remains an assumption, not a solved feature.

## Threat boundary and claims

The storage design protects confidentiality and detects arbitrary modification of the client database
if an attacker does not control the running, unlocked endpoint or its platform key service. The
database must reveal no message body, Olm pickle, private mailbox capability, or private identity key.
AEAD does not distinguish the newest snapshot from a byte-for-byte replay of an older, previously
valid snapshot whose external profile/key binding is still current.

This spike does not claim protection from:

- a compromised process, rooted/unlocked device, debugger, memory dump, malicious keyboard,
  screenshot, or notification leak;
- an attacker who can use the platform key while the device is unlocked;
- replay or rollback of any complete previously valid database snapshot, with or without rolling back
  its platform metadata;
- cloud/device backups not yet governed by a platform implementation; or
- forensic erasure of old encrypted pages, journals, snapshots, or flash blocks.

`generation` and compare-and-swap writes prevent concurrent or accidental stale writers during normal
operation. They do not create a hardware monotonic counter and must never be described as
cryptographic rollback protection. A test must demonstrate that an old authentic database snapshot
can still open, so future documentation cannot accidentally upgrade this limitation into a guarantee.

## State that must move atomically

The authenticated plaintext inside one encrypted state snapshot contains:

| State | Why it is inseparable |
|---|---|
| `AccountPickle` | Holds the stable signing/DH keys, unpublished/published one-time keys, and OTK consumption state. |
| Optional `SessionPickle` | Holds sending and receiving ratchets; reconstructing it from public metadata is impossible. |
| Conversation and pinned-peer binding | Prevents restoring valid crypto state into the wrong logical peer/profile. |
| Private mailbox capabilities | Required to send, fetch, renew ACKs, and manage the mailbox after restart. They never go to the relay. |
| Bootstrap and registration outboxes | Retain the exact pending pre-key bundle and signed mailbox-registration request until exposure/reconciliation is durably resolved. |
| Durable inbound records | One logical record per accepted message, including the locally encrypted body until product code consumes it. |
| Inbound deduplication records | Prevent the same accepted message from creating another logical record after restart. |
| ACK intents/outbox | Bind queue ID, message ID, packet digest, message expiry, and the currently signed ACK request. |
| Send outbox | Retains the exact already-encrypted, already-signed enqueue request for byte-identical retry. |
| Format, protocol, dependency, and generation metadata | Makes downgrade, cross-profile use, and unsupported migrations fail closed. |

Persisting an accepted body inside this outer encrypted snapshot is a deliberate endpoint trade-off.
Without it, a crash after ratchet commit but before application delivery either loses the message or
requires retaining rollback-capable old ratchet state. This is **local encrypted pending delivery**,
not relay plaintext or a promise of permanent conversation history. A later product decision must set
history and deletion policy. The spike may remove the body after consumption while retaining a bounded
deduplication record.

## Storage envelope

### Proposed construction

- Serialize a versioned `ClientStateV1` containing the complete logical snapshot above.
- Encrypt the serialized bytes with `XChaCha20-Poly1305` using one random 256-bit profile
  data-encryption key (DEK) and a fresh 192-bit nonce for every committed generation. Rotating the DEK
  is a separate key-migration event and is outside this spike.
- At implementation time, pin the already-resolved `chacha20poly1305` version exactly and add it as a
  direct dependency. Any primitive/version change is a storage-format review and migration event.
- Generate the DEK and every nonce with the operating-system CSPRNG. RNG failure aborts the write.
- Zeroize temporary serialized plaintext and DEK buffers where the language/library permits. Do not
  claim complete memory erasure; upstream pickle wrappers clone secret-bearing state.

The exact, canonical additional authenticated data (AAD) binds:

```text
domain = "secure-messenger-lab/client-state"
envelope_version
crypto_suite
profile_id
generation
key_ref
SHA-256(wrapped_dek)
protocol_domain
vodozemac_version
state_schema_version
```

The outer database stores only the non-secret header, nonce, wrapped-key reference, and ciphertext.
Header values are authenticated through AAD. The decoder rejects unknown versions/suites, oversized
records, duplicate/missing fields, bad authentication, and trailing data before constructing an
`Account` or `Session`.

`ClientStateV1` has one account pickle, zero or one session pickle, one profile/conversation/peer
binding, one own-mailbox capability set, one peer send capability, bootstrap and registration outbox
records, and maps keyed by message ID for inbound records, send-outbox records, and ACK intents.
Duplicate keys, an outbox entry whose embedded ID disagrees with its map key, an ACK intent without an
accepted inbound record, a pending bundle that does not match the restored Account, or state whose
public identity does not match the restored Account is invalid. Collections and body lengths are
bounded before allocation.

Initial bounds are: 64 KiB per text body, 96 KiB per serialized encrypted packet, 32 pending inbound
records, 32 send-outbox records, 32 ACK intents, 4,096 body-free deduplication records, and 8 MiB for
the complete encrypted state. If adding a record would exceed a count/size bound, the client applies
backpressure and fails **before** Olm mutation or relay emission; it never evicts pending work. A
deduplication record is eligible for removal only when no pending body/ACK references it and at least
seven days have passed after observed `Deleted`/`AlreadyDeleted` (and after message expiry). If no
record is eligible, new inbound processing remains blocked rather than silently weakening replay
protection. Changing any bound or eviction rule is an explicit denial-of-service/storage review.

### Do not use vodozemac pickle encryption as this envelope

`AccountPickle::encrypt` and `SessionPickle::encrypt` use the libolm-compatible pickle construction:
JSON, deterministically derived AES-CBC IV, and an eight-byte truncated MAC. Reusing a pickle key
therefore reuses the IV. Those helpers are prohibited as the sole storage protection and add no useful
layer inside the proposed randomized AEAD envelope. The serde pickle forms are serialized only inside
the outer envelope.

## Platform key boundary

The Rust core depends on a narrow `StateKeyProtector` boundary. It may ask the platform to create a
profile key, wrap/unwrap the DEK, report the actual protection level, and delete the key. The core
never receives or logs the platform wrapping key.

The platform secure store also retains the expected `(profile_id, key_ref)` binding independently of
the SQLite file. Startup obtains that expected binding first and compares it with the authenticated
database header; it never selects a profile merely because an untrusted database row names one. This
is what makes whole-row or cross-profile substitution detectable within the stated threat model.

Policy:

1. Use a non-exportable hardware-backed key when the platform actually provides one.
2. A platform secure-store key that is software-backed may be accepted only when its status is
   detectable and recorded as `software_backed`; it must never be labelled hardware-backed.
3. If the platform secure store is unavailable, the real app fails closed. There is no automatic
   plaintext key file, constant key, device-ID-derived key, PIN-derived key, or debug fallback.
4. A software protector exists only for deterministic desktop tests and must require an explicit test
   constructor that production builds cannot select.
5. Missing or invalid key material locks the profile. The only fallback is an explicit destructive
   identity reset confirmed by the user; the app must not silently create a new account.
6. Keys and the database are device-local and excluded from cloud/transfer backup until recovery and
   multi-device semantics are separately designed.
7. A crash during first-time key/database creation may leave an unreachable orphan platform key, but
   must never leave a database record that falls back to another key. Orphan cleanup is allowed only
   after proving no authenticated profile binding references the key.

The first physical-device implementation target is Android. It must report whether Android Keystore
places the wrapping key in StrongBox, a trusted execution environment, or software. iOS Keychain /
Secure Enclave specifics require their own reviewed adapter; this document does not pretend the two
platforms expose identical symmetric-key guarantees.

## Local transaction model

Use the bundled SQLite only as an atomic container for one current ciphertext snapshot. Store no
secret or message field in a separate plaintext column. Use one writer, `BEGIN IMMEDIATE`, foreign
keys on, `synchronous=FULL`, `secure_delete=ON`, and rollback-journal mode for this spike.

The proposed first schema is deliberately one row and one authoritative DDL string:

```sql
PRAGMA application_id = 0x534D534C; -- "SMSL"
PRAGMA user_version = 1;

CREATE TABLE client_state (
    slot                 INTEGER PRIMARY KEY NOT NULL CHECK(slot = 1),
    profile_id           BLOB NOT NULL CHECK(length(profile_id) = 16),
    generation           INTEGER NOT NULL CHECK(generation >= 1),
    envelope_version     INTEGER NOT NULL CHECK(envelope_version = 1),
    state_schema_version INTEGER NOT NULL CHECK(state_schema_version = 1),
    crypto_suite         INTEGER NOT NULL CHECK(crypto_suite = 1),
    key_ref              BLOB NOT NULL CHECK(length(key_ref) = 16),
    wrapped_dek          BLOB NOT NULL CHECK(length(wrapped_dek) BETWEEN 1 AND 8192),
    nonce                BLOB NOT NULL CHECK(length(nonce) = 24),
    ciphertext           BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 8388608)
) STRICT;
```

`crypto_suite = 1` means XChaCha20-Poly1305 with the AAD contract in this document. The platform wrap
operation separately authenticates the state domain, `profile_id`, and `key_ref`; the state AAD also
binds `key_ref` and a hash of `wrapped_dek`. A copied database therefore does not become usable merely
by changing a key alias.

Startup checks the exact application ID, version, table shape, `STRICT` flag, constraints, and
integrity before reading the row. It sets `trusted_schema=OFF`; no application-defined SQL functions,
loadable extensions, triggers, views, or additional schema objects are allowed. A future schema
change increments `user_version` and supplies a separately reviewed exact migration.

Every update performs a generation compare-and-swap:

```text
read and authenticate generation N
build the complete candidate state in memory
seal candidate as generation N+1 with a fresh nonce
BEGIN IMMEDIATE
UPDATE client_state SET ... generation=N+1 WHERE slot=1 AND generation=N
require exactly one changed row
COMMIT
only then install the candidate as authoritative in memory
```

A conflict, storage error, authentication failure, or uncertain commit fails closed and forces a
reopen/reconciliation. No caller-visible send success, delivery event, or ACK may occur from an
uncommitted candidate. A crash must reveal either the complete old snapshot or the complete new one,
never a mixture.

## Bootstrap state machine

Bootstrap mutations obey the same durable-before-exposure rule:

```text
platform creates expected profile/key binding + wrapped DEK
  -> create Account, conversation ID, and private mailbox capabilities in memory
  -> atomically insert encrypted generation 1
  -> only then expose public identity or a signed mailbox registration

durable Account
  -> generate OTK and signed short-lived pre-key bundle on a cloned Account
  -> mark the candidate keys published
  -> atomically commit candidate Account + exact pending bundle record
  -> only then transfer the bundle through the assumed verified channel

durable verified peer binding
  -> create outbound Session on a candidate
  -> atomically commit the Session
  -> only then permit the first seal
```

Mailbox registration uses the same outbox rule: persist the exact signed registration before the relay
call, then treat a duplicate registration response after response loss as completion only when all
registered public keys match the persisted owner. A crash after platform-key creation but before
generation 1 may leave an orphan key, never a usable half-profile. A verified peer binding or received
send capability becomes usable only after it is committed to the encrypted profile.

An expired pending pre-key bundle is never transferred. Renewal creates a fresh bundle on a cloned
Account and atomically commits that candidate Account plus the replacement pending-bundle record
before exposure. The abandoned published-but-unshared one-time key is never advertised or reused in a
new bundle. If the dependency's bounded one-time-key capacity prevents renewal, bootstrap fails closed
instead of exposing an expired bundle or silently replacing the Account.

## Outbound state machine

```text
ready
  -> encrypt on a cloned Session
  -> build the exact signed SendRequest
  -> atomically commit candidate Session + SendRequest outbox
  -> retry that same request until Stored, Duplicate, or terminal expiry
  -> atomically clear/finish the outbox entry
```

- Before the local commit, no relay request and no success result may escape.
- After the local commit, a crash/retry uses the byte-identical packet, message ID, expiry, and
  signature. It never re-encrypts the body.
- `Stored` and `Duplicate` are success for the retained request. `MessageConflict` is a fail-closed
  integrity error.
- If the message expires before storage is confirmed, mark that outbox entry terminally failed. Do
  not roll the ratchet backward or reuse its message key.

## Inbound and ACK state machine

```text
fetched + outer envelope verified
  -> decrypt on a cloned Account/Session
  -> validate conversation/message binding
  -> create one durable inbound record + ACK intent
  -> atomically commit candidate Account/Session + inbound record + ACK outbox
  -> expose the durable logical record to the application
  -> submit/retry ACK
  -> on Deleted or AlreadyDeleted, atomically mark ACK complete
```

- A crash before the local commit leaves the old account/session authoritative and the relay message
  fetchable. The same packet can be processed after restart.
- A crash after the commit finds the durable inbound record and ACK intent. It does not decrypt again
  or create a second logical message.
- “Exactly once” means one durable inbound record keyed by message ID. It does not claim exactly one
  UI callback or that a human saw a rendered screen; UI delivery is outside this spike.
- The ACK intent is a persistence-safe proof produced only by a successful bound decrypt. It lets the
  receiver capability renew a short-lived signed ACK after restart without recreating an
  `OpenedMessage` or rerunning Olm.
- A retained valid ACK retries unchanged. Request loss returns `Deleted`; response loss returns
  `AlreadyDeleted`. If only the ACK request expires while message retention remains valid, atomically
  replace it with a newly signed ACK from the same intent before sending. If message retention has
  also expired, mark the intent terminal without claiming that deletion was observed.
- No ACK may be sent before the candidate ratchet, inbound record, deduplication record, and ACK intent
  are durably committed together.

## Load and recovery rules

On startup:

1. Open the database without mutating it.
2. Validate the exact local schema and supported schema version.
3. Obtain/unwrap the DEK through `StateKeyProtector`.
4. Authenticate and parse the bounded state envelope.
5. Validate profile/conversation/peer bindings and required record completeness.
6. Restore `Account` and `Session` only after every check succeeds.
7. Resume send and ACK outboxes before accepting new work.

Any missing key, unsupported version, malformed pickle, AAD mismatch, tamper, partial record, invalid
state transition, or database integrity failure locks the profile and returns one coarse storage
error. It never silently empties replay state, generates a replacement identity, drops an outbox, or
falls back to plaintext.

## Relay schema-shape prerequisite

Before the persistence spike is considered complete, relay startup must stop treating
`PRAGMA user_version` plus one `sender_signature` column as proof of a valid current schema.

The implementation must compare the complete on-disk shape with a clean in-memory reference built
from the canonical DDL: allowed objects, `PRAGMA table_list` strictness, ordered
`PRAGMA table_xinfo`, index/primary-key shape, `PRAGMA foreign_key_list`, canonical table SQL for
`CHECK` constraints, `foreign_key_check`, and `integrity_check`. Version 2 accepts only the exact
current shape. Versions 0/1 accept only an exact documented legacy shape or a genuinely empty
database. Version/schema disagreement and all hybrid shapes fail closed without mutation.

This is robustness hardening for an adversary outside the current relay threat model, but it closes a
real fail-open parser boundary before that pattern is copied into local secret-state storage.

## Required interruption matrix

The implementation must use subprocess failpoints and actual forced termination, not only returned
errors. Each failpoint reopens the on-disk state and asserts the stated oracle.

| Forced interruption | Required state after restart |
|---|---|
| After platform key creation, before generation 1 | No profile opens; only an unreachable key may remain. |
| After generation 1, before identity/registration exposure | Complete profile opens; no external request was emitted. |
| After OTK/bundle creation, before local commit | Prior Account; bundle was not exposed. |
| After OTK/bundle commit, before transfer | Same pending bundle and published-key state resume together. |
| During expired pending-bundle replacement | Complete old or new Account/bundle pair; no expired or uncommitted bundle is exposed. |
| After registration relay commit, before response | Exact registration retry reconciles matching keys without replacing the owner. |
| After outbound Session creation, before local commit | No authoritative Session; first seal remains forbidden. |
| After outbound encrypt, before local commit | Old ratchet; no outbox; no relay request emitted. |
| After outbound commit, before relay call | Advanced ratchet plus exact retryable send request. |
| After relay commit, before response | Exact retry returns `Duplicate`; one relay row. |
| After valid initial decrypt, before local commit | Old Account/OTK state; no inbound/ACK record; same pre-key packet succeeds. |
| After valid established decrypt, before local commit | Old Session; no inbound/ACK record; same packet succeeds. |
| After inbound commit, before application read | One recoverable logical inbound record and ACK intent. |
| After application read, before ACK call | Same record, no duplicate logical record, ACK still pending. |
| After ACK relay commit, before response | ACK retry returns `AlreadyDeleted`; no redisplay or ciphertext resurrection. |
| During envelope write/transaction commit | Complete generation N or N+1 only; never a mixed snapshot. |
| During outbox completion write | Pending or complete entry only; both states are safely retryable. |

## Acceptance gate

The spike is a PASS only if all of the following are executable and green:

- Clean restart and every forced interruption above preserve the next valid initial and established
  message path without OTK consumption, ratchet rollback, plaintext fallback, duplicate logical
  delivery, or lost retry material.
- Send-response and ACK-response loss retry byte-identical signed requests and produce `Duplicate`
  and `AlreadyDeleted`, respectively.
- Tampered, wrong-conversation, expired, malformed, unsupported-version, swapped-profile, truncated,
  and oversized states fail closed before authoritative crypto state changes.
- A full same-device profile-A/profile-B database swap fails against the expected profile/key binding.
  Replaying an older authentic snapshot of the same profile is separately tested as an explicit,
  currently undetected rollback limitation rather than a passing security property.
- Failed writes leave the previously committed state usable and produce no send success, delivery
  event, or ACK.
- Database, journal, temporary files, logs, panic text, and diagnostics contain none of three distinct
  canaries: message plaintext, raw serialized Account/Session pickle bytes, or private capability
  material. Ciphertext and non-secret envelope metadata may remain.
- Every committed generation uses a unique nonce in the test corpus; an injected RNG failure aborts
  before a write.
- The test-only software key protector cannot be selected by a production build, and physical Android
  tests report the actual Keystore protection level without upgrading the claim.
- Complete relay and local schema-shape negative fixtures fail without mutating their files.
- `cargo test --locked --all-targets`, strict Clippy, formatting, dependency advisory monitoring, and
  the existing 22 Phase 0 tests remain green.

Any mandatory failure is a **NO-GO**. Passing this spike authorizes the next identity/QR design gate;
it does not authorize a public network relay or a claim that the app is production-secure.

## Decisions required from independent review

Reviewers should return `PASS` or concrete `RETURN` items on:

1. the outer AEAD and prohibition on legacy pickle encryption as the storage envelope;
2. the state/key hierarchy and no-plaintext-fallback policy;
3. inbound, outbound, ACK, and application-delivery ordering;
4. the encrypted pending-body trade-off;
5. the explicit rollback limitation;
6. the platform protector boundary and software fallback posture;
7. the complete schema-manifest requirement; and
8. whether the interruption matrix can falsify every durability claim made here.
