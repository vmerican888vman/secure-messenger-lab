# Encrypted client persistence and crash-recovery spike

> **Status: INITIAL RETURN ITEMS RECONCILED; AWAITING TWO DELTA PASSES.** Kimi and Fable independently
> reviewed exact head `3f9c186c8f1aa34e5a03f45ef3621ac75a5b591e` and both returned `RETURN`.
> This revision reconciles their blocking items, but it remains a design and acceptance contract—not
> authorization to implement or ship. Implementation stays blocked until both reviewers pass this
> exact amended head. The repository remains an unaudited disposable lab.

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
| Bootstrap and registration outboxes | Retain the pending pre-key bundle plus an immutable mailbox-registration intent and its current signed request until exposure/reconciliation is durably resolved. |
| Durable inbound records | One logical record per accepted message, including the locally encrypted body until product code consumes it. |
| Inbound deduplication records | Prevent the same accepted message from creating another logical record after restart. |
| ACK intents/outbox | Bind queue ID, message ID, packet digest, message expiry, and the currently signed ACK request. |
| Send outbox | Retains the exact already-encrypted, already-signed enqueue request for byte-identical retry or a durable body-free `DeliveryUnknown` outcome awaiting application consumption. |
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
- Do not derive a nonce only from `(DEK, generation)`. This design explicitly permits replay of an old
  authentic generation; a divergent write after that replay would otherwise repeat a nonce under the
  same DEK. A fresh random nonce is required even when a generation number has appeared before.
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
public identity does not match the restored Account is invalid. A current registration request must
exactly match its immutable intent's queue ID and three public keys, and its signature must verify
under that intent's management key; an out-of-window timestamp is allowed only so same-intent renewal
can recover it. Collections and body lengths are bounded before allocation.

Every secret-bearing state, pickle, capability/owner, DEK/wrap intermediary, and outbox type prohibits
derived `Debug`. Its manual redacted representation exposes only a fixed type name and non-secret
state/length data. Storage and decode errors are coarse and never include serialized values. The
artifact gate explicitly formats every such type and error path with independent canaries.

### Bounded capacity and backpressure

Initial bounds are: 64 KiB per text body, 96 KiB per serialized encrypted packet, 32 pending inbound
records, 32 send-outbox records (pending requests and unconsumed terminal outcomes combined), 32 ACK
intents, 4,096 body-free deduplication records, and 8 MiB for the complete ciphertext including the
16-byte AEAD tag.

Before candidate Olm mutation, the client checks every count bound and every caller-known body/packet
length. It also uses checked arithmetic for a conservative reservation of the new bounded record and
fixed serialization overhead. This design does not invent an unverified static bound for
vodozemac Account/Session pickle growth. After Olm runs only on a disposable clone, the client
serializes the complete candidate and enforces the exact 8 MiB sealed-ciphertext bound before seal,
write, authoritative install, relay mutation, or application delivery. Post-Olm body/total-size
refusal may therefore discard a mutated clone, but the authoritative Account/Session pickles remain
byte-identical and the relay envelope remains fetchable. Pending work is never evicted.

A deduplication record with no pending body/ACK reference becomes eligible by exactly one of two
paths: (a) at least seven days after observed `Deleted`/`AlreadyDeleted` and after message expiry, or
(b) when ACK became terminal solely because message retention expired, at least seven days after that
signed message expiry. The second path is safe only because an expired envelope is rejected before
decrypt. While no record is eligible, new inbound processing blocks before decrypt rather than
weakening replay protection. Changing any bound, reservation, safety margin, or eviction rule is an
explicit denial-of-service/storage review.

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
   detectable and recorded as `software_backed`; it must never be labelled hardware-backed. Unknown,
   indeterminate, contradictory, unavailable, or inspection-error results use this lowest-claim policy
   bucket without asserting that the implementation proved the key is software-backed.
3. If the platform secure store is unavailable, the real app fails closed. There is no automatic
   plaintext key file, constant key, device-ID-derived key, PIN-derived key, or debug fallback.
4. A software protector exists only for deterministic desktop tests and must require an explicit test
   constructor that production builds cannot select.
5. Missing or invalid key material locks the profile. The only fallback is an explicit destructive
   identity reset confirmed by the user; the app must not silently create a new account.
6. Keys and the database are device-local and excluded from cloud/transfer backup until recovery and
   multi-device semantics are separately designed.
7. Provisioning and orphan cleanup share an exclusive lifecycle lock. Automatic cleanup may delete
   only a provisional key proven to have no expected platform binding and no authenticated database
   reference. If an expected binding exists without a matching authentic database, the profile locks
   and requires explicit destructive reset; absence of a database row is never sufficient proof that
   a key is orphaned.

The first physical-device implementation target is Android. It must report whether Android Keystore
places the wrapping key in StrongBox, a trusted execution environment, or software. iOS Keychain /
Secure Enclave specifics require their own reviewed adapter; this document does not pretend the two
platforms expose identical symmetric-key guarantees. Only explicit StrongBox and trusted-environment
results may make those respective claims. Android `SECURITY_LEVEL_UNKNOWN_SECURE`, software, missing
metadata, API incompatibility, inspection failure, or contradictory evidence all use the lowest-claim
policy bucket and never upgrade UI, logs, telemetry, or acceptance evidence.

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

`crypto_suite = 1` means XChaCha20-Poly1305 with the AAD contract in this document. The core does not
assume every platform wrap primitive accepts associated data. The adapter binds `state-wrap/v1`,
`profile_id`, and `key_ref` either as native authenticated wrap data or inside a versioned wrapped
plaintext structure whose exact fields are verified before the DEK is released. The state AAD
independently binds `profile_id`, `key_ref`, and `SHA-256(wrapped_dek)` and remains the authoritative
cross-file substitution check. A copied database therefore does not become usable merely by changing
a key alias.

Startup checks the exact application ID, version, table shape, `STRICT` flag, constraints, and
integrity before reading the row. It sets `trusted_schema=OFF`; no application-defined SQL functions,
loadable extensions, triggers, views, or additional schema objects are allowed. A future schema
change increments `user_version` and supplies a separately reviewed exact migration.

Production startup uses normal SQLite recovery. A hot rollback journal may be applied before schema
validation so a valid commit interrupted by process death remains recoverable; the application itself
performs no migration, purge, or state write until the recovered database passes validation. Hostile
negative-fixture sources and companion files are preserved byte-for-byte: inspection uses a read-only
immutable connection, and the startup attempt runs only against a disposable copy. A separate valid
exact-schema hot-journal test proves normal recovery rather than pretending `immutable=1` models it.

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

Mailbox registration uses the same durable-before-exposure rule. The encrypted state separately
persists (1) an immutable intent containing the queue ID and all three public keys tied to the durable
owner capabilities and (2) the exact currently signed `MailboxRegistration`.

While the relay's exact time predicate holds
(`now < valid_until <= saturating_add(now, 300 seconds)`), retry the current request byte-for-byte.
The relay result is explicitly `true` for a new mailbox and `false`
only after it compares the stored send, receive, and management public keys with the request and finds
an exact match; either result completes the same intent after a durable local commit.
`MailboxConflict` is fail-closed and never replaces owner keys.

If the intent remains unresolved only because its request falls outside that predicate, construct a
replacement over the same queue ID and same three public keys with a fresh random nonce, a fresh
`valid_until` within the relay's five-minute window, and a fresh management-key signature. Atomically
replace only the current request before transmitting it. No identity, capability, or queue ID is
regenerated. A crash during replacement reveals the complete old invalid-time request or complete new
request; restart renews again if needed. An invalid-time request is never transmitted.

A crash after platform-key creation but before generation 1 may leave a provisional key, never a
usable half-profile. A verified peer binding or received send capability becomes usable only after it
is committed to the encrypted profile.

An expired pending pre-key bundle is never transferred. Renewal creates a fresh bundle on a cloned
Account and atomically commits that candidate Account plus the replacement pending-bundle record
before exposure. The abandoned published-but-unshared one-time key is never advertised or reused in a
new bundle. Pinned `vodozemac` does not refuse generation at its 5,000-key private-store limit; it
silently evicts the oldest key on the candidate and reports it in `OneTimeKeyGenerationResult.removed`.
Renewal therefore requires exactly one created key and `removed.is_empty()` immediately on the cloned
Account. Any removal discards the candidate, persists/exposes nothing, and fails closed without
changing the authoritative Account or pending bundle.

## Outbound state machine

```text
ready
  -> encrypt on a cloned Session
  -> build the exact signed SendRequest
  -> atomically commit candidate Session + SendRequest outbox
  -> retry that same request until Stored, Duplicate, or terminal expiry
  -> atomically record confirmed completion or a durable DeliveryUnknown outcome
```

- Before the local commit, no relay request and no success result may escape.
- After the local commit, a crash/retry uses the byte-identical packet, message ID, expiry, and
  signature. It never re-encrypts the body.
- `Stored` and `Duplicate` are success for the retained request. `MessageConflict` is a fail-closed
  integrity error.
- If message retention expires before `Stored` or `Duplicate` is durably observed, atomically replace
  the pending request with body-free
  `DeliveryUnknown { message_id, packet_digest, expires_at }`. This application-observable outcome
  means storage was not confirmed before expiry; it does **not** claim the relay never stored or
  delivered the packet. It survives restart and is removed only after explicit durable application
  consumption. It counts against the send-outbox bound, never rolls the ratchet backward,
  re-encrypts the body, or reuses its message key. Any user-requested resend is a new logical message,
  not a retry of this one.

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

1. Let SQLite perform any legitimate rollback-journal recovery, without an application migration,
   purge, or state write.
2. Validate the exact recovered local schema and supported schema version.
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
| After platform key creation, before generation 1 | No profile opens; provisional key/binding remain locked and are never auto-deleted merely because the database is absent. |
| After generation 1, before identity/registration exposure | Complete profile opens; no external request was emitted. |
| During provisional-key cleanup | Lifecycle lock serializes cleanup; no key named by an expected or authenticated binding is deleted. |
| After registration local commit, before relay call | Exact unexpired request and immutable intent remain pending; no relay request was emitted. |
| After registration relay commit, before response, while valid | Byte-identical retry returns the matching-key `false` result; exactly one mailbox exists with unchanged keys. |
| After registration relay commit, response loss, restart after `valid_until` | Expired request is not sent; a committed fresh-nonce request over the same intent reconciles to one matching mailbox. |
| During expired-registration replacement | Complete old or renewed request only; no half-request, new owner, or relay emission. |
| After OTK/bundle creation, before local commit | Prior Account; bundle was not exposed. |
| After OTK/bundle commit, before transfer | Same pending bundle and published-key state resume together. |
| During expired pending-bundle replacement | Complete old or new Account/bundle pair; no expired or uncommitted bundle is exposed. |
| OTK renewal candidate reports a removed key | Candidate is discarded; authoritative Account/pending bundle are byte-identical and no bundle is exposed. |
| After outbound Session creation, before local commit | No authoritative Session; first seal remains forbidden. |
| After outbound encrypt, before local commit | Old ratchet; no outbox; no relay request emitted. |
| After outbound commit, before relay call | Advanced ratchet plus exact retryable send request. |
| After relay commit, before response | Exact retry returns `Duplicate`; one relay row. |
| During send-expiry outcome commit | Pending exact request or complete `DeliveryUnknown` only; both preserve the advanced ratchet and never claim non-delivery. |
| After valid initial decrypt, before local commit | Old Account/OTK state; no inbound/ACK record; same pre-key packet succeeds. |
| After valid established decrypt, before local commit | Old Session; no inbound/ACK record; same packet succeeds. |
| After inbound commit, before application read | One recoverable logical inbound record and ACK intent. |
| After application read, before ACK call | Same record, no duplicate logical record, ACK still pending. |
| After ACK relay commit, before response | ACK retry returns `AlreadyDeleted`; no redisplay or ciphertext resurrection. |
| During envelope write/transaction commit | Complete generation N or N+1 only; never a mixed snapshot. |
| During outbox completion write | Pending or complete entry only; both states are safely retryable. |
| At any count/size refusal boundary | Complete pre-refusal snapshot, byte-identical authoritative pickles, all earlier work resumable, and no new relay-mutating request or delivery. |
| After refusal, then after one valid drain | Refusal survives restart; the documented drain frees only eligible state and the formerly refused operation then succeeds. |

### Required bounded-storage oracle

For the 64 KiB body, 96 KiB packet, 32 pending-inbound, 32 combined send-outbox, 32 ACK,
4,096 deduplication, and 8 MiB ciphertext bounds, construct/fill the exact boundary and attempt one
byte or record more. The 8 MiB test is an envelope-codec boundary test as well as an operational
reservation test: exact-cap input may proceed to authentication/bounded parsing, while cap-plus-one is
rejected after querying/streaming the BLOB length and before fully materializing or authenticating it.
It does not invent product padding merely to make a valid logical state consume the whole cap.

Every refusal asserts a specific backpressure result, unchanged generation and byte-identical
authoritative Account/Session pickles, no local write, no enqueue/ACK/registration/bundle request, no
logical delivery, and every earlier pending record still present and completable. Count and
caller-known length failures occur before candidate Olm mutation. Body length, exact serialized size,
or pickle growth knowable only after Olm may mutate only a disposable clone, which is discarded before
any authoritative or external effect.

At each refusal class, force-kill at the injected refusal failpoint before the error returns. Reopen
must yield the complete pre-refusal snapshot with all outboxes resumable. The full-dedup case must
refuse before decrypt while the relay envelope remains fetchable; no record may be pruned while it has
a pending reference or before either eligibility path's safety margin.

Then drain exactly one item through each permitted transition: application consumption plus ACK
completion for a pending inbound body, durable `Stored`/`Duplicate` observation or explicit
consumption of `DeliveryUnknown` for a send slot, durable `Deleted`/`AlreadyDeleted` or terminal
message expiry for an ACK, and the applicable seven-day rule for deduplication. The formerly refused
operation must then succeed without losing older pending work or weakening ratchet/replay semantics.

## Acceptance gate

The spike is a PASS only if all of the following are executable and green:

- Clean restart and every forced interruption above preserve the next valid initial and established
  message path without OTK consumption, ratchet rollback, plaintext fallback, duplicate logical
  delivery, or lost retry material.
- Send-response and ACK-response loss retry byte-identical signed requests and produce `Duplicate`
  and `AlreadyDeleted`, respectively.
- Registration response loss retries byte-identically while valid. After five-minute expiry, a
  durably committed fresh-nonce request over the immutable owner intent reconciles to exactly one
  mailbox with unchanged keys; `true` and matching-key `false` are the only success results.
- Registration state with an intent/request queue or key mismatch, or a request signature that does
  not verify under the intent management key, fails load before renewal or transmission.
- Every count and size limit passes the exact-boundary/one-over, forced-death, no-eviction, and
  drain/resume oracle above. Full ineligible deduplication blocks before decrypt and leaves the relay
  envelope fetchable.
- OTK renewal at the dependency's private-key limit observes a nonempty `removed`, discards the cloned
  Account, and persists/exposes neither the removal nor a replacement bundle.
- Send expiry without confirmed storage yields a durable restart-visible `DeliveryUnknown`, never a
  sent/not-sent claim, ratchet rollback, automatic re-encryption, or message-key reuse.
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
  before a write. After opening an old authentic snapshot and committing divergent state, its fresh
  random nonce differs from the prior occurrence of that generation number.
- The test-only software key protector cannot be selected by a production build, and physical Android
  tests report the actual Keystore protection level without upgrading unknown/indeterminate evidence.
- Provisioning/cleanup failpoints prove no key named by an expected or authenticated binding is
  deleted; a missing/corrupt database locks rather than triggering automatic key cleanup.
- Complete relay and local schema-shape negative fixtures fail with no application migration or state
  write. Original fixture databases and companion files remain byte-identical; valid hot-journal
  recovery is proven separately on a disposable working copy.
- Explicit `Debug`, display/error, panic, and diagnostic formatting of every secret-bearing wrapper
  remains redacted under the same independent canary scan.
- `cargo test --locked --all-targets`, strict Clippy, formatting, dependency advisory monitoring, and
  the existing 22 Phase 0 tests remain green.

Any mandatory failure is a **NO-GO**. Passing this spike authorizes the next identity/QR design gate;
it does not authorize a public network relay or a claim that the app is production-secure.

## Initial review reconciliation

Kimi and Fable independently reviewed `3f9c186c8f1aa34e5a03f45ef3621ac75a5b591e`; both returned
`RETURN`. This revision addresses their union:

1. registration now persists immutable intent separately from its current request and renews an
   expired five-minute signature before transmission;
2. every count/size/backpressure claim now has an exact-boundary, one-over, forced-death,
   no-eviction, and drain/resume oracle; and
3. OTK renewal reflects pinned `vodozemac` behavior by rejecting any candidate generation that
   reports an eviction in `removed`.

It also adopts the nonblocking hardening for lowest-claim Android protection reporting, explicit
platform-wrap binding, lifecycle-locked orphan cleanup, immutable hostile-fixture sources, durable
delivery-unknown outcomes, terminal-expiry dedup reclamation, and structural log/debug redaction.
Generation-derived nonces are intentionally **not** adopted because authentic snapshot rollback can
repeat a generation under the same DEK; the fresh-random-nonce continuation test covers that case.

These amendments still do not authorize implementation. Both independent reviewers must return
`PASS` on the same exact amended head.

## Decisions required from delta review

Reviewers should return `PASS` or concrete `RETURN` items on:

1. the outer AEAD and prohibition on legacy pickle encryption as the storage envelope;
2. the state/key hierarchy and no-plaintext-fallback policy;
3. inbound, outbound, ACK, and application-delivery ordering;
4. the encrypted pending-body trade-off;
5. the explicit rollback limitation;
6. the platform protector boundary and software fallback posture;
7. the complete schema-manifest requirement; and
8. whether the interruption matrix can falsify every durability claim made here.
