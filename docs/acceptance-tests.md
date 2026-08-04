# Acceptance tests

All checks below route through the real prototype client and relay APIs. A passing unit test is not a
release claim.

## Automated now

| Property | Test oracle |
|---|---|
| Relay sees no plaintext | Distinctive plaintext canary absent from current SQLite bytes and relay events before/after delivery |
| Relay receives no private capabilities | Serialized private send/receive/manage keypairs absent from relay database |
| Contact key substitution | Modified Curve25519 identity/one-time key fails its pinned Ed25519 bundle signature |
| Verified pre-key expiry | A bundle verified before expiry cannot create a session after expiry |
| Pre-decrypt envelope binding | Changed ciphertext or outer message ID fails sender-capability verification before Olm state mutation |
| Verified envelope expiry | An envelope verified before expiry cannot mutate an initial or established session after expiry |
| Initial state staging | Binding-invalid first plaintext is rejected without consuming the authoritative OTK; the next valid pre-key message succeeds |
| Ratchet state staging | Binding-invalid established plaintext is repeatably rejected without advancing the authoritative ratchet; the next valid message succeeds |
| Delete only after ACK | Fetch leaves one row; recipient-bound valid ACK deletes it |
| Current-file deletion | Exact queued packet bytes present before ACK and absent after ACK |
| ACK binding | ACK signed for message 2 with message 1 digest cannot delete either item |
| ACK request/response loss | Retained ACK retry deletes if the request was lost and returns `AlreadyDeleted` if the response was lost; retry is bounded by request and message-retention expiry |
| Send retry | Identical signed retry stores one logical row and returns duplicate |
| Message-ID conflict | Different encrypted packet under same ID is rejected |
| No plaintext fallback | Missing Olm session returns `MissingSession`; no relay request exists |
| Tamper rejection | Modified encrypted packet cannot establish/decrypt a session |
| Wrong recipient | Account without the addressed one-time key cannot decrypt |
| Capability separation | Retargeted requests signed by unrelated send/receive/manage keys fail |
| Envelope mailbox/expiry binding | Cross-mailbox presentation and outer-expiry tampering fail before decrypt |
| Request replay | Reusing an authenticated fetch nonce is rejected |
| Request time bounds | Expired, equality-boundary, and over-five-minute register/fetch/ACK/delete requests fail closed |
| Message time bounds | Already-expired and over-seven-day message retention requests fail closed |
| Retention TTL | Expired ciphertext is purged |
| Idle restart expiry | File-backed reopen runs a global sweep without recipient fetch |
| Mailbox resurrection | Captured registration and send requests fail after management deletion |
| Concurrent send | Two file-backed writers resolve an identical request to stored + duplicate, one row total |
| Concurrent conflict | Two file-backed writers using one ID for different packets resolve to stored + conflict, one row total |
| Legacy schema upgrade | Unverifiable queued packets are securely discarded while tombstones and retired queues survive |
| Schema downgrade resistance | Unknown future versions and a malformed current unsigned schema fail closed |
| Minimal schema | No user/contact/conversation/plaintext/phone/email/username schema terms |

## Required before adding a network relay

- Capture complete HTTP/TLS request and response bodies, reverse-proxy/access logs, traces, metrics,
  crash reports, database files, journals, backups, and process dumps with independent canaries.
- Kill the relay between receipt, commit, response, fetch, ACK verification, deletion, and response;
  prove no pre-ACK loss and no post-commit resurrection.
- Test request-size and queue-count limits, malformed encodings, timing differences for known/unknown
  mailboxes, enumeration, flooding, rate limits, and expired signatures under clock skew.
- Persist ACKs before transmission and test request-loss, response-loss, process-death, and expiry
  recovery; define retry semantics for replay-protected fetch/manage requests whose responses are lost.
- Verify that no endpoint, proxy, WAF, telemetry SDK, notification system, or support bundle records
  plaintext, keys, capabilities, full identifiers, or ciphertext bodies.

## Required on physical Android hardware

- Encrypted account/session persistence survives clean restart and forced process death without ratchet
  rollback or plaintext fallback.
- Every session mutation is atomically stored before UI success or ACK.
- Hardware-backed wrapping is used where supported and the fallback policy is explicit.
- QR verification binds stable identity, per-device key, and peer-scoped Olm key material.
- Notification payloads and crash telemetry contain no content or key material.

Any mandatory failure is a NO-GO. “Deleted” must always name the storage surfaces and timing tested; it
can never promise that a recipient or malicious relay did not make a copy.

## Independently passed encrypted-persistence contract — implementation in progress

The next design gate is specified in [`persistence-spike-design.md`](persistence-spike-design.md).
The implemented foundation already covers the exact relay/local schema manifests, the outer
XChaCha20-Poly1305 envelope, expected profile/key substitution defense, exact-row CAS, 8 MiB boundary,
fresh-nonce/rollback limitation, coarse redaction, and real process-abort recovery for creation and
opaque-state commits. It deliberately stores opaque serialized bytes: the semantic Account, Session,
capability, deduplication, registration, send, inbound, and ACK state machines below remain open.

No end-to-end item below is currently claimed as passing:

- restore the same Account, Session, peer/conversation binding, private capabilities, deduplication
  records, and outboxes after clean restart;
- commit an outbound ratchet advance and its exact signed send request before any relay call or
  caller-visible success;
- commit an inbound ratchet/OTK advance, one logical inbound record, and renewable ACK intent before
  application delivery or ACK transmission;
- persist immutable mailbox-registration intent separately from its current signed request; retry the
  exact request while valid, then atomically re-sign with a fresh nonce after the five-minute window
  without changing the queue or owner keys; reject intent/request field or signature mismatches before
  renewal or transmission;
- force process death at every pre/post-commit, send-response, delivery, and ACK-response boundary and
  observe only a complete old or new state;
- fill the 64 KiB body, 96 KiB packet, 32 inbound, 32 combined send-outbox, 32 ACK, 4,096 dedup, and
  8 MiB ciphertext bounds; at each exact/one-over boundary prove refusal before authoritative Olm or
  relay mutation, no pending eviction, forced-death recovery, and success after one valid drain;
- keep a full ineligible deduplication set blocking before decrypt, then prove both observed-ACK and
  terminal-message-expiry ageing paths reclaim only unreferenced records after seven days;
- reject/discard an OTK-renewal candidate whenever pinned `vodozemac` reports any evicted key in
  `OneTimeKeyGenerationResult.removed`, leaving the authoritative Account and bundle unchanged;
- expose send expiry without confirmed storage as a durable body-free `DeliveryUnknown` outcome—not
  proof of non-delivery—and never automatically re-encrypt or reuse its message key;
- fail closed on missing keys, authentication failure, corruption, cross-profile swap, version
  downgrade, malformed/oversized state, write failure, or unsupported migration;
- prove database, journal, temporary files, logs, and diagnostics contain no message canary, raw Olm
  pickle, private capability material, or secret-bearing `Debug`/error rendering;
- prove Android unknown/indeterminate protection evidence uses the lowest claim, platform-wrapped DEKs
  bind the expected profile/key reference, and cleanup never deletes an expected/authenticated key;
- preserve hostile schema-fixture source and companion files byte-for-byte while separately proving
  valid normal SQLite hot-journal recovery on disposable working copies; and
- validate complete relay and local SQLite schema manifests rather than trusting a version number or
  one column name.

The initial independent Kimi and Fable reviews both returned `RETURN` on
`3f9c186c8f1aa34e5a03f45ef3621ac75a5b591e`. Their blocking items were reconciled, and both reviewers
then returned `PASS` on exact amended head `04cd037f21cb37604b0a7d7cc5cfd9e86a04d70a`.
This checklist is therefore authoritative for the disposable persistence spike, but it is not a
production-app or public-security gate.
