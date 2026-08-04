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
| Delete only after ACK | Fetch leaves one row; recipient-bound valid ACK deletes it |
| Current-file deletion | Exact queued packet bytes present before ACK and absent after ACK |
| ACK binding | ACK signed for message 2 with message 1 digest cannot delete either item |
| ACK replay | Repeated valid ACK is harmless and cannot delete another item |
| Send retry | Identical signed retry stores one logical row and returns duplicate |
| Message-ID conflict | Different encrypted packet under same ID is rejected |
| No plaintext fallback | Missing Olm session returns `MissingSession`; no relay request exists |
| Tamper rejection | Modified encrypted packet cannot establish/decrypt a session |
| Wrong recipient | Account without the addressed one-time key cannot decrypt |
| Capability separation | Retargeted requests signed by unrelated send/receive/manage keys fail |
| Request replay | Reusing an authenticated fetch nonce is rejected |
| Retention TTL | Expired ciphertext is purged |
| Idle restart expiry | File-backed reopen runs a global sweep without recipient fetch |
| Mailbox resurrection | Captured registration and send requests fail after management deletion |
| Concurrent send | Two file-backed writers resolve an identical request to stored + duplicate, one row total |
| Legacy schema upgrade | Unverifiable queued packets are securely discarded while tombstones and retired queues survive |
| Minimal schema | No user/contact/conversation/plaintext/phone/email/username schema terms |

## Required before adding a network relay

- Capture complete HTTP/TLS request and response bodies, reverse-proxy/access logs, traces, metrics,
  crash reports, database files, journals, backups, and process dumps with independent canaries.
- Kill the relay between receipt, commit, response, fetch, ACK verification, deletion, and response;
  prove no pre-ACK loss and no post-commit resurrection.
- Test request-size and queue-count limits, malformed encodings, timing differences for known/unknown
  mailboxes, enumeration, flooding, rate limits, and expired signatures under clock skew.
- Define retry semantics for replay-protected fetch/manage requests whose responses are lost.
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
