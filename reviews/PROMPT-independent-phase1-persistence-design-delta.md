# Independent delta review — persistence design return-item reconciliation

Review the exact PR #6 head supplied with this brief and record that full commit hash in your response.
Compare it with the independently reviewed base
`3f9c186c8f1aa34e5a03f45ef3621ac75a5b591e`. This brief is being sent separately to Kimi and Fable;
do not read or rely on the other reviewer's delta response before returning your own.

This remains a **design-only delta review**. Do not implement it or broaden the fixed scope. Decide
whether the amendments close the union of the initial `RETURN` items without introducing a new
security, durability, or falsifiability blocker.

## Required closure attempts

1. **Registration expiry recovery.** Lose the relay response after registration commits, keep the
   client offline beyond the five-minute request window, and restart. Verify the design persists
   immutable owner intent separately from the current signed request, commits a fresh nonce/expiry/
   signature over unchanged queue and owner keys before transmission, and reconciles to exactly one
   matching mailbox. Also kill during request replacement, retry within the original window, and
   inject intent/request field and signature mismatches that must fail before renewal/transmission.
2. **Bound exhaustion.** Fill and exceed every body, packet, pending-inbound, combined send-outbox,
   ACK, deduplication, and complete-ciphertext bound. Verify the exact-boundary/one-over oracles,
   pre-Olm checks for counts/caller-known lengths, discard-only handling when body/pickle/serialized
   size is knowable only after a disposable clone mutates, byte-identical authoritative pickles, no
   relay-mutating request or logical delivery, no pending eviction, forced-death recovery, full-dedup
   blocking, and drain/resume.
3. **OTK capacity behavior.** Confirm pinned `vodozemac 0.10.0` silently evicts and reports an old key
   rather than refusing generation. Verify renewal checks `removed.is_empty()` immediately on the
   cloned Account and discards the entire candidate without persistence or exposure on any removal.

## Hardening incorporated in the same delta

Try to break the new terminal-message-expiry dedup reclamation path, durable body-free
`DeliveryUnknown` outcome, platform-wrap binding contract, lowest-claim Android protection reporting,
lifecycle-locked provisional-key cleanup, immutable hostile-fixture sources versus normal hot-journal
recovery, and structural `Debug`/error redaction.

The design deliberately retains fresh random XChaCha nonces instead of deriving them from
`(DEK, generation)`: an authentic old-snapshot replay can repeat a generation under the same DEK.
Verify that the new rollback-continuation oracle prevents nonce reuse without claiming rollback
protection.

## Required response

Return exactly one of:

- **PASS** — all initial return items are closed on the supplied amended head and the delta introduces
  no new blocker; or
- **RETURN** — concrete remaining/new blockers, each with a failure sequence and minimum design change.

Separate blockers from optional hardening. A PASS authorizes only implementation of this disposable
persistence spike; it does not approve a production app, public network relay, or public security
claim.
