# Independent review — façade leg D2a: ClientPayloadV2 + outbound send path

## Remediation history (v2)

Version 1 (head `16adc902591196bfd0366be2bdb679bcc9253253`): Fable PASS, Sol
RETURN — `record_send_result` substituted the stored message ID instead of
validating the presented request's `message_id`. The amended head requires
`request.message_id == token == record.message_id` in the step-2 bounds
before the digest comparison; mismatches reject without mutation. The
inbound leg (D2b) also landed between the two heads — it is out of scope for
this brief; the D2a-relevant delta is confined to `record_send_result` and
its tests.

Review `secure-messenger-lab` at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Fable and Sol; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own. Untracked `reviews/REVIEW-*` / `RESULTS-*` files may be visible — they
are reviewer artifacts for other legs; ignore them, do not open them.

This is an adversarial review of the façade's outbound send path: `ClientPayloadV2`, the §4
send-side budget/mode machinery, and the families `stage_send`, `pending_send_actions`,
`record_send_result`, `delivery_unknowns`, `consume_delivery_unknown`. The inbound/fetch/ACK/
receipt-processing families are leg D2b — do not return this leg for their absence. The façade D1
leg is dual-PASS (`1434452`); this leg builds on it.

## In scope

- `src/payload.rs` — `ClientPayloadV2` strict codec (canonical compact JSON: bound first,
  `Deserializer::end()`, reserialize byte equality), arm consistency, bounds.
- `src/persistent/mod.rs` — the five new families, the expiry sweep, mode recomputation.
- Tests: `tests/persistent_client.rs` (integration), `src/persistent/tests.rs` (in-crate),
  `src/payload.rs` unit tests.

## §4 claims under review (attack each)

1. Every Olm encryption gets a durable epoch_id and send_seq from one per-session counter starting
   at 1; `send_seq = last_assigned_send_seq + 1` assignment is contiguous and committed before the
   action is exposed.
2. Budget/mode: outstanding = `last_assigned_send_seq − peer_contiguous_high_water`; budget modes
   recompute from outstanding after every committed mutation; `RekeyRequired` dominates and is
   never recomputed away. Application staging only in `Ready`; `ReceiptLocked` and `RekeyRequired`
   block all staging. (Receipt staging is D2b; the `ControlOnly`-allows-control rule exists only as
   that path's gate.)
3. `Stored`, `Duplicate`, `Expired` and consuming `DeliveryUnknown` never advance the peer high
   water and never touch `last_assigned_send_seq`/`peer_contiguous_high_water`.
4. Token discipline without a codec token field: token = the fresh random `message_id`; request
   digest = SHA-256 over canonical SendRecord bytes; presentation requires both; replay rejects
   because the record leaves `Pending`.
5. `consume_delivery_unknown` removes the record (frees the bounded slot); documented decision.
6. Expiry sweep transitions Pending/DeliveryUnknown records with `expires_at <= now` to `Expired`
   at the top of send-path mutators that take a clock.

## Documented decisions / deviations

- The receipt arm is a payload-local `ReceiptV2` mirroring `HighWaterReceipt` (the frozen type
  lacks serde derives; vendored `Ed25519Signature` lacks serde support; signature carried as a
  64-byte `Vec<u8>` with length enforced).
- Receipt staging deferred to D2b (no clean hook without receive-side state).
- Mode-blocked staging returns coarse `LabError::Storage`; expiry uses `InvalidExpiry`;
  wrong-state uses `MessageGone`; unknown ID uses `MessageNotFound`.
- `record_send_result` takes no clock, so it does not sweep (documented).

## Required attacks

1. budget boundaries: 24th application send allowed, 25th rejected; outstanding 32 ⇒ everything
   rejected; `RekeyRequired` at any outstanding ⇒ everything rejected; persistence across reopen;
2. token confusion on send results: wrong/replayed/cross-action/foreign-client tokens and
   requests;
3. crash between any two send-path mutators: only committed state; a result for an uncommitted
   send cannot be recorded after reopen;
4. payload strictness: non-canonical JSON (whitespace, key order, trailing data, missing/extra
   fields), wrong version/kind, both/neither arms, body bound ±1, epoch/conversation/message-ID
   confusion;
5. expiry edge: `expires_at == now`, TTL bound ±1, sweep ordering inside a mutator;
6. delivery-unknown lifecycle: Pending → DeliveryUnknown → consume; double-consume; consuming a
   Pending or terminal record; slot accounting at the 32 bound.

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Return `PASS` or `RETURN` against the exact head SHA. A `RETURN` must list blocking findings only,
each with a concrete reproduction or source reference.
