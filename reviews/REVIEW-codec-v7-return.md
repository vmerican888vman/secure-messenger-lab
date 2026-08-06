# Codec v7 review (second reviewer) — VERDICT: RETURN

- **Reviewer:** the other independent reviewer (relayed paste addressed its
  findings to the implementer; attribution per user paste). Pinned worktree
  `sml-review-codec-v7-89027ea`, clean detached at the exact SHA.
- **Head SHA reviewed:** `89027eace7a50fcfcd0b73aad163867bbe1000b0`.
- **Verdict: RETURN**

## Blocking findings

1. **Current-epoch dedup accepts two logical messages for one sender
   sequence.** `check_dedup` checks coverage but never uniqueness of
   `(epoch_id, sequence)`; inbound/ACK validation has the same omission.
   §4 requires one durable `send_seq` per Olm encryption. The existing test
   at `src/state/tests.rs` *requires acceptance* of two distinct message IDs
   sharing one epoch/sequence — an impossible snapshot (two IDs, payloads
   and ACK intents claiming one ratchet encryption). Fix: enforce unique
   `(epoch_id, sequence)` across current-epoch dedup records; add encode and
   decode regressions.
2. **A canonical Account pickle may reuse the long-term Curve25519 identity
   secret as a published OTK.** OTK uniqueness checks never compare derived
   OTK publics against the account's Curve25519 identity, and
   `check_pending_prekey` then accepts the aliased OTK as published and
   held. Reproduced in an isolated exact-SHA archive: replacing an OTK
   private key with the `diffie_hellman_key` secret and re-signing the
   pending prekey passes encode/decode, and a real inbound 3DH session
   establishes using the long-term identity as the "consumed" OTK —
   defeating OTK/identity separation (consuming the map entry does not
   remove the long-term identity secret). Fix: reject every OTK whose
   derived public equals the account Curve25519 identity; cover both
   encode/decode and a real-session regression.

## Supporting evidence

- `cargo test --locked --all-targets` (239) and strict Clippy passed.
- Worktree finished clean at the requested SHA; the adversarial probe used
  an isolated archive.
