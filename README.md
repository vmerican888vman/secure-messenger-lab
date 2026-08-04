# Secure Messenger Lab

> **Experimental, unaudited, disposable Phase 0 code. Do not use this to protect real messages.**

This repository is a working security test, not an app and not a production codebase. It asks one
small question: can two local clients exchange end-to-end encrypted text through a store-and-forward
relay while the relay stores only opaque ciphertext and deletes it after an authenticated recipient
acknowledgement?

The current answer is **yes inside this constrained local harness**. That is not evidence that a
shippable messenger is secure.

## What works today

- Two peer-scoped Rust clients establish an Olm 1:1 session using
  [`vodozemac` 0.10.0](https://docs.rs/vodozemac/0.10.0/vodozemac/), pinned exactly.
- Each short-lived contact pre-key bundle signs its Curve25519 identity and one-time key with the
  separately pinned Ed25519 contact identity. A substituted bundle fails before session creation.
- A SQLite relay holds two independent unidirectional mailboxes. It has no user, contact,
  conversation, group, phone, email, username, or plaintext tables.
- A random queue ID only locates a mailbox. Separate Ed25519 send, receive, and management signing
  capabilities authorize operations.
- A missing session, altered ciphertext, wrong recipient, wrong capability, expired request, expired
  verified pre-key/envelope, or mismatched acknowledgement fails closed.
- Inbound account and ratchet mutations are staged in memory and committed only after the encrypted
  conversation/message binding succeeds.
- Fetching does not delete. A recipient-signed ACK binds the queue, message ID, and ciphertext hash;
  the client API can create it only after verifying the sender-signed outer envelope and successfully
  decrypting its inner binding. One transaction then deletes ciphertext and adds a bounded replay
  tombstone.
- Tests inspect the live relay database and relay event stream for plaintext, serialized private
  capabilities, and post-ACK ciphertext residue.

## What this does **not** prove

- There is no Android or iOS app, network server, TLS layer, notification path, or public deployment.
- Contact bundles are exchanged directly in the test. There is no QR verification UI, key directory,
  or transactional one-time-key claim service.
- Ratchet and identity state are not persisted. Encrypted local storage, hardware-backed key wrapping,
  crash recovery, and atomic session-state updates remain blockers.
- IP addresses, packet timing, ciphertext size, and traffic correlation are not hidden.
- A malicious relay can copy ciphertext before deletion. Filesystem snapshots, host logs, backups,
  memory, and storage-device remanence are outside the current proof.
- There is no multi-device support, recovery, revocation, groups, attachments, calls, moderation,
  spam resistance, or store-compliance work.
- `vodozemac` supplies the Olm ratchet, but the mailbox protocol and its integration have not been
  independently audited.

The strongest accurate statement is:

> In the tested local harness, message content is encrypted on the sender and decrypted only on the
> recipient; the relay receives no plaintext or private keys, and its current SQLite file contains no
> delivered ciphertext after an authenticated ACK. Opaque delivery metadata remains temporarily.

## Run it

Requires Rust 1.85 or newer.

```sh
cargo run
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
```

Expected demo output:

```text
PASS: two clients exchanged encrypted messages; relay queue is empty after authenticated ACKs
```

## Repository map

- `src/client.rs` — peer-scoped Olm session and fail-closed encrypted payload handling.
- `src/capability.rs` — separate signed mailbox capabilities and canonical command binding.
- `src/relay.rs` — minimal opaque SQLite store, authenticated ACK, TTL, and replay tombstones.
- `tests/` — adversarial end-to-end, state-staging, boundary, concurrency, expiry, and migration checks.
- `THREAT_MODEL.md` — adversaries, guarantees, non-goals, and the metadata budget.
- `SECURITY_STATUS.md` — current security gate and unresolved blockers.
- `docs/architecture.md` — exact prototype flow and trust boundaries.
- `docs/acceptance-tests.md` — what is automated now and what still needs a real network/device lab.
- `docs/persistence-spike-design.md` — proposed encrypted-state/crash-recovery contract awaiting two
  independent delta passes; no implementation is authorized yet.

## Phase boundary

The governing design document permits throwaway prototypes but prohibits production implementation
until Phase 0 clears. This repository is therefore intentionally versioned `0.0.x`, is not published
as a crate, and must not be promoted into a release codebase. Useful findings should be carried into a
fresh implementation only after the protocol, identity, persistence, device, abuse, legal, and
sustainability gates are resolved.

## Open-source contribution model

The code is licensed under Apache-2.0. Contributions use the Developer Certificate of Origin 1.1;
add `Signed-off-by` to every commit. No CLA is required at this stage. See `CONTRIBUTING.md`.

Do not report suspected vulnerabilities in a public issue. Follow `SECURITY.md`.

## Cost

This milestone uses local tools and open-source dependencies: current infrastructure spend is **$0**.
No hosting, domain, paid recruiting, contractor, or audit has been purchased.
