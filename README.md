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
- Fetching does not delete. A recipient-signed ACK binds the queue, message ID, and ciphertext hash;
  the client API can create it only after verifying the sender-signed outer envelope and successfully
  decrypting its inner binding. One transaction then deletes ciphertext and adds a bounded replay
  tombstone.
- Tests inspect the live relay database and relay event stream for plaintext, serialized private
  capabilities, and post-ACK ciphertext residue.
- Relay startup now validates the complete current/legacy `SQLite` manifest and exercises real hot
  rollback-journal recovery before accepting or migrating a database.
- **Phase 2:** the persistence-owning `PersistentClient` façade exclusively owns the encrypted
  client-state store, the Olm account/session, capabilities, bindings and outboxes. Every mutation is
  staged as a complete candidate, validated by the bespoke canonical `ClientStateV1` TLV codec
  (bounds-before-allocation, canonical-JSON pickles, signature/epoch/high-water cross-checks), and
  committed as one generation-CAS snapshot; a commit failure forces reconcile-on-reopen.
  `OlmClient`/capability owners/raw store commits are crate-private — the old production bypasses are
  gone.
- Payloads are strict canonical `ClientPayloadV2` (conversation/epoch/sequence-bound); the §4
  high-water budget, receipt and `RekeyRequired` machinery is implemented and tested, including
  genuine out-of-order assembly and gap-induced rekey locking over a real in-memory relay.
- The private-store boundary enforces owner-only ACL-free directories with exact content checks and a
  strictly non-blocking lifecycle lock; the platform-key lifecycle manager drives
  provisional/expected/locked/deleting transitions with exact-state CAS and tested recovery arms.

## What this does **not** prove

- There is no Android or iOS app, network server, TLS layer, notification path, or public deployment.
- Contact bundles are exchanged directly in the test. There is no QR verification UI, key directory,
  or transactional one-time-key claim service — and no public handle yet for the out-of-band
  send-capability transfer (the demo stops there; see `src/main.rs`).
- The façade is not yet wired to the lifecycle manager (create/open go through the store directly),
  and the §4 rebootstrap ceremony and D2c receipt coalescing remain open.
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
PASS: two façade clients created durable profiles, registered mailboxes on a real relay, minted redacted contact offers, and fetched (empty) mailboxes with verified signatures
NOTE: the demo stops before the conversation: the public API has no handle for the out-of-band send-capability transfer (see the module docs for the exact gap)
```

## Repository map

- `src/persistent/` — the Phase-2 persistence-owning façade (the only public client API).
- `src/state/` — the canonical `ClientStateV1` TLV codec and semantic validation (crate-private).
- `src/payload.rs` — strict `ClientPayloadV2` canonical-JSON payloads.
- `src/lifecycle.rs` — platform-key lifecycle manager (provisional/expected/locked/deleting).
- `src/private_store_dir/` — the enforced private-directory boundary (incl. ACL rejection).
- `src/persistence/` — envelope + profile binding + the one-row encrypted state store
  (crate-private).
- `src/relay.rs` — minimal opaque SQLite store, authenticated ACK, TTL, and replay tombstones.
- `src/client.rs` / `src/capability.rs` — Phase-0 client and capability owners, crate-private,
  retained for the in-crate proof tests.
- `tests/` — adversarial end-to-end, state-staging, boundary, concurrency, expiry, and migration
  checks (path-level hostile fixtures live in-crate beside the modules they exercise).
- `THREAT_MODEL.md` — adversaries, guarantees, non-goals, and the metadata budget.
- `SECURITY_STATUS.md` — current security gate and unresolved blockers.
- `docs/architecture.md` — exact prototype flow and trust boundaries.
- `docs/acceptance-tests.md` — what is automated now and what still needs a real network/device lab.
- `docs/persistence-spike-design.md` — independently passed encrypted-state/crash-recovery contract;
  only its disposable implementation spike is authorized.
- `docs/phase2-design-decisions.md` — the frozen Phase-2 decisions this codebase implements.

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
