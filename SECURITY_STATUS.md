# Security status

## Verdict: NO-GO for real users

The local Phase 0 vertical slice passes its narrow automated tests. The project remains experimental,
unaudited, and unsuitable for sensitive or production messaging.

## Passing in this harness

- [x] End-to-end encrypted two-client round trip through the real relay path.
- [x] No plaintext fallback when session state is absent.
- [x] Relay schema has no plaintext, users, contacts, conversations, phone numbers, emails, or groups.
- [x] Separate signed send, receive, and management capabilities; queue ID alone authorizes nothing.
- [x] Signed contact bundle binds Curve25519/one-time keys to a pinned Ed25519 identity.
- [x] Sender-signed outer envelope is verified before ratchet mutation; ACK creation requires a
      successfully decrypted envelope.
- [x] Previously verified pre-keys and envelopes are rechecked for expiry at the point of use.
- [x] Binding-invalid authenticated payloads cannot burn the authoritative one-time key or advance
      the authoritative ratchet; candidate crypto state commits only after inner validation.
- [x] Authenticated recipient ACK is required before early deletion.
- [x] ACK substitution, ciphertext tampering, wrong-recipient, unauthorized-capability, replay, retry,
      duplicate, conflict, and TTL tests.
- [x] Current SQLite file contains queued ciphertext but no plaintext; exact ciphertext bytes are absent
      after ACK under the tested SQLite settings.
- [x] Relay event stream contains fixed event names only.
- [x] Startup/operation-wide expiry sweeps, deleted-mailbox retirement, and concurrent send
      idempotency are covered by file-backed restart/contention tests.
- [x] A transactional schema migration securely discards legacy queued messages that lack sender
      signatures while preserving other relay state.
- [x] Equality/future request-expiry bounds and invalid message-retention bounds fail closed under
      direct regression tests.
- [x] Relay startup compares the complete current/legacy schema manifest, rejects hostile hybrids
      without application mutation, and recovers a real valid hot rollback journal.
- [x] The opaque local-state foundation authenticates one bounded encrypted snapshot against an
      independently obtained profile/key binding and survives forced death as a complete old/new row.
- [x] The persistence-owning façade commits every account/ratchet/outbox mutation as one validated,
      generation-CAS snapshot through the canonical `ClientStateV1` codec; commit failure locks the
      profile until reopen. Legacy public mutation and raw-commit paths are crate-private, so no
      production bypass remains.
- [x] Strict `ClientPayloadV2` payloads (conversation/epoch/sequence-bound), the §4 send budget and
      receipt machinery, durable ACK intents, dedup, and out-of-order receive assembly, tested
      end-to-end over a real in-memory relay including a durable gap-induced `RekeyRequired`.
- [x] Private-store boundary: owner-only ACL-free directories, exact content validation, torn
      companion rejection, strictly non-blocking lifecycle lock; the platform-key lifecycle manager
      drives create/recovery/reset with exact-state CAS and tested failure arms.

- [x] The `ClientStateV1` TLV codec and its semantic validation carry an independent DUAL PASS at
      `8fab295` (both reviewers, exact SHA). Scope is `src/state/` only; it broadens to no other leg,
      and per `docs/phase3-post-quantum-decision.md` it does not transfer to the MLS replacement.
- [x] The persistence façade leg D2b (inbound path, receipts, ACKs) carries an independent DUAL PASS
      at `a33d2ba`, on the same terms.

## Blocking any app or public-security claim

- [ ] Independently reviewed protocol and complete formal threat model.
- [ ] Verified QR/contact ceremony that binds stable identity to peer-scoped session keys, including a
      public handle for the out-of-band send-capability transfer (currently absent — see src/main.rs).
- [ ] Transactional one-time-key publication and single claim without relay key substitution.
- [ ] Identity-bound envelope authentication before any mailbox send capability is shared or delegated
      beyond the single verified peer assumed by this harness.
- [x] Encrypted, atomic persistence of every mutated Olm account and ratchet state (through the
      façade; the crate-private legacy client keeps keys in memory and is test-only).
- [ ] Hardware-backed local wrapping key where available plus a safe fallback policy (the lifecycle
      manager models the states; real platform adapters are open).
- [ ] Crash/restart tests at every send, fetch, decrypt, persistence, and ACK boundary (the façade's
      crash/reopen and reconcile paths are tested; the full boundary matrix is not).
- [ ] Façade/lifecycle wiring (create/open currently go through the store directly), the §4
      rebootstrap ceremony, and receipt coalescing (D2c).
- [x] Exact fail-closed SQLite schema-shape validation for current and documented legacy schemas.
- [ ] Real authenticated network protocol, TLS configuration, request limits, and traffic/log capture.
- [ ] Periodic expiry scheduler and a measured wall-clock deletion SLA for an otherwise idle relay.
- [ ] Offline ordering, retry, migration, relay failover, duplicate delivery, and deletion across relays.
- [ ] Android physical-device crypto/store/notification spike.
- [ ] Recovery, revocation, and multi-device decision.
- [ ] Abuse reporting, blocking, rate limits/proof of work, moderation operations, and store compliance.
- [ ] Reproducible Android build, dependency/SBOM/provenance pipeline, external audit, and incident plan.
- [ ] Conditional pre-migration PQ exception governance and operational hold: before any pre-PQ launch, verify every disclosure condition applicable at that gate and prove that suspension or lapse blocks new releases, onboarding, and creation of pre-migration message ciphertext while preserving existing user-data access and enabling accurate corrective disclosure. Re-verify applicable conditions at every release or migration gate; after a violation, require a new dated product-owner acceptance and security-architect concurrence before reactivation.

## Dependency note

The crypto path uses the high-level Olm API from `vodozemac` 0.10.0 with default and hazardous
low-level features disabled. [Upstream's 0.10.0 documentation](https://docs.rs/vodozemac/0.10.0/vodozemac/)
states that the crate received one security audit, but that does not establish coverage of version
0.10.0, this integration, or the mailbox protocol. We therefore do not describe this project as
audited. Olm session version 1 uses a truncated MAC. Version 2 in this dependency is gated behind its
`experimental-session-config` feature, which this harness deliberately does not enable. Protocol
selection must be revisited before any production design is accepted.

Open source permits inspection. It does not certify security, guarantee review, stop malicious builds,
or replace a funded independent audit.

## Next proposed gate

[`docs/persistence-spike-design.md`](docs/persistence-spike-design.md) defines the encrypted local-state
and forced-crash experiment. Kimi and Fable independently returned `RETURN` on exact head
`3f9c186c8f1aa34e5a03f45ef3621ac75a5b591e`; their blocking items are reconciled in the amended
design. Both independently returned `PASS` on exact amended head
`04cd037f21cb37604b0a7d7cc5cfd9e86a04d70a`, authorizing only the disposable implementation spike.
This is not production or public-security clearance; every unchecked blocker above remains open.
