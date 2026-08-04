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

## Blocking any app or public-security claim

- [ ] Independently reviewed protocol and complete formal threat model.
- [ ] Verified QR/contact ceremony that binds stable identity to peer-scoped session keys.
- [ ] Transactional one-time-key publication and single claim without relay key substitution.
- [ ] Identity-bound envelope authentication before any mailbox send capability is shared or delegated
      beyond the single verified peer assumed by this harness.
- [ ] Encrypted, atomic persistence of every mutated Olm account and ratchet state.
- [ ] Hardware-backed local wrapping key where available plus a safe fallback policy.
- [ ] Crash/restart tests at every send, fetch, decrypt, persistence, and ACK boundary.
- [ ] Exact fail-closed SQLite schema-shape validation for current and documented legacy schemas.
- [ ] Real authenticated network protocol, TLS configuration, request limits, and traffic/log capture.
- [ ] Periodic expiry scheduler and a measured wall-clock deletion SLA for an otherwise idle relay.
- [ ] Offline ordering, retry, migration, relay failover, duplicate delivery, and deletion across relays.
- [ ] Android physical-device crypto/store/notification spike.
- [ ] Recovery, revocation, and multi-device decision.
- [ ] Abuse reporting, blocking, rate limits/proof of work, moderation operations, and store compliance.
- [ ] Reproducible Android build, dependency/SBOM/provenance pipeline, external audit, and incident plan.

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
and forced-crash experiment. It is awaiting two independent design reviews and is not implementation
or security clearance. Kimi and Fable must review it independently before implementation begins.
