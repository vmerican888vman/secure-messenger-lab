# Independent review request — encrypted client persistence and crash recovery

Review the exact PR head supplied with this brief and record that commit hash in your response.
This same brief is being sent separately to Kimi and Fable. Do not read, summarize, or defer to the
other review before returning your own opinion.

This is a **design review only**. Do not implement it, broaden it into a product architecture, or
repeat the repository's already-disclosed Phase 0 limitations as findings. The question is whether
[`docs/persistence-spike-design.md`](../docs/persistence-spike-design.md) is safe and falsifiable enough
to authorize a disposable implementation spike.

## Fixed scope

- one device, one directly verified peer, text only;
- current in-process relay and pinned `vodozemac = 0.10.0`;
- encrypted client persistence, durable send/ACK outboxes, and process-death recovery only;
- no network server, UI, QR ceremony, one-time-key service, recovery, multi-device, attachments,
  groups, calls, notifications, or production migration.

## Review posture

Try to break the proposal with concrete sequences. In particular:

1. Find any interruption point that can advance an Olm account/session without the matching durable
   inbox/outbox state, or expose a relay request before its ratchet state is durable.
2. Find any request/response-loss sequence that forces re-encryption, duplicate logical delivery,
   premature ACK, or ciphertext loss.
3. Determine whether the proposed AEAD/AAD/key hierarchy actually prevents state substitution and
   plaintext fallback within the stated threat model. Attempt a same-device full database swap between
   two profiles. Attempt database-only replay of an older authentic generation and verify that the
   design describes that as an undetected limitation rather than rollback resistance.
4. Evaluate the decision to persist a pending inbound body only inside the authenticated encrypted
   snapshot so a post-commit/pre-delivery crash cannot lose it.
5. Challenge the platform key-protector and software-fallback policy, including whether Android can
   report the actual protection level without overstating hardware backing.
6. Inspect the pinned `vodozemac 0.10.0` pickle source, locally or upstream. Confirm or refute the
   decision not to use its deterministic-IV, truncated-MAC pickle encryption as the sole storage
   envelope.
7. Try to construct a current or legacy SQLite shape that the proposed schema-manifest rules would
   accept despite missing `STRICT`, length checks, keys, foreign-key cascade, or required tables.
8. Decide whether every security/durability claim has a corresponding forced-process-death or
   artifact-inspection oracle.
9. Break bootstrap: kill between account/key creation, OTK generation, publication marking, bundle or
   registration exposure, outbound-session creation, and the first send. No external artifact should
   escape before its matching secret state is durable.
10. Exhaust every inbox/outbox/deduplication bound and verify the stated backpressure/eviction rules do
    not drop accepted work or mutate a ratchet before refusal.

## Required response

Return exactly one of:

- **PASS** — the design is sufficiently bounded and testable to implement as a disposable spike; or
- **RETURN** — severity-ranked concrete blockers with an exploit/failure sequence and the minimum
  design change required.

Separate true blockers from optional hardening. A PASS authorizes only implementation of this spike;
it does not approve a production app or public network relay.
