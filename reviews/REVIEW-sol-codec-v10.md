# Sol review — client-state codec v10 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), detached worktree clean at the exact
  SHA. Did not open façade source or any `reviews/REVIEW-*` artifact.
  Transcribed from the user's paste.
- **Head SHA reviewed:** `745d957ba25ed399bb37ed92e19884ab5aefc7c6`.
- **Verdict: RETURN** — two P1 findings.
- **Gates:** all 288 tests, clippy `-D warnings`, formatting,
  `git diff --check` and `cargo audit --deny warnings` passed. Those
  checks do not close the two semantic failures.

## P1-1 — the application ledger trusts unbound send metadata

`send_signing_bytes` authenticates the queue, message ID, packet digest
and expiry — but NOT the epoch, sequence, `kind`, or receipt high water.
Ledger validation then exempts records solely because their mutable
`kind` says `Receipt`. The existing kind-arm test constructs genuine
application ciphertext, relabels it `Receipt`, removes its sequence from
field 22, sets `receipt_high_water = 1`, and proves the state encodes and
decodes. That lets application traffic consume control slots with no
application-budget accounting; the outer AEAD merely authenticates the
internally inconsistent state that `encode` accepted.

## P1-2 — the inner-message dedup identity is not unique or validated

`message_digest` is declared the variant-independent dedup identity, but
`check_dedup` never examines it. Sol created two current-epoch records
with distinct message IDs, sequences, packet digests, inbound bodies and
ACKs but the same `message_digest`; both encode and decode succeeded,
allowing one inner Olm identity to back two conflicting delivered
records.

## Requested v9 rulings

- **Ledger authority:** unsound as implemented; P1-1 blocks.
- **Retired discriminant:** correct — stored mode 3 rejects; only 1, 2
  and 4 decode.
- **Shared-distance ceiling:** do not add one. Control sends legitimately
  advance the shared sequence without consuming application capacity; a
  finite load-time cap would reject valid control history.
- **Field 22 reuse:** acceptable pre-approval — the old eight-byte scalar
  and the new count-plus-set encoding cannot alias, and the reuse is
  documented in source.
- **`SCHEMA_VERSION = 1`:** acceptable under the explicit
  no-production-state / pre-approval premise. After codec approval, any
  wire-layout change must bump it.
- **Relaxed control-debt acceptance:** directly covered by the new
  codec-level round-trip test; not blocking.

## Closure

Both remediated in v11. Sol subsequently specified the P1-1 closure in
full — option 3, a local unkeyed SHA-256 consistency commitment — and
that specification is implemented verbatim; see the v11 history in
`reviews/PROMPT-independent-phase2-client-state-codec.md`.
