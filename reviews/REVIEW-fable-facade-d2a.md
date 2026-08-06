# Fable review — façade leg D2a — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), independent — Sol's response not seen.
- **Head SHA reviewed:** `16adc902591196bfd0366be2bdb679bcc9253253` (clean detached
  review worktree; verified via `git rev-parse HEAD`).
- **Verdict: PASS** — no blocking findings.

All six §4 claims verified against source; all six required attack classes hold, via the
shipped suites plus 15 reviewer probes (7 public-API, 8 payload-strictness). Gates on the
pristine tree: `cargo test --locked --all-targets` 202 passed / 0 failed;
`cargo clippy --locked --all-targets -- -D warnings` clean; `cargo fmt --check` clean.

Non-blocking notes (detail in
`reviews/RESULTS-independent-phase2-facade-d2a-fable.md`):

1. A legal ≤ 65,536-byte body with > ~512 escape-inflating characters exceeds
   `MAX_PAYLOAD_BYTES` and fails `stage_send` with coarse `Encoding` instead of the
   documented `InvalidPayload`; fails closed, burns no sequence (probe-proven). Document
   the effective canonical-bytes bound or pre-check in `payload::application`.
2. An expired `DeliveryUnknown` becomes an unconsumable `Expired` record holding an
   outbox slot; bounded within D2a (≤ 24) — terminal-record pruning should land
   deliberately in D2b or later.
3. `ClientPayloadV2.body` plaintext is a non-zeroizing `String` (encoded bytes are
   `Zeroizing`); consistent with existing codec treatment.

No tracked source changes, commits, or merge actions were made.
