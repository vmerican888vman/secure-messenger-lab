# Sol review — façade D2b v2 — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), pinned worktree `sml-review-d2b-v2-eb2020e`,
  clean detached at the exact SHA. (Transcribed from the user's paste.)
- **Head SHA reviewed:** `eb2020e8beb178b2e933ef4d62fb9f0b5d1637e1`.
- **Verdict: RETURN**

## Blocking findings

1. **`record_ack_result(..., Failed)` bypasses ACK binding** — returns
   success for `Failed` before token lookup, field comparison, or signature
   verification; a forged or unrelated action is accepted as a failed
   result.
2. **Receipt staging can prevent inbound consumption at the 32-send
   limit** — `consume_inbound` removes the inbound and creates its ACK,
   then unconditionally stages a receipt; with 32 fresh terminal send
   records retained, send 33 violates MAX_SENDS and rolls back the entire
   mutation, so the inbound remains and no ACK is created until pruning is
   eligible. Reproduction: terminally record 24 sends, apply receipt
   high-water 24, terminally record eight more, then accept and consume an
   application.
3. **Expired pending prekeys remain usable** — `accept_envelope` checks
   only the outer envelope expiry; the pre-key path never compares
   `pending.valid_until` with `now` before consuming the OTK and installing
   the session. A peer can establish a session after the offer expired.
4. **The façade can durably create ACKs the relay will always reject** —
   `consume_inbound` accepts any future `valid_until`, while the relay
   limits ACK authorization to five minutes; 32 such ACKs exhaust the
   bounded slots until expiry.

## Verification (passed but did not cover these attacks)

- `cargo test --locked --all-targets` (220), clippy `-D warnings`,
  `cargo fmt --check`, `git diff --check`; clean detached checkout.
