# Fable review — façade D2a v2 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), isolated pinned worktree
  `sml-review-d2a-v2-eb2020e`, clean at the exact SHA.
- **Head SHA reviewed:** `eb2020e8beb178b2e933ef4d62fb9f0b5d1637e1`.
- **Verdict: PASS** — no blocking findings.

Sol's v1 blocker is fixed correctly: `record_send_result` requires
`request.message_id == token == record.message_id` before the digest
comparison, rejecting with `Unauthorized` and no mutation; the presented
record is rebuilt from the request's queue/packet/expiry/signature, so every
presentable field binds explicitly or via the SHA-256 digest. The regression
test reproduces the exact v1 attack. Budget boundaries, token confusion,
crash discipline, payload strictness, expiry edge, and the delivery-unknown
lifecycle were re-attacked and all defended. The payload escape-inflation
guard and the ACK-sweep hooks do not touch send budget or mode state (§4
claims unaffected). D2b inbound-leg content was excluded per the brief.

Gates at the head: 220 tests green, clippy `-D warnings` clean,
`cargo fmt --check` clean, `git diff --check` clean.
