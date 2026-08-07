# Sol review — façade D2b v10 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), detached worktree
  `sml-review-d2b-v10-dad8bcc`, clean at the exact SHA before and after.
  No committed `reviews/REVIEW-*` artifact was opened. Transcribed from the
  user's paste.
- **Head SHA reviewed:** `dad8bcc5fbb2c3e2014190b1aef1a83345b13f08`.
- **Verdict: RETURN** — two P1 blockers.
- **Gates:** `cargo test --locked --all-targets`, `cargo clippy --locked
  --all-targets -- -D warnings`, and `cargo fmt --check` all passed. They
  are integrity evidence and do not close either semantic failure.

## Blocking findings

### P1-1 — JSON aliases bypass global packet dedup

`EncryptedPacket` hashes raw bytes (`src/client.rs:128`), but
`accept_envelope` later deserializes those bytes permissively as an Olm
message (`src/persistent/mod.rs:2271`). Whitespace, reordered fields, or
ignored fields change the digest while preserving the decrypted message,
so the digest dedup at `src/persistent/mod.rs:1147` does not match.
Replaying an accepted packet under a fresh signed envelope therefore
reaches ratchet `decrypt`, returns `MissingMessageKey`, and durably
commits `RekeyRequired` (`src/persistent/mod.rs:2157`).

**Closure offered:** reject non-canonical Olm JSON before it can reach
dedup/ratchet, or add a separate semantic dedup digest while retaining the
raw digest for envelope/ACK binding.

### P1-2 — an out-of-order truthful congestion signal can be lost permanently

Control debt is armed to the current HCR (`src/persistent/mod.rs:2434`)
rather than to the signaling packet's sequence, and validation forbids
recording a debt water above HCR (`src/state/validate.rs:659`). A delayed
old receipt then advances the delivered marker to that prematurely low
water (`src/persistent/mod.rs:1555`). When the missing packets later drain
HCR, no owed receipt stages (`src/persistent/mod.rs:2737`), leaving the
peer `ControlOnly` at 24 outstanding.

**Closure offered:** bind peer-signaled debt to `parsed.send_seq`, permit
it while that sequence is in the out-of-order set, and add the real-façade
reordered retry regression requiring an HCR-covering receipt and recovery
below 24.

## Round outcome

Fable returned `PASS` at the same head
(`reviews/REVIEW-fable-facade-d2b-v10.md`); this RETURN carries the round.
Both findings are remediated in v11 — see the v11 history at the top of
`reviews/PROMPT-independent-phase2-facade-d2b.md`.
