# Fable review — façade D2b v3 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), pinned worktree
  `sml-review-d2b-v3-af78462`, clean apart from the verdict file.
- **Head SHA reviewed:** `af78462718ddcd5bff5ccd8212fa08ed2fb499c6`.
- **Verdict: PASS** — no blocking findings. Transcribed from the user's
  paste.

All four v2 blockers confirmed genuinely fixed, each with a reproduction
test:

1. `record_ack_result` runs the complete binding verification for every
   outcome including `Failed`; forged tokens/signatures with `Failed`
   reject, and a genuine `Failed` provably mutates nothing.
2. Receipt staging in `consume_inbound` is best-effort (skipped at the
   32-send bound or when the mode blocks control); consume never rolls back
   — verified against Sol's exact 32-terminal-sends repro shape.
3. The pre-key path requires the pending offer unexpired before consuming
   the OTK.
4. All façade-minted requests sit inside the relay's 300-second window;
   the `registration_action` signature change is the minimal honest fix.

Additional attacks that held: replay/dedup (including replay of consumed
and acked messages, and prekey re-establishment under a fresh message ID
caught by epoch-scoped digest dedup), forgery paths, sequence confusion,
receipt regression/future/identity confusion, ACK token splicing, crash and
commit-failure discipline, pruning edges. The reviewer also verified in the
vendored vodozemac source that `find_message_key` raises
`MissingMessageKey`/`TooBigMessageGap` from `&self` on a cloned ratchet —
so the committed `RekeyRequired` candidate carries an unmutated session
pickle, and ordinary MAC failures commit nothing.

## Non-blocking observations

- The implemented accept ordering is signature-before-dedup — the reverse
  of the brief's stated order, strictly safer (unauthenticated senders
  can't probe dedup state); a stale "(b) dedup first" comment should be
  reworded.
- Dedup records (bounded 4,096) are never pruned in this leg; consistent
  with the design assigning dedup retention to rebootstrap, but a follow-up
  leg should explicitly own dedup expiry or a very long-lived session
  eventually wedges its inbound path until rekey.

Gates at the head: full test suite green, clippy `-D warnings` clean, fmt
clean.
