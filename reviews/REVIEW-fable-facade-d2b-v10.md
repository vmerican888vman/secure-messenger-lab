# Fable review — façade D2b v10 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), worktree clean and pinned at the exact
  SHA before and after review. Transcribed from the user's paste.
- **Head SHA reviewed:** `dad8bcc5fbb2c3e2014190b1aef1a83345b13f08`.
- **Verdict: PASS** — no blocking findings.
- **Gates at the exact head:** `cargo test --locked --all-targets` green,
  `cargo clippy --locked --all-targets -- -D warnings` clean,
  `cargo fmt --check` clean.

## The v9 remediations hold

1. **Global digest dedup (v9 finding 1).** The bounds closure in
   `mod.rs:1143-1150` rejects a matching message ID or packet digest across
   every retained dedup record, before any ratchet touch and after the outer
   signature (the stronger order, now correctly documented). The provenance
   claim was attacked directly: a crafted huge-chain-index packet would indeed
   gap-classify before MAC in vodozemac, but reaching `decrypt` requires a
   valid outer signature over the fresh envelope, and only the peer holds the
   send capability — so the only remaining gap-error producers are genuine
   current-chain loss (`RekeyRequired` correct per §4) and the peer itself,
   who can wedge the conversation trivially anyway.
   `cross_epoch_digest_replay_rejected_before_ratchet` verifies both apparent
   ages plus durable retention across reopen, with generation, mode, and
   receive water all asserted untouched.

2+4. **Control debt as a high-water (v9 findings 2 and 4).** Arming is strictly
   `control_debt_up_to = max(self, HCR)` (`mod.rs:2434-2442`); nothing on the
   wire lowers it; the only resolution is the delivered-marker max advance in
   `record_send_result` (`mod.rs:1544-1557`). Erasing an arm with a reordered
   low signal or a delayed `Stored` on an older receipt is inert by
   construction (water-vs-water, both monotone), and
   `control_debt_resolves_on_delivery_never_on_signals` walks exactly those two
   shapes. The over-signaling bound (any-pending guard) survives Sol's
   33-packet probe in `over_signaling_cannot_lock_the_victim`: never more than
   one pending victim receipt, mode stays `Ready`.

3. **Sweep before the staging tail (v9 finding 3).**
   `accept_envelope_operation` now runs `sweep_expired_sends` +
   `prune_terminal_sends` + `sweep_expired_acks` before the entry congestion
   sample and the staging tail (`mod.rs:2253-2255`), so an expired `Pending`
   control receipt is swept out of the any-pending guard and replaced in the
   same receipt-only pass —
   `expired_control_receipt_re_stages_on_receipt_only_traffic` asserts the
   corpse goes `Expired` and the replacement stages at the next sequence in one
   accept.

## Attacks run against the §4 claims

- **Replay/dedup:** ID and digest replay rejected pre-ratchet with no commit;
  the gap packet itself is replay-proof via the `RekeyRequired` inbound lock
  rather than dedup (no dedup write on the gap path — correct, the lock is
  stronger). Idempotent receipts still dedup their packets.
- **Forgery:** outer signature verified against our mailbox send key before
  dedup; receipt inner signature against the pinned peer identity with
  conversation/epoch/issuer/acknowledged-curve binding; reflected receipts fail
  the issuer-curve check; future high water hard-errors and discards the whole
  candidate (ratchet included).
- **Gap → lock → recovery:** `gap_failure_commits_rekey_required` engineers a
  genuine `MissingMessageKey` past the 40-key horizon and asserts mode,
  generation+1, untouched HCR, replay under the lock, post-lock applications
  never exposed, persistence across reopen, and staging lockout — while
  relay-level ACK/send actions stay live.
- **Sequence confusion:** dup-below-water and in-set dup reject; contiguous
  drain correct; set bound errors discard the candidate cleanly (the packet
  remains re-acceptable later).
- **Interleaving/liveness:** the one-directional, lockstep, both-stuck, and
  convergence tests all pass; the arm-first-then-stage tail makes same-pass
  flush real.
- **Crash/token/pruning:** crash-discipline tests between mutator pairs on both
  paths; ACK result binding verified for every outcome including `Failed`;
  terminal-only pruning at `expires_at + 7d` with `Pending`/`DeliveryUnknown`
  untouched.

## Non-blocking observations (no action required for this leg)

1. **`MAX_DEDUP = 4096` is a hard lifetime ceiling.** Dedup is retained forever
   by design, so 4096 is the lifetime bound on accepted packets per profile.
   The retention is genuinely load-bearing — pruning would let a malicious
   relay replay a delivered envelope within its expiry window into a
   `MissingMessageKey` gap-lock — so the façade is right not to prune. But at
   the 4096th accepted packet, every further accept fails at encode and inbound
   closes permanently. That lifecycle presumably belongs to the rebootstrap
   leg; it deserves a line in the design docs so it is not rediscovered as a
   bug.
2. **`accept_envelope_rejects_forgery_expiry_and_wrong_variant` overclaims.**
   It does not exercise the wrong-variant arm — no test covers `ExpectedPreKey`
   (a `Normal` message with no session). The path is safe by inspection
   (rejection in the operation discards the candidate), but the test name
   promises coverage that is not there.
3. **Accepted receipt envelopes are never ACK-deleted from the relay** (no
   inbound record → no intent), so they redeliver on every fetch until their
   7-day expiry, surfacing as `DuplicateMessage` errors to the caller. Bounded
   noise, not a wedge — the relay has no per-queue count bound and purges at
   expiry.
