# Fable review — client-state codec v10 (remediation) — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-codec-v10-fable-380e261`, clean at the
  exact SHA after probes were restored and the full suite re-run.
- **Head SHA reviewed:** `380e261d33a5bdbce4d91cc6785563a82e6cfbc1`.
- **Verdict: PASS** — no blocking findings.
- **Gates:** 237 + 27 + 19 + 5 tests pass, zero failures; clippy
  `-D warnings` clean; `fmt --check` clean.

## Blocker closure confirmed by mutation

The new block in `check_structure` applies to field 22 exactly what
`parse_u64_set` enforces on decode — length bound then strict ascent,
structurally identical to field 17's block. Fable reverted it and
`non_canonical_application_ledger_is_rejected_on_encode` failed, proving
three things at once: the fix is load-bearing, no other validator
incidentally catches ordering (`check_high_water` checks length and
per-element range only; `check_application_ledger` checks membership
only), and the test is not vacuous. The canonical `[2,3]` control arm
proves the fixture is otherwise valid under the same waters, so the
reject arms isolate the ordering rule.

## Sibling-asymmetry sweep — none found

Fable walked every parse-time-only invariant against
`check_structure`/`validate`: TLV grammar and constants are produced by
construction on encode; all enums and fixed-length values are typed in
memory so they cannot hold invalid discriminants; canonical-JSON
re-verification covers the account pickle, the three mailbox keypairs,
the binding keypair and the session pickle; all four record arrays go
through `check_sorted`; both u64 sets are now covered. The one
zero-length-optional hazard (an empty-bytes `Some(EncryptedPacket)`
decoding as `None`) is already rejected, and `Some(0)` receipt high water
dies in `arms_consistent`, which `check_structure` re-runs. **Field 22
was the last set-shaped gap.**

## All three new tests mutation-verified

- **Mode splice:** mutating parse's `_ => Err` to `_ => RekeyRequired`
  (the one variant semantic validation accepts at any count, so nothing
  downstream would mask it) made the test fail with "stored session mode
  0 was accepted". The test also self-anchors — it asserts the located
  byte equals `Ready` before splicing and that value 4 still decodes, so
  a wrong offset fails loudly.
- **Control debt:** tightening the rule to strict broke the ACCEPT arm;
  deleting the rule broke the reject arm. Each arm binds to the intended
  rule, and the ACCEPT arm's success proves the reject arm's only delta
  is the debt value.

## Behavioural delta confined

`git diff 67589d5..HEAD` touches only the `validate.rs` block, six doc
lines in `mod.rs`, eight in `records.rs`, and the three tests. Fable
independently checked the `records.rs` claim that no 8-byte input parses
as a valid set: count = 0 leaves 4 unconsumed bytes and fails `is_done`;
count ≥ 1 needs ≥ 12 bytes. No other production change.

## Non-blocking

- The two carried items — the `high_water = 0` impossible-snapshot
  admission, and `control_send_not_before` having no upper sanity bound
  (façade-owned) — remain as previously assessed. Nothing in this delta
  changes that view.
- Cosmetic: `field_value_offset` in the mode test loops until a bounds
  error rather than an explicit not-found exit. It terminates correctly
  via `.ok_or(...)` on overrun; no action needed.
