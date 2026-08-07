# Fable review — ClientStateV1 codec v3 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), independent — Sol's response not seen.
- **Head SHA reviewed:** `235ccfb854ba0d8def87a612d68c9948adb2719f` (clean; verified via `git rev-parse HEAD`).
- **Verdict: PASS**

This is the amended v3 head, not either returned head. The four Sol v2 blockers
are each fixed and independently reproduced as rejecting; all seven required
attack classes hold; no new codec or validation flaw was found.

## Blocking findings

None.

## Gates

- `cargo test --locked --all-targets` — PASS (exit 0)
- `cargo clippy --locked --all-targets -- -D warnings` — PASS (exit 0)

Gates ran in the main worktree unmodified. All probes ran in a separate git
worktree at the same SHA; the main worktree was untouched apart from the two
report files.

## Confirmation of the four v2 fixes (independently reproduced)

1. **Receive-side provenance** — `src/state/validate.rs:383-389` gates all
   receive-side state on `Session::has_received_message()`. A send-only session
   with fabricated inbound/ACK/receive state fails `encode()`; the genuine
   two-way fixture passes.
2. **Receipt-free conversation binding** — field 18 is parsed
   (`src/state/records.rs:417`) and checked against field 8 unconditionally
   (`src/state/validate.rs:373-375`). A receipt-free session with field 18
   flipped one byte from field 8 fails decode.
3. **`DeliveryUnknown` digest arm** — `carries_full_arm` is `Pending`-only
   (`src/state/records.rs:544`); `arms_consistent` (`:597-609`) rejects a
   full-arm `DeliveryUnknown` on both paths.
4. **Published-OTK prekey** — `check_pending_prekey`
   (`src/state/validate.rs:281-290`) requires held-and-published; unpublished
   and consumed OTKs both fail.

## Non-blocking (not return causes)

- RekeyRequired is unrepresentable at outstanding 24–32 (`check_high_water`,
  `src/state/validate.rs:470-477`) — reproduced (accepted at outstanding 0,
  rejected at 24 and 32). Carried over from the v1 Fable review; not blocked
  here because the brief's required attack 5 codifies the exact matrix the code
  enforces and the design authority did not amend §4 across two remediation
  rounds. Resolve before the façade drives real gap-packet transitions.
- Zero-high-water receipt accepted; duplicate inbound/ACK sender sequences
  accepted; secret reserialization buffers not `Zeroizing` — all carried over
  from the v1 Fable review, code paths unchanged, all harmless at this leg.

No repository source, tests or docs were changed; head remains clean and
unchanged.
