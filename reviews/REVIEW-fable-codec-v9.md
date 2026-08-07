# Fable review — client-state codec v9 — VERDICT: RETURN

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-codec-v9-fable-67589d5`, clean at the
  exact SHA after probes were removed.
- **Head SHA reviewed:** `67589d5561f3acbbc25ac84c6ed44ae3fc96698d`.
- **Verdict: RETURN** — one blocking finding.
- **Gates:** all tests green, clippy `-D warnings` clean, `fmt --check`
  clean.

## Blocking — `encode` serializes a field-22 ledger its own `decode` rejects

`parse_u64_set` enforces strictly-increasing, duplicate-free entries on
DECODE. On the ENCODE path `check_structure` re-checks exactly that for
the sibling set (field 17, `received_above_high_water`) but **never for
field 22**. `check_high_water` checks only per-element range and length,
`check_application_ledger` uses only `contains`, and `encode_u64_set`
checks only length. So an in-memory state with an out-of-order or
duplicated ledger passes full validation and encodes.

**Reproduced at the exact head:** a ledger of `[3, 2]` (also `[2, 3, 3]`)
with all entries in range makes `encode()` return `Ok` while
`decode()` of encode's own output returns `Err`.

This breaks both contracts `mod.rs` states — "no invalid state can be
serialized through `encode`" and "`decode(encode(state))` round-trips" —
and the failure mode is worse than a refused write: the bad snapshot
**commits durably and the profile bricks at next open**. The façade
happens to keep the ledger sorted today (monotone `push`, `retain`
prune), but the codec is precisely the safety net being certified against
future façade bugs.

**Closure:** mirror the field-17 ordering check for field 22 in
`check_structure`, plus a regression.

## Answers to the six questions

1. **Ledger soundness:** sound to the limit of what a snapshot can
   decide, given the one repair. Both misrepresentation directions were
   reproduced and are inherent to pruning being the ledger's reason to
   exist: a phantom entry UNDERSTATES capacity (recoverable — entries are
   ≤ `last_assigned`, so a receipt can cover them), an omitted entry
   OVERSTATES it (worst case peer skipped-key exhaustion →
   `RekeyRequired` → §4 rebootstrap, recoverable, no confidentiality
   loss). Everything snapshot-decidable IS pinned.
2. **Retired discriminant:** confirmed in code and empirically — bytes
   0, 3, 5, 6, 255 all reject; 4 still decodes; 1/2 are gated by the
   ledger-length matrix. No value aliases a live mode. Gap: no committed
   wire-level splice test.
3. **The removed ceiling — correctly removed; no load-time bound
   belongs in the codec.** Control sends advance the shared sequence at
   up to one per second indefinitely, so the reachable distance is
   unbounded over deployment lifetime: any finite ceiling eventually
   rejects an HONEST state and bricks the profile, which is a worse
   availability failure than the one it prevents. It also stops no
   attacker, who simply picks a value under the ceiling. And it is not
   runtime-inert — the state it rejects is exactly what a long-running
   honest session would next commit, so it is the control-encryption
   deadlock family re-entering through the load path.
4. **Field 22 reuse: safe.** Pre-PASS by policy; structurally
   non-aliasing (the old occupant was a bare 8-byte `u64`, this field is
   `count:u32be + 8×count`, and no 8-byte input parses as a valid set);
   and `SCHEMA_VERSION` gates post-freeze drift. Gap: the wire-amendment
   history in `records.rs` omits the add-revert.
5. **`SCHEMA_VERSION` still 1: acceptable, with a condition.** All three
   layout changes happened while the codec has never been passed and no
   production state exists, so exactly one layout will ever appear under
   version 1. The condition to record: from the first PASS onward, any
   wire change — including in-place retype or position reuse, tolerable
   only pre-PASS — must bump it.
6. **Carried P3: should not block.** Fable wrote the missing case and
   confirmed the behaviour is correct; only the committed pin was
   missing.

## Non-blocking

1. No wire-level test for the retired mode discriminant.
2. No direct splice test for the `control_debt_up_to` accept direction.
3. `records.rs` field-22 doc omits the prior occupant.
4. A peer-signed receipt with `high_water = 0` validates; runtime can
   never accept one, so it is an impossible-snapshot admission.
   Requiring `high_water >= 1` on a present receipt would close it.
5. `control_send_not_before` has no upper sanity bound; a façade bug
   writing a huge value would durably mute the control lane. Unfixable
   in a codec with no trusted `now` — the façade leg owns it.
6. Post-PASS version-bump discipline should be written next to
   `SCHEMA_VERSION`.
