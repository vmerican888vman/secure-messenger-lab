# Sol review — façade D2b v11 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), detached worktree
  `sml-review-d2b-v11-sol-b3825fa`, clean at review start and still
  pinned to the SHA at close. A later untracked reviewer artifact was
  left unopened; disposable probe copies were moved to Trash.
  Transcribed from the user's paste.
- **Head SHA reviewed:** `b3825fa30980c797dfad4de3d1a4729c132f3506`.
- **Verdict: RETURN** — two P1 blockers.
- **Gates:** the required test suite, Clippy, formatting and the diff
  check all passed, and both advertised v11 regressions passed. Evidence
  integrity only.

## Blocking findings

### P1-1 — canonical encoding does not eliminate the PreKey/Normal variant alias

After accepting a canonical `PreKey` packet, its inner `Message` can be
canonically serialized as `Normal`, re-signed with a fresh envelope ID,
and bypass raw-digest dedup. Established-session decrypt accepts both
variants and consumes the same inner message key, committing
`RekeyRequired`. Reproduced in a disposable probe. See `src/client.rs:170`,
`src/persistent/mod.rs:1161`, `src/persistent/mod.rs:2169`.

**Closure offered:** deduplicate a semantic identity for the inner Olm
`Message` across both variants while retaining the raw packet digest for
envelope binding. Add a regression asserting no generation, HCR, ratchet,
or mode change for this replay.

### P1-2 — the peer-signal guard bounds concurrency, not lifetime issuance

The "any pending receipt" guard bounds only concurrent receipts. An
authenticated peer can send consecutive high signals; after each
resulting receipt reaches `Stored`, the next signal stages another. A
32-cycle real-relay probe reached `ReceiptLocked` with 32 outstanding
victim receipts and blocked application sends. The existing test only
checks two waves while one receipt remains pending. See
`src/persistent/mod.rs:2479`, `src/persistent/mod.rs:2780`,
`src/persistent/tests.rs:3616`.

**Closure offered:** persistently bound peer-signaled control responses
across `Stored` outcomes; a temporary `Pending` guard is insufficient.
Add the 32 delivery-cycle regression and require the victim to remain
`Ready`.

## Round outcome

Fable returned `PASS` at the same head
(`reviews/REVIEW-fable-facade-d2b-v11.md`); this RETURN carries the round.
Both findings are remediated in v12 — see the v12 history at the top of
`reviews/PROMPT-independent-phase2-facade-d2b.md`.
