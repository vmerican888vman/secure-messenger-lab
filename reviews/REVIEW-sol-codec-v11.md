# Sol review — client-state codec v11 — VERDICT: RETURN

- **Reviewer:** Sol (gpt-5.6-sol), worktree
  `sml-review-codec-v11-sol-cc33eba`, detached, exact and clean. No
  `reviews/REVIEW-*` artifact opened. Codec-only; the façade leg was not
  re-reviewed. Transcribed from the user's paste.
- **Head SHA reviewed:** `cc33eba28070048af95bd4a6f45874ba0352b74f`.
- **Verdict: RETURN** — one P1, one P2.
- **Gates:** 289 tests, clippy `-D warnings`, diff check all passed.

**Confirmed good:** the implementation otherwise enforces global digest
uniqueness and the commitment field/matrix correctly.

## P1 — the closure's ORDERING is incomplete

Encode consumes `kind` for the lane quotas before verifying
`metadata_commitment`; decode calls the kind-dependent `arms_consistent`
before verification. Both paths fail closed TODAY, but that contradicts
the explicitly frozen "verify before anything relies on kind" ordering.

Note this is the same spot Fable examined and judged sound on exactly the
"it fails closed" reasoning. Sol's point is stronger and is the one that
governs: failing closed is a property of today's control flow, not of the
contract, and it stops holding silently the moment a kind-dependent
branch returns anything but an error.

**Closure:** move commitment verification ahead of both uses.

## P2 — the retired-twin regression is nondeterministic

`duplicate_inner_message_digest_is_rejected` does not reliably create two
retired-epoch records. The fixture sorts a RANDOM current-epoch record
against a fixed retired one, and the test then selected `.first()` —
usually the current record. It therefore usually tested current+retired,
so **a future retired-retired exemption could escape it entirely.**

**Closure:** select the retired source deterministically, or construct
two explicit retired records, and assert both epochs before the
accept/reject arms.

## Closure status

Both fixed in v12:

- Commitment verification is hoisted to the top of `check_structure`,
  ahead of the quota counting, and ahead of `arms_consistent` in
  `SendRecord::parse`. The property is now structural rather than
  incidental.
- The regression selects its source record by EPOCH, not position, and
  asserts both twins are retired-epoch before the arms. Verified against
  the exact escape Sol named: adding a hypothetical retired-epoch
  exemption to the uniqueness check fails the test deterministically
  (three runs of three), and five consecutive runs pass at head.
