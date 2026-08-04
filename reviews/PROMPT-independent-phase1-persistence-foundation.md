# Independent implementation review — encrypted persistence foundation

Review `secure-messenger-lab` draft PR #7 at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Kimi and Fable; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own.

This is an adversarial code review of the **first implementation leg only**. The independently passed
design authorizes a disposable persistence spike. This PR intentionally implements the relay-schema
prerequisite and encrypted opaque-state foundation before the semantic Olm/account/outbox state
machines. Do not return it merely because those later, explicitly scoped-out state machines are not in
this PR. Do return any interface or primitive flaw that would make safely building that next leg
impossible or require a storage-format break.

## In scope

- exact relay current/legacy `SQLite` manifest classification, hostile-fixture preflight, migration,
  integrity checks, and valid hot rollback-journal recovery;
- direct exact dependency pins and the XChaCha20-Poly1305 envelope;
- canonical AAD and every authenticated header field;
- fresh random nonce behavior, RNG failure, the 8 MiB ciphertext limit, and the explicit authentic
  snapshot rollback limitation;
- `StateKeyProtector`, independently stored expected `(profile_id, key_ref)` binding, no plaintext
  fallback, lowest-claim protection reporting, and test-only software protection;
- one-row local STRICT schema, atomic generation-1 creation, full authenticated-row CAS, commit/install
  ordering, poison/reopen behavior, and pre-materialization BLOB limits;
- forced-process-death, corruption, substitution, concurrency, redaction, canary, and schema tests;
  and
- whether the public foundation API permits a future caller to bypass any invariant above.

## Required attacks

Attempt concrete failure sequences for at least:

1. profile-A/profile-B database or wrapped-key substitution;
2. changing any authenticated row field between open and commit;
3. crash after each creation/write substep and uncertain commit;
4. nonce reuse after restoring an authentic old snapshot;
5. malformed/future/legacy/hybrid schemas, extra objects, stripped constraints, WAL/journal artifacts,
   and a legitimate hot journal;
6. cap-plus-one BLOBs before allocation or authentication;
7. plaintext, DEK, raw state, capability, or diagnostic leakage through files, journals, errors,
   `Debug`, test helpers, or production-selectable fallbacks; and
8. Rust/API behavior that leaves a usable stale handle after any conflict or storage failure.

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo audit --deny warnings --file Cargo.lock
```

Inspect the pinned crate sources when a dependency behavior matters. Passing tests are evidence, not a
substitute for code-path review. Keep the repository unchanged.

## Response contract

Return exactly one gate verdict:

- **PASS** — no blocking defect in this foundation; or
- **RETURN** — one or more concrete blocking defects.

For every RETURN item, provide the exact failure sequence, affected file/line, violated reviewed
invariant, and minimum correction plus regression oracle. Separate optional hardening from blockers.
State the exact head reviewed and the commands/results you actually verified.

A PASS authorizes work on the next semantic persistence leg only. It does not approve the complete
persistence spike, a production app, public network relay, or public security claim.
