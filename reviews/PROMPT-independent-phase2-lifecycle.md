# Independent review — platform-key lifecycle manager (§4)

Review `secure-messenger-lab` at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Fable and Sol; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own. Committed `reviews/REVIEW-*` files are earlier legs' artifacts — do not
open them before your own verdict.

This is an adversarial review of the platform-key lifecycle manager (`src/lifecycle.rs`), the last
unbuilt component of the frozen design (`docs/phase2-design-decisions.md` §4, "Platform-key
lifecycle"). Prior legs under review or passed are NOT in scope. The manager is not yet wired into
the façade — it vends decisions only; wiring is a later leg. Do not return it for that alone.

## In scope

- `src/lifecycle.rs` — the manager, registry, all transitions, 15 in-crate tests.
- `src/persistence/protector.rs` — the extended `StateKeyProtector` trait (`provision_key`,
  `key_status`, `select_binding`, `delete_key`, `KeyStatus`).
- `src/private_store_dir/mod.rs` — the new `StoreKind::Lifecycle` variant and
  `delete_database_and_companions_synced` (descriptor-relative unlink of the exact basename + three
  companion suffixes, NOENT-tolerant, directory fsync).
- Existing test protectors gained fail-closed stubs — verify they cannot be mistaken for real
  behavior.

## Frozen-design claims under review (attack each, sentence by sentence against §4)

1. Create: non-exportable key + `Provisional` entry atomically; random never-reused aliases/key
   references (the permanent `spent_refs` table); DEK wrapped under `state-wrap/v1` + profile ID +
   key reference; generation 1 written; reopen + full authenticate/parse/validate via the
   provisional handle; exact-state CAS `Provisional -> Expected`; nothing exposed before promotion.
2. Recovery arms: provisional+authentic-gen-1 promotes; provisional+absent ⇒
   `ProvisioningInterrupted` with NO automatic deletion; provisional+unauthentic/mismatched ⇒
   locks; expected+missing/corrupt/unauthentic database or key ⇒ locks and NEVER creates a
   replacement; temporarily-locked platform ⇒ retryable locked state with registry/key/database
   untouched (not persisted).
3. Delete/reset: explicit `DestructiveResetAuth` (not Default/Deserialize-constructible); CAS to
   `Deleting` with fresh reset id; key deleted FIRST; then exact database + allowed companions with
   directory fsync; then registry row; any uncertain step leaves `Deleting` and resumes
   idempotently; no replacement profile while `Deleting`.
4. Abandon: exact provisioning token + exclusive lock + still-Provisional + explicit confirmation;
   no age-based or missing-database automatic cleanup anywhere.
5. Exact-state CAS on every transition (changed-rows==1 against the full prior state), under the
   exclusive lifecycle lock (the registry's own `PrivateStoreDir`).

## Documented decisions / deviations

- `P: Clone` on the manager models "another handle to the same platform adapter" — never a key
  copy.
- `ProvisionOutcome::ProvisionalCreated` is reserved: synchronous create returns `Promoted`;
  interrupted creates surface via `recover`.
- The registry is non-secret by design (unencrypted, exact-schema-validated, inside the boundary).
- Aliases = random profile_id/key_ref; never-reuse enforced by `spent_refs`.
- Known follow-up (flagged, not implemented): façade integration needs the gen-1 payload's
  profile_id/key_ref to equal the minted binding (façade `from_store` checks this) — the wiring leg
  must build the initial state after the mint.

## Required attacks

1. crash between every create substep (the test platform's fail-next flags make these
   deterministic) — every arm must land exactly as §4 requires;
2. registry tampering from a second connection: row flips, row deletion, extra rows, schema
   changes — all must fail closed;
3. CAS races: state changed underneath a transition;
4. reset ordering: database deleted before the key, or registry before the database, must be
   impossible; mid-delete failure leaves `Deleting` and resume completes; create while `Deleting`
   rejects;
5. abandon with wrong/replayed token, on Expected, without the lock;
6. never-reuse: after a full reset, a recreated profile must mint fresh refs;
7. the retryable-locked arm must leave registry, key and database byte-identical.

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Return `PASS` or `RETURN` against the exact head SHA. A `RETURN` must list blocking findings only,
each with a concrete reproduction or source reference.
