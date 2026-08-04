# Fable implementation review — encrypted persistence foundation (PR #7)

Reviewed head: `ea69c07071568cd9a826fd3c99b0bee11801f4a0`
Reviewer: Fable (independent fresh-context agent, 2026-08-05). Kimi's implementation review is separate and was not shared with this reviewer.

---

## Gate verdict: **RETURN**

Exact head reviewed: `ea69c07071568cd9a826fd3c99b0bee11801f4a0` (verified `git rev-parse HEAD`, worktree clean, reviewed in a private clone; `/Users/new/Cursor local/secure-messenger-lab` left untouched at the same SHA with no working-tree changes).

One blocking defect. It is in the relay-schema prerequisite leg, not the encrypted foundation — the encrypted foundation survived every attack I ran.

---

# BLOCKER 1 — The immutable startup preflight permanently bricks a relay whose recovery requires the hot rollback journal

**File/line:** `src/relay.rs:589-607` (`preflight_existing_database`), reached from `src/relay.rs:81-85` (`Relay::open_at`), using `src/relay.rs:609-624` (`immutable_uri`).

**Violated reviewed invariant:** `docs/persistence-spike-design.md:242-247` — *"Production startup uses normal SQLite recovery. A hot rollback journal may be applied before schema validation so a valid commit interrupted by process death remains recoverable... A separate valid exact-schema hot-journal test proves normal recovery rather than pretending `immutable=1` models it."* The implementation places `immutable=1` — which by definition makes SQLite ignore journals — directly in the production startup path. The code's own doc comment at `src/relay.rs:586-588` states the intended behaviour ("A later normal open may recover a valid hot journal; that is the sole permitted pre-validation filesystem mutation") and the implementation contradicts it: the preflight returns a terminal verdict from the *pre-recovery* image, so the "later normal open" never happens.

**Exact failure sequence (deterministic, reproduced 3/3 in two independent forms):**

*Form A — ordinary operation, current schema.* This is the shape of `purge_expired_in` (`src/relay.rs:913-930`), which runs on every open and every register/enqueue/fetch/ack/delete.
1. `Relay::open_at` creates a valid current-schema relay; one mailbox and 64 queued envelopes are stored.
2. A process runs `BEGIN IMMEDIATE; DELETE FROM messages WHERE expires_at <= ?` and is killed before `COMMIT`, after SQLite has spilled dirty pages into the main database file.
3. The main file is now torn; a valid hot `-journal` sits beside it. This is precisely the state rollback recovery exists for.
4. Restart → `Relay::open_at` → `preflight_existing_database` opens `file:...?mode=ro&immutable=1`, so SQLite ignores the journal → `validate_schema_for_open` → `validate_database_integrity` → `PRAGMA integrity_check` on the journal-ignoring image reports corruption → `Err(LabError::Storage)`.
5. No normal connection is ever opened, so the journal is never rolled back and never removed. Every subsequent start repeats step 4 identically. Observed: `ATTEMPT 0/1/2: relay_open_ok=false journal_present=true`.
6. A byte-identical copy of the same database plus journal, handed to a plain SQLite open, recovers cleanly: `integrity_check = ok`, all 64 messages restored, and `Relay::open_at` on that recovered copy **succeeds**. The data was recoverable the whole time; only the application refuses.

*Form B — crash during the legacy→current migration this PR adds.* Same sequence with the child executing the exact statements of `migrate_schema`'s legacy arm (`src/relay.rs:545-553`: `DELETE FROM messages` / `DROP TABLE messages` / `CREATE TABLE messages` / `user_version=2`). Immutable view: `user_version=0`, legacy `messages` shape, `integrity_check` → `*** in database main *** / Tree 4 page 33 cell 0: Rowid 64 out of order / 2nd reference to page 644 / overflow list length is 1 but should be 9 / Page 15..31: never used`. Normal recovery on a byte-identical copy: `user_version=0, integrity=ok, rows=64`, and `Relay::open_at` on the recovered copy succeeds. The live database: refused forever.

**Why the existing test does not catch it:** `tests/relay_schema_upgrade.rs:379-427` (`valid_hot_rollback_journal_recovers_complete_pretransaction_state`) interrupts a *single-row* `UPDATE mailboxes SET created_at = created_at + 1`. That leaves the pre-recovery image self-consistent, so the immutable preflight happens to pass and normal recovery then runs. It therefore proves recovery only for the one case where recovery was not actually gated. It never exercises a torn multi-page image — the definitional case for needing a rollback journal.

**Reproduction note, stated honestly:** my child processes set `PRAGMA cache_size = 1; cache_spill = ON` to force the spill deterministically. That is not an invented condition — it is the identical technique this repo's own hot-journal test uses (`tests/relay_schema_upgrade.rs:31-32`), and pre-commit spill is normal SQLite behaviour whenever a transaction's dirty set exceeds the page cache. This relay accepts 1 MiB packets (`MAX_PACKET_BYTES`, `src/relay.rs:15`) with no queue-depth bound and purges in a single transaction, so multi-megabyte write transactions are expected. With the default 2000-page cache and 57 MB of churn I did *not* reproduce it in three attempts, so the practical frequency is load-dependent — but the defect is not a frequency question. Whenever the pre-rollback image is not a valid schema/integrity image, the relay is unrecoverable by design of this code path, and that is exactly the class the invariant covers.

**Minimum correction:** Do not let the immutable inspection produce a terminal verdict when journal-based recovery is still possible. The smallest correct change: in `preflight_existing_database`, if a non-empty `<path>-journal` or `<path>-wal` companion exists, skip the immutable inspection and fall through to the normal open. This loses nothing, because the authoritative fail-closed check already runs on the real connection at `src/relay.rs:101` (`validate_schema_for_open`) and again inside `migrate_schema` (`src/relay.rs:522`), both strictly before `journal_mode` is changed and before any application write. Dropping the immutable preflight entirely is equally acceptable and matches the design's placement of `immutable=1` in *test fixture inspection*, with hostile-fixture byte-preservation guaranteed by tests using disposable working copies — which `hostile_fixture_source_is_immutable_while_disposable_copy_is_rejected` already does.

**Regression oracle (must fail before the fix, pass after):**
1. Build a current-schema relay database via `Relay::open_at` with one mailbox and ≥64 large (≈40 KB) envelopes.
2. Subprocess: `PRAGMA journal_mode=DELETE; synchronous=FULL; cache_size=1; cache_spill=ON; BEGIN IMMEDIATE; DELETE FROM messages WHERE expires_at <= ?;` then `std::process::abort()`.
3. Assert `<path>-journal` exists and is non-empty.
4. Assert that an `immutable=1` read-only view of the main file reports `PRAGMA integrity_check != "ok"` — this pins the torn pre-recovery image, so the test cannot silently degrade into the current one-row case.
5. Assert `Relay::open_at(&database, NOW).is_ok()`, that `PRAGMA integrity_check == "ok"` afterwards, that the pre-transaction 64 messages are present, and that the journal is gone.
6. Repeat the same test with the legacy→current migration statements in step 2, asserting recovery to the legacy shape followed by a successful migration to `user_version = 2`.
7. Keep `hostile_fixture_source_is_immutable_while_disposable_copy_is_rejected` and `malformed_schema_with_wal_artifact_is_rejected_without_target_mutation` green so the fix cannot be made by weakening hostile-fixture rejection.

---

## What I attacked and could not break (all eight required attacks)

The encrypted persistence foundation itself held under every sequence I ran. Recording these so the fix does not get over-scoped.

1. **Profile-A/B database or wrapped-key substitution** — all four variants rejected: whole-file B-as-A, full row copy (`profile_id`, `key_ref`, `wrapped_dek`, `nonce`, `ciphertext`) from B into A's file, wrapped-key-only swap, and a generation bump to 99 with `ignore_check_constraints=ON`. Defense is layered correctly: the binding is read from the protector *before* any database byte is trusted (`src/persistence/sqlite.rs:144`), `read_row` cross-checks stored `profile_id`/`key_ref` against it (`sqlite.rs:610-614`), and the AAD independently binds `profile_id`, `key_ref`, `generation`, and `SHA-256(wrapped_dek)` (`envelope.rs:102-120`).
2. **Changing any authenticated row field between open and commit** — the CAS `WHERE` clause covers all ten columns (`sqlite.rs:263-281`), `validate_schema` runs inside the same `IMMEDIATE` transaction (`sqlite.rs:260`), and `changed != 1` poisons. The PR's own wrapper/nonce/ciphertext substitution tests confirm the on-disk row is left byte-identical after refusal.
3. **Crash after each creation/write substep** — `create_after_schema`, `create_after_insert`, `create_after_commit`, `commit_after_seal`, `commit_after_update`, `commit_after_commit`, driven by real `std::process::abort()` in a subprocess. Every outcome is a complete old or complete new row; failpoints are `#[cfg(test)]` only, so no production abort path or env-var-selectable behaviour ships.
4. **Nonce reuse after authentic snapshot rollback** — nonce is freshly drawn per commit from `OsRng` and never derived from `(DEK, generation)` (`sqlite.rs:238-239`, and the explicit comment at `envelope.rs:24-27`). The rollback limitation is asserted as a limitation, not a property. RNG failure aborts the write and leaves the file byte-identical.
5. **Malformed/future/legacy/hybrid schemas, extra objects, stripped constraints, WAL/journal artifacts** — the relay's full-manifest comparison (`sqlite_schema` rows, `table_list` strictness, ordered `table_xinfo`, index shape, `foreign_key_list`, `foreign_key_check`, `integrity_check`) is genuinely exact and rejects `(2, Legacy)`, `(1, Current)`, an added trigger, and constraint-poisoned rows without mutation. The local store's `validate_schema` byte-compares the canonical DDL string. *(The legitimate hot-journal case is Blocker 1.)*
6. **Cap-plus-one BLOBs** — `read_row` queries all nine `length(...)` values first and rejects before materializing, inside the same read transaction as the value read, so there is no TOCTOU window. `seal` rejects `plaintext_len > 8 MiB − 16` before `encrypt`. Exact-cap succeeds; cap-plus-one fails and leaves a zero-object database.
7. **Leakage** — three distinct canaries do not appear in `Debug`, `Display`, error text, or any file in the database directory after create/commit/reopen. `LabError::Storage` is a single coarse variant. `ProfileBinding`'s `Debug` is hand-redacted. The pinned `chacha20poly1305 0.10.1` zeroizes its key on drop unconditionally (`src/lib.rs:292-301`). Converting a store file to WAL out-of-band is silently normalized back to `delete` before any commit and leaves no `-wal` residue. No production-selectable software protector exists — `TestProtector` lives inside `#[cfg(test)] mod tests`.
8. **Stale handle after conflict or storage failure** — any `commit` error sets `poisoned`, and `state()`, `generation()`, `binding()` all gate on it. A losing concurrent writer is left with a dead handle and the winner's row intact.

**Public API bypass check:** `ClientStateStore` exposes no way to write without the CAS, no way to read state without authentication, no constructor from raw parts, and no production-reachable RNG injection (`create_with_rng`/`commit_with_rng` are private; `RandomSource` is private). `ProfileBinding::new` is public but the store only ever consumes `protector.expected_binding()`.

**Dependency pins:** all seven direct dependencies are `=`-pinned, `chacha20poly1305 = "=0.10.1"` is a direct dependency as the design required, `unsafe_code = "forbid"`, and `unwrap_used`/`expect_used`/`panic` are `deny`.

---

## Optional hardening (not blocking, no storage-format impact)

1. **`commit` poisons on refusals where nothing was written** — `src/persistence/sqlite.rs:225-234`. An 8 MiB oversize refusal or an RNG failure kills the handle even though no transaction was opened. I verified the on-disk invariant still holds (file byte-identical, reopen yields the pre-refusal state at the original generation), and the next leg is required by design to enforce the 8 MiB bound *before* calling `commit`, so this is not a blocker. But `docs/persistence-spike-design.md:449-458` frames capacity refusal as routine backpressure where "every earlier pending record [is] still present and completable"; classifying a pre-transaction refusal as an uncertain commit forces a full profile reload for a normal outcome. Consider returning refusals that provably performed no write without setting `poisoned`.
2. **`ProtectionLevel` lowest-claim policy is documentation only** — `src/persistence/protector.rs:43-51`. The rule that `Indeterminate` must never rank above `SoftwareBacked` is a prose comment with no method, no ordering, and no test. Add `fn permits_hardware_claim(&self) -> bool` returning `false` for both, plus a test asserting all four variants, before any adapter or UI consumes this.
3. **The DEK crosses the public trait boundary as `Zeroizing<[u8; 32]>`** — `protector.rs:77` and `:86`. That type is `Debug`-printable, so a third-party protector can format the raw key. The design requires secret-bearing wrappers to prohibit derived `Debug`. A `StateKeyMaterial` newtype with a redacted `Debug` closes it without changing behaviour. Related: `unwrap_dek`'s `&mut` output contract does not require the buffer to be fully written; a partial write yields a partly-zero DEK (harmless — AEAD then fails — but worth stating in the trait contract).
4. **No `busy_timeout` on the local store connection** — `sqlite.rs:345-356`. The relay sets 2 s (`relay.rs:98`); the local store sets none, so transient `SQLITE_BUSY` from any second opener immediately and permanently poisons the handle. Fail-closed and consistent with the one-writer design, but a small timeout would avoid a needless profile reload.
5. **`journal_mode` result is never checked** — `sqlite.rs:358-368`. `PRAGMA journal_mode = DELETE` returns the resulting mode and cannot convert a WAL database while another connection is attached; `execute_batch` discards the row, so the store could silently keep operating in WAL. Confirmed harmless in the single-connection case I tested (it converts correctly and removes the `-wal`), but reading back and asserting `delete` would make the design's "rollback-journal mode for this spike" an enforced property.
6. **Local schema validation tolerates `sqlite_*` objects** — `sqlite.rs:412` filters `name NOT LIKE 'sqlite_%'` and `sqlite.rs:503-505` skips `sqlite_` prefixes, so an `ANALYZE`-created `sqlite_stat1`/`sqlite_stat4` is accepted. The relay's manifest rejects them. Harmless today (planner-only, `trusted_schema=OFF`) but the two layers should agree.
7. **`create_with_rng` copies caller state before validating its length** — `sqlite.rs:84-85`. `state.to_vec()` runs before `seal`'s bound check. Checking `state.len()` first avoids a 2× allocation on a cap-plus-one input.
8. **`protection_level()` answers on a poisoned handle** — `sqlite.rs:208-211`. Non-secret, but it lets a caller report a hardware-protection claim for a dead handle.

---

## Commands run and results

All in the private clone at `ea69c07071568cd9a826fd3c99b0bee11801f4a0`; adversarial probes in a separate copy so the reviewed tree stayed pristine.

| Command | Result |
|---|---|
| `git rev-parse HEAD` | `ea69c07071568cd9a826fd3c99b0bee11801f4a0` |
| `git status --porcelain` | empty (clean, before and after review) |
| `cargo test --locked --all-targets` | **PASS** — 46 tests green (17 + 12 + 11 + 2 + 2 + 2, 0 failed) |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | **PASS** — exit 0, no diagnostics |
| `cargo fmt --all -- --check` | **PASS** — exit 0 |
| `cargo audit --deny warnings --file Cargo.lock` | **PASS** — exit 0, 116 crates, 1189 advisories loaded, 0 findings |
| Probe: crash during legacy→current migration commit | **BRICK** — relay refuses forever (3/3); normal recovery on byte-identical copy restores `integrity=ok`, 64 rows, and opens successfully |
| Probe: crash during bulk `purge_expired`-shaped DELETE | **BRICK** — relay refuses forever (3/3); recovered copy opens successfully |
| Probe: crash during bulk INSERT (default cache) | no brick — pre-recovery image stayed self-consistent |
| Probe: crash during bulk DELETE/UPDATE (default cache, 57 MB) | no brick in 3 attempts — load-dependent, see reproduction note |
| Probe: cross-profile whole-file / row / wrapped-key / generation substitution | all four correctly **rejected** |
| Probe: WAL-mode local store file | accepted, converted to `delete`, no `-wal` residue |
| Probe: oversize commit | refused, file byte-identical, reopen yields pre-refusal state at generation 1 |
| Probe: stale-handle Debug + protection level after poison | state redacted, `poisoned: true` surfaced |
| Inspected pinned source `chacha20poly1305-0.10.1/src/lib.rs:292-301` | key zeroized on drop unconditionally |

Both repositories were verified unchanged at the end: review clone clean at the exact head, and `/Users/new/Cursor local/secure-messenger-lab` at `ea69c07` with no working-tree modifications.

**Scope of this verdict:** RETURN on the relay-schema prerequisite only. The encrypted opaque-state foundation — envelope, AAD, binding, CAS, bounds, poisoning, redaction, forced-death behaviour — is sound as reviewed and I found no interface or primitive flaw that would obstruct the next semantic leg or force a storage-format break. Fix Blocker 1 and add its regression oracle, and this reads as a PASS-shaped foundation. A future PASS would authorize only the next semantic persistence leg — not the complete spike, a production app, a public network relay, or any public security claim.
