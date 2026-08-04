VERDICT: PASS

# Independent security review — secure-messenger-lab commit 63fe117

- Reviewed head: `63fe117847f6839dc0090918d18110deb96368d4` ("Fix hot-journal recovery bypass and hostile sqlite_ schema objects"), parent `ea69c07071568cd9a826fd3c99b0bee11801f4a0`.
- Verdict basis: my own reading of `src/relay.rs`, `src/persistence/sqlite.rs`, `tests/relay_schema_upgrade.rs`, the diff `ea69c07..63fe117`, the authoritative brief `reviews/PROMPT-independent-phase1-persistence-foundation.md`, and my own experiments in scratch dir `/tmp/kimi-parent-probe` (never in the clone). I did not read the other reviewer's results.

## Target A — Relay hot-journal recovery (src/relay.rs)

Code facts (verified by reading):

- `has_nonempty_recovery_companion` (relay.rs:618) has exactly one caller: `preflight_existing_database` (relay.rs:602), which itself is called only from `Relay::open_at` (relay.rs:82) before `Connection::open`.
- Nonempty exact-suffix `-journal` → bypass immutable preflight → normal open performs SQLite rollback-journal recovery. Zero-byte journal (`metadata.len() > 0` is false, relay.rs:632) does NOT bypass; the immutable-inspection path runs unchanged.
- WAL bypass is gated by `database_header_uses_wal` (relay.rs:638): magic `SQLite format 3\0` + header bytes 18/19 both == 2. A stray WAL next to a rollback-mode (1,1) header db stays on the immutable path.
- Fail-closed on filesystem errors: every non-`NotFound` stat error and every non-EOF read/open error maps to `Err(LabError::Storage)` (relay.rs:594, 598, 634, 639, 644). Short reads (<20 bytes) return `Ok(false)` → no bypass → immutable open of the truncated file fails → `Err`.
- Ordering: `initialize` runs `validate_schema_for_open` (relay.rs:101) BEFORE any pragma/migration/purge; `migrate_schema` re-validates (relay.rs:522) before mutating. Validation is authoritative on the post-recovery image, so a bypass can never skip schema/integrity checks — it only lets SQLite recover first.

Empirical probes (scratch: `/tmp/kimi-parent-probe/amended/tests/probe_relay_companions.rs`, 4/4 pass):

1. Malformed db + ZERO-BYTE `-journal` → `Err(Storage)`, main db byte-identical afterward (no bypass, no mutation on rejection path).
2. 10-byte main file + nonempty `-wal` → `Err(Storage)` (short read handled).
3. Fake 30-byte header with WAL magic + (2,2) + nonempty `-wal` → `Err(Storage)`.
4. Genuine crash image: WAL-mode db (header verified (2,2)) + live non-checkpointed WAL containing a committed mailbox insert → `Relay::open_at` succeeds, mailbox row preserved. The predicate covers this legitimate recovery state.
5. Stale garbage nonempty `-journal` next to a valid db → opens fine (SQLite ignores non-hot journals; validation still runs).

Malformed-WAL "no mutation" fixture: cannot be turned into a mutation via the new predicate. The fixture's main header is rollback-mode (1,1), so `database_header_uses_wal` is false and the file takes the untouched immutable path; the pre-existing test `malformed_schema_with_wal_artifact_is_rejected_without_target_mutation` still passes (see suite results). Flipping bytes 18/19 to (2,2) does not help an attacker either: recovery output must still pass the exact-manifest + `integrity_check` + `foreign_key_check` gauntlet before any relay write, and anything beyond that requires crafting a fully valid relay database, which a filesystem-write attacker could do directly anyway.

TOCTOU between the companion check and the open exists but is inherent to path-based preflights against a local filesystem attacker; see Optional hardening.

## Target B — Regression-test strength (tests/relay_schema_upgrade.rs)

- `hot_journal_from_aborted_bulk_delete_recovers_all_current_messages`: seeds 64 × 40 KiB messages (forced page spill), subprocess `DELETE`s all 64 inside `BEGIN IMMEDIATE` then `std::process::abort()`. The test asserts the `-journal` is nonempty AND that the main image is genuinely torn (`!immutable_integrity_is_ok`) before opening — it is not faked. After `Relay::open_at`: integrity ok, all 64 messages restored, journal removed. PASSES at 63fe117.
- `hot_journal_from_aborted_legacy_migration_recovers_then_migrates`: subprocess performs the real mutation order of `migrate_schema` (DELETE → DROP TABLE → CREATE current messages table → `user_version = 2`) inside one immediate transaction, then aborts. Open recovers the legacy image first, validates, then migrates; asserts `user_version == 2`, `sender_signature` in DDL, counts `(messages, mailboxes, tombstones, retired_queues) == (0, 1, 1, 1)`, journal removed. PASSES at 63fe117.
- CRITICAL parent-failure proof (empirical): in `/tmp/kimi-parent-probe` (checkout of `ea69c07` with ONLY the new test file copied in), `cargo test --locked --test relay_schema_upgrade hot_journal_from_aborted` → **both tests FAIL with `Error: Storage`** (`0 passed; 2 failed`). The vulnerable parent rejects exactly these recoverable crash states at the immutable preflight. The tests are genuine regression oracles for B1.
- Pre-existing protections intact: all 13 tests in `relay_schema_upgrade` pass at 63fe117, including `malformed_schema_with_wal_artifact_is_rejected_without_target_mutation`, `hostile_fixture_source_is_immutable_while_disposable_copy_is_rejected`, `integrity_check_rejects_constraint_poison_without_mutation`, and the legacy/constraint fail-closed tests.

## Target C — Local client-state schema defense (src/persistence/sqlite.rs)

- `validate_schema` (sqlite.rs:401) now compares the COMPLETE unfiltered `sqlite_schema` listing (`SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name`, sqlite.rs:415) against exactly one expected `client_state` row. No `sqlite_%` exemption remains.
- `validate_table_list` (sqlite.rs:481) compares the full `pragma_table_list WHERE schema = 'main'` against exactly `client_state(table,10,wr=0,strict=1)` + `sqlite_schema(table,5,0,0)`. Temp-schema built-ins are out of scope of the query; extra views/tables of any name fail the equality.
- No false positives: this DDL (STRICT table, INTEGER PRIMARY KEY rowid alias, no AUTOINCREMENT, no indices, no ANALYZE anywhere in the library) creates no `sqlite_sequence`, no `sqlite_autoindex`, no stats tables. The clean control test `strict_whole_schema_validation_accepts_the_clean_store` (create → reopen → commit → reopen, generation 2) passes, so a normal database is not bricked.
- Exploit reproduction (required, empirical): in `/tmp/kimi-parent-probe` (parent `ea69c07`), my test `tests/exploit_sqlite_evil.rs` injects `CREATE TRIGGER sqlite_evil AFTER UPDATE ON client_state BEGIN DELETE FROM client_state; END` via `writable_schema` + `schema_version` bump. Observed on the parent:
  - `ClientStateStore::open` → **Ok** (exemption hid the trigger),
  - `store.commit(b"post-injection")` on a pre-injection handle → **Ok**,
  - durable `SELECT COUNT(*) FROM client_state` → **0**. Exploit confirmed: silent loss of the authoritative row under a "successful" commit.
- Amended behavior (empirical, same exploit test run against 63fe117 in `/tmp/kimi-parent-probe/amended`): fresh open → `Err(Storage)`; pre-injection handle commit → `Err`; durable row count stays 1. Rejection happens in `validate_schema` at sqlite.rs:149 (open) and sqlite.rs:260 (commit), i.e. BEFORE DEK unwrap/authentication (sqlite.rs:153-161) and BEFORE the UPDATE that would fire the trigger (sqlite.rs:261). The handle is poisoned after the failed commit, so no usable stale handle remains.
- All four hostile fixtures (DELETE trigger, RAISE(IGNORE) trigger, view, renamed table with valid root page) are covered by committed tests that assert rejection AND byte-identical ten-column rows after rejection; all pass (19/19 persistence::sqlite lib tests).
- Byte-identity on the rejection path: `assert_open_rejects_and_row_is_intact` compares the full 10-column row before/after; confirmed passing.

## Required commands (verbatim results, run from /tmp/kimi-smlab-review)

| Command | Result |
|---|---|
| `cargo test --locked --test relay_schema_upgrade` | PASS — `test result: ok. 13 passed; 0 failed; 0 ignored` |
| `cargo test --locked persistence::sqlite --lib` | PASS — `test result: ok. 19 passed; 0 failed; 0 ignored; 3 filtered out` |
| `cargo test --locked --all-targets` | PASS — 7 suites, 53 passed total, 0 failed: lib 22/22, main 0/0, e2e_relay 12/12, expiry_revalidation 2/2, relay_schema_upgrade 13/13, request_boundaries 2/2, state_staging 2/2 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | PASS — exit 0, no warnings |
| `cargo fmt --all -- --check` | PASS — exit 0, no diff |
| `cargo audit --deny warnings --file Cargo.lock` | PASS — exit 0 (cargo-audit installed; 116 dependencies scanned, 1189 advisories loaded, none applicable) |
| `git diff --check` | PASS — exit 0 (empty working tree) |

## Optional hardening (non-blocking; NOT grounds for this verdict)

1. TOCTOU: the companion check and the subsequent `Connection::open` are two separate path-based operations; an attacker with concurrent filesystem write access could swap the journal/WAL in between. fd-based or `O_NOFOLLOW` style hardening would narrow this, but a local concurrent-write attacker is largely outside the stated preflight trust model.
2. A garbage NONEMPTY `-journal` next to a malformed db routes through the normal open; SQLite ignores the non-hot journal and validation still rejects, but SQLite may remove the stray companion file during open (companion-path mutation on a rejection path; the main db is untouched). Worth a comment/test documenting this accepted behavior.
3. `database_header_uses_wal` reads only 20 bytes; it could also sanity-check page size/header fields. SQLite performs authoritative parsing immediately after, so this is defense-in-depth only.
4. The immutable preflight path requires UTF-8 paths (`path.to_str()`), while the companion-bypass path does not; inconsistent but fail-closed.
5. Cosmetic: the commit-range `git diff ea69c07..63fe117 --check` flags "new blank line at EOF" in the committed `reviews/RESULTS-independent-phase1-persistence-foundation-kimi.md` (documentation only; the required working-tree `git diff --check` is clean).

## Clone integrity confirmation

`git status --porcelain` output (empty):

```
```

`git rev-parse HEAD`:

```
63fe117847f6839dc0090918d18110deb96368d4
```

`target/` is gitignored (verified in `.gitignore`); all scratch/probe work was done in `/tmp/kimi-parent-probe`, never in the clone. No commits, staging, stashes, or rewrites were performed.
