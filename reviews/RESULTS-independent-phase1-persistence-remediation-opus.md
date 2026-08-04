VERDICT: PASS

Reviewer: Claude Opus (independent gate reviewer #1)
Head reviewed: 63fe117847f6839dc0090918d18110deb96368d4
Parent: ea69c07071568cd9a826fd3c99b0bee11801f4a0
Worktree: clean; repository unmodified throughout the review.

## A. Relay hot-journal recovery (src/relay.rs)

- has_nonempty_recovery_companion (relay.rs:618) has exactly one caller,
  preflight_existing_database (relay.rs:602), which itself has one caller,
  Relay::open_at (relay.rs:82).
- Non-empty rollback journal: nonempty_companion(path,"-journal") -> bypass the
  immutable preflight so Connection::open can replay it. Correct.
- Zero-byte companion: nonempty_companion returns metadata.len() > 0, so a
  0-byte -journal or -wal returns false and the immutable preflight still runs.
  Empirically verified (probe_zero_byte_journal / probe_zero_byte_wal): hostile
  db rejected AND the main file byte-identical afterwards.
- Fail-closed on filesystem error: nonempty_companion relay.rs:633 maps any
  non-NotFound error to LabError::Storage; database_header_uses_wal relay.rs:639
  maps File::open failure to Storage and non-EOF read errors to Storage.
  UnexpectedEof returns Ok(false), which fails closed toward performing the
  immutable preflight. Directory-as-path and short (<20 byte) main files both
  fail closed (probe_directory_path, probe_short_main_file).
- WAL deviation (relay.rs:646, header[..16] magic && header[18]==2 &&
  header[19]==2): offsets 18/19 are the file-format write/read versions; SQLite
  persists 2/2 in the MAIN file when a database is converted to WAL mode, and
  1/1 for rollback mode. Empirically confirmed: a relay database (journal_mode
  = DELETE) reads (1,1); a WAL database reads (2,2) (probe_wal_header_bytes).
  The predicate therefore covers every legitimately recoverable WAL state (a WAL
  that SQLite would replay always has a 2/2 main header; a WAL-mode database
  whose main file is still 0 bytes is short-circuited earlier at relay.rs:599),
  and it excludes the malformed-WAL fixture, which is a rollback-mode image with
  a stray -wal: header (1,1) -> no bypass -> immutable preflight -> rejection
  with no mutation. probe_stray_nonempty_wal confirms rejection plus a
  byte-identical main file, and the pre-existing
  malformed_schema_with_wal_artifact_is_rejected_without_target_mutation still
  passes.
- The bypass grants no attacker capability. It is reachable by planting a
  non-empty -journal, but Relay::initialize (relay.rs:101) runs the *same*
  validate_schema_for_open on the live connection, unconditionally, before
  PRAGMA journal_mode/secure_delete (relay.rs:102), before the migration
  transaction (relay.rs:113-114) and before purge_expired_in (relay.rs:115).
  Verified empirically: probe_forged_nonempty_journal_bypasses_preflight_but_
  live_validation_rejects (garbage 8 KiB journal -> preflight skipped -> hostile
  schema still rejected) and probe_wal_mode_hostile_db_with_wal_still_rejected.
  This unconditional second validation is also what makes the check/open TOCTOU
  window non-exploitable: a journal created after the preflight passes still
  lands in front of the live validation.
- Anyone able to plant a -journal beside the database can equally rewrite the
  main file, so the bypass confers no privilege escalation. Journal replay is
  the explicitly reviewed "sole permitted pre-validation filesystem mutation".
- Symlinks: fs::metadata follows links, so is_file() and File::open agree.
  Companion names are built by exact byte-suffix append on the caller-supplied
  path. If the database path is a symlink, SQLite's unixFullPathname may resolve
  it and name the journal after the target, in which case a legitimate hot
  journal would be missed and the torn image would be rejected. That is
  fail-closed (availability, not integrity) and is listed under hardening.
- Non-UTF8 paths: immutable_uri (relay.rs:650) rejects non-UTF8 via to_str(),
  and percent-encodes every other byte, so the preflight cannot be redirected.

## B. Regression strength (tests/relay_schema_upgrade.rs)

- The bulk-delete subprocess writes 64 rows x 40 KiB, then DELETEs all 64 inside
  BEGIN IMMEDIATE and process::abort()s. The test asserts the journal exists and
  is non-empty AND asserts !immutable_integrity_is_ok(&database), i.e. the main
  image really is torn, not merely accompanied by a journal. After
  Relay::open_at, immutable integrity is ok, COUNT(*) = 64, and the journal is
  gone. Genuine crash state, genuine recovery.
- The legacy-migration subprocess reproduces migrate_schema's real legacy branch
  ordering (DELETE FROM messages; DROP TABLE messages; CREATE current messages;
  PRAGMA user_version = 2) and aborts mid-transaction. On reopen the test proves
  recovery-then-migration: user_version 2, messages DDL contains
  sender_signature, and (messages, mailboxes, tombstones, retired_queues) =
  (0, 1, 1, 1), i.e. mailbox/tombstone/retired state survived.
- Both tests genuinely fail on the vulnerable parent. Verified empirically in an
  isolated checkout (/tmp/opus-parent-probe at ea69c07 with only the new test
  file copied in): both new tests FAILED with "Error: Storage"; the other 11
  tests, including the malformed-WAL and hostile-fixture protections, passed.
  Note that the pre-existing single-row hot-journal test passes at the parent,
  so the new large-transaction fixtures are what actually exercise the bug.
- No pre-existing protection was weakened: all 13 relay_schema_upgrade tests
  pass at 63fe117.

## C. Local schema defense (src/persistence/sqlite.rs)

- validate_schema (sqlite.rs:414) now selects the complete UNFILTERED
  sqlite_schema and requires exact equality with a single expected row
  (type=table, name=client_state, tbl_name=client_state, sql=CLIENT_STATE_SQL).
  Any injected object of any type or name makes the vector length 2 and fails.
- validate_table_list (sqlite.rs:486) compares pragma_table_list restricted to
  schema='main' against exactly [(client_state,table,10,0,1),
  (sqlite_schema,table,5,0,0)]. Empirically the clean DDL yields exactly those
  two main rows plus temp.sqlite_temp_schema, which the schema='main' filter
  correctly excludes (SQLite 3.51.3).
- No legitimate internal object is rejected: probe_clean_store_schema_listing_is
  _exactly_minimal shows the DDL materializes exactly one sqlite_schema row.
  slot INTEGER PRIMARY KEY is a rowid alias so there is no sqlite_autoindex; no
  AUTOINCREMENT so no sqlite_sequence; CHECK constraints create no objects.
  strict_whole_schema_validation_accepts_the_clean_store (create -> reopen ->
  commit -> reopen -> read) passes.
- Vulnerable-parent exploit reproduced. In /tmp/opus-parent-probe at ea69c07 I
  injected type='trigger', name='sqlite_evil' on client_state
  (AFTER UPDATE ... DELETE FROM client_state) via writable_schema and bumped
  schema_version. Observed: open_ok=true, commit_ok=true,
  durable_rows_after_commit=0. Open succeeded, commit reported success, and the
  durable row was gone. The old WHERE name NOT LIKE 'sqlite_%' filter was the
  cause.
- The amended implementation rejects it before authentication and before commit:
  open() calls validate_schema at sqlite.rs:149, ahead of read_row (:150) and
  protector.unwrap_dek (:153); commit_inner calls validate_schema at
  sqlite.rs:260, ahead of the UPDATE at :261, so the trigger cannot fire.
  PRAGMA trusted_schema = OFF is already applied in open_connection
  (sqlite.rs:349) before any validation query.
- All four hostile fixtures are covered and pass: DELETE trigger, RAISE(IGNORE)
  trigger, view, and the renamed table with a valid allocated root page.
- Rejection leaves the row byte-identical: each fixture compares all ten columns
  (slot, profile_id, generation, envelope_version, state_schema_version,
  crypto_suite, key_ref, wrapped_dek, nonce, ciphertext) before and after and
  asserts COUNT(*) = 1.
- Pre-injection handle: the delete-trigger test keeps a live store open across
  the injection and asserts store.commit(b"post-injection").is_err() with the
  row still byte-identical. commit_with_rng (sqlite.rs:230) poisons the handle
  on any failure, so no usable stale handle survives.

## Command results at 63fe117 (all exit 0)

cargo test --locked --test relay_schema_upgrade      13 passed, 0 failed
cargo test --locked persistence::sqlite --lib        19 passed, 0 failed
cargo test --locked --all-targets                    7 binaries, all ok, exit 0
cargo clippy --locked --all-targets --all-features -- -D warnings   exit 0, clean
cargo fmt --all -- --check                           exit 0
cargo audit --deny warnings --file Cargo.lock        exit 0, 116 deps, 0 vulns
git diff --check                                     exit 0

## Blockers

None.

## Optional hardening (NOT blockers)

1. relay.rs:628 nonempty_companion builds companion names from the caller path.
   If the database path is a symlink, SQLite may name its journal after the
   resolved target and a legitimate hot journal would be missed. Fail-closed,
   but resolving the path with fs::canonicalize before deriving companion names
   would remove the availability edge.
2. relay.rs:622 checks -journal before -wal unconditionally; a stray non-empty
   -journal beside a WAL-mode database bypasses the preflight needlessly.
   Harmless because of the live re-validation, but gating the -journal branch on
   !database_header_uses_wal would be tighter.
3. sqlite.rs:513 hardcodes sqlite_schema's ncol as 5. This is stable but couples
   validation to a SQLite internal; a comment pinning the expectation to the
   bundled version would help future upgrades.
4. relay.rs:101 runs validate_schema_for_open before PRAGMA trusted_schema = OFF
   at relay.rs:109 (pre-existing, unchanged by this diff). sqlite.rs sets
   trusted_schema OFF first; the relay could match that ordering.
