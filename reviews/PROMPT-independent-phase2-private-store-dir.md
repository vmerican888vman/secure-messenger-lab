# Independent review — Phase 2 private-store boundary (`PrivateStoreDir`)

## Remediation history (v2)

Version 1 (head `09dc706607dc33387097e0eb613b7fe6c67e4747`) was PASSed by
Fable and RETURNED by Sol with four blockers (verdicts in
`reviews/REVIEW-fable-private-store-dir.md` and
`reviews/REVIEW-sol-private-store-dir.md`). The amended head under review now
fixes all four:

1. Companion-only directories (any `-journal/-wal/-shm` with no main) are
   rejected inside the boundary, so no store create can ever observe
   `Absent`+companions (§1's "main and all companions absent" rule).
2. The raw-path store constructors are now `#[cfg(test)] pub(crate)`; the
   path-level hostile-fixture tests moved in-crate (`src/relay/` test
   submodules) so the gate command still exercises them. Normal builds
   contain no path-based store constructor (verified by symbol check).
3. Owner-only now means mode bits AND no extended ACL: macOS uses a minimal
   two-symbol FFI shim (`acl_get_fd`/`acl_free`, detect-only, nothing
   stripped) in `src/private_store_dir/acl.rs` — the crate's only `unsafe`,
   enabled by relaxing `unsafe_code` from `forbid` to `deny` with a scoped
   `#![allow]`; Linux parses `system.posix_acl_access` via rustix (minimal
   mode-equivalent ACL accepted, anything else rejected); other Unix rejects
   unconditionally. Inherited ACLs fail the create path as well.
4. The lifecycle lock is strictly non-blocking again: exactly one
   `flock(LOCK_EX|LOCK_NB)` attempt. The macOS vnode release-lag is handled
   only in tests (a bounded grace helper on immediate drop→reopen sites);
   production documents the transient fail-closed reopen as caller-retryable.

One prior decision is superseded: the bounded `WouldBlock` retry (v1
decision 1) is removed per finding 4. The lock target (flock on the
directory descriptor) is unchanged and was confirmed by both reviewers'
probes.

Review `secure-messenger-lab` at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Fable and Sol; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own.

This is an adversarial review of the `PrivateStoreDir` implementation leg of Phase-2 design decision
§1 (`docs/phase2-design-decisions.md`), including its wiring into both stores. The frozen decision
requires: an enforced private directory; fixed crate-owned basenames; owner-only, same-owner,
single-link regular files; rejection of every symlink/hardlink/device/FIFO/socket/dangling path and
unexpected entry; descriptor-relative or no-follow operations; an exclusive non-blocking lifecycle
lock taken before any database or companion is examined and held for the store's lifetime; split
create (main database and companions absent) from open (existing non-empty regular main file); raw
`Path` constructors private or test-only.

## In scope

- `src/private_store_dir.rs` — the boundary itself.
- `src/persistence/sqlite.rs` and `src/relay.rs` — the wiring: stores own their `PrivateStoreDir`,
  require the correct `StoreKind`, split `create` from `open`, and keep the lifecycle lock for the
  store's lifetime. The raw-path constructors are now `#[cfg(test)]` (`ClientStateStore`) or
  doc-hidden `*_for_test` (`Relay`, needed by the path-level hostile-fixture integration tests).
  Judge whether those escape hatches violate the frozen decision or are acceptable test-only
  surfaces.
- `src/private_store_dir.rs` `create_main_database_file` — `SQLite` creates missing databases
  subject to umask, which would violate owner-only; the boundary pre-creates the main file with
  `O_EXCL` and mode 0600 and relies on `SQLite` propagating the main file's mode to its journals.
  Verify that propagation claim empirically.
- The new `rustix = "=1.1.4"` dependency (safe POSIX wrappers; the crate forbids `unsafe_code`).
- `tests/private_store_dir.rs` and the new `ClientStateStore` unit tests.

## Decisions taken that need explicit scrutiny

1. **Bounded retry on `WouldBlock`.** On macOS, a contended vnode's `flock` release was observed to
   lag the closing of the holding descriptor: an immediate drop-then-relock failed with
   `WouldBlock` while no descriptor in the process referenced the vnode (captured via `/dev/fd`
   scans), only under heavy parallel filesystem churn; 20,000 single-threaded iterations were clean.
   `lock_directory` therefore retries contention up to 10 × 5 ms before failing. The claim under
   review: a legitimate holder keeps its lock for the entire store lifetime, so a 50 ms grace window
   cannot mask real contention and the lock remains non-blocking in the design sense. Attack this
   claim and the implementation.
2. **Lock target.** The lock is taken on the directory descriptor itself (`flock`), chosen over a
   lock file and over `fcntl` record locks (process-scoped; would not detect same-process duplicate
   opens). Confirm `flock` on a directory descriptor has the required cross-process exclusion and
   same-process conflict behavior on macOS, and assess Linux behavior by inspection.
3. **Residual pathname race.** `rusqlite` opens the database by pathname after the boundary's
   descriptor-relative validation. The module documents this as out of scope per §1 (same-UID
   attackers are excluded). Confirm the documentation matches the code and that no *new* attacker
   reachable below same-UID can influence the path that is finally opened.

## Required attacks

Attempt concrete failure sequences for at least:

1. symlink, hardlink, FIFO, socket, device, subdirectory, and unexpected-name entries at every
   expected and unexpected position, including dangling links and lookalike companion names;
2. group/other-accessible or foreign-owned directories, lock files, databases, and companions;
3. racing the create/open split: two stores in one directory, store kind confusion, create over an
   existing database, open of a zero-length or absent database;
4. lock behavior: second live store in the same process, in a second process, reopen after drop,
   reopen after process death, and the documented `WouldBlock` retry window under genuine
   contention;
5. permission propagation: after `create`, restart `open`, and induced journal creation, every file
   in the directory must be owner-only — check with `stat`, not assumptions;
6. TOCTOU between boundary validation and the store's pathname-based `SQLite` open from a thread
   that shares the UID but not the lock (document why it is or is not in scope per §1);
7. error-path resource leaks: every early return between `openat` and handle construction must not
   leak the lock or a descriptor in a way that blocks a later open.

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

plus a repeated-run stability check of `tests/private_store_dir.rs` (it reproduced the release-lag
flake; it must be stable now).

Return `PASS` or `RETURN` against the exact head SHA. A `RETURN` must list blocking findings only,
each with a concrete reproduction or source reference.
