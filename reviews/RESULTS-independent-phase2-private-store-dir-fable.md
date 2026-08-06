# Independent review results — Phase 2 private-store boundary (Fable)

Reviewed head: `09dc706607dc33387097e0eb613b7fe6c67e4747`
Reviewed in a detached worktree at that exact SHA; worktree confirmed clean before and after.
Brief: `reviews/PROMPT-independent-phase2-private-store-dir.md`. The other reviewer's response was
not sought or read.

## Verdict: PASS

No blocking findings. Both flagged decisions survive attack. Non-blocking notes at the end.

## Gates

- `cargo test --locked --all-targets` — all 9 suites green (including the 23-test
  `private_store_dir` suite and the store unit tests).
- `cargo clippy --locked --all-targets -- -D warnings` — clean.
- Stability: `cargo test --locked --test private_store_dir` run 40 consecutive times — 40/40 runs,
  23/23 tests, zero deviations. The release-lag flake is gone.

## Decision 1 — bounded 10×5 ms `WouldBlock` retry: claim holds

The claim's load-bearing premise is that a legitimate holder keeps the lock for the store's entire
lifetime. Verified in the wiring, not just the docs: both `ClientStateStore` and `Relay` store the
`PrivateStoreDir` in a `_dir` field declared *after* `connection`, so Rust's declaration-order drop
closes the SQLite connection before the directory descriptor releases the lock. There is no window
in which the lock is free while the database is still open.

Given that premise, the retry can only change the outcome in two situations, and both are correct:

1. **Genuine contention (holder alive).** The contender still fails — it just takes ~50 ms.
   Measured empirically through the crate: a second `open` against a live holder failed after
   55.5 ms (probe asserted bounded within [40 ms, 500 ms)). Nothing is masked; the failure is
   delayed, not converted.
2. **Holder actually gone (close lag or death).** Any `flock` success implies the kernel considers
   every descriptor of the previous holder closed, i.e. the holder's connection is already closed
   (drop order above) or the process is dead. Acquiring a genuinely free lock late is correct
   behavior, not masked contention.

The only theoretical shape where retry changes an outcome semantically — a legitimate holder whose
entire lifetime is shorter than 50 ms — converts a spurious failure into a correct acquisition of a
released lock, which is the intended fix for the measured macOS lag.

Cross-process behavior verified with a probe that re-executes the test binary as a child holding
the lock: the second process fails through the crate's own retry path while the holder lives, and
a SIGKILLed holder's lock is released by the kernel (reopen succeeds immediately after `wait`).

Error paths do not leak the lock: an `open` that takes the lock and then fails entry validation
(planted `intruder` file) drops its only descriptor on the error return; removing the intruder and
reopening succeeds immediately (probed empirically). `rustix::fs::Dir::read_from` was checked at
source (`rustix 1.1.4`, libc backend): it obtains an *independent* description via
`openat(fd, ".")`, never `flock`s it, and closes only its own descriptor — it cannot self-conflict
with or release the lifecycle lock.

## Decision 2 — `flock` on the directory descriptor: confirmed on macOS, sound on Linux by inspection

Kernel-level probe on this machine (macOS, Darwin 25.5.0), directory descriptor:

| Probe | Result |
|---|---|
| `LOCK_EX\|LOCK_NB` on a directory fd | acquired |
| Second `open()` of the same dir, same process | `EWOULDBLOCK` — description-scoped, as the module claims |
| `dup()` of the holding fd | re-lock succeeds (same description, no self-conflict) |
| Forked child | `EWOULDBLOCK` — cross-process exclusion |
| Holder closes fd | immediate relock succeeds (single-threaded; the documented lag needs churn) |
| Holder SIGKILLed | lock released with the process |

This is exactly the behavior the module documentation asserts, and it is why `fcntl` record locks
(process-scoped — the same-process second open would silently succeed) would be wrong here. Linux
by inspection: `flock(2)` accepts any fd including directories, is description-scoped, and returns
`EWOULDBLOCK` under `LOCK_NB` contention; same semantics. (Network-filesystem caveat in the notes.)

## Decision 3 — residual pathname race: documentation matches code

Module docs state the final `rusqlite` open is pathname-based and the gap is a same-UID race,
excluded by §1. Confirmed: `database_path()` is derived only from the canonicalized, validated,
locked directory path plus the crate-fixed basename; no attacker below same-UID (or below control
of a parent path component, which is the pending platform-adapter duty §1 assigns to platform
private storage, documented as not yet done in the module docs) can influence the path. No new
attacker class found.

## Required attacks — results

1. **Hostile entries.** Suite covers symlinked main, dangling symlinked companion, hardlinked main
   (second link outside the dir, so only the `st_nlink` rule can catch it), FIFO at a companion
   name, main-as-directory, subdirectory, unexpected file, lookalike companion (`-wal.bak`),
   foreign-store database, leftover lock file. I additionally probed a **unix socket** at
   `relay.sqlite3-wal`: rejected (macOS refuses `open(2)` on sockets; `fstat` type check backstops
   platforms where it succeeds). Devices are unreachable without root; by inspection the
   `verify_regular_file` type check rejects them. Companion suffix matching is exact
   (`len == base+suffix && starts_with(base) && ends_with(suffix)` — no overlap trick exists at
   those lengths). Case-insensitive-APFS lookalikes (`RELAY.SQLITE3`) fall into the
   unexpected-entry reject arm.
2. **Ownership/permissions.** Group-readable main, group-accessible directory covered by tests;
   foreign-owner rejection is by `st_uid != geteuid()` on `fstat` of the probe descriptor
   (unforgeable without root). Directory mode is made exact with `fchmod` post-create (the
   `DirBuilder` mode can only be narrowed by umask, never widened, and `secure` re-verifies).
3. **Create/open split.** Create over existing path, open of absent path, create racing (O_EXCL on
   the pre-created main under the held lock), zero-length main → `Empty` (both stores refuse),
   store-kind confusion refused both by `kind()` checks and by the foreign basename failing entry
   validation. Two stores in one directory cannot pass validation.
4. **Lock behavior.** Same-process second open, cross-process, reopen-after-drop,
   reopen-after-SIGKILL, bounded-retry timing under genuine contention — all verified empirically
   (suite + probes above).
5. **Permission propagation.** `stat`-checked, not assumed. After boundary create + relay writes +
   restart + more writes: directory 0700, every file 0600. Control probe: a raw SQLite create of a
   fresh database yields 0644 under umask 022 — `create_main_database_file` is load-bearing.
   Journal propagation verified two ways: source inspection of the exact bundled SQLite
   (`libsqlite3-sys 0.37.0` per `Cargo.lock`): `findCreateFileMode` copies the database file's mode
   for `-journal`/`-wal`, and `unixOpenSharedMemory` creates `-shm` with `sStat.st_mode & 0777`
   from the database fd; plus an empirical probe (0600 main under umask 022 → journal, wal, shm all
   0600).
6. **TOCTOU.** In scope-matching order: boundary validation is descriptor-relative throughout;
   the final pathname open is documented as the accepted same-UID residual per §1. Documentation
   and code agree.
7. **Error-path leaks.** Every early return between `openat` and handle construction is RAII
   (`File`-wrapped descriptors); the planted-entry probe confirms a failed open blocks nothing.

## Escape hatches — judged acceptable, with an asymmetry note

`ClientStateStore`'s raw-path constructors are `#[cfg(test)]` — absent from production builds;
fully compliant. `Relay::open_with_path_for_test` / `open_at_with_path_for_test` are
`#[doc(hidden)] pub` because the path-level hostile-fixture integration tests
(`e2e_relay.rs`, `relay_schema_upgrade.rs`) genuinely need raw paths and integration tests can
only see `pub` items. That is not strictly "private or test-only" — the symbols compile into
production builds. For a `publish = false` lab crate with the intent documented on the functions,
this is acceptable; it should not survive into a production crate without a feature gate
(e.g. `#[cfg(feature = "hostile-fixtures")]`, with the gate wired into the CI test invocation).

## Non-blocking notes

1. **Relay hatch asymmetry** — see above. Also, the in-crate `capability.rs` unit test uses the
   doc-hidden hatch where a `#[cfg(test)]` path would do; cosmetic.
2. **Network filesystems.** On Linux-NFS, `flock` is emulated over POSIX record locks:
   process-scoped, so the same-process duplicate-open guarantee silently disappears; some SMB
   mounts drop `flock` entirely. Fine today because §1 assigns platform-private *local* storage to
   the (pending) platform adapter, and the module documents that duty as not yet done — but the
   adapter must treat "local, flock-capable filesystem" as a hard requirement, not a default.
3. **macOS ACLs.** `st_mode & 0o077 == 0` does not preclude an ACL granting another user access;
   ACLs are invisible to `fstat` mode bits. Setting an ACL on the user's own directory requires
   the user (or same-UID code, excluded) or root (excluded); noted only so the check is not later
   believed stronger than it is.
4. **Retry arithmetic.** "10 × 5 ms" is 10 attempts with 9 inter-attempt sleeps ≈ 45 ms of sleep;
   measured wall time ~55 ms. The module text ("10 attempts, 5 ms apart") is accurate; the commit
   message's "up to 10x5ms" rounds it. Cosmetic.
5. **Empty-main brick.** A crash between `create_main_database_file` and the first committed write
   leaves a zero-length main; thereafter both create and open refuse forever (manual directory
   removal required). This is exactly what the frozen decision demands (`Empty` is unexpected
   leftover state), but it is an operational fact the future platform adapter should surface as a
   distinguishable condition rather than a generic storage error.
