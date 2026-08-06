# Sol review — PrivateStoreDir boundary — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), independent.
- **Head SHA reviewed:** `09dc706607dc33387097e0eb613b7fe6c67e4747`.
- **Verdict: RETURN**

## Blocking findings

1. **Companion-only directories pass as `Absent`**; both stores then create
   over a pre-existing `-journal/-wal/-shm`, violating §1's "main and all
   companions absent" create rule.
2. **`Relay::open*_with_path_for_test` is public in normal builds.**
   `#[doc(hidden)]` is not test-only; an external probe opened a valid relay
   from a `0755` directory without the boundary or lifecycle lock.
3. **macOS ACLs bypass owner-only checks.** A directory with mode `0700` plus
   `everyone allow` ACL was accepted; inherited ACLs also survive the
   `fchmod(0700)` create path.
4. **The `WouldBlock` retry is not non-blocking as claimed**: a live holder
   released after 18 ms and the contender succeeded after ~24 ms. It cannot
   distinguish real contention from vnode release lag (and implements nine
   5 ms sleeps, ~45 ms, not 10×5 ms).

## Checks that passed

- `cargo test --locked --all-targets` (92 tests); Clippy.
- `tests/private_store_dir.rs` stable 100/100.
- Directory-descriptor `flock` correct across same-/cross-process opens and
  after drop/death.
- SQLite propagated precreated `0600` mode to journal/WAL/SHM under
  `umask 000`.

(Fable independently PASSed the same head; see
`reviews/REVIEW-fable-private-store-dir.md` and the RESULTS file.)
