# Fable review — PrivateStoreDir boundary — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), independent.
- **Head SHA reviewed:** `09dc706607dc33387097e0eb613b7fe6c67e4747`
  (detached worktree at the exact SHA).
- **Verdict: PASS** — no blocking findings.
- Full results: `reviews/RESULTS-independent-phase2-private-store-dir-fable.md`.

## Gates

- All 9 test suites green; clippy `-D warnings` clean.
- The flake-prone `private_store_dir` suite ran 40 consecutive times with
  zero deviations.

## Flagged decisions survived attack

- **Bounded retry.** The premise — a legitimate holder holds the lock for the
  store's whole lifetime — is true in the wiring: both stores declare
  `connection` before `_dir`, so drop order closes SQLite before the lock
  releases; there is no window where the lock is free while the database is
  open. Retry success can only mean the prior holder genuinely released (or
  died), making late acquisition correct rather than masked contention. A
  contender against a live holder still fails after a measured 55 ms; a
  SIGKILLed holder's lock releases with the process.
- **Lock target.** Probed directly: `flock` on a directory fd is exclusive; a
  second `open()` in the same process conflicts (the property `fcntl` record
  locks lack); a `dup` doesn't self-conflict; cross-process exclusion works —
  verified at syscall level and through the crate's retry path.

## Other evidence

- Journal-permission propagation verified against the bundled SQLite source
  (libsqlite3-sys 0.37.0) and empirically: 0600 main under umask 022 yields
  0600 companions; a control raw create yields 0644 — proving
  `create_main_database_file` is load-bearing.
- A failed open that takes the lock then rejects a planted entry leaks
  nothing. A socket entry (untested in the suite) is rejected.

## Non-blocking notes (act on eventually)

- The Relay `*_for_test` hatches are `#[doc(hidden)] pub` and compile into
  production builds — acceptable for a `publish = false` lab; should become
  feature-gated in any production crate.
- The future platform adapter must treat a local flock-capable filesystem as
  a hard requirement: Linux-NFS emulates flock via process-scoped POSIX
  locks, which silently kills the same-process duplicate-open guarantee.
