# Fable confirmation — vodozemac patch 0001 amendment — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), independent — Sol's amended-patch
  response not consulted before forming this verdict.
- **Head SHA reviewed:** `8aa08e01f267b712907224a73816a6c7539b8636` (clean
  detached worktree).
- **Scope:** delta since my v1 PASS at `d019504` — patch-0001 files only
  (`vendor/vodozemac-0.10.0/src/olm/account/mod.rs`, the restored vendored
  `Cargo.lock`, `vendor/README.md`, `tests/otk_membership.rs`). The boundary
  leg commits sharing this range are reviewed separately.
- **Verdict: PASS** — confirmation by delta check, per the one-line protocol
  agreed after v1: a full re-review is not required when the only patch-scope
  change is the remediation of the other reviewer's blocker.

## Delta verification

- crates.io `vodozemac-0.10.0.crate` cache still verifies:
  `b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b`.
- `diff -ru` pristine extraction vs `vendor/vodozemac-0.10.0` at `8aa08e0`:
  the only delta is the amended patch-0001 method block in
  `src/olm/account/mod.rs` (+43 lines). The restored vendored `Cargo.lock`
  is byte-identical to upstream's, so it no longer appears in the diff —
  Sol's v1 blocker is closed exactly, not approximately.
- Lockfile: `vodozemac 0.10.0` entry has no `source`/`checksum` (path patch
  selected), no `[[patch.unused]]`.

## The amendment itself

`contains_one_time_key` now scans the authoritative
`one_time_keys.private_keys` store (`.values().any(|secret|
Curve25519PublicKey::from(secret) == key)`) instead of the derived
`key_ids_by_key` reverse map. Membership is therefore true iff any held
one-time private key corresponds to the queried public key — it cannot
disagree with `stored_one_time_key_count()` in either direction, which
closes Sol's duplicate-secret-alias inconsistency. My v1 analysis of the
same aliasing state (documented as a fail-closed false negative) is
superseded by this strictly stronger property. The O(n) validation-time
cost and the remaining duplicate-secret pickle pathology are documented on
the method; the latter is upstream's unpickling tolerance, out of patch
scope, and correctly delegated to validators.

## Checks run at `8aa08e0`

- `cargo test --locked --all-targets` — all green (full suite; exit 0).
- `cargo clippy --locked --all-targets -- -D warnings` — clean.
- `tests/otk_membership.rs` — 5/5 including
  `duplicate_secret_pickle_membership_stays_consistent_with_held_keys`,
  which pins Sol's exact reproduction (hand-edited pickle, same secret
  under two key IDs, one alias consumed via a real inbound session).
- **Mutation check:** reverting the method body to the old
  `key_ids_by_key.contains_key(&key)` makes that regression test FAIL;
  restoring the amendment makes it pass. The test genuinely discriminates
  the two implementations.

## Non-blocking observation

None new. The duplicate-secret pickle state remains constructible at
unpickle time (upstream tolerance); the method documents that validators
must reject duplicate public keys separately — unchanged from v1 and
correctly scoped out.
