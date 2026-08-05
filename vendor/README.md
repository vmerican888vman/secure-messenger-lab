# Vendored dependencies

## `vodozemac-0.10.0`

An exact copy of the crates.io `vodozemac` 0.10.0 release with local patches
applied, wired in through `[patch.crates-io]` in the root `Cargo.toml`. The
upstream release remains pinned at `=0.10.0`; the vendored copy keeps that
version so the lockfile still records `0.10.0`.

Every local change is marked in the source with a
`SECURE-MESSENGER-LAB PATCH <nnnn>` comment so the complete delta can be found
with `grep -rn "SECURE-MESSENGER-LAB PATCH" vendor/`.

### Patch 0001 — `Account::contains_one_time_key` — status: UNREVIEWED

`docs/phase2-design-decisions.md` section 3 requires, as an upstream blocker,
a reviewed pinned API:

```rust
pub fn contains_one_time_key(&self, key: Curve25519PublicKey) -> bool
```

that reports membership of a public key in the account's one-time key store
only — never the fallback key store — because a total-count check is
insufficient for the Phase-2 validation step "the exact pending published OTK
private key must still exist".

Upstream 0.10.0 does not expose this. The patch adds the method to
`src/olm/account/mod.rs`, implemented as a lookup in the existing
`key_ids_by_key` map of the `OneTimeKeys` store. It reads state that upstream
already maintains; it changes no behavior of any existing API.

Behavioral checks live in the root crate at `tests/otk_membership.rs` and pin:

- generated one-time keys are found, before and after `mark_keys_as_published`;
- fallback keys are never found;
- keys of a foreign account are not found;
- a one-time key consumed by `create_inbound_session` is no longer found.

The vendored crate's own test suite is not runnable in this environment (its
dev-dependencies build native libolm via cmake), so the behavioral checks live
in the root crate where CI runs them.

This patch must not be treated as an upstream API, must not be submitted
upstream as-is, and remains **UNREVIEWED** until the independent reviewers
(Fable, Sol) sign off on the exact delta. Any further patch to this vendored
copy restarts review for the whole file.
