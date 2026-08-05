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
`src/olm/account/mod.rs`.

**Amended after Sol's review of `df53995` (RETURN).** The first implementation
consulted the derived `key_ids_by_key` reverse map, which collapses duplicate
public keys: a hand-edited pickle holding the same secret under two key IDs
produced an inconsistent oracle after one alias was consumed (membership
`false` while `stored_one_time_key_count() == 1`). The method now derives its
answer only from the authoritative `private_keys` store — membership is true
if and only if ANY held one-time private key corresponds to the given public
key — so it cannot disagree with the store in either direction. It changes no
behavior of any existing upstream API. The pathological duplicate-secret
state itself (upstream's unpickling tolerates it and leaves an unconsumable
copy) is documented on the method; validators that care must reject duplicate
public keys separately.

Behavioral checks live in the root crate at `tests/otk_membership.rs` and pin:

- generated one-time keys are found, before and after `mark_keys_as_published`;
- fallback keys are never found;
- keys of a foreign account are not found;
- a one-time key consumed by `create_inbound_session` is no longer found;
- a duplicate-secret pickle keeps membership consistent with the held private
  keys through consumption of one alias (Sol's reproduction).

The vendored crate's own test suite is not runnable in this environment (its
dev-dependencies build native libolm via cmake), so the behavioral checks live
in the root crate where CI runs them.

This patch must not be treated as an upstream API, must not be submitted
upstream as-is, and remains **UNREVIEWED** until the independent reviewers
(Fable, Sol) sign off on the exact delta. Any further patch to this vendored
copy restarts review for the whole file.
