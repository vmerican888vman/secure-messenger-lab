# Independent review — vodozemac patch 0001 (`Account::contains_one_time_key`)

Review `secure-messenger-lab` at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Fable and Sol; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own.

This is an adversarial review of **one local dependency patch only**. The repository vendors the
exact crates.io `vodozemac` 0.10.0 release under `vendor/vodozemac-0.10.0` and selects it with
`[patch.crates-io]`. The complete delta against upstream is a single added method in
`src/olm/account/mod.rs`, marked `SECURE-MESSENGER-LAB PATCH 0001`, plus test and documentation
files outside the vendored crate. Verify that claim before reviewing anything else:

```sh
diff -ru "$(cargo metadata --format-version 1 --no-deps >/dev/null 2>&1; echo ~/.cargo/registry/src/*/vodozemac-0.10.0)" vendor/vodozemac-0.10.0
```

If the delta contains anything beyond patch 0001, or the crates.io source no longer verifies as
authentic 0.10.0, return immediately with that finding.

## Background

`docs/phase2-design-decisions.md` section 3 declares an upstream blocker: the Phase-2
`ClientStateV1` validation must prove "the exact pending published OTK private key must still exist"
in the restored `Account`, and pinned vodozemac 0.10.0 exposes no such membership query. The frozen
design requires a reviewed pinned API with exactly this signature:

```rust
pub fn contains_one_time_key(&self, key: Curve25519PublicKey) -> bool
```

It must inspect only the one-time key store, not fallback keys. A total-count check is explicitly
insufficient.

The implementation is a lookup in `OneTimeKeys::key_ids_by_key`, an existing upstream-maintained
`HashMap<Curve25519PublicKey, KeyId>` covering every one-time key whose private part is still held.
The patch changes no existing upstream code path.

## In scope

- whether `key_ids_by_key` is a complete and accurate index of the one-time key store at every
  mutation point (`insert_secret_key`, `remove_secret_key`, `generate`, unpickling, libolm-compat
  conversion), published and unpublished alike;
- whether any path can leave a private key in `private_keys` without an entry in `key_ids_by_key`
  (false negative) or vice versa (false positive);
- whether fallback keys can ever be reported by this method;
- whether the method can observe a key whose private part was already consumed or evicted;
- whether `key_ids_by_key` rebuild in `From<OneTimeKeysPickle>` can diverge from `private_keys`;
- collision or aliasing hazards from keying by public key (two key IDs, same public key);
- whether the patch alters any observable behavior of the existing upstream API, the pickle format,
  or feature-gated code;
- the `[patch.crates-io]` wiring: version equality, lockfile resolution, and whether any build path
  can still silently select the unpatched crates.io release;
- `tests/otk_membership.rs`: whether the pinned semantics are actually tested, including consumption
  by `create_inbound_session`, and whether the tests could pass against unpatched upstream (they must
  not — the method must not exist there).

## Out of scope

- Phase-2 validation logic that will *consume* this API (reviewed later, with that code);
- the general security of vodozemac, Olm, or the mailbox protocol;
- whether the patch should be submitted upstream (it must not, as-is).

## Required checks

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Attempt to construct, from the public upstream API plus this patch, an `Account` for which
`contains_one_time_key` returns a wrong answer in either direction. Document each attempt and its
outcome, including unpickling adversarial or hand-edited pickles if the pickle format permits
constructing them.

Return `PASS` or `RETURN` against the exact head SHA. A `RETURN` must list blocking findings only,
each with a concrete reproduction or source reference.
