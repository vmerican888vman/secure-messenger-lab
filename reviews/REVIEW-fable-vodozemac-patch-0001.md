# Fable review — vodozemac patch 0001 (`Account::contains_one_time_key`)

- **Reviewer:** Fable (claude-fable-5), independent — Sol's response not seen.
- **Head SHA reviewed:** `d019504d107e492e1286d8515aa11d670a3eba10` (branch `docs/phase2-frozen-decisions`), worktree clean.
- **Verdict: PASS**

## Disclosure

The patch work was uncommitted when this review began; the reviewing session
committed the already-prepared delta as `d019504d` (DCO-signed) to obtain an
exact reviewable SHA, then reviewed it. The reviewer authored none of the
patch content.

## Delta verification

- crates.io `vodozemac-0.10.0.crate` cache verifies against the pre-patch
  lockfile checksum `b98bf83c0992…ae5b` (authentic 0.10.0).
- `diff -ru` of a pristine extraction vs `vendor/vodozemac-0.10.0`: the only
  delta is the patch-0001 method block in `src/olm/account/mod.rs` (+ an inert
  `.cargo-ok` extraction marker). No other file differs.

## Required checks

- `cargo test --locked --all-targets` — all green, including the four
  `tests/otk_membership.rs` tests.
- `cargo clippy --locked --all-targets -- -D warnings` — clean.
- Lockfile: `vodozemac 0.10.0` entry has no `source`/`checksum` (path patch
  selected); no `[[patch.unused]]`; `cargo tree --locked -p vodozemac` resolves
  to `vendor/vodozemac-0.10.0`. Patch version equals the pinned `=0.10.0`
  requirement, so `--locked` builds cannot silently select the registry crate.

## Invariant analysis (`key_ids_by_key` vs `private_keys`)

All mutation points maintain the pair together:

- `insert_secret_key` (used by `generate`, both libolm-compat import sites at
  `mod.rs:820` and `mod.rs:984`) inserts into both; the max-capacity eviction
  removes the map entry keyed by the public key derived from the evicted
  private key.
- `remove_secret_key` (the `create_inbound_session` consumption path) removes
  the map entry first, then the private key — a consumed key can never remain
  observable.
- `From<OneTimeKeysPickle>` rebuilds `key_ids_by_key` exclusively from
  `private_keys`, so every map entry's public key is derived from a held
  private key; `key_ids_by_key` can never contain a key whose private part is
  absent. The unpublished `public_keys` pickle map is not consulted.
- Fallback keys live in the separate `FallbackKeys` store, which the method
  never touches; `fallback_keys.rs` never writes into `OneTimeKeys`.

**False positives (reports a key whose private part is gone): not
constructible** from the public API or from hand-edited pickles.

## Adversarial construction attempts (all documented)

1. **Duplicate secret under two key IDs** (hand-edited JSON `AccountPickle`,
   same secret under key IDs `0` and `999`): membership correctly reports
   `true` while held. After `create_inbound_session` consumes the key,
   membership reports `false` while one private-key copy is still stored —
   a **false negative**, the fail-closed direction for the Phase-2 use.
   Reachable only via adversarial/hand-crafted pickles or libolm import of
   same; unreachable via normal key generation (fresh CSPRNG per key).
   Upstream's own store is identically inconsistent in this state
   (`get_secret_key` also cannot see the survivor). Non-blocking; noted.
2. **Phantom unpublished public key** (entry in pickle `public_keys` with no
   private part): not reported by the method. No false positive.
3. **Published-state divergence** (emptied `public_keys` map): membership
   unaffected, still reported while the private part is held.

## Test-suite adequacy

`tests/otk_membership.rs` pins all four claimed semantics: found before and
after `mark_keys_as_published`, fallback keys never found, foreign keys not
found, and consumption by `create_inbound_session` removes membership. The
tests call `Account::contains_one_time_key`, which does not exist in unpatched
0.10.0 (verified by diff), so they cannot compile — let alone pass — against
the unpatched crate.

## Non-blocking observations

- The aliasing false negative above (adversarial-pickle-only, fail-closed).
- `stored_one_time_key_count` counts `private_keys` entries while membership
  reads `key_ids_by_key`; under the same adversarial aliasing the two can
  disagree. Phase-2 code should not treat count and membership as mutually
  consistent oracles in adversarial-pickle scenarios.
