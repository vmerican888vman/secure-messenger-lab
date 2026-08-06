# Sol review v4 — ClientStateV1 codec — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), clean detached SHA review.
- **Head SHA reviewed:** `eb9d26f1fe59a9b51fa347b18f0ca45f53985222`.
- **Verdict: RETURN**

## Blocking finding

`check_one_time_key_consistency()` validates OTK uniqueness and
unpublished-map consistency but ignores `next_key_id`. A canonical pickle
can point that counter at an existing retained OTK; the next generation then
selects the occupied ID (`one_time_keys.rs:115`) and silently replaces its
secret (`one_time_keys.rs:105`), potentially invalidating a published OTK
and pending bundle.

**Required remediation:** validate that `next_key_id` cannot collide with
any retained key, and add a regression covering canonical re-pickle equality
plus subsequent key generation.

## Checks that passed

- `cargo test --locked --all-targets`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo fmt --check`

No repository files were changed.
