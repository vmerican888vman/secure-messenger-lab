# Independent review — `PersistentClient` façade, leg D1

Review `secure-messenger-lab` at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Fable and Sol; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own. (Two untracked `reviews/REVIEW-*-v3.md` / `RESULTS-*-v3.md` files from
Fable's codec review may be visible in the worktree; they are expected, committed later — ignore
them, do not open them.)

This is an adversarial review of the first façade leg (`src/persistent/`) implementing Phase-2
design decision §2 (`docs/phase2-design-decisions.md`) for the families that do not require
`ClientPayloadV2`. The remaining §2 families (`stage_send`, `fetch_request`, `accept_envelope`,
ACK, delivery-unknowns) and the §4 platform-key lifecycle manager are explicitly later legs — do not
return this leg merely for their absence. Do return anything in this leg that would make those legs
unsafe to build, and any deviation from §2 not documented as a deviation.

## In scope

- `src/persistent/mod.rs` — the whole leg: ownership, lifecycle, the `Ready`/`Mutating`/
  `ReconcileRequired` state machine, the `mutate()` sequence, staging/install, the D1 operation
  families (`public_identity`, `protection_level`, `prekey_action`, `commit_verified_contact`,
  `establish_outbound_session`, `registration_action`, `record_registration_result`), and
  `DurableAction<T>` token discipline.
- The 2-hunk visibility change in `src/state/mod.rs` (`use` → `pub(crate) use` of the record
  types): zero behavioral change, forced because the façade must construct codec records. Judge
  whether it widens any misuse surface.
- `tests/persistent_client.rs` — 7 integration tests against the public API only.

## §2 claims under review (attack each)

1. `PersistentClient` is non-`Clone`, non-`Sync`, owned by a single actor; it exclusively owns the
   store, decoded state, `Account`, optional `Session`, capability keypairs, binding, inbound
   records and outboxes. No `Account`, `Session`, pickle, `ClientStateV1`, store handle, candidate
   state, mutable capability owner, or reference into façade state can escape any public method.
2. Every mutator follows the frozen sequence: require `Ready`/enter `Mutating`; known bounds
   checks; clone the COMPLETE candidate (state via encode/decode round-trip, crypto via pickle
   round-trips); mutate, cross-validate, serialize, aggregate bounds (via `ClientStateV1::encode`'s
   full validation); commit the complete snapshot; install by infallible moves, artifact only after
   success; pre-commit failure discards to `Ready`; commit/CAS failure enters `ReconcileRequired`,
   which exposes nothing and rejects all operations until drop and reopen.
3. `DurableAction`: every externally transmitted request is returned only after the exact request
   and candidate crypto state committed; result presentation requires the random action token AND
   request digest; generation alone is insufficient — an authentic rollback must reject a newer
   token.
4. `create` (fresh account/mailbox, generation 1, atomic, full re-validation before exposure) and
   `open` (decode + full codec validation + crypto reconstruction) cannot yield a usable handle
   over invalid state.

## Documented decisions (attack these)

- Action token = the freshly minted random registration nonce; request binding = manage signature
  re-verification + SHA-256 over the canonical record; result consumption re-mints the nonce
  (replay rejection). The codec grammar has no token field — this is the chosen encoding.
- Registration terminal markers: Confirmed keeps `valid_until`; Failed re-signs with
  `valid_until = 0`.
- `create`'s re-validation runs through the same committed handle (protector is consumed,
  `P: !Clone`) rather than a physical reopen.
- `PendingPreKey.created_at = 0` (no clock handed to `prekey_action`; codec requires only
  `created_at < valid_until`).
- The mailbox triple is built from raw `Ed25519Keypair` instead of `MailboxOwner` (whose
  constructors are test-gated); identical signing-bytes construction via `pub(crate)` helpers.

## Declared gaps for later legs

Platform-key lifecycle manager (§4); `ClientPayloadV2` and remaining operation families; removal
of the public `OlmClient` mutations and raw store-commit bypasses (§2 final paragraph).

## Required attacks

1. crash/drop and reopen between every pair of mutators: only the last committed state may exist;
2. force commit/CAS failure at each mutator: `ReconcileRequired` must reject everything (except
   non-failing `protection_level`), byte state must be the last committed generation, reopen must
   recover;
3. token confusion: wrong, replayed, cross-action, and cross-client tokens; result presentation
   before any action; a rollback to an earlier generation must not validate a newer token;
4. escape-hatch search: any public method or `Debug` impl leaking secret or mutable interior
   state;
5. expiry/window/signature confusion in `commit_verified_contact` and `establish_outbound_session`
   (wrong pinned identity, expired bundle, too-wide window, signature over wrong bytes, second
   session);
6. re-entrancy and aliasing: nested mutator calls, artifact use-after-failure, staging a candidate
   while `Mutating`.

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Return `PASS` or `RETURN` against the exact head SHA. A `RETURN` must list blocking findings only,
each with a concrete reproduction or source reference.
