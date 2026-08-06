# Independent review — `PersistentClient` façade, leg D1, v2 delta (Fable)

Reviewed head: `143445294c7a88439ba0f8e84d2bf49c65ac0d94`
("Remediate the five facade D1 blockers from Sol's review").

Delta review: Fable's v1 review (`reviews/REVIEW-fable-facade-d1.md`, RETURN
at `7325735`) covered the whole leg; this pass reviews the remediation
commit (`src/persistent/mod.rs`, `src/persistent/tests.rs`,
`tests/persistent_client.rs`) as new attack surface, verifies the
disposition of every v1 finding, and re-runs the required attacks the delta
touched. `git rev-parse HEAD` confirmed; no tracked files modified
(untracked `reviews/*` only).

Gates at this head, from the repo root:

- `cargo test --locked --all-targets` — 182 passed, 0 failed
  (lib 127, e2e_relay 7, expiry_revalidation 2, otk_membership 5,
  persistent_client 8, private_store_dir 29, request_boundaries 2,
  state_staging 2; plus the subprocess abort-harness re-executions, all ok).
- `cargo clippy --locked --all-targets -- -D warnings` — clean.

## Verdict: PASS

No blocking findings. Fable's v1 blocker is genuinely fixed, all four v1
non-blocking observations are resolved as a side effect of the remediation,
and each of the five remediation changes held under adversarial re-review.

---

## A. Fable's v1 blocker — embedded generation frozen at 1: FIXED

- `pre_commit` (src/persistent/mod.rs:793-815) pins
  `candidate.state.generation = store.generation() + 1` after the operation
  and `sync_pickles` but **before** `ClientStateV1::encode` — so the pinned
  value is inside the serialized, AEAD-sealed payload, and it overrides
  anything an operation closure could have written.
- Post-commit, `mutate` (mod.rs:770-774) requires
  `store.generation() == candidate.state.generation` before install;
  mismatch → `ReconcileRequired`, no install, no artifact.
- `from_store` (mod.rs:348-354) requires payload `generation`,
  `profile_id` and `key_ref` to equal the store's authenticated generation
  and independently held binding exactly, on both `open` and `create`'s
  re-validation path. `create` writes generation 1 and the store's create
  commits generation 1 — equality holds at the edge.
- Invariant now maintained everywhere: installed `state.generation ==
  store.generation` (create: both 1; from_store: checked; mutate:
  pinned + verified + installed atomically).
- The v1 repro (several mutators then reopen → 4 vs 1 divergence) is now a
  regression test: `payload_generation_tracks_store_generation`
  (src/persistent/tests.rs) asserts equality after every mutator and across
  reopen. Sol's forge repro (authentic envelope, outer generation 2 /
  payload generation 1) is `outer_generation_two_with_payload_generation_one_rejected`,
  with `rewritten_payload_roundtrip_sanity` proving the forge pipeline
  itself is authentic (rejections come from the finding-2 comparison, not
  envelope damage).
- Crash between commit and install: the store is durably at N+1; the façade
  either crashed (reopen loads N+1, equality holds) or is in
  `ReconcileRequired`/stuck non-`Ready` (everything rejects until drop and
  reopen). No path exposes the divergent in-memory state.

**The post-commit-mismatch judgment call is accepted.** `store.generation()`
is an in-memory field (`src/persistence/sqlite.rs:249-252`) advanced exactly
once per successful `commit_inner` under an exact-generation CAS
(sqlite.rs:292-353); the pin reads that same field, and exclusive `&mut`
ownership means nothing runs between pin and commit. The mismatch is
unreachable by construction and fail-closed if reached (no install, no
artifact, `ReconcileRequired`). See non-blocking observation 2 for the
sibling read-failure branch.

## B. The five remediation changes as new attack surface — all held

1. **`record_registration_result(&DurableAction, outcome)`**
   (mod.rs:673-713). Token AND digest verified in the step-2 bounds
   closure, against the CURRENT committed record, before any staging.
   `RegistrationRecord::encode` (src/state/records.rs:111-127) is
   fixed-length TLV — injective and infallible on typed input — so
   SHA-256-digest equality is exactly record byte equality; acceptance
   therefore requires the presented request byte-identical to the durable
   record AND the token equal to its nonce (which also forces
   `action.token == action.request.nonce`). Attacks run: forged token
   (rejects, record untouched, fresh action still consumes — tested);
   token-A/request-B and token-B/request-A cross-splices (both reject —
   tested in `action_token_and_digest_both_verified`); replay after consume
   (nonce re-minted → rejects — tested); superseded action after re-mint
   replacement (rejects — tested); rollback + newer token (rollback
   restores the OLD record and nonce, so the newer token rejects even at a
   repeated generation — the §2 property; re-verified in source, unchanged
   by the replace-on-remint semantics); result presentation before any
   action (create-time nonce never exposed, 16 random bytes). The
   replace-on-remint crash-recovery rule is documented and does not weaken
   any of the above.
2. **Generation tracking** — see A.
3. **`pending_prekey_offer()`** (mod.rs:469-482). `ensure_ready`-gated
   (rejects in `ReconcileRequired` and the unreachable `Mutating`); reads
   only the installed committed `self.state`, never a candidate; returns an
   owned `Copy` struct of public keys, expiry and signature —
   `PendingPreKey` contains no secret material at all (the one-time private
   key lives in the account pickle). Crash-between-commit-and-return
   recovery tested byte-identical (`pending_prekey_offer_recovers_committed_offer`);
   rejected in `ReconcileRequired` (tested); no consumption path exists in
   D1 (later-leg concern; the view would correctly return `None`).
4. **`commit_verified_contact` capability bytes** (mod.rs:500-543,
   `parse_capability_keypair` mod.rs:840-852). Bound (512) checked before
   deserialization; strict deserialize; trailing data rejected
   (`deserializer.end()`); canonical round-trip byte-equality rejects
   non-canonical input, matching the codec's own rule for
   `PeerBinding.send_keypair_json` (records.rs:244-245) so committed state
   always re-validates on decode. The typed `Ed25519Keypair` exists only
   inside the closure, only its public key is extracted, and the caller's
   `Zeroizing` bytes are moved into state (or dropped zeroized on any error
   path). No typed capability owner is exported anywhere. The reserialized
   copy is `Zeroizing`. Vendored-type residue: see observation 4.
5. **Frozen mutator order** — verified for every mutator at head:
   `mutate` (mod.rs:749-788) gates `Ready` and enters `Mutating` first;
   `pre_commit` runs `bounds(self)` against current state (step 2) before
   `stage()` (step 3), then operation/sync/pin/encode (step 4), then
   commit (5), install-by-moves (6), pre-commit discard to `Ready` (7),
   commit failure → `ReconcileRequired` (8). `prekey_action`,
   `commit_verified_contact`, `establish_outbound_session`,
   `registration_action` and `record_registration_result` all put their
   known-bounds checks in the bounds closure and ALL input validation
   inside the operation closure — nothing validates, serializes or parses
   caller input before the Ready gate (the token+digest check is a step-2
   current-state check, exactly as the brief specifies). A bounds closure
   calling back into a public method would self-reject on the `Mutating`
   state; none do.

## C. Disposition of Fable's v1 non-blocking observations — all resolved

1. `_request_digest` computed and discarded — resolved: the discarded line
   is gone from `mint_registration`; the digest is now actually compared in
   `record_registration_result`, and the doc claim matches the code.
2. §2 steps 2/3 swapped — resolved: `pre_commit` runs bounds before
   staging; the module docs' step mapping matches.
3. `commit_verified_contact` verified before `ensure_ready` — resolved: all
   verification moved inside the operation closure; `ReconcileRequired` now
   uniformly returns `Storage` (tested).
4. `from_store` binding assertions — resolved: profile_id/key_ref equality
   enforced and covered by the authentic-forge test
   (`payload_profile_or_key_ref_mismatch_rejected_on_reopen`).

## D. Re-run attacks — held

- **Token confusion incl. rollback-vs-newer-token:** see B.1.
- **Crash/reopen between mutators:** integration tests re-exercised at
  head; generation equality now also proven across every reopen.
- **Escape-hatch search on the new surface:** `pending_prekey_offer`
  (owned public-only `Copy`), the `&DurableAction` borrow (no escape), and
  `DurableAction` itself (shape unchanged; `Debug`/`Clone` expose only the
  caller's own token and public request — same as v1). The
  `persistent_client_is_neither_sync_nor_clone` compile-time check still
  guards the handle.

## Non-blocking observations (no action required)

1. **Duplicated doc comment** on `record_registration_result`
   (mod.rs:642-672): the pre-remediation doc block was left above the new
   one, so the rendered doc has two overlapping paragraphs and two
   `# Errors` sections. Delete the stale first block.
2. **Post-commit `store.generation()` read failure leaves `Mutating`, not
   `ReconcileRequired`** (mod.rs:770): the `map_err(..)?` propagates while
   `facade_state == Mutating`. Doubly unreachable (a successful commit
   cannot leave the store poisoned, and `generation()` fails only when
   poisoned) and behaviorally identical (`ensure_ready` rejects `Mutating`
   exactly like `ReconcileRequired`, with no path back to `Ready`), but the
   step-8 discipline names `ReconcileRequired`; a one-line
   `self.facade_state = ReconcileRequired` before the `?` would make the
   defensive branch self-consistent.
3. **Crash between a `record_registration_result` commit and its return**
   leaves the caller unable to positively confirm the outcome was recorded:
   the retry rejects `Unauthorized` (token consumed), which is the required
   replay-rejection property and loses no data (the outcome is durably
   applied) — unlike the prekey case there is no orphaned artifact. Worth a
   doc sentence that a post-crash `Unauthorized` on the exact retained
   action means "already recorded".
4. **Transient serde copies of the typed keypair** inside
   `parse_capability_keypair` (`serde_json::to_vec` internals may leave
   unzeroized heap copies during buffer growth): pre-existing pattern used
   crate-wide (`create` serializes the same type the same way), accepted in
   v1; noting only because the remediation touches this path. The
   caller-side erasure duty for the vendored `Clone + Serialize` type is
   documented in the module docs, as claimed.
