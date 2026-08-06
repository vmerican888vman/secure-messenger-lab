# Independent review — `PersistentClient` façade, leg D1 (Fable)

Reviewed head: `73257357f912b79e5fbf656ff1fe0cfbc3885d45`
("Add the persistence-owning PersistentClient facade, leg D1").

The primary checkout carried unrelated uncommitted work, so the review ran in a
detached `git worktree` at the exact SHA with a clean tree. Gates at that SHA:

- `cargo test --locked --all-targets` — 162 passed, 0 failed.
- `cargo clippy --locked --all-targets -- -D warnings` — clean.

## Verdict: RETURN

One blocking finding. Everything else attacked held; the non-blocking
observations at the end require no code change to clear the RETURN.

---

## Blocking finding 1 — the embedded `ClientStateV1.generation` is frozen at 1 forever

**Claim attacked:** §2/§3 state-integrity model; brief criteria "any deviation
not documented as a deviation" and "anything that would make later legs unsafe
to build."

**What the code does.** `create` writes `generation: 1` into the state
(`src/persistent/mod.rs:262`) and no mutator ever touches the field again —
`grep '\.generation' src/persistent/mod.rs` has zero hits; `stage()` round-trips
it unchanged and `mutate()` commits it unchanged. Meanwhile
`ClientStateStore::commit_inner` advances its own generation on every commit and
seals it into the envelope AAD (`src/persistence/sqlite.rs:293-306`,
`src/persistence/envelope.rs:37`). From the second commit onward, every durable
snapshot's authenticated plaintext claims generation 1 while the envelope that
authenticates it says generation N.

**Reproduction** (run as a temporary `#[cfg(test)]` module inside
`src/persistent/mod.rs` with a trivial XOR protector; passes at the head SHA):

```rust
let mut client = PersistentClient::create(dir, XorProtector, 1_800_000_000)?;
client.prekey_action(1_800_000_300)?;
let action = client.registration_action(1_800_003_600)?;
client.record_registration_result(action.token, RegistrationOutcome::Confirmed)?;
assert_eq!(client.store.generation()?, 4);   // envelope/AAD generation
assert_eq!(client.state.generation, 1);      // embedded field — stale
// Divergence is durable: reopen shows the same 4 vs 1.
```

**Why it blocks.**

1. **It breaks a premise another leg's review was accepted on.** The codec leg
   deliberately does not cross-check `profile_id`/`key_ref`/`generation`
   inside the plaintext, on the recorded premise that "they are authenticated
   by the outer AEAD/platform binding" (`src/state/tests.rs:6-10`, and the
   byte-flip exclusion at `src/state/tests.rs:1095`). The AEAD authenticates
   the *column* generation via AAD; the embedded field is only as truthful as
   the sealer writes it. This façade **is** the sealer, and it writes a false
   value on every commit after the first. The documented gap chain breaks
   exactly here.
2. **It makes the §4 leg unsafe to build.** §4 recovery pivots on "provisional
   plus authentic generation 1 promotes"
   (`docs/phase2-design-decisions.md:323`). The decoded, semantically
   validated `ClientStateV1` is the natural authenticated object for that
   check — and under this façade its generation field reads 1 for *every*
   snapshot the profile has ever produced. A §4 implementation that trusts the
   embedded field would accept an arbitrarily old (or rolled-back, or copied)
   database as "authentic generation 1" and promote it. The safe alternative
   (`store.generation()`) exists, but the frozen field is a planted landmine
   that turns the natural implementation into a rollback-acceptance primitive.
3. **It is an undocumented deviation.** The module docs enumerate six
   deliberate deviations (`src/persistent/mod.rs:39-79`); a permanently stale
   §3 field-4 is not among them, and nothing in §2/§3 licenses it — §2's own
   rationale ("an authentic rollback can repeat it") presupposes a generation
   that advances per commit.

**No D1-internal exploit** — rollback detection in this leg rests on the AAD
generation, the exact-generation CAS and the nonce-token discipline, all of
which held under attack. The finding is the undocumented deviation plus the
cross-leg hazard, per the brief's return criteria.

**Suggested shape of the fix** (not prescriptive): in `mutate()`, set
`candidate.state.generation` to the store's next generation before
`sync_pickles`/`encode`; in `from_store`, require
`state.generation == store.generation()`. That also upgrades required attack 1:
the embedded field then proves the last committed generation *inside* the AEAD.

---

## Attacks run, all held

1. **Crash/drop + reopen between every mutator pair.** Exercised via the
   integration tests (`crash_reopen_discipline_between_every_mutator`,
   `create_mutate_reopen_round_trips`) and re-walked in source: `stage()`
   clones via encode/decode + pickle round-trips; pre-commit failure discards
   the candidate without touching installed state; only the committed snapshot
   exists after reopen. `create` keeps the exact bytes it sealed and inserted
   in the committed transaction, and `from_store` re-runs full decode +
   semantic validation on them (documented no-physical-reopen deviation —
   accepted).
2. **Forced commit/CAS failure at each mutator.** `commit_inner` CAS-guards on
   every column including nonce and ciphertext; any failure poisons the store
   handle *and* moves the façade to `ReconcileRequired`, where `ensure_ready`
   rejects everything including `public_identity()`; `protection_level()` is a
   protector passthrough exposing no state. Byte state stays the last
   committed generation (CAS failed, nothing written); reopen recovers it
   (`reconcile_required_rejects_everything_until_reopen`).
3. **Token confusion.** Wrong/replayed/cross-action/cross-client tokens all
   reject: the presented `[u8; 16]` must equal the durable record's nonce,
   nonces are OsRng-fresh per mint (`src/ids.rs`), consumption re-mints. A
   rollback restores the OLD record and therefore the old nonce, so a newer
   token fails even at a repeated generation — verified in source and by test.
   Result-presentation-before-any-action fails because the create-time
   record's nonce is never exposed.
4. **Escape-hatch search.** All returned types (`PublicIdentity`,
   `RedactedContactOffer`, `DurableAction<MailboxRegistration>`) carry only
   public keys, IDs, signatures and the deliberately-returned token; all owned
   or `Copy`. No `Debug` on `PersistentClient`, `MailboxKeypairs` or
   `Candidate`; the store's `Debug` redacts state. Non-`Clone`, non-`Sync`
   (and non-`Send`, stricter than required) — compile-time-checked by
   `persistent_client_is_neither_sync_nor_clone`. `mutate` is private and its
   closures are internal, so no caller code runs while `Mutating`.
5. **Expiry/window/signature confusion.** `commit_verified_contact` pins
   identity, enforces `now < valid_until <= now + 300` (matches the private
   `CONTACT_BUNDLE_MAX_VALIDITY_SECONDS` replica against `src/client.rs:12`),
   verifies with the *pinned* key over the same canonical signing bytes as
   `client.rs`; second binding and second session are bounds-rejected;
   `establish_outbound_session` re-checks bundle expiry at establish time.
   `verification_failures_do_not_mutate` covers the matrix behaviorally.
6. **Re-entrancy/aliasing.** Synchronous `&mut self` throughout; operation
   closures receive only `&mut Candidate` + `&MailboxKeypairs` and cannot call
   back into the façade; artifacts are returned only after commit; staging
   while `Mutating` is unreachable.

## Documented decisions — attacked, accepted

- **Token = registration nonce.** Sufficient: the nonce is inside the
  manage-signed record, so token equality transitively binds the exact
  request. See non-blocking observation 1, though.
- **Terminal markers** (Confirmed keeps `valid_until`, Failed re-signs with
  0): both round-trip codec validation and reopen; both consume the token.
- **`create` re-validation through the same handle:** the store consumes the
  protector and holds the directory lock; the re-validated bytes are the exact
  sealed-and-committed bytes. Accepted as documented.
- **`created_at = 0`:** fail-closed — a `valid_until = 0` offer fails codec
  validation pre-commit and discards to `Ready`.
- **Raw `Ed25519Keypair` mailbox triple:** `mint_registration`'s signing bytes
  are construction-identical to `MailboxOwner::registration`
  (`src/capability.rs:43-58`); verified by the independent replica in the
  integration tests.

## The `src/state/mod.rs` visibility widening

Two hunks, `use` → `pub(crate) use` of the record types, comment-only
otherwise. The second re-export block was already `pub(crate)`; record
construction was already possible crate-wide via `ClientStateV1`'s `pub(crate)`
fields, and `encode` re-runs full validation so no invalid state can be
serialized through widened access. No misuse surface added. Accepted.

## Non-blocking observations (no action required for the RETURN)

1. **`_request_digest` is computed and discarded**
   (`src/persistent/mod.rs:590`). The "request digest" half of the documented
   token discipline gates nothing — there is no second copy to compare it
   against in this realization, and the caller presents no digest. The
   security property survives on nonce uniqueness + signature re-verification
   alone, but the line is verification theater: either fold the digest into
   the presented token (e.g. 48-byte `nonce || digest`) or delete the
   statement and the doc claim.
2. **§2 steps 2 and 3 run swapped** — staging happens before the bounds checks
   inside each operation closure. Behaviorally equivalent (a bounds failure is
   a pre-commit failure → discard → `Ready`) and acknowledged in the module
   docs' step mapping, but it is a reordering of a frozen sequence and worth a
   one-line callout in the deviation list when the generation finding is
   fixed.
3. **`commit_verified_contact` verifies the offer before `ensure_ready`**, so
   in `ReconcileRequired` an invalid offer returns `PeerVerificationFailed`
   rather than the uniform `Storage`. Input-derived only; no state exposure.
4. **`from_store` could cheaply assert** `state.profile_id`/`key_ref` against
   `store.binding()` (both in hand). Unlike generation these cannot actually
   diverge under current code, so this is hardening, not a defect.
