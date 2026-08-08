# Audit — do the checked claims in `SECURITY_STATUS.md` still hold?

**Status: implementer's analysis, 2026-08-08. PARTIAL — 7 of 24 claims verified
in depth. Not certified by any reviewer.** Uncommitted; repository under a
no-commit hold.

Applying the BLK lesson to this repo: *a security property is unproven until you
can point at the line that executes it on the live path.* The recent dual PASS
certified the amendment documents' internal coherence — it did **not** re-verify
these 24 checked items against the code, and the cold reviewer said so
explicitly.

## Coverage — read this before quoting anything below

Two different depths were applied, and the difference matters:

| Depth | What it means | Count |
|---|---|---|
| **Traced** | Read the executing code and, for negative claims, checked the test has an accept-arm control so it cannot pass vacuously | **9** |
| **Existence-verified** | Located a named test whose name matches the claim; did **not** read its body or check for controls | **8** |
| Not examined | — | **7** |

**Traced:** lines 10, 11, 12, 13, 14, 18, 20, 23, and the pair 47/50.

**Existence-verified only:** 21, 26, 28, 30, 32, 34, 36, 40, 43. These have
plausibly-named tests. *A matching test name is not evidence the test asserts
anything* — this repo has had four tests pass vacuously, so treat this tier as
"a test exists", nothing more.

**Not examined:** 15, 17, 25, 61, 69.

Absence of a finding below is absence of an audit, not evidence of correctness.

## Finding 1 — the E2E round trip is reachable only from inside the crate

**Claim (line 10):** *"End-to-end encrypted two-client round trip through the
real relay path."*

**Verdict: literally true, materially narrower than it reads.**

The round trip exists and passes: `two_client_conversation_over_real_relay`
(`src/persistent/tests.rs:566`) drives two façade clients over a real `Relay`,
including out-of-order accept, crash/reopen mid-spine, and duplicate rejection.
The crypto and the relay path are genuine.

But the test's `connect()` helper obtains the peer's send capability by reaching
into private state:

```rust
Zeroizing::new(serde_json::to_vec(&a.keypairs.send)?)
```

That is precisely the export the façade deliberately does **not** provide —
review finding F4 — and precisely what `src/main.rs` documents as missing:

> the public API has no handle for the out-of-band send-capability transfer

So **no external consumer of this crate can perform the round trip the claim
describes.** It works because the test lives inside the crate and can read
`a.keypairs.send` directly.

This is a mild instance of the BLK shape — working crypto beside a path that is
not reachable as designed. Mild, because unlike BLK the crypto genuinely
executes on the tested path and the gap is openly recorded in `main.rs` and in
blocker 2. It is not a false claim. It is a claim whose scope a reader of a
public repository would over-estimate.

**Recommended:** qualify line 10 — e.g. *"through the real relay path, in-crate;
the public API cannot yet complete the capability transfer (see blocker 2)."*
Wording is not mine to choose — `SECURITY_STATUS.md` governs public claims.

## Finding 2 — the metadata budget omits fields the relay actually stores

**Not a checked claim, but load-bearing for claim 12 and for every
server-blindness statement.**

`THREAT_MODEL.md`'s "Metadata budget" table enumerates 9 relay-visible fields.
Its only caveat concerns a *real network* relay — source IP, connection time,
request size, TLS metadata, timing — which implies the table is complete for the
relay as built.

Comparing against `CURRENT_SCHEMA_DDL` (`src/relay.rs:795`), these are stored
and **absent from the budget**:

| Column | Table | Why it matters |
|---|---|---|
| `sender_signature` BLOB(64) | `messages` | **The material one.** A per-message Ed25519 signature, stored at rest. If a sender's signing key is stable across messages, this is a durable linkability artifact the budget does not account for |
| `created_at` | `mailboxes` | Mailbox creation timestamp — traffic analysis |
| `retired_at` | `retired_queues` | Retirement timestamp, and that table is retained **indefinitely** |
| `role` TEXT | `request_nonces` | Reveals which capability class is being exercised (send / receive / manage) |
| `delete_after` | `tombstones`, both nonce tables | Partly implied by the retention column, never listed as a field |

**Claim 12 itself holds** — verified column by column, the schema contains no
plaintext, users, contacts, conversations, phone numbers, emails, or groups. The
defect is in the threat model's enumeration, not the schema.

This matters more now than before: the Delivery Service brief asks the architect
how much relay-visible metadata MLS ordering costs, and that question cannot be
answered against an inventory that is already short by five fields.

## Finding 3 — claim 30's boundary tests cannot distinguish "fail closed" from "fail always"

**Claim (line 30):** *"Equality/future request-expiry bounds and invalid
message-retention bounds fail closed under direct regression tests."*

**Verdict after two corrections: ONE of the two tests lacks an accept arm, and
the coverage that compensates for it is scheduled for deletion.**

**Correction 1 — I first wrote that both tests were reject-only. That was
wrong.** `signed_request_time_boundaries_fail_closed_for_every_command` is in
fact exemplary: it asserts `authorize_fetch(NOW + 300)` — the **exact
maximum** — succeeds and returns one envelope, alongside `NOW + 301` rejected,
and it drives a full register/enqueue/fetch/open/ack sequence whose `?`
operators are themselves accept arms. It pins the boundary in both directions.

**Correction 2 — I claimed a `>` → `>=` off-by-one would be undetectable. It
would not.** A mutation probe flipping `src/relay.rs:1127` to `>=` fails **16
tests**, not one.

**What is actually true**, and still worth fixing:

`src/relay/request_boundary_tests.rs` holds both:

- `message_retention_expiry_bounds_fail_closed` iterates `[NOW, NOW + MAX_MESSAGE_TTL_SECONDS + 1]`, asserts each returns `Err(LabError::InvalidExpiry)`, then asserts `queued_message_count_at(NOW) == 0`.
- `signed_request_time_boundaries_fail_closed_for_every_command` iterates `[NOW - 1, NOW, NOW + 301]` across register / fetch / delete, asserting rejection for each.

**Neither test ever asserts that a valid bound is accepted.** A regression that
rejected *every* expiry would pass both, and the trailing
`queued_message_count == 0` would not merely still pass — it would be
*guaranteed*, which makes it worse than no assertion.

Concretely untested: **the exact maximum**, `NOW + MAX_MESSAGE_TTL_SECONDS`.
The relay's check is `expires_at > now.saturating_add(MAX_MESSAGE_TTL_SECONDS)`
(`src/relay.rs:1127`) — strictly greater, so the exact maximum **should be
accepted**. An off-by-one changing `>` to `>=` would reject the exact maximum and
**both tests would still pass.**

This is a test-quality defect, not a demonstrated vulnerability — the code at
`src/relay.rs:1127` reads correctly. But the claim's warrant is "under direct
regression tests", and these tests do not carry that warrant. It is exactly the
vacuity pattern this project adopted the accept-arm rule to prevent, surviving
in the two tests whose names most confidently assert the property.

### Why it still matters — the compensating coverage is scheduled for deletion

All 16 tests that catch the mutant live in `persistent::tests` and are §4
control-lane, receipt, and budget tests: `control_churn_is_budget_neutral…`,
`lockstep_traffic_never_deadlocks_budget`, `over_signaling_cannot_lock_the_victim`,
and so on. They catch it incidentally, because
`src/persistent/mod.rs:2954` uses `now.saturating_add(MAX_MESSAGE_TTL_SECONDS)`
as an ordinary expiry.

The Phase 3 ruling marks exactly that machinery — *"the skipped-key-driven
24/8/32 budget, Olm-specific `RekeyRequired`"* — **retire and redesign against
MLS epochs/commits.** So the coverage protecting this bound today disappears
with the Olm machinery, and the one test named for the property would be left
unable to detect the regression it exists to catch.

### Fix applied and mutation-verified

`message_retention_expiry_bounds_fail_closed` now enqueues at exactly
`NOW + MAX_MESSAGE_TTL_SECONDS` and asserts the queued count becomes 1, mirroring
the boundary discipline its sibling already applies at `NOW + 300`.

Verified, not assumed:

1. Amended test passes against clean code.
2. Amended test **fails** against the `>` → `>=` mutant.
3. Mutant reverted; full suite green at 240 passed.

The point of the fix is not that the bound is currently unprotected — it is
protected, 16 times over. It is that the protection is incidental and lives in
code the ruling has already condemned, while the test that names the property
could not carry it alone.

## Verified sound — no finding

| Line | Claim | Evidence |
|---|---|---|
| 11 | No plaintext fallback when session state is absent | `src/persistent/mod.rs:854,863` return `LabError::MissingSession`; no fallback branch |
| 12 | Relay schema has no plaintext/users/contacts/conversations/groups | Every column of `CURRENT_SCHEMA_DDL` read; holds |
| 14 | Signed contact bundle binds Curve25519/one-time keys to a pinned Ed25519 identity | `commit_verified_contact` verifies the signature over the reconstructed bundle against the caller's pinned identity, inside the mutator, before any state commits |
| 20 | Authenticated recipient ACK required before early deletion | `acknowledge` verifies the request signature against the mailbox `receive_key`, `Unauthorized` on failure, before deletion |
| 47 | `ClientStateV1` codec DUAL PASS at `8fab295` | Commit exists; both `REVIEW-fable-codec-v12` and `REVIEW-sol-codec-v12` present |
| 50 | Façade D2b DUAL PASS at `a33d2ba` | Commit exists; both `REVIEW-fable-facade-d2b-v16` and `REVIEW-sol-facade-d2b-v16` present |
| 13 | Separate signed send/receive/manage capabilities; queue ID alone authorizes nothing | Four distinct verification sites in `src/relay.rs`: `send_key` at enqueue (324), `receive_key` at fetch (394) and acknowledge (453), `manage_key` at management (525). No path authorises on queue ID alone |
| 18 | Binding-invalid payloads cannot burn the authoritative one-time key or advance the ratchet | **Both arms present and both carry accept-arm controls.** `rejected_initial_binding_does_not_consume_the_one_time_key` rejects the invalid envelope, then proves a subsequent *valid* initial message opens — which is only possible if the OTK survived. `rejected_established_binding_does_not_advance_the_ratchet` mirrors it with `valid-after-rejected-established` |
| 23 | SQLite holds queued ciphertext but no plaintext; exact ciphertext absent after ACK | **Exemplary.** `ciphertext_is_stored_then_logically_erased_after_recipient_ack` asserts the plaintext canary is absent *and* the ciphertext **is present** before ACK — the positive control proving the byte-scan works — then that neither survives after ACK, and that the event stream never contains the canary |

## Claim 21 — all nine attacks have backing tests

Claim 21 packs nine distinct attacks behind one checkbox, so it was mapped
attack by attack:

| Attack | Backing test |
|---|---|
| ACK substitution | `ack_result_requires_full_request_binding`, `ack_requires_matching_dedup_record` — the ACK must bind the full request, which is the anti-substitution property |
| Ciphertext tampering | `tamper_wrong_binding_and_authentic_rollback_are_explicit` |
| Wrong-recipient | `tamper_wrong_recipient_and_missing_session_all_fail_closed` |
| Unauthorized-capability | 36 assertion sites on `LabError::Unauthorized` |
| Replay | `cross_epoch_digest_replay_rejected_before_ratchet`, `deleted_mailbox_cannot_be_resurrected_by_registration_or_send_replay` |
| Retry | `ack_binding_and_lost_request_or_response_retries_are_safe` |
| Duplicate | `concurrent_identical_sends_resolve_to_stored_plus_duplicate` |
| Conflict | `concurrent_conflicting_sends_resolve_to_stored_plus_conflict` |
| TTL | `expired_ack_intents_are_swept` |

**No gap found.** Bodies still unread, so this remains existence-tier.

### Methodological warning for whoever continues this

**Name-based test discovery failed twice in this audit**, and both times it
would have produced a *false* gap:

1. Claims 28 and 30 first appeared to have no tests. Both have near-perfectly
   named ones.
2. Claim 21's "ACK substitution" and "unauthorized-capability" arms first
   appeared uncovered. Both are covered — the first under `ack_*_binding`
   naming, the second by error-variant assertions rather than a test whose name
   contains "unauthorized".

**Search by error variant and by semantics, not by test name.** A false finding
in a security audit costs more than a missed one: it teaches the reader to
discount every other line.

## Existence-verified only — tests located, bodies not read

| Claim | Test located |
|---|---|
| 26 | `send_expiry_sweep`, `destructive_reset_flow_and_idempotent_resume` |
| 28 | `upgrade_discards_unverifiable_legacy_messages_and_preserves_relay_state`, plus `hot_journal_from_aborted_legacy_migration_recovers_then_migrates` |
| 30 | `message_retention_expiry_bounds_fail_closed`, `validate_message_expiry` |
| 32 | `schema_manifest`, `hot_rollback_journal_child` |
| 34, 43 | `acl_free`, `acl_get_fd` |
| 36 | `cas_conflict_poisons_the_stale_handle`, `cas_to_deleting` |
| 40 | `control_churn_is_budget_neutral_and_the_local_arm_survives`, `lockstep_traffic_never_deadlocks_budget` |

**A caution on this tier.** My first pass reported no test for claims 28 and 30
and I nearly recorded that as a finding. It was a bad grep pattern — both tests
exist with near-perfect names. Re-checking before writing caught it. A false
finding in a security audit is worse than a missing one, because it burns the
reader's trust in every other line.

## Second pass — the five previously unexamined claims

| Line | Claim | Verdict |
|---|---|---|
| 15 | Sender-signed outer envelope verified before ratchet mutation; ACK creation requires a decrypted envelope | **First half: enforced by the type system.** `verify_envelope` (`src/capability.rs:192`) returns `Result<VerifiedEnvelope>` — a distinct type. Downstream ratchet operations take `VerifiedEnvelope`, so an unverified envelope **cannot** reach them; this is a compile-time guarantee, not an ordering convention. It also checks queue-ID match and expiry, then verifies the sender signature over bytes including `expires_at`. **Second half — that ACK creation requires a successful decrypt — not verified.** |
| 17 | Previously verified pre-keys and envelopes are rechecked for expiry at the point of use | **Holds.** Four distinct recheck sites in `src/client.rs`: bundle window at 52–53, `peer.valid_until <= now` at 323, `envelope.expires_at() <= now` at 377 **and** 415 — two separate envelope use sites, which is what "at the point of use" requires |
| 25 | Relay event stream contains fixed event names only | **Holds, exhaustively.** 9 `audit_events.push` sites, **0** that are anything but a bare string literal — checked by counting non-literal pushes, not by sampling. Nine fixed names, no interpolation, so no data can leak through the event stream |
| 61 | Encrypted atomic persistence through the façade; legacy client crate-private and test-only | **Holds.** `src/lib.rs` exports only `client::EncryptedPacket`; neither `Client` nor `OlmClient` is re-exported, so the legacy in-memory client is unreachable outside the crate |
| 69 | Exact fail-closed SQLite schema-shape validation | **Holds at existence tier, with unusually specific test names**: `current_schema_rejects_extra_trigger_and_version_shape_disagreement`, `current_schema_version_without_sender_signatures_fails_closed`, `current_schema_with_sender_signature_but_missing_constraints_fails_closed`, `exact_schema_rejects_extra_objects` |

**Claim 15's unverified half is the only remaining gap in the "traced" tier.**
Whether ACK creation genuinely requires a successful decrypt — rather than
merely a verified envelope — is worth closing, because an ACK that can be
produced from a verified-but-undecryptable envelope would let a recipient
delete relay state for a message it never read.

## Highest value next

Read the bodies of the existence-verified tier, in this order, on the reasoning
that negative assertions are the easiest to satisfy vacuously and this repo has
four precedents:

1. **21** — the attack matrix (ACK substitution, tampering, wrong-recipient,
   unauthorized-capability, replay, retry, duplicate, conflict, TTL). Nine
   distinct attacks behind one checkbox; that is where a vacuous arm hides.
2. **40** — the §4 budget and receipt machinery. Note this is Olm-specific and
   the ruling marks it *retire and redesign*, so verify only enough to know
   whether the claim is true today.
3. **32** — the schema-manifest and rollback-journal paths.

Encouraging signal from the traced tier: **every negative claim examined had a
real accept-arm control.** Claims 18 and 23 are textbook — they prove the
detector works before asserting it detects nothing. That is the adopted fix
pattern actually being applied, not just documented.

## What to do with this

Nothing here is edited into `SECURITY_STATUS.md` by me. Both findings touch
public claims, and that file is the authority on claims — the same reason the
Phase 3 amendment went to the architect rather than being applied directly.
Finding 1 needs a wording ruling; Finding 2 needs the metadata budget extended
and should be settled **before** the Delivery Service ruling, since that ruling
depends on knowing the current metadata baseline.
