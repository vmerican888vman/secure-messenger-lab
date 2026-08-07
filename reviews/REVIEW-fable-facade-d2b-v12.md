# Fable review — façade D2b v12 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a subagent
  (first round not relayed through the user). Worktree
  `sml-review-d2b-v12-fable-5dbcca7`, verified clean at the exact SHA;
  probes reverted and the scratch clone deleted.
- **Head SHA reviewed:** `5dbcca73d2c918420747bf222e44383439b5b30e`.
- **Verdict: PASS** — no blocking findings.
- **Gates at the exact head:** `cargo test --locked --all-targets` 280
  green (229 lib + 5 + 19 + 27), `cargo clippy --locked --all-targets --
  -D warnings` clean, `cargo fmt --check` clean.

## Independently reproduced rather than assumed

- **The brief's "fails at `b3825fa`" claim.** Fable cloned to scratch,
  checked out the parent, transplanted both new tests, and ran them:
  `prekey_normal_variant_alias_is_deduplicated` → `Err(Crypto)` (past
  dedup, into the ratchet); `over_signaling_cannot_lock_the_victim` →
  left `Ready` for `ControlOnly` at cycle 25. Both regressions are real
  and causally attributable to this head; neither is vacuous.
- **The reciprocity gate's liveness link — the attack it most wanted to
  land.** Built over the real relay: B fills the §4 budget (24
  outstanding, `ControlOnly`, truthful signal on seq 24) and A never
  consumes, so the control arm is A's only receipt source. A armed at 24,
  staged one receipt at its seq 1, `control_signal_response_at = 1`; B
  accepted it, B's UNGATED local arm fired and counter-receipted at seq
  25 with water 1; A applied it → `peer_hw = 1 >= csra = 1`, gate
  reopens. The reciprocation link is verified, not assumed.
- **Durability:** drop/reopen with a nonzero marker round-trips `1 → 1`
  and full revalidation passes.
- **The `invalid_enums_rejected` adjustment:** probed the computed index
  `len - 1 - 38`; the byte there is `DedupState::Accepted`, and swapping
  it for another VALID enum value still decodes — so the test's
  rejections come from the invalid enum, not collateral corruption of the
  new digest field.

## Claims checked directly against the code

- **`inner_message_digest` is the right identity.** `Message::to_bytes()`
  is `version ‖ protobuf(ratchet_key, chain_index, ciphertext) ‖ full
  MAC`, and `PreKeyMessage::message()` returns that same inner value, so
  both variants of one inner message hash identically and nothing that
  selects the consumed message key is excluded. It is strictly
  more-rejecting: a record exists only for an ACCEPTED packet (the
  gap-failure path returns before `push_dedup`), and two distinct honest
  packets cannot share inner bytes because Olm never reuses
  `(ratchet_key, chain_index)`.
- **Every write/read path.** One production `DedupRecord` construction
  (`push_dedup`), fed by both the application arm and `apply_receipt`;
  the two terminal transitions mutate in place so `message_digest`
  survives; the read loop does not filter by state, and runs after the
  `RekeyRequired` lock and the envelope-signature check but before any
  ratchet touch — no oracle for an unauthenticated sender.
- **Codec.** Fields ascending in both `parse` and `encode` for both
  records; `ObjectReader` enforces the exact `1..=field_count` sequence
  plus `finish()`, so a 7-field dedup record, a 21-field session, or any
  spliced/duplicated field rejects. The new rule
  `control_signal_response_at <= last_assigned_send_seq` is sound by
  construction — the field is only ever assigned from
  `last_assigned_send_seq`, which is monotone.
- **Gate semantics.** The marker is the receipt's OWN sequence
  (`stage_receipt` advances `last_assigned_send_seq` first), so the gate
  asks precisely "did the peer receive the answer". It blocks only
  ARMING; `control_debt_up_to` stays monotone and standing debt still
  re-stages ungated, so an already-recorded need is never abandoned.

## Attacks that failed

Cross-epoch/cross-session digest collision (ratchet keys are per-session
random); false dedup of a genuine PreKey retransmission vs a Normal
message (distinct chain indices ⇒ distinct digests); poisoning dedup from
a FAILED accept (failed accepts discard the candidate, and the one
committing failure path returns before `push_dedup`); honest deadlock
from the gate (every route resolves through the ungated app-debt arm, or
B's ungated local arm, or is a pre-existing §4 property).

## Non-blocking observations

1. **The docs overclaim (act on this).** The alias class is not closable
   against the adversary it is written for. The envelope signature is
   over `(queue, message_id, packet_digest, expires_at)` under the
   mailbox send capability, so only a capability holder — the peer — can
   mount a variant alias at all. Fable probed that same adversary
   flipping ONE MAC byte of the accepted inner message: different
   `message_digest` AND `packet_digest` → passes dedup →
   `find_message_key` runs BEFORE MAC verification
   (`vendor/.../receiver_chain.rs:186-195`) → `MissingMessageKey` →
   durable `RekeyRequired`, reproduced (generation 6→7). A fresh message
   with `chain_index` past `MAX_MESSAGE_GAP` does the same with no replay
   at all. §4 designates peer-authenticated gap failures as DESIGNED
   behavior, so this is not a defect at this head — but the docs at
   `client.rs` and `records.rs` must stop describing the inner-message
   digest as closing the GAP-LOCK class. It closes the
   DUPLICATE-CONSUMPTION class.
2. **The one-receipt lifetime bound is an accept-path property, not a
   debt-lifecycle property.** `control_signal_response_at` is written
   only in `accept_staging_tail`. A receipt that answers standing
   peer-armed debt but stages inside `consume_inbound` or `stage_send`
   does not spend the allowance, leaving the gate open. Fable could not
   turn this into amplification — such a receipt is one the victim owed
   anyway via the app-debt arm — but a tighter closure is to set the
   marker whenever a receipt stages while `control_debt_up_to` was last
   raised by the peer arm.
3. **Narrow liveness corner (reasoned, not reproduced).** If the
   counter-receipt that reopens the gate is lost (stored at the relay but
   expiring unfetched) AND the receiver never consumes inbound and never
   sends, the peer-signal arm stays shut and the peer stays
   `ControlOnly`. Never became a real deadlock: a non-consuming receiver
   is bounded by the 32-slot inbound array anyway, so blocking the sender
   there is backpressure.
4. `message_digest` has no validator cross-check, unlike `packet_digest`
   (cross-checked in `check_inbound`/`check_acks`). Reachable only by
   someone who already holds the DEK, so outside the threat model, but
   the field is trusted purely as an equality token.
5. Layouts changed again (dedup 7→8, session 21→22) with the state schema
   version still `1`, so a database written by any earlier head fails
   validation on open rather than migrating. Acceptable while Phase 2 is
   unshipped and consistent with the v3/v5/v6 field additions.
6. `DIGEST_FIELD_BLOCK = 6 + 32` in `invalid_enums_rejected` hard-codes
   the assumption that the record's trailing field is a 32-byte fixed
   field; a future field 9 will silently move the target without failing
   the test.
