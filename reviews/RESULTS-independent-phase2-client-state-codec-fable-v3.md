# Independent review — `ClientStateV1` TLV codec and validation (v3) — Fable

- Reviewed SHA: `235ccfb854ba0d8def87a612d68c9948adb2719f` (verified via `git rev-parse HEAD`; worktree clean at review start)
- Reviewer: Fable (claude-fable-5), independent — Sol's v3 response was not sought, read, or referenced. The v1/v2 review files are cited as remediation history per the brief.
- Brief: `reviews/PROMPT-independent-phase2-client-state-codec.md`
- Design basis: `docs/phase2-design-decisions.md` §3 and §4 (with `docs/persistence-spike-design.md` for the `DeliveryUnknown` arm)

## Verdict

**PASS**

I am reviewing the amended v3 head, not either returned head: the four Sol v2
blockers are each fixed and independently reproduced as rejecting, all seven
required attack classes hold, and no new codec or validation flaw was found that
would make the façade unsafe to build on this leg. One design tension carried
over from the v1 Fable review (RekeyRequired representability at high
outstanding) remains but is not a v3 blocker — see the non-blocking section for
the reasoning.

## Gates

Both run from the repo root at the pinned SHA, on the unmodified main worktree:

| Gate | Result |
|---|---|
| `cargo test --locked --all-targets` | PASS (exit 0; all suites green, including the state `--lib` suite at 89 passed and every integration target) |
| `cargo clippy --locked --all-targets -- -D warnings` | PASS (exit 0) |

All probe code was written and executed in a **separate** git worktree at the
same SHA (`git worktree add … 235ccfb…`), never in the main worktree, which was
left untouched apart from these two report files. Every result below was
reproduced by a real `cargo test` run against real vodozemac operations; probe
sources are inlined.

## Blocking findings

None.

## Judgement of the four v2 remediations (all confirmed fixed)

1. **Receive-side provenance requires `has_received_message()`.**
   `check_active_session` (`src/state/validate.rs:383-389`) sets
   `receive_side_present` from `highest_contiguous_received_seq > 0`, a non-empty
   received set, non-empty inbound, or non-empty ACKs, and rejects unless the
   restored ratchet proves a receiving chain. Independently reproduced: the
   send-only fixture (session only ever encrypted) carrying fabricated
   inbound/ACK/receive state fails `encode()`, while the genuine two-way
   populated fixture (real encrypt → real inbound accept → real reply → real
   decrypt) passes decode/encode (probe `probe_receive_side_requires_has_received`,
   passed). A send-side receipt alone does not set `receive_side_present`, so a
   receipt-only session is not forced to have received — correct.

2. **Receipt-free sessions are conversation-bound.** Field 18
   (`conversation_id[16]`) is parsed in `ActiveSession::parse`
   (`src/state/records.rs:417`) and checked unconditionally against top-level
   field 8 in `check_active_session` (`src/state/validate.rs:373-375`),
   independent of any receipt. Reproduced: a receipt-free session (high water 0,
   `receipt = None`) with field 18 mutated one byte away from field 8 fails
   decode (probe `probe_receipt_free_conversation_binding`, passed). This closes
   Sol v2 blocker 2 exactly.

3. **`DeliveryUnknown` uses the digest+expiry arm.**
   `SendState::carries_full_arm` (`src/state/records.rs:544`) returns true only
   for `Pending`; `DeliveryUnknown`, `Stored`, `Duplicate` and `Expired` carry
   only digest and expiry, enforced by `arms_consistent`
   (`src/state/records.rs:597-609`) on both parse and `check_structure`.
   Reproduced by the shipped tests `delivery_unknown_transition_uses_digest_arm_and_round_trips`
   and `delivery_unknown_with_full_arm_rejected`, which I read and re-ran green;
   a `DeliveryUnknown` carrying the full arm fails on both encode and decode.

4. **Pending prekeys must reference a published OTK.**
   `check_pending_prekey` (`src/state/validate.rs:281-290`) requires the key to
   be held (`account.contains_one_time_key`) AND absent from
   `account.one_time_keys()` (the unpublished set). Independently reproduced: a
   held-but-unmarked OTK fails `encode()` (probe `probe_unpublished_prekey_rejected`,
   passed); a consumed OTK (peer already established a real inbound session,
   removing it from the account) also fails (probe `probe_consumed_otk_prekey_rejected`,
   passed).

## Judgement of the documented decisions (§ "attack these", 1–9)

- **1 (nested type IDs 0x0002–0x0009, per-object layouts):** each nested object
  enforces the exact `1..=field_count` ascending sequence and complete
  consumption (`ObjectReader`, `src/state/tlv.rs:124-162`); the frozen design
  fixes content/order, not IDs. Accepted.
- **2 (`queue_id` = 32 bytes):** matches the crate's real `QueueId`
  (`QueueId::from_slice`, used in `src/state/records.rs:46-48`). Accepted;
  documented as a forced deviation in `records.rs`.
- **3 (field 11 packed layout with exact consumption):** `parse_mailbox`
  (`src/state/mod.rs:310-326`) rejects any trailing bytes after the three
  length-delimited keypairs. Accepted.
- **4 (received set bound 64):** `MAX_RECEIVED_SET = 64`
  (`src/state/mod.rs:75`); §3 requires bounded without a number. Accepted.
- **5 (send array bound 32 including terminals):** `MAX_SENDS = 32` applies to
  the whole array (`encode_record_array` / `parse_record_array`); confirmed by
  the shipped `send_bound_accounting_across_mixed_arms`. Accepted (stricter than
  the table row, which is safe).
- **6 (receipt ⇒ `high_water == peer_contiguous_high_water`; absent ⇒ 0; peer
  binding pins the signer):** `check_receipt` (`src/state/validate.rs:489-524`).
  Reproduced: receipt/high-water divergence and future receipt
  (`high_water > last_assigned`) both rejected (probes
  `probe_receipt_divergence_rejected`, `probe_future_receipt_and_epoch_divergence`,
  passed). Accepted.
- **7 (every inbound/ACK needs a matching dedup; converse not required; session
  absence ⇒ session-dependent arrays empty, dedup allowed):** `check_inbound` /
  `check_acks` / `check_records` (`src/state/validate.rs:316-334, 527-619`).
  Reproduced: inbound without dedup and dedup-digest mismatch both rejected
  (probe `probe_inbound_dedup_cross_checks`, passed); session-absent-with-inbound
  rejected while the minimal dedup-only fixture passes (probe
  `probe_epoch_and_session_absence`, passed). Accepted.
- **8 (receipt signing part order):** `receipt_signing_bytes`
  (`src/state/validate.rs:91-103`) frames `[version, conversation_id, epoch_id,
  acknowledged_sender_curve, issuer_curve, high_water]`. Matches the decision
  and the record layout. Accepted.
- **9 (`created_at < valid_until`, no 300 s window at load):**
  `check_pending_prekey` (`src/state/validate.rs:273-275`) enforces the
  ordering only. Accepted; consistent with the no-load-time-freshness gap.

## Judgement of the declared gaps (acceptable at this leg)

All five are acceptable for a crate-private codec leg with no trusted `now` and
an outer AEAD/platform binding:

- No load-time freshness (no trusted `now`) — internal-consistency checks only;
  the façade supplies time. Documented in `validate.rs:22-25`.
- `profile_id`/`key_ref`/`generation` not cross-checked — authenticated by the
  outer AEAD/platform binding (§1); the codec cannot detect their mutation, and
  the tests intentionally do not assert it (`src/state/tests.rs:6-10`).
- Terminal send digests unverifiable by design (packet erased) — only `Pending`
  carries a verifiable arm.
- Inbound "signed expiry" is structural only — the record layout carries no
  envelope signature; `expires_at > accepted_at` is the only internal check.
- Outbox transition legality over time is snapshot-undecidable — arm
  consistency, distinct sequences, and `sequence <= last_assigned_send_seq` are
  enforced instead (`check_sends`, `src/state/validate.rs:557-599`).

## Coverage of every required attack class

Every class was exercised; all held.

1. **Structural rejection classes** — covered by the shipped suite (wrong
   magic, wrong object type, field-count mismatch,
   unknown/missing/duplicate/out-of-order fields, invalid enums including 0,
   wrong fixed length, truncation, trailing bytes, `u32::MAX` / bound+1 length
   prefixes, zero-length optional semantics, array count bound+1, unsorted/
   equal-ID arrays), read and re-run green. The `ObjectReader` enforces the exact
   `1..=field_count` sequence with one check (`src/state/tlv.rs:124-137`) and
   every bounded field is checked before `take` (`take_bounded`,
   `src/state/tlv.rs:62-67`), so no allocation from attacker-controlled length
   exists on the decode path.
2. **Canonical-JSON violations** — the shipped suite covers whitespace,
   duplicate keys, a serde-defaulted member (`session config`), the real
   vodozemac serde alias, and non-canonical order against the account pickle,
   session pickle and keypair fields (`account_pickle_whitespace_variant_rejected`,
   `keypair_json_duplicate_key_rejected_empirically`,
   `session_pickle_defaulted_member_rejected`, `account_pickle_serde_alias_rejected`,
   `noncanonical_keypair_json_rejected_on_decode`). `canonical_json`
   (`src/state/tlv.rs:201-216`) bounds first, uses `Deserializer::end` for
   trailing data, and requires byte-equal reserialization. Held.
3. **Byte-flip mutations** — every cross-checked top-level field and every
   signature position covered by `byte_flip_in_each_cross_checked_field_fails`
   and `byte_flip_in_signature_positions_fails`; additionally reproduced
   epoch-id and field-18 conversation-id flips (probes
   `probe_epoch_and_session_absence`, `probe_receipt_free_conversation_binding`).
   Held (profile/key-ref/generation excepted by design).
4. **Semantic mismatches** — re-pickle inequality, identity mismatch,
   capability/registration mismatch (shipped suite); forged transcript signature
   (probe `probe_forged_transcript_signature_rejected`), consumed OTK via a real
   inbound session (probe `probe_consumed_otk_prekey_rejected`), unpublished OTK
   (probe `probe_unpublished_prekey_rejected`), wrong epoch (probe
   `probe_epoch_and_session_absence`), session-absent-with-dependent-records
   (same probe). Genuine inbound-role round-trip holds (probe
   `probe_inbound_role_round_trip`). Held.
5. **High-water / mode matrix** — reproduced: outstanding 33 rejected;
   outstanding 32 rejected unless `ReceiptLocked`; outstanding 24 rejected under
   `Ready`, accepted under `ControlOnly`; receipt divergence, future receipt and
   receipt-epoch divergence all rejected (probes `probe_high_water_mode_matrix`,
   `probe_receipt_divergence_rejected`, `probe_future_receipt_and_epoch_divergence`).
   Held.
6. **Cross-record attacks** — send sequence above `last_assigned_send_seq`
   (shipped `check_sends` + `send_bound_accounting_across_mixed_arms`), duplicate
   send sequences (probe `probe_duplicate_send_sequence_rejected`), inbound/ACK
   without matching dedup and dedup field mismatch (probe
   `probe_inbound_dedup_cross_checks`). Held.
7. **Re-encode byte identity** — holds for the populated, minimal and genuine
   inbound fixtures and for every accepted probe variant (`encode` re-runs full
   validation, and decode/encode round-trips are asserted equal in the probes).
   Held.

## Non-blocking observations

Recorded for the façade slice and maintainers; none is a v3 return cause.

1. **RekeyRequired is unrepresentable at outstanding 24–32 (carried over from
   the v1 Fable review, F2; code unchanged).** `check_high_water`
   (`src/state/validate.rs:470-477`) admits only `ReceiptLocked` at outstanding
   32 and only `ControlOnly`/`ReceiptLocked` at 24–31, so a session that has
   accumulated ≥ 24 unreceipted sends and then must move durably to
   `RekeyRequired` on a receive-side gap packet (§4: "moves the session durably
   to `RekeyRequired`") cannot record that mode. Reproduced: `RekeyRequired`
   encodes fine at outstanding 0 (probe
   `probe_rekey_required_low_outstanding_isolated`, `rekey_required_ok=true`)
   but is rejected at outstanding 24 and 32 (probe `probe_high_water_mode_matrix`,
   `outstanding24_rejected=true outstanding32_rejected=true`). I am **not**
   blocking on this in v3: the brief's required attack 5 explicitly codifies the
   exact matrix the code enforces ("32 only ReceiptLocked; 24–31 only
   ControlOnly or ReceiptLocked") as the behavior to verify, and the design
   authority did not amend §4 or this check across the v2 and v3 remediation
   rounds after the v1 finding, which reads as an adjudicated acceptance at this
   leg. It should still be resolved before the façade drives real gap-packet
   transitions: either admit `RekeyRequired` at any outstanding ≤ 32, or amend
   §4 to state how a gap at high outstanding is durably recorded.
2. **Zero-high-water receipt accepted (from v1 Fable, code path unchanged).** A
   present, peer-signed receipt with `high_water == 0` and
   `peer_contiguous_high_water == 0` loads, although §4's runtime rule
   (`old < new`) can never mint one. Requires a valid peer signature, so
   harmless; slightly widens the loadable-state space.
3. **Duplicate inbound/ACK sender sequences accepted (from v1 Fable, unchanged).**
   Only *send*-sequence uniqueness is enforced (`check_sends`); two inbound
   records with distinct `MessageId`s but the same `(epoch, sender_sequence)`,
   each with a matching dedup, are not rejected. Honest operation cannot produce
   this and the brief's required cross-checks list only send-sequence
   uniqueness, so it is not a deviation; the façade must not assume the codec
   enforces inbound/dedup sequence uniqueness.
4. **Secret-bearing reserialization buffers are not zeroized (from v1 Fable,
   unchanged).** `reserialized` in `canonical_json` (`src/state/tlv.rs:211`) and
   the `reencoded` vectors in `check_account` / `check_active_session`
   (`src/state/validate.rs:203, 344`) hold complete account/session/keypair
   secret JSON in ordinary heap allocations. Inherent to the frozen
   reserialize-and-compare design; heap remanence is arguably out of scope, but
   the module is otherwise strict about `Zeroizing`, so wrapping the owned
   buffers (and documenting the serde-internal residue) would be consistent.

## What was checked and held (summary)

- Both gates PASS at the pinned SHA on the unmodified worktree.
- All four Sol v2 blockers independently reproduced as fixed.
- All seven required attack classes exercised; every one held.
- All nine documented decisions judged acceptable and, where reproducible,
  confirmed implemented.
- All five declared gaps judged acceptable at this crate-private leg.
- The leg is not returned merely for lacking a consumer; the codec and
  validation are safe to build the façade on, subject to the non-blocking
  RekeyRequired resolution before real gap-packet handling.
