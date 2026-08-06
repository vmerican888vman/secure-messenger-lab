# Independent review — façade leg D2a: ClientPayloadV2 + outbound send path (Fable)

- Reviewed SHA: `16adc902591196bfd0366be2bdb679bcc9253253` ("Add ClientPayloadV2 and the
  facade outbound send path, leg D2a"), verified via `git rev-parse HEAD` in a detached
  review worktree (`sml-review-d2a-16adc90`); tracked worktree clean at review start and
  at review end.
- Reviewer: Fable (claude-fable-5), independent — Sol's response was not sought, read, or
  referenced. Untracked reviewer artifacts for other legs were left unopened per the brief.
- Brief: `reviews/PROMPT-independent-phase2-facade-d2a.md`.
- Scope: `src/payload.rs`, the five D2a families in `src/persistent/mod.rs`
  (`stage_send`, `pending_send_actions`, `record_send_result`, `delivery_unknowns`,
  `consume_delivery_unknown`), the expiry sweep, mode recomputation, and the three test
  surfaces. Inbound/fetch/ACK/receipt-processing (D2b) not held against this leg.

## Verdict: PASS

No blocking findings. Three non-blocking notes at the end.

## Gates (pristine tree, before any probe was added)

- `cargo test --locked --all-targets` — 202 passed, 0 failed
  (lib 138, e2e_relay 7, expiry_revalidation 2, otk_membership 5, persistent_client 15,
  private_store_dir 29, request_boundaries 2, state_staging 2, plus doc/empty suites).
- `cargo clippy --locked --all-targets -- -D warnings` — clean.
- `cargo fmt --check` — clean.

## §4 claims — verification

1. **Durable epoch/seq from one per-session counter, committed before exposure.**
   `stage_send_operation` (`src/persistent/mod.rs:1170-1259`) assigns
   `send_seq = last_assigned_send_seq.checked_add(1)`, writes the record and the counter
   into the candidate, and the artifact is returned only after the generation-CAS commit
   and infallible install (`mutate`, mod.rs:1019-1058). A pre-commit failure discards the
   candidate — probe-proven that a failed stage burns no sequence (see probes). The codec
   re-validates sequence ∈ 1..=last_assigned, uniqueness across the outbox, and epoch
   match on every commit (`src/state/validate.rs:629-674`). HOLDS.
2. **Budget/mode.** `recompute_mode` (mod.rs:1154-1166) derives outstanding from the two
   counters; `RekeyRequired` early-returns and dominates; runs after every send-path
   mutation (stage/record/consume). The underflow in the subtraction is impossible:
   `check_high_water` (validate.rs:529-533) rejects any decoded state with
   `peer_contiguous_high_water > last_assigned_send_seq`, and the codec also enforces
   outstanding ≤ 32 and mode-vs-outstanding consistency at every decode/encode. Staging
   requires `Ready` in the bounds phase (mod.rs:800-802). HOLDS.
3. **`Stored`/`Duplicate`/`Expired`/consume never touch the counters.**
   `record_send_result`'s operation (mod.rs:894-915) mutates only the record's own fields;
   `consume_delivery_unknown` removes the record; `sweep_expired_sends` rewrites record
   arms only. Outstanding derives exclusively from the counters, so none of these recover
   budget — probe-confirmed (consume at ReceiptLocked-equivalent state does not change
   mode; slot removal leaves counters intact). HOLDS.
4. **Token discipline.** Token = record's `message_id` (binary-search key over the sorted
   outbox); the presented request is re-materialized as a `Pending` `SendRecord` and its
   canonical-bytes digest must equal the durable record's (mod.rs:867-892), all in the
   bounds phase before staging. Wrong token → `MessageNotFound`; replay → record left
   `Pending` → `MessageGone`; tampered expiry/queue/packet → digest mismatch →
   `Unauthorized` (probe-verified); foreign-client action → `MessageNotFound` (shipped
   test). HOLDS.
5. **Consume removes the record.** mod.rs:955-990 removes at the found index; the
   decision and its §4 rationale are documented on the method. HOLDS.
6. **Expiry sweep.** `sweep_expired_sends` uses `expires_at <= now` (equality sweeps —
   probe-verified ±1) and runs at the top of both clock-taking send mutators;
   `consume_delivery_unknown` re-checks the target after the sweep so an expired target
   rejects `MessageGone` instead of being consumed (probe-verified, including that the
   failed mutator's sweep does not commit). `record_send_result` takes no clock and does
   not sweep — documented. HOLDS.

## Required attacks — evidence

1. **Budget boundaries** — shipped `send_budget_and_mode_boundaries` (24th allowed, 25th
   rejected, persists across reopen); in-crate fixtures pin `ReceiptLocked` at
   outstanding 32 and `RekeyRequired` at any outstanding (including recompute-away
   attempt at zero outstanding). PASS.
2. **Token confusion** — shipped `send_token_discipline` (wrong/cross/replay) and the
   foreign-client case in `send_crash_discipline_between_every_mutator`; my probes add
   tampered-expiry and tampered-queue digest rejections with the genuine action still
   consumable afterwards. PASS.
3. **Crash between send-path mutators** — shipped drop/reopen chain plus
   `send_reconcile_required_on_commit_failure` (CAS failure → `ReconcileRequired`
   rejects everything; after restore+reopen exactly the committed pending action
   survives). A result for an uncommitted send is structurally unrecordable: the action
   value only exists after its commit succeeded. PASS.
4. **Payload strictness** — shipped unit tests (whitespace, trailing data, missing
   required field, version/kind, arm consistency, body ±1, binding mismatches) plus my
   8 probes: duplicate key, `\u`-escape variant, unknown extra field, missing
   `Option` field (`"receipt":null` / `"body"` omitted — caught only by the reserialize
   byte-equality, which works), `send_seq` as float/negative/exponent/2^64, receipt
   signature length 63/65, oversized input rejected before parse, wire-level kind flip.
   All reject. PASS.
5. **Expiry edges** — probes: `expires_at == now` staging rejects `InvalidExpiry`; TTL
   exactly 7d accepted, 7d+1s rejected; sweep fires at exactly `expires_at` and not one
   second before; sweep-then-target-state-recheck ordering inside `consume`. PASS.
6. **Delivery-unknown lifecycle** — shipped `delivery_unknown_flow` plus probes:
   double-consume → `MessageNotFound`; consuming `Pending` → `MessageGone`; consuming a
   terminal (`Stored`) → `MessageGone`; consuming an expired unknown → swept to
   `Expired`, rejects, and the failed mutator's sweep correctly does not commit. Slot
   accounting: within this leg the outbox cannot exceed 24 records (staging blocks at
   outstanding ≥ 24 and nothing in D2a recovers budget), inside the codec's
   `MAX_SENDS = 32`, which is re-enforced on every commit. PASS.

## Probes

Reviewer artifacts, not part of the leg:

- `tests/d2a_probes.rs` (untracked, in the review worktree) — 7 public-API probes, all
  pass.
- A temporary `#[cfg(test)]` probe module appended to `src/payload.rs` — 8 strictness
  probes, all pass; the file was reverted afterwards (`git status` clean but for the
  untracked probe file).

Gates ran on the pristine tree before either probe artifact existed.

## Non-blocking findings

1. **Escape-inflation bodies inside `MAX_BODY` are rejected with the wrong error.**
   `MAX_PAYLOAD_BYTES = MAX_BODY + 512` (`src/payload.rs:29`) budgets 512 bytes for JSON
   framing, but JSON string escaping charges the body itself: a legal body of ≤ 65,536
   UTF-8 bytes containing more than ~512 escape-inflating characters (`"`, `\`, control
   characters — each costs 1–5 extra bytes) exceeds the encoded bound and `stage_send`
   fails with coarse `LabError::Encoding`, contradicting the documented contract
   (`InvalidPayload` for an oversized body; nothing else should reject a legal body).
   Probe: a 65,536-byte body with 513 quotes → `Err(Encoding)`. Fails closed, burns no
   sequence (probe-proven), and is wire-consistent (decode enforces the same bound), so
   not blocking — but D2b's inbound path inherits the same effective bound, and either
   the API contract should document "canonical encoded payload ≤ 66,048 bytes" or
   `payload::application` should pre-check the encoded size and return `InvalidPayload`.
2. **An expired `DeliveryUnknown` occupies its outbox slot permanently in this leg.**
   Once swept to `Expired` it can never be consumed (`MessageGone`) and nothing in D2a
   removes terminal records. Bounded (≤ 24 slots reachable in D2a) and terminal-record
   pruning is naturally D2b/later scope — flagged so it lands there deliberately.
3. **Plaintext body lives in a non-zeroizing `String`.** `ClientPayloadV2.body` and the
   `body.to_owned()` copy are dropped unzeroized; only the encoded bytes are
   `Zeroizing`. Consistent with the codec's existing treatment of decoded plaintext
   elsewhere, so a note, not a finding against this leg.

No tracked source changes, commits, or merge actions were made anywhere.
