# Sol review v2 — ClientStateV1 codec (role-aware) — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6)
- **Head SHA reviewed:** `eaebebe4e6aef7c1a024e8f2a3ef6bebd7061bd4` (clean).
- **Verdict: RETURN**

The role-aware remediation is correct, but four blockers remain:

1. **Impossible receive history is accepted.** `src/state/validate.rs`
   reconstructs the session without checking
   `Session::has_received_message()`. The accepted populated fixture creates
   an outbound session, only encrypts, then fabricates
   inbound/ACK/receipt/receive-progress state and round-trips successfully.
   Vodozemac defines `has_received_message()` as proof that a receiving chain
   exists. A façade could therefore expose or ACK a message the restored
   ratchet proves it never decrypted.
2. **Receipt-free sessions are not conversation-bound.** Field 8 is merely
   parsed in `src/state/mod.rs`; `check_receipt` checks it only when a
   receipt exists. Set high water to zero with `receipt=None`, encode, change
   `conversation_id`, and decode still succeeds — violating the required
   field-8 mutation rejection and the frozen conversation-binding invariant.
3. **`DeliveryUnknown` has the wrong wire/state arm.** `src/state/records.rs`
   classifies it as nonterminal and requires queue, packet, and signature
   while forbidding the digest. The frozen design requires a body-free
   `DeliveryUnknown { message_id, packet_digest, expires_at }`
   (`docs/persistence-spike-design.md`). The correct expiry transition cannot
   encode; satisfying the codec instead retains the expired packet and leaves
   it on the retryable path.
4. **Pending prekeys may reference unpublished OTKs.** `check_pending_prekey`
   only calls `contains_one_time_key()`, which deliberately returns true for
   both published and unpublished keys. A generated, unmarked OTK with a
   valid signed `PendingPreKey` therefore reopens successfully, contradicting
   the required generate → mark published → atomically commit sequence.

## Checks that passed

- `cargo test --locked --all-targets` — PASS
- strict Clippy — PASS
- `git diff --check` — PASS; worktree clean at the exact SHA
