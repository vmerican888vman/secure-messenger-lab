# Sol review — façade leg D1 — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), isolated `git archive` review; no other
  reviewers' artifacts opened.
- **Head SHA reviewed:** `73257357f912b79e5fbf656ff1fe0cfbc3885d45`.
- **Verdict: RETURN**

## Blocking findings

1. **Request-digest verification is absent.** `DurableAction` carries only a
   16-byte token; `record_registration_result` accepts only token and
   outcome. The digest computed at mint is compared with nothing. Mint
   actions A then B; an A result mislabeled with `B.token` consumes B
   because A's digest cannot be presented.
2. **Payload generation does not track the authenticated store generation.**
   `mutate()` never increments `candidate.state.generation`, while
   `ClientStateStore::commit()` advances the outer generation;
   `from_store()` compares neither generation nor payload profile/key
   metadata with the store. Reproduced: outer generation 2 containing
   payload generation 1, accepted after reopen.
3. **A crash can permanently orphan a committed prekey.** `prekey_action`
   exposes its offer only after commit returns; death after COMMIT but
   before the return leaves `pending_prekey = Some`, every retry rejected,
   and D1 has no API to retrieve the committed offer.
4. **Peer send-capability exclusivity is not enforced.**
   `commit_verified_contact` takes `Ed25519Keypair` by value, but the
   vendored type is publicly serializable and `Clone`; a caller can retain
   an equivalent signer and bypass later durable-send discipline.
5. **The frozen mutator ordering is reversed.** `mutate()` stages the
   complete candidate before operation-specific known-bound checks run, and
   `commit_verified_contact` validates/serializes inputs before reaching the
   `Ready` gate — an undocumented deviation from frozen steps 1–3.

## Accepted

The `pub(crate)` visibility widening in `src/state/mod.rs` is acceptable:
behind private `mod state`, no external reachability.

## Checks that passed

- `cargo test --locked --all-targets` (incl. 7/7 façade tests);
  clippy `-D warnings`.
- Targeted diagnostic reproduced both generation divergence and acceptance
  of mismatched inner/store profile metadata.
