# Sol review v3 — ClientStateV1 codec — VERDICT: RETURN

- **Reviewer:** Sol (GPT-5.6), independent (isolated clone; no Fable
  artifacts opened).
- **Head SHA reviewed:** `235ccfb854ba0d8def87a612d68c9948adb2719f`.
- **Verdict: RETURN**

## Blocking findings

1. **High — current-epoch dedup bypasses receive-state authority.**
   `receive_side_present` omits dedup records; `check_dedup` checks only
   queue and nonzero sequence. The `receipt_only_session_validates` test
   retains current-epoch dedup records on a ratchet that never received and
   round-trips — bypassing remediation 1; can suppress a real inbound or
   lose out-of-order progress. Current-epoch dedup must require
   `has_received_message()`, and its sequence must be at/below HCR or in
   `received_above_high_water`; retired-epoch dedup can remain exempt.
2. **High — required `RekeyRequired` is unrepresentable with 24–32
   outstanding sends.** The mode matrix rejects `RekeyRequired` in that
   range, but the frozen design requires every authenticated current-epoch
   gap failure to durably enter `RekeyRequired` without an outstanding-count
   exception. `RekeyRequired` must dominate the budget mode or be represented
   orthogonally.
3. **Medium — canonical duplicate-OTK state is accepted and later becomes
   uncommittable.** The vendored patch documents that validators must reject
   duplicate public keys; `check_account` does not. Sol's reproduction:
   `ClientStateV1::encode()` accepts the canonical duplicate-secret account;
   after legitimate consumption the surviving alias makes inbound validation
   reject the candidate. Validate unique derived OTK public keys and
   authoritative unpublished-map/key-ID consistency.
4. **Medium — secret intermediates violate the frozen zeroization
   requirement.** Account/session re-pickles and encoded private
   keypair/session objects are ordinary `Vec<u8>` buffers that drop without
   erasure (persistence-spike-design.md requires zeroization). These buffers
   are under this crate's control and can be wrapped or explicitly zeroized.

## Verification

- All-target tests: 155 passed; scoped state tests: 62 passed; strict
  all-feature Clippy: passed; `cargo audit --deny warnings`: passed;
  `git diff --check`: passed.
- **Repo CI formatting gate: failed**, including in-scope state files; the
  exact head is not CI-green.

The four named v2 changes are present literally, but the blockers above keep
this head at RETURN.
