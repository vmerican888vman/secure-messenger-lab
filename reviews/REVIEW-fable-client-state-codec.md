# Fable review — ClientStateV1 codec — VERDICT: RETURN

- **Reviewer:** Fable (claude-fable-5), independent — Sol's response not seen.
- **Head SHA reviewed:** `a630f9a7b8b7c379330332d48e87239651944fb6` (clean).
- **Verdict: RETURN**

## Blocking finding

Legitimate inbound sessions cannot be represented by the active-session
transcript model.

`src/state/records.rs` (`PeerBundle`) binds the peer's identity and advertised
OTK. Validation then requires an inbound session's identity and OTK to match
that same bundle (`src/state/validate.rs`).

A genuine vodozemac inbound session instead contains:

- `identity_key` = peer initiator's identity
- `one_time_key` = local recipient's consumed OTK

Reproduced with a real inbound session; `ClientStateV1::encode()` returned
`LabError::Storage`. Existing coverage constructs an outbound session and
merely relabels it inbound (`src/state/tests.rs`).

## Checks that passed

- `cargo test --locked --all-targets` — PASS
- `cargo clippy --locked --all-targets -- -D warnings` — PASS
- All required attacks completed

No repository changes; head remains clean and unchanged.
