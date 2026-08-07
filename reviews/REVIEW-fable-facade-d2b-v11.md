# Fable review — façade D2b v11 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), checkout and clean worktree
  verified. Full verdict also in their own
  `reviews/REVIEW-fable-facade-d2b-v11.md` artifact inside the review
  worktree. Transcribed from the user's paste.
- **Head SHA reviewed:** `b3825fa30980c797dfad4de3d1a4729c132f3506`.
- **Verdict: PASS** — no blocking findings.
- **Gates at the exact head:** `cargo test --locked --all-targets`,
  `cargo clippy -- -D warnings`, and `cargo fmt --check` all pass.

Both v10 blockers are structurally closed, and the load-bearing claims
were verified rather than taken on faith.

## P1-1 — canonical Olm encoding

The soundness of `parse_canonical` hinges on whether re-serialization
canonicalizes the INNER Olm framing or only the JSON wrapper. Fable read
the vendored vodozemac to settle it: `Deserialize` parses the inner prost
framing, and `Serialize` re-encodes the parsed struct (`to_parts` calls
`to_bytes()` — it does not echo the input bytes). The byte-compare
therefore collapses every alias class at once: JSON key order, whitespace,
ignored fields, base64 padding, AND non-canonical inner protobuf. Exactly
one encoding per message is accepted, so the raw digest genuinely is the
semantic identity.

Supporting checks:

- Placement before the transaction is a pure function of the bytes, so it
  is no oracle, and `MAX_PACKET` is re-checked ahead of it.
- The façade has no other path to the ratchet — the permissive decodes in
  `client.rs` belong to the boundary-leg `OlmClient`.
- Every sender site emits exactly the canonical form, so there are no
  false rejects.

## P1-2 — control debt bound to the signaling sequence

The arm raises the debt water to the signaling packet's `send_seq` via a
monotone `max`. The invariant Fable weighted most heavily — the new
validator rule admitting a debt water that sits in the out-of-order set —
holds because `track_sender_sequence` rejects at the set bound rather
than EVICTING, so entries leave the set only by draining into HCR. The
debt water therefore can never be stranded in a rejected position.

The freshness gate (`HCR > marker`) covers both debt arms, so debt
stranded above HCR cannot spam idempotent receipts. Attacker leverage is
unchanged: the armed value is our own received sequence, never the
attacker-supplied outstanding count.

## Independent regression confirmation

Fable checked out the parent `dad8bcc` in a scratch worktree with the v11
tests copied in, and reproduced both failures in exactly the claimed
modes: the JSON alias returned `Err(Crypto)` — it had passed dedup and
reached ratchet `decrypt`, which is the bypass — and the debt armed to 1
instead of 24, which is the wedge. The other 226 tests pass at the parent,
so the two new tests are the only delta. The scratch worktree was removed.

## Non-blocking

- **P3.** The codec-level ACCEPT direction of the new validator rule (a
  debt water in the out-of-order set decodes cleanly) is proven only via
  persistent-layer commits. A companion splice case in the state tests
  would pin it directly. In scope for the codec leg.
