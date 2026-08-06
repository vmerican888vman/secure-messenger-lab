# Codec v7 review — VERDICT: PASS

- **Reviewer:** one of the two independent reviewers — the relayed paste did
  not state which; recorded unattributed pending the user's confirmation.
  Pinned worktree `sml-review-codec-v7-89027ea`, clean at the exact SHA.
- **Head SHA reviewed:** `89027eace7a50fcfcd0b73aad163867bbe1000b0`.
- **Verdict: PASS** — no blocking findings. Transcribed from the user's
  paste.

## Coverage (per the reviewer)

- Gates green: `cargo test --locked --all-targets` (173 lib incl. ~70
  state:: + all integration), clippy `-D warnings`, `cargo fmt --check`.
- Independent source trace of tlv/records/mod/validate against frozen §3/§4
  and the required-attack list: exact field count and ascending-ID
  enforcement, bound-before-consume, canonical-JSON byte equality,
  complete-consumption; account re-pickle equality, OTK-store consistency
  (unique derived publics, unpublished-map correspondence, `next_key_id`
  strictly above retained ids + wrap headroom), mailbox/identity
  non-aliasing, role-aware transcripts, epoch_id derivation, receipt-free
  conversation binding, receive-side provenance via `has_received_message`,
  the §4 high-water/mode matrix with `RekeyRequired` dominating, receipt
  rules, cross-record dedup matching (inbound requires `expires_at`
  agreement, ACK correctly does not).
- Both v6 blockers confirmed fixed with regression tests.
- Own adversarial probe: exhaustive single-byte-flip fuzz (low and high
  bits) across the entire populated encoding — every flip rejected or
  re-encoded byte-identically; zero non-canonical acceptances outside the
  three documented AEAD-covered fields.
- Declared gaps (no trusted clock at load; profile/key-ref/generation
  AEAD-covered; terminal digests and inbound signed-expiry structural-only)
  judged appropriate at this crate-private leg.

Note: the codec has since gained a wire amendment (ActiveSession field 19,
`last_staged_receipt_high_water`, head `844f6b1`) driven by the D2b v3
remediation — that delta is covered by the D2b v4 brief and needs its own
reviewer sign-off before the codec gate closes.
