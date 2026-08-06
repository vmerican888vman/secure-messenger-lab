# Codec v6 review — VERDICT: RETURN

- **Head SHA reviewed:** `eb2020e8beb178b2e933ef4d62fb9f0b5d1637e1`
  (pinned worktree `sml-review-codec-v6-eb2020e`, clean, detached).
- **Verdict: RETURN** — transcribed from the user's paste; the relayed
  text did not name the reviewer.
- The v5 remediations were confirmed present and effective; all gates
  passed at the head.

## Blocking findings

1. **Long-term identity keys can alias transferable mailbox send
   capabilities.** `check_mailbox` only distinguishes the three mailbox
   keys; it never compares the send key with `own_ed25519_identity`.
   `check_peer_binding` likewise permits the peer send keypair to equal the
   peer's pinned signing identity. This violates the documented separation
   (`docs/architecture.md`): the mailbox send private key is shared with the
   peer, while contact bundles use a separately pinned identity. Concrete
   reproduction: an account pickle's canonical `signing_key` reused as
   `send_keypair_json` (distinct receive/manage keys, valid manage-signed
   registration, session-dependent records empty) passed both `encode()` and
   `decode()`. Transferring that sender capability would disclose the
   long-term identity secret and permit forged contact/prekey signatures.
2. **Matching inbound and dedup records may disagree on message expiry.**
   `check_inbound` compares epoch, sequence, queue and digest, but not
   `dedup.expires_at == inbound.expires_at`. Frozen §3 requires expiry and
   dedup references to cross-check. Concrete reproduction: changing only the
   matching dedup record's expiry to 0 passed both `encode()` and
   `decode()`; expiry-based retention could discard replay protection before
   the corresponding inbound record's authenticated deadline.

## Verification (per the reviewer)

- Worktree remained detached, clean, at the exact SHA.
- `cargo test --locked --all-targets` and strict Clippy passed.
- Both hostile acceptance cases were confirmed with isolated temporary
  tests; the review worktree was not modified.
- No `reviews/REVIEW-*` file was opened.
