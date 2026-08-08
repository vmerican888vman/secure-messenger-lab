# Fable review — THREAT_MODEL.md post-quantum section — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), dispatched directly as a
  subagent. Worktree `sml-review-threatmodel-fable-629753e`, clean before
  and after; no reviewed file modified.
- **Head SHA reviewed:** `629753e6f30e6d4cff280e6250ca531f05ef70b9`.
- **Verdict: PASS** — no blocking defects.
- Document review, not code; no gates apply.

## The central claim, verified against the vendored key schedule

Fable read the actual code rather than reasoning from general knowledge:

- `shared_secret.rs` — R0 and C0,0 = `HKDF-SHA256(salt=[0], ECDH(Ia,Eb) ‖
  ECDH(Ea,Ib) ‖ ECDH(Ea,Eb), info="OLM_ROOT")`. All three inputs are
  X25519 shared secrets; salt and info are public constants. **No PSK, no
  out-of-band secret, no ceremony entropy is mixed in.**
- `session/root_key.rs` — every root advancement is
  `HKDF(salt=previous root, DH(new ratchet pair), info="OLM_RATCHET")`.
  X25519-only plus constants.
- `session/chain_key.rs` and `cipher/mod.rs` — chain advance and
  message-key extraction are HMAC-SHA256 with constant seeds, then HKDF
  with public info. Deterministic given the chain key.
- `messages/message.rs`, `messages/pre_key.rs` — every normal message
  carries the sender's current ratchet public key and chain index; every
  pre-key message carries the sender identity key, base key and recipient
  one-time key public.

**Conclusion: the entire schedule is a deterministic function of X25519
DH outputs plus public constants.** A CRQC solving Curve25519 discrete
logs recovers one private key per DH pair from recorded publics and
recomputes R0, every root advancement, every chain and every message key.

So the document's two strongest sentences are correct for this codebase:
harvesting one session compromises that session's messages *generally*,
and ratcheting bounds the damage from a stolen key, not from a broken
primitive.

## Drift check — none found

Compared clause by clause against `docs/phase3-post-quantum-decision.md`.
The claim sentence is verbatim identical. The does-not-cover list matches
the ruling's five exclusions exactly. The provisional suite name, the
confidentiality-versus-authenticity split, the gate restatement including
mobile/device validation, and the substituted-identity point all match.
Nothing authorises an interim layer, weakens the gate, or claims anything
the ruling withheld.

## Internal consistency and completeness

Seven-day expiry matches the metadata budget row; the
logical-not-forensic reference matches the deletion-semantics section
word for word; the rewritten CRQC entry is coherent with its heading and
with `SECURITY_STATUS.md`, which makes no PQ claim. All five items the
ruling asked for are present with substance — none is hollow.

**On the undecided horizon:** acceptable. The falsifiable content — no PQ
protection at any head, the migration boundary, the gated claim — does
not depend on the horizon value, and the table honestly flags the
decision as open with its conditional consequence stated.

## Non-blocking

1. **The one place the vodozemac check bit.** "Everything it requires —
   the ciphertext and the handshake public keys — is already on the wire
   by design" is slightly too strong for THIS harness: the `ECDH(Ea, Ib)`
   leg needs the recipient's long-term Curve25519 identity public, which
   is not in the pre-key message — it travels only in the contact bundle,
   which `src/client.rs` says is transferred out of band and never
   published by the relay. A strictly wire-only recorder lacks that one
   input. It does not weaken the model (a long-term public key is not a
   confidential asset, standard threat modelling grants the adversary all
   public keys, and the planned system publishes KeyPackages anyway) and
   it errs in the safe direction by overstating the adversary. Suggested
   correction: "the ciphertext, the handshake public keys carried in
   pre-key and ratchet messages, and the peer's long-term identity public
   key distributed in the contact bundle — all public by design."
2. The undecided plaintext horizon is flagged in the table but tracked
   nowhere that forces the decision — and it is exactly what determines
   whether PQ is a shipping requirement, which triggers the ruling's
   hold-shipment rule. A link to that rule, or an open item in
   `SECURITY_STATUS.md`, would close the loop.
3. "The cost of hybridising is bounded and known" — "known" is generous
   given the ruling itself says mobile readiness is unestablished.
   "Bounded" alone carries the argument.
4. "Would remain false even after migration, because the third is
   broader" — all three terms remain false for the same reason; the
   sentence gives the reason only for the third. Wording nit.
