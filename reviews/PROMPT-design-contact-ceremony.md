# Design brief — contact ceremony and KeyPackage publication

**This is a design request, not a review.** You are being asked to rule as
security architect, as you did for Phase 3. Nothing is committed and nothing
will be until you rule — the repository is under a no-commit hold while its
public surface is audited.

This is **sequencing step 2** of your own Phase 3 ruling, and the two biggest
unchecked blockers in `SECURITY_STATUS.md`. Your ruling's words: *a PQ KEM
authenticated to a substituted identity solves nothing.* Everything the
seven-round amendment bought is worth nothing against key substitution during an
unverified exchange.

## Ground truth — verified by reading the code, not asserted

**What exists and works.** `RedactedContactOffer`
(`src/persistent/mod.rs:379`) is the transferable artifact: `signing_identity`
(Ed25519), `curve_identity` (Curve25519), `one_time_key` (Curve25519),
`valid_until`, `signature`. It never contains the account, a pickle, or a
private key.

`commit_verified_contact` (`src/persistent/mod.rs:788`) does genuinely verify —
I traced the executing path:

- `offer.signing_identity` must equal the caller's `pinned_signing_identity`
- the validity window is checked against `now` and `CONTACT_OFFER_MAX_VALIDITY_SECONDS`
- **the signature is verified** — `pinned_signing_identity.verify(&prekey_signing_bytes(&bundle), &offer.signature)` — against the reconstructed bundle, inside the mutator, before any state commits
- at most one peer binding may ever be committed (single-assignment)

So the offer is cryptographically bound to the pinned identity on the live path.
That part is not the gap.

**Gap 1 — the pinning has no ceremony.** Everything above rests on the caller
already holding the correct `pinned_signing_identity`. There is no QR exchange,
no safety-number comparison, no out-of-band channel — nothing that establishes
*where the pinned identity came from*. The strongest verification in the world
over an attacker-supplied pin is worthless.

**Gap 2 — the send capability cannot be transferred.** `commit_verified_contact`
takes `peer_send_keypair: Zeroizing<Vec<u8>>`, but the façade **by design never
exports a typed or serialized capability owner** (review finding F4), so there is
no public way to obtain the peer's send capability to pass in. `src/main.rs`
states this in its module docs and the demo stops before session establishment:

> the public API has no handle for the out-of-band send-capability transfer

The exact missing thing is a public **transferable send-capability artifact**,
which **the frozen §2 caller-retention list currently forbids.** That is the
design tension, and it is why this is being escalated rather than patched.

**Gap 3 — no publication or single-claim path.** The offer carries exactly one
`one_time_key`, handed over out of band. There is no relay-mediated publication
with transactional single claim, and therefore no defence against relay key
substitution — `SECURITY_STATUS.md` blocker 58.

## The sequencing question, and a proposed answer from your own table

Sequencing step 2 says to freeze *"single-use **KeyPackage** publication/claim"*
— MLS vocabulary — while the ruling retires the Olm prekey machinery. So the
obvious worry is that designing this now builds something MLS immediately
retires.

**Your retain/retire table appears to resolve it, by splitting the ceremony into
three layers with different fates.** Proposed, for you to confirm or correct:

| Layer | Table says | Proposal |
|---|---|---|
| **Identity + pinning** — the out-of-band exchange, what is compared, rebinding policy | not in the table; protocol-independent | **Design and freeze now.** MLS changes the key material, not what it means to have verified a human. |
| **Send-capability transfer** — the Gap-2 artifact | line 82: *Relay capabilities … **Retain transport invariants**; rebind to MLS messages* | **Design now.** This is transport, not crypto. It is explicitly retained, so it is not wasted work. |
| **Key material** — `one_time_key` today, KeyPackage later | line 83: *OTK records … **Retire*** | **Defer.** Specify the publication/claim *properties* now; bind them to a concrete format when the MLS suite is fixed. |

If that split holds, two of the three gaps are workable immediately and only
publication/claim waits on MLS. If it does not hold — in particular if you think
the capability artifact cannot be designed without knowing what an MLS
KeyPackage claim looks like — say so, because it inverts the plan.

**Prior art you should know about, which predates your ruling.**
`reviews/PROMPT-independent-phase2-slice-f.md` already declared Gap 2 and
proposed a shape:

> The demo stops before the conversation: the public API has no transferable
> send-capability artifact, so `commit_verified_contact` cannot be satisfied
> externally. The fix (a minimal export returning the bounded canonical
> serialized keypair, symmetric with the input side) is a follow-up leg needing
> its own review.

That was written before Phase 3. Two things to rule on: whether a minimal
symmetric export is still the right shape, and whether exporting it reintroduces
what F4 deliberately removed — the slice-F note asserts symmetry with the input
side as the safety argument, and I do not think symmetry alone establishes that.

## What I need specified

1. **The ceremony itself.** What is exchanged out of band, over what channel,
   and what does each party verify? QR encoding a signed identity, a
   comparable safety number, both? What is authenticated *by* what, and what is
   the attacker model for the out-of-band channel — assumed authentic,
   assumed only confidential, or assumed hostile?
2. **Re-verification and change.** What happens when a peer's identity key
   changes? Silent accept is how identity substitution actually lands in
   shipped messengers. Note the current code permits **at most one** peer
   binding, ever — so rebinding is presently impossible, which is safe but may
   be too rigid.
3. **Gap 2's resolution.** Either §2 is amended to permit a transferable
   capability artifact — in which case specify its exact shape, what it binds
   to, and why exporting it does not reintroduce what F4 removed — **or** the
   design changes so that no capability transfer is needed. I am not choosing
   between those.
4. **Publication and single claim.** How a one-time key or KeyPackage is
   published and claimed exactly once, such that a hostile relay cannot
   substitute a key it controls. What is signed, what is checked, and what the
   client does when a claim returns something unexpected.
5. **Identity-bound envelope authentication** (blocker 60) — where it sits
   relative to the ceremony, since the current harness assumes a single verified
   peer.
6. **What is testable now.** Which properties can be proved in this harness, and
   which are inherently unprovable without a real network and a second device.
   I would rather record an untestable property honestly than write a test that
   passes for the wrong reason.

## Constraints

- No `vodozemac` fork.
- Nothing may regress a leg carrying an independent dual PASS.
- The codec has no trusted `now`.
- `SECURITY_STATUS.md` is NO-GO with 15 unchecked blockers. Nothing here
  authorizes a launch or a public-security claim, and no product surface may
  state or imply post-quantum protection before migration.
- A human cryptographer signs off on the protocol before any shipped claim; no
  model holds final merge on the crypto core.

## Process notes, learned the hard way on this repo

- **Do not let me improvise this.** A reciprocity gate was once invented
  mid-loop to close a reviewer finding; it deadlocked honest peers and took a
  seven-round failure loop and a full revert. The loop only ended when the
  *design* was escalated instead of patched a fourth time. That is why this is a
  brief and not a pull request.
- **Every negative test gets an accept-arm control.** Four separate tests here
  once passed vacuously. Anything you specify should be falsifiable, and I will
  prove each test fails against the mutant before I claim it works.
- If a bound needs repeated tuning, the bound is measuring the wrong thing —
  that was the §4 control-lane split.

## Output

A ruling in prose. Where you want exact text in a document, quote it exactly as
it should appear. It will be transcribed verbatim into
`reviews/REVIEW-sol-design-contact-ceremony.md` and then dual-certified at one
SHA, as the Phase 3 amendment was.

If the honest answer is that part of this cannot be specified until the MLS and
Delivery Service decisions land, say which part and why — a deferral you name is
worth more than a specification you are not confident in.
