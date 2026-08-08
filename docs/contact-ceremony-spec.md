# Specification — contact ceremony, identity pinning, and send-capability transfer

**Status: DRAFT for dual independent review. Not certified. Uncommitted.**
Repository is under a no-commit hold.

**Authority.** The normative content is the security architect's ruling,
transcribed at `reviews/REVIEW-sol-design-contact-ceremony.md`. This document
specifies the concrete constructions that ruling requires and does not supply.

**Every construction below is marked:**

- **[N]** — normative, restating the architect's ruling.
- **[P]** — **proposed by the implementer.** Needs review. Not authorized.

The architect was explicit: *"Do not implement this protocol from inference or
incrementally improvise missing rules during review."* Accordingly, no code has
been written, and every gap the ruling left is marked **[P]** rather than
silently filled.

**A human cryptographer must approve this before any shipped claim.** No model
holds final merge authority over the cryptographic core.

## Scope

In scope, because the architect authorized freezing these now: the ceremony
record and its encodings, the safety number, identity-change detection, and the
`SendCapabilityOffer` artifact.

Out of scope, deferred by the ruling: KeyPackage encoding, MLS credential
construction, Delivery Service claim protocol, receipt format, and the rebinding
state machine.

## Product decisions incorporated

| Decision | Date | Consequence here |
|---|---|---|
| **Single profile per installation** | 2026-08-08 | `CHECK(slot = 1)` in `lifecycle_profiles` is correct and untouched. No cross-profile unlinkability property is claimed. |
| **Stable opaque account identifier** | 2026-08-08 | 16 random bytes minted at profile creation. No PII. Shared only with ceremony-verified contacts; **never relay-visible**, so the metadata budget is unchanged. Rationale: §2 makes identity change expensive, so identity-equals-signing-key would mean keys could never rotate. |
| **Invite/QR only, no discovery** | prior | There is no directory, no phone number, no email. The ceremony is the only path to a verified contact. |

### [P] Assumption requiring confirmation — no device identifier

The ruling admits a device identifier *"only if the product deliberately
verifies devices rather than people."* **This spec assumes people, not
devices**, and omits any device identifier.

Reasoning: multi-device is undecided and deferred (blocker 12). A device-bound
ceremony would require re-verifying every contact per device later — exactly the
friction §2 deliberately makes expensive. Signal and SimpleX both verify
identities rather than devices.

**If the reviewers disagree, this changes the ceremony record, the safety
number, and the rebinding triggers.** It is the single assumption with the
widest blast radius.

## 1. Canonical encoding — reuse, do not invent

**[N]** The record is a signed structure with a protocol-domain separator.

**[P]** Use the existing house primitive rather than a new encoding.
`canonical(action, parts)` (`src/capability.rs:432`) prepends
`PROTOCOL_DOMAIN` (`b"secure-messenger-lab/phase0/v1"`), then the action label,
then each part — every element preceded by its length as a big-endian `u64`.

Length-prefixing every field is what makes the encoding unambiguous: no choice of
field values can produce the same byte string under a different field split.
That property is the reason to reuse this helper rather than define a second
encoding whose injectivity would need separate argument.

**[P]** New action labels, following the existing naming style:

| Purpose | Label |
|---|---|
| Ceremony record signature | `contact-ceremony-record/v1` |
| Safety number derivation | `contact-safety-number/v1` |
| Send-capability offer signature | `send-capability-offer/v1` |

**[P] Open:** the ruling requires a *ceremony-version identifier* distinct from
the protocol domain. Proposed as an explicit `u16` field, so the ceremony can be
revised without moving `PROTOCOL_DOMAIN`, which other subsystems depend on.

## 2. The ceremony record

**[N]** Fields, in the ruling's order, all covered by the signature:

| # | Field | **[P]** representation |
|---|---|---|
| 1 | Protocol-domain separator | supplied by `canonical()` |
| 2 | Ceremony-version identifier | `u16` big-endian |
| 3 | Account identifier | 16 bytes |
| 4 | Ed25519 signing identity | 32 bytes |
| 5 | Device identifier | **omitted** — see the assumption above |
| 6 | Identity epoch | `u64` big-endian |
| 7 | Record expiry | `u64` big-endian, seconds |
| 8 | Ceremony nonce | 16 bytes, fresh per record |
| 9 | Signature | Ed25519 over `canonical()` of fields 1–8 |

**[P]** The identity epoch is a monotonically increasing counter, incremented
whenever the signing identity changes. It exists so that an old, validly signed
record cannot be replayed as current after a key change — the epoch, not the
signature, is what makes staleness detectable.

**[P]** Record expiry is validated against **caller-supplied trusted time**,
consistent with the frozen "the codec has no trusted `now`" constraint and with
the ruling's own wording for capability expiry.

### Validation order **[P]**

Fail closed at the first failure, with no state mutation at any point:

1. Ceremony version is recognised.
2. Signature verifies **against the signing identity contained in the record**.
3. Expiry is in the future relative to caller-supplied time.
4. Nonce has not been seen before for this account identifier.
5. Only then is the record eligible to be presented to the human.

Step 2 deserves care: a self-signed record proves only internal consistency —
that the holder of that key made that statement. **It proves nothing about who
the key belongs to.** The human comparison in §3 is what supplies that, and no
amount of signature checking substitutes for it.

## 3. Verification — what the ceremony actually claims

**[N]** Verbatim from the ruling, normative:

> A contact is verified only after the local client has validated the peer's
> signed ceremony record and the human user has authenticated that record
> through an independent out-of-band comparison. Receipt of a record through the
> messaging relay, application deep link, contact-import channel, or other
> attacker-routable channel does not constitute verification.

> The out-of-band channel is assumed to provide authenticity through human
> comparison, not confidentiality. It may be observed, recorded, delayed,
> replayed, or copied by an attacker. If the attacker can replace both the
> in-band record and the human's out-of-band observation without detection, the
> ceremony provides no security claim.

**[N]** In person, scanning the QR from the peer's unlocked device suffices
after signature, version, expiry and nonce validation. Remotely, users compare
the **complete** safety number over an independently authenticated channel. A QR
received over the same relay path is not an independent ceremony.

**[P] Implementation consequence.** The two presentations must not be
substitutable in the UI. A "scan" affordance that silently accepts a record
arriving through the app would convert an attacker-routable channel into an
apparent ceremony. Scanning must be camera-only, from a physically present
device.

## 4. Safety number

**[N]** Derived from a domain-separated hash over both parties' canonical
identity tuples, canonically ordered so both parties display the same value.
Binds account identifier, signing identity, identity epoch, and protocol version
for each party. **Must not** include ephemeral prekeys, KeyPackages, relay
capabilities, or mutable profile data.

**[P]** Construction:

1. Each party's tuple: `canonical(b"contact-safety-number/v1", [version, account_id, signing_identity, identity_epoch])`.
2. Order the two tuples **byte-lexicographically** — not by role, not by who
   initiated. Both sides must compute the same order without coordination.
3. `digest = SHA-256(canonical(b"contact-safety-number/v1", [lower, higher]))`.
4. Render for humans as decimal groups.

**[P] Open, and this needs a cryptographer rather than me:**

- **Truncation length.** Signal uses 60 decimal digits. The security parameter is
  the cost of finding a colliding identity pair that displays identically. I
  propose 60 digits (≈199 bits) but have not analysed it, and note that the
  relevant attack is offline second-preimage search against a *displayed*
  truncation, not against SHA-256.
- **Digit derivation.** Converting hash bytes to decimal groups must not
  introduce modulo bias in a way that reduces the effective space.
- **Whether SHA-256 is the right choice** given `sha2 = 0.10.9` is already a
  dependency and adding another hash increases audit surface.

**[P]** The full value must be displayed and compared. Truncated comparison —
"first and last group" — is a common UX shortcut and it silently destroys the
security parameter. The UI must not offer it.

## 5. Identity change — detection and fail-closed

**[N]** Fail closed. Silent replacement, TOFU overwrite, and automatic
inheritance of verified status are forbidden.

**[N]** Verbatim:

> Any change to a verified peer's account identifier, signing identity, identity
> epoch, or device-verification scope SHALL invalidate the existing verified
> state before any message is sent or accepted under the new identity. The client
> SHALL preserve and prominently display the old and proposed new identity
> fingerprints, suspend affected outbound messaging, reject establishment under
> the new identity, and require a new independent ceremony.

> A relay assertion, signed statement from the new key alone, restored local
> backup, contact sync result, or ordinary application login SHALL NOT authorize
> rebinding.

**[N] Not designed here.** The ruling states the present single-assignment
behaviour SHALL remain until a dedicated rebinding state machine is designed and
dual-reviewed. **This spec therefore specifies detection and refusal only.**
`commit_verified_contact`'s existing at-most-one-peer-binding rule stays exactly
as it is.

**[P]** Detection triggers — any of these, compared against the committed
binding: account identifier differs, signing identity differs, identity epoch is
lower than or equal to the committed epoch when the identity differs, or the
identity epoch moves without a completed ceremony.

**[P]** On detection: no state mutation, a distinct error variant separate from
ordinary verification failure, and both fingerprints preserved for display. An
identity change must not be reportable as a generic failure — the user has to be
able to tell "this peer's key changed" from "this message was malformed."

## 6. `SendCapabilityOffer`

**[N]** §2's caller-retention restriction is narrowly amended to permit exactly
this one public transferable artifact. A raw or generically serialized keypair
export is rejected.

**[N]** Fields — all covered by the issuer's signature:

| # | Field | **[P]** representation |
|---|---|---|
| 1 | Protocol-domain separator | supplied by `canonical()` |
| 2 | Artifact version | `u16` big-endian |
| 3 | Capability material | opaque, canonical, **bounded** encoding of the minimum the receiver requires |
| 4 | Recipient account identifier | 16 bytes |
| 5 | Recipient signing-identity fingerprint | 32 bytes |
| 6 | Issuer account identifier | 16 bytes |
| 7 | Issuer signing-identity fingerprint | 32 bytes |
| 8 | Capability identifier | 16 bytes, unique |
| 9 | Issued-at | `u64` big-endian |
| 10 | Expiry | `u64` big-endian, **short** |
| 11 | Capability generation | `u64` big-endian |
| 12 | Purpose and direction | explicit enum, not a free-form string |
| 13 | Signature | Ed25519 by the issuer's signing identity over 1–12 |

**[N]** If secret keypair material is genuinely required, the artifact SHALL
additionally be **encrypted to the recipient** under a separately authenticated
recipient encryption key bound by the verified identity. It SHALL never expose
private capability material as plaintext, logs, display text, generic byte
access, cloning, debug output, or durable caller-retained state.

**[P] Open — this is the load-bearing unresolved question.** Whether secret
material is required at all depends on what the receiver truly needs. If the
send capability can be reduced to something the issuer can delegate *publicly* —
an authorization the relay verifies rather than a secret the peer holds — the
encryption requirement disappears and the artifact becomes far safer. **I have
not established which is the case**, and the answer determines whether this
artifact carries secrets at all. It should be settled before implementation.

**[P] Rust-level obligations** implied by "never expose … cloning, debug output":
no `Clone`, no `Copy`, a manual `Debug` that redacts, no `Deref` to bytes, no
public accessor returning the material, and `Zeroizing` for any secret. These
are compile-time enforceable and should be, in the spirit of §5's existing
type-state discipline.

**[N]** Consumption verifies issuer identity, recipient identity, purpose,
direction, version, expiry against caller-supplied trusted time, capability
generation, signature, and prior-consumption state **before any peer binding
commits**, and consumption plus commitment are **one atomic operation**.

**[N]** Single-recipient, single-use. Replay, cross-contact swap, reflection
back to the issuer, wrong direction, unknown version, expiry, and
generation rollback all fail closed with **no partial state mutation**.

**[N] API change.** Per the ruling: if these properties cannot hold while
`commit_verified_contact` takes an externally supplied secret keypair, the
parameter is replaced by typed artifact consumption inside the mutator. The
current signature (`src/persistent/mod.rs:788`) takes
`peer_send_keypair: Zeroizing<Vec<u8>>`; under this spec that becomes a
`SendCapabilityOffer`.

**[N]** F4 is not reintroduced, and the argument is *not* symmetry with the
input side — it is constrained authority, recipient binding, one-time
consumption, and non-extractability.

## 7. Test plan

**[N]** Every negative test carries an accept-arm control using a valid artifact
differing only in the tested condition, and each test is demonstrated to fail
against its mutant. This project has had four vacuous tests; the discipline is
not optional.

Testable here:

- canonical encoding injectivity; signature validation; domain separation
- safety-number agreement across both orderings; mutation of any bound field changes it
- expiry, replay, and nonce reuse rejection
- exact pin-to-offer identity equality
- identity-change detection, fail-closed, distinct error, zero mutation
- capability bounds, issuer/recipient/purpose/direction binding
- one-time atomic consumption; replay, reflection, swap, expiry, generation rollback
- zero partial mutation on every rejection path

**[N]** Not provable in this harness: human comparison quality, coerced or
mistaken verification, camera and display integrity, independent-channel
authenticity, real two-device lifecycle, DS atomicity under real faults, network
metadata, secure hardware, and MLS interoperability.

## 8. Questions for the reviewers

1. **The no-device-identifier assumption** — widest blast radius.
2. **Safety-number truncation length and digit derivation** — needs a
   cryptographer, not a reviewer's intuition.
3. **Does the send capability require secret material at all?** If not, the
   encryption requirement and most of the artifact's risk disappear.
4. **Ceremony-version identifier as a separate field** rather than folding into
   `PROTOCOL_DOMAIN`.
5. Whether identity-epoch monotonicity as specified is sufficient to prevent
   stale-record replay.

## Final gate

`SECURITY_STATUS.md` remains **NO-GO** with 15 unchecked blockers. This document
closes none of them, authorizes no implementation, no commit, no launch, and no
public-security claim. Blockers 2, 3 and 4 remain open and will remain open
until the constructions here are built, dual-reviewed at one exact SHA, and
approved by a human cryptographer.
