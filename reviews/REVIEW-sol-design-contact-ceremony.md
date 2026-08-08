# Sol ruling — contact ceremony and KeyPackage publication

- **Ruling authority:** Sol (gpt-5.6-sol), security architect.
- **Brief:** `reviews/PROMPT-design-contact-ceremony.md`.
- **Relayed read-only.** Sol created no artifact and committed nothing; this
  file is the implementer's transcription. **Uncommitted** — repository under a
  no-commit hold.

## Disposition of the brief's central question

**The proposed three-layer split is CONFIRMED, with one correction that
matters:** the Gap-2 artifact is *not* merely transport data. It is an
**authorization capability carried by the transport layer**. Its wire format may
be frozen before MLS, but its authority, lifecycle, and identity binding are
security invariants, not plumbing.

The brief's pushback on slice F was upheld. Sol states outright: *"Symmetry with
the input side is not the safety argument; constrained authority, recipient
binding, one-time consumption, and non-extractability are."*

## Implementer's analysis — verified against the code

### 1. §5 is not satisfied today, and that is bigger than blocker 4's wording

Sol requires that every envelope carry authentication bound to the sender's
verified identity, the conversation, protocol version, generation, ciphertext,
and metadata — and states:

> Transport possession, relay admission, **a valid send capability**, and
> successful decryption SHALL NOT by themselves authenticate an envelope's
> sender.

Traced: `verify_envelope` (`src/capability.rs:192`) verifies against
`self.send_verification_key` — **the send capability key, not the peer's Ed25519
signing identity** — and binds only `queue_id`, `message_id`, `packet`, and
`expires_at`. The relay side likewise verifies against `send_key`
(`src/relay.rs:324`).

So the outer envelope authenticates **exactly** "a valid send capability", which
is the thing §5 says is insufficient. Conversation, version, generation and
sender identity are not bound at that layer.

**This is not a contradiction with the current claims** — blocker 4 is
unchecked, and inner `ClientPayloadV2` does bind conversation/epoch/sequence
while Olm authenticates the sender cryptographically at decrypt time. The
practical exposure is bounded by claim 18 (a binding-invalid payload cannot burn
the OTK or advance the ratchet).

**What is new** is scope: §5 makes blocker 4 substantially larger than its
wording implies. It reads as "before sharing a capability beyond one peer", but
Sol specifies a **per-envelope identity-binding requirement** the current outer
signature does not provide at all. Blocker 4 should be understood as a redesign
of envelope authentication, not a guard on capability sharing.

### 2. This ruling amends a frozen §2 decision

The caller-retention restriction is "narrowly amended" to permit one public
artifact, `SendCapabilityOffer`. Amending a frozen decision is exactly what the
Phase 3 leg went through seven rounds to do properly. Sol's own closing text
requires dual independent review at one exact SHA for the concrete constructions,
so this amendment should not land by implementer application alone.

### 3. A concrete API directive, not just a specification

> If these properties cannot be achieved while `commit_verified_contact`
> requires an externally supplied secret keypair, the correct design is to
> replace that parameter with typed artifact consumption inside the mutator.

`commit_verified_contact` (`src/persistent/mod.rs:788`) currently takes
`peer_send_keypair: Zeroizing<Vec<u8>>`. Under this ruling that parameter is
replaced by consumption of a typed `SendCapabilityOffer`, with consumption and
peer-binding commit as **one atomic operation**.

### 4. Open question — do accounts exist?

The ceremony record includes *"the subject's stable account identifier, **if
accounts exist**"*, and `SendCapabilityOffer` requires the recipient's and
issuer's "verified account identifier" without that conditional. The product
decision on record is invite/QR only, no discovery, no phone or email
identifiers. **Whether a stable account identifier exists at all is unresolved**,
and the safety number is specified to bind it. This needs answering before the
ceremony record can be encoded.

### 5. This ruling imposes requirements on the still-pending DS brief

§4 requires the Delivery Service to provide an atomic single-claim operation
with an authenticated receipt binding requester, publisher, package identifier,
package digest, publication generation, and result. The DS brief
(`reviews/PROMPT-design-delivery-service.md`) has not yet been relayed. **The
two rulings interlock** — the DS relay should note that its claim protocol is
already partly constrained by this one.

### 6. No trusted `now` — consistent

Expiry validation is specified as "using **caller-supplied trusted time**",
which preserves the frozen "the codec has no trusted `now`" constraint rather
than breaking it. Noted because blocker 9's scheduler collides with that same
constraint and this ruling shows the intended resolution: push time to the
caller.

---

# Security-architect ruling — contact ceremony and KeyPackage publication

## Ruling

The proposed three-layer split is correct, with one correction: the Gap-2 artifact is not merely transport data. It is an authorization capability carried by the transport layer. Its wire format can be frozen before MLS, but its authority, lifecycle, and identity binding must be specified as security invariants.

The resulting sequence is:

1. Freeze the human-verification ceremony and rebinding policy now.
2. Amend the caller-retention boundary and design the transferable send-capability artifact now.
3. Freeze publication and single-claim invariants now, but defer the concrete published key-material format, signature transcript, and claim protocol until the MLS ciphersuite and Delivery Service model are selected.
4. Require identity-bound authentication for every envelope independently of transport authorization.
5. Do not implement this protocol from inference or incrementally improvise missing rules during review.

This does not authorize implementation of the deferred portions, launch, or any public security claim.

## 1. Ceremony and identity pinning

The ceremony SHALL support both a machine-readable QR exchange and a human-comparable safety number. They are two presentations of the same canonical ceremony record, not independent verification mechanisms.

The canonical ceremony record SHALL contain:

- a protocol-domain separator and ceremony-version identifier;
- the subject's stable account identifier, if accounts exist;
- the subject's Ed25519 signing identity;
- any stable device identifier only if the product deliberately verifies devices rather than people;
- an explicit identity epoch or generation;
- an expiry time for the ceremony record;
- a fresh ceremony nonce;
- a signature by the included signing identity over every preceding field.

The QR encoding SHALL be a canonical encoding of that complete signed record. The safety number SHALL be derived from a domain-separated hash over both parties' canonical identity tuples, ordered canonically so both parties display the same value. The safety number SHALL bind the account identifier, signing identity, identity epoch, and protocol version for each party. It SHALL NOT include ephemeral prekeys, KeyPackages, relay capabilities, or mutable profile data.

The following text is normative:

> A contact is verified only after the local client has validated the peer's signed ceremony record and the human user has authenticated that record through an independent out-of-band comparison. Receipt of a record through the messaging relay, application deep link, contact-import channel, or other attacker-routable channel does not constitute verification.

> The out-of-band channel is assumed to provide authenticity through human comparison, not confidentiality. It may be observed, recorded, delayed, replayed, or copied by an attacker. If the attacker can replace both the in-band record and the human's out-of-band observation without detection, the ceremony provides no security claim.

For in-person verification, scanning the QR from the peer's unlocked device is sufficient after signature, version, expiry, and nonce validation. For remote verification, users SHALL compare the complete displayed safety number over an independently authenticated channel. A QR received over the same compromised relay path is not an independent ceremony.

The current `RedactedContactOffer` may be accepted only after its `signing_identity` exactly matches the identity established by this ceremony. Its signature and validity checks remain necessary but do not replace the ceremony.

## 2. Re-verification and identity change

Identity change SHALL fail closed. Silent replacement, trust-on-first-use overwrite, and automatic inheritance of verification status are forbidden.

Normative text:

> Any change to a verified peer's account identifier, signing identity, identity epoch, or device-verification scope SHALL invalidate the existing verified state before any message is sent or accepted under the new identity. The client SHALL preserve and prominently display the old and proposed new identity fingerprints, suspend affected outbound messaging, reject establishment under the new identity, and require a new independent ceremony.

> A relay assertion, signed statement from the new key alone, restored local backup, contact sync result, or ordinary application login SHALL NOT authorize rebinding.

The present single-assignment behavior is safe and SHALL remain until a dedicated rebinding state machine is designed and dual-reviewed. Rebinding SHALL be an explicit transition from a frozen old binding to a separately verified new binding. It SHALL be atomic, rollback-resistant, and auditable. No implementation may simulate rebinding by deleting or resetting the old contact record.

A future recovery mechanism may allow the old verified identity to sign a transition to a new identity, but this can reduce warning severity only. It SHALL NOT silently preserve human-verified status unless a human cryptographer approves that exact recovery protocol.

## 3. Gap 2 — transferable send capability

Section 2's caller-retention restriction SHALL be narrowly amended to permit one public transferable artifact: `SendCapabilityOffer`. A raw or generically serialized keypair export is rejected.

The artifact SHALL contain:

- a protocol-domain separator and artifact version;
- an opaque, canonical, bounded encoding of the minimum capability material required by the current receiver;
- the intended recipient's verified account identifier and signing-identity fingerprint;
- the issuer's verified account identifier and signing-identity fingerprint;
- a unique capability identifier;
- an issuance time and short expiry time;
- a capability generation;
- an explicit purpose and direction;
- a signature by the issuer's Ed25519 signing identity over all fields.

If the current receiver truly requires secret keypair material, the artifact SHALL additionally be encrypted to the intended recipient using a separately authenticated recipient encryption key bound by the verified identity. It SHALL never expose private capability material as plaintext, logs, display text, generic byte access, cloning, debug output, or durable caller-retained state.

Normative text:

> The public API SHALL expose construction, canonical serialization for transfer, parsing, validation, and one-time consumption of a typed `SendCapabilityOffer`; it SHALL NOT expose the underlying private keypair or a generic capability-owner export.

> Consumption SHALL verify issuer identity, intended recipient identity, purpose, direction, version, expiry using caller-supplied trusted time, capability generation, signature, and prior-consumption state before any peer binding commits. Consumption and peer-binding commitment SHALL be one atomic operation.

The artifact SHALL be single-recipient and single-use. Replays, cross-contact swaps, reflection back to the issuer, wrong-direction use, unknown versions, expired artifacts, and capability-generation rollback SHALL fail closed without partial state mutation.

This does not reintroduce F4 because the caller receives a sealed, typed, bounded transfer object rather than ownership of an unrestricted secret or a reusable serialized keypair. Symmetry with the input side is not the safety argument; constrained authority, recipient binding, one-time consumption, and non-extractability are.

If these properties cannot be achieved while `commit_verified_contact` requires an externally supplied secret keypair, the correct design is to replace that parameter with typed artifact consumption inside the mutator. It is not acceptable to weaken the artifact.

## 4. Publication and transactional single claim

The invariants can be frozen now; the concrete protocol is deferred.

A published MLS KeyPackage SHALL be signed and authenticated according to the selected standardized MLS ciphersuite and SHALL additionally bind, directly or through an approved credential chain:

- the publisher's verified account identity;
- the publisher's verified signing identity or approved successor credential;
- the device identity if devices are independently addressable;
- a unique package identifier;
- the supported suite and protocol version;
- an expiry;
- the publication generation.

The Delivery Service SHALL provide an atomic single-claim operation. A successful claim SHALL consume exactly the identified package and return an authenticated receipt binding requester, publisher, package identifier, package digest, publication generation, and claim result. Concurrent claims SHALL have at most one success. Retry behavior SHALL be idempotent for the same authenticated request and SHALL never silently substitute a different package.

Normative text:

> A client SHALL NOT trust a KeyPackage because the Delivery Service returned it. Before use, the client SHALL verify the KeyPackage signature, credential-to-verified-identity binding, expected publisher and device, supported suite, expiry, publication generation, and digest bound by the claim receipt.

> If a claim returns an unexpected identity, device, generation, package identifier, package digest, suite, expiry, signature, credential, or receipt, the client SHALL reject the result, perform no session-state mutation, and surface a security error. It SHALL NOT retry by accepting a replacement selected by the relay.

The current `one_time_key` offer mechanism SHALL not be expanded into a provisional relay publication protocol. OTK records are retired by the Phase 3 direction. Exact KeyPackage encoding, MLS credential construction, Delivery Service authentication, transactional storage protocol, receipt format, retry semantics, and exhaustion behavior are deferred until the MLS suite and Delivery Service trust model are fixed. This deferral does not permit implementation-specific placeholders to become normative.

## 5. Identity-bound envelope authentication

The ceremony authenticates a human-to-identity binding. A send capability authorizes a transport action. Neither authenticates each individual message envelope.

Every envelope SHALL carry cryptographic authentication bound to:

- the sender's verified identity or MLS credential;
- the intended recipient, group, or conversation;
- the protocol version and ciphersuite;
- the conversation identifier;
- the message generation or sequence;
- the payload ciphertext and relevant immutable metadata;
- the capability or authorization context where applicable.

Normative text:

> Transport possession, relay admission, a valid send capability, and successful decryption SHALL NOT by themselves authenticate an envelope's sender. The receiver SHALL verify identity-bound envelope authentication before delivering plaintext, generating receipts, advancing trusted conversation state, or applying control messages.

Unknown identities, stale identity epochs, wrong conversations, cross-recipient replay, metadata substitution, and validly encrypted but identity-mismatched envelopes SHALL fail closed. The current single-peer harness may model these bindings, but it does not prove multi-device, group, relay, or network behavior.

## 6. Tests and deferrals

The current harness can and SHALL test:

- canonical ceremony encoding, signature validation, safety-number agreement, domain separation, expiry, replay, and mutation rejection;
- exact pin-to-offer identity equality;
- fail-closed identity-change behavior and absence of silent rebinding;
- typed capability bounds, confidentiality where applicable, issuer/recipient/direction/purpose binding, one-time atomic consumption, replay, reflection, swap, expiry, rollback, and zero partial mutation;
- envelope identity, recipient, conversation, generation, ciphertext, and metadata binding;
- simulated single-claim state-machine races, idempotent retry, substitution rejection, and no-state-change failures.

Every negative test SHALL include an accept-arm control using a valid artifact differing only in the tested condition, and each test SHALL be demonstrated to fail against the corresponding mutant.

The harness cannot prove:

- human comparison quality or resistance to coerced/mistaken verification;
- camera/display integrity;
- independent-channel authenticity;
- real two-device lifecycle and recovery behavior;
- Delivery Service atomicity under real crashes, partitions, retries, rollback, and concurrency;
- network metadata properties;
- secure hardware behavior;
- interoperability or security of the future MLS suite.

Those require real network integration, at least two independent devices, fault injection, interoperability tests, and human review.

## Final gate

`SECURITY_STATUS.md` remains **NO-GO**. This ruling closes no unchecked blocker by itself, authorizes no commit, and authorizes no launch or public-security claim. No product surface may state or imply post-quantum protection before the standardized MLS migration is complete and validated.

The concrete MLS protocol, credentials, KeyPackage transcript, Delivery Service claim protocol, rebinding state machine, and identity-bound envelope construction require dual independent review at one exact SHA. A qualified human cryptographer SHALL approve the protocol and its shipped claims. No model holds final merge authority over the cryptographic core.
