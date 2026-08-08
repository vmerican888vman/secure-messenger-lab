# Remaining-work map — what "finish the messaging app" actually requires

**Status: implementer's analysis, 2026-08-08. Not certified by any reviewer.**
Derived from `SECURITY_STATUS.md` (15 unchecked blockers) read against
`docs/phase3-post-quantum-decision.md`. Uncommitted; the repository is under a
no-commit hold.

This exists because nobody had a remaining-work list. It is deliberately
pessimistic about sequencing, because the failure mode this project keeps
hitting is work that looked done and was not.

## The headline

**Two blockers cannot be closed by any amount of engineering here**, and both
are hard gates on launch:

- **Blocker 1** — independently reviewed protocol and complete formal threat
  model — requires a **human cryptographer or security firm**. No model holds
  final merge on the crypto core; that is a standing project rule.
- **Blocker 15** — the conditional PQ exception governance — requires **an
  independently acting security architect who is not the product owner.** On a
  one-human project this is currently satisfiable by **nobody**, which both
  reviewers confirmed is the intended fail-closed result. Until a second person
  exists in that role, the hold-shipment default stands regardless of code.

So "finish" is not reachable by finishing code. It is reachable by finishing
code **and** buying a review **and** finding a second responsible party.

The third structural fact: **the MLS migration invalidates part of what is
already built.** The ruling states existing PASSes are valid only for their exact
Olm code and **none transfers to MLS.**

## The 15, grouped by what actually gates them

### A. Closed or advanced by the contact-ceremony leg (3)

| # | Blocker | Ceremony's effect |
|---|---|---|
| 2 | Verified QR/contact ceremony + public handle for send-capability transfer | **Closes it**, if the ceremony is specified and built |
| 3 | Transactional one-time-key publication and single claim without relay substitution | **Partial.** Properties specifiable now; the concrete format waits on MLS KeyPackages (ruling retires OTK records) |
| 4 | Identity-bound envelope authentication beyond the single assumed peer | **Partial.** Depends on the ceremony's output but is a separate leg |

### B. Gated on MLS + the Delivery Service (2, plus rework)

| # | Blocker | Note |
|---|---|---|
| 10 | Offline ordering, retry, migration, relay failover, duplicate delivery, cross-relay deletion | MLS needs a DS that provides ordering; the pairwise-mailbox design has no serializer. The DS spike is ruling step 3 and is **unbuilt** |
| 12 | Recovery, revocation, multi-device decision | MLS changes what revocation means (group key rotation), so deciding pre-MLS risks deciding twice |

**Rework hiding here, not tracked as a blocker:** blocker 7 (façade/lifecycle
wiring, the §4 rebootstrap ceremony, receipt coalescing D2c) is built on the
Olm-specific 24/8/32 budget and `RekeyRequired`, which the ruling marks *"retire
and redesign against MLS epochs/commits."* **Work on D2c now is likely wasted.**
The ruling also says to stop adding discretionary Olm-only features. This needs
the architect's explicit confirmation rather than my inference — it is the
single largest "is this wasted effort" question outstanding.

### C. Protocol-independent — but two are less unblocked than first mapped

**Correction, 2026-08-08 (later).** This group was originally listed as
buildable immediately. Examining blockers 6 and 9 to start work on them showed
both have dependencies the first pass missed.

**Blocker 9 is a design decision, not a coding task.** The relay has a clock
source but **no scheduler**: `unix_now()` (`src/relay.rs:1133`, wrapping
`SystemTime::now`) is used only to supply a default `now` at five
convenience-constructor and count sites — there is no thread, no timer, and no
periodic task anywhere. `now` is otherwise a parameter on every call, and
`queued_message_count_at` sweeps before counting, so there is not even a
non-mutating probe for observing an unswept row. Sweeps ride on traffic:
`purge_expired_in` is called at seven sites inside operations, plus startup. A
continuously-running idle relay therefore never sweeps, which is exactly what
the blocker names. Fixing it means introducing a
scheduler, and that **collides with the frozen "the codec has no trusted `now`"
constraint** and raises whether this library takes a background thread at all
or exposes a `next_sweep_at`-style policy for a host to drive. That is an
architecture decision. Improvising one is the documented failure mode here, so
it needs a design brief rather than an implementer's choice.

**Blocker 6 is partly gated on blocker 2.** Coverage is already substantial —
30 crash/restart/recovery tests, including two systematic matrices,
`crash_reopen_discipline_between_every_mutator` (create → prekey → contact →
registration, with a drop/reopen between every mutator, asserting
single-assignment rejections survive) and `send_crash_discipline_between_every_mutator`.
The genuine remaining gap is a systematic **inbound** matrix over
fetch → decrypt → ACK. But that cannot be written at the integration level in
`tests/persistent_client.rs`, because the public API cannot complete a
conversation — the send-capability transfer does not exist (F4, blocker 2).
That is why the existing inbound crash coverage lives crate-internal in
`src/persistent/tests.rs`, reaching into private state. **So the full inbound
boundary matrix is downstream of the contact ceremony**, not parallel to it.

Remaining in this group and genuinely unblocked: 5, 8, 11.

These do not touch the crypto core and survive the migration.

| # | Blocker |
|---|---|
| 5 | Hardware-backed local wrapping key + safe fallback policy (lifecycle manager models the states; real platform adapters are open) |
| 6 | Crash/restart tests at every send/fetch/decrypt/persistence/ACK boundary (façade paths tested; full matrix is not) |
| 8 | Real authenticated network protocol, TLS config, request limits, traffic/log capture |
| 9 | Periodic expiry scheduler + measured wall-clock deletion SLA for an idle relay |
| 11 | Android physical-device crypto/store/notification spike |

**Blocker 11 deserves promotion.** OpenMLS builds its listed mobile targets but
does not test them, so mobile readiness is unestablished — and a device spike is
the only thing that finds what static review cannot. On a sibling project this
week, four static review rounds passed and hands-on device QA still found four
bugs, one of which made a feature completely unreachable. This is cheap relative
to what it de-risks and it does not depend on MLS.

### D. Product, ops, and compliance (3)

| # | Blocker | Note |
|---|---|---|
| 13 | Abuse reporting, blocking, rate limits/PoW, moderation, store compliance | Constrained by E2E-everywhere: no content-reading moderation is possible, so this is a design problem, not a feature list |
| 14 | Reproducible Android build, dependency/SBOM/provenance, external audit, incident plan | Reproducible builds are **Android-only** — Apple re-signs, so the anti-backdoor argument does not cover iOS. Say so publicly or do not claim it |
| 15 | Conditional PQ exception governance + provable operational hold | See headline. Also requires *proving* the hold blocks releases, onboarding, and ciphertext creation — that is executable evidence, not a document |

### E. Human-gated (1)

| # | Blocker | Note |
|---|---|---|
| 1 | Independently reviewed protocol and complete formal threat model | The threat model now exists and carries a dual PASS on internal coherence — **that is not the same thing.** This blocker wants a human cryptographer's review of the protocol |

## Honest sequencing

1. **Contact ceremony** (blockers 2, part of 3 and 4) — in flight; brief with the architect.
2. **Delivery Service ordering/fork spike** (unblocks 10, and decides whether MLS is viable over pairwise mailboxes). The ruling states MLS relies on a DS to break simultaneous-Commit ties and that *"the current pairwise-mailbox design does not provide that function"* — it does not say the spike may kill MLS. That stronger framing comes from the earlier project plan, not from the ruling, and should not be attributed to the architect. Either way it is an executable question, not a paper one.
3. **Android device spike** (11) — in parallel, no dependencies, highest information per hour.
4. **Confirm what MLS retires** before building more Phase-2 machinery, especially D2c.
5. Everything in group C as capacity allows.
6. Human review and the second-architect problem — start early, they have long lead times.

## What I am least confident about

- Whether blocker 7's remaining work survives MLS. I inferred "likely retired"
  from the retain/retire table; the architect should confirm or deny.
- Whether the DS spike is weeks or months. It is unscoped, and the ruling admits
  it may invalidate the MLS choice entirely.
- Whether the three-layer split proposed in the ceremony brief holds. If the
  architect rejects it, group A's timing changes.

## What this map is not

It is not a schedule, and it does not estimate. Prior planning on this project
put the timeline at 18–24 months solo with calls and multi-device; nothing here
contradicts that. It is a dependency map so that work is not spent on things the
migration will delete.
