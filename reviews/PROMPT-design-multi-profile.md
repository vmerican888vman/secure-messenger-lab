# ⚠ DEFERRED — NOT RELAYED. Product decision 2026-08-08: SINGLE PROFILE.

The owner decided against multiple profiles for now: *"single is less
complicated."* This brief was written before that decision and was **never sent
to the architect.** Retained because SimpleX-style multi-profile is a plausible
later feature and the analysis below would otherwise have to be redone.

**What the single-profile decision resolves:**

- **C2 is closed, favourably.** `CHECK(slot = 1)` in `lifecycle_profiles` is not
  a collision — it is now *correct*, and matches the product. The frozen
  exact-schema contract and the checked schema-shape claim stand untouched. The
  existing design was right for the product that is actually being built.
- **C3 is closed.** There is no cross-profile unlinkability to claim, so no new
  security property enters the threat model and no correlation analysis is owed.
  Note for any future revival: `THREAT_MODEL.md` still contains **zero**
  occurrences of "profile", so this would be greenfield.
- **The account-identifier decision survives unchanged.** Its justification never
  depended on multi-profile — it rests on §2 making identity change expensive, so
  that identity-equals-signing-key would mean keys can never rotate.

**What survives, in changed form — C1.** The device-identifier question is still
open, but it is no longer about linking profiles. It is now tied to the
**multi-device** decision (blocker 12), which is itself deferred pending MLS.
Carried into the ceremony spec rather than a separate architect round.

---

# Design question — multiple profiles per installation

**A design request, not a review.** Short: one product decision landed that your
ceremony ruling did not have in front of it, and it settles one of your own
conditionals while colliding with a frozen schema.

Nothing is committed; the repository is under a no-commit hold. This is not a
request to implement anything.

## The product decision

**The app will support multiple profiles at once, SimpleX-style** — one
installation, several independent identities, deliberately compartmentalised so
that contacts of profile A cannot tell it shares a device with profile B.

Also decided, following your ceremony ruling: identity gets a **stable opaque
account identifier**, 16 random bytes minted at profile creation, no PII. It is
shared only with ceremony-verified contacts and is **never relay-visible** — the
relay continues to see only random queue IDs, so the metadata budget is
unchanged. The reason for a separate identifier rather than reusing the Ed25519
signing key is your §2: with identity *equal to* the signing key, every key
rotation becomes a full identity change requiring re-ceremony with every
contact, which in practice means keys can never rotate. Your safety number also
binds account identifier, signing identity and identity epoch as three distinct
dimensions, which only works if they are distinct. Correct me if that reasoning
is wrong.

## C1 — this resolves your device-identifier conditional. Please confirm.

Your ceremony record specifies:

> any stable device identifier only if the product deliberately verifies devices
> rather than people

With multiple profiles per installation, **a stable device identifier in the
ceremony record links every profile on that device to every other.** That
defeats the entire purpose of compartmentalisation.

Reading: **no device identifier in the ceremony record; the ceremony verifies
people, not devices.** Confirm or correct — it is a one-line answer that unblocks
encoding the record.

## C2 — it collides with a frozen, dual-reviewed schema

`src/lifecycle.rs:111`:

```sql
slot INTEGER PRIMARY KEY NOT NULL CHECK(slot = 1),
```

`lifecycle_profiles` is hard-constrained to **exactly one row**. One profile per
store, by construction. That table sits under the comment *"The exact-schema
contract: whitespace is part of it, as in the store"*, and exact fail-closed
schema-shape validation is a **checked** claim in `SECURITY_STATUS.md`. Relaxing
the CHECK would break schema-shape validation and re-open that claim.

Two shapes, neither chosen here:

- **One store directory per profile.** The constraint is per-store, so N profiles
  become N stores and the frozen schema is untouched. It also inherits the
  owner-only ACL-free directory boundary already reviewed under claim 43. Cost:
  a profile→directory mapping layer that does not exist, and a question about
  where it lives and whether *it* becomes a linkability artifact.
- **Relax the CHECK to allow N rows.** Simpler mapping, but it reopens a frozen
  schema and a checked claim, and puts all profiles in one database file.

The first looks right for compartmentalisation, but it is your call.

## C3 — cross-profile unlinkability is not modelled anywhere

`THREAT_MODEL.md` contains **zero** occurrences of "profile". There is no
unlinkability, correlation, or compartmentalisation modelling of any kind.

This matters because unlinkability would become a **claimed security property**,
and separate storage buys only storage separation. Correlation channels that
survive it, none currently analysed:

- the shared platform key and the single lifecycle manager;
- relay connection reuse, source IP and TLS session metadata once a real network
  layer exists (blocker 8);
- timing and activity correlation across profiles on one device;
- shared OS-level artifacts — notifications, backups, filesystem timestamps.

**What is the actual claim?** Something like *"a relay operator cannot determine
that two profiles share a device"* is far stronger than *"profile data is stored
separately on disk"*, and only the second is plausibly true today. Please state
the claim you are willing to defend, and what explicitly defeats it, so it can
go into the threat model before the feature is built rather than after.

## What I need

1. **C1** — confirm no device identifier. One line.
2. **C2** — which storage shape, and whether it needs its own dual review.
3. **C3** — the exact unlinkability claim and its stated limits, as text for
   `THREAT_MODEL.md`. I will not draft this; it is a claim.
4. Whether the account-identifier reasoning above is sound.
5. Whether any of this changes the ceremony ruling you already issued — in
   particular the safety number, which binds the account identifier.

## Constraints, unchanged

`SECURITY_STATUS.md` is NO-GO with 15 unchecked blockers. Nothing here authorizes
a launch, a commit, or any public-security claim. Implementation from inference
is forbidden — this exists so I do not guess while writing the ceremony spec.
