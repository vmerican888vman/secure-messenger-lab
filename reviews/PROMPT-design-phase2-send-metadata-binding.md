# Design brief — binding send-record metadata (secure-messenger-lab)

You raised this as codec v10 P1-1 and offered a closure shape. I am
asking you to SPECIFY it before I implement, because the obvious readings
lead to different frozen-design changes and I do not want to guess. Your
P1-2 (duplicate `message_digest`) is already fixed and is not in scope
here.

## Repo and head

`secure-messenger-lab`, branch `docs/phase2-frozen-decisions`, head after
the P1-2 fix (I will supply the exact SHA with the review dispatch).
Relevant: `src/state/validate.rs` (`check_sends`, `check_application_ledger`),
`src/state/records.rs` (`SendRecord`), `src/capability.rs`
(`send_signing_bytes`, `ACTION_SEND`), `src/persistent/mod.rs`
(`admit_application_send`, `stage_receipt`).

## The finding, restated so we agree on it

`SendRecord` carries `epoch_id`, `sequence`, `kind` and
`receipt_high_water` as LOCAL metadata. The only cryptographic binding on
the record is `send_signature` over
`canonical(ACTION_SEND, [queue_id, message_id, packet_digest, expires_at])`
— none of the four fields above. `check_application_ledger` then exempts
a record from the ledger solely because `kind == Receipt`.

So relabelling a genuine application record as `Receipt`, dropping its
sequence from field 22 and setting `receipt_high_water` produces a state
that `encode` accepts and `decode` reloads. Application traffic then
occupies control slots with no application-budget accounting, bounded by
the 8-record control quota — i.e. up to 8 application sends escaping the
24-application §4 budget, which is exactly the skipped-key pressure §4
exists to bound.

I agree it is real and I am not disputing the severity.

## Why I am not just implementing your closure

You wrote: "retain a codec-verifiable typed commitment binding at least
`{packet_digest, epoch_id, sequence, kind, receipt_high_water}` through
terminalization." Three readings, with materially different blast radius:

1. **Extend `send_signing_bytes`.** Strongest — relabelling breaks
   signature verification. But that construction is WIRE protocol: the
   relay verifies it at enqueue (`capability.rs:198`) and the receiving
   peer verifies it in `accept_envelope` (`persistent/mod.rs:1152`).
   Adding our local outbox bookkeeping to bytes a peer and relay verify
   looks wrong on its face, and it is a frozen §2 change affecting two
   other parties.
2. **A separate LOCAL keyed commitment** — a new `SendRecord` field, MAC
   over the five values under some key the codec can reach. But every key
   in reach is also reachable by the façade, so this does not defend
   against a buggy façade; it defends against an actor who can rewrite
   state, who has by definition already defeated the outer AEAD that §1
   declares as the boundary.
3. **A separate LOCAL unkeyed digest** — same field, plain hash. Cheapest
   and survives terminalization, but it is a checksum: it catches a
   PARTIAL mutation (one field changed, commitment not recomputed) and
   catches nothing that recomputes both.

My own reading is that the useful property here is (3) — the codec as a
consistency net against façade bugs, the same role it played in the
field-22 blocker — and that (1) is disproportionate and (2) buys nothing
over (3) given the §1 boundary. But that is a judgement about the threat
model, which is yours, not mine.

## What I need you to specify

1. **Which of the three (or a fourth I have missed).** If (1), say
   explicitly that the §2 wire construction changes and what the relay
   and receiving peer are expected to do with the added fields.
2. **The exact committed tuple and its canonical encoding**, so the codec
   and façade cannot disagree about it.
3. **When it is computed and when re-verified** — in particular whether
   it must survive terminalization (your phrase), given that
   terminalization drops `queue_id`, `packet` and `send_signature` and
   keeps `packet_digest`.
4. **What validation does on mismatch** — reject the state (profile
   lock), or something softer.
5. **Whether `kind` should instead become structurally inferable**, which
   would remove the need for a commitment at all. For example: require a
   receipt-kind record to carry evidence only `stage_receipt` could
   produce. I could not find such evidence — the codec cannot decrypt the
   packet, and a relabelled record satisfies `arms_consistent` — but you
   may see one.

## Constraints

- §2 (relay/wire) and §3 (codec) are frozen text; you are authorising any
  change, so supply the replacement wording for whatever you change.
- Do not propose anything requiring a `vodozemac` change.
- The codec has no trusted `now`.
- Prior warning that still binds: nothing may be added that gates control
  encryption at runtime — that reintroduced a deadlock family across
  seven review rounds on the façade leg.

## Caveats

- I have been wrong before by improvising a protocol change rather than
  asking, which is why this is a brief and not a patch.
- Fable independently reviewed this same head and did NOT flag P1-1. That
  is not evidence against you — it reviewed the ledger's authority as a
  snapshot question and explicitly bounded its answer to "sound to the
  limit of what a snapshot can decide" — but you should know the two
  reviews diverged here, and that Fable ruled the related hostile-state
  question out of scope under §1.
