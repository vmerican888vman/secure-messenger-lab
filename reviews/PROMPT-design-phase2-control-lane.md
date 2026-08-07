# Design brief — §4 control-lane split (secure-messenger-lab)

You are being asked for a DESIGN DECISION and frozen-§4 specification
text, not an implementation. Opus implements from your spec afterwards
and both reviewers then review the result as usual.

## Repo and head

`secure-messenger-lab`, branch `docs/phase2-frozen-decisions`, head
`9fe095c` (`/Users/new/Cursor local/secure-messenger-lab` — quote the
path, it has spaces). Relevant files: `src/persistent/mod.rs`
(`recompute_mode`, `accept_staging_tail`, `maybe_stage_owed_receipt`,
`stage_receipt`), `src/state/records.rs` (`ActiveSession`, `SendRecord`),
`src/state/validate.rs`, `docs/phase2-design-decisions.md` §4.

## The problem

The peer-signaled control-debt arm has been RETURNED in independent
review in v6, v7, v8, v9, v10, v11 and v12 — seven consecutive rounds,
across two different implementers. Each round fixed the reported symptom
and the next round found a new one. That is a design signal.

Root cause, confirmed at this head:

    outstanding = last_assigned_send_seq - peer_contiguous_high_water

counts ALL sends, application and control alike, because both kinds draw
sequences from one stream. §4 then keys the budget modes off it: `< 24`
Ready, `24..31` ControlOnly (application bodies blocked), `32`
ReceiptLocked (all encryption blocked), recovering only through a valid
receipt FROM the peer.

Consequence: every control receipt we emit spends application budget, and
our outstanding falls only when the PEER acknowledges us. So any
mechanism that makes us emit receipts in response to peer stimulus is an
amplification lever on our own send capacity.

Three local bounds have been tried and each failed structurally:

1. **Bound concurrent responses** (`any_receipt_pending`, v11) — defeated
   by simply completing the delivery cycle: once a response reaches
   `Stored` the guard frees and the next signal arms another. Sol's
   32-cycle probe reached `ReceiptLocked` with application sends blocked.
2. **Bound by peer reciprocity** (`control_signal_response_at`, v12 —
   answer a signal only once `peer_contiguous_high_water` covers our last
   answer) — DEADLOCKS an honest peer. An uncongested peer has no reason
   to counter-receipt, and receipt-only acceptance creates no receipt
   debt by design (the v5 quiescence property), so the gate latches shut
   forever against a peer that has done nothing wrong. Reproduced by Sol;
   reverted in v13.
3. **Bound by our own congestion** (rejected before shipping) — above the
   threshold the ungated LOCAL congestion arm takes over and continues
   the escalation to `ReceiptLocked`, so the bound is bypassed in two
   stages instead of one. The local arm cannot simply be gated too: it is
   the both-stuck backstop that v6 introduced.

The current head is deliberately back to v11 behaviour on this arm, which
still carries the known v11 P1 (unbounded lifetime issuance). The
acceptance test `over_signaling_cannot_lock_the_victim` is retained and
marked `#[ignore]` with that reason.

## Direction already chosen

**Split the control lane**: control (receipt-kind) sends must stop
consuming the application budget, so the lever disappears rather than
being capped. Options "cap per epoch" and "drop the peer-signal arm" were
considered and rejected — the first silently loses truthful congestion
signals once the cap burns (the under-arming direction v10 was returned
for), the second reopens the one-directional stall v7 closed.

Do not re-litigate the direction unless you think it is unsound; if you
do, say so plainly and say why.

## What I need you to specify

1. **Accounting.** What exactly replaces `outstanding` for the §4 modes?
   The hard constraint: sequences are a SINGLE stream shared by both
   kinds, and `HighWaterReceipt` (frozen) reports one contiguous high
   water over that stream. So "application sends not yet covered by the
   peer's high water" is not directly derivable from the high water
   alone. Send records carry `kind`, but the outbox is bounded at 32 and
   terminal records are pruned, so historical app sends cannot be counted
   retrospectively. Options include a durable per-kind counter pair on
   `ActiveSession`, or splitting the sequence space. State which, and
   what invariants it must satisfy on load.
2. **Bounds on the control lane itself.** Removing the app-budget
   coupling does not by itself bound how many receipts a peer can make us
   emit — they still consume outbox slots, relay bandwidth and storage.
   What bounds the control lane, and what happens when that bound is
   reached? This is the part that must not reintroduce an honest-peer
   deadlock, so please state the liveness argument explicitly.
3. **Mode semantics.** Do `Ready`/`ControlOnly`/`ReceiptLocked` all key
   off application outstanding only? What blocks control sends now, and
   what does `ReceiptLocked` recovery mean when the lanes are separate?
4. **Wire impact.** `ClientPayloadV2.issuer_outstanding` currently
   reports the issuer's post-advance total outstanding and drives the
   peer-signal arm. Does it now report application-only outstanding? The
   frozen `HighWaterReceipt` is not to be changed without saying so
   explicitly.
5. **Codec impact.** Name the new/changed `ActiveSession` fields and
   their validation rules. The object is currently 21 fields; the codec
   is pre-PASS, so in-place layout changes are acceptable.
6. **What the acceptance test must assert.** The retained ignored test is
   32 full delivery cycles with the victim remaining `Ready`. Say whether
   that is still the right criterion under the new accounting, and what
   the honest-peer liveness regression must look like (Sol's v12 repro:
   delayed signal, peer recovers before we see it, peer later re-congests
   while quiescent).

## Constraints

- §4 is frozen text; you are authorising the change, so write the
  replacement wording for the affected paragraphs.
- No model holds final merge on the crypto core; a human security
  authority still approves the protocol.
- Group scale is low hundreds; single-device, single-peer at this leg.
- Do not propose changes that require modifying `vodozemac` (it is
  vendored with one reviewed patch and each patch is its own review leg).

## Caveats you should know while deciding

- I have been wrong twice in a row on this exact mechanism, so treat the
  root-cause analysis above as a claim to check, not a given. The
  specific thing to verify is that `outstanding` really is the shared
  counter and that both arms feed it — `recompute_mode` in
  `src/persistent/mod.rs` is the whole of it.
- Fable PASSed the v12 head and separately established that the
  gap-lock class is NOT closable against a peer holding our mailbox send
  capability (it can gap-lock at will with a fresh message past the chain
  gap, no replay needed). So do not spend budget trying to make the
  control lane defend against a malicious peer's ability to wedge the
  conversation — §4 already designates peer-authenticated gap failure as
  designed behaviour. The property at stake is narrower: a peer must not
  be able to consume our APPLICATION send capacity by signalling.
- The 4,096-record dedup capacity bug (Sol's v12 P1-2) is already fixed
  at this head and is out of scope for this brief.
