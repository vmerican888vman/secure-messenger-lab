# Design brief — Delivery Service ordering and the fork problem

**A design request, not a review.** Ruling step 3. Nothing is committed and
nothing will be until you rule; the repository is under a no-commit hold.

This is queued alongside `reviews/PROMPT-design-contact-ceremony.md` (step 2)
rather than after it, because the two may constrain each other and I would
rather find that out now than in a later round.

## Why this is on the critical path, not a groups-later problem

The ruling adopts MLS for **both 1:1 and groups**, and a 1:1 chat is a two-member
MLS group. MLS epochs are linear and the Delivery Service exists to break
simultaneous-Commit ties. So **without a DS there is no first conversation** —
this does not wait for group chat.

The ruling states it plainly: MLS relies on the DS to break simultaneous-Commit
ties, and *"the current pairwise-mailbox design does not provide that
function."*

## Ground truth — read from the code, not assumed

**The relay today has no ordering whatsoever.** `src/relay.rs` exposes
`enqueue` / `fetch` / `acknowledge` over unidirectional mailboxes keyed by a
random 32-byte queue ID. There is no sequence number, no per-conversation
grouping, no serializer, and nothing that relates one queue to another.

**That absence is a deliberate, currently-claimed security property.**
`SECURITY_STATUS.md` carries this as a **checked** item:

> - [x] Relay schema has no plaintext, users, contacts, conversations, phone numbers, emails, or groups.

And `THREAT_MODEL.md`'s metadata budget enumerates every relay-visible field:
queue ID, three Ed25519 public keys, message ID, ciphertext and length, expiry,
fetch/manage/registration nonces, a SHA-256 of retired queue IDs, and event
type. **Nothing in that table links two queues together.**

## The collision, stated precisely

A Delivery Service must know *which messages belong to the same group and in
what order*. Any serializer therefore introduces a relay-visible relation
between messages that the current design does not have.

So building a DS plausibly means:

1. **Adding at least one row to the metadata budget** — some group or epoch
   handle, plus an ordering position.
2. **Un-checking `SECURITY_STATUS.md`'s "no conversations, no groups" line**, or
   rewording it to something narrower and still true.
3. **Creating a linkability surface that does not exist today** — every member
   of a group hits the same handle, so the relay learns the membership set's
   size and activity pattern even if it learns no identities.

Point 2 is a change to a **claim**, which under the Phase 3 amendment is
governed: no product surface may overstate protection, and `SECURITY_STATUS.md`
is the authority on what may be claimed. I am not editing a checked security
property on my own judgement — that is what this brief is for.

## ⚠ Prerequisite — the current metadata baseline is wrong, fix it before ruling

You are about to rule on how much relay-visible metadata MLS ordering adds. That
question cannot be answered against the inventory in `THREAT_MODEL.md`, because
**the inventory is incomplete.** Found by auditing the schema against the budget
(`docs/checked-claims-audit.md`, Finding 2).

The budget lists 9 relay-visible fields and caveats only what a *real network*
relay would additionally see — implying it is complete for the relay as built.
Comparing against `CURRENT_SCHEMA_DDL` (`src/relay.rs:795`), these are stored and
**not in the budget**:

| Column | Table | Why it matters |
|---|---|---|
| `sender_signature` BLOB(64) | `messages` | **Material.** A per-message Ed25519 signature stored at rest. If a sender's signing key is stable across messages, this is a durable linkability artifact — arguably the single largest metadata surface the relay already has, and it is unlisted |
| `created_at` | `mailboxes` | Mailbox creation timestamp; traffic analysis |
| `retired_at` | `retired_queues` | Retirement timestamp, in a table retained **indefinitely** |
| `role` TEXT | `request_nonces` | Reveals which capability class is exercised (send / receive / manage) |
| `delete_after` | `tombstones`, both nonce tables | Partly implied by the retention column, never listed as a field |

The checked claim *"relay schema has no plaintext, users, contacts,
conversations, phone numbers, emails, or groups"* **does hold** — I read every
column. The defect is the threat model's enumeration, not the schema.

**Please rule on this first**, with exact replacement rows for the budget table.
Then the DS question becomes answerable: *how much does ordering add on top of a
correct baseline* — rather than on top of one that already understates by five
fields, one of which may be the biggest linkability surface present.

I have not edited the budget. It is a claims artifact and those are yours.

## What I need ruled

1. **Does the DS regress the metadata budget, and by exactly how much?** Name
   the fields the relay would newly see. If the answer is "a blind ordered
   queue keyed by an opaque handle the relay cannot link to identities", say so
   and specify what the handle binds to and how it rotates. Note that a stable
   `sender_signature` may already provide much of the linkability a group handle
   would add — if so, the DS's marginal cost is smaller than it first appears,
   and that is worth stating explicitly rather than leaving as a coincidence.
2. **What replaces the checked claim?** If "no groups" stops being true, give
   the exact replacement wording for `SECURITY_STATUS.md`. It should be narrower
   and still literally true — the standing rule is never claim more than the
   code does.
3. **Which shape.** Three were previously sketched; I am not choosing:
   - an opaque per-group ordering queue (relay serializes, cannot link);
   - pure pairwise fan-out with client-side tie-breaking (no DS, but something
     must still enforce epoch linearity — say what);
   - abandoning MLS for sender keys (recorded so it is visibly rejected rather
     than overlooked, unless you want it reconsidered).
4. **Fork handling.** What happens when clients disagree about epoch order — how
   is a fork detected, who detects it, and what is the recovery? A silent fork
   is a partition where two halves believe they are talking securely and are
   not.
5. **Trust boundary.** The design principle recorded for this project is that the
   DS provides **ordering, not trust**. Confirm that holds, and state what a
   hostile DS can do: reorder, withhold, replay, or stall. Which of those must
   be detectable by clients, and which are accepted?
6. **What the spike must execute.** This is an executable question, not a paper
   one. Specify the minimum experiment that would actually falsify the design —
   concurrent Commits from N clients, induced partitions, a hostile serializer —
   and what result would count as "MLS over mailboxes does not work."

## Constraints

- Relay capabilities, idempotent sends, durable outboxes, deletion ACKs and
  tombstones are marked **retain transport invariants; rebind to MLS messages**.
  The DS should be built on the existing capability model, not beside it.
- The frozen bounds do not automatically become MLS bounds: `MAX_PACKET` 96 KiB,
  sealed state 8 MiB, relay wire limit 1 MiB.
- Group scale is **low hundreds**, not thousands — mobile commit catch-up was
  the stated limit.
- `SECURITY_STATUS.md` is NO-GO with 15 unchecked blockers. Nothing here
  authorizes a launch or any public-security claim.
- Self-hostable relays are a day-one requirement, so whatever the DS is, an
  operator must be able to run it without privileged knowledge.

## Process notes

- **Do not let me improvise this.** A protocol change invented mid-loop to
  unblock a reviewer finding once deadlocked honest peers and cost a seven-round
  failure loop plus a full revert. The loop ended only when the design was
  escalated rather than patched again.
- Every negative test gets an accept-arm control; four tests here have passed
  vacuously in the past. Anything you specify should be falsifiable, and I will
  prove each test fails against the mutant before claiming it works.
- If a bound needs repeated tuning, the bound is measuring the wrong thing.

## Output

A ruling in prose, with exact text where you want it in a document. It will be
transcribed verbatim into `reviews/REVIEW-sol-design-delivery-service.md` and
dual-certified at one SHA.

**If the honest answer is that the DS cannot be specified until the spike is
run, say that** — and specify the spike instead. An experiment you scope is
worth more than an architecture you are not confident in, and this is the one
decision in the plan that could invalidate the MLS choice entirely.
