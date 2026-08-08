# Scope — blocker 8: real authenticated network protocol, TLS, request limits, traffic capture

**Status: implementer's scoping, 2026-08-08. Not certified. Uncommitted.**
No code written. This exists to establish whether blocker 8 is the unblocked
build it appeared to be in `docs/remaining-work-map.md`.

**Conclusion up front: it is buildable, but it is not small, and three of its
four parts have prerequisites. The dependency-surface question is the real
decision and it is not mine to make.**

## What exists today

The relay is an **in-process struct over SQLite**. There is no network layer of
any kind.

- `Relay` exposes `register` / `enqueue` / `fetch` / `acknowledge` /
  `delete_mailbox` / `purge_expired`, taking typed Rust structs.
- The four request types — `SendRequest`, `FetchRequest`, `AckRequest`,
  `DeleteMailboxRequest` (`src/capability.rs:331–395`) — carry `queue_id`,
  `message_id`/`nonce`, payload or hash, an expiry, and an `Ed25519Signature`.
- **None of them derive `Serialize`.** There is no wire format at all.
- No async runtime, no HTTP stack, no TLS crate anywhere in the tree.

## What is already solved, and should not be redesigned

**Authentication is done.** The capability model already signs every command
with a per-role Ed25519 key — send, receive, manage — verified relay-side, with
nonces for replay rejection and expiry windows on every request. A network layer
must **transport** that, not invent auth on top of it. Anything that adds
session tokens, bearer credentials, or TLS-client-cert identity would be
duplicating a solved problem and adding a second, weaker path.

Signed request expiries are capped at five minutes and each command carries a
nonce, so the existing scheme already resists replay across a network. That is
the property a naive HTTP port would most likely break.

## The four parts, and their real prerequisites

### 1. Wire protocol — **blocked on the Delivery Service ruling**

Serializing the four request types is mechanical. Freezing the *endpoint set* is
not. The DS brief asks the architect whether the relay gains a per-group
ordering function. **If it does, the endpoint set changes.** Freezing a wire
format now risks freezing one that a Commit-ordering endpoint immediately
invalidates.

Recommendation: defer the wire format until the DS ruling lands. The rest can
proceed.

### 2. TLS configuration — **the dependency-surface decision**

This is the part that needs a human decision rather than an implementer's
preference.

The crate today is **116 crates total**, with **12 exact-pinned (`=`) direct
dependencies**. The discipline is strict enough that a single forced version
bump carries a written justification in `Cargo.toml` explaining why the
review-authorized version did not resolve.

Adding an async runtime plus an HTTP stack plus TLS — the conventional
`tokio` + `hyper`/`axum` + `rustls` triple — would add roughly on the order of
100+ transitive crates, near-doubling the audit surface of a project whose
entire thesis is that its claims can be checked.

That directly interacts with **blocker 14** (reproducible build,
dependency/SBOM/provenance pipeline, external audit). Every crate added here is
a crate someone pays to have audited later.

Options, none chosen:

- **Full async stack** — conventional, best ecosystem support, largest surface.
- **Blocking, thread-per-connection with `rustls` only** — no async runtime, far
  fewer crates, adequate for a store-and-forward mailbox relay with short
  requests. Likely the best fit for the actual traffic shape.
- **TLS terminated by a reverse proxy** the operator runs — smallest crate
  surface, but pushes a security-critical configuration onto every self-hoster,
  and **self-hostable relays are a day-one requirement**. That trade needs
  stating explicitly rather than assuming competent operators.

### 3. Request limits — **buildable now**

Three frozen bounds apply, and two have confusingly similar names — verified
against the ruling, all three agree:

| Constant | Value | Role |
|---|---|---|
| `MAX_PACKET_BYTES` | `1_048_576` = **1 MiB** | the relay's wire limit — **this is the one a network layer enforces** |
| `MAX_PACKET` | `98_304` = **96 KiB** | the Olm packet bound, enforced deeper in the client |
| `MAX_CIPHERTEXT_BYTES` | 8 MiB | sealed local-state limit |

A network layer must enforce the 1 MiB wire limit and must **not** be mistaken
for the place the 96 KiB Olm bound lives. Enforcing them at a connection
boundary needs no new decision: reject
oversize bodies before allocation, bound header sizes, cap concurrent
connections per source, and time out slow requests. The existing bounds
discipline — *test exact and one-over decoding before allocation* — carries over
directly, and the accept-arm rule applies to every limit test.

### 4. Traffic and log capture — **buildable now, and it is a measurement, not a feature**

This is the most valuable part and the cheapest. The threat model already
concedes:

> A real network relay would additionally observe source IP, connection time,
> request size, TLS metadata, and timing unless another transport layer hides
> them. None of those are modeled or claimed away here.

Capture exists to turn that concession into measurements: record an actual
session and enumerate what an observer sees. Expect it to **expand the metadata
budget**, which is the same collision the DS raises — and note the budget is
**already short by five fields** (`docs/checked-claims-audit.md`, Finding 2), so
this should follow the budget correction rather than precede it.

## Sequencing this implies

1. Fix the metadata budget (already queued as a prerequisite in the DS brief).
2. Decide the dependency-surface question — **owner/architect, not implementer.**
3. Build request limits and traffic capture. Neither is blocked.
4. Build the wire protocol and TLS **after** the DS ruling fixes the endpoint set.

## What I would need before writing code

A single decision: **which TLS/runtime shape**, judged against audit surface
rather than convenience. Everything else follows from it, and it is the kind of
choice that is very expensive to reverse once a wire format and an operator
story depend on it.

I have deliberately not picked one. On this project the standing rule is that
where two readings differ on rigour the more rigorous wins — and the smallest
auditable surface is the more rigorous reading, which argues against the
conventional async stack despite it being the path of least resistance.
