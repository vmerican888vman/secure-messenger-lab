# Independent review — slice F: production-bypass removal

Review `secure-messenger-lab` at the exact head SHA supplied with this brief. Confirm the
checked-out SHA and that the worktree is clean before reviewing. This same brief is being sent
separately to Fable and Sol; do not seek, read, summarize, or defer to the other reviewer's response
before returning your own. Committed `reviews/REVIEW-*` files are earlier legs' artifacts — do not
open them before your own verdict.

This is an adversarial review of the bypass-removal leg implementing the frozen §2 final
paragraph: `OlmClient`, `OpenedMessage`, `ClientStateStore` and their mutating methods are now
crate-private, and no public mutation path remains outside the façade.

## In scope

- `src/lib.rs` — the final public surface. After this leg, the entire public API is:

```rust
pub use capability::{AckRequest, DeleteMailboxRequest, FetchRequest, MailboxRegistration, SendRequest};
pub use client::EncryptedPacket;
pub use error::{LabError, Result};
pub use ids::{ConversationId, MessageId, Nonce, QueueId};
pub use lifecycle::{DestructiveResetAuth, LifecycleManager, LifecycleState, LockReason, ProvisionOutcome};
pub use persistence::{KeyStatus, ProfileBinding, ProtectionLevel, StateKeyProtector};
pub use persistent::{AcceptOutcome, AckOutcomeView, DeliveryUnknownView, DurableAction, InboundView,
    PersistentClient, PublicIdentity, RedactedContactOffer, RegistrationOutcome, SendOutcome};
pub use private_store_dir::{MainDatabase, PrivateStoreDir, StoreKind};
pub use relay::{AckOutcome, EnqueueOutcome, Relay, StoredEnvelope};
```

- Mechanism: `mod client` / `mod capability` are crate-private modules (in-module items stay
  `pub`, unreachable externally); `persistence` re-exports `ClientStateStore` as `pub(crate)`.
- Test migration: `tests/{e2e_relay,request_boundaries,expiry_revalidation,state_staging}.rs`
  moved in-crate (`src/relay/`, `src/client/` submodules), plus two boundary tests into
  `src/private_store_dir/store_boundary_tests.rs`. All behaviorally identical.
- `src/main.rs` — the demo ported to the façade public API.
- Hygiene: duplicated doc block removed, `Mutating` unreachability documented, DurableAction
  post-commit-crash doc sentence, pub sweep.
- `README.md`, `SECURITY_STATUS.md`, `docs/architecture.md` — updated to match reality.

## Claims under review

1. No external crate can name `OlmClient`, `OpenedMessage`, `PlainMessage`, `PeerPreKey`,
   `VerifiedPeerPreKey`, `MailboxOwner`, `SendCapability`, `ReceiveCapability`,
   `ManageCapability`, `VerifiedEnvelope`, or `ClientStateStore` — verified by rlib probes
   (E0422/E0433/E0599 for each). Attempt to defeat the module-privacy mechanism (re-export leaks,
   pub-in-pub paths, `Debug` exposure).
2. Every remaining public item is needed by the relay or façade construction. Find one that is
   not, or one through which façade-interior state escapes.
3. The moved tests are behaviorally identical (imports only).
4. Docs match code: `SECURITY_STATUS.md` claims and the README "what works / does not prove"
   lists are accurate after this leg.

## Known gap (declared, not a defect of this leg)

The demo stops before the conversation: the public API has no transferable send-capability
artifact, so `commit_verified_contact` cannot be satisfied externally. The fix (a minimal export
returning the bounded canonical serialized keypair, symmetric with the input side) is a follow-up
leg needing its own review.

## Required attacks

1. reach the removed types or a mutating method from an external crate context by any path;
2. any mutation of durable state achievable without the façade's mutator discipline;
3. any test that changed behavior during the moves;
4. any doc statement in README/SECURITY_STATUS/architecture that is false of this head.

Run at minimum:

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
cargo build --locked   # then attempt the external-reachability probes
```

Return `PASS` or `RETURN` against the exact head SHA. A `RETURN` must list blocking findings only,
each with a concrete reproduction or source reference.
