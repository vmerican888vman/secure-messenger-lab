//! Disposable Phase 0 security harness.
//!
//! This crate is intentionally not a production messenger. It tests whether two
//! clients can exchange Olm-encrypted payloads through a relay that only stores
//! opaque envelopes and deletes them after an authenticated recipient ACK.

mod capability;
mod client;
mod companion;
pub mod error;
pub mod ids;
mod lifecycle;
mod payload;
pub mod persistence;
mod persistent;
mod private_store_dir;
pub mod relay;
mod state;

// §2: only the relay's wire types stay public from the old client/
// capability surface. `OlmClient`, `OpenedMessage`, `ClientStateStore`,
// `PlainMessage`, the prekey bundle types, `MailboxOwner` and the
// capability owners are crate-private: their public mutations were
// production bypasses of the persistence-owning façade.
pub use capability::{
    AckRequest, DeleteMailboxRequest, FetchRequest, MailboxRegistration, SendRequest,
};
pub use client::EncryptedPacket;
pub use error::{LabError, Result};
pub use ids::{ConversationId, MessageId, Nonce, QueueId};
pub use lifecycle::{
    DestructiveResetAuth, LifecycleManager, LifecycleState, LockReason, ProvisionOutcome,
};
pub use persistence::{KeyStatus, ProfileBinding, ProtectionLevel, StateKeyProtector};
pub use persistent::{
    AcceptOutcome, AckOutcomeView, DeliveryUnknownView, DurableAction, InboundView,
    PersistentClient, PublicIdentity, RedactedContactOffer, RegistrationOutcome, SendOutcome,
    StageSendOutcome,
};
pub use private_store_dir::{MainDatabase, PrivateStoreDir, StoreKind};
pub use relay::{AckOutcome, EnqueueOutcome, Relay, StoredEnvelope};

/// Protocol-domain label used by every signed relay command.
pub const PROTOCOL_DOMAIN: &[u8] = b"secure-messenger-lab/phase0/v1";
