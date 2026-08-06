//! Disposable Phase 0 security harness.
//!
//! This crate is intentionally not a production messenger. It tests whether two
//! clients can exchange Olm-encrypted payloads through a relay that only stores
//! opaque envelopes and deletes them after an authenticated recipient ACK.

pub mod capability;
pub mod client;
mod companion;
pub mod error;
pub mod ids;
mod payload;
pub mod persistence;
mod persistent;
mod private_store_dir;
pub mod relay;
mod state;

pub use capability::{
    AckRequest, FetchRequest, MailboxOwner, MailboxRegistration, ManageCapability,
    ReceiveCapability, SendCapability, SendRequest, VerifiedEnvelope,
};
pub use client::{
    EncryptedPacket, OlmClient, OpenedMessage, PeerPreKey, PlainMessage, VerifiedPeerPreKey,
};
pub use error::{LabError, Result};
pub use ids::{ConversationId, MessageId, Nonce, QueueId};
pub use persistence::{ClientStateStore, ProfileBinding, ProtectionLevel, StateKeyProtector};
pub use persistent::{
    AcceptOutcome, AckOutcomeView, DeliveryUnknownView, DurableAction, InboundView,
    PersistentClient, PublicIdentity, RedactedContactOffer, RegistrationOutcome, SendOutcome,
};
pub use private_store_dir::{MainDatabase, PrivateStoreDir, StoreKind};
pub use relay::{AckOutcome, EnqueueOutcome, Relay, StoredEnvelope};

/// Protocol-domain label used by every signed relay command.
pub const PROTOCOL_DOMAIN: &[u8] = b"secure-messenger-lab/phase0/v1";
