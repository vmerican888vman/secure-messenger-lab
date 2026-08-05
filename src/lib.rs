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
pub mod persistence;
pub mod relay;

pub use capability::{
    MailboxOwner, MailboxRegistration, ManageCapability, ReceiveCapability, SendCapability,
    VerifiedEnvelope,
};
pub use client::{
    EncryptedPacket, OlmClient, OpenedMessage, PeerPreKey, PlainMessage, VerifiedPeerPreKey,
};
pub use error::{LabError, Result};
pub use ids::{ConversationId, MessageId, Nonce, QueueId};
pub use persistence::{ClientStateStore, ProfileBinding, ProtectionLevel, StateKeyProtector};
pub use relay::{AckOutcome, EnqueueOutcome, Relay, StoredEnvelope};

/// Protocol-domain label used by every signed relay command.
pub const PROTOCOL_DOMAIN: &[u8] = b"secure-messenger-lab/phase0/v1";
