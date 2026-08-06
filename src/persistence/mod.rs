//! Encrypted endpoint-state storage foundation.
//!
//! This module deliberately stores opaque serialized client state. The next
//! implementation leg owns the versioned Olm/outbox semantic codec. Keeping
//! the boundary narrow lets this layer prove the outer AEAD, platform binding,
//! exact `SQLite` schema, atomic generation CAS, and fail-closed recovery first.

mod envelope;
mod protector;
mod sqlite;

pub use protector::{KeyStatus, ProfileBinding, ProtectionLevel, StateKeyProtector};
pub use sqlite::ClientStateStore;
