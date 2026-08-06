use crate::Result;
use zeroize::Zeroizing;

/// Non-secret profile identity and platform-key reference retained by the
/// platform secure store independently of the `SQLite` state file.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProfileBinding {
    profile_id: [u8; 16],
    key_ref: [u8; 16],
}

impl ProfileBinding {
    #[must_use]
    pub const fn new(profile_id: [u8; 16], key_ref: [u8; 16]) -> Self {
        Self {
            profile_id,
            key_ref,
        }
    }

    #[must_use]
    pub const fn profile_id(&self) -> &[u8; 16] {
        &self.profile_id
    }

    #[must_use]
    pub const fn key_ref(&self) -> &[u8; 16] {
        &self.key_ref
    }
}

impl std::fmt::Debug for ProfileBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProfileBinding")
            .field("profile_id", &"opaque")
            .field("key_ref", &"opaque")
            .finish()
    }
}

/// Protection evidence reported by a platform adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLevel {
    StrongBox,
    TrustedEnvironment,
    SoftwareBacked,
    /// Missing, contradictory, unknown-secure, or inspection-error evidence.
    /// Consumers must give this the same lowest claim as software-backed storage.
    Indeterminate,
}

/// Availability of a specific platform key, reported without changing any
/// state (lifecycle manager recovery arms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// The exact key exists and is usable.
    Present,
    /// The exact key is gone.
    Missing,
    /// The platform is temporarily locked; retryable, and nothing about the
    /// registry, key or database may change because of it.
    TemporarilyLocked,
}

/// Platform boundary for the non-exportable state-wrapping key.
///
/// Implementations must keep the expected profile binding outside the `SQLite`
/// file and use that independently stored binding inside every wrap/unwrap
/// operation. The caller never supplies a database-derived binding to those
/// operations. Unknown or indeterminate hardware evidence maps to
/// [`ProtectionLevel::Indeterminate`] and must never be upgraded.
pub trait StateKeyProtector {
    /// Return the expected binding from a trusted platform-side registry.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when the binding or key is unavailable.
    fn expected_binding(&self) -> Result<ProfileBinding>;

    #[must_use]
    fn protection_level(&self) -> ProtectionLevel;

    /// Wrap one profile DEK while binding the state-wrap domain and expected
    /// profile/key reference.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when the platform operation fails.
    fn wrap_dek(&self, dek: &Zeroizing<[u8; 32]>) -> Result<Vec<u8>>;

    /// Unwrap into caller-owned zeroizing storage only after verifying the
    /// state-wrap domain and expected profile/key reference.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error for missing keys, binding mismatch, or
    /// authentication failure.
    fn unwrap_dek(&self, wrapped_dek: &[u8], output: &mut Zeroizing<[u8; 32]>) -> Result<()>;

    // --- lifecycle operations (added for the §4 platform-key lifecycle
    // manager; deviation documented in src/lifecycle.rs) -----------------
    //
    // The trait predates the lifecycle manager and had no key-creation or
    // key-deletion operations. These four are required methods; existing
    // test-only implementors were updated to match.

    /// Create a fresh non-exportable key and register `binding` as the
    /// current expected binding. Implementations must refuse an existing
    /// binding (references are never reused).
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when the platform cannot create the
    /// key or the binding already exists.
    fn provision_key(&self, binding: ProfileBinding) -> Result<()>;

    /// Report the availability of the exact key behind `binding`, without
    /// changing anything.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when the platform cannot answer.
    fn key_status(&self, binding: ProfileBinding) -> Result<KeyStatus>;

    /// Make an existing registered binding the current expected one (the
    /// lifecycle manager selects a profile's binding before opening its
    /// store during recovery).
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when the binding is unknown.
    fn select_binding(&self, binding: ProfileBinding) -> Result<()>;

    /// Delete the exact platform key behind `binding`. Deleting an absent
    /// key succeeds (idempotent resume of a destructive reset).
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when the platform refuses.
    fn delete_key(&self, binding: ProfileBinding) -> Result<()>;
}
