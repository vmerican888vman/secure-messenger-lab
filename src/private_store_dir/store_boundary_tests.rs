//! Store-level boundary tests that need crate-private types
//! (`MailboxOwner`, `ClientStateStore`), moved in-crate from
//! `tests/private_store_dir.rs` when those types left the public API.
//! Behaviorally identical to the integration originals; only imports and
//! the constructor paths changed.

use std::error::Error;

use super::{MainDatabase, PrivateStoreDir, StoreKind};
use crate::capability::MailboxOwner;
use crate::persistence::{
    ClientStateStore, KeyStatus, ProfileBinding, ProtectionLevel, StateKeyProtector,
};
use crate::{LabError, Result};

const NOW: u64 = 1_800_000_000;

/// XOR test protector, mirrored from `persistence/sqlite.rs` tests.
struct TestProtector {
    binding: ProfileBinding,
    mask: [u8; 32],
}

fn protector() -> TestProtector {
    TestProtector {
        binding: ProfileBinding::new([0x42; 16], [0x24; 16]),
        mask: [0x24; 32],
    }
}

impl StateKeyProtector for TestProtector {
    fn expected_binding(&self) -> Result<ProfileBinding> {
        Ok(self.binding)
    }

    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::SoftwareBacked
    }

    fn wrap_dek(&self, dek: &zeroize::Zeroizing<[u8; 32]>) -> Result<Vec<u8>> {
        let mut wrapped = b"state-wrap/v1".to_vec();
        wrapped.extend_from_slice(self.binding.profile_id());
        wrapped.extend_from_slice(self.binding.key_ref());
        wrapped.extend(dek.iter().zip(self.mask).map(|(value, mask)| value ^ mask));
        Ok(wrapped)
    }

    fn unwrap_dek(
        &self,
        wrapped_dek: &[u8],
        output: &mut zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<()> {
        const PREFIX: &[u8] = b"state-wrap/v1";
        let expected = PREFIX.len() + 16 + 16 + 32;
        if wrapped_dek.len() != expected
            || &wrapped_dek[..PREFIX.len()] != PREFIX
            || &wrapped_dek[PREFIX.len()..PREFIX.len() + 16] != self.binding.profile_id()
            || &wrapped_dek[PREFIX.len() + 16..PREFIX.len() + 32] != self.binding.key_ref()
        {
            return Err(LabError::Storage);
        }
        for (target, (value, mask)) in output.iter_mut().zip(
            wrapped_dek[PREFIX.len() + 32..]
                .iter()
                .zip(self.mask.iter()),
        ) {
            *target = value ^ mask;
        }
        Ok(())
    }

    /// Static test protector: lifecycle operations are unsupported and
    /// fail closed; the fixed binding is always present.
    fn provision_key(&self, _binding: ProfileBinding) -> Result<()> {
        Err(LabError::Storage)
    }

    fn key_status(&self, _binding: ProfileBinding) -> Result<KeyStatus> {
        Ok(KeyStatus::Present)
    }

    fn select_binding(&self, binding: ProfileBinding) -> Result<()> {
        if binding != self.binding {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    fn delete_key(&self, _binding: ProfileBinding) -> Result<()> {
        Err(LabError::Storage)
    }
}

#[test]
fn relay_create_open_round_trip_through_the_boundary() -> std::result::Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("store");

    let dir = PrivateStoreDir::create(&path, StoreKind::Relay)?;
    let mut relay = crate::Relay::create_at(dir, NOW)?;
    let owner = MailboxOwner::new();
    relay.register(&owner.registration(NOW + 60), NOW)?;
    drop(relay);

    let dir = super::open_with_release_grace(&path, StoreKind::Relay)?;
    assert_eq!(dir.main_database_at_open(), MainDatabase::Present);
    let mut relay = crate::Relay::open_at(dir, NOW + 1)?;
    // Identical re-registration proves the mailbox survived the restart.
    assert!(!relay.register(&owner.registration(NOW + 120), NOW + 1)?);
    Ok(())
}

/// Store-level proof: because the boundary rejects companion-only
/// directories, neither store's create can ever observe Absent+companions.
#[test]
fn stores_refuse_companion_only_directories() -> std::result::Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;

    let relay_path = temp.path().join("relay-store");
    drop(PrivateStoreDir::create(&relay_path, StoreKind::Relay)?);
    seed(&relay_path, "relay.sqlite3-wal", b"torn")?;
    let relay_create = PrivateStoreDir::open(&relay_path, StoreKind::Relay)
        .and_then(|dir| crate::Relay::create_at(dir, NOW));
    assert!(relay_create.is_err());

    let state_path = temp.path().join("state-store");
    drop(PrivateStoreDir::create(
        &state_path,
        StoreKind::ClientState,
    )?);
    seed(&state_path, "client-state.sqlite3-journal", b"torn")?;
    let state_create = PrivateStoreDir::open(&state_path, StoreKind::ClientState)
        .and_then(|dir| ClientStateStore::create(dir, protector(), b"state").map(|_| ()));
    assert!(state_create.is_err());
    Ok(())
}

fn seed(
    dir: &std::path::Path,
    name: &str,
    content: &[u8],
) -> std::result::Result<(), Box<dyn Error>> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let path = dir.join(name);
    let mut file = std::fs::File::create(&path)?;
    file.write_all(content)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
