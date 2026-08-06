//! Tests for the Phase-2 `PrivateStoreDir` boundary (design decision §1).
//! Each invariant gets a direct positive and negative test.

#![cfg(unix)]

use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use secure_messenger_lab::{MainDatabase, PrivateStoreDir, StoreKind};
use tempfile::TempDir;

/// Create `parent/name` with exact permissions and content.
fn seed_file(parent: &Path, name: &str, mode: u32, content: &[u8]) -> Result<PathBuf, Box<dyn Error>> {
    let path = parent.join(name);
    let mut file = File::create(&path)?;
    file.write_all(content)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    Ok(path)
}

/// A fresh `PrivateStoreDir::create` target inside a tempdir.
fn target(temp: &TempDir) -> PathBuf {
    temp.path().join("store")
}

/// Reopen with a bounded grace window for the macOS vnode release lag
/// (see the boundary's module docs). Used only by tests that reopen
/// immediately after a drop; assertions that a CONTENDED open fails keep
/// the plain single-attempt `PrivateStoreDir::open`.
fn open_grace(path: &Path, kind: StoreKind) -> Result<PrivateStoreDir, Box<dyn Error>> {
    for _ in 0..50 {
        match PrivateStoreDir::open(path, kind) {
            Ok(dir) => return Ok(dir),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    Ok(PrivateStoreDir::open(path, kind)?)
}

#[test]
fn create_makes_owner_only_locked_directory() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let dir = PrivateStoreDir::create(&target(&temp), StoreKind::ClientState)?;

    assert_eq!(dir.main_database_at_open(), MainDatabase::Absent);
    assert!(dir.database_path().ends_with("client-state.sqlite3"));

    let mode = fs::metadata(target(&temp))?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    Ok(())
}

#[test]
fn create_rejects_an_existing_path() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let _dir = PrivateStoreDir::create(&target(&temp), StoreKind::Relay)?;
    assert!(PrivateStoreDir::create(&target(&temp), StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn open_rejects_a_missing_path() {
    let temp = TempDir::new().ok();
    let Some(temp) = temp else { return };
    assert!(PrivateStoreDir::open(&target(&temp), StoreKind::Relay).is_err());
}

#[test]
fn second_open_fails_while_lock_is_held_and_succeeds_after_drop() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let dir = PrivateStoreDir::create(&target(&temp), StoreKind::Relay)
        .map_err(|e| format!("create: {e:?}"))?;

    assert!(PrivateStoreDir::open(&target(&temp), StoreKind::Relay).is_err());

    drop(dir);
    let reopened = open_grace(&target(&temp), StoreKind::Relay)?;
    assert_eq!(reopened.main_database_at_open(), MainDatabase::Absent);
    Ok(())
}

#[test]
fn open_reports_present_absent_and_empty_main() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    let dir = PrivateStoreDir::create(&path, StoreKind::Relay)?;
    drop(dir);

    seed_file(&path, "relay.sqlite3", 0o600, b"not-a-real-db-but-non-empty")?;
    let dir = open_grace(&path, StoreKind::Relay)?;
    assert_eq!(dir.main_database_at_open(), MainDatabase::Present);
    drop(dir);

    fs::write(path.join("relay.sqlite3"), b"")?;
    let dir = open_grace(&path, StoreKind::Relay)?;
    assert_eq!(dir.main_database_at_open(), MainDatabase::Empty);
    Ok(())
}

#[test]
fn group_or_other_readable_main_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    seed_file(&path, "relay.sqlite3", 0o640, b"x")?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn symlinked_main_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    let real = seed_file(temp.path(), "elsewhere.sqlite3", 0o600, b"x")?;
    symlink(real, path.join("relay.sqlite3"))?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn hardlinked_main_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    let main = seed_file(&path, "relay.sqlite3", 0o600, b"x")?;
    // The second link lives outside the store directory, so only the
    // single-link rule can be what rejects this.
    fs::hard_link(main, temp.path().join("alias.sqlite3"))?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn unexpected_entry_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    seed_file(&path, "notes.txt", 0o600, b"x")?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn unexpected_subdirectory_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    fs::create_dir(path.join("nested"))?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn main_that_is_a_directory_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    fs::create_dir(path.join("relay.sqlite3"))?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn fifo_entry_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    let status = std::process::Command::new("mkfifo")
        .arg(path.join("relay.sqlite3-wal"))
        .status()?;
    assert!(status.success());
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn sqlite_companions_are_accepted_when_regular_and_owner_only() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    seed_file(&path, "relay.sqlite3", 0o600, b"db")?;
    seed_file(&path, "relay.sqlite3-journal", 0o600, b"journal")?;
    seed_file(&path, "relay.sqlite3-wal", 0o600, b"")?;
    seed_file(&path, "relay.sqlite3-shm", 0o600, b"")?;
    let dir = open_grace(&path, StoreKind::Relay)?;
    assert_eq!(dir.main_database_at_open(), MainDatabase::Present);
    Ok(())
}

#[test]
fn symlinked_companion_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    seed_file(&path, "relay.sqlite3", 0o600, b"db")?;
    // Dangling: the guard must reject the link without following it.
    symlink(path.join("no-such-target"), path.join("relay.sqlite3-journal"))?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn lookalike_companion_name_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    seed_file(&path, "relay.sqlite3", 0o600, b"db")?;
    seed_file(&path, "relay.sqlite3-wal.bak", 0o600, b"x")?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn group_accessible_directory_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o750))?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn leftover_lock_file_from_old_versions_is_rejected() -> Result<(), Box<dyn Error>> {
    // The boundary locks the directory descriptor itself; no lock file is a
    // legitimate entry, including one left by an older implementation.
    let temp = TempDir::new()?;
    let path = target(&temp);
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    seed_file(&path, "store.lock", 0o600, b"")?;

    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn foreign_store_database_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    // A client-state database has no business inside a relay directory.
    seed_file(&path, "client-state.sqlite3", 0o600, b"db")?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    Ok(())
}

#[test]
fn open_through_symlinked_path_resolves_and_locks_real_directory() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::ClientState)?);

    let alias = temp.path().join("alias");
    symlink(&path, &alias)?;
    let via_alias = open_grace(&alias, StoreKind::ClientState)?;
    assert_eq!(via_alias.main_database_at_open(), MainDatabase::Absent);
    let canonical_store = fs::canonicalize(&path)?;
    assert_eq!(
        via_alias.database_path(),
        canonical_store.join("client-state.sqlite3")
    );
    // The lock is held on the real directory regardless of the entry path.
    assert!(PrivateStoreDir::open(&path, StoreKind::ClientState).is_err());
    Ok(())
}

const NOW: u64 = 1_800_000_000;

#[test]
fn relay_create_open_round_trip_through_the_boundary() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);

    let dir = PrivateStoreDir::create(&path, StoreKind::Relay)?;
    let mut relay = secure_messenger_lab::Relay::create_at(dir, NOW)?;
    let owner = secure_messenger_lab::MailboxOwner::new();
    relay.register(&owner.registration(NOW + 60), NOW)?;
    drop(relay);

    let dir = open_grace(&path, StoreKind::Relay)?;
    assert_eq!(dir.main_database_at_open(), MainDatabase::Present);
    let mut relay = secure_messenger_lab::Relay::open_at(dir, NOW + 1)?;
    // Identical re-registration proves the mailbox survived the restart.
    assert!(!relay.register(&owner.registration(NOW + 120), NOW + 1)?);
    Ok(())
}

#[test]
fn relay_open_without_create_and_double_create_are_refused() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;

    // Open requires an existing non-empty database.
    let fresh = target(&temp);
    let dir = PrivateStoreDir::create(&fresh, StoreKind::Relay)?;
    assert!(secure_messenger_lab::Relay::open_at(dir, NOW).is_err());

    // Create requires no database.
    let occupied = temp.path().join("occupied");
    let dir = PrivateStoreDir::create(&occupied, StoreKind::Relay)?;
    drop(secure_messenger_lab::Relay::create_at(dir, NOW)?);
    let dir = open_grace(&occupied, StoreKind::Relay)?;
    assert!(secure_messenger_lab::Relay::create_at(dir, NOW).is_err());
    Ok(())
}

#[test]
fn relay_holds_the_lifecycle_lock() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    let dir = PrivateStoreDir::create(&path, StoreKind::Relay)?;
    let relay = secure_messenger_lab::Relay::create_at(dir, NOW)?;

    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());

    drop(relay);
    assert!(open_grace(&path, StoreKind::Relay).is_ok());
    Ok(())
}

#[test]
fn wrong_kind_directory_is_rejected_for_a_relay() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    // A directory secured for the client-state store must not be usable as a
    // relay directory, and vice versa.
    let dir = PrivateStoreDir::create(&path, StoreKind::ClientState)?;
    assert!(secure_messenger_lab::Relay::create_at(dir, NOW).is_err());
    Ok(())
}

// --- companion-only directories (review remediation, finding 1) -----------

/// Every companion suffix alone in a directory (no main database) must
/// reject, for both store kinds.
#[test]
fn companion_only_directory_is_rejected_for_both_kinds() -> Result<(), Box<dyn Error>> {
    for kind in [StoreKind::Relay, StoreKind::ClientState] {
        let (base, companions): (&str, [&str; 3]) = match kind {
            StoreKind::Relay => ("relay.sqlite3", ["-journal", "-wal", "-shm"]),
            StoreKind::ClientState => ("client-state.sqlite3", ["-journal", "-wal", "-shm"]),
        };
        for suffix in companions {
            let temp = TempDir::new()?;
            let path = target(&temp);
            drop(PrivateStoreDir::create(&path, kind)?);
            seed_file(&path, &format!("{base}{suffix}"), 0o600, b"torn-companion")?;
            assert!(
                PrivateStoreDir::open(&path, kind).is_err(),
                "lone companion {base}{suffix} accepted for {kind:?}"
            );
        }
    }
    Ok(())
}

/// A main database WITH a companion (the hot-journal state) must still be
/// accepted by the boundary.
#[test]
fn main_with_companion_is_accepted_hot_journal_state() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);
    seed_file(&path, "relay.sqlite3", 0o600, b"non-empty-database")?;
    seed_file(&path, "relay.sqlite3-journal", 0o600, b"hot-journal")?;
    let dir = open_grace(&path, StoreKind::Relay)?;
    assert_eq!(dir.main_database_at_open(), MainDatabase::Present);
    Ok(())
}

/// Store-level proof: because the boundary rejects companion-only
/// directories, neither store's create can ever observe Absent+companions.
#[test]
fn stores_refuse_companion_only_directories() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let relay_path = target(&temp);
    drop(PrivateStoreDir::create(&relay_path, StoreKind::Relay)?);
    seed_file(&relay_path, "relay.sqlite3-wal", 0o600, b"torn")?;
    let relay_create = PrivateStoreDir::open(&relay_path, StoreKind::Relay)
        .and_then(|dir| secure_messenger_lab::Relay::create_at(dir, NOW));
    assert!(relay_create.is_err());

    let state_path = temp.path().join("state-store");
    drop(PrivateStoreDir::create(&state_path, StoreKind::ClientState)?);
    seed_file(&state_path, "client-state.sqlite3-journal", 0o600, b"torn")?;
    let state_create = PrivateStoreDir::open(&state_path, StoreKind::ClientState)
        .and_then(|dir| {
            secure_messenger_lab::ClientStateStore::create(dir, protector(), b"state").map(|_| ())
        });
    assert!(state_create.is_err());
    Ok(())
}

// --- ACL rejection (review remediation, finding 3; macOS) ------------------

/// XOR test protector for the store-level refusal test, mirroring the one
/// in `src/persistence/sqlite.rs` tests.
struct TestProtector {
    binding: secure_messenger_lab::ProfileBinding,
    mask: [u8; 32],
}

fn protector() -> TestProtector {
    TestProtector {
        binding: secure_messenger_lab::ProfileBinding::new([0x42; 16], [0x24; 16]),
        mask: [0x24; 32],
    }
}

impl secure_messenger_lab::StateKeyProtector for TestProtector {
    fn expected_binding(&self) -> secure_messenger_lab::Result<secure_messenger_lab::ProfileBinding> {
        Ok(self.binding)
    }

    fn protection_level(&self) -> secure_messenger_lab::ProtectionLevel {
        secure_messenger_lab::ProtectionLevel::SoftwareBacked
    }

    fn wrap_dek(
        &self,
        dek: &zeroize::Zeroizing<[u8; 32]>,
    ) -> secure_messenger_lab::Result<Vec<u8>> {
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
    ) -> secure_messenger_lab::Result<()> {
        const PREFIX: &[u8] = b"state-wrap/v1";
        let expected = PREFIX.len() + 16 + 16 + 32;
        if wrapped_dek.len() != expected
            || &wrapped_dek[..PREFIX.len()] != PREFIX
            || &wrapped_dek[PREFIX.len()..PREFIX.len() + 16] != self.binding.profile_id()
            || &wrapped_dek[PREFIX.len() + 16..PREFIX.len() + 32] != self.binding.key_ref()
        {
            return Err(secure_messenger_lab::LabError::Storage);
        }
        for (target, (value, mask)) in output
            .iter_mut()
            .zip(wrapped_dek[PREFIX.len() + 32..].iter().zip(self.mask.iter()))
        {
            *target = value ^ mask;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn chmod(args: &[&str], path: &Path) -> Result<(), Box<dyn Error>> {
    let status = std::process::Command::new("chmod")
        .args(args)
        .arg(path)
        .status()?;
    assert!(status.success(), "chmod {args:?} failed");
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn directory_with_acl_is_rejected_until_cleaned() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);

    // A 0700 directory carrying an `everyone allow` ACL must be rejected:
    // the mode bits alone no longer express the access policy.
    chmod(&["+a", "everyone allow read"], &path)?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());

    // After stripping every ACL the same directory is accepted.
    chmod(&["-N"], &path)?;
    assert!(open_grace(&path, StoreKind::Relay).is_ok());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn create_under_acl_inheriting_parent_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let parent = temp.path().join("inheriting-parent");
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    chmod(
        &[
            "+a",
            "everyone allow read,write,execute,file_inherit,directory_inherit",
        ],
        &parent,
    )?;

    // The fresh child inherits the ACL; create must fail closed (and must
    // not strip it).
    let child = parent.join("store");
    assert!(PrivateStoreDir::create(&child, StoreKind::Relay).is_err());

    // Cleanup: remove the ACL and the leftover child directory; a fresh
    // create then succeeds.
    chmod(&["-N"], &parent)?;
    fs::remove_dir(&child)?;
    let dir = PrivateStoreDir::create(&child, StoreKind::Relay)?;
    assert_eq!(dir.main_database_at_open(), MainDatabase::Absent);
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn main_or_companion_with_acl_is_rejected() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let path = target(&temp);
    drop(PrivateStoreDir::create(&path, StoreKind::Relay)?);
    let main = seed_file(&path, "relay.sqlite3", 0o600, b"non-empty-database")?;

    chmod(&["+a", "everyone allow read"], &main)?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    chmod(&["-N"], &main)?;
    assert!(open_grace(&path, StoreKind::Relay).is_ok());

    let companion = seed_file(&path, "relay.sqlite3-wal", 0o600, b"hot-wal")?;
    chmod(&["+a", "everyone allow read"], &companion)?;
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_err());
    chmod(&["-N"], &companion)?;
    assert!(open_grace(&path, StoreKind::Relay).is_ok());
    Ok(())
}
