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
    let reopened = PrivateStoreDir::open(&target(&temp), StoreKind::Relay)?;
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
    let dir = PrivateStoreDir::open(&path, StoreKind::Relay)?;
    assert_eq!(dir.main_database_at_open(), MainDatabase::Present);
    drop(dir);

    fs::write(path.join("relay.sqlite3"), b"")?;
    let dir = PrivateStoreDir::open(&path, StoreKind::Relay)?;
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
    let dir = PrivateStoreDir::open(&path, StoreKind::Relay)?;
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
    let via_alias = PrivateStoreDir::open(&alias, StoreKind::ClientState)?;
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

    let dir = PrivateStoreDir::open(&path, StoreKind::Relay)?;
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
    let dir = PrivateStoreDir::open(&occupied, StoreKind::Relay)?;
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
    assert!(PrivateStoreDir::open(&path, StoreKind::Relay).is_ok());
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
