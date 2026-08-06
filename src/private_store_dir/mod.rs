//! The enforced private-directory boundary of Phase-2 design decision §1.
//!
//! One opaque [`PrivateStoreDir`] is shared by both stores (relay and client
//! state). It owns the directory that holds exactly one database and its
//! `SQLite` companions, with crate-fixed basenames, and enforces the frozen
//! rules:
//!
//! - the directory is owned by the application UID with no group or other
//!   access;
//! - the directory and every expected file are regular, owner-only,
//!   same-owner and single-link, and carry NO access-control entries beyond
//!   what the mode bits express (POSIX ACLs bypass owner-only mode checks
//!   on macOS and survive `fchmod`; detection is fail-closed and nothing is
//!   ever stripped — see `acl.rs`);
//! - a directory containing any companion (`-journal`/`-wal`/`-shm`) while
//!   the main database is absent is torn/anomalous state and is rejected —
//!   create requires the main database and all companions absent, and a
//!   lone companion is never auto-deleted (§1);
//! - every symlink, hardlink, device, FIFO, socket and unexpected entry is
//!   rejected;
//! - an exclusive non-blocking lifecycle lock is acquired before any database
//!   or companion is examined, and held for the lifetime of the handle;
//! - content checks are descriptor-relative (probe-opened with `O_NOFOLLOW`
//!   and `fstat`-ed), never canonicalize-then-reopen.
//!
//! The lifecycle lock is an `flock` on the directory descriptor itself, not
//! on a lock file: there is no lock file to create, validate, or leave
//! behind, and the lock is released exactly when the handle's last directory
//! descriptor closes. `flock` (not `fcntl` record locks) is used precisely
//! because it is description-scoped, so a second open by the *same* process
//! still conflicts — `fcntl` locks are process-scoped and would silently
//! admit a duplicate live store.
//!
//! The lock is strictly non-blocking: exactly one
//! `flock(NonBlockingLockExclusive)` attempt, and contention or any error
//! fails immediately. Consequence, measured on this codebase's own suite:
//! on macOS an immediate drop-then-reopen can transiently fail closed under
//! filesystem churn (vnode release lag). That is fail-closed and retryable
//! by the caller — the façade's reconcile path surfaces it as an ordinary
//! storage error — so production code never retries inside the boundary and
//! only tests reopen through a bounded grace helper.
//!
//! What this boundary deliberately does not defend against (frozen in §1):
//! root or OS compromise, arbitrary code running under the application UID,
//! same-UID processes that ignore the lock, external `SQLite` tools,
//! filesystem or block-level rollback, and copied foreign relay databases.
//! The final `SQLite` open is still pathname-based (`rusqlite` accepts no
//! descriptor); the residual gap between these checks and that open is a
//! same-UID race, which is out of scope above.
//!
//! Platform duties from §1 that a harness cannot perform — creating the
//! directory under the platform's private storage, excluding it from backup
//! and transfer — belong to the future platform adapter and are documented
//! here as not yet done.
//!
//! Only Unix is supported in Phase 2: this module uses descriptor-relative
//! POSIX operations throughout, and the crate's stores depend on it, so the
//! crate does not build on non-Unix targets.

mod acl;

#[cfg(test)]
mod store_boundary_tests;

use std::ffi::OsStr;
use std::fs::{DirBuilder, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use rustix::process::geteuid;

use crate::{LabError, Result};

/// Which store a [`PrivateStoreDir`] hosts. Basenames are fixed here and
/// nowhere else; callers never choose them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Relay,
    ClientState,
    /// The platform-key lifecycle registry (`src/lifecycle.rs`).
    Lifecycle,
}

impl StoreKind {
    fn main_basename(self) -> &'static [u8] {
        match self {
            Self::Relay => b"relay.sqlite3",
            Self::ClientState => b"client-state.sqlite3",
            Self::Lifecycle => b"lifecycle.sqlite3",
        }
    }
}

/// The open-time state of the main database file, after full validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainDatabase {
    /// No main database file exists. Store creation requires this state.
    Absent,
    /// A main database file exists but is zero-length. Neither store may
    /// create or open over it: it is unexpected leftover state.
    Empty,
    /// A non-empty, validated main database file exists. Store open requires
    /// this state.
    Present,
}

/// `SQLite` companion suffixes that may sit beside the main database.
const COMPANION_SUFFIXES: [&[u8]; 3] = [b"-journal", b"-wal", b"-shm"];

/// A validated, locked, private store directory.
///
/// The directory descriptor holds the exclusive lifecycle lock for the
/// lifetime of the handle; dropping the handle releases it.
#[derive(Debug)]
pub struct PrivateStoreDir {
    dir: File,
    path: PathBuf,
    kind: StoreKind,
    main_at_open: MainDatabase,
}

impl PrivateStoreDir {
    /// Create a fresh private directory at `path`, which must not yet exist,
    /// and return the locked, validated handle. The directory is created
    /// owner-only and must contain no database or companion.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error if the path exists, the directory
    /// cannot be secured, the lock cannot be taken, or any unexpected entry
    /// appears.
    pub fn create(path: &Path, kind: StoreKind) -> Result<Self> {
        DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| LabError::Storage)?;
        let path = canonical(path)?;
        let dir = open_dir(&path)?;
        // The builder mode passes through umask; make the permission exact
        // before anything else looks at the directory. Tightening a fresh,
        // self-created directory is safe; `secure` verifies the result.
        fs::fchmod(&dir, Mode::from_raw_mode(0o700)).map_err(|_| LabError::Storage)?;
        let handle = Self::secure(dir, path, kind)?;
        // A fresh directory contains nothing. Anything else means the path
        // was raced or reused; fail closed.
        if handle.main_at_open != MainDatabase::Absent {
            return Err(LabError::Storage);
        }
        Ok(handle)
    }

    /// Open and validate an existing private directory at `path`, take the
    /// exclusive lifecycle lock, and validate every entry inside it.
    ///
    /// The caller then decides from [`Self::main_database_at_open`] whether a
    /// store create or store open is permitted.
    ///
    /// The lock is strictly non-blocking. On macOS, an immediate reopen
    /// after dropping the previous handle can transiently fail closed under
    /// filesystem churn (vnode release lag, measured in this repository).
    /// That failure is an ordinary retryable storage error; the façade's
    /// reconcile path surfaces it as one. Production callers retry at their
    /// own cadence; this boundary never retries internally.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error on any violated invariant: missing or
    /// misowned directory, anomalous entry, symlink, hardlink, ACL beyond
    /// the mode bits, torn companions, or lock contention.
    pub fn open(path: &Path, kind: StoreKind) -> Result<Self> {
        let path = canonical(path)?;
        let dir = open_dir(&path)?;
        Self::secure(dir, path, kind)
    }

    /// The pathname of the main database inside the secured directory.
    ///
    /// `SQLite` opens by pathname; this path is derived from the
    /// canonicalized, validated, locked directory and the crate-fixed
    /// basename. See the module docs for the accepted residual race.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.path.join(OsStr::from_bytes(self.kind.main_basename()))
    }

    /// The validated state of the main database at the moment the directory
    /// was secured.
    #[must_use]
    pub const fn main_database_at_open(&self) -> MainDatabase {
        self.main_at_open
    }

    /// The store kind this directory was secured for.
    #[must_use]
    pub const fn kind(&self) -> StoreKind {
        self.kind
    }

    /// Create the still-absent main database file, owner-only, failing if it
    /// already exists.
    ///
    /// `SQLite` creates a missing database world-readable-subject-to-umask,
    /// which this boundary would then reject on the next open, and stores
    /// must not repair permissions after the fact. Creating the file
    /// descriptor-relative with exact permissions first lets `SQLite` inherit
    /// them (it propagates the main file's mode to its journals), and the
    /// exclusive create closes the gap between the [`MainDatabase::Absent`]
    /// check and the database's first write.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error if the file exists or cannot be created
    /// with owner-only permissions.
    pub fn create_main_database_file(&self) -> Result<()> {
        let name =
            std::ffi::CString::new(self.kind.main_basename()).map_err(|_| LabError::Storage)?;
        let fd = fs::openat(
            &self.dir,
            name.as_c_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| LabError::Storage)?;
        let file = File::from(fd);
        verify_regular_file(&file)?;
        Ok(())
    }

    /// Delete exactly the main database and the three allowed companions,
    /// descriptor-relative, then durably sync the directory. Missing entries
    /// are skipped, so a partially completed delete resumes idempotently
    /// (used by the lifecycle manager's destructive reset).
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error if an unlink or the directory sync
    /// fails.
    pub(crate) fn delete_database_and_companions_synced(&self) -> Result<()> {
        for suffix in [b"".as_slice(), b"-journal", b"-wal", b"-shm"] {
            let mut name = self.kind.main_basename().to_vec();
            name.extend_from_slice(suffix);
            let c_name = std::ffi::CString::new(name).map_err(|_| LabError::Storage)?;
            match fs::unlinkat(&self.dir, c_name.as_c_str(), fs::AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(_) => return Err(LabError::Storage),
            }
        }
        fs::fsync(&self.dir).map_err(|_| LabError::Storage)
    }

    /// Shared tail of `create`/`open`: verify the directory itself, take the
    /// lifecycle lock, then enumerate and validate every entry.
    fn secure(dir: File, path: PathBuf, kind: StoreKind) -> Result<Self> {
        verify_directory(&dir)?;
        lock_directory(&dir)?;
        let main_at_open = validate_entries(&dir, kind)?;
        Ok(Self {
            dir,
            path,
            kind,
            main_at_open,
        })
    }
}

/// Canonicalize an existing path; a missing or unresolvable path fails
/// closed. After this, the directory is opened descriptor-first and every
/// content check below is descriptor-relative.
fn canonical(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|_| LabError::Storage)
}

/// Open a directory itself with `O_NOFOLLOW | O_DIRECTORY`, so a swapped or
/// symlinked final component fails instead of being followed.
fn open_dir(path: &Path) -> Result<File> {
    let fd = fs::openat(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| LabError::Storage)?;
    Ok(File::from(fd))
}

/// The directory must be a real directory, owned by this UID, with no group
/// or other access bits and no ACL beyond what the mode bits express.
fn verify_directory(dir: &File) -> Result<()> {
    let stat = fs::fstat(dir).map_err(|_| LabError::Storage)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(LabError::Storage);
    }
    if stat.st_uid != geteuid().as_raw() {
        return Err(LabError::Storage);
    }
    if stat.st_mode & 0o077 != 0 {
        return Err(LabError::Storage);
    }
    acl::reject_extended_acl(dir)
}

/// Take the exclusive lifecycle lock on the directory descriptor.
///
/// Strictly non-blocking: exactly one `flock(NonBlockingLockExclusive)`
/// attempt; contention or any error fails immediately. See the module docs
/// for the measured macOS vnode-release-lag consequence and where the
/// resulting transient failure is absorbed (callers/tests, never here).
fn lock_directory(dir: &File) -> Result<()> {
    fs::flock(dir, FlockOperation::NonBlockingLockExclusive).map_err(|_| LabError::Storage)
}

/// An expected file must be a regular file, owned by this UID, single-link,
/// owner-only, and free of any ACL beyond what the mode bits express.
fn verify_regular_file(file: &File) -> Result<()> {
    let stat = fs::fstat(file).map_err(|_| LabError::Storage)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(LabError::Storage);
    }
    if stat.st_uid != geteuid().as_raw() {
        return Err(LabError::Storage);
    }
    if stat.st_nlink != 1 {
        return Err(LabError::Storage);
    }
    if stat.st_mode & 0o077 != 0 {
        return Err(LabError::Storage);
    }
    acl::reject_extended_acl(file)
}

/// Enumerate the directory descriptor-relative and validate every entry.
/// Anything that is not the main database or an exact-suffix companion of it
/// rejects the whole directory. A companion present while the main database
/// is absent is torn/anomalous state and also rejects: create requires the
/// main database and all companions absent, and nothing is auto-deleted.
fn validate_entries(dir: &File, kind: StoreKind) -> Result<MainDatabase> {
    let mut listing = fs::Dir::read_from(dir).map_err(|_| LabError::Storage)?;
    let mut main: Option<u64> = None;
    let mut companion_seen = false;
    while let Some(entry) = listing.read() {
        let entry = entry.map_err(|_| LabError::Storage)?;
        let name = entry.file_name().to_bytes();
        // `Dir::read` yields `.` and `..`; they are not store content.
        if name == b"." || name == b".." {
            continue;
        }
        let base = kind.main_basename();
        if name == base {
            let probe = probe(dir, name)?;
            let stat = fs::fstat(&probe).map_err(|_| LabError::Storage)?;
            main = Some(u64::try_from(stat.st_size).map_err(|_| LabError::Storage)?);
            continue;
        }
        let is_companion = COMPANION_SUFFIXES.iter().any(|suffix| {
            name.len() == base.len() + suffix.len()
                && name.starts_with(base)
                && name.ends_with(suffix)
        });
        if is_companion {
            let _ = probe(dir, name)?;
            companion_seen = true;
            continue;
        }
        // Any other entry — including subdirectories, devices, FIFOs,
        // sockets, dangling paths and plain unexpected files — fails closed.
        return Err(LabError::Storage);
    }
    if companion_seen && main.is_none() {
        return Err(LabError::Storage);
    }
    Ok(match main {
        None => MainDatabase::Absent,
        Some(0) => MainDatabase::Empty,
        Some(_) => MainDatabase::Present,
    })
}

/// Probe-open one entry descriptor-relative with `O_NOFOLLOW` and validate
/// it. A symlink fails the open itself; a vanishing entry fails closed; the
/// opened descriptor — not the name — is what gets inspected.
fn probe(dir: &File, name: &[u8]) -> Result<File> {
    let c_name = std::ffi::CString::new(name).map_err(|_| LabError::Storage)?;
    let fd = fs::openat(
        dir,
        c_name.as_c_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| LabError::Storage)?;
    let file = File::from(fd);
    verify_regular_file(&file)?;
    Ok(file)
}

/// Test-only open with a bounded grace window for the macOS vnode release
/// lag (see the module docs): retries `open` for up to 500 ms in 10 ms
/// steps. In-crate tests that reopen immediately after dropping a handle
/// use this; assertions that a CONTENDED open fails must keep using the
/// plain single-attempt [`PrivateStoreDir::open`]. Integration tests carry
/// their own copy (they cannot reach crate-private items).
#[cfg(test)]
pub(crate) fn open_with_release_grace(path: &Path, kind: StoreKind) -> Result<PrivateStoreDir> {
    for _ in 0..50 {
        match PrivateStoreDir::open(path, kind) {
            Ok(dir) => return Ok(dir),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    PrivateStoreDir::open(path, kind)
}
