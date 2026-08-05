//! Shared `SQLite` companion-file inspection.
//!
//! Both database-backed stores in this crate — the relay and the client state
//! store — are exposed to the same weakness, so the guard lives here rather
//! than being copied. A copy that drifts from its twin is exactly how a false
//! claim survives review, which this codebase has demonstrated repeatedly.

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::Path;

use crate::{LabError, Result};

/// Fail closed when a non-empty `-wal` sits beside a database whose own header
/// is not in WAL mode, before anything opens the database normally.
///
/// `SQLite` opens a `-wal` on file existence alone and never consults the main
/// header, so without this check the normal open replays whatever the file
/// contains and checkpoints it in. Creating that one file — with no write
/// access to the database itself — was enough to destroy a healthy store
/// permanently, because the foreign content landed in the database before
/// validation could reject it and stayed there afterwards. Measured on both
/// stores: a relay went 57344 -> 61440 bytes and a client state store 8192 ->
/// 12288, each rejected on every later open even after the planted file was
/// removed.
///
/// Refusing keeps the database byte-identical, which turns that into a
/// recoverable condition: remove the stray file and the store opens again. It
/// does mean a planted file can stop a store from starting, but a refusal that
/// preserves the data is strictly better than an open that destroys it.
///
/// Neither store *leaves* a database in WAL mode — both set
/// `journal_mode = DELETE` on every open that succeeds. Either will still
/// accept one, and convert it back, so this is not a claim that the header is
/// always rollback-mode. A *failed* open does leave it: both stores validate
/// before setting the pragma, so a rejected database keeps its WAL-mode header.
/// What this does mean is that a SUCCESSFUL open never *ends* in WAL mode,
/// so a `-wal` beside a rollback-mode header did not come from this crate and
/// is not legitimate recovery state. That holds because `SQLite` checkpoints
/// and unlinks the `-wal` before flipping the header out of WAL mode, so a
/// crash mid-conversion leaves a WAL-mode header with no companion, never the
/// reverse. That ordering is in the bundled engine, not inferred from crash
/// sampling: in `libsqlite3-sys` 0.37.0 / `SQLite` 3.51.3, `OP_JournalMode`
/// calls `sqlite3PagerCloseWal`, whose comment reads "checkpoints and deletes
/// the write-ahead-log file", and only then calls `sqlite3PagerSetJournalMode`
/// to change the header. Re-verify this on any `SQLite` bump. A genuine
/// WAL-mode database with a live `-wal` passes this check unharmed.
///
/// Both stores refuse alike, including when the database itself is absent: a
/// non-empty `-wal` with no main database is never legitimate recovery state,
/// so there is nothing to preserve by allowing the open. Neither store ever
/// enables WAL, so this cannot be self-inflicted.
///
/// The guard covers this crate's own open paths, not the filesystem. Any other
/// `SQLite` client that opens the same path while the planted file exists still
/// triggers the replay, because that decision belongs to whoever opens the
/// database. That is not hypothetical: an inspection helper inside
/// `planted_wal_is_refused_without_touching_the_database` corrupted the very
/// database the refusal had just preserved, until it was moved after cleanup.
///
/// # Errors
///
/// Returns [`LabError::Storage`] when the companion is anomalous, and when a
/// filesystem error other than a missing companion prevents deciding.
pub(crate) fn reject_anomalous_wal(path: &Path) -> Result<()> {
    let resolved = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !nonempty_companion(&resolved, "-wal")? {
        return Ok(());
    }
    if database_header_uses_wal(&resolved)? {
        return Ok(());
    }
    Err(LabError::Storage)
}

/// Whether an exact-suffix companion exists and is non-empty.
///
/// Callers resolve the path before calling this, because `SQLite` names its
/// journal after the link target rather than the link, and deriving companion
/// names from an unresolved symlink would miss a genuine hot journal and reject
/// a recoverable database. This function itself performs no resolution and
/// appends the suffix to whatever it is given.
///
/// Resolution is best-effort at the call site: [`reject_anomalous_wal`] falls
/// back to the unresolved path when `canonicalize` fails, which it does for any
/// path that does not exist — the normal case for a first create. A dangling
/// symlink therefore escapes the guard, which is benign because the target is
/// created fresh and a planted WAL's salts cannot match it.
///
/// # Errors
///
/// Returns [`LabError::Storage`] on any filesystem error other than the
/// companion being absent.
pub(crate) fn nonempty_companion(path: &Path, suffix: &str) -> Result<bool> {
    let mut companion = path.as_os_str().to_os_string();
    companion.push(suffix);
    match fs::metadata(Path::new(&companion)) {
        Ok(metadata) => Ok(metadata.len() > 0),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(LabError::Storage),
    }
}

/// Whether the main database header itself declares WAL mode.
///
/// A file too short to hold a header reads as not-WAL, which fails closed
/// toward the caller's stricter path rather than toward the bypass.
///
/// # Errors
///
/// Returns [`LabError::Storage`] when the file cannot be opened or read.
pub(crate) fn database_header_uses_wal(path: &Path) -> Result<bool> {
    let mut file = fs::File::open(path).map_err(|_| LabError::Storage)?;
    let mut header = [0_u8; 20];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(false),
        Err(_) => return Err(LabError::Storage),
    }
    Ok(header[..16] == *b"SQLite format 3\0" && header[18] == 2 && header[19] == 2)
}
