use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

use crate::capability::{
    AckRequest, DeleteMailboxRequest, FetchRequest, MailboxRegistration, SendRequest, digest,
};
use crate::companion::{database_header_uses_wal, nonempty_companion, reject_anomalous_wal};
use crate::private_store_dir::{MainDatabase, PrivateStoreDir, StoreKind};
use crate::{EncryptedPacket, LabError, MessageId, Nonce, QueueId, Result};

// The path-level hostile-fixture tests moved in-crate with the raw-path
// constructors they exercise (review remediation: those constructors are
// `#[cfg(test)] pub(crate)`, so their tests must be too).
#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod file_backed_tests;
#[cfg(test)]
mod request_boundary_tests;
#[cfg(test)]
mod schema_upgrade_tests;

const MAX_PACKET_BYTES: usize = 1_048_576;
const MAX_MESSAGE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const TOMBSTONE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const CURRENT_SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Stored,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    Deleted,
    AlreadyDeleted,
}

#[derive(Clone)]
pub struct StoredEnvelope {
    pub queue_id: QueueId,
    pub message_id: MessageId,
    pub packet: EncryptedPacket,
    pub expires_at: u64,
    pub sender_signature: Ed25519Signature,
}

impl std::fmt::Debug for StoredEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredEnvelope")
            .field("queue_id", &self.queue_id)
            .field("message_id", &self.message_id)
            .field("packet", &self.packet)
            .field("expires_at", &self.expires_at)
            .field("sender_signature", &"redacted")
            .finish()
    }
}

/// SQLite-backed store-and-forward relay for the disposable proof.
///
/// The schema intentionally has no users, contacts, conversations, groups, or
/// plaintext columns. It stores per-mailbox public authorization keys, opaque
/// queue/message identifiers, ciphertext, expiries, and bounded tombstones.
///
/// Production construction goes through [`PrivateStoreDir`] only, split into
/// [`Relay::create`] (directory must hold no database) and [`Relay::open`]
/// (directory must hold one validated non-empty database). The store owns the
/// directory handle, holding the lifecycle lock for its own lifetime. The
/// raw-path constructors are `#[cfg(test)]` and exist for the path-level
/// hostile-fixture tests, which live in-crate for that reason; normal builds
/// contain no path-based store constructor.
pub struct Relay {
    connection: Connection,
    audit_events: Vec<&'static str>,
    // Held for the lifecycle lock and the boundary's entry validation. Only
    // `None` for in-memory relays and the cfg(test) path constructors.
    _dir: Option<PrivateStoreDir>,
}

impl Relay {
    /// Create a file-backed relay database inside a secured private
    /// directory. The directory must contain no database or companion
    /// ([`MainDatabase::Absent`]).
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if the directory already holds a
    /// database or `SQLite` cannot initialize the schema.
    pub fn create(dir: PrivateStoreDir) -> Result<Self> {
        Self::create_at(dir, unix_now()?)
    }

    /// Create a file-backed relay using an explicit clock value for its first
    /// global expiry sweep. This keeps startup behavior testable.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if the directory already holds a
    /// database or `SQLite` cannot initialize the schema.
    pub fn create_at(dir: PrivateStoreDir, now: u64) -> Result<Self> {
        if dir.kind() != StoreKind::Relay || dir.main_database_at_open() != MainDatabase::Absent {
            return Err(LabError::Storage);
        }
        dir.create_main_database_file()?;
        let connection = Connection::open(dir.database_path())?;
        Self::initialize(connection, now, Some(dir))
    }

    /// Open the existing file-backed relay database inside a secured private
    /// directory. The directory must hold one validated non-empty database
    /// ([`MainDatabase::Present`]).
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if no usable database exists, if
    /// `SQLite` cannot open or migrate it, and also when the open is
    /// *refused* — a non-empty `-wal` beside a database not in WAL mode fails
    /// closed even though `SQLite` could have opened it. See
    /// [`reject_anomalous_wal`].
    pub fn open(dir: PrivateStoreDir) -> Result<Self> {
        Self::open_at(dir, unix_now()?)
    }

    /// Open a file-backed relay and run its global expiry sweep using an
    /// explicit clock value. This keeps restart behavior testable.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if no usable database exists, if
    /// `SQLite` cannot open, migrate, or sweep it, and also when the open is
    /// *refused* — a non-empty `-wal` beside a database not in WAL mode fails
    /// closed even though `SQLite` could have opened it. See
    /// [`reject_anomalous_wal`].
    pub fn open_at(dir: PrivateStoreDir, now: u64) -> Result<Self> {
        if dir.kind() != StoreKind::Relay || dir.main_database_at_open() != MainDatabase::Present {
            return Err(LabError::Storage);
        }
        Self::open_at_path(&dir.database_path(), now, Some(dir))
    }

    /// Test-only raw-path constructor for the path-level hostile-fixture
    /// tests (now in-crate), bypassing the [`PrivateStoreDir`] boundary.
    /// Compiled only under `cfg(test)`: normal builds contain no
    /// path-based store constructor at all.
    #[cfg(test)]
    pub(crate) fn open_with_path_for_test(path: &Path) -> Result<Self> {
        Self::open_at_path(path, unix_now()?, None)
    }

    /// Test-only raw-path constructor for the path-level hostile-fixture
    /// tests (now in-crate), bypassing the [`PrivateStoreDir`] boundary.
    /// Compiled only under `cfg(test)`: normal builds contain no
    /// path-based store constructor at all.
    #[cfg(test)]
    pub(crate) fn open_at_with_path_for_test(path: &Path, now: u64) -> Result<Self> {
        Self::open_at_path(path, now, None)
    }

    fn open_at_path(path: &Path, now: u64, dir: Option<PrivateStoreDir>) -> Result<Self> {
        preflight_existing_database(path)?;
        let connection = Connection::open(path)?;
        Self::initialize(connection, now, dir)
    }

    /// Open an ephemeral in-memory relay database.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if `SQLite` cannot initialize the schema.
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        Self::initialize(connection, unix_now()?, None)
    }

    fn initialize(
        mut connection: Connection,
        now: u64,
        dir: Option<PrivateStoreDir>,
    ) -> Result<Self> {
        connection.busy_timeout(Duration::from_secs(2))?;
        // Do not change journal mode or begin a migration until the opened
        // database has passed the exact schema/version preflight.
        validate_schema_for_open(&connection)?;
        connection.execute_batch(
            "
            PRAGMA secure_delete = ON;
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            PRAGMA auto_vacuum = FULL;
            PRAGMA trusted_schema = OFF;
            ",
        )?;

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        migrate_schema(&transaction)?;
        purge_expired_in(&transaction, now)?;
        transaction.commit()?;
        Ok(Self {
            connection,
            audit_events: Vec::new(),
            _dir: dir,
        })
    }

    /// Register a mailbox after verifying proof of the management capability.
    ///
    /// Returns `true` for a new mailbox and `false` for an identical retry.
    ///
    /// # Errors
    ///
    /// Returns an error for an expired/invalid signature, a conflicting queue,
    /// or a storage failure.
    pub fn register(&mut self, request: &MailboxRegistration, now: u64) -> Result<bool> {
        validate_request_time(request.valid_until, now)?;
        request
            .manage_key
            .verify(&request.signing_bytes(), &request.signature)
            .map_err(|_| LabError::Unauthorized)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge_expired_in(&transaction, now)?;
        let queue_hash = digest(request.queue_id.as_bytes());
        let retired = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM retired_queues WHERE queue_hash = ?1)",
            params![queue_hash.as_slice()],
            |row| row.get::<_, bool>(0),
        )?;
        if retired {
            return Err(LabError::MailboxConflict);
        }

        let existing = transaction
            .query_row(
                "SELECT send_key, receive_key, manage_key FROM mailboxes WHERE queue_id = ?1",
                params![request.queue_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;

        if let Some((send, receive, manage)) = existing {
            let same = send == request.send_key.as_bytes()
                && receive == request.receive_key.as_bytes()
                && manage == request.manage_key.as_bytes();
            if !same {
                return Err(LabError::MailboxConflict);
            }
            transaction.execute(
                "INSERT OR IGNORE INTO registration_nonces(queue_id, nonce, delete_after)
                 VALUES (?1, ?2, ?3)",
                params![
                    request.queue_id.as_bytes().as_slice(),
                    request.nonce.as_bytes().as_slice(),
                    to_i64(request.valid_until)?,
                ],
            )?;
            transaction.commit()?;
            self.audit_events.push("mailbox_registration_duplicate");
            return Ok(false);
        }

        let recorded = transaction.execute(
            "INSERT OR IGNORE INTO registration_nonces(queue_id, nonce, delete_after)
             VALUES (?1, ?2, ?3)",
            params![
                request.queue_id.as_bytes().as_slice(),
                request.nonce.as_bytes().as_slice(),
                to_i64(request.valid_until)?,
            ],
        )?;
        if recorded != 1 {
            return Err(LabError::Unauthorized);
        }
        transaction.execute(
            "INSERT INTO mailboxes(queue_id, send_key, receive_key, manage_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request.queue_id.as_bytes().as_slice(),
                request.send_key.as_bytes().as_slice(),
                request.receive_key.as_bytes().as_slice(),
                request.manage_key.as_bytes().as_slice(),
                to_i64(now)?,
            ],
        )?;
        transaction.commit()?;
        self.audit_events.push("mailbox_registered");
        Ok(true)
    }

    /// Store one authenticated opaque packet with bounded retention.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid size/expiry/authentication, unknown mailbox,
    /// a replayed deleted ID, conflicting retry, or storage failure.
    pub fn enqueue(&mut self, request: &SendRequest, now: u64) -> Result<EnqueueOutcome> {
        if request.packet.as_bytes().is_empty()
            || request.packet.as_bytes().len() > MAX_PACKET_BYTES
        {
            return Err(LabError::InvalidPayload);
        }
        validate_message_expiry(request.expires_at, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge_expired_in(&transaction, now)?;
        let send_key = mailbox_key(&transaction, request.queue_id, "send_key")?;
        send_key
            .verify(&request.signing_bytes(), &request.signature)
            .map_err(|_| LabError::Unauthorized)?;

        let tombstoned = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM tombstones
                WHERE queue_id = ?1 AND message_id = ?2 AND delete_after > ?3
            )",
            params![
                request.queue_id.as_bytes().as_slice(),
                request.message_id.as_bytes().as_slice(),
                to_i64(now)?,
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if tombstoned {
            return Err(LabError::MessageGone);
        }

        let existing = transaction
            .query_row(
                "SELECT ciphertext, expires_at FROM messages
                 WHERE queue_id = ?1 AND message_id = ?2",
                params![
                    request.queue_id.as_bytes().as_slice(),
                    request.message_id.as_bytes().as_slice(),
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        if let Some((ciphertext, expires_at)) = existing {
            if ciphertext == request.packet.as_bytes() && expires_at == to_i64(request.expires_at)?
            {
                transaction.commit()?;
                self.audit_events.push("message_enqueue_duplicate");
                return Ok(EnqueueOutcome::Duplicate);
            }
            return Err(LabError::MessageConflict);
        }

        transaction.execute(
            "INSERT INTO messages(queue_id, message_id, ciphertext, expires_at, sender_signature)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request.queue_id.as_bytes().as_slice(),
                request.message_id.as_bytes().as_slice(),
                request.packet.as_bytes(),
                to_i64(request.expires_at)?,
                request.signature.to_bytes().as_slice(),
            ],
        )?;
        transaction.commit()?;
        self.audit_events.push("message_enqueued");
        Ok(EnqueueOutcome::Stored)
    }

    /// Fetch queued envelopes without deleting them.
    ///
    /// # Errors
    ///
    /// Returns an error for expired/replayed/unauthorized requests, unknown
    /// mailbox, malformed stored data, or storage failure.
    pub fn fetch(&mut self, request: &FetchRequest, now: u64) -> Result<Vec<StoredEnvelope>> {
        validate_request_time(request.valid_until, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge_expired_in(&transaction, now)?;
        let receive_key = mailbox_key(&transaction, request.queue_id, "receive_key")?;
        receive_key
            .verify(&request.signing_bytes(), &request.signature)
            .map_err(|_| LabError::Unauthorized)?;

        record_nonce(
            &transaction,
            request.queue_id,
            "receive",
            request.nonce,
            request.valid_until,
        )?;

        let envelopes = {
            let mut statement = transaction.prepare(
                "SELECT message_id, ciphertext, expires_at, sender_signature FROM messages
                 WHERE queue_id = ?1 AND expires_at > ?2 ORDER BY rowid ASC",
            )?;
            let rows = statement.query_map(
                params![request.queue_id.as_bytes().as_slice(), to_i64(now)?],
                |row| {
                    let raw_message_id = row.get::<_, Vec<u8>>(0)?;
                    let message_id = MessageId::from_slice(&raw_message_id)
                        .ok_or_else(|| rusqlite::Error::InvalidQuery)?;
                    let ciphertext = row.get::<_, Vec<u8>>(1)?;
                    let expires_at = row.get::<_, i64>(2)?;
                    let expires_at =
                        u64::try_from(expires_at).map_err(|_| rusqlite::Error::InvalidQuery)?;
                    let signature = row.get::<_, Vec<u8>>(3)?;
                    let sender_signature = Ed25519Signature::from_slice(&signature)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok(StoredEnvelope {
                        queue_id: request.queue_id,
                        message_id,
                        packet: EncryptedPacket::from_untrusted(ciphertext),
                        expires_at,
                        sender_signature,
                    })
                },
            )?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        transaction.commit()?;
        self.audit_events.push("mailbox_fetched");
        Ok(envelopes)
    }

    /// Verify a recipient-bound ACK and atomically delete its ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid authorization/time, unknown or mismatched
    /// ciphertext, unknown mailbox/message, or storage failure.
    pub fn acknowledge(&mut self, request: &AckRequest, now: u64) -> Result<AckOutcome> {
        validate_request_time(request.valid_until, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge_expired_in(&transaction, now)?;
        let receive_key = mailbox_key(&transaction, request.queue_id, "receive_key")?;
        receive_key
            .verify(&request.signing_bytes(), &request.signature)
            .map_err(|_| LabError::Unauthorized)?;

        let existing = transaction
            .query_row(
                "SELECT ciphertext FROM messages WHERE queue_id = ?1 AND message_id = ?2",
                params![
                    request.queue_id.as_bytes().as_slice(),
                    request.message_id.as_bytes().as_slice(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;

        let Some(ciphertext) = existing else {
            let already_deleted = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM tombstones WHERE queue_id = ?1 AND message_id = ?2
                )",
                params![
                    request.queue_id.as_bytes().as_slice(),
                    request.message_id.as_bytes().as_slice(),
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if already_deleted {
                transaction.commit()?;
                self.audit_events.push("message_ack_duplicate");
                return Ok(AckOutcome::AlreadyDeleted);
            }
            return Err(LabError::MessageNotFound);
        };

        if digest(&ciphertext) != request.packet_hash {
            return Err(LabError::Unauthorized);
        }
        transaction.execute(
            "DELETE FROM messages WHERE queue_id = ?1 AND message_id = ?2",
            params![
                request.queue_id.as_bytes().as_slice(),
                request.message_id.as_bytes().as_slice(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO tombstones(queue_id, message_id, delete_after)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(queue_id, message_id) DO UPDATE SET delete_after = excluded.delete_after",
            params![
                request.queue_id.as_bytes().as_slice(),
                request.message_id.as_bytes().as_slice(),
                to_i64(now.saturating_add(TOMBSTONE_TTL_SECONDS))?,
            ],
        )?;
        transaction.commit()?;
        self.audit_events.push("message_acknowledged_and_deleted");
        Ok(AckOutcome::Deleted)
    }

    /// Delete a mailbox and its associated opaque state using its management capability.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/replayed authorization, unknown mailbox, or
    /// storage failure.
    pub fn delete_mailbox(&mut self, request: &DeleteMailboxRequest, now: u64) -> Result<bool> {
        validate_request_time(request.valid_until, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge_expired_in(&transaction, now)?;
        let manage_key = mailbox_key(&transaction, request.queue_id, "manage_key")?;
        manage_key
            .verify(&request.signing_bytes(), &request.signature)
            .map_err(|_| LabError::Unauthorized)?;

        record_nonce(
            &transaction,
            request.queue_id,
            "manage",
            request.nonce,
            request.valid_until,
        )?;
        let queue_hash = digest(request.queue_id.as_bytes());
        transaction.execute(
            "INSERT OR IGNORE INTO retired_queues(queue_hash, retired_at) VALUES (?1, ?2)",
            params![queue_hash.as_slice(), to_i64(now)?],
        )?;
        let deleted = transaction.execute(
            "DELETE FROM mailboxes WHERE queue_id = ?1",
            params![request.queue_id.as_bytes().as_slice()],
        )?;
        transaction.commit()?;
        self.audit_events.push("mailbox_deleted");
        Ok(deleted == 1)
    }

    /// Delete expired ciphertext, tombstones, and request nonces.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if the `SQLite` operation fails or `now`
    /// cannot be represented by the schema.
    pub fn purge_expired(&mut self, now: u64) -> Result<usize> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deleted = purge_expired_in(&transaction, now)?;
        transaction.commit()?;
        if deleted > 0 {
            self.audit_events.push("expired_messages_deleted");
        }
        Ok(deleted)
    }

    /// Count currently queued ciphertext rows.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if the query or integer conversion fails.
    pub fn queued_message_count(&mut self) -> Result<usize> {
        self.queued_message_count_at(unix_now()?)
    }

    /// Count queued ciphertext after a global expiry sweep at an explicit time.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if the sweep, query, or integer conversion fails.
    pub fn queued_message_count_at(&mut self, now: u64) -> Result<usize> {
        self.purge_expired(now)?;
        let count = self
            .connection
            .query_row("SELECT COUNT(*) FROM messages", [], |row| {
                row.get::<_, i64>(0)
            })?;
        usize::try_from(count).map_err(|_| LabError::Storage)
    }

    /// Count bounded opaque replay tombstones.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if the query or integer conversion fails.
    pub fn tombstone_count(&self) -> Result<usize> {
        let count = self
            .connection
            .query_row("SELECT COUNT(*) FROM tombstones", [], |row| {
                row.get::<_, i64>(0)
            })?;
        usize::try_from(count).map_err(|_| LabError::Storage)
    }

    #[must_use]
    pub fn audit_events(&self) -> &[&'static str] {
        &self.audit_events
    }
}

fn migrate_schema(connection: &Connection) -> Result<()> {
    validate_schema_for_open(connection)?;

    let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    let current = schema_manifest(connection)?;
    let expected_empty = SchemaManifest::default();
    let expected_legacy = reference_manifest(LEGACY_SCHEMA_DDL)?;
    let expected_current = reference_manifest(CURRENT_SCHEMA_DDL)?;

    match (
        version,
        classify_schema(
            &current,
            &expected_empty,
            &expected_legacy,
            &expected_current,
        ),
    ) {
        (CURRENT_SCHEMA_VERSION, SchemaKind::Current) => Ok(()),
        (0 | 1, SchemaKind::Empty) => {
            create_current_schema(connection)?;
            connection.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
            validate_current_schema(connection, &expected_current)
        }
        (0 | 1, SchemaKind::Legacy) => {
            // Legacy envelopes cannot satisfy the sender-authentication invariant.
            // secure_delete is enabled before this transaction begins.
            connection.execute("DELETE FROM messages", [])?;
            connection.execute_batch("DROP TABLE messages;")?;
            connection.execute_batch(CURRENT_MESSAGES_DDL)?;
            connection.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
            validate_current_schema(connection, &expected_current)
        }
        _ => Err(LabError::Storage),
    }
}

fn validate_schema_for_open(connection: &Connection) -> Result<()> {
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    if !(0..=CURRENT_SCHEMA_VERSION).contains(&version) {
        return Err(LabError::Storage);
    }

    let current = schema_manifest(connection)?;
    let expected_empty = SchemaManifest::default();
    let expected_legacy = reference_manifest(LEGACY_SCHEMA_DDL)?;
    let expected_current = reference_manifest(CURRENT_SCHEMA_DDL)?;

    match (
        version,
        classify_schema(
            &current,
            &expected_empty,
            &expected_legacy,
            &expected_current,
        ),
    ) {
        (CURRENT_SCHEMA_VERSION, SchemaKind::Current)
        | (0 | 1, SchemaKind::Empty | SchemaKind::Legacy) => {
            validate_database_integrity(connection)
        }
        _ => Err(LabError::Storage),
    }
}

/// Inspect an existing main database without allowing `SQLite` to replay or
/// create journals when no recovery companion is present. If a non-empty
/// rollback journal or WAL exists, the later normal open must recover it before
/// the authoritative schema validation can inspect a coherent database image.
///
/// Two properties hold, each pinned by a test. Do not add a third without one:
///
/// - Acceptance: `validate_schema_for_open` runs on whatever image the normal
///   open produces, ahead of any migration, purge, or application write, so an
///   image the relay would not otherwise accept is rejected.
/// - Refusal on an anomalous WAL is byte-preserving: `reject_anomalous_wal`
///   runs before anything opens the database normally, so a planted `-wal`
///   leaves the database untouched and removing it restores service.
///
/// Beyond those, recovery *does* write, and the writes are recorded here as
/// observed behavior rather than as limits:
///
/// - Recovery materializes whatever a companion records, which is not this
///   database's own history. Rollback journals are matched by header and page
///   checksums with no binding to the adjacent database, so a genuine journal
///   lifted from an unrelated database is replayed: measured rewriting a
///   57344-byte victim to 2711552 bytes holding the source's pages. No
///   equivalent guard exists for rollback journals, which unlike a `-wal`
///   beside a rollback-mode header cannot be distinguished from legitimate
///   crash recovery by inspection.
/// - A rejected open on the bypass path is not byte-preserving. Hot-journal
///   replay writes recovered pages into the main database, and closing a
///   WAL-mode database checkpoints it and removes both companions. Discarding
///   a stray non-hot journal is the exception: it consumes the companion but
///   leaves the main database byte-identical.
fn preflight_existing_database(path: &Path) -> Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(LabError::Storage),
    };
    if !metadata.is_file() {
        return Err(LabError::Storage);
    }
    if metadata.len() == 0 {
        return reject_anomalous_wal(path);
    }
    reject_anomalous_wal(path)?;
    if has_nonempty_recovery_companion(path)? {
        return Ok(());
    }

    let connection = Connection::open_with_flags(
        immutable_uri(path)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    validate_schema_for_open(&connection)
}

/// Decides whether an exact-suffix companion is close enough to recoverable
/// state to warrant skipping the immutable preflight. The two arms are
/// deliberately asymmetric, and neither one determines whether `SQLite` would
/// actually replay the companion:
///
/// - `-journal`: any non-empty rollback journal counts, hot or not. Deciding
///   hotness means parsing the journal header and comparing it against the main
///   database, which is `SQLite`'s job, not this function's. Counting a stray
///   journal costs only a discarded file, whereas missing a genuine hot journal
///   would reject a database that was fully recoverable, so this arm is
///   deliberately permissive. `stray_journal_is_discarded_but_target_database_
///   is_never_mutated` pins that a non-hot journal really does take this path.
/// - `-wal`: gated additionally on the main database header being in WAL mode,
///   so a WAL beside a rollback-mode database does not route through the
///   bypass. That combination no longer reaches this function at all:
///   `reject_anomalous_wal` fails the open before the caller gets here, so this
///   arm sees only WAL-mode headers and the `false` branch is unreachable in
///   practice. It is not itself a defense — `SQLite` opens a `-wal` on file
///   existence alone, so if the earlier refusal were removed, the normal open
///   would replay a planted WAL regardless of what this arm reported.
///
/// Deciding either arm differently changes no outcome the relay accepts:
/// `validate_schema_for_open` still runs authoritatively on whatever image the
/// normal open produces. It does not follow that the on-disk bytes are
/// preserved; see `preflight_existing_database`.
///
/// Companion names are derived from the fully resolved path because `SQLite`
/// names its journal after the link target, not the link. Deriving them from an
/// unresolved symlink would miss a genuine hot journal and reject a recoverable
/// database.
fn has_nonempty_recovery_companion(path: &Path) -> Result<bool> {
    let resolved = fs::canonicalize(path).map_err(|_| LabError::Storage)?;
    if nonempty_companion(&resolved, "-journal")? {
        return Ok(true);
    }
    if nonempty_companion(&resolved, "-wal")? && database_header_uses_wal(&resolved)? {
        return Ok(true);
    }
    Ok(false)
}

fn immutable_uri(path: &Path) -> Result<String> {
    let path = path.to_str().ok_or(LabError::Storage)?;
    let mut uri = String::from("file:");
    for byte in path.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'-' | b'_' | b':') {
            uri.push(char::from(*byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            uri.push('%');
            uri.push(char::from(HEX[usize::from(*byte >> 4)]));
            uri.push(char::from(HEX[usize::from(*byte & 0x0f)]));
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Ok(uri)
}

fn create_current_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(CURRENT_SCHEMA_DDL)?;
    Ok(())
}

const CURRENT_SCHEMA_DDL: &str = "
        CREATE TABLE mailboxes (
            queue_id BLOB PRIMARY KEY NOT NULL CHECK(length(queue_id) = 32),
            send_key BLOB NOT NULL CHECK(length(send_key) = 32),
            receive_key BLOB NOT NULL CHECK(length(receive_key) = 32),
            manage_key BLOB NOT NULL CHECK(length(manage_key) = 32),
            created_at INTEGER NOT NULL
        ) STRICT;

        CREATE TABLE messages (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK(length(message_id) = 16),
            ciphertext BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            sender_signature BLOB NOT NULL CHECK(length(sender_signature) = 64),
            PRIMARY KEY (queue_id, message_id),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE tombstones (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK(length(message_id) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, message_id),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE request_nonces (
            queue_id BLOB NOT NULL,
            role TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK(length(nonce) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, role, nonce),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE registration_nonces (
            queue_id BLOB NOT NULL CHECK(length(queue_id) = 32),
            nonce BLOB NOT NULL CHECK(length(nonce) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, nonce)
        ) STRICT;

        CREATE TABLE retired_queues (
            queue_hash BLOB PRIMARY KEY NOT NULL CHECK(length(queue_hash) = 32),
            retired_at INTEGER NOT NULL
        ) STRICT;
        ";

const CURRENT_MESSAGES_DDL: &str = "
        CREATE TABLE messages (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK(length(message_id) = 16),
            ciphertext BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            sender_signature BLOB NOT NULL CHECK(length(sender_signature) = 64),
            PRIMARY KEY (queue_id, message_id),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;
        ";

const LEGACY_SCHEMA_DDL: &str = "
        CREATE TABLE mailboxes (
            queue_id BLOB PRIMARY KEY NOT NULL CHECK(length(queue_id) = 32),
            send_key BLOB NOT NULL CHECK(length(send_key) = 32),
            receive_key BLOB NOT NULL CHECK(length(receive_key) = 32),
            manage_key BLOB NOT NULL CHECK(length(manage_key) = 32),
            created_at INTEGER NOT NULL
        ) STRICT;

        CREATE TABLE messages (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK(length(message_id) = 16),
            ciphertext BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (queue_id, message_id),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE tombstones (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK(length(message_id) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, message_id),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE request_nonces (
            queue_id BLOB NOT NULL,
            role TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK(length(nonce) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, role, nonce),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE registration_nonces (
            queue_id BLOB NOT NULL CHECK(length(queue_id) = 32),
            nonce BLOB NOT NULL CHECK(length(nonce) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, nonce)
        ) STRICT;

        CREATE TABLE retired_queues (
            queue_hash BLOB PRIMARY KEY NOT NULL CHECK(length(queue_hash) = 32),
            retired_at INTEGER NOT NULL
        ) STRICT;
        ";

#[derive(Debug, Default, PartialEq, Eq)]
struct SchemaManifest {
    objects: Vec<SchemaObject>,
    tables: BTreeMap<String, TableShape>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SchemaObject(String, String, String, Option<String>);

type TableColumn = (i64, String, String, i64, Option<String>, i64, i64);
type ForeignKey = (i64, i64, String, String, String, String, String, String);

#[derive(Debug, PartialEq, Eq)]
struct TableShape {
    table_list: (String, String, String, i64, i64, i64),
    columns: Vec<TableColumn>,
    indexes: Vec<IndexShape>,
    foreign_keys: Vec<ForeignKey>,
}

#[derive(Debug, PartialEq, Eq)]
struct IndexShape {
    list: (i64, String, i64, String, i64),
    columns: Vec<(i64, i64, Option<String>, i64, String, i64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchemaKind {
    Empty,
    Legacy,
    Current,
    Unknown,
}

fn reference_manifest(ddl: &str) -> Result<SchemaManifest> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")?;
    connection.execute_batch(ddl)?;
    schema_manifest(&connection)
}

fn classify_schema(
    actual: &SchemaManifest,
    empty: &SchemaManifest,
    legacy: &SchemaManifest,
    current: &SchemaManifest,
) -> SchemaKind {
    if actual == empty {
        SchemaKind::Empty
    } else if actual == legacy {
        SchemaKind::Legacy
    } else if actual == current {
        SchemaKind::Current
    } else {
        SchemaKind::Unknown
    }
}

fn validate_current_schema(connection: &Connection, expected: &SchemaManifest) -> Result<()> {
    if schema_manifest(connection)? != *expected {
        return Err(LabError::Storage);
    }
    validate_database_integrity(connection)
}

fn validate_database_integrity(connection: &Connection) -> Result<()> {
    let foreign_key_problem = connection
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?;
    if foreign_key_problem.is_some() {
        return Err(LabError::Storage);
    }
    let integrity = connection
        .prepare("PRAGMA integrity_check")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if integrity.as_slice() != ["ok"] {
        return Err(LabError::Storage);
    }
    Ok(())
}

fn schema_manifest(connection: &Connection) -> Result<SchemaManifest> {
    let mut objects = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")?
        .query_map([], |row| {
            Ok(SchemaObject(
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    objects.sort();

    let table_names = objects
        .iter()
        .filter(|object| object.0 == "table")
        .map(|object| object.1.clone())
        .collect::<Vec<_>>();
    let mut tables = BTreeMap::new();
    for table in table_names {
        tables.insert(table.clone(), table_shape(connection, &table)?);
    }
    Ok(SchemaManifest { objects, tables })
}

fn table_shape(connection: &Connection, table: &str) -> Result<TableShape> {
    let table_list = connection.query_row(
        "SELECT schema, name, type, ncol, wr, strict FROM pragma_table_list WHERE schema = 'main' AND name = ?1",
        params![table],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    )?;
    let columns = connection
        .prepare("SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden FROM pragma_table_xinfo(?1) ORDER BY cid")?
        .query_map(params![table], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let index_rows = connection
        .prepare(
            "SELECT seq, name, \"unique\", origin, partial FROM pragma_index_list(?1) ORDER BY seq",
        )?
        .query_map(params![table], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<(i64, String, i64, String, i64)>, _>>()?;
    let mut indexes = Vec::with_capacity(index_rows.len());
    for list in index_rows {
        let columns = connection
            .prepare("SELECT seqno, cid, name, \"desc\", coll, key FROM pragma_index_xinfo(?1) ORDER BY seqno")?
            .query_map(params![list.1], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        indexes.push(IndexShape { list, columns });
    }
    let foreign_keys = connection
        .prepare("SELECT id, seq, \"table\", \"from\", \"to\", on_update, on_delete, \"match\" FROM pragma_foreign_key_list(?1) ORDER BY id, seq")?
        .query_map(params![table], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(TableShape {
        table_list,
        columns,
        indexes,
        foreign_keys,
    })
}

fn mailbox_key(
    connection: &Connection,
    queue_id: QueueId,
    column: &str,
) -> Result<Ed25519PublicKey> {
    let query = match column {
        "send_key" => "SELECT send_key FROM mailboxes WHERE queue_id = ?1",
        "receive_key" => "SELECT receive_key FROM mailboxes WHERE queue_id = ?1",
        "manage_key" => "SELECT manage_key FROM mailboxes WHERE queue_id = ?1",
        _ => return Err(LabError::Storage),
    };
    let bytes = connection
        .query_row(query, params![queue_id.as_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .optional()?
        .ok_or(LabError::MailboxNotFound)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| LabError::Storage)?;
    Ed25519PublicKey::from_slice(&bytes).map_err(|_| LabError::Storage)
}

fn purge_expired_in(connection: &Connection, now: u64) -> Result<usize> {
    let now = to_i64(now)?;
    let deleted =
        connection.execute("DELETE FROM messages WHERE expires_at <= ?1", params![now])?;
    connection.execute(
        "DELETE FROM tombstones WHERE delete_after <= ?1",
        params![now],
    )?;
    connection.execute(
        "DELETE FROM request_nonces WHERE delete_after <= ?1",
        params![now],
    )?;
    connection.execute(
        "DELETE FROM registration_nonces WHERE delete_after <= ?1",
        params![now],
    )?;
    Ok(deleted)
}

fn record_nonce(
    connection: &Connection,
    queue_id: QueueId,
    role: &str,
    nonce: Nonce,
    delete_after: u64,
) -> Result<()> {
    let inserted = connection.execute(
        "INSERT OR IGNORE INTO request_nonces(queue_id, role, nonce, delete_after)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            queue_id.as_bytes().as_slice(),
            role,
            nonce.as_bytes().as_slice(),
            to_i64(delete_after)?,
        ],
    )?;
    if inserted != 1 {
        return Err(LabError::Unauthorized);
    }
    Ok(())
}

fn validate_request_time(valid_until: u64, now: u64) -> Result<()> {
    if valid_until <= now || valid_until > now.saturating_add(5 * 60) {
        return Err(LabError::RequestExpired);
    }
    Ok(())
}

fn validate_message_expiry(expires_at: u64, now: u64) -> Result<()> {
    if expires_at <= now || expires_at > now.saturating_add(MAX_MESSAGE_TTL_SECONDS) {
        return Err(LabError::InvalidExpiry);
    }
    Ok(())
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| LabError::Storage)
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| LabError::Storage)
}
