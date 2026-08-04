use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

use crate::capability::{
    AckRequest, DeleteMailboxRequest, FetchRequest, MailboxRegistration, SendRequest, digest,
};
use crate::{EncryptedPacket, LabError, MessageId, Nonce, QueueId, Result};

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
pub struct Relay {
    connection: Connection,
    audit_events: Vec<&'static str>,
}

impl Relay {
    /// Open or create a file-backed relay database.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if `SQLite` cannot open or initialize the database.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_at(path, unix_now()?)
    }

    /// Open a file-backed relay and run its global expiry sweep using an
    /// explicit clock value. This keeps restart behavior testable.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if `SQLite` cannot open, initialize, or
    /// sweep the database.
    pub fn open_at(path: &Path, now: u64) -> Result<Self> {
        let connection = Connection::open(path)?;
        Self::initialize(connection, now)
    }

    /// Open an ephemeral in-memory relay database.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Storage`] if `SQLite` cannot initialize the schema.
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        Self::initialize(connection, unix_now()?)
    }

    fn initialize(mut connection: Connection, now: u64) -> Result<Self> {
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.execute_batch(
            "
            PRAGMA secure_delete = ON;
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            PRAGMA auto_vacuum = FULL;
            ",
        )?;

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        migrate_schema(&transaction)?;
        purge_expired_in(&transaction, now)?;
        transaction.commit()?;
        Ok(Self {
            connection,
            audit_events: Vec::new(),
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
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    if !(0..=CURRENT_SCHEMA_VERSION).contains(&version) {
        return Err(LabError::Storage);
    }

    let messages_exist = table_exists(connection, "messages")?;
    let has_sender_signature = !messages_exist || table_has_column(connection, "sender_signature")?;
    if version == CURRENT_SCHEMA_VERSION && !has_sender_signature {
        return Err(LabError::Storage);
    }

    if messages_exist && !has_sender_signature {
        // Legacy envelopes cannot satisfy the sender-authentication invariant.
        // secure_delete is enabled before this transaction begins.
        connection.execute("DELETE FROM messages", [])?;
        connection.execute_batch("DROP TABLE messages;")?;
    }

    create_current_schema(connection)?;
    connection.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    Ok(())
}

fn create_current_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS mailboxes (
            queue_id BLOB PRIMARY KEY NOT NULL CHECK(length(queue_id) = 32),
            send_key BLOB NOT NULL CHECK(length(send_key) = 32),
            receive_key BLOB NOT NULL CHECK(length(receive_key) = 32),
            manage_key BLOB NOT NULL CHECK(length(manage_key) = 32),
            created_at INTEGER NOT NULL
        ) STRICT;

        CREATE TABLE IF NOT EXISTS messages (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK(length(message_id) = 16),
            ciphertext BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            sender_signature BLOB NOT NULL CHECK(length(sender_signature) = 64),
            PRIMARY KEY (queue_id, message_id),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE IF NOT EXISTS tombstones (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK(length(message_id) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, message_id),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE IF NOT EXISTS request_nonces (
            queue_id BLOB NOT NULL,
            role TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK(length(nonce) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, role, nonce),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;

        CREATE TABLE IF NOT EXISTS registration_nonces (
            queue_id BLOB NOT NULL CHECK(length(queue_id) = 32),
            nonce BLOB NOT NULL CHECK(length(nonce) = 16),
            delete_after INTEGER NOT NULL,
            PRIMARY KEY (queue_id, nonce)
        ) STRICT;

        CREATE TABLE IF NOT EXISTS retired_queues (
            queue_hash BLOB PRIMARY KEY NOT NULL CHECK(length(queue_hash) = 32),
            retired_at INTEGER NOT NULL
        ) STRICT;
        ",
    )?;
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn table_has_column(connection: &Connection, column: &str) -> Result<bool> {
    let mut statement = connection.prepare("PRAGMA table_info(messages)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(columns.iter().any(|existing| existing == column))
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
    if valid_until < now || valid_until > now.saturating_add(5 * 60) {
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
