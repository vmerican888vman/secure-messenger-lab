use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

use rusqlite::{Connection, OpenFlags, params};
use secure_messenger_lab::Relay;

const NOW: u64 = 1_800_000_000;
const HOT_JOURNAL_CHILD_PATH: &str = "SECURE_MESSENGER_HOT_JOURNAL_CHILD_PATH";
const HOT_JOURNAL_CHILD_OPERATION: &str = "SECURE_MESSENGER_HOT_JOURNAL_CHILD_OPERATION";
const LARGE_MESSAGE_COUNT: usize = 64;
const LARGE_CIPHERTEXT_BYTES: usize = 40 * 1024;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn hot_rollback_journal_child() -> Result<(), Box<dyn Error>> {
    let Ok(path) = env::var(HOT_JOURNAL_CHILD_PATH) else {
        return Ok(());
    };
    let operation =
        env::var(HOT_JOURNAL_CHILD_OPERATION).unwrap_or_else(|_| String::from("mailbox-update"));

    let connection = Connection::open(path)?;
    connection.execute_batch(
        "
        PRAGMA journal_mode = DELETE;
        PRAGMA synchronous = FULL;
        PRAGMA cache_size = 1;
        PRAGMA cache_spill = ON;
        BEGIN IMMEDIATE;
        ",
    )?;
    match operation.as_str() {
        "mailbox-update" => {
            let changed = connection.execute(
                "UPDATE mailboxes SET created_at = created_at + 1 WHERE queue_id = ?1",
                params![vec![0x11_u8; 32]],
            )?;
            if changed != 1 {
                return Err(std::io::Error::other(
                    "hot-journal child did not update its benign row",
                )
                .into());
            }
        }
        "bulk-delete" => {
            let changed = connection.execute(
                "DELETE FROM messages WHERE expires_at <= ?1",
                params![i64::try_from(NOW + 60)?],
            )?;
            if changed != LARGE_MESSAGE_COUNT {
                return Err(std::io::Error::other(
                    "hot-journal child did not delete every seeded message",
                )
                .into());
            }
        }
        "legacy-migration" => {
            let changed = connection.execute("DELETE FROM messages", [])?;
            if changed != LARGE_MESSAGE_COUNT {
                return Err(std::io::Error::other(
                    "hot-journal child did not delete every legacy message",
                )
                .into());
            }
            connection.execute_batch(
                "
                DROP TABLE messages;
                CREATE TABLE messages (
                    queue_id BLOB NOT NULL,
                    message_id BLOB NOT NULL CHECK(length(message_id) = 16),
                    ciphertext BLOB NOT NULL,
                    expires_at INTEGER NOT NULL,
                    sender_signature BLOB NOT NULL CHECK(length(sender_signature) = 64),
                    PRIMARY KEY (queue_id, message_id),
                    FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
                ) STRICT;
                PRAGMA user_version = 2;
                ",
            )?;
        }
        "wal-crash" => {
            // Leave a genuine crashed WAL: committed content, no clean close.
            connection.execute_batch(
                "COMMIT;
                 PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;
                 BEGIN IMMEDIATE;",
            )?;
            let changed = connection.execute("DELETE FROM messages WHERE expires_at > 0", [])?;
            if changed != LARGE_MESSAGE_COUNT {
                return Err(std::io::Error::other(
                    "wal-crash child did not delete every seeded message",
                )
                .into());
            }
            connection.execute_batch("COMMIT;")?;
        }
        _ => return Err(std::io::Error::other("unknown hot-journal child operation").into()),
    }

    // Intentionally leave SQLite's real rollback journal hot. This test only
    // invokes the helper through the parent subprocess below.
    std::process::abort();
}

fn message_id(index: usize) -> Result<[u8; 16], Box<dyn Error>> {
    let mut message_id = [0_u8; 16];
    message_id[..8].copy_from_slice(b"msg-id-v");
    message_id[8..].copy_from_slice(&u64::try_from(index)?.to_be_bytes());
    Ok(message_id)
}

fn seed_current_large_messages(database: &Path) -> Result<(), Box<dyn Error>> {
    drop(Relay::open_at(database, NOW)?);
    let mut connection = Connection::open(database)?;
    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT INTO mailboxes(queue_id, send_key, receive_key, manage_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            vec![0x11_u8; 32],
            vec![0x22_u8; 32],
            vec![0x33_u8; 32],
            vec![0x44_u8; 32],
            i64::try_from(NOW)?,
        ],
    )?;
    let ciphertext = vec![0xA5_u8; LARGE_CIPHERTEXT_BYTES];
    for index in 0..LARGE_MESSAGE_COUNT {
        transaction.execute(
            "INSERT INTO messages(queue_id, message_id, ciphertext, expires_at, sender_signature)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                vec![0x11_u8; 32],
                message_id(index)?.as_slice(),
                &ciphertext,
                i64::try_from(NOW + 60)?,
                vec![0x66_u8; 64],
            ],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn seed_legacy_large_messages(database: &Path) -> Result<(), Box<dyn Error>> {
    let queue_id = vec![0x11_u8; 32];
    let first_message_id = message_id(0)?;
    let tombstone_message_id = vec![0x33_u8; 16];
    let ciphertext = vec![0xB6_u8; LARGE_CIPHERTEXT_BYTES];
    create_legacy_database(
        database,
        &queue_id,
        &first_message_id,
        &tombstone_message_id,
        &ciphertext,
    )?;
    let mut connection = Connection::open(database)?;
    let transaction = connection.transaction()?;
    for index in 1..LARGE_MESSAGE_COUNT {
        transaction.execute(
            "INSERT INTO messages(queue_id, message_id, ciphertext, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                &queue_id,
                message_id(index)?.as_slice(),
                &ciphertext,
                i64::try_from(NOW + 60)?,
            ],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn run_hot_journal_child(database: &Path, operation: &str) -> Result<(), Box<dyn Error>> {
    let status = Command::new(env::current_exe()?)
        .arg("--exact")
        .arg("hot_rollback_journal_child")
        .arg("--nocapture")
        .env(HOT_JOURNAL_CHILD_PATH, database)
        .env(HOT_JOURNAL_CHILD_OPERATION, operation)
        .status()?;
    assert!(!status.success());
    Ok(())
}

fn immutable_integrity_is_ok(database: &Path) -> Result<bool, Box<dyn Error>> {
    let uri = format!("file:{}?mode=ro&immutable=1", database.display());
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    let Ok(mut statement) = connection.prepare("PRAGMA integrity_check") else {
        return Ok(false);
    };
    let Ok(integrity) = statement
        .query_map([], |row| row.get::<_, String>(0))
        .and_then(Iterator::collect::<std::result::Result<Vec<_>, _>>)
    else {
        return Ok(false);
    };
    Ok(integrity.as_slice() == ["ok"])
}

fn create_legacy_database(
    database: &Path,
    queue_id: &[u8],
    legacy_message_id: &[u8],
    tombstone_message_id: &[u8],
    legacy_ciphertext: &[u8],
) -> Result<(), Box<dyn Error>> {
    let connection = Connection::open(database)?;
    connection.execute_batch(
        "
        PRAGMA foreign_keys = ON;

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
        ",
    )?;
    connection.execute(
        "INSERT INTO mailboxes(queue_id, send_key, receive_key, manage_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            queue_id,
            vec![0x44_u8; 32],
            vec![0x55_u8; 32],
            vec![0x66_u8; 32],
            i64::try_from(NOW)?,
        ],
    )?;
    connection.execute(
        "INSERT INTO messages(queue_id, message_id, ciphertext, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            queue_id,
            legacy_message_id,
            legacy_ciphertext,
            i64::try_from(NOW + 60)?,
        ],
    )?;
    connection.execute(
        "INSERT INTO tombstones(queue_id, message_id, delete_after) VALUES (?1, ?2, ?3)",
        params![queue_id, tombstone_message_id, i64::try_from(NOW + 60)?,],
    )?;
    connection.execute(
        "INSERT INTO retired_queues(queue_hash, retired_at) VALUES (?1, ?2)",
        params![vec![0x77_u8; 32], i64::try_from(NOW)?],
    )?;
    Ok(())
}

fn create_current_database_with_messages(
    database: &Path,
    messages: &str,
) -> Result<Connection, Box<dyn Error>> {
    let connection = Connection::open(database)?;
    connection.execute_batch(&format!(
        "
        PRAGMA foreign_keys = ON;
        CREATE TABLE mailboxes (
            queue_id BLOB PRIMARY KEY NOT NULL CHECK(length(queue_id) = 32),
            send_key BLOB NOT NULL CHECK(length(send_key) = 32),
            receive_key BLOB NOT NULL CHECK(length(receive_key) = 32),
            manage_key BLOB NOT NULL CHECK(length(manage_key) = 32),
            created_at INTEGER NOT NULL
        ) STRICT;
        {messages}
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
        "
    ))?;
    connection.pragma_update(None, "user_version", 2_i64)?;
    Ok(connection)
}

#[test]
fn upgrade_discards_unverifiable_legacy_messages_and_preserves_relay_state()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("relay.sqlite");
    let queue_id = vec![0x11_u8; 32];
    let legacy_message_id = vec![0x22_u8; 16];
    let tombstone_message_id = vec![0x33_u8; 16];
    let legacy_ciphertext = b"legacy-unverifiable-ciphertext".to_vec();

    create_legacy_database(
        &database,
        &queue_id,
        &legacy_message_id,
        &tombstone_message_id,
        &legacy_ciphertext,
    )?;

    let mut relay = Relay::open_at(&database, NOW)?;
    assert_eq!(relay.queued_message_count_at(NOW)?, 0);
    assert_eq!(relay.tombstone_count()?, 1);
    drop(relay);

    let upgraded = Connection::open(&database)?;
    let version = upgraded.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    assert_eq!(version, 2);
    let message_columns = upgraded
        .prepare("PRAGMA table_info(messages)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert!(
        message_columns
            .iter()
            .any(|column| column == "sender_signature")
    );
    let retired = upgraded.query_row("SELECT COUNT(*) FROM retired_queues", [], |row| {
        row.get::<_, i64>(0)
    })?;
    assert_eq!(retired, 1);
    drop(upgraded);
    assert!(!contains(&fs::read(&database)?, &legacy_ciphertext));
    Ok(())
}

#[test]
fn future_schema_version_fails_closed() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("future.sqlite");
    let connection = Connection::open(&database)?;
    connection.pragma_update(None, "user_version", 3_i64)?;
    drop(connection);

    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));
    Ok(())
}

#[test]
fn current_schema_version_without_sender_signatures_fails_closed() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("malformed-current.sqlite");
    let queue_id = vec![0x11_u8; 32];
    let legacy_message_id = vec![0x22_u8; 16];
    let tombstone_message_id = vec![0x33_u8; 16];
    let legacy_ciphertext = b"must-not-migrate-as-current".to_vec();
    create_legacy_database(
        &database,
        &queue_id,
        &legacy_message_id,
        &tombstone_message_id,
        &legacy_ciphertext,
    )?;
    let connection = Connection::open(&database)?;
    connection.pragma_update(None, "user_version", 2_i64)?;
    drop(connection);

    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));
    assert!(contains(&fs::read(&database)?, &legacy_ciphertext));
    Ok(())
}

#[test]
fn current_schema_with_sender_signature_but_missing_constraints_fails_closed()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("shape-broken.sqlite");
    let connection = create_current_database_with_messages(
        &database,
        "
        CREATE TABLE messages (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            sender_signature BLOB NOT NULL,
            PRIMARY KEY (queue_id, message_id)
        );
        ",
    )?;
    connection.execute(
        "INSERT INTO mailboxes(queue_id, send_key, receive_key, manage_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            vec![0x11_u8; 32],
            vec![0x22_u8; 32],
            vec![0x33_u8; 32],
            vec![0x44_u8; 32],
            i64::try_from(NOW)?,
        ],
    )?;
    connection.execute(
        "INSERT INTO messages(queue_id, message_id, ciphertext, expires_at, sender_signature)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            vec![0x11_u8; 32],
            vec![0x55_u8; 16],
            b"poisoned".as_slice(),
            i64::try_from(NOW + 60)?,
            vec![0x66_u8; 1],
        ],
    )?;
    drop(connection);

    let before = fs::read(&database)?;
    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));
    assert_eq!(fs::read(&database)?, before);
    Ok(())
}

#[test]
fn current_schema_rejects_extra_trigger_and_version_shape_disagreement()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("extra-trigger.sqlite");
    drop(Relay::open_at(&database, NOW)?);
    let connection = Connection::open(&database)?;
    connection.execute_batch(
        "CREATE TRIGGER messages_noop AFTER INSERT ON messages BEGIN SELECT 1; END;",
    )?;
    drop(connection);
    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));

    let clean = directory.path().join("current-as-v1.sqlite");
    drop(Relay::open_at(&clean, NOW)?);
    let connection = Connection::open(&clean)?;
    connection.pragma_update(None, "user_version", 1_i64)?;
    drop(connection);
    assert!(matches!(
        Relay::open_at(&clean, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));
    Ok(())
}

#[test]
fn historical_v2_if_not_exists_shape_remains_compatible() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("historical-v2.sqlite");
    let connection = create_current_database_with_messages(
        &database,
        "
        CREATE TABLE IF NOT EXISTS messages (
            queue_id BLOB NOT NULL,
            message_id BLOB NOT NULL CHECK(length(message_id) = 16),
            ciphertext BLOB NOT NULL,
            expires_at INTEGER NOT NULL,
            sender_signature BLOB NOT NULL CHECK(length(sender_signature) = 64),
            PRIMARY KEY (queue_id, message_id),
            FOREIGN KEY (queue_id) REFERENCES mailboxes(queue_id) ON DELETE CASCADE
        ) STRICT;
        ",
    )?;
    drop(connection);

    drop(Relay::open_at(&database, NOW)?);
    Ok(())
}

#[test]
fn valid_hot_rollback_journal_recovers_complete_pretransaction_state() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("valid-hot-journal.sqlite");
    drop(Relay::open_at(&database, NOW)?);
    let connection = Connection::open(&database)?;
    connection.execute(
        "INSERT INTO mailboxes(queue_id, send_key, receive_key, manage_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            vec![0x11_u8; 32],
            vec![0x22_u8; 32],
            vec![0x33_u8; 32],
            vec![0x44_u8; 32],
            i64::try_from(NOW)?,
        ],
    )?;
    drop(connection);

    let status = Command::new(env::current_exe()?)
        .arg("--exact")
        .arg("hot_rollback_journal_child")
        .arg("--nocapture")
        .env(HOT_JOURNAL_CHILD_PATH, &database)
        .status()?;
    assert!(!status.success());

    let journal = directory.path().join("valid-hot-journal.sqlite-journal");
    assert!(journal.is_file());
    assert!(fs::metadata(&journal)?.len() > 0);

    drop(Relay::open_at(&database, NOW)?);
    let recovered = Connection::open(&database)?;
    let created_at = recovered.query_row(
        "SELECT created_at FROM mailboxes WHERE queue_id = ?1",
        params![vec![0x11_u8; 32]],
        |row| row.get::<_, i64>(0),
    )?;
    let version = recovered.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    let messages_sql = recovered.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'messages'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    assert_eq!(created_at, i64::try_from(NOW)?);
    assert_eq!(version, 2);
    assert!(messages_sql.contains("sender_signature"));
    Ok(())
}

#[test]
fn hot_journal_from_aborted_bulk_delete_recovers_all_current_messages() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("bulk-delete.sqlite");
    seed_current_large_messages(&database)?;

    run_hot_journal_child(&database, "bulk-delete")?;

    let journal = directory.path().join("bulk-delete.sqlite-journal");
    assert!(journal.is_file());
    assert!(fs::metadata(&journal)?.len() > 0);
    assert!(!immutable_integrity_is_ok(&database)?);

    drop(Relay::open_at(&database, NOW)?);

    assert!(immutable_integrity_is_ok(&database)?);
    let recovered = Connection::open(&database)?;
    let messages = recovered.query_row("SELECT COUNT(*) FROM messages", [], |row| {
        row.get::<_, i64>(0)
    })?;
    assert_eq!(messages, i64::try_from(LARGE_MESSAGE_COUNT)?);
    drop(recovered);
    assert!(!journal.exists());
    Ok(())
}

#[test]
fn hot_journal_from_aborted_legacy_migration_recovers_then_migrates() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("legacy-migration.sqlite");
    seed_legacy_large_messages(&database)?;

    run_hot_journal_child(&database, "legacy-migration")?;

    let journal = directory.path().join("legacy-migration.sqlite-journal");
    assert!(journal.is_file());
    assert!(fs::metadata(&journal)?.len() > 0);
    assert!(!immutable_integrity_is_ok(&database)?);

    drop(Relay::open_at(&database, NOW)?);

    assert!(immutable_integrity_is_ok(&database)?);
    let recovered = Connection::open(&database)?;
    let version = recovered.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    assert_eq!(version, 2);
    let messages_sql = recovered.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'messages'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    assert!(messages_sql.contains("sender_signature"));
    let counts = recovered.query_row(
        "SELECT (SELECT COUNT(*) FROM messages),
                (SELECT COUNT(*) FROM mailboxes),
                (SELECT COUNT(*) FROM tombstones),
                (SELECT COUNT(*) FROM retired_queues)",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    assert_eq!(counts, (0, 1, 1, 1));
    drop(recovered);
    assert!(!journal.exists());
    Ok(())
}

#[test]
fn symlinked_database_recovers_its_hot_journal_from_the_resolved_path() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let target = directory.path().join("symlink-target.sqlite");
    let link = directory.path().join("symlink-link.sqlite");
    seed_current_large_messages(&target)?;
    std::os::unix::fs::symlink(&target, &link)?;

    // The child opens through the link; SQLite names the journal after the
    // resolved target, which is exactly the case an unresolved suffix append
    // would miss.
    run_hot_journal_child(&link, "bulk-delete")?;

    let target_journal = directory.path().join("symlink-target.sqlite-journal");
    let link_journal = directory.path().join("symlink-link.sqlite-journal");
    assert!(target_journal.is_file());
    assert!(fs::metadata(&target_journal)?.len() > 0);
    assert!(!link_journal.exists());
    assert!(!immutable_integrity_is_ok(&target)?);

    // Opening through the link must still find and recover that journal.
    drop(Relay::open_at(&link, NOW)?);

    assert!(immutable_integrity_is_ok(&target)?);
    let recovered = Connection::open(&target)?;
    let messages = recovered.query_row("SELECT COUNT(*) FROM messages", [], |row| {
        row.get::<_, i64>(0)
    })?;
    assert_eq!(messages, i64::try_from(LARGE_MESSAGE_COUNT)?);
    drop(recovered);
    assert!(!target_journal.exists());
    Ok(())
}

/// Pins the true bypass-path behavior: replaying a genuine hot journal writes
/// recovered pages into the main database BEFORE validation runs, and does so
/// even when validation then rejects the schema. This is accepted rather than
/// fixed, but it must never be silently reduced to "the main database is never
/// mutated". Recovery replays what the companion records; that it is this
/// database's own committed state is a property of this fixture, not a
/// guarantee — see `foreign_journal_is_replayed_into_an_unrelated_database`.
#[test]
fn hot_journal_replay_mutates_main_database_before_validation_rejects() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("replay-then-reject.sqlite");
    seed_current_large_messages(&database)?;
    // Make the schema unacceptable so validation must reject after recovery.
    let connection = Connection::open(&database)?;
    connection.execute_batch("CREATE TABLE extra_hostile(x);")?;
    drop(connection);

    run_hot_journal_child(&database, "bulk-delete")?;
    let journal = directory.path().join("replay-then-reject.sqlite-journal");
    assert!(fs::metadata(&journal)?.len() > 0);

    let before = fs::read(&database)?;
    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));
    let after = fs::read(&database)?;

    // Recovery ran before validation, so the main database is NOT byte-identical.
    assert_ne!(before, after);
    // And recovery restored the committed state rather than inventing one.
    let recovered = Connection::open(&database)?;
    let messages = recovered.query_row("SELECT COUNT(*) FROM messages", [], |row| {
        row.get::<_, i64>(0)
    })?;
    assert_eq!(messages, i64::try_from(LARGE_MESSAGE_COUNT)?);
    Ok(())
}

/// Pins that recovery replays whatever the companion records rather than this
/// database's own history. A rollback journal is matched by header and page
/// checksums, with no binding to the database beside it, so a GENUINE journal
/// lifted from an unrelated database is replayed into the victim. The open is
/// still rejected — acceptance, not the bytes on disk, is what the preflight
/// guarantees. This exists so the doc comment cannot drift back to claiming
/// recovery only ever materializes the last committed state.
#[test]
fn foreign_journal_is_replayed_into_an_unrelated_database() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;

    // Source: 64 large messages, then a genuine hot journal from a real abort.
    let source = directory.path().join("foreign-source.sqlite");
    seed_current_large_messages(&source)?;
    run_hot_journal_child(&source, "bulk-delete")?;
    let source_journal = directory.path().join("foreign-source.sqlite-journal");
    let genuine_journal = fs::read(&source_journal)?;
    assert!(!genuine_journal.is_empty());

    // Victim: an unrelated, freshly created relay that never held these pages.
    let victim = directory.path().join("foreign-victim.sqlite");
    drop(Relay::open_at(&victim, NOW)?);
    let victim_before = fs::read(&victim)?;
    let source_marker = vec![0xA5_u8; 2048];
    assert!(!contains(&victim_before, &source_marker));

    fs::write(
        directory.path().join("foreign-victim.sqlite-journal"),
        &genuine_journal,
    )?;

    // Acceptance is what is guaranteed: the victim is still rejected.
    assert!(matches!(
        Relay::open_at(&victim, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));

    // But its bytes are not preserved: it now holds the source's pages.
    let victim_after = fs::read(&victim)?;
    assert_ne!(victim_after, victim_before);
    assert!(contains(&victim_after, &source_marker));
    Ok(())
}

/// The pass-through arm of `reject_anomalous_wal`: a WAL-mode database with a
/// LIVE `-wal` must still open and recover. Reaching that arm requires both a
/// WAL-mode header and a non-empty `-wal`, so the crash has to be real — a
/// clean close checkpoints and deletes the companion, which short-circuits the
/// guard before the header is ever consulted and silently tests nothing.
/// The assertions on `wal_len` and the header exist to prove the arm is
/// actually reached, not merely assumed.
#[test]
fn wal_mode_database_with_live_wal_opens_and_recovers() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("wal-mode-ok.sqlite");
    seed_current_large_messages(&database)?;

    // Real crash: converts to WAL, commits a delete of every message, aborts
    // before any checkpoint. Schema stays valid, so the open must succeed.
    run_hot_journal_child(&database, "wal-crash")?;

    let wal = directory.path().join("wal-mode-ok.sqlite-wal");
    let header = fs::read(&database)?;
    assert_eq!((header[18], header[19]), (2, 2));
    assert!(fs::metadata(&wal)?.len() > 0);

    // Must open, not be refused by the anomalous-WAL guard.
    drop(Relay::open_at(&database, NOW)?);

    // The committed delete was recovered, not lost, and the relay converted
    // the database back out of WAL mode.
    let recovered = Connection::open(&database)?;
    let messages = recovered.query_row("SELECT COUNT(*) FROM messages", [], |row| {
        row.get::<_, i64>(0)
    })?;
    drop(recovered);
    assert_eq!(messages, 0);
    let after = fs::read(&database)?;
    assert_eq!((after[18], after[19]), (1, 1));
    assert!(!wal.exists());
    Ok(())
}

/// Creating a single file beside a healthy relay — with no write access to the
/// database itself — used to destroy it permanently: `SQLite` opens a `-wal` on
/// existence alone, so the planted file was replayed and checkpointed in before
/// validation could reject it, and every later open failed. Reproduced
/// identically at ea69c07, so it predated the companion gating.
///
/// `reject_anomalous_wal` now fails closed first. This asserts the two things
/// that make the difference: the database is left byte-identical, and removing
/// the planted file restores service.
#[test]
fn planted_wal_is_refused_without_touching_the_database() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;

    // Attacker prepares a WAL elsewhere carrying a schema the relay rejects.
    let attacker = directory.path().join("attacker.sqlite");
    drop(Relay::open_at(&attacker, NOW)?);
    let staging = Connection::open(&attacker)?;
    staging.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA wal_autocheckpoint = 0;
         CREATE TABLE extra_hostile(x);",
    )?;
    let planted = fs::read(directory.path().join("attacker.sqlite-wal"))?;
    // Leaked deliberately: closing would checkpoint and empty the WAL.
    std::mem::forget(staging);
    assert!(!planted.is_empty());

    // Victim: a healthy rollback-mode relay that opens cleanly.
    let victim = directory.path().join("victim.sqlite");
    drop(Relay::open_at(&victim, NOW)?);
    drop(Relay::open_at(&victim, NOW)?);
    let before = fs::read(&victim)?;
    assert_eq!((before[18], before[19]), (1, 1));

    // The whole attack: create one file. The database is never written.
    fs::write(directory.path().join("victim.sqlite-wal"), &planted)?;

    // Refused, repeatedly, without ever opening the database normally.
    for _ in 0..3 {
        assert!(matches!(
            Relay::open_at(&victim, NOW),
            Err(secure_messenger_lab::LabError::Storage)
        ));
    }

    // The database is untouched: same bytes, same rollback-mode header.
    let after = fs::read(&victim)?;
    assert_eq!(after, before);
    assert_eq!((after[18], after[19]), (1, 1));

    // Deliberately NOT opened normally here. Any SQLite client that opens this
    // path while the planted file exists would itself trigger the replay this
    // refusal avoids — the guard covers the relay's own open path, not the
    // filesystem. Checking the schema now would corrupt the victim and pass for
    // the wrong reason.

    // Recoverable: removing the planted file restores service, and the
    // foreign schema never landed.
    fs::remove_file(directory.path().join("victim.sqlite-wal"))?;
    drop(Relay::open_at(&victim, NOW)?);
    let inspector = Connection::open(&victim)?;
    let hostile = inspector.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'extra_hostile'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    drop(inspector);
    assert_eq!(hostile, 0);
    Ok(())
}

/// Exercises the WAL arm of the companion bypass, which no other test reaches,
/// and pins the fact that a rejected open on this path is NOT byte-preserving:
/// closing the connection checkpoints the recovered WAL into the main database
/// and removes both companions. This is accepted rather than fixed, but it must
/// not be described as leaving the database untouched. Recovery materializes
/// what the companion records; that it is this database's own committed state
/// is a property of this fixture, not a guarantee — the WAL case has the same
/// foreign-content exposure as `foreign_journal_is_replayed_into_an_unrelated_
/// database` pins for rollback journals.
#[test]
fn rejected_wal_open_checkpoints_and_removes_both_companions() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("wal-reject.sqlite");
    seed_current_large_messages(&database)?;
    // Make the schema unacceptable so validation must reject after recovery.
    let connection = Connection::open(&database)?;
    connection.execute_batch("CREATE TABLE extra_hostile(x);")?;
    drop(connection);

    run_hot_journal_child(&database, "wal-crash")?;

    let wal = directory.path().join("wal-reject.sqlite-wal");
    let shm = directory.path().join("wal-reject.sqlite-shm");
    assert!(fs::metadata(&wal)?.len() > 0);
    // The main header must actually be in WAL mode, or the bypass arm under
    // test is not the one being exercised.
    let header = fs::read(&database)?;
    assert_eq!(&header[..16], b"SQLite format 3\0");
    assert_eq!((header[18], header[19]), (2, 2));
    let before = fs::read(&database)?;

    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));

    // Rejection on this path rewrites the main database and consumes both
    // companions. Asserted explicitly so it cannot regress into a silent
    // "companions are left byte-identical" claim.
    assert_ne!(fs::read(&database)?, before);
    assert!(!wal.exists());
    assert!(!shm.exists());
    Ok(())
}

/// Documents accepted behavior: on the companion-bypass path `SQLite` may discard
/// a stray non-hot journal even when validation then rejects the database. The
/// main database itself must still be byte-identical.
#[test]
fn stray_journal_is_discarded_but_target_database_is_never_mutated() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("stray-journal.sqlite");
    let connection = create_current_database_with_messages(
        &database,
        "CREATE TABLE messages(queue_id BLOB, sender_signature BLOB);",
    )?;
    drop(connection);
    let companion = directory.path().join("stray-journal.sqlite-journal");
    fs::write(&companion, vec![0xEE_u8; 4096])?;
    let database_before = fs::read(&database)?;

    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));

    // The rejection must not have touched the database the caller named.
    assert_eq!(fs::read(&database)?, database_before);
    // The stray companion, by contrast, is consumed by SQLite during the open.
    assert!(!companion.exists());
    Ok(())
}

#[test]
fn malformed_schema_with_wal_artifact_is_rejected_without_target_mutation()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("malformed-wal.sqlite");
    let connection = create_current_database_with_messages(
        &database,
        "CREATE TABLE messages(queue_id BLOB, sender_signature BLOB);",
    )?;
    drop(connection);
    let companion = directory.path().join("malformed-wal.sqlite-wal");
    fs::write(&companion, b"hostile-wal-artifact")?;
    let database_before = fs::read(&database)?;
    let companion_before = fs::read(&companion)?;

    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));
    assert_eq!(fs::read(&database)?, database_before);
    assert_eq!(fs::read(&companion)?, companion_before);
    Ok(())
}

#[test]
fn integrity_check_rejects_constraint_poison_without_mutation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("constraint-poison.sqlite");
    drop(Relay::open_at(&database, NOW)?);
    let connection = Connection::open(&database)?;
    connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
    connection.execute(
        "INSERT INTO mailboxes(queue_id, send_key, receive_key, manage_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            vec![0x11_u8; 32],
            vec![0x22_u8; 32],
            vec![0x33_u8; 32],
            vec![0x44_u8; 32],
            i64::try_from(NOW)?,
        ],
    )?;
    connection.execute(
        "INSERT INTO messages(queue_id, message_id, ciphertext, expires_at, sender_signature)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            vec![0x11_u8; 32],
            vec![0x55_u8; 16],
            b"constraint-poison".as_slice(),
            i64::try_from(NOW + 60)?,
            vec![0x66_u8; 1],
        ],
    )?;
    drop(connection);
    let before = fs::read(&database)?;

    assert!(matches!(
        Relay::open_at(&database, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));
    assert_eq!(fs::read(&database)?, before);
    Ok(())
}

#[test]
fn hostile_fixture_source_is_immutable_while_disposable_copy_is_rejected()
-> Result<(), Box<dyn Error>> {
    let source_directory = tempfile::tempdir()?;
    let source = source_directory.path().join("hostile.sqlite");
    let connection = create_current_database_with_messages(
        &source,
        "CREATE TABLE messages(queue_id BLOB, sender_signature BLOB);",
    )?;
    drop(connection);
    let original = fs::read(&source)?;
    let companion = source_directory.path().join("hostile.sqlite-journal");
    fs::write(&companion, b"hostile-fixture-companion")?;
    let original_companion = fs::read(&companion)?;

    let uri = format!("file:{}?mode=ro&immutable=1", source.display());
    let immutable = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    assert_eq!(
        immutable.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'messages'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    drop(immutable);

    let work_directory = tempfile::tempdir()?;
    let working_copy = work_directory.path().join("hostile.sqlite");
    fs::copy(&source, &working_copy)?;
    assert!(matches!(
        Relay::open_at(&working_copy, NOW),
        Err(secure_messenger_lab::LabError::Storage)
    ));
    assert_eq!(fs::read(&source)?, original);
    assert_eq!(fs::read(&companion)?, original_companion);
    Ok(())
}
