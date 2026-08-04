use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

use rusqlite::{Connection, OpenFlags, params};
use secure_messenger_lab::Relay;

const NOW: u64 = 1_800_000_000;
const HOT_JOURNAL_CHILD_PATH: &str = "SECURE_MESSENGER_HOT_JOURNAL_CHILD_PATH";

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
    let changed = connection.execute(
        "UPDATE mailboxes SET created_at = created_at + 1 WHERE queue_id = ?1",
        params![vec![0x11_u8; 32]],
    )?;
    if changed != 1 {
        return Err(
            std::io::Error::other("hot-journal child did not update its benign row").into(),
        );
    }

    // Intentionally leave SQLite's real rollback journal hot. This test only
    // invokes the helper through the parent subprocess below.
    std::process::abort();
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
