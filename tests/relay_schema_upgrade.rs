use std::error::Error;
use std::fs;
use std::path::Path;

use rusqlite::{Connection, params};
use secure_messenger_lab::Relay;

const NOW: u64 = 1_800_000_000;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
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
