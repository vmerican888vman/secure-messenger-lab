use std::path::Path;

use rand::{CryptoRng, RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use zeroize::Zeroizing;

use super::envelope::{
    CRYPTO_SUITE, ENVELOPE_VERSION, MAX_CIPHERTEXT_BYTES, NONCE_BYTES, STATE_SCHEMA_VERSION, open,
    seal,
};
use super::protector::{ProfileBinding, ProtectionLevel, StateKeyProtector};
use crate::companion::reject_anomalous_wal;
use crate::private_store_dir::{MainDatabase, PrivateStoreDir, StoreKind};
use crate::{LabError, Result};

const APPLICATION_ID: i64 = 0x534D_534C;
const USER_VERSION: i64 = 1;
const SLOT: i64 = 1;
const DEK_BYTES: usize = 32;
const WRAPPED_DEK_MAX_BYTES: usize = 8_192;

// This is deliberately also the comparison value for sqlite_schema.sql. Do
// not prettify it independently of the DDL below: whitespace is part of the
// exact-shape contract for this first secret-state schema.
const CLIENT_STATE_SQL: &str = "CREATE TABLE client_state (\
    slot                 INTEGER PRIMARY KEY NOT NULL CHECK(slot = 1),\
    profile_id           BLOB NOT NULL CHECK(length(profile_id) = 16),\
    generation           INTEGER NOT NULL CHECK(generation >= 1),\
    envelope_version     INTEGER NOT NULL CHECK(envelope_version = 1),\
    state_schema_version INTEGER NOT NULL CHECK(state_schema_version = 1),\
    crypto_suite         INTEGER NOT NULL CHECK(crypto_suite = 1),\
    key_ref              BLOB NOT NULL CHECK(length(key_ref) = 16),\
    wrapped_dek          BLOB NOT NULL CHECK(length(wrapped_dek) BETWEEN 1 AND 8192),\
    nonce                BLOB NOT NULL CHECK(length(nonce) = 24),\
    ciphertext           BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 8388608)\
) STRICT";

trait RandomSource: CryptoRng + RngCore {}
impl<T: CryptoRng + RngCore> RandomSource for T {}

/// One encrypted, authenticated endpoint-state snapshot in a one-row `SQLite`
/// database. Secret state is opaque to this layer.
///
/// Production construction goes through [`PrivateStoreDir`] only: the store
/// owns the directory handle, holding the lifecycle lock for its own
/// lifetime. The raw-path constructors are `#[cfg(test)]` and exist for the
/// path-level hostile-fixture tests.
pub struct ClientStateStore<P: StateKeyProtector> {
    connection: Connection,
    protector: P,
    binding: ProfileBinding,
    dek: Zeroizing<[u8; DEK_BYTES]>,
    wrapped_dek: Vec<u8>,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    generation: u64,
    state: Zeroizing<Vec<u8>>,
    poisoned: bool,
    // Held for the lifecycle lock and the boundary's entry validation. Only
    // `None` through the cfg(test) raw-path constructors.
    _dir: Option<PrivateStoreDir>,
}

impl<P: StateKeyProtector> ClientStateStore<P> {
    /// Create generation one inside a secured private directory. The
    /// directory must contain no database or companion
    /// ([`MainDatabase::Absent`]); the store takes ownership of the directory
    /// handle and its lifecycle lock.
    ///
    /// The protector's independently held binding is read before any state is
    /// written.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error if the directory already holds a
    /// database or companion, or if protection, encryption, schema, RNG, or
    /// the initial atomic write fails.
    pub fn create(dir: PrivateStoreDir, protector: P, state: &[u8]) -> Result<Self> {
        if dir.kind() != StoreKind::ClientState
            || dir.main_database_at_open() != MainDatabase::Absent
        {
            return Err(LabError::Storage);
        }
        dir.create_main_database_file()?;
        Self::create_at_path(&dir.database_path(), protector, state, Some(dir))
    }

    /// Open and authenticate the one authoritative snapshot inside a secured
    /// private directory, which must hold a non-empty validated database
    /// ([`MainDatabase::Present`]).
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when no usable database exists or for
    /// an invalid schema/binding/key or an unauthenticated or malformed state
    /// envelope.
    pub fn open(dir: PrivateStoreDir, protector: P) -> Result<Self> {
        if dir.kind() != StoreKind::ClientState
            || dir.main_database_at_open() != MainDatabase::Present
        {
            return Err(LabError::Storage);
        }
        Self::open_at_path(&dir.database_path(), protector, Some(dir))
    }

    #[cfg(test)]
    fn create_with_path(path: &Path, protector: P, state: &[u8]) -> Result<Self> {
        Self::create_at_path(path, protector, state, None)
    }

    #[cfg(test)]
    fn open_with_path(path: &Path, protector: P) -> Result<Self> {
        Self::open_at_path(path, protector, None)
    }

    fn create_at_path(
        path: &Path,
        protector: P,
        state: &[u8],
        dir: Option<PrivateStoreDir>,
    ) -> Result<Self> {
        let mut rng = OsRng;
        Self::create_with_rng(path, protector, state, &mut rng, dir)
    }

    fn create_with_rng<R: RandomSource>(
        path: &Path,
        protector: P,
        state: &[u8],
        rng: &mut R,
        dir: Option<PrivateStoreDir>,
    ) -> Result<Self> {
        let binding = protector.expected_binding()?;
        let mut connection = open_connection(path)?;
        validate_empty_database(&connection)?;
        let mut dek = Zeroizing::new([0_u8; DEK_BYTES]);
        fill(rng, &mut *dek)?;
        let wrapped_dek = protector.wrap_dek(&dek)?;
        if wrapped_dek.is_empty() || wrapped_dek.len() > WRAPPED_DEK_MAX_BYTES {
            return Err(LabError::Storage);
        }
        let mut nonce = [0_u8; NONCE_BYTES];
        fill(rng, &mut nonce)?;
        let candidate_state = Zeroizing::new(state.to_vec());
        let ciphertext = seal(binding, 1, &wrapped_dek, &dek, &nonce, &candidate_state)?;
        validate_ciphertext_len(ciphertext.len())?;

        activate_storage_settings(&connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LabError::Storage)?;
        validate_empty_database(&transaction)?;
        create_schema(&transaction)?;
        #[cfg(test)]
        test_abort_at("create_after_schema");
        transaction
            .execute(
                "INSERT INTO client_state(slot, profile_id, generation, envelope_version, \
                 state_schema_version, crypto_suite, key_ref, wrapped_dek, nonce, ciphertext) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    SLOT,
                    binding.profile_id().as_slice(),
                    1_i64,
                    ENVELOPE_VERSION,
                    STATE_SCHEMA_VERSION,
                    CRYPTO_SUITE,
                    binding.key_ref().as_slice(),
                    &wrapped_dek,
                    nonce.as_slice(),
                    &ciphertext,
                ],
            )
            .map_err(|_| LabError::Storage)?;
        #[cfg(test)]
        test_abort_at("create_after_insert");
        validate_schema(&transaction)?;
        transaction.commit().map_err(|_| LabError::Storage)?;
        #[cfg(test)]
        test_abort_at("create_after_commit");
        Ok(Self {
            connection,
            protector,
            binding,
            dek,
            wrapped_dek,
            nonce,
            ciphertext,
            generation: 1,
            state: candidate_state,
            poisoned: false,
            _dir: dir,
        })
    }

    fn open_at_path(path: &Path, protector: P, dir: Option<PrivateStoreDir>) -> Result<Self> {
        // Expected binding must be loaded independently of, and before trusting,
        // any bytes supplied by the database.
        let binding = protector.expected_binding()?;
        let mut connection = open_connection(path)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| LabError::Storage)?;
        validate_schema(&transaction)?;
        let row = read_row(&transaction, binding)?;
        transaction.commit().map_err(|_| LabError::Storage)?;
        let mut dek = Zeroizing::new([0_u8; DEK_BYTES]);
        protector.unwrap_dek(&row.wrapped_dek, &mut dek)?;
        let state = open(
            binding,
            row.generation,
            &row.wrapped_dek,
            &dek,
            &row.nonce,
            &row.ciphertext,
        )?;
        activate_storage_settings(&connection)?;
        Ok(Self {
            connection,
            protector,
            binding,
            dek,
            wrapped_dek: row.wrapped_dek,
            nonce: row.nonce,
            ciphertext: row.ciphertext,
            generation: row.generation,
            state,
            poisoned: false,
            _dir: dir,
        })
    }

    /// Return the authenticated serialized state while this handle is usable.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error after any failed commit; callers must
    /// reopen and reconcile before using state again.
    pub fn state(&self) -> Result<&[u8]> {
        self.ensure_usable()?;
        Ok(&self.state)
    }

    /// Return the authenticated generation while this handle is usable.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error after any failed commit.
    pub fn generation(&self) -> Result<u64> {
        self.ensure_usable()?;
        Ok(self.generation)
    }

    /// Return the independently obtained profile binding while usable.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error after any failed commit.
    pub fn binding(&self) -> Result<ProfileBinding> {
        self.ensure_usable()?;
        Ok(self.binding)
    }

    #[must_use]
    pub fn protection_level(&self) -> ProtectionLevel {
        self.protector.protection_level()
    }

    /// Commit a complete replacement snapshot with an exact generation CAS.
    /// Any failure poisons this handle: callers must reopen and reconcile.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error on a poisoned handle, failed RNG/seal,
    /// stale generation, or an uncertain storage write.
    pub fn commit(&mut self, state: &[u8]) -> Result<()> {
        let mut rng = OsRng;
        self.commit_with_rng(state, &mut rng)
    }

    fn commit_with_rng<R: RandomSource>(&mut self, state: &[u8], rng: &mut R) -> Result<()> {
        if self.poisoned {
            return Err(LabError::Storage);
        }
        let result = self.commit_inner(state, rng);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn commit_inner<R: RandomSource>(&mut self, state: &[u8], rng: &mut R) -> Result<()> {
        let next_generation = self.generation.checked_add(1).ok_or(LabError::Storage)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        fill(rng, &mut nonce)?;
        let candidate_state = Zeroizing::new(state.to_vec());
        // The DEK is stable per profile, but the nonce is fresh for every
        // commit, including divergent commits after an authentic rollback.
        let ciphertext = seal(
            self.binding,
            next_generation,
            &self.wrapped_dek,
            &self.dek,
            &nonce,
            &candidate_state,
        )?;
        validate_ciphertext_len(ciphertext.len())?;
        #[cfg(test)]
        test_abort_at("commit_after_seal");
        let expected = i64::try_from(self.generation).map_err(|_| LabError::Storage)?;
        let next = i64::try_from(next_generation).map_err(|_| LabError::Storage)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LabError::Storage)?;
        validate_schema(&transaction)?;
        let changed = transaction
            .execute(
                "UPDATE client_state SET generation = ?1, nonce = ?2, ciphertext = ?3 \
                 WHERE slot = ?4 AND generation = ?5 AND profile_id = ?6 AND key_ref = ?7 \
                 AND envelope_version = ?8 AND state_schema_version = ?9 AND crypto_suite = ?10 \
                 AND wrapped_dek = ?11 AND nonce = ?12 AND ciphertext = ?13",
                params![
                    next,
                    nonce.as_slice(),
                    &ciphertext,
                    SLOT,
                    expected,
                    self.binding.profile_id().as_slice(),
                    self.binding.key_ref().as_slice(),
                    ENVELOPE_VERSION,
                    STATE_SCHEMA_VERSION,
                    CRYPTO_SUITE,
                    &self.wrapped_dek,
                    self.nonce.as_slice(),
                    &self.ciphertext,
                ],
            )
            .map_err(|_| LabError::Storage)?;
        if changed != 1 {
            return Err(LabError::Storage);
        }
        #[cfg(test)]
        test_abort_at("commit_after_update");
        transaction.commit().map_err(|_| LabError::Storage)?;
        #[cfg(test)]
        test_abort_at("commit_after_commit");
        // This assignment is intentionally after COMMIT.
        self.generation = next_generation;
        self.state = candidate_state;
        self.nonce = nonce;
        self.ciphertext = ciphertext;
        Ok(())
    }

    fn ensure_usable(&self) -> Result<()> {
        if self.poisoned {
            return Err(LabError::Storage);
        }
        Ok(())
    }
}

impl<P: StateKeyProtector> std::fmt::Debug for ClientStateStore<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientStateStore")
            .field("generation", &self.generation)
            .field("state", &"redacted")
            .field("state_length", &self.state.len())
            .field("binding", &self.binding)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

struct StoredRow {
    generation: u64,
    wrapped_dek: Vec<u8>,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

fn fill<R: RandomSource>(rng: &mut R, bytes: &mut [u8]) -> Result<()> {
    rng.try_fill_bytes(bytes).map_err(|_| LabError::Storage)
}

#[cfg(test)]
fn test_abort_at(point: &str) {
    const FAILPOINT: &str = "SECURE_MESSENGER_STATE_FAILPOINT";
    const MARKER: &str = "SECURE_MESSENGER_STATE_FAILPOINT_MARKER";
    if std::env::var(FAILPOINT).as_deref() != Ok(point) {
        return;
    }
    if let Ok(marker) = std::env::var(MARKER) {
        let _ = std::fs::write(marker, point);
    }
    std::process::abort();
}

/// The single choke point for both `create` and `open`, which is why the
/// anomalous-WAL refusal lives here: guarding one entry point and not the other
/// would leave the store destroyable through whichever was missed.
///
/// This store holds wrapped key material rather than replaceable queue state,
/// so the consequence of the weakness is worse here than in the relay. Measured
/// before the guard: planting one `-wal` beside a healthy store, with no write
/// access to the database, took it from 8192 to 12288 bytes and made every
/// later open fail, including after the planted file was removed.
fn open_connection(path: &Path) -> Result<Connection> {
    reject_anomalous_wal(path)?;
    let connection = Connection::open(path).map_err(|_| LabError::Storage)?;
    connection
        .execute_batch(
            "PRAGMA trusted_schema = OFF;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA secure_delete = ON;",
        )
        .map_err(|_| LabError::Storage)?;
    Ok(connection)
}

fn activate_storage_settings(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            "PRAGMA trusted_schema = OFF;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA secure_delete = ON;
             PRAGMA journal_mode = DELETE;",
        )
        .map_err(|_| LabError::Storage)
}

fn validate_empty_database(connection: &Connection) -> Result<()> {
    let application_id = connection
        .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
        .map_err(|_| LabError::Storage)?;
    let user_version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(|_| LabError::Storage)?;
    let object_count = connection
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| LabError::Storage)?;
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(|_| LabError::Storage)?;
    if application_id != 0 || user_version != 0 || object_count != 0 || integrity != "ok" {
        return Err(LabError::Storage);
    }
    Ok(())
}

fn create_schema(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {APPLICATION_ID};
             PRAGMA user_version = {USER_VERSION};
             {CLIENT_STATE_SQL};"
        ))
        .map_err(|_| LabError::Storage)
}

fn validate_schema(connection: &Connection) -> Result<()> {
    let application_id = connection
        .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
        .map_err(|_| LabError::Storage)?;
    let user_version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(|_| LabError::Storage)?;
    if application_id != APPLICATION_ID || user_version != USER_VERSION {
        return Err(LabError::Storage);
    }
    // The complete schema listing must be exactly the one expected table. No
    // name-based exemptions: a hostile `sqlite_`-prefixed trigger, view, or
    // table injected via writable_schema must fail this comparison.
    let objects = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .map_err(|_| LabError::Storage)?;
    let expected = vec![(
        String::from("table"),
        String::from("client_state"),
        String::from("client_state"),
        Some(String::from(CLIENT_STATE_SQL)),
    )];
    if objects != expected {
        return Err(LabError::Storage);
    }
    validate_table_list(connection)?;
    validate_table_xinfo(connection)?;
    validate_no_indexes_or_foreign_keys(connection)?;
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(|_| LabError::Storage)?;
    if integrity != "ok" {
        return Err(LabError::Storage);
    }
    let foreign_key_problem = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| LabError::Storage)?;
    if foreign_key_problem {
        return Err(LabError::Storage);
    }
    Ok(())
}

fn validate_no_indexes_or_foreign_keys(connection: &Connection) -> Result<()> {
    let index_count = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_index_list('client_state')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| LabError::Storage)?;
    let foreign_key_count = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('client_state')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| LabError::Storage)?;
    if index_count != 0 || foreign_key_count != 0 {
        return Err(LabError::Storage);
    }
    Ok(())
}

fn validate_table_list(connection: &Connection) -> Result<()> {
    // Exact comparison of the main schema's complete table list: the store's
    // one table plus the built-in sqlite_schema, nothing else, with no
    // prefix-based exception. The temporary schema's built-in
    // sqlite_temp_schema entry is excluded by querying only `schema = 'main'`.
    let tables = connection
        .prepare(
            "SELECT name, type, ncol, wr, strict FROM pragma_table_list \
             WHERE schema = 'main' ORDER BY name",
        )
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .map_err(|_| LabError::Storage)?;
    let expected = vec![
        (
            String::from("client_state"),
            String::from("table"),
            10,
            0,
            1,
        ),
        (
            String::from("sqlite_schema"),
            String::from("table"),
            5,
            0,
            0,
        ),
    ];
    if tables != expected {
        return Err(LabError::Storage);
    }
    Ok(())
}

fn validate_table_xinfo(connection: &Connection) -> Result<()> {
    let actual = connection
        .prepare("PRAGMA table_xinfo(client_state)")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .map_err(|_| LabError::Storage)?;
    let names = [
        ("slot", "INTEGER", 1_i64),
        ("profile_id", "BLOB", 0),
        ("generation", "INTEGER", 0),
        ("envelope_version", "INTEGER", 0),
        ("state_schema_version", "INTEGER", 0),
        ("crypto_suite", "INTEGER", 0),
        ("key_ref", "BLOB", 0),
        ("wrapped_dek", "BLOB", 0),
        ("nonce", "BLOB", 0),
        ("ciphertext", "BLOB", 0),
    ];
    if actual.len() != names.len() {
        return Err(LabError::Storage);
    }
    for (index, (name, type_name, pk)) in names.iter().enumerate() {
        let row = &actual[index];
        if row.0 != i64::try_from(index).map_err(|_| LabError::Storage)?
            || row.1 != *name
            || row.2 != *type_name
            || row.3 != 1
            || row.4.is_some()
            || row.5 != *pk
            || row.6 != 0
        {
            return Err(LabError::Storage);
        }
    }
    Ok(())
}

fn read_row(connection: &Connection, binding: ProfileBinding) -> Result<StoredRow> {
    let lengths = connection
        .query_row(
            "SELECT length(profile_id), generation, envelope_version, state_schema_version, crypto_suite,
                    length(key_ref), length(wrapped_dek), length(nonce), length(ciphertext)
             FROM client_state WHERE slot = ?1",
            params![SLOT],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?, row.get::<_, i64>(7)?, row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LabError::Storage)?
        .ok_or(LabError::Storage)?;
    if lengths.0 != 16
        || lengths.1 < 1
        || lengths.2 != ENVELOPE_VERSION
        || lengths.3 != STATE_SCHEMA_VERSION
        || lengths.4 != CRYPTO_SUITE
        || lengths.5 != 16
        || lengths.6 < 1
        || lengths.6 > i64::try_from(WRAPPED_DEK_MAX_BYTES).map_err(|_| LabError::Storage)?
        || lengths.7 != i64::try_from(NONCE_BYTES).map_err(|_| LabError::Storage)?
        || lengths.8 < 16
        || lengths.8 > i64::try_from(MAX_CIPHERTEXT_BYTES).map_err(|_| LabError::Storage)?
    {
        return Err(LabError::Storage);
    }
    let row = connection
        .query_row(
            "SELECT profile_id, generation, key_ref, wrapped_dek, nonce, ciphertext
             FROM client_state WHERE slot = ?1",
            params![SLOT],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .map_err(|_| LabError::Storage)?;
    if row.0.as_slice() != binding.profile_id().as_slice()
        || row.2.as_slice() != binding.key_ref().as_slice()
    {
        return Err(LabError::Storage);
    }
    let nonce: [u8; NONCE_BYTES] = row.4.try_into().map_err(|_| LabError::Storage)?;
    Ok(StoredRow {
        generation: u64::try_from(row.1).map_err(|_| LabError::Storage)?,
        wrapped_dek: row.3,
        nonce,
        ciphertext: row.5,
    })
}

fn validate_ciphertext_len(length: usize) -> Result<()> {
    if !(16..=MAX_CIPHERTEXT_BYTES).contains(&length) {
        return Err(LabError::Storage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::*;

    const CHILD_PATH: &str = "SECURE_MESSENGER_STATE_CHILD_PATH";
    const CHILD_OPERATION: &str = "SECURE_MESSENGER_STATE_CHILD_OPERATION";
    const FAILPOINT: &str = "SECURE_MESSENGER_STATE_FAILPOINT";
    const FAILPOINT_MARKER: &str = "SECURE_MESSENGER_STATE_FAILPOINT_MARKER";

    #[derive(Clone)]
    struct TestProtector {
        binding: ProfileBinding,
        mask: [u8; DEK_BYTES],
    }

    impl TestProtector {
        fn new(profile: u8, key: u8) -> Self {
            Self {
                binding: ProfileBinding::new([profile; 16], [key; 16]),
                mask: [key; DEK_BYTES],
            }
        }

        fn with_mask(profile: u8, key: u8, mask: u8) -> Self {
            Self {
                binding: ProfileBinding::new([profile; 16], [key; 16]),
                mask: [mask; DEK_BYTES],
            }
        }
    }

    impl StateKeyProtector for TestProtector {
        fn expected_binding(&self) -> Result<ProfileBinding> {
            Ok(self.binding)
        }

        fn protection_level(&self) -> ProtectionLevel {
            ProtectionLevel::SoftwareBacked
        }

        fn wrap_dek(&self, dek: &Zeroizing<[u8; DEK_BYTES]>) -> Result<Vec<u8>> {
            let mut wrapped = b"state-wrap/v1".to_vec();
            wrapped.extend_from_slice(self.binding.profile_id());
            wrapped.extend_from_slice(self.binding.key_ref());
            wrapped.extend(dek.iter().zip(self.mask).map(|(value, mask)| value ^ mask));
            Ok(wrapped)
        }

        fn unwrap_dek(
            &self,
            wrapped_dek: &[u8],
            output: &mut Zeroizing<[u8; DEK_BYTES]>,
        ) -> Result<()> {
            const PREFIX: &[u8] = b"state-wrap/v1";
            let expected = PREFIX.len() + 16 + 16 + DEK_BYTES;
            if wrapped_dek.len() != expected {
                return Err(LabError::Storage);
            }
            if &wrapped_dek[..PREFIX.len()] != PREFIX
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
    }

    struct TestRng {
        next: u8,
        fail: bool,
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let value = self.next;
            self.next = self.next.wrapping_add(1);
            u32::from(value)
        }

        fn next_u64(&mut self) -> u64 {
            let value = self.next;
            self.next = self.next.wrapping_add(1);
            u64::from(value)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let _ = self.try_fill_bytes(dest);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
            if self.fail {
                return Err(rand::Error::new("injected RNG failure"));
            }
            for byte in dest {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    fn database(directory: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        directory.path().join(name)
    }

    type RawSnapshot = (i64, Vec<u8>, Vec<u8>, Vec<u8>);

    fn raw_snapshot(connection: &Connection) -> rusqlite::Result<RawSnapshot> {
        connection.query_row(
            "SELECT generation, wrapped_dek, nonce, ciphertext FROM client_state WHERE slot = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
    }

    fn run_forced_death_child(
        path: &Path,
        operation: &str,
        failpoint: &str,
        marker: &Path,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let status = Command::new(env::current_exe()?)
            .arg("--exact")
            .arg("persistence::sqlite::tests::forced_death_child")
            .arg("--nocapture")
            .env(CHILD_PATH, path)
            .env(CHILD_OPERATION, operation)
            .env(FAILPOINT, failpoint)
            .env(FAILPOINT_MARKER, marker)
            .status()?;
        assert!(!status.success());
        assert_eq!(fs::read_to_string(marker)?, failpoint);
        Ok(())
    }

    #[test]
    fn forced_death_child() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let Ok(path) = env::var(CHILD_PATH) else {
            return Ok(());
        };
        let operation = env::var(CHILD_OPERATION)?;
        match operation.as_str() {
            "create" => {
                let _ = ClientStateStore::create_with_path(
                    Path::new(&path),
                    TestProtector::new(31, 32),
                    b"created",
                )?;
            }
            "commit" => {
                let mut store =
                    ClientStateStore::open_with_path(Path::new(&path), TestProtector::new(31, 32))?;
                store.commit(b"committed")?;
            }
            "wal-crash" => {
                // Leave a genuine live WAL: converted, written, never closed.
                // A clean close would checkpoint and unlink the companion, and
                // a leaked in-process connection would hold a lock that makes
                // the later open fail for an unrelated reason.
                let connection = Connection::open(Path::new(&path))?;
                connection.execute_batch(
                    "PRAGMA journal_mode = WAL;
                     PRAGMA wal_autocheckpoint = 0;",
                )?;
                connection.execute("UPDATE client_state SET slot = 1 WHERE slot = 1", [])?;
                std::process::abort();
            }
            _ => return Err(Box::new(LabError::Storage)),
        }
        Err(Box::new(LabError::Storage))
    }

    /// Creating a single file beside a healthy store — with no write access to
    /// the database — used to destroy it permanently, the same weakness the
    /// relay carried. It matters more here: this store holds wrapped key
    /// material, not replaceable queue state.
    ///
    /// Asserts the two things that make refusal better than an open: the
    /// database is left byte-identical, and removing the planted file restores
    /// service with the state still readable.
    #[test]
    fn planted_wal_is_refused_without_touching_the_state_store()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;

        // Stage a WAL elsewhere carrying a schema the store would reject.
        let attacker = database(&directory, "attacker.sqlite");
        drop(ClientStateStore::create_with_path(
            &attacker,
            TestProtector::new(51, 52),
            b"attacker",
        )?);
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

        // Victim: a healthy store holding secret state.
        let victim = database(&directory, "victim.sqlite");
        drop(ClientStateStore::create_with_path(
            &victim,
            TestProtector::new(53, 54),
            b"irreplaceable-state",
        )?);
        let before = fs::read(&victim)?;
        assert_eq!((before[18], before[19]), (1, 1));

        // The whole attack: create one file. The database is never written.
        fs::write(directory.path().join("victim.sqlite-wal"), &planted)?;

        for _ in 0..3 {
            assert!(matches!(
                ClientStateStore::open_with_path(&victim, TestProtector::new(53, 54)),
                Err(LabError::Storage)
            ));
        }

        // Untouched: same bytes, same rollback-mode header.
        let after = fs::read(&victim)?;
        assert_eq!(after, before);
        assert_eq!((after[18], after[19]), (1, 1));

        // Deliberately NOT opened normally here — any SQLite client that opens
        // this path while the planted file exists triggers the replay the
        // refusal avoids, and would corrupt the very database under assertion.

        // Recoverable: remove the planted file and the state is still there.
        fs::remove_file(directory.path().join("victim.sqlite-wal"))?;
        let reopened = ClientStateStore::open_with_path(&victim, TestProtector::new(53, 54))?;
        assert_eq!(reopened.state()?, b"irreplaceable-state");
        assert_eq!(reopened.generation()?, 1);
        Ok(())
    }

    /// A WAL-mode store with a live `-wal` must still open, covering the state
    /// store's route through the shared guard's pass-through arm.
    ///
    /// The arm itself is not otherwise uncovered: deleting it also fails the
    /// relay tests `wal_mode_database_with_live_wal_opens_and_recovers` and
    /// `rejected_wal_open_checkpoints_and_removes_both_companions`, so three
    /// tests across two targets fail. What this one adds is that the guard is
    /// reached from `open_connection` and passes for a state-store database,
    /// which no relay test can show.
    #[test]
    fn wal_mode_state_store_with_live_wal_opens()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "wal-live.sqlite");
        drop(ClientStateStore::create_with_path(
            &path,
            TestProtector::new(55, 56),
            b"wal-mode-state",
        )?);

        // Real crash, so the companion is live and no lock is held.
        let status = Command::new(env::current_exe()?)
            .arg("--exact")
            .arg("persistence::sqlite::tests::forced_death_child")
            .arg("--nocapture")
            .env(CHILD_PATH, &path)
            .env(CHILD_OPERATION, "wal-crash")
            .status()?;
        assert!(!status.success());

        let header = fs::read(&path)?;
        assert_eq!((header[18], header[19]), (2, 2));
        assert!(fs::metadata(directory.path().join("wal-live.sqlite-wal"))?.len() > 0);

        // Must reach the pass-through arm and open, not be refused.
        let opened = ClientStateStore::open_with_path(&path, TestProtector::new(55, 56))?;
        assert_eq!(opened.state()?, b"wal-mode-state");
        Ok(())
    }

    #[test]
    fn round_trip_restart_and_redaction() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "state.sqlite");
        let canaries: [&[u8]; 3] = [
            b"message-plaintext-canary",
            b"raw-account-pickle-canary",
            b"private-capability-canary",
        ];
        let mut state = Vec::new();
        for canary in canaries {
            state.extend_from_slice(canary);
        }
        let store = ClientStateStore::create_with_path(&path, TestProtector::new(1, 2), &state)?;
        assert_eq!(store.state()?, state);
        assert_eq!(store.generation()?, 1);
        let debug = format!("{store:?}");
        let error_display = LabError::Storage.to_string();
        let error_debug = format!("{:?}", LabError::Storage);
        for canary in canaries {
            let text = std::str::from_utf8(canary)?;
            assert!(!debug.contains(text));
            assert!(!error_display.contains(text));
            assert!(!error_debug.contains(text));
        }
        drop(store);
        let reopened = ClientStateStore::open_with_path(&path, TestProtector::new(1, 2))?;
        assert_eq!(reopened.state()?, state);
        drop(reopened);
        for entry in fs::read_dir(directory.path())? {
            let bytes = fs::read(entry?.path())?;
            for canary in canaries {
                assert!(!bytes.windows(canary.len()).any(|part| part == canary));
            }
        }
        Ok(())
    }

    #[test]
    fn tamper_wrong_binding_and_authentic_rollback_are_explicit()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "state.sqlite");
        let rollback = database(&directory, "rollback.sqlite");
        let mut store = ClientStateStore::create_with_path(&path, TestProtector::new(3, 4), b"old")?;
        fs::copy(&path, &rollback)?;
        store.commit(b"new")?;
        drop(store);
        // This is deliberately an accepted, documented rollback limitation.
        fs::copy(&rollback, &path)?;
        assert_eq!(
            ClientStateStore::open_with_path(&path, TestProtector::new(3, 4))?.state()?,
            b"old"
        );
        assert!(ClientStateStore::open_with_path(&path, TestProtector::new(9, 10)).is_err());
        assert!(ClientStateStore::open_with_path(&path, TestProtector::with_mask(3, 4, 99)).is_err());
        let connection = Connection::open(&path)?;
        connection.execute("UPDATE client_state SET ciphertext = zeroblob(16)", [])?;
        drop(connection);
        assert!(ClientStateStore::open_with_path(&path, TestProtector::new(3, 4)).is_err());
        Ok(())
    }

    #[test]
    fn fresh_nonce_rng_failure_and_exact_size_bound()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "state.sqlite");
        let mut rng = TestRng {
            next: 1,
            fail: false,
        };
        let mut store =
            ClientStateStore::create_with_rng(&path, TestProtector::new(5, 6), b"one", &mut rng, None)?;
        let first_nonce = store.connection.query_row(
            "SELECT nonce FROM client_state WHERE slot = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        store.commit_with_rng(b"two", &mut rng)?;
        let second_nonce = store.connection.query_row(
            "SELECT nonce FROM client_state WHERE slot = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        assert_ne!(first_nonce, second_nonce);
        let before = fs::read(&path)?;
        let mut failing = TestRng {
            next: 0,
            fail: true,
        };
        assert!(store.commit_with_rng(b"three", &mut failing).is_err());
        assert_eq!(before, fs::read(&path)?);
        drop(store);
        let maximum = vec![7_u8; MAX_CIPHERTEXT_BYTES - 16];
        let max_path = database(&directory, "max.sqlite");
        assert!(ClientStateStore::create_with_path(&max_path, TestProtector::new(7, 8), &maximum).is_ok());
        let over_path = database(&directory, "over.sqlite");
        let over = vec![7_u8; MAX_CIPHERTEXT_BYTES - 15];
        assert!(ClientStateStore::create_with_path(&over_path, TestProtector::new(9, 10), &over).is_err());
        let over_database = Connection::open(&over_path)?;
        assert_eq!(
            over_database.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| {
                row.get::<_, i64>(0)
            })?,
            0
        );
        Ok(())
    }

    #[test]
    fn failed_creation_leaves_no_partial_profile_and_retry_succeeds()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "creation.sqlite");
        let mut failing = TestRng {
            next: 0,
            fail: true,
        };
        assert!(
            ClientStateStore::create_with_rng(
                &path,
                TestProtector::new(21, 22),
                b"state",
                &mut failing,
                None,
            )
            .is_err()
        );
        let empty = Connection::open(&path)?;
        assert_eq!(
            empty.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            empty.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            empty.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| {
                row.get::<_, i64>(0)
            })?,
            0
        );
        drop(empty);

        let mut good = TestRng {
            next: 1,
            fail: false,
        };
        let store = ClientStateStore::create_with_rng(
            &path,
            TestProtector::new(21, 22),
            b"state",
            &mut good,
            None,
        )?;
        assert_eq!(store.state()?, b"state");
        Ok(())
    }

    #[test]
    fn forced_death_during_creation_reveals_no_half_profile()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for failpoint in [
            "create_after_schema",
            "create_after_insert",
            "create_after_commit",
        ] {
            let path = database(&directory, &format!("{failpoint}.sqlite"));
            let marker = database(&directory, &format!("{failpoint}.marker"));
            run_forced_death_child(&path, "create", failpoint, &marker)?;
            if failpoint == "create_after_commit" {
                let store = ClientStateStore::open_with_path(&path, TestProtector::new(31, 32))?;
                assert_eq!(store.state()?, b"created");
            } else {
                assert!(ClientStateStore::open_with_path(&path, TestProtector::new(31, 32)).is_err());
                let store =
                    ClientStateStore::create_with_path(&path, TestProtector::new(31, 32), b"retried")?;
                assert_eq!(store.state()?, b"retried");
            }
        }
        Ok(())
    }

    #[test]
    fn forced_death_during_commit_reveals_complete_old_or_new_state()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for (failpoint, expected) in [
            ("commit_after_seal", b"old".as_slice()),
            ("commit_after_update", b"old".as_slice()),
            ("commit_after_commit", b"committed".as_slice()),
        ] {
            let path = database(&directory, &format!("{failpoint}.sqlite"));
            let marker = database(&directory, &format!("{failpoint}.marker"));
            drop(ClientStateStore::create_with_path(
                &path,
                TestProtector::new(31, 32),
                b"old",
            )?);
            run_forced_death_child(&path, "commit", failpoint, &marker)?;
            let store = ClientStateStore::open_with_path(&path, TestProtector::new(31, 32))?;
            assert_eq!(store.state()?, expected);
        }
        Ok(())
    }

    #[test]
    fn wrapped_key_substitution_cannot_be_committed_over()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "wrapper-race.sqlite");
        let mut store = ClientStateStore::create_with_path(&path, TestProtector::new(23, 24), b"old")?;
        let attacker = Connection::open(&path)?;
        let wrapper_length = attacker.query_row(
            "SELECT length(wrapped_dek) FROM client_state WHERE slot = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        attacker.execute(
            "UPDATE client_state SET wrapped_dek = zeroblob(?1) WHERE slot = 1",
            params![wrapper_length],
        )?;
        let before = raw_snapshot(&attacker)?;
        drop(attacker);

        assert!(store.commit(b"new").is_err());
        assert!(store.state().is_err());
        let verifier = Connection::open(&path)?;
        let after = raw_snapshot(&verifier)?;
        assert_eq!(after, before);
        Ok(())
    }

    #[test]
    fn nonce_or_ciphertext_substitution_cannot_be_committed_over()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for (name, tamper_nonce) in [("nonce.sqlite", true), ("ciphertext.sqlite", false)] {
            let path = database(&directory, name);
            let mut store = ClientStateStore::create_with_path(&path, TestProtector::new(27, 28), b"old")?;
            let attacker = Connection::open(&path)?;
            let column = if tamper_nonce { "nonce" } else { "ciphertext" };
            let query = format!("SELECT {column} FROM client_state WHERE slot = 1");
            let mut value = attacker.query_row(&query, [], |row| row.get::<_, Vec<u8>>(0))?;
            if let Some(first) = value.first_mut() {
                *first ^= 1;
            } else {
                return Err(Box::new(LabError::Storage));
            }
            let update = if tamper_nonce {
                "UPDATE client_state SET nonce = ?1 WHERE slot = 1"
            } else {
                "UPDATE client_state SET ciphertext = ?1 WHERE slot = 1"
            };
            attacker.execute(update, params![value])?;
            let before = raw_snapshot(&attacker)?;
            drop(attacker);

            assert!(store.commit(b"new").is_err());
            assert!(store.state().is_err());
            let verifier = Connection::open(&path)?;
            assert_eq!(raw_snapshot(&verifier)?, before);
        }
        Ok(())
    }

    #[test]
    fn divergent_commit_after_authentic_rollback_uses_a_fresh_nonce()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "rollback-nonce.sqlite");
        let snapshot = database(&directory, "generation-one.sqlite");
        let mut first_rng = TestRng {
            next: 1,
            fail: false,
        };
        let mut first = ClientStateStore::create_with_rng(
            &path,
            TestProtector::new(25, 26),
            b"one",
            &mut first_rng,
            None,
        )?;
        fs::copy(&path, &snapshot)?;
        first.commit_with_rng(b"first-generation-two", &mut first_rng)?;
        let first_nonce = first.connection.query_row(
            "SELECT nonce FROM client_state WHERE slot = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        drop(first);

        fs::copy(&snapshot, &path)?;
        let mut divergent = ClientStateStore::open_with_path(&path, TestProtector::new(25, 26))?;
        let mut second_rng = TestRng {
            next: 201,
            fail: false,
        };
        divergent.commit_with_rng(b"divergent-generation-two", &mut second_rng)?;
        let second_nonce = divergent.connection.query_row(
            "SELECT nonce FROM client_state WHERE slot = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        assert_eq!(divergent.generation()?, 2);
        assert_ne!(first_nonce, second_nonce);
        Ok(())
    }

    #[test]
    fn committed_nonce_corpus_is_unique() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "nonce-corpus.sqlite");
        let mut store = ClientStateStore::create_with_path(&path, TestProtector::new(33, 34), b"zero")?;
        let mut seen = HashSet::new();
        assert!(seen.insert(store.nonce.to_vec()));
        for generation in 2_u64..=128 {
            store.commit(&generation.to_be_bytes())?;
            assert!(seen.insert(store.nonce.to_vec()));
        }
        assert_eq!(store.generation()?, 128);
        Ok(())
    }

    #[test]
    fn exact_schema_rejects_extra_objects() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "state.sqlite");
        let store = ClientStateStore::create_with_path(&path, TestProtector::new(13, 14), b"state")?;
        drop(store);
        let connection = Connection::open(&path)?;
        connection.execute_batch("CREATE TABLE extra_state(value INTEGER) STRICT;")?;
        drop(connection);
        assert!(ClientStateStore::open_with_path(&path, TestProtector::new(13, 14)).is_err());
        Ok(())
    }

    type FullRow = (
        i64,
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );

    fn full_row(connection: &Connection) -> rusqlite::Result<FullRow> {
        connection.query_row(
            "SELECT slot, profile_id, generation, envelope_version, state_schema_version, \
             crypto_suite, key_ref, wrapped_dek, nonce, ciphertext FROM client_state \
             WHERE slot = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
    }

    fn bump_schema_version(
        connection: &Connection,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let version =
            connection.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))?;
        connection.pragma_update(None, "schema_version", version + 1)?;
        Ok(())
    }

    fn inject_hostile_schema_row(
        path: &Path,
        kind: &str,
        name: &str,
        tbl_name: &str,
        sql: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA writable_schema = ON;")?;
        connection.execute(
            "INSERT INTO sqlite_schema(type, name, tbl_name, rootpage, sql) \
             VALUES (?1, ?2, ?3, 0, ?4)",
            params![kind, name, tbl_name, sql],
        )?;
        bump_schema_version(&connection)?;
        connection.execute_batch("PRAGMA writable_schema = OFF;")?;
        Ok(())
    }

    fn assert_open_rejects_and_row_is_intact(
        path: &Path,
        protector: TestProtector,
        before: &FullRow,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            ClientStateStore::open_with_path(path, protector),
            Err(LabError::Storage)
        ));
        let verifier = Connection::open(path)?;
        assert_eq!(&full_row(&verifier)?, before);
        let rows = verifier.query_row("SELECT COUNT(*) FROM client_state", [], |row| {
            row.get::<_, i64>(0)
        })?;
        assert_eq!(rows, 1);
        Ok(())
    }

    #[test]
    fn hostile_sqlite_prefixed_delete_trigger_fails_closed_without_data_loss()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "evil-delete-trigger.sqlite");
        let mut store = ClientStateStore::create_with_path(&path, TestProtector::new(41, 42), b"guarded")?;
        let inspector = Connection::open(&path)?;
        let before = full_row(&inspector)?;
        drop(inspector);
        inject_hostile_schema_row(
            &path,
            "trigger",
            "sqlite_evil",
            "client_state",
            "CREATE TRIGGER sqlite_evil AFTER UPDATE ON client_state \
             BEGIN DELETE FROM client_state; END",
        )?;

        assert_open_rejects_and_row_is_intact(&path, TestProtector::new(41, 42), &before)?;
        // The pre-injection handle revalidates the whole schema inside its
        // commit transaction, so the executable DELETE trigger can never ride
        // a successful commit to an empty table.
        assert!(store.commit(b"post-injection").is_err());
        let verifier = Connection::open(&path)?;
        assert_eq!(full_row(&verifier)?, before);
        Ok(())
    }

    #[test]
    fn hostile_sqlite_prefixed_raise_ignore_trigger_fails_closed()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "evil-ignore-trigger.sqlite");
        drop(ClientStateStore::create_with_path(
            &path,
            TestProtector::new(43, 44),
            b"guarded",
        )?);
        let inspector = Connection::open(&path)?;
        let before = full_row(&inspector)?;
        drop(inspector);
        inject_hostile_schema_row(
            &path,
            "trigger",
            "sqlite_evil",
            "client_state",
            "CREATE TRIGGER sqlite_evil BEFORE UPDATE ON client_state \
             BEGIN SELECT RAISE(IGNORE); END",
        )?;

        assert_open_rejects_and_row_is_intact(&path, TestProtector::new(43, 44), &before)
    }

    #[test]
    fn hostile_sqlite_prefixed_view_fails_closed()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "evil-view.sqlite");
        drop(ClientStateStore::create_with_path(
            &path,
            TestProtector::new(45, 46),
            b"guarded",
        )?);
        let inspector = Connection::open(&path)?;
        let before = full_row(&inspector)?;
        drop(inspector);
        inject_hostile_schema_row(
            &path,
            "view",
            "sqlite_evil_view",
            "sqlite_evil_view",
            "CREATE VIEW sqlite_evil_view AS SELECT slot FROM client_state",
        )?;

        assert_open_rejects_and_row_is_intact(&path, TestProtector::new(45, 46), &before)
    }

    #[test]
    fn hostile_sqlite_prefixed_table_with_valid_root_page_fails_closed()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "evil-table.sqlite");
        drop(ClientStateStore::create_with_path(
            &path,
            TestProtector::new(47, 48),
            b"guarded",
        )?);
        let inspector = Connection::open(&path)?;
        let before = full_row(&inspector)?;
        drop(inspector);
        // A reserved-name table cannot be created through DDL, so create an
        // ordinary table first and rename its schema entry and SQL through
        // writable_schema; it keeps a valid allocated root page.
        let injector = Connection::open(&path)?;
        injector.execute_batch("CREATE TABLE hostile_placeholder(payload INTEGER);")?;
        injector.execute_batch("PRAGMA writable_schema = ON;")?;
        injector.execute(
            "UPDATE sqlite_schema SET name = 'sqlite_evil_table', \
             tbl_name = 'sqlite_evil_table', \
             sql = 'CREATE TABLE sqlite_evil_table(payload INTEGER)' \
             WHERE name = 'hostile_placeholder'",
            [],
        )?;
        bump_schema_version(&injector)?;
        injector.execute_batch("PRAGMA writable_schema = OFF;")?;
        drop(injector);

        assert_open_rejects_and_row_is_intact(&path, TestProtector::new(47, 48), &before)
    }

    #[test]
    fn strict_whole_schema_validation_accepts_the_clean_store()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "clean-control.sqlite");
        drop(ClientStateStore::create_with_path(
            &path,
            TestProtector::new(49, 50),
            b"first",
        )?);
        let mut store = ClientStateStore::open_with_path(&path, TestProtector::new(49, 50))?;
        store.commit(b"second")?;
        drop(store);
        let store = ClientStateStore::open_with_path(&path, TestProtector::new(49, 50))?;
        assert_eq!(store.state()?, b"second");
        assert_eq!(store.generation()?, 2);
        Ok(())
    }

    #[test]
    fn oversized_blobs_are_refused_by_length_before_materialization()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for (name, oversized_wrapper) in [("wrapper.sqlite", true), ("ciphertext.sqlite", false)] {
            let path = database(&directory, name);
            let store = ClientStateStore::create_with_path(&path, TestProtector::new(29, 30), b"state")?;
            let binding = store.binding()?;
            drop(store);
            let connection = Connection::open(&path)?;
            connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
            if oversized_wrapper {
                connection.execute(
                    "UPDATE client_state SET wrapped_dek = zeroblob(?1) WHERE slot = 1",
                    params![i64::try_from(WRAPPED_DEK_MAX_BYTES + 1)?],
                )?;
            } else {
                connection.execute(
                    "UPDATE client_state SET ciphertext = zeroblob(?1) WHERE slot = 1",
                    params![i64::try_from(MAX_CIPHERTEXT_BYTES + 1)?],
                )?;
            }
            assert!(matches!(
                read_row(&connection, binding),
                Err(LabError::Storage)
            ));
        }
        Ok(())
    }

    #[test]
    fn cas_conflict_poisons_the_stale_handle() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let path = database(&directory, "state.sqlite");
        let mut first = ClientStateStore::create_with_path(&path, TestProtector::new(11, 12), b"one")?;
        let second = ClientStateStore::open_with_path(&path, TestProtector::new(11, 12))?;
        first.commit(b"two")?;
        let mut stale = second;
        assert!(stale.commit(b"three").is_err());
        assert!(stale.commit(b"four").is_err());
        assert!(stale.state().is_err());
        assert!(stale.generation().is_err());
        assert!(stale.binding().is_err());
        assert_eq!(
            ClientStateStore::open_with_path(&path, TestProtector::new(11, 12))?.state()?,
            b"two"
        );
        Ok(())
    }

    #[test]
    fn private_dir_create_open_round_trip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store_path = directory.path().join("state-store");
        let dir = PrivateStoreDir::create(&store_path, crate::StoreKind::ClientState)?;
        let mut store = ClientStateStore::create(dir, TestProtector::new(71, 72), b"secured")?;
        store.commit(b"secured-two")?;
        drop(store);

        // Grace helper for the macOS vnode release lag: this is an
        // immediate drop-then-reopen, not a contention assertion.
        let dir = crate::private_store_dir::open_with_release_grace(
            &store_path,
            crate::StoreKind::ClientState,
        )?;
        let reopened = ClientStateStore::open(dir, TestProtector::new(71, 72))?;
        assert_eq!(reopened.state()?, b"secured-two");
        assert_eq!(reopened.generation()?, 2);
        Ok(())
    }

    #[test]
    fn private_dir_split_create_from_open() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        // Create over an existing database refuses.
        let store_path = directory.path().join("occupied");
        let dir = PrivateStoreDir::create(&store_path, crate::StoreKind::ClientState)?;
        drop(ClientStateStore::create(dir, TestProtector::new(73, 74), b"one")?);
        let dir = crate::private_store_dir::open_with_release_grace(
            &store_path,
            crate::StoreKind::ClientState,
        )?;
        assert!(ClientStateStore::create(dir, TestProtector::new(73, 74), b"two").is_err());

        // Open without a database refuses.
        let empty_path = directory.path().join("empty");
        let dir = PrivateStoreDir::create(&empty_path, crate::StoreKind::ClientState)?;
        assert!(ClientStateStore::open(dir, TestProtector::new(73, 74)).is_err());
        Ok(())
    }

    #[test]
    fn store_holds_the_lifecycle_lock() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store_path = directory.path().join("locked");
        let dir = PrivateStoreDir::create(&store_path, crate::StoreKind::ClientState)?;
        let store = ClientStateStore::create(dir, TestProtector::new(75, 76), b"held")?;

        assert!(PrivateStoreDir::open(&store_path, crate::StoreKind::ClientState).is_err());

        drop(store);
        assert!(
            crate::private_store_dir::open_with_release_grace(
                &store_path,
                crate::StoreKind::ClientState,
            )
            .is_ok()
        );
        Ok(())
    }
}
