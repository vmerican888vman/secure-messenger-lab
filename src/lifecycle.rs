//! The platform-key lifecycle manager (frozen design
//! docs/phase2-design-decisions.md §4, "Platform-key lifecycle").
//!
//! The manager sits BETWEEN the platform key store (modeled behind the
//! [`StateKeyProtector`] trait) and the façade: it owns the durable
//! registry of key state (its own tiny `SQLite` database inside its own
//! [`PrivateStoreDir`], `StoreKind::Lifecycle`) and drives create,
//! recovery and delete. It vends decisions; it does not replace the
//! façade, and it never holds a live profile store beyond an operation.
//!
//! Durable states: `Absent` (no registry row), `Provisional`,
//! `Expected`, `Locked`, `Deleting`. Every transition runs under the
//! exclusive lifecycle lock (the registry directory's `PrivateStoreDir`
//! lock, held for the manager's lifetime) with an exact-state CAS:
//! `UPDATE ... WHERE <every prior-state field>` with a changed-row check,
//! mirroring the store's generation CAS.
//!
//! # Mapping of the frozen text
//!
//! - **Create** (`create_profile`): refuse if any registry row exists (no
//!   replacement profile, including while `Deleting`); mint random
//!   never-reused `profile_id`/`key_ref` (the harness's aliases — recorded
//!   forever in the `lifecycle_spent_refs` table); `provision_key` the
//!   platform key; insert the `Provisional` row; create the client store
//!   (which wraps the DEK under `state-wrap/v1` + profile ID + key
//!   reference inside `ClientStateStore::create`) writing generation 1;
//!   drop and reopen the store, fully authenticate it, and parse +
//!   validate the payload (`ClientStateV1::decode`) using the provisional
//!   handle; CAS `Provisional -> Expected`; return `Promoted`. Only after
//!   this returns may a façade expose identity, registration or prekey
//!   material.
//! - **Recovery** (`recover`): `Provisional` + absent database ⇒
//!   `ProvisioningInterrupted` with no automatic deletion (registry
//!   untouched); `Provisional` + authentic generation 1 ⇒ promote;
//!   `Provisional` + present-but-unauthentic or generation-mismatched
//!   database ⇒ `Locked` (`DatabaseUnauthentic` / `ProvisioningMismatch`);
//!   `Expected` + missing database ⇒ `Locked(DatabaseMissing)`, + corrupt
//!   or unauthentic database ⇒ `Locked(DatabaseUnauthentic)`, + missing
//!   key ⇒ `Locked(KeyMissing)` — and never creates a replacement;
//!   `Expected` + temporarily locked platform ⇒ `Locked(
//!   PlatformTemporarilyLocked)` returned WITHOUT persisting it — the
//!   registry, key and database stay exactly as they were (there is no
//!   live DEK or crypto at this layer to discard; any live store handle
//!   is impossible while the caller holds the store directory lock).
//! - **Delete/reset** (`destructive_reset`): requires the explicit
//!   [`DestructiveResetAuth`] phrase token (no `Default`, no
//!   `Deserialize`; real confirmation UI is out of scope for the
//!   harness); CAS from `Expected` or `Locked` to `Deleting` with a fresh reset
//!   ID; delete the exact platform key first; delete exactly the main
//!   database and the three allowed companions inside the still-locked
//!   store directory and fsync it (`PrivateStoreDir` holds no live
//!   profile handle — its exclusive lock is precisely what proves none
//!   exists); remove the registry row. A failure after the CAS leaves
//!   `Deleting` and a later call resumes idempotently; `create_profile`
//!   refuses while any row, including `Deleting`, exists.
//! - **Abandon** (`abandon_provisional`): only with the exact
//!   provisioning token, the lock held (structural), the state still
//!   `Provisional`, and the token presentation itself as the explicit
//!   confirmation. Deletes the platform key, any partial database, and
//!   the row. No age-based or database-missing automatic cleanup exists.
//!
//! # Deviations (for review)
//!
//! - **`StateKeyProtector` gained four required methods**
//!   (`provision_key`, `key_status`, `select_binding`, `delete_key`): the
//!   trait predates the manager and had no key lifecycle operations. All
//!   existing test-only implementors were updated (fail-closed stubs);
//!   the brief sanctioned this.
//! - **`P: Clone` on the manager.** `ClientStateStore::create/open`
//!   consume the protector by value, so the manager clones its platform
//!   handle to vend per-operation handles. `Clone` here models "another
//!   handle to the same platform adapter", never a key copy — the test
//!   platform is a shared registry behind `Rc<RefCell<_>>`.
//! - **Aliases**: the random `profile_id` and `key_ref` are the harness's
//!   aliases/references; never-reuse is enforced by the permanent
//!   `lifecycle_spent_refs` table.
//! - **The registry is non-secret** by design (profile IDs, key
//!   references, protection levels, reasons), so it lives unencrypted
//!   under the private-directory boundary with exact-schema validation;
//!   integrity comes from the boundary, the CAS discipline, and `SQLite`
//!   `synchronous = FULL`.
//! - **`ProvisionOutcome::ProvisionalCreated` is reserved**: `create`
//!   is synchronous from the caller's view and returns `Promoted` on
//!   success; an interrupted create is observed through `recover`.

use std::marker::PhantomData;
use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::persistence::{
    ClientStateStore, KeyStatus, ProfileBinding, ProtectionLevel, StateKeyProtector,
};
use crate::private_store_dir::{MainDatabase, PrivateStoreDir, StoreKind};
use crate::state::ClientStateV1;
use crate::{LabError, Result};

const TAG_PROVISIONAL: i64 = 1;
const TAG_EXPECTED: i64 = 2;
const TAG_LOCKED: i64 = 3;
const TAG_DELETING: i64 = 4;

const REASON_DATABASE_UNAUTHENTIC: i64 = 1;
const REASON_DATABASE_MISSING: i64 = 2;
const REASON_KEY_MISSING: i64 = 3;
const REASON_PLATFORM_TEMPORARILY_LOCKED: i64 = 4;
const REASON_PROVISIONING_MISMATCH: i64 = 5;

// The exact-schema contract: whitespace is part of it, as in the store.
const PROFILES_SQL: &str = "CREATE TABLE lifecycle_profiles (\
    slot               INTEGER PRIMARY KEY NOT NULL CHECK(slot = 1),\
    profile_id           BLOB NOT NULL CHECK(length(profile_id) = 16),\
    state_tag            INTEGER NOT NULL CHECK(state_tag BETWEEN 1 AND 4),\
    provisioning_id      BLOB CHECK(provisioning_id IS NULL OR length(provisioning_id) = 16),\
    key_ref              BLOB NOT NULL CHECK(length(key_ref) = 16),\
    protection_level     INTEGER NOT NULL CHECK(protection_level BETWEEN 1 AND 4),\
    reason               INTEGER CHECK(reason IS NULL OR reason BETWEEN 1 AND 5),\
    reset_id             BLOB CHECK(reset_id IS NULL OR length(reset_id) = 16)\
) STRICT";

const SPENT_REFS_SQL: &str = "CREATE TABLE lifecycle_spent_refs (\
    key_ref BLOB PRIMARY KEY CHECK(length(key_ref) = 16)\
) STRICT";

const REGISTRY_SLOT: i64 = 1;

/// Why a profile is locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// The database is present but does not authenticate.
    DatabaseUnauthentic,
    /// The database is missing (or empty) where one must exist.
    DatabaseMissing,
    /// The platform key is gone.
    KeyMissing,
    /// The platform is temporarily locked; retryable, and never persisted
    /// — registry, key and database are left untouched.
    PlatformTemporarilyLocked,
    /// A provisional registry entry does not match the database found.
    ProvisioningMismatch,
}

/// The manager's decision after a create or recovery drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionOutcome {
    /// Reserved for a split-phase create; the synchronous
    /// `create_profile` returns `Promoted` on success.
    ProvisionalCreated,
    /// A create completed, or a provisional entry with an authentic
    /// generation-1 database was promoted to `Expected`.
    Promoted,
    /// Provisional entry with no database: provisioning was interrupted.
    /// Nothing is deleted automatically.
    ProvisioningInterrupted,
    /// The profile is locked; the reason says which arm fired.
    Locked(LockReason),
    /// An `Expected` profile's database and key authenticated.
    ExpectedReady,
}

/// An owned view of the durable lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Absent,
    Provisional {
        provisioning_id: [u8; 16],
        profile_id: [u8; 16],
        key_ref: [u8; 16],
        protection_level: ProtectionLevel,
    },
    Expected {
        profile_id: [u8; 16],
        key_ref: [u8; 16],
        protection_level: ProtectionLevel,
    },
    Locked {
        profile_id: [u8; 16],
        key_ref: [u8; 16],
        reason: LockReason,
    },
    Deleting {
        reset_id: [u8; 16],
        profile_id: [u8; 16],
        key_ref: [u8; 16],
    },
}

/// Explicit destructive-reset authorization. Constructible only by
/// presenting the exact confirmation phrase; no `Default`, no
/// `Deserialize`, no accidental construction. Real user-confirmation UI
/// is out of scope for this harness.
#[derive(Debug, Clone, Copy)]
pub struct DestructiveResetAuth(());

const DESTRUCTIVE_RESET_PHRASE: &str = "permanently delete this profile";

impl DestructiveResetAuth {
    #[must_use]
    pub fn confirm(phrase: &str) -> Option<Self> {
        if phrase == DESTRUCTIVE_RESET_PHRASE {
            Some(Self(()))
        } else {
            None
        }
    }
}

struct RegistryRow {
    profile_id: [u8; 16],
    key_ref: [u8; 16],
    protection_level: ProtectionLevel,
    state: RowState,
}

#[derive(Clone, Copy)]
enum RowState {
    Provisional { provisioning_id: [u8; 16] },
    Expected,
    Locked { reason: LockReason },
    Deleting { reset_id: [u8; 16] },
}

/// The platform-key lifecycle manager. Not `Clone` and not `Sync` (the
/// registry connection plus the marker); owned by a single actor, like
/// the façade.
pub struct LifecycleManager<P: StateKeyProtector> {
    connection: Connection,
    platform: P,
    _dir: PrivateStoreDir,
    _not_sync: PhantomData<*mut ()>,
}

impl<P: StateKeyProtector + Clone> LifecycleManager<P> {
    /// Open (or initialize) the lifecycle registry inside its secured
    /// private directory, holding the directory's exclusive lifecycle lock
    /// for the manager's lifetime.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error on any boundary violation, an
    /// unexpected registry schema, or a corrupt registry.
    pub fn open(dir: PrivateStoreDir, platform: P) -> Result<Self> {
        if dir.kind() != StoreKind::Lifecycle {
            return Err(LabError::Storage);
        }
        let database = dir.database_path();
        match dir.main_database_at_open() {
            MainDatabase::Absent => {
                dir.create_main_database_file()?;
                let mut connection = Connection::open(&database).map_err(|_| LabError::Storage)?;
                activate(&connection)?;
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|_| LabError::Storage)?;
                transaction
                    .execute_batch(&format!("{PROFILES_SQL};{SPENT_REFS_SQL};"))
                    .map_err(|_| LabError::Storage)?;
                transaction.commit().map_err(|_| LabError::Storage)?;
                validate_registry_schema(&connection)?;
                return Ok(Self {
                    connection,
                    platform,
                    _dir: dir,
                    _not_sync: PhantomData,
                });
            }
            MainDatabase::Empty => return Err(LabError::Storage),
            MainDatabase::Present => {}
        }
        let connection = Connection::open(&database).map_err(|_| LabError::Storage)?;
        activate(&connection)?;
        validate_registry_schema(&connection)?;
        Ok(Self {
            connection,
            platform,
            _dir: dir,
            _not_sync: PhantomData,
        })
    }

    /// The full create sequence; see the module docs for the mapping.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when a profile already exists (any
    /// registry row, including `Deleting`), the platform cannot provision
    /// the key, or a store step fails. A failure leaves the registry
    /// `Provisional` for `recover` to resolve.
    pub fn create_profile(
        &mut self,
        store_dir: PrivateStoreDir,
        initial_state: &[u8],
    ) -> Result<ProvisionOutcome> {
        if self.read_row()?.is_some() {
            // No replacement profile while any row exists.
            return Err(LabError::Storage);
        }
        let store_path = store_path_of(&store_dir)?;
        let binding = self.mint_binding()?;
        self.platform.provision_key(binding)?;
        let provisioning_id = random_id();
        let row = RegistryRow {
            profile_id: *binding.profile_id(),
            key_ref: *binding.key_ref(),
            protection_level: self.platform.protection_level(),
            state: RowState::Provisional { provisioning_id },
        };
        self.insert_row(&row)?;
        // Wrap the DEK (state-wrap/v1 + profile ID + key reference, inside
        // the store's create) and write generation 1.
        let store = ClientStateStore::create(store_dir, self.platform.clone(), initial_state)?;
        drop(store);
        // Reopen and fully authenticate, parse and validate using the
        // provisional handle. A transient boundary failure here leaves the
        // row Provisional; recover() completes the promotion.
        //
        // The reopen immediately follows a drop, so on macOS the strictly
        // non-blocking lifecycle lock can transiently report contention
        // (vnode release lag, documented in the boundary's module docs —
        // fail-closed and caller-retryable). This manager IS the caller,
        // so it retries briefly; a persistent failure still fails closed
        // and leaves the row Provisional.
        let reopened_dir = open_dir_with_grace(&store_path)?;
        let store = ClientStateStore::open(reopened_dir, self.platform.clone())?;
        if store.generation()? != 1 {
            return Err(LabError::Storage);
        }
        let _validated = ClientStateV1::decode(store.state()?)?;
        self.cas_to_expected(&row, provisioning_id)?;
        Ok(ProvisionOutcome::Promoted)
    }

    /// The recovery arms; see the module docs for the mapping.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error when the registry has no profile or
    /// is `Deleting` (complete the reset first), or a platform query
    /// fails.
    pub fn recover(&mut self, store_dir: PrivateStoreDir) -> Result<ProvisionOutcome> {
        let Some(row) = self.read_row()? else {
            return Err(LabError::Storage);
        };
        match row.state {
            RowState::Provisional { provisioning_id } => {
                self.recover_provisional(&row, provisioning_id, store_dir)
            }
            RowState::Expected => self.recover_expected(&row, store_dir),
            RowState::Locked { reason } => Ok(ProvisionOutcome::Locked(reason)),
            RowState::Deleting { .. } => Err(LabError::Storage),
        }
    }

    // The directory arrives by value deliberately: the recovery arm that
    // opens the store consumes the locked handle.
    #[allow(clippy::needless_pass_by_value)]
    fn recover_provisional(
        &mut self,
        row: &RegistryRow,
        provisioning_id: [u8; 16],
        store_dir: PrivateStoreDir,
    ) -> Result<ProvisionOutcome> {
        match store_dir.main_database_at_open() {
            MainDatabase::Absent => {
                drop(store_dir);
                // No automatic deletion: the row stays Provisional.
                Ok(ProvisionOutcome::ProvisioningInterrupted)
            }
            MainDatabase::Empty => {
                drop(store_dir);
                self.cas_to_locked(row, LockReason::DatabaseUnauthentic)?;
                Ok(ProvisionOutcome::Locked(LockReason::DatabaseUnauthentic))
            }
            MainDatabase::Present => {
                self.platform.select_binding(binding_of(row))?;
                if let Ok(store) = ClientStateStore::open(store_dir, self.platform.clone()) {
                    if store.generation()? == 1 && ClientStateV1::decode(store.state()?).is_ok() {
                        self.cas_to_expected(row, provisioning_id)?;
                        Ok(ProvisionOutcome::Promoted)
                    } else {
                        self.cas_to_locked(row, LockReason::ProvisioningMismatch)?;
                        Ok(ProvisionOutcome::Locked(LockReason::ProvisioningMismatch))
                    }
                } else {
                    self.cas_to_locked(row, LockReason::DatabaseUnauthentic)?;
                    Ok(ProvisionOutcome::Locked(LockReason::DatabaseUnauthentic))
                }
            }
        }
    }

    // See recover_provisional for the by-value directory.
    #[allow(clippy::needless_pass_by_value)]
    fn recover_expected(
        &mut self,
        row: &RegistryRow,
        store_dir: PrivateStoreDir,
    ) -> Result<ProvisionOutcome> {
        match self.platform.key_status(binding_of(row))? {
            KeyStatus::Missing => {
                self.cas_to_locked(row, LockReason::KeyMissing)?;
                return Ok(ProvisionOutcome::Locked(LockReason::KeyMissing));
            }
            KeyStatus::TemporarilyLocked => {
                // Retryable: registry, key and database are not changed.
                return Ok(ProvisionOutcome::Locked(
                    LockReason::PlatformTemporarilyLocked,
                ));
            }
            KeyStatus::Present => {}
        }
        match store_dir.main_database_at_open() {
            MainDatabase::Absent | MainDatabase::Empty => {
                drop(store_dir);
                self.cas_to_locked(row, LockReason::DatabaseMissing)?;
                Ok(ProvisionOutcome::Locked(LockReason::DatabaseMissing))
            }
            MainDatabase::Present => {
                self.platform.select_binding(binding_of(row))?;
                if let Ok(store) = ClientStateStore::open(store_dir, self.platform.clone()) {
                    if store.generation()? >= 1 && ClientStateV1::decode(store.state()?).is_ok() {
                        Ok(ProvisionOutcome::ExpectedReady)
                    } else {
                        self.cas_to_locked(row, LockReason::DatabaseUnauthentic)?;
                        Ok(ProvisionOutcome::Locked(LockReason::DatabaseUnauthentic))
                    }
                } else {
                    self.cas_to_locked(row, LockReason::DatabaseUnauthentic)?;
                    Ok(ProvisionOutcome::Locked(LockReason::DatabaseUnauthentic))
                }
            }
        }
    }

    /// The delete sequence; see the module docs for the mapping. Resumes
    /// idempotently from `Deleting`.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error without the authorization phrase,
    /// when no resettable profile exists (Absent or `Provisional` — use
    /// `abandon_provisional`), or when a step fails (the row stays
    /// `Deleting` and a later call resumes).
    // The locked store directory is owned for the duration of the delete.
    #[allow(clippy::needless_pass_by_value)]
    pub fn destructive_reset(
        &mut self,
        auth: DestructiveResetAuth,
        store_dir: PrivateStoreDir,
    ) -> Result<()> {
        let DestructiveResetAuth(()) = auth;
        let Some(row) = self.read_row()? else {
            return Err(LabError::Storage);
        };
        let reset_id = match row.state {
            RowState::Expected | RowState::Locked { .. } => {
                let reset_id = random_id();
                self.cas_to_deleting(&row, reset_id)?;
                reset_id
            }
            RowState::Deleting { reset_id } => reset_id,
            RowState::Provisional { .. } => return Err(LabError::Storage),
        };
        // Delete the exact platform key first; any failure leaves Deleting.
        self.platform.delete_key(binding_of(&row))?;
        // Then the exact database and allowed companions, synced, inside
        // the still-locked store directory.
        store_dir.delete_database_and_companions_synced()?;
        // Then the registry row.
        self.delete_row_deleting(&row, reset_id)?;
        Ok(())
    }

    /// Abandon a provisional profile: exact provisioning token, lock held
    /// (structural), state still `Provisional`, the token presentation
    /// being the explicit confirmation. Deletes the platform key, any
    /// partial database, and the row.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error for a wrong token, a non-provisional
    /// or absent row, or a failed delete step.
    // The locked store directory is owned for the duration of the delete.
    #[allow(clippy::needless_pass_by_value)]
    pub fn abandon_provisional(
        &mut self,
        token: [u8; 16],
        store_dir: PrivateStoreDir,
    ) -> Result<()> {
        let Some(row) = self.read_row()? else {
            return Err(LabError::Storage);
        };
        let RowState::Provisional { provisioning_id } = row.state else {
            return Err(LabError::Storage);
        };
        if provisioning_id != token {
            return Err(LabError::Storage);
        }
        self.platform.delete_key(binding_of(&row))?;
        store_dir.delete_database_and_companions_synced()?;
        self.delete_row_provisional(&row, provisioning_id)?;
        Ok(())
    }

    /// An owned view of the durable lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns a coarse storage error on a corrupt registry.
    pub fn state(&self) -> Result<LifecycleState> {
        let Some(row) = self.read_row()? else {
            return Ok(LifecycleState::Absent);
        };
        Ok(match row.state {
            RowState::Provisional { provisioning_id } => LifecycleState::Provisional {
                provisioning_id,
                profile_id: row.profile_id,
                key_ref: row.key_ref,
                protection_level: row.protection_level,
            },
            RowState::Expected => LifecycleState::Expected {
                profile_id: row.profile_id,
                key_ref: row.key_ref,
                protection_level: row.protection_level,
            },
            RowState::Locked { reason } => LifecycleState::Locked {
                profile_id: row.profile_id,
                key_ref: row.key_ref,
                reason,
            },
            RowState::Deleting { reset_id } => LifecycleState::Deleting {
                reset_id,
                profile_id: row.profile_id,
                key_ref: row.key_ref,
            },
        })
    }

    /// Mint a fresh random binding whose key reference has never been used
    /// (recorded permanently in `lifecycle_spent_refs`).
    fn mint_binding(&mut self) -> Result<ProfileBinding> {
        let key_ref = random_id();
        let inserted = self
            .connection
            .execute(
                "INSERT INTO lifecycle_spent_refs(key_ref) VALUES (?1)",
                params![key_ref.as_slice()],
            )
            .map_err(|_| LabError::Storage)?;
        if inserted != 1 {
            return Err(LabError::Storage);
        }
        Ok(ProfileBinding::new(random_id(), key_ref))
    }

    fn read_row(&self) -> Result<Option<RegistryRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT profile_id, state_tag, provisioning_id, key_ref, protection_level, \
                 reason, reset_id FROM lifecycle_profiles",
            )
            .map_err(|_| LabError::Storage)?;
        let rows = statement
            .query_map([], |sql_row| {
                Ok((
                    sql_row.get::<_, Vec<u8>>(0)?,
                    sql_row.get::<_, i64>(1)?,
                    sql_row.get::<_, Option<Vec<u8>>>(2)?,
                    sql_row.get::<_, Vec<u8>>(3)?,
                    sql_row.get::<_, i64>(4)?,
                    sql_row.get::<_, Option<i64>>(5)?,
                    sql_row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            })
            .map_err(|_| LabError::Storage)?;
        let mut parsed = Vec::new();
        for row in rows {
            parsed.push(parse_row(row.map_err(|_| LabError::Storage)?)?);
        }
        if parsed.len() > 1 {
            return Err(LabError::Storage);
        }
        Ok(parsed.into_iter().next())
    }

    fn insert_row(&mut self, row: &RegistryRow) -> Result<()> {
        let RowState::Provisional { provisioning_id } = row.state else {
            return Err(LabError::Storage);
        };
        let changed = self
            .connection
            .execute(
                "INSERT INTO lifecycle_profiles(slot, profile_id, state_tag, provisioning_id, \
                 key_ref, protection_level, reason, reset_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL)",
                params![
                    REGISTRY_SLOT,
                    row.profile_id.as_slice(),
                    TAG_PROVISIONAL,
                    provisioning_id.as_slice(),
                    row.key_ref.as_slice(),
                    level_code(row.protection_level),
                ],
            )
            .map_err(|_| LabError::Storage)?;
        if changed != 1 {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    /// Exact-state CAS: `Provisional` -> `Expected`.
    fn cas_to_expected(&mut self, row: &RegistryRow, provisioning_id: [u8; 16]) -> Result<()> {
        let changed = self
            .connection
            .execute(
                "UPDATE lifecycle_profiles SET state_tag = ?1, provisioning_id = NULL \
                 WHERE slot = ?2 AND profile_id = ?3 AND state_tag = ?4 AND provisioning_id = ?5 \
                 AND key_ref = ?6 AND protection_level = ?7 AND reason IS NULL AND reset_id IS NULL",
                params![
                    TAG_EXPECTED,
                    REGISTRY_SLOT,
                    row.profile_id.as_slice(),
                    TAG_PROVISIONAL,
                    provisioning_id.as_slice(),
                    row.key_ref.as_slice(),
                    level_code(row.protection_level),
                ],
            )
            .map_err(|_| LabError::Storage)?;
        if changed != 1 {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    /// Exact-state CAS: `Provisional`/`Expected` -> `Locked`.
    fn cas_to_locked(&mut self, row: &RegistryRow, reason: LockReason) -> Result<()> {
        let prior_tag = match row.state {
            RowState::Provisional { .. } => TAG_PROVISIONAL,
            RowState::Expected => TAG_EXPECTED,
            _ => return Err(LabError::Storage),
        };
        let changed = self
            .connection
            .execute(
                "UPDATE lifecycle_profiles SET state_tag = ?1, reason = ?2, provisioning_id = NULL \
                 WHERE slot = ?3 AND profile_id = ?4 AND state_tag = ?5 \
                 AND key_ref = ?6 AND protection_level = ?7 AND reason IS NULL AND reset_id IS NULL",
                params![
                    TAG_LOCKED,
                    reason_code(reason),
                    REGISTRY_SLOT,
                    row.profile_id.as_slice(),
                    prior_tag,
                    row.key_ref.as_slice(),
                    level_code(row.protection_level),
                ],
            )
            .map_err(|_| LabError::Storage)?;
        if changed != 1 {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    /// Exact-state CAS: `Expected`/`Locked` -> `Deleting` with a fresh
    /// reset ID.
    fn cas_to_deleting(&mut self, row: &RegistryRow, reset_id: [u8; 16]) -> Result<()> {
        let (prior_tag, prior_reason) = match row.state {
            RowState::Expected => (TAG_EXPECTED, None),
            RowState::Locked { reason } => (TAG_LOCKED, Some(reason_code(reason))),
            _ => return Err(LabError::Storage),
        };
        let changed = self
            .connection
            .execute(
                "UPDATE lifecycle_profiles SET state_tag = ?1, reset_id = ?2 \
                 WHERE slot = ?3 AND profile_id = ?4 AND state_tag = ?5 \
                 AND key_ref = ?6 AND protection_level = ?7 AND provisioning_id IS NULL \
                 AND ((?8 AND reason IS NULL) OR (NOT ?8 AND reason = ?9)) AND reset_id IS NULL",
                params![
                    TAG_DELETING,
                    reset_id.as_slice(),
                    REGISTRY_SLOT,
                    row.profile_id.as_slice(),
                    prior_tag,
                    row.key_ref.as_slice(),
                    level_code(row.protection_level),
                    prior_reason.is_none(),
                    prior_reason,
                ],
            )
            .map_err(|_| LabError::Storage)?;
        if changed != 1 {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    fn delete_row_deleting(&mut self, row: &RegistryRow, reset_id: [u8; 16]) -> Result<()> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM lifecycle_profiles WHERE slot = ?1 AND profile_id = ?2 \
                 AND state_tag = ?3 AND reset_id = ?4",
                params![
                    REGISTRY_SLOT,
                    row.profile_id.as_slice(),
                    TAG_DELETING,
                    reset_id.as_slice()
                ],
            )
            .map_err(|_| LabError::Storage)?;
        if changed != 1 {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    fn delete_row_provisional(
        &mut self,
        row: &RegistryRow,
        provisioning_id: [u8; 16],
    ) -> Result<()> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM lifecycle_profiles WHERE slot = ?1 AND profile_id = ?2 \
                 AND state_tag = ?3 AND provisioning_id = ?4",
                params![
                    REGISTRY_SLOT,
                    row.profile_id.as_slice(),
                    TAG_PROVISIONAL,
                    provisioning_id.as_slice()
                ],
            )
            .map_err(|_| LabError::Storage)?;
        if changed != 1 {
            return Err(LabError::Storage);
        }
        Ok(())
    }
}

type RawRow = (
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Vec<u8>,
    i64,
    Option<i64>,
    Option<Vec<u8>>,
);

fn parse_row(raw: RawRow) -> Result<RegistryRow> {
    let (profile_id, tag, provisioning_id, key_ref, level, reason, reset_id) = raw;
    let profile_id: [u8; 16] = profile_id.try_into().map_err(|_| LabError::Storage)?;
    let key_ref: [u8; 16] = key_ref.try_into().map_err(|_| LabError::Storage)?;
    let protection_level = code_level(level)?;
    let state = match tag {
        TAG_PROVISIONAL => RowState::Provisional {
            provisioning_id: fixed_id(provisioning_id)?,
        },
        TAG_EXPECTED => RowState::Expected,
        TAG_LOCKED => RowState::Locked {
            reason: code_reason(reason.ok_or(LabError::Storage)?)?,
        },
        TAG_DELETING => RowState::Deleting {
            reset_id: fixed_id(reset_id)?,
        },
        _ => return Err(LabError::Storage),
    };
    Ok(RegistryRow {
        profile_id,
        key_ref,
        protection_level,
        state,
    })
}

fn fixed_id(value: Option<Vec<u8>>) -> Result<[u8; 16]> {
    let bytes = value.ok_or(LabError::Storage)?;
    bytes.try_into().map_err(|_| LabError::Storage)
}

fn binding_of(row: &RegistryRow) -> ProfileBinding {
    ProfileBinding::new(row.profile_id, row.key_ref)
}

fn level_code(level: ProtectionLevel) -> i64 {
    match level {
        ProtectionLevel::StrongBox => 1,
        ProtectionLevel::TrustedEnvironment => 2,
        ProtectionLevel::SoftwareBacked => 3,
        ProtectionLevel::Indeterminate => 4,
    }
}

fn code_level(code: i64) -> Result<ProtectionLevel> {
    match code {
        1 => Ok(ProtectionLevel::StrongBox),
        2 => Ok(ProtectionLevel::TrustedEnvironment),
        3 => Ok(ProtectionLevel::SoftwareBacked),
        4 => Ok(ProtectionLevel::Indeterminate),
        _ => Err(LabError::Storage),
    }
}

fn reason_code(reason: LockReason) -> i64 {
    match reason {
        LockReason::DatabaseUnauthentic => REASON_DATABASE_UNAUTHENTIC,
        LockReason::DatabaseMissing => REASON_DATABASE_MISSING,
        LockReason::KeyMissing => REASON_KEY_MISSING,
        LockReason::PlatformTemporarilyLocked => REASON_PLATFORM_TEMPORARILY_LOCKED,
        LockReason::ProvisioningMismatch => REASON_PROVISIONING_MISMATCH,
    }
}

fn code_reason(code: i64) -> Result<LockReason> {
    match code {
        REASON_DATABASE_UNAUTHENTIC => Ok(LockReason::DatabaseUnauthentic),
        REASON_DATABASE_MISSING => Ok(LockReason::DatabaseMissing),
        REASON_KEY_MISSING => Ok(LockReason::KeyMissing),
        REASON_PLATFORM_TEMPORARILY_LOCKED => Ok(LockReason::PlatformTemporarilyLocked),
        REASON_PROVISIONING_MISMATCH => Ok(LockReason::ProvisioningMismatch),
        _ => Err(LabError::Storage),
    }
}

fn random_id() -> [u8; 16] {
    let mut id = [0_u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    id
}

fn store_path_of(dir: &PrivateStoreDir) -> Result<PathBuf> {
    dir.database_path()
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or(LabError::Storage)
}

/// Bounded caller-side retry of a `ClientState` directory open after an
/// immediate drop-then-reopen; see `create_profile` for why this exists.
/// Roughly one second in 10 ms steps; the final attempt's error is the
/// returned one.
fn open_dir_with_grace(path: &std::path::Path) -> Result<PrivateStoreDir> {
    for _ in 0..100 {
        match PrivateStoreDir::open(path, StoreKind::ClientState) {
            Ok(dir) => return Ok(dir),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    PrivateStoreDir::open(path, StoreKind::ClientState)
}

fn activate(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            "
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            PRAGMA trusted_schema = OFF;
            ",
        )
        .map_err(|_| LabError::Storage)
}

fn validate_registry_schema(connection: &Connection) -> Result<()> {
    for (name, expected) in [
        ("lifecycle_profiles", PROFILES_SQL),
        ("lifecycle_spent_refs", SPENT_REFS_SQL),
    ] {
        let sql: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| LabError::Storage)?;
        if sql.as_deref() != Some(expected) {
            return Err(LabError::Storage);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::rc::Rc;

    use rusqlite::{Connection, params};
    use tempfile::TempDir;
    use vodozemac::Ed25519Keypair;
    use vodozemac::olm::Account;
    use zeroize::Zeroizing;

    use super::{
        DestructiveResetAuth, LifecycleManager, LifecycleState, LockReason, ProvisionOutcome,
    };
    use crate::persistence::{
        ClientStateStore, KeyStatus, ProfileBinding, ProtectionLevel, StateKeyProtector,
    };
    use crate::state::{ClientStateV1, RegistrationRecord};
    use crate::{
        ConversationId, LabError, MailboxRegistration, Nonce, PrivateStoreDir, QueueId, Result,
        StoreKind,
    };

    const NOW: u64 = 1_800_000_000;

    /// A controllable platform: a shared registry of keys behind
    /// `Rc<RefCell>`, so cloning the protector vends another handle to the
    /// same platform (never a key copy).
    struct PlatformInner {
        current: Option<ProfileBinding>,
        keys: Vec<ProfileBinding>,
        temporarily_locked: bool,
        fail_next_wrap: bool,
        fail_next_unwrap: bool,
    }

    #[derive(Clone)]
    struct TestPlatform {
        inner: Rc<RefCell<PlatformInner>>,
    }

    impl TestPlatform {
        fn new() -> Self {
            Self {
                inner: Rc::new(RefCell::new(PlatformInner {
                    current: None,
                    keys: Vec::new(),
                    temporarily_locked: false,
                    fail_next_wrap: false,
                    fail_next_unwrap: false,
                })),
            }
        }

        fn lose_key(&self, binding: ProfileBinding) {
            self.inner
                .borrow_mut()
                .keys
                .retain(|present| present != &binding);
        }

        fn key_count(&self) -> usize {
            self.inner.borrow().keys.len()
        }
    }

    impl StateKeyProtector for TestPlatform {
        fn expected_binding(&self) -> Result<ProfileBinding> {
            self.inner.borrow().current.ok_or(LabError::Storage)
        }

        fn protection_level(&self) -> ProtectionLevel {
            ProtectionLevel::SoftwareBacked
        }

        fn wrap_dek(&self, dek: &Zeroizing<[u8; 32]>) -> Result<Vec<u8>> {
            let mut inner = self.inner.borrow_mut();
            if inner.fail_next_wrap {
                inner.fail_next_wrap = false;
                return Err(LabError::Storage);
            }
            let binding = inner.current.ok_or(LabError::Storage)?;
            let mask = binding.key_ref()[0];
            let mut wrapped = b"state-wrap/v1".to_vec();
            wrapped.extend_from_slice(binding.profile_id());
            wrapped.extend_from_slice(binding.key_ref());
            wrapped.extend(dek.iter().map(|value| value ^ mask));
            Ok(wrapped)
        }

        fn unwrap_dek(&self, wrapped_dek: &[u8], output: &mut Zeroizing<[u8; 32]>) -> Result<()> {
            const PREFIX: &[u8] = b"state-wrap/v1";
            let mut inner = self.inner.borrow_mut();
            if inner.fail_next_unwrap {
                inner.fail_next_unwrap = false;
                return Err(LabError::Storage);
            }
            let expected = PREFIX.len() + 16 + 16 + 32;
            if wrapped_dek.len() != expected {
                return Err(LabError::Storage);
            }
            let profile_id: [u8; 16] = wrapped_dek[PREFIX.len()..PREFIX.len() + 16]
                .try_into()
                .map_err(|_| LabError::Storage)?;
            let key_ref: [u8; 16] = wrapped_dek[PREFIX.len() + 16..PREFIX.len() + 32]
                .try_into()
                .map_err(|_| LabError::Storage)?;
            let binding = ProfileBinding::new(profile_id, key_ref);
            if Some(binding) != inner.current || !inner.keys.contains(&binding) {
                return Err(LabError::Storage);
            }
            let mask = key_ref[0];
            for (target, value) in output
                .iter_mut()
                .zip(wrapped_dek[PREFIX.len() + 32..].iter())
            {
                *target = value ^ mask;
            }
            Ok(())
        }

        fn provision_key(&self, binding: ProfileBinding) -> Result<()> {
            let mut inner = self.inner.borrow_mut();
            if inner.keys.contains(&binding) {
                return Err(LabError::Storage);
            }
            inner.keys.push(binding);
            inner.current = Some(binding);
            Ok(())
        }

        fn key_status(&self, binding: ProfileBinding) -> Result<KeyStatus> {
            let inner = self.inner.borrow();
            if inner.temporarily_locked {
                return Ok(KeyStatus::TemporarilyLocked);
            }
            if inner.keys.contains(&binding) {
                Ok(KeyStatus::Present)
            } else {
                Ok(KeyStatus::Missing)
            }
        }

        fn select_binding(&self, binding: ProfileBinding) -> Result<()> {
            let mut inner = self.inner.borrow_mut();
            if !inner.keys.contains(&binding) {
                return Err(LabError::Storage);
            }
            inner.current = Some(binding);
            Ok(())
        }

        fn delete_key(&self, binding: ProfileBinding) -> Result<()> {
            let mut inner = self.inner.borrow_mut();
            inner.keys.retain(|present| present != &binding);
            Ok(())
        }
    }

    /// A minimal genuine `ClientStateV1` encoding (account, mailbox,
    /// registration; no optionals, empty arrays).
    fn initial_state() -> std::result::Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
        let account = Account::new();
        let send = Ed25519Keypair::new();
        let receive = Ed25519Keypair::new();
        let manage = Ed25519Keypair::new();
        let queue_id = QueueId::random();
        let mut registration = MailboxRegistration {
            queue_id,
            send_key: send.public_key(),
            receive_key: receive.public_key(),
            manage_key: manage.public_key(),
            nonce: Nonce::random(),
            valid_until: NOW + 3_600,
            signature: manage.sign(b""),
        };
        registration.signature = manage.sign(&registration.signing_bytes());
        let state = ClientStateV1 {
            profile_id: [0x51; 16],
            key_ref: [0x52; 16],
            generation: 1,
            conversation_id: ConversationId::random(),
            account_pickle: Zeroizing::new(serde_json::to_vec(&account.pickle())?),
            own_ed25519_identity: account.ed25519_key(),
            own_curve_identity: account.curve25519_key(),
            mailbox_queue_id: queue_id,
            send_keypair_json: Zeroizing::new(serde_json::to_vec(&send)?),
            receive_keypair_json: Zeroizing::new(serde_json::to_vec(&receive)?),
            manage_keypair_json: Zeroizing::new(serde_json::to_vec(&manage)?),
            registration: RegistrationRecord {
                queue_id: registration.queue_id,
                send_key: registration.send_key,
                receive_key: registration.receive_key,
                manage_key: registration.manage_key,
                nonce: registration.nonce,
                valid_until: registration.valid_until,
                signature: registration.signature,
            },
            pending_prekey: None,
            peer_binding: None,
            active_session: None,
            inbound: Vec::new(),
            sends: Vec::new(),
            acks: Vec::new(),
            dedup: Vec::new(),
        };
        Ok(state.encode()?)
    }

    struct Rig {
        _registry_dir: TempDir,
        _store_dir: TempDir,
        registry_path: PathBuf,
        store_path: PathBuf,
        platform: TestPlatform,
        manager: LifecycleManager<TestPlatform>,
    }

    fn open_registry_at(
        path: &std::path::Path,
        platform: TestPlatform,
    ) -> std::result::Result<LifecycleManager<TestPlatform>, Box<dyn Error>> {
        let dir = PrivateStoreDir::create(path, StoreKind::Lifecycle)?;
        Ok(LifecycleManager::open(dir, platform)?)
    }

    fn new_rig() -> std::result::Result<Rig, Box<dyn Error>> {
        let registry_dir = TempDir::new()?;
        let store_dir = TempDir::new()?;
        let registry_path = registry_dir.path().join("registry");
        let store_path = store_dir.path().join("store");
        let platform = TestPlatform::new();
        let manager = open_registry_at(&registry_path, platform.clone())?;
        Ok(Rig {
            _registry_dir: registry_dir,
            _store_dir: store_dir,
            registry_path,
            store_path,
            platform,
            manager,
        })
    }

    fn store_dir_handle(rig: &Rig) -> std::result::Result<PrivateStoreDir, Box<dyn Error>> {
        Ok(PrivateStoreDir::create(
            &rig.store_path,
            StoreKind::ClientState,
        )?)
    }

    fn reopen_store_dir(rig: &Rig) -> std::result::Result<PrivateStoreDir, Box<dyn Error>> {
        Ok(crate::private_store_dir::open_with_release_grace(
            &rig.store_path,
            StoreKind::ClientState,
        )?)
    }

    fn database_file(rig: &Rig) -> PathBuf {
        rig.store_path.join("client-state.sqlite3")
    }

    fn current_state(rig: &Rig) -> LifecycleState {
        rig.manager.state().unwrap_or(LifecycleState::Absent)
    }

    #[test]
    fn create_happy_path_promotes() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        assert_eq!(current_state(&rig), LifecycleState::Absent);
        let initial = initial_state()?;
        let outcome = rig
            .manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;
        assert_eq!(outcome, ProvisionOutcome::Promoted);
        let LifecycleState::Expected {
            profile_id,
            key_ref,
            protection_level,
        } = current_state(&rig)
        else {
            return Err("not Expected after create".into());
        };
        assert_eq!(protection_level, ProtectionLevel::SoftwareBacked);

        // The generation-1 store stands alone and holds the initial bytes.
        let store = ClientStateStore::open(reopen_store_dir(&rig)?, rig.platform.clone())?;
        assert_eq!(store.generation()?, 1);
        assert_eq!(store.state()?, &initial[..]);
        assert_ne!(profile_id, [0x51; 16]);
        assert_ne!(key_ref, [0x52; 16]);
        Ok(())
    }

    #[test]
    fn create_refused_when_profile_exists() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        let initial = initial_state()?;
        rig.manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;
        assert!(
            rig.manager
                .create_profile(reopen_store_dir(&rig)?, &initial)
                .is_err(),
            "second create accepted"
        );
        Ok(())
    }

    /// Drive create to failure after the Provisional row exists. Returns
    /// whether the (empty) database file remains.
    fn failed_create(rig: &mut Rig, fail_wrap: bool) -> std::result::Result<(), Box<dyn Error>> {
        {
            let mut inner = rig.platform.inner.borrow_mut();
            if fail_wrap {
                inner.fail_next_wrap = true;
            } else {
                inner.fail_next_unwrap = true;
            }
        }
        let initial = initial_state()?;
        assert!(
            rig.manager
                .create_profile(store_dir_handle(rig)?, &initial)
                .is_err()
        );
        assert!(matches!(
            current_state(rig),
            LifecycleState::Provisional { .. }
        ));
        Ok(())
    }

    #[test]
    fn recover_provisional_absent_db_is_interrupted() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        failed_create(&mut rig, true)?;
        // The wrap failed before the database write; remove the empty
        // file it left (crash before the write).
        fs::remove_file(database_file(&rig))?;
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(outcome, ProvisionOutcome::ProvisioningInterrupted);
        // No automatic deletion: the row is still Provisional.
        assert!(matches!(
            current_state(&rig),
            LifecycleState::Provisional { .. }
        ));
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(outcome, ProvisionOutcome::ProvisioningInterrupted);
        Ok(())
    }

    #[test]
    fn recover_provisional_authentic_gen1_promotes() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        failed_create(&mut rig, false)?;
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(outcome, ProvisionOutcome::Promoted);
        assert!(matches!(
            current_state(&rig),
            LifecycleState::Expected { .. }
        ));
        Ok(())
    }

    #[test]
    fn recover_provisional_unauthentic_locks() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        failed_create(&mut rig, false)?;
        // Corrupt the ciphertext while keeping the envelope shape.
        let connection = Connection::open(database_file(&rig))?;
        connection.execute(
            "UPDATE client_state SET ciphertext = randomblob(48) WHERE slot = 1",
            [],
        )?;
        drop(connection);
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(
            outcome,
            ProvisionOutcome::Locked(LockReason::DatabaseUnauthentic)
        );
        assert!(matches!(
            current_state(&rig),
            LifecycleState::Locked {
                reason: LockReason::DatabaseUnauthentic,
                ..
            }
        ));
        // Locked reads back idempotently.
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(
            outcome,
            ProvisionOutcome::Locked(LockReason::DatabaseUnauthentic)
        );
        Ok(())
    }

    #[test]
    fn recover_provisional_mismatched_generation_locks() -> std::result::Result<(), Box<dyn Error>>
    {
        let mut rig = new_rig()?;
        failed_create(&mut rig, false)?;
        // Move the authentic database to generation 2.
        let initial = initial_state()?;
        let mut store = ClientStateStore::open(reopen_store_dir(&rig)?, rig.platform.clone())?;
        store.commit(&initial)?;
        assert_eq!(store.generation()?, 2);
        drop(store);
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(
            outcome,
            ProvisionOutcome::Locked(LockReason::ProvisioningMismatch)
        );
        Ok(())
    }

    #[test]
    fn recover_expected_missing_database_locks_without_replacement()
    -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        let initial = initial_state()?;
        rig.manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;
        fs::remove_file(database_file(&rig))?;
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(
            outcome,
            ProvisionOutcome::Locked(LockReason::DatabaseMissing)
        );
        // Never creates a replacement: no new key, no new database.
        assert_eq!(rig.platform.key_count(), 1);
        assert!(!database_file(&rig).exists());
        assert!(
            rig.manager
                .create_profile(reopen_store_dir(&rig)?, &initial)
                .is_err(),
            "replacement profile created over Locked"
        );
        Ok(())
    }

    #[test]
    fn recover_expected_corrupt_database_locks() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        let initial = initial_state()?;
        rig.manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;
        let connection = Connection::open(database_file(&rig))?;
        connection.execute(
            "UPDATE client_state SET ciphertext = randomblob(48) WHERE slot = 1",
            [],
        )?;
        drop(connection);
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(
            outcome,
            ProvisionOutcome::Locked(LockReason::DatabaseUnauthentic)
        );
        Ok(())
    }

    #[test]
    fn recover_expected_missing_key_locks() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        let initial = initial_state()?;
        rig.manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;
        let LifecycleState::Expected {
            profile_id,
            key_ref,
            ..
        } = current_state(&rig)
        else {
            return Err("not Expected".into());
        };
        rig.platform
            .lose_key(ProfileBinding::new(profile_id, key_ref));
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(outcome, ProvisionOutcome::Locked(LockReason::KeyMissing));
        Ok(())
    }

    #[test]
    fn recover_expected_temporarily_locked_is_retryable() -> std::result::Result<(), Box<dyn Error>>
    {
        let mut rig = new_rig()?;
        let initial = initial_state()?;
        rig.manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;
        rig.platform.inner.borrow_mut().temporarily_locked = true;
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(
            outcome,
            ProvisionOutcome::Locked(LockReason::PlatformTemporarilyLocked)
        );
        // Registry, key and database are untouched.
        assert!(matches!(
            current_state(&rig),
            LifecycleState::Expected { .. }
        ));
        assert_eq!(rig.platform.key_count(), 1);
        assert!(database_file(&rig).exists());
        rig.platform.inner.borrow_mut().temporarily_locked = false;
        let outcome = rig.manager.recover(reopen_store_dir(&rig)?)?;
        assert_eq!(outcome, ProvisionOutcome::ExpectedReady);
        Ok(())
    }

    #[test]
    fn destructive_reset_flow_and_idempotent_resume() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        let initial = initial_state()?;
        rig.manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;
        let LifecycleState::Expected {
            profile_id,
            key_ref,
            ..
        } = current_state(&rig)
        else {
            return Err("not Expected".into());
        };

        // Authorization is required and non-accidental.
        assert!(DestructiveResetAuth::confirm("no").is_none());
        let auth = DestructiveResetAuth::confirm("permanently delete this profile")
            .ok_or("phrase rejected")?;

        // Force a failure between the key deletion and the file deletion:
        // the store directory is write-less (0500), so the unlink fails.
        fs::set_permissions(&rig.store_path, fs::Permissions::from_mode(0o500))?;
        let locked_dir = reopen_store_dir(&rig).map_err(|e| format!("reopen at 0500: {e:?}"))?;
        let reset_result = rig.manager.destructive_reset(auth, locked_dir);
        assert!(
            reset_result.is_err(),
            "reset unexpectedly succeeded: {reset_result:?}"
        );
        let LifecycleState::Deleting { reset_id, .. } = current_state(&rig) else {
            return Err("not Deleting after failed reset".into());
        };
        // The key went first.
        assert_eq!(
            rig.platform
                .key_status(ProfileBinding::new(profile_id, key_ref))?,
            KeyStatus::Missing
        );
        // No replacement profile while Deleting.
        assert!(
            rig.manager
                .create_profile(reopen_store_dir(&rig)?, &initial)
                .is_err()
        );

        // Resume idempotently with the same Deleting row.
        fs::set_permissions(&rig.store_path, fs::Permissions::from_mode(0o700))?;
        let resumed_dir = reopen_store_dir(&rig).map_err(|e| format!("reopen at 0700: {e:?}"))?;
        rig.manager
            .destructive_reset(auth, resumed_dir)
            .map_err(|e| format!("resume reset: {e:?}"))?;
        assert_eq!(current_state(&rig), LifecycleState::Absent);
        assert!(!database_file(&rig).exists());
        assert_eq!(rig.platform.key_count(), 0);
        let _ = reset_id;

        // A fresh profile can be created now, with never-reused refs.
        // (The directory still exists, now empty: open, not create.)
        rig.manager
            .create_profile(reopen_store_dir(&rig)?, &initial)?;
        let LifecycleState::Expected {
            key_ref: new_key_ref,
            ..
        } = current_state(&rig)
        else {
            return Err("not Expected after recreate".into());
        };
        assert_ne!(new_key_ref, key_ref);
        Ok(())
    }

    #[test]
    fn abandon_provisional_rules() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        failed_create(&mut rig, true)?;
        let LifecycleState::Provisional {
            provisioning_id, ..
        } = current_state(&rig)
        else {
            return Err("not Provisional".into());
        };
        // Wrong token.
        assert!(
            rig.manager
                .abandon_provisional([0xEE; 16], reopen_store_dir(&rig)?)
                .is_err()
        );
        assert!(matches!(
            current_state(&rig),
            LifecycleState::Provisional { .. }
        ));
        // Exact token: key, partial database and row all go.
        rig.manager
            .abandon_provisional(provisioning_id, reopen_store_dir(&rig)?)?;
        assert_eq!(current_state(&rig), LifecycleState::Absent);
        assert!(!database_file(&rig).exists());
        assert_eq!(rig.platform.key_count(), 0);
        // Nothing left to abandon.
        assert!(
            rig.manager
                .abandon_provisional(provisioning_id, reopen_store_dir(&rig)?)
                .is_err()
        );

        // Abandon never applies to an Expected profile.
        let initial = initial_state()?;
        rig.manager
            .create_profile(reopen_store_dir(&rig)?, &initial)?;
        assert!(
            rig.manager
                .abandon_provisional(provisioning_id, reopen_store_dir(&rig)?)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn registry_tampering_fails_closed() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        let initial = initial_state()?;
        rig.manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;

        // Externally flip Expected to Deleting: abandon and recover fail
        // closed; destructive_reset resumes the Deleting row to
        // completion (idempotent by design).
        let registry_db = rig.registry_path.join("lifecycle.sqlite3");
        let connection = Connection::open(&registry_db)?;
        connection.execute(
            "UPDATE lifecycle_profiles SET state_tag = 4, reset_id = ?1 WHERE slot = 1",
            params![[0x77_u8; 16].as_slice()],
        )?;
        drop(connection);
        assert!(
            rig.manager
                .abandon_provisional([0x01; 16], reopen_store_dir(&rig)?)
                .is_err()
        );
        assert!(rig.manager.recover(reopen_store_dir(&rig)?).is_err());
        let auth = DestructiveResetAuth::confirm("permanently delete this profile")
            .ok_or("phrase rejected")?;
        rig.manager
            .destructive_reset(auth, reopen_store_dir(&rig)?)?;
        assert_eq!(current_state(&rig), LifecycleState::Absent);

        // Externally changed key reference: recovery fails closed into
        // KeyMissing rather than trusting the row.
        let mut rig2 = new_rig()?;
        rig2.manager
            .create_profile(store_dir_handle(&rig2)?, &initial)?;
        let registry_db = rig2.registry_path.join("lifecycle.sqlite3");
        let connection = Connection::open(&registry_db)?;
        connection.execute(
            "UPDATE lifecycle_profiles SET key_ref = ?1 WHERE slot = 1",
            params![[0x66_u8; 16].as_slice()],
        )?;
        drop(connection);
        let outcome = rig2.manager.recover(reopen_store_dir(&rig2)?)?;
        assert_eq!(outcome, ProvisionOutcome::Locked(LockReason::KeyMissing));

        // Externally deleted row: everything fails closed.
        let connection = Connection::open(&registry_db)?;
        connection.execute("DELETE FROM lifecycle_profiles WHERE slot = 1", [])?;
        drop(connection);
        assert_eq!(current_state(&rig2), LifecycleState::Absent);
        assert!(rig2.manager.recover(reopen_store_dir(&rig2)?).is_err());
        Ok(())
    }

    #[test]
    fn manager_open_validates_exact_schema() -> std::result::Result<(), Box<dyn Error>> {
        let rig = new_rig()?;
        drop(rig.manager);
        let registry_db = rig.registry_path.join("lifecycle.sqlite3");
        let connection = Connection::open(&registry_db)?;
        connection.execute_batch("ALTER TABLE lifecycle_spent_refs RENAME TO moved_refs;")?;
        drop(connection);
        let dir = crate::private_store_dir::open_with_release_grace(
            &rig.registry_path,
            StoreKind::Lifecycle,
        )?;
        assert!(LifecycleManager::open(dir, rig.platform.clone()).is_err());
        Ok(())
    }

    #[test]
    fn spent_refs_are_never_reused() -> std::result::Result<(), Box<dyn Error>> {
        let mut rig = new_rig()?;
        let initial = initial_state()?;
        rig.manager
            .create_profile(store_dir_handle(&rig)?, &initial)?;
        let LifecycleState::Expected { key_ref: first, .. } = current_state(&rig) else {
            return Err("not Expected".into());
        };
        let auth = DestructiveResetAuth::confirm("permanently delete this profile")
            .ok_or("phrase rejected")?;
        rig.manager
            .destructive_reset(auth, reopen_store_dir(&rig)?)?;
        rig.manager
            .create_profile(reopen_store_dir(&rig)?, &initial)?;
        let LifecycleState::Expected {
            key_ref: second, ..
        } = current_state(&rig)
        else {
            return Err("not Expected after recreate".into());
        };
        assert_ne!(first, second);
        // The spent_refs table retains both.
        let registry_db = rig.registry_path.join("lifecycle.sqlite3");
        let connection = Connection::open(&registry_db)?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM lifecycle_spent_refs", [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 2);
        Ok(())
    }
}
