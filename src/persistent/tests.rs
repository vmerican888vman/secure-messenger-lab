//! In-crate façade tests: payload-generation tracking assertions (they
//! read private façade fields) and Sol's finding-2 reproductions, which
//! need a forged-but-authentic envelope. The forge is possible because the
//! test protector's wrap is a known XOR mask; the AAD construction is a
//! replica of `persistence/envelope.rs` (private there).

use std::error::Error;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::{PersistentClient, RegistrationOutcome};
use crate::persistence::{ProfileBinding, ProtectionLevel, StateKeyProtector};
use crate::{LabError, PrivateStoreDir, StoreKind};

const NOW: u64 = 1_800_000_000;
const DEK_BYTES: usize = 32;

/// The XOR test protector, mirrored from `persistence/sqlite.rs` tests.
struct TestProtector {
    binding: ProfileBinding,
    mask: [u8; DEK_BYTES],
}

fn protector() -> TestProtector {
    TestProtector {
        binding: ProfileBinding::new([0x42; 16], [0x24; 16]),
        mask: [0x24; DEK_BYTES],
    }
}

impl StateKeyProtector for TestProtector {
    fn expected_binding(&self) -> crate::Result<ProfileBinding> {
        Ok(self.binding)
    }

    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::SoftwareBacked
    }

    fn wrap_dek(&self, dek: &Zeroizing<[u8; DEK_BYTES]>) -> crate::Result<Vec<u8>> {
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
    ) -> crate::Result<()> {
        const PREFIX: &[u8] = b"state-wrap/v1";
        let expected = PREFIX.len() + 16 + 16 + DEK_BYTES;
        if wrapped_dek.len() != expected
            || &wrapped_dek[..PREFIX.len()] != PREFIX
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

fn store_path(temp: &TempDir) -> PathBuf {
    temp.path().join("client")
}

fn create_client(
    temp: &TempDir,
) -> std::result::Result<PersistentClient<TestProtector>, Box<dyn Error>> {
    let dir = PrivateStoreDir::create(&store_path(temp), StoreKind::ClientState)?;
    Ok(PersistentClient::create(dir, protector(), NOW)?)
}

fn open_client(
    temp: &TempDir,
) -> std::result::Result<PersistentClient<TestProtector>, Box<dyn Error>> {
    let dir = crate::private_store_dir::open_with_release_grace(
        &store_path(temp),
        StoreKind::ClientState,
    )?;
    Ok(PersistentClient::open(dir, protector())?)
}

/// Replica of the envelope AAD in `persistence/envelope.rs`.
fn envelope_aad(binding: &ProfileBinding, generation: u64, wrapped_dek: &[u8]) -> Vec<u8> {
    let wrapped_dek_hash: [u8; 32] = Sha256::digest(wrapped_dek).into();
    let mut encoded = Vec::new();
    for part in [
        b"secure-messenger-lab/client-state".as_slice(),
        &1_i64.to_be_bytes(),
        &1_i64.to_be_bytes(),
        binding.profile_id().as_slice(),
        &generation.to_be_bytes(),
        binding.key_ref().as_slice(),
        &wrapped_dek_hash,
        crate::PROTOCOL_DOMAIN,
        b"0.10.0",
        &1_i64.to_be_bytes(),
    ] {
        encoded.extend_from_slice(&u32::try_from(part.len()).unwrap_or(0).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    encoded
}

/// Decrypt the stored payload, mutate it, re-encrypt authentically (the
/// test protector's mask makes the DEK recoverable), and write it back.
/// The outer envelope stays valid for the row's stored generation.
fn rewrite_payload(
    database: &Path,
    mutate: impl FnOnce(&mut [u8]),
) -> std::result::Result<(), Box<dyn Error>> {
    let connection = Connection::open(database)?;
    let (generation, wrapped_dek, nonce, ciphertext): (i64, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT generation, wrapped_dek, nonce, ciphertext FROM client_state WHERE slot = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let generation = u64::try_from(generation)?;
    let protector = protector();
    let mut dek = Zeroizing::new([0_u8; DEK_BYTES]);
    protector.unwrap_dek(&wrapped_dek, &mut dek)?;
    let aad = envelope_aad(&protector.binding, generation, &wrapped_dek);
    let cipher = XChaCha20Poly1305::new_from_slice(&*dek).map_err(|_| LabError::Storage)?;
    let nonce = XNonce::from_slice(&nonce);
    let mut payload = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext[..],
                aad: &aad,
            },
        )
        .map_err(|_| "envelope decrypt failed")?;
    mutate(&mut payload);
    let forged = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &payload[..],
                aad: &aad,
            },
        )
        .map_err(|_| "envelope encrypt failed")?;
    connection.execute(
        "UPDATE client_state SET ciphertext = ?1 WHERE slot = 1",
        params![forged],
    )?;
    Ok(())
}

// Top-level payload offsets (magic 8 + type 2 + count 2, then
// field 1: 6+2, field 2 profile_id: 6+16, field 3 key_ref: 6+16,
// field 4 generation: 6+8).
const PROFILE_ID_VALUE: usize = 26;
const KEY_REF_VALUE: usize = 48;
const GENERATION_VALUE: usize = 70;

#[test]
fn payload_generation_tracks_store_generation() -> std::result::Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    assert_eq!(client.state.generation, 1);
    assert_eq!(client.store.generation()?, 1);

    client.prekey_action(NOW + 300)?;
    assert_eq!(client.state.generation, client.store.generation()?);
    assert_eq!(client.state.generation, 2);

    let action = client.registration_action(NOW + 3_600)?;
    client.record_registration_result(&action, RegistrationOutcome::Confirmed)?;
    assert_eq!(client.state.generation, client.store.generation()?);
    assert_eq!(client.state.generation, 4);

    drop(client);
    let client = open_client(&temp)?;
    assert_eq!(client.state.generation, 4);
    assert_eq!(client.state.generation, client.store.generation()?);
    Ok(())
}

#[test]
fn rewritten_payload_roundtrip_sanity() -> std::result::Result<(), Box<dyn Error>> {
    // The forge pipeline is authentic: a no-op rewrite leaves a perfectly
    // openable store, so the mismatch tests below reject because of the
    // finding-2 comparisons, not envelope damage.
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    client.prekey_action(NOW + 300)?;
    drop(client);
    rewrite_payload(&store_path(&temp).join("client-state.sqlite3"), |_| {})?;
    let client = open_client(&temp)?;
    assert_eq!(client.state.generation, 2);
    Ok(())
}

#[test]
fn outer_generation_two_with_payload_generation_one_rejected()
-> std::result::Result<(), Box<dyn Error>> {
    // Sol's repro: outer generation 2, payload generation 1.
    let temp = TempDir::new()?;
    let mut client = create_client(&temp)?;
    client.prekey_action(NOW + 300)?;
    drop(client);
    rewrite_payload(&store_path(&temp).join("client-state.sqlite3"), |payload| {
        payload[GENERATION_VALUE..GENERATION_VALUE + 8].copy_from_slice(&1_u64.to_be_bytes());
    })?;
    assert!(open_client(&temp).is_err());
    Ok(())
}

#[test]
fn payload_profile_or_key_ref_mismatch_rejected_on_reopen()
-> std::result::Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let client = create_client(&temp)?;
    drop(client);
    rewrite_payload(&store_path(&temp).join("client-state.sqlite3"), |payload| {
        payload[PROFILE_ID_VALUE] ^= 0x01;
    })?;
    assert!(open_client(&temp).is_err());

    let temp = TempDir::new()?;
    let client = create_client(&temp)?;
    drop(client);
    rewrite_payload(&store_path(&temp).join("client-state.sqlite3"), |payload| {
        payload[KEY_REF_VALUE] ^= 0x01;
    })?;
    assert!(open_client(&temp).is_err());
    Ok(())
}
