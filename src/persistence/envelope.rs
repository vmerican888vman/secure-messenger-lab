use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{LabError, PROTOCOL_DOMAIN, Result};

use super::protector::ProfileBinding;

pub(super) const ENVELOPE_VERSION: i64 = 1;
pub(super) const CRYPTO_SUITE: i64 = 1;
pub(super) const STATE_SCHEMA_VERSION: i64 = 1;
pub(super) const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024 * 1024;
pub(super) const NONCE_BYTES: usize = 24;
pub(super) const MAX_PLAINTEXT_BYTES: usize = MAX_CIPHERTEXT_BYTES - 16;

const MAX_WRAPPED_DEK_BYTES: usize = 8192;
const STATE_DOMAIN: &[u8] = b"secure-messenger-lab/client-state";
const VODOZEMAC_VERSION: &[u8] = b"0.10.0";

/// Seal one complete client-state generation using the reviewed outer envelope.
///
/// The caller supplies a newly generated nonce; this function deliberately does
/// not derive one from the generation because an accepted database rollback can
/// repeat a generation under the same DEK.
pub(super) fn seal(
    binding: ProfileBinding,
    generation: u64,
    wrapped_dek: &[u8],
    dek: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    validate_header(generation, wrapped_dek, plaintext.len())?;
    let aad = aad(binding, generation, wrapped_dek)?;
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| LabError::Storage)?;
    let nonce = XNonce::from(*nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| LabError::Storage)?;

    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(LabError::Storage);
    }

    Ok(ciphertext)
}

/// Authenticate and open one complete client-state generation.
///
/// Returned plaintext is zeroized on drop. All authentication, header, and
/// length failures intentionally map to the same coarse storage error.
pub(super) fn open(
    binding: ProfileBinding,
    generation: u64,
    wrapped_dek: &[u8],
    dek: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < 16 || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(LabError::Storage);
    }
    validate_header(generation, wrapped_dek, ciphertext.len() - 16)?;

    let aad = aad(binding, generation, wrapped_dek)?;
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| LabError::Storage)?;
    let nonce = XNonce::from(*nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| LabError::Storage)?;

    Ok(Zeroizing::new(plaintext))
}

fn validate_header(generation: u64, wrapped_dek: &[u8], plaintext_len: usize) -> Result<()> {
    if generation == 0
        || i64::try_from(generation).is_err()
        || wrapped_dek.is_empty()
        || wrapped_dek.len() > MAX_WRAPPED_DEK_BYTES
        || plaintext_len > MAX_PLAINTEXT_BYTES
    {
        return Err(LabError::Storage);
    }
    Ok(())
}

fn aad(binding: ProfileBinding, generation: u64, wrapped_dek: &[u8]) -> Result<Vec<u8>> {
    let wrapped_dek_hash: [u8; 32] = Sha256::digest(wrapped_dek).into();
    let mut encoded = Vec::new();
    for part in [
        STATE_DOMAIN,
        &ENVELOPE_VERSION.to_be_bytes(),
        &CRYPTO_SUITE.to_be_bytes(),
        binding.profile_id().as_slice(),
        &generation.to_be_bytes(),
        binding.key_ref().as_slice(),
        &wrapped_dek_hash,
        PROTOCOL_DOMAIN,
        VODOZEMAC_VERSION,
        &STATE_SCHEMA_VERSION.to_be_bytes(),
    ] {
        append_part(&mut encoded, part)?;
    }
    Ok(encoded)
}

fn append_part(encoded: &mut Vec<u8>, part: &[u8]) -> Result<()> {
    let length = u32::try_from(part.len()).map_err(|_| LabError::Storage)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(part);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ProfileBinding {
        ProfileBinding::new([1_u8; 16], [2_u8; 16])
    }

    fn dek() -> [u8; 32] {
        [3_u8; 32]
    }

    fn nonce() -> [u8; NONCE_BYTES] {
        [4_u8; NONCE_BYTES]
    }

    #[test]
    fn round_trip_authenticates_every_header_part() -> Result<()> {
        let wrapped_dek = [5_u8; 32];
        let ciphertext = seal(binding(), 1, &wrapped_dek, &dek(), &nonce(), b"state")?;
        let plaintext = open(binding(), 1, &wrapped_dek, &dek(), &nonce(), &ciphertext)?;

        assert_eq!(plaintext.as_slice(), b"state");
        assert!(matches!(
            open(binding(), 2, &wrapped_dek, &dek(), &nonce(), &ciphertext),
            Err(LabError::Storage)
        ));
        assert!(matches!(
            open(
                ProfileBinding::new([9_u8; 16], [2_u8; 16]),
                1,
                &wrapped_dek,
                &dek(),
                &nonce(),
                &ciphertext,
            ),
            Err(LabError::Storage)
        ));
        assert!(matches!(
            open(
                ProfileBinding::new([1_u8; 16], [9_u8; 16]),
                1,
                &wrapped_dek,
                &dek(),
                &nonce(),
                &ciphertext,
            ),
            Err(LabError::Storage)
        ));
        assert!(matches!(
            open(binding(), 1, &[6_u8; 32], &dek(), &nonce(), &ciphertext,),
            Err(LabError::Storage)
        ));
        assert!(matches!(
            open(
                binding(),
                1,
                &wrapped_dek,
                &dek(),
                &[7_u8; NONCE_BYTES],
                &ciphertext,
            ),
            Err(LabError::Storage)
        ));
        let mut changed_ciphertext = ciphertext;
        changed_ciphertext[0] ^= 1;
        assert!(matches!(
            open(
                binding(),
                1,
                &wrapped_dek,
                &dek(),
                &nonce(),
                &changed_ciphertext,
            ),
            Err(LabError::Storage)
        ));
        Ok(())
    }

    #[test]
    fn rejects_oversized_ciphertext_before_decrypt() {
        let ciphertext = vec![0_u8; MAX_CIPHERTEXT_BYTES + 1];
        assert!(open(binding(), 1, &[5_u8; 32], &dek(), &nonce(), &ciphertext).is_err());
        assert!(seal(binding(), u64::MAX, &[5_u8; 32], &dek(), &nonce(), b"state").is_err());
    }
}
