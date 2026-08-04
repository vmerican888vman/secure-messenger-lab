use sha2::{Digest, Sha256};
use vodozemac::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature};

use crate::relay::StoredEnvelope;
use crate::{
    EncryptedPacket, LabError, MessageId, Nonce, OpenedMessage, PROTOCOL_DOMAIN, QueueId, Result,
};

const ACTION_REGISTER: &[u8] = b"register";
const ACTION_SEND: &[u8] = b"send";
const ACTION_FETCH: &[u8] = b"fetch";
const ACTION_ACK: &[u8] = b"ack";
const ACTION_DELETE: &[u8] = b"delete-mailbox";

/// The three independent private capabilities for one unidirectional mailbox.
///
/// The queue identifier only locates the mailbox. It cannot send, receive, ACK,
/// or manage anything without the matching signing capability.
pub struct MailboxOwner {
    queue_id: QueueId,
    send: Ed25519Keypair,
    receive: Ed25519Keypair,
    manage: Ed25519Keypair,
}

impl MailboxOwner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue_id: QueueId::random(),
            send: Ed25519Keypair::new(),
            receive: Ed25519Keypair::new(),
            manage: Ed25519Keypair::new(),
        }
    }

    #[must_use]
    pub const fn queue_id(&self) -> QueueId {
        self.queue_id
    }

    #[must_use]
    pub fn registration(&self, valid_until: u64) -> MailboxRegistration {
        let nonce = Nonce::random();
        let send_key = self.send.public_key();
        let receive_key = self.receive.public_key();
        let manage_key = self.manage.public_key();
        let signing_bytes = canonical(
            ACTION_REGISTER,
            &[
                self.queue_id.as_bytes(),
                send_key.as_bytes(),
                receive_key.as_bytes(),
                manage_key.as_bytes(),
                nonce.as_bytes(),
                &valid_until.to_be_bytes(),
            ],
        );
        MailboxRegistration {
            queue_id: self.queue_id,
            send_key,
            receive_key,
            manage_key,
            nonce,
            valid_until,
            signature: self.manage.sign(&signing_bytes),
        }
    }

    /// Clone only the sender capability for transfer through a verified,
    /// out-of-band contact exchange. It is never uploaded to the relay.
    #[must_use]
    pub fn sender_capability(&self) -> SendCapability {
        SendCapability {
            queue_id: self.queue_id,
            signing_key: self.send.clone(),
        }
    }

    #[must_use]
    pub fn receiver_capability(&self) -> ReceiveCapability {
        ReceiveCapability {
            queue_id: self.queue_id,
            signing_key: self.receive.clone(),
            send_verification_key: self.send.public_key(),
        }
    }

    #[must_use]
    pub fn manager_capability(&self) -> ManageCapability {
        ManageCapability {
            queue_id: self.queue_id,
            signing_key: self.manage.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn serialized_private_material(&self) -> Vec<Vec<u8>> {
        [&self.send, &self.receive, &self.manage]
            .iter()
            .map(|key| serde_json::to_vec(key).unwrap_or_default())
            .collect()
    }
}

impl Default for MailboxOwner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct SendCapability {
    queue_id: QueueId,
    signing_key: Ed25519Keypair,
}

impl SendCapability {
    #[must_use]
    pub const fn queue_id(&self) -> QueueId {
        self.queue_id
    }

    #[must_use]
    pub fn authorize(
        &self,
        message_id: MessageId,
        packet: EncryptedPacket,
        expires_at: u64,
    ) -> SendRequest {
        let signing_bytes = canonical(
            ACTION_SEND,
            &[
                self.queue_id.as_bytes(),
                message_id.as_bytes(),
                &packet.digest(),
                &expires_at.to_be_bytes(),
            ],
        );
        SendRequest {
            queue_id: self.queue_id,
            message_id,
            packet,
            expires_at,
            signature: self.signing_key.sign(&signing_bytes),
        }
    }
}

#[derive(Clone)]
pub struct ReceiveCapability {
    queue_id: QueueId,
    signing_key: Ed25519Keypair,
    send_verification_key: Ed25519PublicKey,
}

impl ReceiveCapability {
    #[must_use]
    pub fn authorize_fetch(&self, valid_until: u64) -> FetchRequest {
        let nonce = Nonce::random();
        let signing_bytes = canonical(
            ACTION_FETCH,
            &[
                self.queue_id.as_bytes(),
                nonce.as_bytes(),
                &valid_until.to_be_bytes(),
            ],
        );
        FetchRequest {
            queue_id: self.queue_id,
            nonce,
            valid_until,
            signature: self.signing_key.sign(&signing_bytes),
        }
    }

    /// Authenticate the sender-signed outer envelope before any ratchet state
    /// is allowed to advance.
    ///
    /// # Errors
    ///
    /// Returns an error if the queue, expiry, packet digest, or sender
    /// signature does not match this mailbox.
    pub fn verify_envelope(&self, envelope: &StoredEnvelope, now: u64) -> Result<VerifiedEnvelope> {
        if envelope.queue_id != self.queue_id || envelope.expires_at <= now {
            return Err(LabError::Unauthorized);
        }
        self.send_verification_key
            .verify(
                &send_signing_bytes(
                    envelope.queue_id,
                    envelope.message_id,
                    &envelope.packet,
                    envelope.expires_at,
                ),
                &envelope.sender_signature,
            )
            .map_err(|_| LabError::Unauthorized)?;
        Ok(VerifiedEnvelope {
            queue_id: envelope.queue_id,
            message_id: envelope.message_id,
            packet: envelope.packet.clone(),
            expires_at: envelope.expires_at,
        })
    }

    /// Sign an ACK only for an envelope that the client successfully decrypted
    /// and accepted.
    #[must_use]
    pub fn authorize_ack(&self, opened: &OpenedMessage, valid_until: u64) -> AckRequest {
        let envelope = opened.verified_envelope();
        let packet_hash = envelope.packet.digest();
        let signing_bytes = canonical(
            ACTION_ACK,
            &[
                self.queue_id.as_bytes(),
                envelope.message_id.as_bytes(),
                &packet_hash,
                &valid_until.to_be_bytes(),
            ],
        );
        AckRequest {
            queue_id: self.queue_id,
            message_id: envelope.message_id,
            packet_hash,
            valid_until,
            signature: self.signing_key.sign(&signing_bytes),
        }
    }
}

/// An outer envelope authenticated with the peer's mailbox send capability.
/// Only `ReceiveCapability::verify_envelope` can construct this type.
#[derive(Clone)]
pub struct VerifiedEnvelope {
    queue_id: QueueId,
    message_id: MessageId,
    packet: EncryptedPacket,
    expires_at: u64,
}

impl VerifiedEnvelope {
    #[must_use]
    pub const fn queue_id(&self) -> QueueId {
        self.queue_id
    }

    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    #[must_use]
    pub const fn packet(&self) -> &EncryptedPacket {
        &self.packet
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[derive(Clone)]
pub struct ManageCapability {
    queue_id: QueueId,
    signing_key: Ed25519Keypair,
}

impl ManageCapability {
    #[must_use]
    pub fn authorize_delete(&self, valid_until: u64) -> DeleteMailboxRequest {
        let nonce = Nonce::random();
        let signing_bytes = canonical(
            ACTION_DELETE,
            &[
                self.queue_id.as_bytes(),
                nonce.as_bytes(),
                &valid_until.to_be_bytes(),
            ],
        );
        DeleteMailboxRequest {
            queue_id: self.queue_id,
            nonce,
            valid_until,
            signature: self.signing_key.sign(&signing_bytes),
        }
    }
}

#[derive(Clone)]
pub struct MailboxRegistration {
    pub queue_id: QueueId,
    pub send_key: Ed25519PublicKey,
    pub receive_key: Ed25519PublicKey,
    pub manage_key: Ed25519PublicKey,
    pub nonce: Nonce,
    pub valid_until: u64,
    pub signature: Ed25519Signature,
}

impl MailboxRegistration {
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        canonical(
            ACTION_REGISTER,
            &[
                self.queue_id.as_bytes(),
                self.send_key.as_bytes(),
                self.receive_key.as_bytes(),
                self.manage_key.as_bytes(),
                self.nonce.as_bytes(),
                &self.valid_until.to_be_bytes(),
            ],
        )
    }
}

#[derive(Clone)]
pub struct SendRequest {
    pub queue_id: QueueId,
    pub message_id: MessageId,
    pub packet: EncryptedPacket,
    pub expires_at: u64,
    pub signature: Ed25519Signature,
}

impl SendRequest {
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        send_signing_bytes(
            self.queue_id,
            self.message_id,
            &self.packet,
            self.expires_at,
        )
    }
}

#[derive(Clone)]
pub struct FetchRequest {
    pub queue_id: QueueId,
    pub nonce: Nonce,
    pub valid_until: u64,
    pub signature: Ed25519Signature,
}

impl FetchRequest {
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        canonical(
            ACTION_FETCH,
            &[
                self.queue_id.as_bytes(),
                self.nonce.as_bytes(),
                &self.valid_until.to_be_bytes(),
            ],
        )
    }
}

#[derive(Clone)]
pub struct AckRequest {
    pub queue_id: QueueId,
    pub message_id: MessageId,
    pub packet_hash: [u8; 32],
    pub valid_until: u64,
    pub signature: Ed25519Signature,
}

impl AckRequest {
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        canonical(
            ACTION_ACK,
            &[
                self.queue_id.as_bytes(),
                self.message_id.as_bytes(),
                &self.packet_hash,
                &self.valid_until.to_be_bytes(),
            ],
        )
    }
}

#[derive(Clone)]
pub struct DeleteMailboxRequest {
    pub queue_id: QueueId,
    pub nonce: Nonce,
    pub valid_until: u64,
    pub signature: Ed25519Signature,
}

impl DeleteMailboxRequest {
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        canonical(
            ACTION_DELETE,
            &[
                self.queue_id.as_bytes(),
                self.nonce.as_bytes(),
                &self.valid_until.to_be_bytes(),
            ],
        )
    }
}

fn send_signing_bytes(
    queue_id: QueueId,
    message_id: MessageId,
    packet: &EncryptedPacket,
    expires_at: u64,
) -> Vec<u8> {
    canonical(
        ACTION_SEND,
        &[
            queue_id.as_bytes(),
            message_id.as_bytes(),
            &packet.digest(),
            &expires_at.to_be_bytes(),
        ],
    )
}

pub(crate) fn canonical(action: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let total_part_bytes: usize = parts.iter().map(|part| part.len()).sum();
    let mut encoded =
        Vec::with_capacity(PROTOCOL_DOMAIN.len() + action.len() + total_part_bytes + 64);
    append_part(&mut encoded, PROTOCOL_DOMAIN);
    append_part(&mut encoded, action);
    for part in parts {
        append_part(&mut encoded, part);
    }
    encoded
}

fn append_part(target: &mut Vec<u8>, part: &[u8]) {
    let length = u64::try_from(part.len()).unwrap_or(u64::MAX);
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(part);
}

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;

    use super::MailboxOwner;
    use crate::Relay;

    #[test]
    fn relay_database_does_not_contain_serialized_private_capabilities()
    -> std::result::Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("relay.sqlite");
        let mut relay = Relay::open(&database)?;
        let owner = MailboxOwner::new();
        let private_material = owner.serialized_private_material();
        relay.register(&owner.registration(1_800_000_060), 1_800_000_000)?;
        drop(relay);

        let database_bytes = fs::read(database)?;
        for secret in private_material {
            assert!(
                !database_bytes
                    .windows(secret.len())
                    .any(|window| window == secret),
                "serialized private capability leaked into relay storage"
            );
        }
        Ok(())
    }
}
