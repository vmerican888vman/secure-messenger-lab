// The whole module is crate-private legacy retained for the in-crate
// end-to-end proof tests; the façade (`src/persistent`) is the
// production path and does not use it.
#![allow(dead_code)]

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

use crate::capability::VerifiedEnvelope;
use crate::capability::{canonical, digest};
use crate::{ConversationId, LabError, MessageId, Result};

// Path-level staging and expiry tests live in-crate with the crate-private
// client types they exercise.
#[cfg(test)]
mod expiry_tests;
#[cfg(test)]
mod staging_tests;

const PAYLOAD_VERSION: u8 = 1;
const CONTACT_BUNDLE_ACTION: &[u8] = b"peer-prekey";
const CONTACT_BUNDLE_MAX_VALIDITY_SECONDS: u64 = 5 * 60;

/// A contact bundle that must be transferred and verified out of band in this
/// spike. The relay never publishes or modifies it.
#[derive(Clone, Copy)]
pub struct PeerPreKey {
    pub signing_identity: Ed25519PublicKey,
    pub curve_identity: Curve25519PublicKey,
    pub one_time_key: Curve25519PublicKey,
    pub valid_until: u64,
    pub signature: Ed25519Signature,
}

impl PeerPreKey {
    /// Verify the complete Curve25519 bundle against a separately pinned
    /// Ed25519 contact identity.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::PeerVerificationFailed`] if the pinned identity,
    /// signature, or short validity window does not match.
    pub fn verify(
        &self,
        pinned_signing_identity: Ed25519PublicKey,
        now: u64,
    ) -> Result<VerifiedPeerPreKey> {
        if self.signing_identity != pinned_signing_identity
            || self.valid_until <= now
            || self.valid_until > now.saturating_add(CONTACT_BUNDLE_MAX_VALIDITY_SECONDS)
        {
            return Err(LabError::PeerVerificationFailed);
        }
        pinned_signing_identity
            .verify(&self.signing_bytes(), &self.signature)
            .map_err(|_| LabError::PeerVerificationFailed)?;
        Ok(VerifiedPeerPreKey {
            signing_identity: self.signing_identity,
            curve_identity: self.curve_identity,
            one_time_key: self.one_time_key,
            valid_until: self.valid_until,
        })
    }

    fn signing_bytes(&self) -> Vec<u8> {
        peer_prekey_signing_bytes(
            self.signing_identity,
            self.curve_identity,
            self.one_time_key,
            self.valid_until,
        )
    }
}

/// A contact bundle whose key binding was checked against a separately pinned
/// Ed25519 identity. Its fields cannot be altered by transport code.
#[derive(Clone, Copy)]
pub struct VerifiedPeerPreKey {
    signing_identity: Ed25519PublicKey,
    curve_identity: Curve25519PublicKey,
    one_time_key: Curve25519PublicKey,
    valid_until: u64,
}

impl VerifiedPeerPreKey {
    #[must_use]
    pub const fn signing_identity(&self) -> Ed25519PublicKey {
        self.signing_identity
    }

    #[must_use]
    pub const fn curve_identity(&self) -> Curve25519PublicKey {
        self.curve_identity
    }

    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

/// Opaque wire bytes produced only after successful Olm encryption.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedPacket(Vec<u8>);

impl EncryptedPacket {
    /// Parse bytes received from an untrusted transport. Authenticity is not
    /// established until an `OlmClient` successfully decrypts the packet.
    #[must_use]
    pub fn from_untrusted(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest(&self.0)
    }
}

impl std::fmt::Debug for EncryptedPacket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedPacket")
            .field("bytes", &"redacted")
            .field("length", &self.0.len())
            .finish()
    }
}

/// Application data that exists only inside the encrypted Olm payload and on
/// endpoint devices.
#[derive(Clone, Serialize, Deserialize)]
pub struct PlainMessage {
    pub version: u8,
    pub conversation_id: ConversationId,
    pub message_id: MessageId,
    pub sent_at: u64,
    pub body: String,
}

/// A plaintext message paired with the authenticated outer envelope that was
/// successfully decrypted. Only this type can be acknowledged by the client API.
pub struct OpenedMessage {
    message: PlainMessage,
    envelope: VerifiedEnvelope,
}

impl OpenedMessage {
    #[must_use]
    pub const fn message(&self) -> &PlainMessage {
        &self.message
    }

    pub(crate) const fn verified_envelope(&self) -> &VerifiedEnvelope {
        &self.envelope
    }
}

/// A single-device, single-peer client used by the executable proof.
///
/// One `Account` per peer keeps the Olm Curve25519 identity from becoming a
/// global cross-contact identifier in this constrained prototype.
pub struct OlmClient {
    account: Account,
    session: Option<Session>,
    conversation_id: ConversationId,
    displayed_messages: HashSet<MessageId>,
}

impl OlmClient {
    #[must_use]
    pub fn new(conversation_id: ConversationId) -> Self {
        Self {
            account: Account::new(),
            session: None,
            conversation_id,
            displayed_messages: HashSet::new(),
        }
    }

    /// Export one pre-key bundle for a verified contact exchange. A production
    /// design still needs transactional one-time-key publication and claiming.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::Crypto`] if the account cannot produce a one-time key.
    pub fn prekey_bundle(&mut self, valid_until: u64) -> Result<PeerPreKey> {
        self.account.generate_one_time_keys(1);
        let Some(one_time_key) = self.account.one_time_keys().values().next().copied() else {
            return Err(LabError::Crypto);
        };
        let signing_identity = self.account.ed25519_key();
        let curve_identity = self.account.curve25519_key();
        let signature = self.account.sign(peer_prekey_signing_bytes(
            signing_identity,
            curve_identity,
            one_time_key,
            valid_until,
        ));
        let bundle = PeerPreKey {
            signing_identity,
            curve_identity,
            one_time_key,
            valid_until,
            signature,
        };
        self.account.mark_keys_as_published();
        Ok(bundle)
    }

    #[must_use]
    pub fn curve_identity(&self) -> Curve25519PublicKey {
        self.account.curve25519_key()
    }

    #[must_use]
    pub fn signing_identity(&self) -> Ed25519PublicKey {
        self.account.ed25519_key()
    }

    /// Create the outbound Olm session from a directly verified peer bundle.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::SessionAlreadyExists`] if this peer already has a
    /// session, [`LabError::PeerVerificationFailed`] if the verified bundle has
    /// expired, or [`LabError::Crypto`] if Olm rejects the bundle.
    pub fn start_outbound_session(&mut self, peer: &VerifiedPeerPreKey, now: u64) -> Result<()> {
        if self.session.is_some() {
            return Err(LabError::SessionAlreadyExists);
        }
        if peer.valid_until <= now {
            return Err(LabError::PeerVerificationFailed);
        }
        let session = self
            .account
            .create_outbound_session(
                SessionConfig::version_1(),
                peer.curve_identity,
                peer.one_time_key,
            )
            .map_err(|_| LabError::Crypto)?;
        self.session = Some(session);
        Ok(())
    }

    /// Encrypt or fail closed. There is intentionally no plaintext transport
    /// return type and no fallback branch.
    ///
    /// # Errors
    ///
    /// Returns [`LabError::MissingSession`] when no ratchet exists and a coarse
    /// encoding or crypto error if authenticated encryption cannot complete.
    pub fn seal(&mut self, body: &str, sent_at: u64) -> Result<(MessageId, EncryptedPacket)> {
        let message_id = MessageId::random();
        let plaintext = PlainMessage {
            version: PAYLOAD_VERSION,
            conversation_id: self.conversation_id,
            message_id,
            sent_at,
            body: body.to_owned(),
        };
        let encoded = serde_json::to_vec(&plaintext).map_err(|_| LabError::Encoding)?;
        let session = self.session.as_mut().ok_or(LabError::MissingSession)?;
        let encrypted = session.encrypt(encoded).map_err(|_| LabError::Crypto)?;
        let packet = serde_json::to_vec(&encrypted).map_err(|_| LabError::Encoding)?;
        Ok((message_id, EncryptedPacket(packet)))
    }

    /// Establish the inbound session and authenticate/decrypt the first packet.
    ///
    /// # Errors
    ///
    /// Returns an error for an existing session, malformed/non-pre-key packet,
    /// wrong sender identity, an expired envelope, failed authentication, or
    /// invalid inner binding.
    pub fn open_initial(
        &mut self,
        envelope: VerifiedEnvelope,
        expected_sender: &VerifiedPeerPreKey,
        now: u64,
    ) -> Result<OpenedMessage> {
        if self.session.is_some() {
            return Err(LabError::SessionAlreadyExists);
        }
        if envelope.expires_at() <= now {
            return Err(LabError::Unauthorized);
        }
        let olm_message: OlmMessage =
            serde_json::from_slice(envelope.packet().as_bytes()).map_err(|_| LabError::Encoding)?;
        let OlmMessage::PreKey(pre_key) = olm_message else {
            return Err(LabError::ExpectedPreKey);
        };
        // Stage account mutation so a successfully authenticated Olm packet
        // cannot consume a one-time key unless its application binding also
        // succeeds. The candidate becomes authoritative only after every
        // plaintext check passes.
        let mut candidate_account = Account::from_pickle(self.account.pickle());
        let inbound = candidate_account
            .create_inbound_session(
                SessionConfig::version_1(),
                expected_sender.curve_identity,
                &pre_key,
            )
            .map_err(|_| LabError::Crypto)?;
        let plaintext = self.validate_plaintext(&inbound.plaintext, envelope.message_id())?;
        self.account = candidate_account;
        self.session = Some(inbound.session);
        self.displayed_messages.insert(plaintext.message_id);
        Ok(OpenedMessage {
            message: plaintext,
            envelope,
        })
    }

    /// Decrypt a packet on an established session, or fail without acknowledging it.
    ///
    /// # Errors
    ///
    /// Returns an error when session state is absent, packet decoding or
    /// authentication fails, the envelope has expired, or the inner
    /// conversation/message binding is invalid.
    pub fn open(&mut self, envelope: VerifiedEnvelope, now: u64) -> Result<OpenedMessage> {
        if envelope.expires_at() <= now {
            return Err(LabError::Unauthorized);
        }
        let olm_message: OlmMessage =
            serde_json::from_slice(envelope.packet().as_bytes()).map_err(|_| LabError::Encoding)?;
        // Decrypt against a staged ratchet. Rejected application bindings do
        // not consume message keys or advance the authoritative session.
        let mut candidate_session = {
            let session = self.session.as_ref().ok_or(LabError::MissingSession)?;
            Session::from_pickle(session.pickle())
        };
        let plaintext = candidate_session
            .decrypt(&olm_message)
            .map_err(|_| LabError::Crypto)?;
        let message = self.validate_plaintext(&plaintext, envelope.message_id())?;
        self.session = Some(candidate_session);
        self.displayed_messages.insert(message.message_id);
        Ok(OpenedMessage { message, envelope })
    }

    fn validate_plaintext(
        &self,
        plaintext: &[u8],
        outer_message_id: MessageId,
    ) -> Result<PlainMessage> {
        let message: PlainMessage =
            serde_json::from_slice(plaintext).map_err(|_| LabError::InvalidPayload)?;
        if message.version != PAYLOAD_VERSION {
            return Err(LabError::InvalidPayload);
        }
        if message.conversation_id != self.conversation_id {
            return Err(LabError::WrongConversation);
        }
        if message.message_id != outer_message_id {
            return Err(LabError::MessageIdMismatch);
        }
        if self.displayed_messages.contains(&message.message_id) {
            return Err(LabError::DuplicateMessage);
        }
        Ok(message)
    }
}

fn peer_prekey_signing_bytes(
    signing_identity: Ed25519PublicKey,
    curve_identity: Curve25519PublicKey,
    one_time_key: Curve25519PublicKey,
    valid_until: u64,
) -> Vec<u8> {
    canonical(
        CONTACT_BUNDLE_ACTION,
        &[
            signing_identity.as_bytes(),
            curve_identity.as_bytes(),
            one_time_key.as_bytes(),
            &valid_until.to_be_bytes(),
        ],
    )
}
