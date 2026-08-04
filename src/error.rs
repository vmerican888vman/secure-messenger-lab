use thiserror::Error;

/// Errors are intentionally coarse: callers should not expose detailed crypto
/// failures to untrusted peers or logs.
#[derive(Debug, Error)]
pub enum LabError {
    #[error("no encrypted session is available; sending stopped")]
    MissingSession,
    #[error("an encrypted session already exists")]
    SessionAlreadyExists,
    #[error("the packet did not contain the required pre-key message")]
    ExpectedPreKey,
    #[error("the peer key bundle could not be authenticated")]
    PeerVerificationFailed,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("encrypted packet encoding failed")]
    Encoding,
    #[error("message payload was invalid")]
    InvalidPayload,
    #[error("the message belongs to another conversation")]
    WrongConversation,
    #[error("the message identifier did not match its encrypted payload")]
    MessageIdMismatch,
    #[error("this logical message was already displayed")]
    DuplicateMessage,
    #[error("relay authorization failed")]
    Unauthorized,
    #[error("relay request expired")]
    RequestExpired,
    #[error("message expiry is invalid")]
    InvalidExpiry,
    #[error("mailbox does not exist")]
    MailboxNotFound,
    #[error("mailbox registration conflicts with an existing mailbox")]
    MailboxConflict,
    #[error("message identifier conflicts with a different envelope")]
    MessageConflict,
    #[error("message has already been acknowledged or expired")]
    MessageGone,
    #[error("message does not exist")]
    MessageNotFound,
    #[error("relay storage failed")]
    Storage,
}

pub type Result<T> = std::result::Result<T, LabError>;

impl From<rusqlite::Error> for LabError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
