use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

macro_rules! opaque_id {
    ($name:ident, $length:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name([u8; $length]);

        impl $name {
            #[must_use]
            pub fn random() -> Self {
                let mut value = [0_u8; $length];
                OsRng.fill_bytes(&mut value);
                Self(value)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }

            #[allow(dead_code)]
            pub(crate) fn from_slice(value: &[u8]) -> Option<Self> {
                let value: [u8; $length] = value.try_into().ok()?;
                Some(Self(value))
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"opaque")
                    .finish()
            }
        }
    };
}

opaque_id!(QueueId, 32);
opaque_id!(MessageId, 16);
opaque_id!(ConversationId, 16);
opaque_id!(Nonce, 16);
