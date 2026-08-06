//! Phase-2 demo: two persistence-owning façade clients on one in-memory
//! relay.
//!
//! What this demonstrates through the public API only: atomic profile
//! creation, durable mailbox registration on a real relay, redacted
//! contact offers, and a signed fetch round-trip.
//!
//! What it CANNOT demonstrate, deliberately: the full conversation. The
//! out-of-band contact exchange needs the peer's send-capability keypair
//! bytes, and the façade by design never exports a typed or serialized
//! capability owner (review finding F4). So `commit_verified_contact`
//! has no public way to receive the peer's send capability in this
//! harness, and the demo stops before session establishment. The exact
//! gap is a public "transferable send capability" artifact, which the
//! frozen §2 caller-retention list currently forbids. See the slice-F
//! report.

use std::time::{SystemTime, UNIX_EPOCH};

use secure_messenger_lab::{
    LabError, PersistentClient, PrivateStoreDir, ProfileBinding, ProtectionLevel,
    RegistrationOutcome, Relay, Result, StateKeyProtector, StoreKind,
};
use zeroize::Zeroizing;

/// Demo-grade software protector: a fixed in-process binding and an XOR
/// wrap. NOT a platform key — it exists only so the binary can run
/// without a secure enclave.
struct DemoProtector {
    binding: ProfileBinding,
    mask: [u8; 32],
}

impl DemoProtector {
    fn new(profile: u8, key: u8) -> Self {
        Self {
            binding: ProfileBinding::new([profile; 16], [key; 16]),
            mask: [key; 32],
        }
    }
}

impl StateKeyProtector for DemoProtector {
    fn expected_binding(&self) -> Result<ProfileBinding> {
        Ok(self.binding)
    }

    fn protection_level(&self) -> ProtectionLevel {
        ProtectionLevel::SoftwareBacked
    }

    fn wrap_dek(&self, dek: &Zeroizing<[u8; 32]>) -> Result<Vec<u8>> {
        let mut wrapped = b"state-wrap/v1".to_vec();
        wrapped.extend_from_slice(self.binding.profile_id());
        wrapped.extend_from_slice(self.binding.key_ref());
        wrapped.extend(dek.iter().zip(self.mask).map(|(value, mask)| value ^ mask));
        Ok(wrapped)
    }

    fn unwrap_dek(&self, wrapped_dek: &[u8], output: &mut Zeroizing<[u8; 32]>) -> Result<()> {
        const PREFIX: &[u8] = b"state-wrap/v1";
        let expected = PREFIX.len() + 16 + 16 + 32;
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

    // The demo never drives the platform-key lifecycle; these fail closed.
    fn provision_key(&self, _binding: ProfileBinding) -> Result<()> {
        Err(LabError::Storage)
    }

    fn key_status(&self, _binding: ProfileBinding) -> Result<secure_messenger_lab::KeyStatus> {
        Ok(secure_messenger_lab::KeyStatus::Present)
    }

    fn select_binding(&self, binding: ProfileBinding) -> Result<()> {
        if binding != self.binding {
            return Err(LabError::Storage);
        }
        Ok(())
    }

    fn delete_key(&self, _binding: ProfileBinding) -> Result<()> {
        Err(LabError::Storage)
    }
}

fn main() {
    if let Err(error) = run_demo() {
        eprintln!("Phase 2 demo failed: {error}");
        std::process::exit(1);
    }
}

fn run_demo() -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LabError::InvalidPayload)?
        .as_secs();

    let directory = tempfile::tempdir().map_err(|_| LabError::Storage)?;
    let alice_dir =
        PrivateStoreDir::create(&directory.path().join("alice"), StoreKind::ClientState)?;
    let bob_dir = PrivateStoreDir::create(&directory.path().join("bob"), StoreKind::ClientState)?;

    let mut relay = Relay::open_in_memory()?;
    let mut alice = PersistentClient::create(alice_dir, DemoProtector::new(0xA1, 0x1A), now)?;
    let mut bob = PersistentClient::create(bob_dir, DemoProtector::new(0xB2, 0x2B), now)?;

    // Durable mailbox registration on the relay, confirmed through the
    // action-token discipline.
    for client in [&mut alice, &mut bob] {
        let action = client.registration_action(now + 60, now)?;
        relay.register(&action.request, now)?;
        client.record_registration_result(&action, RegistrationOutcome::Confirmed)?;
    }

    // Redacted contact offers: the transferable public view of each
    // client.
    let alice_offer = alice.prekey_action(now + 300)?;
    let bob_offer = bob.prekey_action(now + 300)?;
    if alice_offer.signing_identity != alice.public_identity()?.ed25519
        || bob_offer.signing_identity != bob.public_identity()?.ed25519
    {
        return Err(LabError::InvalidPayload);
    }

    // A signed fetch round-trip against each empty mailbox.
    for client in [&alice, &bob] {
        let fetch = client.fetch_request(now + 60, now)?;
        if !relay.fetch(&fetch.request, now)?.is_empty() {
            return Err(LabError::Storage);
        }
    }

    println!(
        "PASS: two façade clients created durable profiles, registered mailboxes on a real relay, \
         minted redacted contact offers, and fetched (empty) mailboxes with verified signatures"
    );
    println!(
        "NOTE: the demo stops before the conversation: the public API has no handle for the \
         out-of-band send-capability transfer (see the module docs for the exact gap)"
    );
    Ok(())
}
