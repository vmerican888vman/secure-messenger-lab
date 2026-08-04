# Contributing

This is an experimental security lab, not a secure product. Small, test-backed contributions that
make a claim narrower, an invariant stronger, or a failure reproducible are welcome.

## Before opening a pull request

1. For a suspected vulnerability, stop and follow `SECURITY.md`; do not open a public issue.
2. For protocol, identity, persistence, or cryptographic changes, open a design discussion before
   writing code. State the attacker, invariant, failure case, and test oracle.
3. Do not implement cryptographic primitives. Use reviewed high-level library APIs and justify any new
   dependency, feature flag, or protocol.
4. Keep production features, branding, hosting, telemetry, analytics, and monetization out of this
   disposable Phase 0 repository.

## Required checks

```sh
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

Add an adversarial integration test for every security-relevant behavior. Tests must go through the
same client and relay path as the demo; a raw-key unit test alone is insufficient.

## DCO sign-off

Every commit must certify the Developer Certificate of Origin 1.1 in `DCO`:

```sh
git commit -s
```

This adds `Signed-off-by: Name <email>` to the commit. The sign-off is a certification of your right
to contribute under Apache-2.0; it is not a copyright assignment. Contributors retain ownership of
their work. No CLA is required today.

## Pull request expectations

- Explain the concrete attack or failure scenario.
- List changed trust assumptions and metadata.
- Show a failing test before the fix when practical.
- Update `THREAT_MODEL.md`, `SECURITY_STATUS.md`, or architecture docs when a claim changes.
- Avoid message bodies, keys, capabilities, raw request bodies, or full identifiers in logs and test
  failure output.
- Preserve the experimental/unaudited warning.

By participating, you agree to `CODE_OF_CONDUCT.md`.
