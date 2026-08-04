## Failure or attack addressed

Describe the concrete scenario and attacker prerequisites.

## Security and metadata impact

List changed assumptions, relay-visible fields, retention, and deletion behavior.

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo test --all-targets`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Adversarial regression test added or omission explained
- [ ] Threat/security documentation updated if claims changed
- [ ] No plaintext, keys, capabilities, raw request bodies, or full identifiers added to logs
- [ ] Every commit includes `Signed-off-by` per `DCO`

## Phase boundary

- [ ] This remains disposable Phase 0 work and does not present itself as a production messenger
