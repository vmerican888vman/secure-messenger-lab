# Fable review — PrivateStoreDir boundary v2 — VERDICT: PASS

- **Reviewer:** Fable (claude-fable-5), isolated clean worktree.
- **Head SHA reviewed:** `f056cac36f78212cd152cd806be84feb7975db1f`.
- **Verdict: PASS** — no blocking findings.

- Required all-target tests and Clippy passed.
- Repeated stability: 200 runs, all passed.
- Empirical ACL, permission propagation, socket/FIFO/symlink/hardlink
  rejection, same/cross-process locking, process-death recovery, and
  descriptor-leak probes passed.

Non-blocking observations: wording around the documented pathname race could
be broadened; Linux default-ACL detection could be hardened later. Neither
violates frozen §1's threat model.

v1 verdict (`09dc706`, PASS with non-blocking notes):
`reviews/REVIEW-fable-private-store-dir.md`. Sol RETURNed v1; this PASS
covers the remediated head.

Scope note: this opens only the `PrivateStoreDir` boundary leg; it is not a
broader Phase-2 production-security approval.
