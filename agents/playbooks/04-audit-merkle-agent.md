# Devin Agent Playbook 04: Zero-Knowledge Audit Ledger & Air-Gapped Compliance CLI

> **Playbook ID**: `RSV-PLAYBOOK-04`
> **Agent Role**: Transparency Log, Merkle Cryptography & Air-Gapped Compliance Tooling Engineer
> **Active Milestones**: `M2-B` (`rsv-audit`, parallel with `M2-A`/`M2-C`) and `M5` (`rsv-compliance-cli`)
> **Target Toolchain**: Rust 2024 Edition (MSRV `1.94.0`) + `wasm32-unknown-unknown` (`rsv-audit`)

---

## 1. Mission & Exclusive Ownership

Your mission is to implement:
1. `rsv-audit` (`M2-B`): Pure `no_std + alloc`, WASM-compatible, `#![forbid(unsafe_code)]` engine for `TBK`-blinded HMAC audit tags, `CPubK`/`CPK` compliance envelope encryption/decryption, RFC 9162 domain-separated Merkle trees (`0x00` leaf / `0x01` node), inclusion & consistency proofs, C2SP `tlog-tiles` (height 8 / 256 leaves), and witness checkpoint verification.
2. `rsv-compliance-cli` (`M5`): Strictly **air-gapped** native CLI binary (ZERO network crates in dependency tree!) enabling compliance auditors and VSS custodians to verify Merkle checkpoints, detect server tampering or split-view forks, decrypt `X-RSV-Audit-Envelope` export bundles using offline `CPK`, and execute `t`-of-`n` Feldman VSS `ORPK_SEED` recovery ceremonies inside `LockedSecretBox`.

### Exclusive Write Ownership
- `crates/rsv-audit/`
- `crates/rsv-compliance-cli/`
- `test-vectors/v1/audit_blinded_hmac.kat.json`
- `test-vectors/v1/audit_rfc9162_merkle_tiles.kat.{json,cbor}`

### Owned Formal Invariants
`INV-010`, `INV-011`, `INV-012`, `INV-015`, `INV-016`, `INV-017`, `INV-018`, `INV-019`

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context:
1. [`AGENTS.md`](../../AGENTS.md)
2. [`agents/CRATE-CONTRACTS.md`](../CRATE-CONTRACTS.md) (§2, §3.3, §3.5, §5)
3. [`agents/BUILD-DAG.md`](../BUILD-DAG.md) (Milestones `M2-B` & `M5`)
4. [`specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md`](../../specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md)
5. [`specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md`](../../specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md) (Feldman VSS & `ORPK_SEED` recovery sections)
6. [`adrs/ADR-0005-rfc9162-c2sp-tiled-merkle-audit-log.md`](../../adrs/ADR-0005-rfc9162-c2sp-tiled-merkle-audit-log.md)
7. [`adrs/ADR-0001-hybrid-escrow-and-feldman-vss.md`](../../adrs/ADR-0001-hybrid-escrow-and-feldman-vss.md)
8. [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](../../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (§4: `INV-015`–`INV-019`)
9. [`specs/10-TEST-VECTORS-AND-VERIFICATION.md`](../../specs/10-TEST-VECTORS-AND-VERIFICATION.md) (§2.5, §2.6, §3.3)

---

## 3. Strict Boundaries & Forbidden Actions

1. **ZERO `unsafe` Code (`INV-010`)**: Both `crates/rsv-audit/src/lib.rs` and `crates/rsv-compliance-cli/src/main.rs` MUST declare `#![forbid(unsafe_code)]`.
2. **Strict Air-Gap Firewall on `rsv-compliance-cli` (`INV-019`)**: `rsv-compliance-cli` MUST contain **ZERO** network or async runtime dependencies (`tokio`, `reqwest`, `hyper`, `axum`, `sqlx`, `rustls`, `socket2`, `mio`, `h2` are ALL strictly forbidden). Every CLI test MUST pass inside a network-isolated namespace (`unshare -rn`).
3. **Strict Tier-0 Firewall on `rsv-audit`**: `rsv-audit` MUST remain `no_std + alloc` and compile cleanly to `--no-default-features --target wasm32-unknown-unknown` with zero OS/async/DB crates.
4. **Exact RFC 9162 Domain Separation (`INV-018`)**: Leaf hashing MUST prepend `0x00`; interior node hashing MUST prepend `0x01`; empty tree root MUST equal `SHA-256("")` (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). Never omit prefixes (prevents second-preimage tree-forging attacks).
5. **Exact Blinded HMAC Domain Prefix (`INV-017`)**: `compute_blinded_tag` MUST bind domain `"rsv:audit:blind:v1"`, `tenant_id`, `field_domain`, and canonical value with length-prefixed encoding to eliminate canonicalization ambiguity.
6. **Locked Memory for Sensitive CLI Keys (`INV-011`, `INV-012`)**: `rsv-compliance-cli` MUST call `rsv_mem::harden_process()` at startup, hold `CPK`, trustee VSS shares, and reconstructed `ORPK_SEED` strictly inside `rsv_mem::LockedSecretBox`, and NEVER print raw private keys to stdout/stderr/logs unless explicitly requested to a `0600` sealed output file during an authorized recovery ceremony.
7. **Deterministic Non-Zero Exit Codes (`specs/10` §3.3)**: Verification failures MUST return distinct documented non-zero exit codes (`10`..`15`) and machine-readable JSON diagnostics—never exit `0` on warnings or missing witness signatures.

---

## 4. Ordered Implementation Checklist

### Phase A — Milestone `M2-B` (`crates/rsv-audit/`)
1. Implement `compute_blinded_tag` (`HMAC-SHA256(TBK, "rsv:audit:blind:v1" || tenant_id || len(field_domain) || field_domain || canonical_value)`).
2. Implement `seal_compliance_envelope` and `open_compliance_envelope` wrapping canonical CBOR audit records under `CPubK`/`CPK` (`CS-01` or `CS-02` X-Wing) with mandatory `AadContext` binding `(tenant_id, device_id, idempotency_key, event_type_code)`.
3. Implement RFC 9162 Merkle Hash Tree (`hash_leaf`, `hash_node`, `compute_root`, `generate_inclusion_proof`, `verify_inclusion_proof`, `generate_consistency_proof`, `verify_consistency_proof`) using overflow-checked `u64` arithmetic.
4. Implement C2SP `tlog-tiles` (height 8, 256 leaves per full tile, partial tile paths `tile/L/NNN.p/W`) encoder, decoder, and tile-backed root/proof verifier.
5. Implement signed checkpoint parser & witness cosignature verifier (`verify_witnessed_checkpoint`) supporting C2SP Signed Note format + split-view fork detection (`AuditError::SplitViewDetected`).
6. Generate and verify `test-vectors/v1/audit_blinded_hmac.kat.json` and `test-vectors/v1/audit_rfc9162_merkle_tiles.kat.{json,cbor}` (0 leaves, 8 leaves, 300 leaves crossing height-8 tile boundary) plus `prop_rfc9162_inclusion_consistency`.
7. Run `M2-B` exit commands and open `M2-B` PR.

### Phase B — Milestone `M5` (`crates/rsv-compliance-cli/`)
8. Implement air-gapped CLI (`clap`) calling `rsv_mem::harden_process()` + `install_scrubbing_panic_hook()` on entry with three subcommands:
   - `rsv-compliance-cli verify-log --bundle <dir> --log-vk <file> --witness-vks <dir> --min-witnesses <k> [--prior-checkpoint <file>]`: verifies all C2SP tiles, leaf hashes, witness cosignatures, and consistency against prior checkpoints; emits exact exit codes (`10` leaf mismatch, `11` missing row/root mismatch, `12` split-view fork, `13` witness sig invalid).
   - `rsv-compliance-cli decrypt-audit --bundle <dir> --cpk-file <file> --out <ndjson>`: verifies Merkle inclusion first (refusing to decrypt unverified logs unless `--allow-unverified` is explicitly denied in production mode), unseals every `X-RSV-Audit-Envelope` with `CPK` inside `LockedSecretBox`, fails with exit code `14` on any AAD mismatch.
   - `rsv-compliance-cli vss-ceremony {verify-share | reconstruct}`: verifies individual trustee shares offline against `FeldmanCommitments` (`INV-015`, exit code `15` on poisoned share) and reconstructs `ORPK_SEED` inside `LockedSecretBox` when `>= t` valid shares are supplied (`INV-016`), verifying deterministic `ORPubK` fingerprint match.
9. Implement `crates/rsv-compliance-cli/tests/merkle_tamper_chaos.rs` executing all 8 chaos cases (`CHAOS-AUDIT-01` through `CHAOS-AUDIT-08` from `specs/10` §3.3).
10. Run `M5` exit commands (including `unshare -rn` network sandbox) and open `M5` PR.

---

## 5. Exact Verification Commands & Exit Criteria

ALL commands below MUST exit with code `0` before opening your PR:

```bash
# 1. Formatting, strict clippy & unsafe firewall
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 clippy -p rsv-audit -p rsv-compliance-cli --all-targets -- -D warnings
grep -q '#!\[forbid(unsafe_code)\]' crates/rsv-audit/src/lib.rs
grep -q '#!\[forbid(unsafe_code)\]' crates/rsv-compliance-cli/src/main.rs

# 2. Tier-0 no_std + WASM firewall for rsv-audit
cargo +1.94.0 check -p rsv-audit --no-default-features --target wasm32-unknown-unknown
! cargo tree -p rsv-audit | grep -E 'tokio|sqlx|axum|gpui|libc|windows|reqwest|hyper'

# 3. Strict Air-Gap Firewall for rsv-compliance-cli (ZERO network crates!)
! cargo tree -p rsv-compliance-cli | grep -E 'tokio|reqwest|hyper|axum|sqlx|rustls|socket2|mio|h2'

# 4. Audit KATs & heavy property tests
cargo +1.94.0 test -p rsv-audit --features kat-deterministic
PROPTEST_CASES=2048 cargo +1.94.0 test -p rsv-audit

# 5. Air-gapped Merkle Tamper, Split-View & VSS Recovery Chaos Suite (zero network namespace!)
unshare -rn cargo +1.94.0 test -p rsv-compliance-cli --test merkle_tamper_chaos -- --nocapture

# 6. Supply chain & license compliance
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

---

## 6. Handoff & PR Contract

- **Branch Naming**: `feat/m2b-agent04-audit`, `feat/m5-agent04-compliance-cli`
- **PR Description MUST Include**:
  - Explicit Invariant Tags Verified: `[INV-010] [INV-011] [INV-012] [INV-015] [INV-016] [INV-017] [INV-018] [INV-019]`
  - Output of `cargo tree -p rsv-compliance-cli` confirming zero network/socket crates.
  - Complete pass table of `CHAOS-AUDIT-01`..`CHAOS-AUDIT-08` executed inside `unshare -rn` showing exact exit codes (`0`, `10`, `11`, `12`, `13`, `14`, `15`).
- **Downstream Unblock Signal**: Merging `M2-B` unblocks Agents 03 (`M3-A`) and 06 (`M3-B`); merging `M5` unblocks Agent 07 (`M6`).
