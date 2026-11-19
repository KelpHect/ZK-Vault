# Architecture Decision Records (ADRs)

This directory contains all **Architecture Decision Records (ADRs)** for RusticStack Core (`ZK-Vault`), authored in [MADR](https://adr.github.io/madr/) format. Each ADR documents an immutable architectural trade-off, the rejected alternatives, the security/performance rationale, and concrete verification criteria that autonomous coding agents and engineers MUST uphold.

---

## ADR Index

| ID | Title | Status | Governing Spec(s) |
| :--- | :--- | :---: | :--- |
| **[ADR-0001](ADR-0001-hybrid-escrow-and-feldman-vss.md)** | Hybrid Escrowed Public Key Wrappers + Padded Feldman Verifiable Secret Sharing for Recovery | Accepted | [`SPEC-02`](../specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md) |
| **[ADR-0002](ADR-0002-shared-schema-rls-over-schema-per-tenant.md)** | Shared Schema with Dual-Enforced PostgreSQL RLS & Hash Partitioning over Schema-per-Tenant | Accepted | [`SPEC-05`](../specs/05-MULTI-TENANT-DATABASE.md) |
| **[ADR-0003](ADR-0003-gpui-native-desktop-over-electron.md)** | Native Rust GPUI Desktop Client + Locked Daemon over Electron/WebView | Accepted | [`SPEC-03`](../specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md), [`SPEC-07`](../specs/07-OMNI-CLIENT-ARCHITECTURE.md) |
| **[ADR-0004](ADR-0004-two-tier-hardware-enclave-p256-delegation.md)** | Two-Tier Hardware Enclave Delegation Using Native NIST P-256 Silicon Keys | Accepted | [`SPEC-03`](../specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md) |
| **[ADR-0005](ADR-0005-rfc9162-c2sp-tiled-merkle-audit-log.md)** | RFC 9162 Domain-Separated Merkle Trees & C2SP `tlog-tiles` with Witness Cosigning | Accepted | [`SPEC-06`](../specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md) |
| **[ADR-0006](ADR-0006-native-messaging-daemon-offload-for-extension.md)** | Chrome MV3 Extension Cryptographic Offload via Chunked Native Messaging to GPUI Daemon | Accepted | [`SPEC-07`](../specs/07-OMNI-CLIENT-ARCHITECTURE.md) |
| **[ADR-0007](ADR-0007-crypto-agility-xwing-post-quantum-hybrid.md)** | Versioned Cipher Suite Agility with X-Wing (`X25519 + ML-KEM-768`) Post-Quantum Hybrid KEM | Accepted | [`SPEC-02`](../specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md) |
| **[ADR-0008](ADR-0008-wasm-fixed-arena-zeroization-strategy.md)** | Dual Fixed-Memory WebAssembly Worker Split & Opaque Key Handles for Browser Zeroization | Accepted | [`SPEC-03`](../specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md), [`SPEC-07`](../specs/07-OMNI-CLIENT-ARCHITECTURE.md) |
| **[ADR-0009](ADR-0009-key-transparency-and-blind-scim-sso.md)** | Auditable Key Transparency Directory, `Auth != Decrypt` Enterprise SSO & Blind SCIM 2.0 | Accepted | [`SPEC-11`](../specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md) |
| **[ADR-0010](ADR-0010-native-ssh-agent-and-synced-passkeys.md)** | Native RFC 9987 Hardware-Gated SSH Agent, Synced Enterprise Passkeys & OIDC Machine Identities | Accepted | [`SPEC-12`](../specs/12-DEVELOPER-SECRETS-SSH-PASSKEYS-AND-CLI.md) |
| **[ADR-0011](ADR-0011-stream-chunked-aead-and-fido-cxf.md)** | STREAM 64 KiB Chunked AEAD Attachments & FIDO Alliance CXF/CXP v1.0 Interoperability | Accepted | [`SPEC-13`](../specs/13-STREAMING-ATTACHMENTS-OFFLINE-SYNC-AND-MIGRATION.md) |
| **[ADR-0012](ADR-0012-dual-profile-sovereign-self-hosting.md)** | Dual-Profile Single-Binary Sovereign Self-Hosting (`< 128 MiB` RAM) & Enterprise HA Cells | Accepted | [`SPEC-14`](../specs/14-SELF-HOSTED-OPERATIONS-AND-OBSERVABILITY.md) |

---

## Governance Rules

1. **Immutability:** Accepted ADRs are NEVER silently edited to change an engineering decision. To reverse or evolve a decision, propose a new ADR (`ADR-NNNN`) that marks the prior record as `Superseded by ADR-NNNN`.
2. **Agent Compliance:** Autonomous coding agents MUST NOT deviate from any `Accepted` ADR without an explicit human-approved superseding ADR.
3. **Traceability:** Every ADR MUST cite the formal invariants (`INV-001`–`INV-036`) it establishes or enforces.
