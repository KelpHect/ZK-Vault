# AGENTS.md — RusticStack Core (`ZK-Vault`) Autonomous Engineering Manual

> **Injection Notice:** Kept strictly **under 15 KiB** so autonomous agents (including Devin's 16 KiB auto-injection window) load 100% of hard guardrails on Turn 0 without truncation. Deep normative specs live in `specs/00..15`, `adrs/ADR-0001..0012`, `schemas/`, and `agents/playbooks/01..10`.

---

## 1. Repository State & Mission

- **Project:** RusticStack Core (`ZK-Vault`) — `https://github.com/KelpHect/ZK-Vault`
- **Current Phase:** **Normative Specification Repository (`v1.0-spec`)**. No implementation code exists yet.
- **When editing specs:** Preserve cross-document consistency across `specs/`, `adrs/`, `schemas/`, and `agents/`. Never leave TODOs or diverging identifiers.
- **When commissioned for milestones (`M0`–`M7`):** Follow `agents/BUILD-DAG.md`, lock strictly to `agents/CRATE-CONTRACTS.md`, and run your domain playbook in `agents/playbooks/01..10`.

---

## 2. Hard Non-Negotiable Guardrails (STOP IF VIOLATED)

1. **Zero Server Knowledge (`INV-001`):** `rsv-server` and PostgreSQL MUST NEVER decrypt, log, or possess plaintext vault payloads, collection/team metadata, attachments, `MUK`, `USK`, `TK`, `CK`, `DEK`, `AEK`, `ORPK`, `DRPK`, or `CPK`.
2. **`unsafe` Firewall (`INV-010`):** Every Rust crate MUST declare `#![forbid(unsafe_code)]` EXCEPT `rsv-mem` and `rsv-enclave`, which isolate OS/hardware FFI with `// SAFETY:` proofs on every `unsafe` block.
3. **Dependency Firewall:** Tier 0 crates (`rsv-types`, `rsv-crypto`, `rsv-vss`, `rsv-graph`, `rsv-audit`) MUST remain `no_std` + `alloc`, compile to `wasm32-unknown-unknown`, and NEVER depend on `tokio`, `sqlx`, `axum`, `gpui`, `libc`, `windows`, or filesystem/network I/O.
4. **Mandatory AEAD AAD (`INV-002`, `INV-030`):** Every `AES-256-GCM` encryption (including 64 KiB STREAM attachment chunks) MUST bind canonical CBOR AAD `(domain, tenant_id, object_id, parent_id, epoch_or_version, cipher_suite_id)`. Empty AAD is a build-breaking vulnerability.
5. **No Secret Leakage (`INV-011`, `INV-032`, `INV-033`, `INV-034`):** Wrap every key in `secrecy::SecretBox<T>` + `zeroize::ZeroizeOnDrop`. Never print secrets in `Debug`/logs/telemetry, never store plaintext in browser storage/DOM, and always set OS concealed/history-excluded clipboard flags with auto-clear.
6. **Hardware Enclave Reality (`INV-013`):** Apple Secure Enclave natively isolates **NIST P-256 ONLY** (never Ed25519/X25519); TPM 2.0 chips widely support P-256/RSA. Use Two-Tier Hardware Trust: silicon P-256 `HDIK`/`HDSK` seals/signs for software X25519/X-Wing/Ed25519 keys.
7. **Post-Quantum & VSS Exactness (`INV-004`, `INV-015`):** `CS-02` uses **X-Wing** (`draft-connolly-cfrg-xwing-kem`: `SHA3-256(ss_M || ss_X || ct_X || pk_X || 0x5c2e2f2f5e5c)` — NEVER confuse with TLS 1.3 `X25519MLKEM768`). Feldman VSS (`rsv-vss`) splits 256-bit `ORPK_SEED` into two 128-bit chunks with **124-bit CSPRNG high-order scalar padding** over Ristretto255 to defeat $2^{64}$ Pollard Kangaroo attacks on commitments.
8. **PostgreSQL Dual-Enforced RLS (`INV-006`, `INV-007`):** NEVER bypass `TenantScopedTx`. Every tenant query MUST run `SELECT set_config('app.current_tenant_id', $1::text, true)` (PgBouncer transaction-mode safe) AND include an explicit `WHERE tenant_id = $1` predicate for O(1) 64-way `HASH (tenant_id)` partition pruning. `rsv_app` MUST have `NOBYPASSRLS`.
9. **Key Transparency & Blind SSO/SCIM (`INV-025`–`INV-027`, `INV-036`):** Every provisioning grant MUST verify witnessed `vault.key_transparency_log` inclusion/consistency before wrapping keys. OIDC/SAML MUST obey `Authentication != Decryption`; SCIM 2.0 writes unsigned `scim_pending_intents` only and never holds keys.
10. **Chrome Native Messaging & WASM Arena (`INV-021`, `INV-024`, `INV-035`):** `rsv-nm-host` -> Extension frames MUST stay `<= 786,432` bytes (under Chrome's 1 MiB kill limit). `rsv-wasm` uses a **Dual Fixed-Memory Worker Split** (`16 MiB` core + `144 MiB` ephemeral Argon2id worker, `0` `memory.grow` opcodes) with opaque `KeyHandle(u32)` handles only. Autofill MUST require explicit user gesture and Closed Shadow DOM isolation.
11. **Zero-Disk SSH Agent & CLI Injection (`INV-028`, `INV-029`):** RFC 9987 SSH private keys live strictly in `rsv-mem` locked RAM gated by biometric/hardware approval; `rsv run` injects resolved `rsv://` secrets strictly into child `envp` (never `.env` files).
12. **Zero AI Attribution in Git History:** Never include AI model/tool names or `Co-Authored-By` trailers in git commits.

---

## 3. Target Toolchain & Pinned Ecosystem Versions

- **Rust:** Edition `2024`, MSRV **`1.94.0`** | **DB:** PostgreSQL `17`/`18` + `PgBouncer` (transaction mode)
- **Web/Extension:** React `19`, TypeScript `5.8+` (strict), Vite `6`, Tailwind CSS `v4`, zero runtime external CDNs (`INV-032`)
- **Pinned Rust Crates:** `aes-gcm` `0.11`, `hpke` `0.15`, `ml-kem` (FIPS 203), `x25519-dalek` `3.0`, `ed25519-dalek` `3.0`, `argon2` `0.6`, `hkdf`, `hmac`, `sha2`, `sha3`, `blake3`, `secrecy` `0.10`, `zeroize` `1.9`, `vsss-rs` `6.0`, `tss-esapi`, `windows`, `security-framework`, `axum` `0.8`, `tokio` `1.x`, `sqlx` `0.9`, `webauthn-rs`, `gpui` / `gpui-ce`, `wasm-bindgen`.

---

## 4. Planned 13-Crate Workspace Topology

| Crate | Scope | `no_std`/WASM | `unsafe` | Primary Spec(s) |
| :--- | :--- | :---: | :---: | :--- |
| `rsv-types` | UUIDv7 IDs, DTOs, deterministic CBOR, errors | Yes | Forbidden | `SPEC-08`, `CRATE-CONTRACTS` |
| `rsv-crypto` | `CS-01`/`CS-02` (X-Wing), AEAD, STREAM, HPKE, Argon2id | Yes | Forbidden | `SPEC-02`, `SPEC-13` |
| `rsv-vss` | Feldman VSS (2×128b + 124b pad Ristretto255), resharing | Yes | Forbidden | `SPEC-02` |
| `rsv-graph` | Blind RBAC DAG resolver, cycle check, epoch planner | Yes | Forbidden | `SPEC-04`, `SPEC-11` |
| `rsv-audit` | Blinded HMAC, `CPubK` envelopes, RFC 9162 / C2SP tiles, KT | Yes | Forbidden | `SPEC-06`, `SPEC-11` |
| `rsv-mem` | `LockedSecretBox`, guard pages, `mlock`/`VirtualLock`/DACL | Native | Audited | `SPEC-03` |
| `rsv-enclave` | `HardwareKeyProvider` (Apple SE, TPM 2.0, Win CNG) | Native | Audited | `SPEC-03` |
| `rsv-wasm` | Dual fixed-arena WASM workers, opaque `KeyHandle(u32)` | WASM | Forbidden | `SPEC-03`, `SPEC-07`, `SPEC-15` |
| `rsv-daemon` | Locked crypto daemon, OS IPC, `rsv-nm-host`, RFC 9987 SSH Agent, offline cache | Native | Forbidden | `SPEC-07`, `SPEC-12`, `SPEC-13` |
| `rsv-desktop` | GPUI native 120 FPS desktop UI + Admin Mode | Native | Forbidden | `SPEC-07`, `SPEC-15` |
| `rsv-cli` | Thin CLI (`rsv run` zero-disk injection, OIDC workload identity, migration) | Native | Forbidden | `SPEC-12`, `SPEC-13` |
| `rsv-server` | Blind Axum API (Sovereign `<128 MiB` & HA Cells), `TenantScopedTx`, SCIM, C2SP tiles | Native | Forbidden | `SPEC-05`, `SPEC-08`, `SPEC-11`, `SPEC-14` |
| `rsv-compliance-cli` | Air-gapped audit decryptor (`CPK`), Merkle/KT & VSS CLI | Native | Forbidden | `SPEC-06`, `SPEC-02`, `SPEC-14` |

---

## 5. Canonical Identifiers & Unified 17-Table Schema

### Cryptographic Keys
- `HDIK`/`HDSK`: Non-exportable NIST P-256 silicon identity & sealing keys
- `MUK`: Master Unlock Key (`Argon2id` XOR `HKDF(WebAuthn PRF)`)
- `UIK` (`Ed25519`), `UPK`/`USK` (`X25519` or `X-Wing`): User identity & KEM keypairs
- `MIK`/`MPK`: Machine Identity signing & KEM keypairs (OIDC Workload Identity, read-only `permission_mask = 1`)
- `ORPubK`/`ORPK`: Organization Root Recovery (`ORPK_SEED` split via `t-of-n` Feldman VSS, default `3-of-5`)
- `DRPubK`/`DRPK`: Scoped Delegated Recovery (allowed on `standard` tier ONLY; forbidden on `enterprise_escrow` / `strict_zk`)
- `TK`, `CK`, `DEK`, `AEK`: 256-bit symmetric Team, Collection, Item, and STREAM Attachment keys
- `CPubK`/`CPK`: Standalone Compliance HPKE keypair (`CPK` offline/HSM only) | `TBK`: Tenant Blinding Key (`"rsv:audit:blind:v1"`, KMS/RAM only)

### PostgreSQL `vault` Schema (17 Tables — `schemas/postgresql-schema.sql`)
- **Core (12):** `tenants`, `tenant_vss_ceremonies`, `users`, `user_devices`, `teams`, `collections`, `key_graph_edges` *(HASH-64)*, `vault_items` *(HASH-64)*, `vault_item_revisions` *(HASH-64)*, `audit_events` *(HASH-64)*, `audit_merkle_tiles` *(HASH-64)*, `audit_checkpoints`.
- **Extensions (5):** `key_transparency_log` *(HASH-64)*, `key_transparency_checkpoints`, `scim_pending_intents`, `machine_identities`, `vault_attachments` *(HASH-64)*.
- **Canonical `escrow_tier` SQL Enum:** `standard` (CK + `ORPubK` + `DRPubK`), `enterprise_escrow` (CK + `ORPubK` root-quorum-only; NO `DRPubK`), `strict_zk` (CK only; no delegated recovery).

### API Contract (`schemas/openapi-v1.yaml` & `SPEC-08`/`11`/`12`/`13`)
- Base paths: `/api/v1` and `/scim/v2`
- Mandatory headers: `Authorization`, `X-RSV-Tenant-Id`, `X-RSV-Device-Id`, `X-RSV-Request-Signature`, `X-RSV-Audit-Envelope`, `Idempotency-Key`.
- Core error codes: `TENANT_MISMATCH`, `INVALID_SIGNATURE`, `MISSING_AUDIT_ENVELOPE`, `STALE_KEY_EPOCH`, `VERSION_CONFLICT`, `GRAPH_CYCLE_REJECTED`, `ESCROW_POLICY_VIOLATION`, `UNSUPPORTED_CIPHER_SUITE`, `DEVICE_ATTESTATION_FAILED`, `RATE_LIMITED`, `QUORUM_THRESHOLD_UNMET`, `AUDIT_COMMITMENT_INVALID`, `KT_PROOF_INVALID`, `KT_SPLIT_VIEW_DETECTED`, `SSO_ASSERTION_INVALID`, `ENROLLMENT_EXPIRED`, `SCIM_SCOPE_VIOLATION`.

---

## 6. Specification & Playbook Lookup Map

| Domain | Read First | Playbook |
| :--- | :--- | :--- |
| System topology, glossary, invariants | `specs/00`, `specs/01`, `specs/09` (`INV-001..036`) | `agents/README.md`, `BUILD-DAG.md` |
| Crypto envelopes, X-Wing, Feldman VSS | `specs/02`, `adrs/ADR-0001`, `ADR-0007` | `playbooks/01-crypto-core-agent.md` |
| OS memory locking, TPM/SE, WASM arena | `specs/03`, `adrs/ADR-0004`, `ADR-0008` | `playbooks/02-os-enclave-mem-agent.md` |
| Blind RBAC, PG 17/18 RLS, OpenAPI | `specs/04`, `specs/05`, `specs/08`, `schemas/*`, `ADR-0002` | `playbooks/03-backend-rls-agent.md` |
| Blinded audit, RFC 9162, C2SP tiles | `specs/06`, `adrs/ADR-0005` | `playbooks/04-audit-merkle-agent.md` |
| GPUI daemon/desktop, MV3 ext, Web SPA | `specs/07`, `schemas/ipc-*`, `ADR-0003`, `ADR-0006` | `playbooks/05`, `playbooks/06` |
| KATs, RLS/RAM/Merkle chaos, fuzzing | `specs/10`, `agents/CRATE-CONTRACTS.md` | `playbooks/07-qa-redteam-agent.md` |
| Key Transparency, OIDC/SAML, SCIM, SSH, Passkeys, CLI | `specs/11`, `specs/12`, `ADR-0009`, `ADR-0010` | `playbooks/08-sso-keytrans-devsecrets-agent.md` |
| STREAM attachments, Offline Sync, CXF, Sovereign Ops | `specs/13`, `specs/14`, `ADR-0011`, `ADR-0012` | `playbooks/09-attachments-sync-selfhost-agent.md` |
| GPUI Views, MV3 Autofill UX, Web SPA, Org Dashboard | `specs/15` | `playbooks/10-ui-ux-dashboard-agent.md` |

---

## 7. Mandatory Verification Gates (For Future Implementation PRs)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p rsv-types -p rsv-crypto -p rsv-vss -p rsv-graph -p rsv-audit --target wasm32-unknown-unknown
cargo test --workspace
cargo audit && cargo deny check
# Plus domain gates per playbook: 100-tenant RLS chaos + Subplans Removed: 63,
# /proc/self/smaps VmLck+dd & post-Drop canary, wasmparser 0 memory.grow check,
# RFC 9162 Merkle/KT tamper & witness split-view rejection, Native Messaging >1 MiB chunking,
# STREAM chunk truncation/reorder tests, and Playwright zero-leak DOM/autofill suites.
```
