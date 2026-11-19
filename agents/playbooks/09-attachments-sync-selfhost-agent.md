# Agent Playbook 09: Streaming Attachments, Offline Sync, Migration & Sovereign Self-Hosting Agent

| Field | Value |
| :--- | :--- |
| **Playbook ID** | `AGENT-09` (`09-attachments-sync-selfhost-agent`) |
| **Project** | RusticStack Core (`ZK-Vault` — `https://github.com/KelpHect/ZK-Vault`) |
| **Target Toolchain** | Rust 2024 Edition, MSRV `1.94.0` |
| **Primary Crates** | `rsv-types`, `rsv-crypto`, `rsv-daemon`, `rsv-wasm`, `rsv-desktop`, `rsv-server`, `rsv-cli`, `rsv-compliance-cli` |
| **Primary Normative Specs** | `specs/13-STREAMING-ATTACHMENTS-OFFLINE-SYNC-AND-MIGRATION.md`, `specs/14-SELF-HOSTED-OPERATIONS-AND-OBSERVABILITY.md` |
| **Primary ADRs** | `adrs/ADR-0011-stream-chunked-aead-and-fido-cxf.md`, `adrs/ADR-0012-dual-profile-sovereign-self-hosting.md` |
| **Enforced Invariants** | `INV-001`, `INV-002`, `INV-006`, `INV-007`, `INV-010`, `INV-011`, `INV-012`, `INV-024`, `INV-030`, `INV-031`, `INV-032` |

---

## 1. Scoped Engineering Mission

You are the autonomous implementation agent commissioned to deliver **Streaming Encrypted Attachments (STREAM)**, **Offline-First Hardware-Sealed Sync & 3-Way Conflict Resolution**, **FIDO CXF v1.0 / CXP & Offline Importers + Printable Emergency Recovery Kits**, and **Dual-Profile Sovereign Self-Hosting (`< 128 MiB` RAM) + Enterprise HA / PITR / GDPR Crypto-Shredding / Zero-Secret Observability** for RusticStack Core (`ZK-Vault`).

Your deliverables span five cohesive workstreams:
1. **STREAM Chunked AEAD & `vault.vault_attachments`**: Constant-memory 64 KiB `AES-256-GCM` streaming encryption/decryption in `rsv-crypto` (`no_std + alloc`, WASM-clean), incremental `BLAKE3` ciphertext root commitments, PostgreSQL `vault.vault_attachments` migration (HASH-64 + `FORCE RLS` + escrow `CHECK`), and `< 256 KiB` RAM/stream `/api/v1/attachments/*` endpoints supporting both pre-signed S3/MinIO and Sovereign local disk.
2. **Offline-First Encrypted Cache & Lossless 3-Way Sync**: Page-encrypted local cache in `rsv-daemon` keyed by `HDSK`-sealed `CacheKey`, cursor-based `/api/v1/sync/delta` + WebSocket integration, freshly re-signed offline mutation replay (`If-Match` + `Idempotency-Key`), and deterministic 3-way conflict detection surfacing structured `ConflictPair` merge workflows (zero silent overwrite).
3. **FIDO CXF v1.0 / CXP, Offline Importers & Emergency Recovery Kit**: Pure-Rust `#![forbid(unsafe_code)]` client-side importers/exporters (FIDO CXF v1.0 / CXP with Passkeys, Bitwarden JSON & Encrypted Export, 1Password `.1pux`, KeePassXC `.kdbx` v4, hardened browser CSV) and 100% local in-memory printable Emergency Recovery Kits (SLIP-0039 33-word mnemonic + Bech32m `rsvrk1...` + Level-H QR code).
4. **Dual-Profile Sovereign & Enterprise HA `rsv-server`**: Single static `musl` binary implementing `ObjectStoreBackend`, `KmsTbkProvider`, `SyncEventBus`, and `TilePublisher` across Profile 1 (`sovereign`: `< 45 MiB` idle / `< 128 MiB` active, single PG 17/18, embedded Web SPA, zero phone-home) and Profile 2 (`enterprise_ha`: Patroni + PgBouncer + S3 WORM + Witnesses + Cloud/HSM KMS + Cell routing), plus hardened Docker Compose and `systemd` unit deliverables.
5. **PITR Merkle Rollback Detection, Single-Tenant Portable Export, GDPR Crypto-Shredding & Zero-Secret Observability**: `rsv-compliance-cli verify-restore`, `rsv-cli tenant export`, two-phase GDPR erasure + attestation certificate, compile-time `Redacted<T>` wrappers, bounded-enum Prometheus metrics, and automated RLS partition-pruning regression probes.

---

## 2. Mandatory Turn-0 Reading List

Read these exact files in order BEFORE writing any code, migrations, or deployment manifests:

1. `AGENTS.md` (Root guardrails, crate firewalls, verification gates)
2. `specs/13-STREAMING-ATTACHMENTS-OFFLINE-SYNC-AND-MIGRATION.md` (Primary normative contract for Parts 1–3)
3. `specs/14-SELF-HOSTED-OPERATIONS-AND-OBSERVABILITY.md` (Primary normative contract for Parts 4–5)
4. `adrs/ADR-0011-stream-chunked-aead-and-fido-cxf.md`
5. `adrs/ADR-0012-dual-profile-sovereign-self-hosting.md`
6. `specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md` (`RSV1` envelopes, AAD rules, `CS-01`/`CS-02` X-Wing, `MUK` Recovery Kit HKDF)
7. `specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md` (`rsv-mem`, `HDSK`, `rsv-wasm` fixed-arena zero-grow constraints)
8. `schemas/postgresql-schema.sql` (Exact DDL style, roles `rsv_app`/`rsv_auditor_ro`/`rsv_migrator`, HASH-64 loops, InitPlan RLS policy)
9. `specs/08-API-AND-WIRE-PROTOCOLS.md` (6 mandatory headers, canonical request signing, `/api/v1/sync/stream`, error codes)
10. `specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md` (`INV-001`..`INV-024` baseline)

---

## 3. Strictly Forbidden Actions (STOP-THE-LINE RULES)

Violating ANY rule below fails the PR immediately:

1. **NEVER Buffer Full Attachments in Memory**: Neither `rsv-server`, `rsv-daemon`, nor `rsv-wasm` may read an entire 50–500 MiB attachment into a `Vec<u8>`. `rsv-server` MUST stay strictly `< 256 KiB` RAM per active stream; `rsv-wasm` MUST NEVER execute `memory.grow()` (`INV-024`, `INV-030`).
2. **NEVER Alter STREAM Nonce or Omit Per-Chunk AAD**: Every chunk MUST use `nonce_prefix (7B) || BE_u32(chunk_counter) || final_flag (0x00 | 0x01)` and bind canonical RFC 8949 CBOR AAD `(domain="rsv:attach:v1", tenant_id, item_id, attachment_id, chunk_counter, final_flag, cipher_suite_id)`. Truncated streams lacking `final_flag = 0x01` or containing trailing bytes MUST fail closed (`INV-030`).
3. **NEVER Implement Silent Last-Write-Wins Conflict Overwrite**: When `PUT /api/v1/items/{item_id}` returns `409 VERSION_CONFLICT`, clients MUST NEVER discard either Local or Remote edits. Conflicting or sensitive-field edits MUST surface a lossless `ConflictPair` and link `merge_parent_digests` on resolution (`INV-031`).
4. **NEVER Store Plaintext Metadata in Local Cache**: Local cache database files on disk MUST contain zero unencrypted item titles, URLs, usernames, collection names, or search indexes (`INV-031`).
5. **NEVER Upload Third-Party Exports or Recovery Kit Secrets to `rsv-server`**: Bitwarden/1PUX/KDBX4/CSV/CXF parsing and Emergency Recovery Kit generation MUST run 100% locally client-side (`INV-001`).
6. **NEVER Bypass `TenantScopedTx` or `FORCE RLS` on `vault.vault_attachments`**: Every query MUST bind `app.current_tenant_id` transaction-locally AND include explicit `WHERE tenant_id = $1` achieving `Subplans Removed: 63` (`INV-006`, `INV-007`).
7. **NEVER Introduce `unsafe` Outside `rsv-mem`/`rsv-enclave` or Break `no_std`/WASM**: All new modules in `rsv-types` and `rsv-crypto` MUST declare `#![forbid(unsafe_code)]` and compile cleanly on `wasm32-unknown-unknown`.
8. **NEVER Emit Secrets or High-Cardinality Labels to Logs/Metrics**: NEVER attach `tenant_id`, `user_id`, `device_id`, `item_id`, `attachment_id`, or `email` to Prometheus metrics; NEVER log `Authorization`, `X-RSV-Audit-Envelope`, keys, or plaintext item fields (`INV-032`).
9. **NEVER Add Outbound Telemetry, License Checks, or External CDN Assets**: Profile 1 (`sovereign`) and embedded Web SPA MUST pass 100% air-gap `unshare -n` tests (`INV-032`).
10. **NEVER Include AI Attribution in Git Commits**: Zero AI tool/model references or `Co-Authored-By` trailers.

---

## 4. Phased Implementation Checklist

### Workstream A — STREAM Chunked AEAD & `vault.vault_attachments` (`INV-030`)
- [ ] **`rsv-types/src/attachments.rs`**: Define `AttachmentId`, `StreamChunkConfig` (default `65_536`, checked bounds `16_384..=1_048_576`), `AttachmentChunkAad` (deterministic RFC 8949 CBOR encoder with integer keys `1..=7`), `AttachmentManifestEntry`, `AttachmentStatus`, and `AttachmentInitRequest`/`CommitRequest` DTOs.
- [ ] **`rsv-crypto/src/stream.rs`** (`no_std + alloc`, `#![forbid(unsafe_code)]`):
  - Implement `StreamEncryptor` and `StreamDecryptor` over `aes-gcm` `0.11` (`AES-256-GCM`).
  - Enforce 96-bit nonce `nonce_prefix (7B) || BE_u32(counter) || final_flag (0x00 | 0x01)` with strict `u32::MAX` overflow abort.
  - Integrate incremental `blake3::Hasher` computing domain-separated `blake3_ciphertext_root`.
  - Enforce `ZeroizeOnDrop` on `AttachmentEncryptionKey` (`AEK`) and internal chunk buffers.
  - Handle 0-byte attachments and exact `65,536`-byte multiples cleanly; reject premature EOF, trailing bytes after `0x01`, reordered/duplicated chunks, and cross-attachment splicing.
- [ ] **`rsv-wasm/src/stream.rs`**: Expose `StreamEncryptHandle(u32)` / `StreamDecryptHandle(u32)` reusing pre-allocated fixed 64 KiB + 16 B arena buffers (`0` `memory.grow()` calls).
- [ ] **PostgreSQL Migration (`migrations/0002_vault_attachments.sql`)**: Implement exact normative `vault.vault_attachments` DDL from `SPEC-13 §2.3` (64 HASH partitions, `FORCE RLS`, InitPlan policy, escrow tier `CHECK` constraint, `rsv_app` & `rsv_auditor_ro` grants).
- [ ] **`rsv-server/src/attachments/`**: Implement `/init`, `/stream` (bounded 64 KiB `BodyDataStream` -> atomic tmpfile + incremental `BLAKE3` + `rename`/`fsync`), `/commit`, `/download`, `/delete`, and 24h `pending_upload` orphan GC task.

### Workstream B — Offline-First Encrypted Cache & Deterministic 3-Way Sync (`INV-031`)
- [ ] **`rsv-daemon/src/cache/`**:
  - Implement page-encrypted `redb` (or audited encrypted pager) using 4 KiB `AES-256-GCM` pages with per-page AAD `(tenant_id, device_id, cache_epoch, page_number)`.
  - Seal 256-bit `CacheKey` under `rsv-enclave` `HDSK` (with explicit Tier-2 `HKDF(MUK)` fallback) and hold active `CacheKey` + in-memory search index strictly inside `rsv-mem::LockedSecretBox` / `Zeroizing`, wiping within `<= 50 ms` on lock/sleep.
  - Mark cache directories non-indexed on macOS/Windows.
- [ ] **`rsv-server/src/sync/delta.rs`**: Implement `GET /api/v1/sync/delta?cursor=<opaque>&limit=200` with monotonic opaque CBOR cursors and `410 Gone (cursor_expired)` handling.
- [ ] **`rsv-daemon/src/sync/`**:
  - Implement encrypted `pending_mutations` outbox preserving `base_version`, `base_revision_digest`, sealed `Base` snapshot, sealed `Local` draft, and `Idempotency-Key`.
  - On reconnect, refresh stale epochs (`409 STALE_KEY_EPOCH`), immediately purge revoked collections (`CONFLICT_ACCESS_REVOKED`), and freshly sign `X-RSV-Request-Signature` (`HDIK`) + `X-RSV-Audit-Envelope` (`UIK`) on replay.
- [ ] **`rsv-types/src/merge.rs` & `rsv-desktop` / Web SPA UI**:
  - Implement deterministic field-level 3-way diff `(Base, Local, Remote)` escalating all conflicting or coupled high-risk secret edits (`password`, `totp_seed`, `passkey_private_key`, `ssh_private_key`, `api_secret`) to `HumanMergeRequired`.
  - Persist `ConflictPair` losslessly in local encrypted cache, surface side-by-side GPUI/Web merge inspector, and record `merge_parent_digests: [remote_digest, local_digest]` in resolved revisions.

### Workstream C — FIDO CXF v1.0 / CXP, Offline Importers & Emergency Recovery Kit
- [ ] **`rsv-crypto/src/recovery_kit.rs`**: Implement 256-bit CSPRNG `RK`, `K_rk` HKDF derivation (`"rsv:muk:recovery-kit:v1"`), deterministic **SLIP-0039** 33-word RS1024 mnemonic codec, **Bech32m (`rsvrk1...`)** codec, and ISO/IEC 18004 Level-H QR URI generator (`rsv-rk://v1?...`).
- [ ] **`rsv-desktop` / `rsv-cli` Recovery Kit Renderer**: Pure-Rust in-memory PDF & self-contained HTML renderer (`Zeroizing<Vec<u8>>`, zero temp files, zero remote assets).
- [ ] **`rsv-cli/src/migrate/` & `rsv-daemon/src/migrate/`** (shared pure-Rust `#![forbid(unsafe_code)]` library modules):
  - **FIDO Alliance CXF v1.0 / CXP**: Encrypted import/export supporting Passkeys (PKCS#8 validation + `signCount` warning), Logins, TOTP, SSH Keys, Cards, Notes, and STREAM attachments; enforce `allow_unencrypted_export == false` enterprise lockdown + audit logging.
  - **Bitwarden Importer**: Unencrypted JSON + Password-Protected Encrypted Export (`encType: 2` HMAC-verified AES-256-CBC, PBKDF2-SHA256 & Argon2id).
  - **1Password `.1pux` Importer**: Hardened ZIP parser (`<= 100:1` compression ratio limit, path-traversal guard) streaming `files/*` directly into STREAM attachments.
  - **KeePassXC `.kdbx` v4 Importer**: Argon2d/Argon2id/AES-KDF, optional keyfile, header & block HMAC-SHA256 verification, AES-256-CBC/ChaCha20/Twofish, ChaCha20/Salsa20 inner stream protection, XXE-disabled XML parser, `<Binaries>` -> STREAM.
  - **Hardened CSV Importer**: Line-by-line `Zeroizing<String>` streaming, formula-injection neutralization on display, mandatory post-import shred warning prompt.

### Workstream D — Dual-Profile `rsv-server` (Sovereign & Enterprise HA) & Packaging (`INV-032`)
- [ ] **`rsv-server/src/traits/`**: Define and wire `ObjectStoreBackend` (`LocalFsStore`, `S3CompatibleStore`), `KmsTbkProvider` (`Tpm2SealedKms`, `LocalKeyfileKms` with `0400` + non-`PGDATA` check, `AwsKms`, `GcpKms`, `VaultTransitKms`), `SyncEventBus` (in-process + PG `LISTEN/NOTIFY` vs Redis/Valkey/NATS), and `TilePublisher` (local disk vs S3 WORM + CDN + External Witnesses).
- [ ] **Embedded Web SPA Asset Server**: Embed compiled Web SPA + `rsv-wasm` inside `rsv-server` with strict `'self'` CSP (`SPEC-14 §2.1`) and zero external URLs.
- [ ] **Hardened Deployment Artifacts**:
  - Multi-stage static `musl` Dockerfile producing `gcr.io/distroless/static-debian12:nonroot` (`UID 65532`).
  - `deploy/sovereign/docker-compose.yml` matching `SPEC-14 §2.1` (`read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, `mem_limit: 128m`).
  - `deploy/sovereign/rsv-server.service` hardened `systemd` unit (`DynamicUser=yes`, `ProtectSystem=strict`, `MemoryDenyWriteExecute=true`, `LoadCredentialEncrypted`, `MemoryMax=128M`).
  - Enterprise HA Helm/K8s reference manifests + Global Tenant Cell Router contract.

### Workstream E — PITR Verification, Single-Tenant Export, GDPR Crypto-Shredding & Zero-Secret Observability (`INV-032`)
- [ ] **`rsv-types/src/redacted.rs`**: Implement `Redacted<T>` (`Debug`/`Display` -> `"[REDACTED]"`, non-serializable by default) and finite `enum` Prometheus label types (`RouteLabel`, `StatusClass`, `ErrorCodeLabel`, `CipherSuiteLabel`, `PartitionLabel`).
- [ ] **`rsv-server/src/telemetry.rs`**: Implement Tower/Axum sensitive-header scrubber, structured JSON `tracing` logger, Prometheus `/metrics` exporter implementing all 10 Golden Signal metrics (`SPEC-14 §4.2`), optional OTLP (`RSV_OTLP_ENABLED=false` default in Sovereign Mode), and periodic `EXPLAIN (FORMAT JSON)` RLS partition-pruning regression probe.
- [ ] **`rsv-compliance-cli/src/verify_restore.rs`**: Compare restored `vault.audit_checkpoints` against Witness / pinned checkpoints; fail loudly with `RECOVERY_DISCONTINUITY_DETECTED` if `restored_tree_size < witnessed_tree_size`.
- [ ] **`rsv-cli/src/tenant_export.rs`**: Implement repeatable-read `TenantScopedTx` single-tenant portable `.tar.zst` archive export (all 13 tables + STREAM objects + C2SP tiles + signed `EXPORT_MANIFEST.cbor`) and verified re-import.
- [ ] **`rsv-server/src/shred.rs` & `rsv-cli`**: Implement two-phase GDPR Article 17 crypto-shredding (`active -> suspended -> crypto_shredding -> erased`), KMS `TBK` destruction receipt capture, targeted single-partition `DELETE` + `VACUUM`, object deletion, and signed Cryptographic Erasure Attestation Certificate generation.

---

## 5. Mandatory Verification Gates (All Must Pass with Exit Code `0`)

Run EVERY gate below before marking any PR ready for review:

```bash
# 1. Workspace format, strict clippy, and unsafe firewall
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# 2. Core no_std & WASM compilation firewall
cargo check -p rsv-types -p rsv-crypto -p rsv-vss -p rsv-graph -p rsv-audit --target wasm32-unknown-unknown

# 3. Deterministic KATs, STREAM tamper matrix, 3-way merge proptests, importers & Recovery Kit KATs
cargo test --workspace

# 4. Dependency security & license compliance (Dual MIT / Apache-2.0)
cargo audit && cargo deny check

# 5. Domain-Specific Security & Operational Harnesses
# 5a. STREAM constant-memory (<256 KiB server delta on 256 MiB stream) & WASM zero-grow check
cargo test -p rsv-crypto --test stream_kat_and_tamper
cargo test -p rsv-server --test attachment_stream_rss_budget

# 5b. PostgreSQL vault.vault_attachments RLS chaos (0 leaks) + EXPLAIN Subplans Removed: 63
cargo test -p rsv-server --test attachments_rls_and_partition_pruning

# 5c. Offline cache forensic disk canary scan (0 plaintext hits) + 3-way conflict proptest
cargo test -p rsv-daemon --test offline_cache_forensics_and_conflict_merge

# 5d. Sovereign Air-Gap Boot (unshare -n, 0 egress packets, <45 MiB idle / <128 MiB active RSS)
cargo test -p rsv-server --test sovereign_airgap_and_rss_ceiling

# 5e. Zero-Secret Telemetry Canary Scan (0 leaked secret bytes, 0 forbidden Prometheus labels)
cargo test -p rsv-server --test zero_secret_telemetry_and_cardinality

# 5f. PITR Merkle Rollback Detection, Single-Tenant Export Round-Trip & GDPR Crypto-Shredding
cargo test -p rsv-compliance-cli --test pitr_rollback_and_gdpr_shredding
```

---

## 6. PR Handoff & Acceptance Criteria

Your PR description MUST explicitly include:
1. Confirmation that all 5 workstream checklists and all 6 verification gate groups exited `0`.
2. Measured Sovereign Mode static `musl` binary RSS (idle `< 45 MiB`, active 100-client + 10-stream load `< 128 MiB`) and per-stream server RAM delta (`< 256 KiB`).
3. Captured `EXPLAIN (ANALYZE, FORMAT JSON)` proof showing `Subplans Removed: 63` on `vault.vault_attachments` queries and `0` rows returned when `app.current_tenant_id` is unset.
4. Proof that `rsv-wasm` emits zero `memory.grow` instructions during STREAM attachment tests (`wasm-tools dump` check).
5. Zero leftover temporary files, zero TODOs, and zero AI attribution anywhere in diffs or commit history.
