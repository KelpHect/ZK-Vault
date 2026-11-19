# ADR-0012: Dual-Profile Sovereign Self-Hosting and Enterprise HA Cells from One Binary (`rsv-server`)

| Field | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0012` |
| **Project** | RusticStack Core (`ZK-Vault` — `https://github.com/KelpHect/ZK-Vault`) |
| **Status** | Accepted |
| **Date** | `2026-11-19` |
| **Target Toolchain** | Rust 2024 Edition, MSRV `1.94.0` |
| **Related Specs** | `specs/14-SELF-HOSTED-OPERATIONS-AND-OBSERVABILITY.md`, `specs/05-MULTI-TENANT-DATABASE.md`, `specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md`, `specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md` |

---

## 1. Context and Problem Statement

In the password and secrets management industry, deployment architecture has split into two incompatible extremes:

1. **SaaS-Only or Heavyweight Microservice Fleets**: Commercial platforms either prohibit self-hosting entirely (1Password) or require multi-container enterprise stacks consuming gigabytes of RAM, complex message brokers, external identity proxies, and phone-home licensing checks—rendering them impractical for individual engineers, sovereign air-gapped networks, and lean security teams.
2. **Divergent Lightweight Community Forks**: Lightweight self-hosted implementations (such as Vaultwarden) gain huge adoption via tiny `< 50 MiB` RAM footprints and single-container simplicity, yet achieve that simplicity by re-implementing an external protocol, defaulting to SQLite without multi-tenant Row-Level Security, and omitting enterprise-grade verifiable audit ledgers, external transparency witnesses, HSM KMS integration, and multi-cell horizontal scaling.

RusticStack Core (`ZK-Vault`) targets **both** sovereign self-hosters (including air-gapped defense, homelab, and SMB environments) **and** `10,000–100,000+` seat multi-tenant enterprise SaaS deployments. Maintaining two separate server codebases or two diverging database engines (e.g., SQLite vs. PostgreSQL) would inevitably introduce schema drift, security regressions, and broken upgrade paths.

How should RusticStack Core architect `rsv-server` so an individual or SMB can deploy it in two minutes with `< 128 MiB` RAM and zero phone-home, while large enterprises run the exact same audited binary in horizontally sharded HA cells with type-enforced zero-secret observability?

---

## 2. Decision Drivers

- **Single Audited Security Core (Zero Feature-Gating of Security)**: Post-quantum `CS-02` (X-Wing), Feldman VSS quorum escrow, `FORCE ROW LEVEL SECURITY`, 64-way `HASH (tenant_id)` partitioning, STREAM attachments, and RFC 9162 / C2SP Merkle transparency logs MUST operate identically in both profiles.
- **Vaultwarden-Class Sovereign Simplicity**: Profile 1 MUST deploy as **one statically linked binary + one PostgreSQL 17/18 instance** (no Redis, no Kafka, no cloud KMS required), idling at `< 45 MiB` RSS and operating active loads in `< 128 MiB` RAM.
- **Strict Zero-Phone-Home & Air-Gap Compliance (`INV-032`)**: Zero telemetry pings, zero license callbacks, zero external CDN/font/script dependencies in the embedded Web SPA.
- **Seamless Zero-Migration Path to Enterprise HA & Cell Sharding**: Growing from 25 seats on a single VM to 50,000+ seats across Patroni HA + PgBouncer + S3/CDN + External Witnesses + Cloud/HSM KMS MUST require **zero schema migrations or data conversions**.
- **Type-Enforced Zero-Secret Observability**: Compile-time redaction (`Redacted<T>`, `secrecy::SecretBox`) and bounded-enum Prometheus labels MUST guarantee that logs, traces, and metrics never leak secrets, PII, or unbounded `tenant_id` cardinality.

---

## 3. Considered Options

1. **Option 1 (Chosen): Single Statically-Linked `rsv-server` Binary with Trait-Isolated Dual Deployment Profiles (Profile 1: Self-Hosted Sovereign + Profile 2: Enterprise HA Cells) Over Mandatory PostgreSQL 17/18**
2. **Option 2: SaaS-Only Proprietary Backend (No Official Self-Hosting)**
3. **Option 3: Separate Lightweight SQLite "Community Server" vs. Distributed Enterprise Microservices**
4. **Option 4: Kubernetes-Only Microservice Architecture (Separate Auth, Vault, Graph, Audit, Attachment Services)**

---

## 4. Decision Outcome

**Chosen Option: Option 1 — One statically linked `rsv-server` binary implementing both Profile 1 (Self-Hosted Sovereign Mode) and Profile 2 (Enterprise HA Cell Mode) behind clean Rust infrastructure traits over mandatory PostgreSQL 17/18.**

### 4.1 Normative Architectural Rules (`SPEC-14`)

1. **Infrastructure Trait Isolation Inside One Binary**:
   - `rsv-server` isolates deployment-specific infrastructure behind four internal traits selected strictly via configuration (`RSV_PROFILE=sovereign` vs `RSV_PROFILE=enterprise_ha`):
     - `ObjectStoreBackend`: `LocalFsStore` (atomic temp+rename + incremental BLAKE3) / `S3CompatibleStore` (AWS S3 / MinIO / GCS S3-compat with pre-signed URLs and WORM support).
     - `KmsTbkProvider`: `Tpm2SealedKms` / `LocalKeyfileKms` (loaded via `0400` file or systemd `LoadCredentialEncrypted` into `rsv-mem::LockedSecretBox`) vs `AwsKms` / `GcpKms` / `VaultTransitKms` / `Pkcs11Hsm`.
     - `SyncEventBus`: In-process `tokio::sync::broadcast` + PostgreSQL `LISTEN/NOTIFY` vs Redis/Valkey/NATS opaque invalidation fanout.
     - `TilePublisher`: Local disk/MinIO immutable C2SP tile writer vs S3 Object Lock (WORM) + CDN + External Witness cosigning pipeline.
2. **PostgreSQL 17/18 Mandatory in Both Profiles (No SQLite Dialect)**:
   - Even in Profile 1 (Self-Hosted Sovereign Mode), PostgreSQL 17/18 is REQUIRED so that `FORCE ROW LEVEL SECURITY` (`INV-006`), 64-way `HASH (tenant_id)` partitioning (`INV-007`), append-only audit triggers, recursive CTE DAG cycle guards, `pgBackRest` PITR, and single-tenant portable export remain **100% identical** between a Raspberry Pi / single VPS and a 100,000-seat Enterprise HA Cell.
3. **Hardened Sovereign Packaging & Zero-Phone-Home (`INV-032`)**:
   - Official container images use distroless/scratch non-root (`UID 65532`), `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`. Official Linux packages ship hardened `systemd` units (`DynamicUser=yes`, `ProtectSystem=strict`, `MemoryDenyWriteExecute=true`, `MemoryMax=128M`).
   - Web SPA + `rsv-wasm` assets are embedded directly inside `rsv-server` with strict `'self'` CSP and zero external network requests.
4. **Cell-Based Sharding & Provable Data Lifecycle**:
   - Deployments exceeding 50k–100k seats or requiring EU/US/Swiss data residency scale horizontally via autonomous **Cells** fronted by a signed Global Tenant Cell Router (zero cross-cell secret replication).
   - Backups pair `pgBackRest` PITR with mandatory `rsv-compliance-cli verify-restore` Merkle checkpoint rollback detection, single-tenant portable archive exports, and two-phase provable GDPR crypto-shredding (`TBK` + `ORPK` destruction -> partitioned `DELETE` + `VACUUM`).
5. **Compile-Time Zero-Secret Observability**:
   - `Redacted<T>` and `secrecy::SecretBox` prevent accidental secret formatting; Prometheus metrics accept strictly finite Rust `enum` labels (banning `tenant_id`/`user_id`/`email`/`item_id`); OTLP defaults to `false` in Sovereign Mode.

---

## 5. Consequences

### 5.1 Positive Consequences

- **Zero Security Bifurcation**: A self-hosted 5-person engineering team receives the exact same post-quantum cryptography, Merkle audit verification, RLS defense-in-depth, and STREAM attachment integrity audited for Fortune 500 enterprises.
- **Minimal Operational Surface**: Deploying Profile 1 requires only two containers (`rsv-server` + `postgres:17-alpine`) or one `systemd` service + local PostgreSQL, fitting comfortably inside a 512 MiB–1 GiB VPS (`< 128 MiB` for `rsv-server`).
- **True Sovereignty & Portability**: Air-gapped networks run with zero external dependencies, and single-tenant signed `.tar.zst` exports migrate seamlessly between Self-Hosted Sovereign and Enterprise HA Cells with zero vendor lock-in.
- **High-Velocity Maintenance**: One Rust binary, one PostgreSQL schema, one CI security harness—zero drift between "community" and "enterprise" servers.

### 5.2 Negative Consequences & Mitigations

| Risk / Trade-off | Impact | Normative Mitigation |
| :--- | :--- | :--- |
| **PostgreSQL Required Even for Single-User Homelabs** | Slightly higher floor than a zero-process SQLite file (`postgres:17-alpine` adds `~30–60 MiB` RAM). | Provided turn-key hardened Docker Compose & `systemd` manifests configure PostgreSQL in < 60 seconds; the massive security payoff (`FORCE RLS`, append-only triggers, `pgBackRest` PITR, zero dialect bugs) decisively outweighs 40 MiB of RAM. |
| **Modular Monolith vs. Microservices Scaling** | All HTTP routes, sync fanout, and tile publication live inside one binary. | Stateless horizontal pod scaling behind Ingress + PgBouncer + S3 pre-signed attachment offloading removes single-process bottlenecks cleanly up to 100k seats per Cell, with Cell Sharding scaling linearly beyond that without microservice RPC latency or serialization overhead. |
| **Local Keyfile `TBK` Custody in Non-TPM Containers** | Operators without TPM 2.0 or Cloud KMS must protect the `rsv_tbk_kek` secret file separately from database backups. | Enforce startup permission checks (`0400`, outside `PGDATA`), support `systemd-creds` (`LoadCredentialEncrypted`), document offsite separate backup of `TBK_KEK`, and remember that `TBK` ONLY blinds audit index tags—compromising `TBK` NEVER decrypts a single vault item (`INV-001`). |

---

## 6. Pros and Cons of Considered Alternatives

### 6.1 Option 2: SaaS-Only Proprietary Backend
- **Pros**: Centralized operator control; no diverse customer deployment environments to support.
- **Cons**: Eliminates sovereign self-hosting, air-gapped government/defense deployments, and independent security inspection; creates vendor lock-in. **Rejected.**

### 6.2 Option 3: Separate SQLite Community Fork vs. Enterprise Server
- **Pros**: Sub-20 MiB single-file SQLite deployment for tiny homelabs.
- **Cons**: Doubles SQL/ORM surface area; SQLite lacks PostgreSQL `FORCE ROW LEVEL SECURITY`, declarative 64-way `HASH` partitioning, and PgBouncer transaction-pooled concurrency; forces painful data-conversion migrations when teams grow; historically causes divergent security fixes between editions. **Rejected.**

### 6.3 Option 4: Kubernetes-Only Microservice Fleet
- **Pros**: Independent per-service deployment cadence for very large engineering organizations.
- **Cons**: Imposes multi-gigabyte memory overhead, complex inter-service mTLS/mesh failure modes, distributed transaction complexity around atomic mutation + C2SP audit leaf commits, and makes clean single-host self-hosting nearly impossible. **Rejected.**

---

## 7. Verification Criteria

This decision is considered properly implemented when:
1. A single compiled `rsv-server` static `musl` binary boots cleanly in both `RSV_PROFILE=sovereign` (using `LocalFsStore` + `LocalKeyfileKms` + single PG 17/18) and `RSV_PROFILE=enterprise_ha` (using S3 + PgBouncer transaction mode + KMS + external witness).
2. Sovereign Mode RSS benchmarks measure `< 45 MiB` idle and `< 128 MiB` under 100 concurrent clients + 10 concurrent STREAM uploads.
3. Air-gap CI tests (`unshare -n`) confirm `0` outbound network attempts and `0` external Web SPA resource fetches (`INV-032`).
4. Canary telemetry tests confirm `0` leaked secret bytes in `TRACE` logs/OTLP/panics and `0` unbounded `tenant_id`/`email`/`item_id` Prometheus labels.
5. PITR rollback drills confirm `rsv-compliance-cli verify-restore` deterministically detects and blocks silent audit history truncation, and GDPR crypto-shredding drills prove immediate backup irrecoverability.
