# ADR-0002: Shared Schema with HASH Partitioning and Defense-in-Depth RLS over Schema-per-Tenant

| Field | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0002` |
| **Status** | Accepted |
| **Date** | `2026-11-19` |
| **Project** | RusticStack Core (`ZK-Vault`, `https://github.com/KelpHect/ZK-Vault`) |
| **License** | Dual MIT / Apache-2.0 |
| **Deciders** | Architecture & Database Engineering |
| **Related Specs** | [`specs/05-MULTI-TENANT-DATABASE.md`](../specs/05-MULTI-TENANT-DATABASE.md), [`schemas/postgresql-schema.sql`](../schemas/postgresql-schema.sql) |

---

## 1. Context and Problem Statement

RusticStack Core (**ZK-Vault**) is a multi-tenant, zero-knowledge enterprise secrets manager backed by PostgreSQL 17/18, PgBouncer (transaction pooling mode), and a Rust 2024 (`axum` 0.8 + `sqlx` 0.9) API tier. A single production cluster must reliably serve **1,000 to 10,000+ tenants** and **10,000 to 500,000+ seats** with strict tenant data isolation, sub-10ms P99 query latency, zero-downtime schema migrations, and GDPR Article 17 erasure support.

How should RusticStack Core isolate tenant relational data inside PostgreSQL 17/18 without sacrificing horizontal scalability, connection pool efficiency, migration velocity, or query planner performance?

---

## 2. Decision Drivers

1. **Cryptographic & Relational Defense-in-Depth**: Even though all vault payloads, metadata, and compliance audit envelopes are AES-256-GCM / HPKE ciphertexts (`CS-01` / `CS-02`), a bug in application SQL MUST NOT allow cross-tenant ciphertext metadata disclosure, graph edge leakage, or cross-tenant writes.
2. **PostgreSQL Catalog & Memory Scalability at 10,000+ Tenants**: Backend memory (`RelCache`/`CatCache`), `pg_class`/`pg_attribute` catalog size, and `pg_upgrade` duration MUST remain bounded ($O(1)$) as tenant count grows.
3. **Zero-Downtime Schema Migrations**: Rolling out a DDL migration MUST NOT require acquiring thousands of sequential `ACCESS EXCLUSIVE` locks or leave tenants running mixed schema versions.
4. **PgBouncer Transaction Pooling & Prepared Statement Compatibility**: Connections multiplexed across thousands of stateless `tokio` tasks MUST preserve prepared-statement cache locality and MUST NOT leak tenant session state across transactions.
5. **Deterministic Partition Pruning & Index Locality**: Query plans on partitioned tables MUST prune to a single partition (`Subplans Removed: 63`) and avoid `Seq Scan` regressions—specifically avoiding the common trap where naive RLS predicates break partition pruning.
6. **Path to Dedicated Enterprise Cells**: Whale tenants ($> 50{,}000$ seats or sovereign compliance regions) MUST be movable to dedicated PostgreSQL clusters with zero schema or SQL rewrites.

---

## 3. Considered Options

1. **Option A: Shared Schema (`vault`) + 64-Way `HASH(tenant_id)` Partitioning + Dual-Enforcement RLS (`TenantScopedTx` + `FORCE ROW LEVEL SECURITY` InitPlan) + Cryptographic Isolation (Chosen)**
2. **Option B: Schema-per-Tenant (`tenant_<uuid>.*`) inside a Shared PostgreSQL Cluster**
3. **Option C: Database-per-Tenant (`CREATE DATABASE tenant_<uuid>`) inside a Shared or Fleet PostgreSQL Deployment**
4. **Option D: Shared Schema with Application-Layer `WHERE tenant_id = $1` Only (No PostgreSQL RLS)**

---

## 4. Decision Outcome

**Chosen Option: Option A — Shared Schema (`vault`) + `PARTITION BY HASH (tenant_id)` (64 Partitions) + Dual-Enforcement RLS (`TenantScopedTx` + InitPlan-Cached `FORCE ROW LEVEL SECURITY`).**

All 12 canonical tables reside inside a single PostgreSQL schema `vault` with `tenant_id UUID NOT NULL` as the leading column in every primary key, unique index, secondary index, and composite foreign key. The 5 high-cardinality tables (`vault.key_graph_edges`, `vault.vault_items`, `vault.vault_item_revisions`, `vault.audit_events`, `vault.audit_merkle_tiles`) use `PARTITION BY HASH (tenant_id)` with 64 baseline partitions (`p00`..`p63`).

Every runtime database access executes through Rust's `TenantScopedTx` wrapper (`sqlx` 0.9), which:
1. Opens an explicit `BEGIN` transaction and binds `SELECT pg_catalog.set_config('app.current_tenant_id', $1::text, true)` (strictly transaction-local for PgBouncer safety).
2. Passes explicit `WHERE tenant_id = $1` in every compile-time-verified `sqlx::query!` statement, guaranteeing O(1) partition pruning (`Subplans Removed: 63`) and `(tenant_id, ...)` leading-column index scans.
3. Connects exclusively as `rsv_app` (`NOSUPERUSER NOBYPASSRLS`) against tables enforcing BOTH `ENABLE` and `FORCE ROW LEVEL SECURITY` with an InitPlan-cached LEAKPROOF predicate:
   ```sql
   USING (tenant_id = (SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
   WITH CHECK (tenant_id = (SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
   ```

---

## 5. Pros and Cons of the Options

### Option A: Shared Schema + `HASH(tenant_id)` Partitioning + Dual-Enforcement RLS (Accepted)

- **Good**, because catalog size is strictly $O(1)$: 12 parent tables + 320 leaf partitions regardless of whether the cluster hosts 50 or 50,000 tenants.
- **Good**, because Expand-and-Contract DDL migrations execute once across the `vault` schema in milliseconds under `lock_timeout = '2s'`.
- **Good**, because PgBouncer 1.21+ `transaction` pooling achieves maximum prepared-statement plan sharing (`vault.*` queries are identical across tenants) with zero `search_path` cache thrashing.
- **Good**, because combining explicit `WHERE tenant_id = $1` with InitPlan-cached `FORCE RLS` resolves the classical PostgreSQL RLS partition-pruning penalty while maintaining a fail-closed database backstop if application code omits a `WHERE` filter.
- **Good**, because the exact same schema scales vertically to 256 HASH partitions and horizontally via cell-based sharding for sovereign/whale tenants without SQL changes.
- **Bad**, because developers must strictly use `TenantScopedTx` and never call `set_config(..., false)` or autocommit queries under PgBouncer (mitigated by encapsulating `PgPool` privately inside `VaultDb`, startup `rolbypassrls = false` verification, and mandatory CI RLS negative tests).
- **Bad**, because single-tenant point-in-time recovery (PITR) requires logical extraction from a restored staging snapshot rather than a schema-level dump (mitigated by single-tenant logical export tooling and per-item immutable `vault.vault_item_revisions`).

### Option B: Schema-per-Tenant (`tenant_<uuid>.*`) (Rejected)

- **Good**, because `pg_dump --schema=tenant_x` is trivial at small scale (< 50 tenants) and naive SQL cannot accidentally join across schemas when `search_path` is strictly managed.
- **Bad (Disqualifying)**, because at 5,000 tenants (12 tables + ~35 indexes/TOAST objects per tenant $\approx 47$ `pg_class` entries and $\sim 420$ `pg_attribute` entries per schema), PostgreSQL accumulates **235,000+ `pg_class` rows and 2.1M+ `pg_attribute` rows**. Every backend's private `RelCache`/`CatCache` grows unboundedly, causing severe RSS exhaustion and multi-hour `pg_upgrade` / logical-backup pauses.
- **Bad (Disqualifying)**, because schema migrations devolve into 5,000-schema `ALTER TABLE` lock storms, exhausting `max_locks_per_transaction` and leaving the fleet in inconsistent partial-migration states for tens of minutes.
- **Bad (Disqualifying)**, because dynamic `SET search_path` destroys PgBouncer prepared-statement sharing and forces $O(\text{queries} \times \text{tenants})$ backend plan compilation.
- **Bad**, because tens of thousands of tiny relation files fragment OS page cache and starve `autovacuum_max_workers`.

### Option C: Database-per-Tenant (Rejected)

- **Good**, because tenants enjoy hard physical separation and independent backup/restore lifecycles.
- **Bad (Disqualifying)**, because PgBouncer requires a separate backend connection pool per database (`O(tenants)` idle PostgreSQL backends), making 5,000+ tenants economically and operationally unviable on shared infrastructure.
- **Bad**, because cross-fleet migrations and monitoring scale poorly at thousands of small SaaS tenants.
- **Note**: While rejected as the *baseline* architecture, RusticStack Core retains **Dedicated Enterprise Cell Sharding** (a dedicated PostgreSQL cluster running the same `vault` schema) for whale/sovereign enterprise customers who explicitly pay for dedicated hardware.

### Option D: Shared Schema Without PostgreSQL RLS (Rejected)

- **Good**, because query plans avoid RLS InitPlan overhead (measured at $< 5\ \mu\text{s}$ per statement—negligible).
- **Bad (Disqualifying)**, because a single omitted `WHERE tenant_id = $1` clause in a new API endpoint, admin report, or future refactor immediately exposes cross-tenant rows (including ciphertext metadata, blind graph topology, and blinded audit logs). Failing to use PostgreSQL's native `FORCE ROW LEVEL SECURITY` violates defense-in-depth engineering standards for a security-critical vault.

---

## 6. Quantitative Engineering Comparison (5,000-Tenant Cluster Baseline)

| Metric (5,000 Tenants, 100M Audit Rows, 10M Items) | Option A: Shared + 64 HASH + RLS | Option B: Schema-per-Tenant | Option C: DB-per-Tenant |
| :--- | :---: | :---: | :---: |
| **`pg_class` Relations** | ~1,100 (Constant $O(1)$) | ~235,000 ($O(N)$) | ~550,000 across cluster |
| **Schema Migration Duration (`ADD COLUMN`)** | **< 200 ms** (1 atomic lock) | 25–90 min (5,000 locks) | Hours (5,000 DB connections) |
| **Active PgBouncer Backend Pools** | **1 shared pool** (64 backends) | 1 pool (broken plan cache) | 5,000 pools (unviable) |
| **Prepared Statement Cache Hit Rate** | **> 99.5%** | < 15% (`search_path` churn) | N/A |
| **Cross-Tenant Bug Blast Radius** | **Blocked by `FORCE RLS` + Crypto** | Blocked by `search_path` | Blocked by DB boundary |
| **Partition Pruning (`EXPLAIN`)** | **`Subplans Removed: 63`** | N/A | N/A |

---

## 7. Consequences & Compliance Guardrails

1. **Mandatory CI Planner Gate**: Integration tests MUST execute `EXPLAIN (ANALYZE, BUFFERS)` on all hot-path queries and assert zero `Seq Scan`, `Subplans Removed: 63`, and single-evaluation `InitPlan` on RLS predicates.
2. **Mandatory CI Security Gate**: Negative tests running as `rsv_app` MUST verify fail-closed zero-row reads when `app.current_tenant_id` is unset, zero cross-tenant reads, and SQLSTATE `42501` rejections on cross-tenant inserts/updates.
3. **Zero `BYPASSRLS` Policy**: No application, auditor, or pre-auth lookup role (`rsv_app`, `rsv_auditor_ro`, `rsv_slug_resolver`, `rsv_migrator`) is permitted to hold `SUPERUSER` or `BYPASSRLS`. Pre-auth tenant slug lookup uses a narrow column-scoped role (`rsv_slug_resolver`) restricted exclusively to `SELECT (tenant_id, slug, status)` on `vault.tenants`.
4. **GDPR Erasure**: Tenant offboarding relies primarily on immediate **crypto-shredding** (`TBK_mw`, `ORPK`, `DRPK`, `CPK` destruction) followed by controlled `rsv_migrator` batched physical purging, ensuring zero disruption to neighboring tenants sharing the same HASH partition.
