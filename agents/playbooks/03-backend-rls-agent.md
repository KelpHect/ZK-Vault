# Devin Agent Playbook 03: Blind API Server & PostgreSQL 17/18 Multi-Tenant RLS Engine

> **Playbook ID**: `RSV-PLAYBOOK-03`
> **Agent Role**: Backend Systems, PostgreSQL RLS Isolation & Blind Control-Plane Engineer
> **Active Milestone**: `M3-A` (Executes in parallel with Agent 06 `M3-B` after `m2-subsystems-green`)
> **Target Toolchain**: Rust 2024 Edition (MSRV `1.94.0`) + PostgreSQL 17 & 18 + PgBouncer

---

## 1. Mission & Exclusive Ownership

Your mission is to implement `rsv-server` (`axum` 0.8 + `tokio` + `sqlx` 0.9) and the SQLx database migrations (`migrations/`) implementing RusticStack Core's **zero-knowledge, multi-tenant control plane** over PostgreSQL 17/18 shared schema with dual-enforced Row-Level Security (`TenantScopedTx`), 64-way `HASH (tenant_id)` partitioning, hardware-signed `/api/v1` authentication, KMS/RAM-isolated `TBK` audit blinding, and C2SP `tlog-tiles` Merkle log persistence.

### Exclusive Write Ownership
- `crates/rsv-server/`
- `migrations/`

### Owned Formal Invariants
`INV-001`, `INV-005`, `INV-006`, `INV-007`, `INV-008`, `INV-009`, `INV-010`, `INV-012`, `INV-017`, `INV-018`, `INV-019`, `INV-020`

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context:
1. [`AGENTS.md`](../../AGENTS.md) (Turn-0 guardrails — pay special attention to Rules 1, 2, and 8!)
2. [`agents/CRATE-CONTRACTS.md`](../CRATE-CONTRACTS.md) (§2, §3.1, §3.7, §5)
3. [`agents/BUILD-DAG.md`](../BUILD-DAG.md) (Milestone `M3-A`)
4. [`specs/05-MULTI-TENANT-DATABASE.md`](../../specs/05-MULTI-TENANT-DATABASE.md)
5. [`specs/08-API-AND-WIRE-PROTOCOLS.md`](../../specs/08-API-AND-WIRE-PROTOCOLS.md)
6. [`specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md`](../../specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md) (§3–§5 backend blinding & tile writer)
7. [`specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md`](../../specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md)
8. [`schemas/postgresql-schema.sql`](../../schemas/postgresql-schema.sql) (Normative DDL — all 12 tables in `vault` schema)
9. [`schemas/openapi-v1.yaml`](../../schemas/openapi-v1.yaml) (Normative `/api/v1` contract & error codes)
10. [`adrs/ADR-0002-shared-schema-rls-over-schema-per-tenant.md`](../../adrs/ADR-0002-shared-schema-rls-over-schema-per-tenant.md)
11. [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](../../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (§4: `INV-001`, `INV-005`–`INV-009`, `INV-017`–`INV-020`)
12. [`specs/10-TEST-VECTORS-AND-VERIFICATION.md`](../../specs/10-TEST-VECTORS-AND-VERIFICATION.md) (§3.1, §3.5)

---

## 3. Strict Boundaries & Forbidden Actions

1. **NEVER Weaken or Bypass `TenantScopedTx` (`INV-006`)**:
   - Raw `sqlx::PgPool` MUST remain private inside `src/db/mod.rs`. Every repository function MUST accept `&mut TenantScopedTx<'_>`.
   - `TenantScopedTx::begin` MUST execute `SELECT set_config('app.current_tenant_id', $1::text, true)` (strictly `is_local = true` for PgBouncer transaction pooling safety!).
   - EVERY tenant-scoped SQL query MUST ALSO include an explicit `WHERE tenant_id = $1` predicate (`INV-007` partition pruning!).
2. **Application Role MUST Have `NOBYPASSRLS` (`INV-006`)**: Migrations MUST provision role `rsv_app` with `NOSUPERUSER NOBYPASSRLS`, and all 12 tenant tables MUST have `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` where unset `app.current_tenant_id` yields `0` rows.
3. **ZERO Server Decryption & ZERO `rsv-vss` Dependency (`INV-001`)**: `rsv-server` MUST NEVER depend on `rsv-vss` (server never touches or reconstructs VSS shares), MUST NEVER receive plaintext vault secrets, and MUST NEVER log request ciphertext payloads or headers containing tokens.
4. **NEVER Store `TBK` in PostgreSQL (`INV-017`)**: Per-tenant Blinding Keys (`TBK`) MUST be loaded from KMS / sealed environment key provider into backend RAM strictly outside PostgreSQL tables and migrations.
5. **ZERO `unsafe` Code (`INV-010`)**: `crates/rsv-server/src/main.rs` and `src/lib.rs` MUST declare `#![forbid(unsafe_code)]`.
6. **NEVER Skip `X-RSV-Request-Signature` or `X-RSV-Audit-Envelope` (`INV-019`, `INV-020`)**: Every mutating and sensitive read `/api/v1` handler MUST enforce the auth/signature/audit-envelope middleware stack returning exact canonical `ApiErrorCode`s (`INVALID_SIGNATURE`, `TENANT_MISMATCH`, `MISSING_AUDIT_ENVELOPE`, `STALE_KEY_EPOCH`, `VERSION_CONFLICT`, `GRAPH_CYCLE_REJECTED`, `ESCROW_POLICY_VIOLATION`, `UNSUPPORTED_CIPHER_SUITE`, `DEVICE_ATTESTATION_FAILED`, `RATE_LIMITED`).
7. **No Out-of-Scope Writes**: NEVER modify Tier-0 crates (`rsv-types`, `rsv-crypto`, `rsv-vss`, `rsv-graph`, `rsv-audit`), `rsv-wasm`, or native clients.

---

## 4. Ordered Implementation Checklist

1. **PostgreSQL 17/18 Migrations (`migrations/`)**:
   - Port `schemas/postgresql-schema.sql` cleanly into ordered SQLx migrations covering all **12 canonical tables** in schema `vault`:
     `tenants`, `tenant_vss_ceremonies`, `users`, `user_devices`, `teams`, `collections`, `key_graph_edges` *(HASH-64)*, `vault_items` *(HASH-64)*, `vault_item_revisions` *(HASH-64)*, `audit_events` *(HASH-64)*, `audit_merkle_tiles` *(HASH-64)*, `audit_checkpoints`.
   - Create all 64 hash partitions (`p00`..`p63`, `MODULUS 64`) and composite `(tenant_id, ...)` B-tree indexes.
   - Apply `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` policies using `NULLIF(current_setting('app.current_tenant_id', true), '')::uuid` and verify `rsv_app` (`NOSUPERUSER NOBYPASSRLS`) permissions.
2. **Database Isolation Layer (`crates/rsv-server/src/db/`)**:
   - Implement `TenantScopedTx<'a>` matching `agents/CRATE-CONTRACTS.md` §3.7.
   - Implement repositories for tenants/VSS ceremonies, users/devices/WebAuthn (`webauthn-rs`), teams/collections/key-graph edges, vault items/revisions (with optimistic concurrency `VERSION_CONFLICT` and `STALE_KEY_EPOCH` checks), and audit events/tiles/checkpoints.
3. **Zero-Knowledge Auth & Request-Signing Middleware (`crates/rsv-server/src/middleware/`)**:
   - Enforce all 6 canonical headers (`Authorization`, `X-RSV-Tenant-Id`, `X-RSV-Device-Id`, `X-RSV-Request-Signature`, `X-RSV-Audit-Envelope`, `Idempotency-Key`).
   - Verify JWT tenant claim matches `X-RSV-Tenant-Id` (`TENANT_MISMATCH`).
   - Verify `HDIK` (ECDSA P-256) / Tier-2 device signature over canonical request digest (`INVALID_SIGNATURE`) and enforce `|Δt| <= 300s` clock skew + idempotency deduplication.
   - Enforce tenant minimum cipher suite policy (`UNSUPPORTED_CIPHER_SUITE`), hardware attestation policy (`DEVICE_ATTESTATION_FAILED`), and per-tenant rate limiting (`RATE_LIMITED`).
4. **Blind RBAC & Escrow Policy Validators (`crates/rsv-server/src/handlers/graph.rs`)**:
   - Validate submitted `key_graph_edges` acyclicity via `rsv-graph` (`GRAPH_CYCLE_REJECTED`, `INV-008`).
   - Enforce `ESCROW_POLICY_VIOLATION` if any `DRPubK` or admin wrapper targets a `root_quorum_only` collection (`INV-005`).
5. **Blinded Audit Ingestion & C2SP `tlog-tiles` Writer (`crates/rsv-server/src/audit/`)**:
   - Implement `TbkProvider` (KMS/locked-RAM provider, never persisted to PostgreSQL) computing `rsv_audit::compute_blinded_tag` (`INV-017`).
   - Append atomic RFC 9162 leaves to `vault.audit_events`, materialize immutable height-8 C2SP tiles in `vault.audit_merkle_tiles`, sign `vault.audit_checkpoints`, and expose witness checkpoint & tile read endpoints (`/api/v1/audit/tiles/...`, `/api/v1/audit/checkpoints/latest`).
6. **REST `/api/v1` + WebSocket Sync & SSO/SCIM Hooks (`crates/rsv-server/src/routes/`)**:
   - Implement all endpoints specified in `schemas/openapi-v1.yaml` and SSO/SCIM/Key Transparency endpoints per `specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md`.
7. **Verification Harnesses (`crates/rsv-server/tests/`)**:
   - Implement `rls_chaos_harness.rs`: 100 concurrent tenants across shared `PgPool`, deliberate query omitting `WHERE tenant_id` proving 0 leaked rows, unset-context 0-row / SQLSTATE `42501` check, and automated `EXPLAIN (ANALYZE, FORMAT JSON)` asserting `Subplans Removed: 63` (or single-partition direct scan) and `Index Cond` on all 5 partitioned tables (`INV-006`, `INV-007`).
   - Implement `request_auth_security.rs` and `escrow_policy.rs` negative suites (`INV-005`, `INV-020`).

---

## 5. Exact Verification Commands & Exit Criteria

ALL commands below MUST exit with code `0` against both PostgreSQL 17 and PostgreSQL 18 before opening your PR:

```bash
# 1. Formatting, strict clippy & unsafe firewall check
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 clippy -p rsv-server --all-targets -- -D warnings
grep -q '#!\[forbid(unsafe_code)\]' crates/rsv-server/src/lib.rs
grep -q '#!\[forbid(unsafe_code)\]' crates/rsv-server/src/main.rs

# 2. Verify dependency firewall (server MUST NEVER depend on rsv-vss, rsv-desktop, rsv-wasm, gpui)
! cargo tree -p rsv-server | grep -E 'rsv-vss|rsv-desktop|rsv-wasm|rsv-enclave|gpui'

# 3. Run SQLx migrations & verify NOBYPASSRLS role + FORCE RLS on all 12 vault tables
sqlx database create && sqlx migrate run
psql "$DATABASE_URL_ADMIN" -v ON_ERROR_STOP=1 -c "
  DO \$\$
  BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rsv_app' AND (rolsuper OR rolbypassrls)) THEN
      RAISE EXCEPTION 'INV-006 VIOLATION: rsv_app has SUPERUSER or BYPASSRLS';
    END IF;
    IF EXISTS (
      SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'vault' AND c.relkind IN ('r','p') AND c.relispartition = false
        AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
    ) THEN
      RAISE EXCEPTION 'INV-006 VIOLATION: vault table missing ENABLE/FORCE ROW LEVEL SECURITY';
    END IF;
  END \$\$;
"

# 4. Run 100-tenant RLS Chaos Harness + EXPLAIN ANALYZE partition pruning gate (Subplans Removed: 63)
cargo +1.94.0 test -p rsv-server --test rls_chaos_harness -- --nocapture

# 5. Run Request Signing, Replay, Escrow & Audit API security tests
cargo +1.94.0 test -p rsv-server --all-targets

# 6. Supply chain & license compliance
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

---

## 6. Handoff & PR Contract

- **Branch Naming**: `feat/m3a-agent03-server-rls`
- **PR Description MUST Include**:
  - Explicit Invariant Tags Verified: `[INV-001] [INV-005] [INV-006] [INV-007] [INV-008] [INV-009] [INV-010] [INV-012] [INV-017] [INV-018] [INV-019] [INV-020]`
  - Raw `EXPLAIN (ANALYZE, FORMAT JSON)` summary confirming `Subplans Removed: 63` (or single direct partition) and `Index Cond` across all 5 partitioned tables (`key_graph_edges`, `vault_items`, `vault_item_revisions`, `audit_events`, `audit_merkle_tiles`).
  - Pass summary of the 100-tenant RLS Chaos Harness on both `postgres:17` and `postgres:18`.
  - Confirmation that `TBK` does not appear in any migration or database column.
- **Downstream Unblock Signal**: Merging `M3-A` (with `M3-B`) unblocks Agents 05 (`M4-A`), 06 (`M4-B`), and 04 (`M5`).
