# ADR-0005: RFC 9162 Merkle Tree with C2SP `tlog-tiles` and External Witness Cosigning for the Zero-Knowledge Audit Ledger

| Field | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0005` |
| **Status** | Accepted |
| **Date** | `2026-11-19` |
| **Project** | RusticStack Core (`ZK-Vault`, `https://github.com/KelpHect/ZK-Vault`) |
| **License** | Dual MIT / Apache-2.0 |
| **Deciders** | Cryptography, Security & Backend Architecture |
| **Related Specs** | [`specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md`](../specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md), [`schemas/postgresql-schema.sql`](../schemas/postgresql-schema.sql) |

---

## 1. Context and Problem Statement

Enterprise secret managers must satisfy strict forensic and regulatory compliance standards (SOC 2 Type II, ISO 27001, HIPAA, PCI-DSS, FedRAMP) while operating under a **zero-knowledge threat model** where the hosting infrastructure, cloud provider, and database administrators are untrusted.

An audit ledger for RusticStack Core (**ZK-Vault**) must simultaneously guarantee:
1. **Logarithmic Tamper Evidence**: Any auditor or end user must be able to prove inclusion of event `log_index = i` and append-only consistency between checkpoints `size_1 -> size_2` without downloading the entire log ($O(\log N)$ bandwidth and compute).
2. **Defense Against Split-View (Equivocation) Attacks**: Even if an attacker compromises BOTH `rsv-server` AND its PostgreSQL primary AND the server's checkpoint signing key, the attacker MUST NOT be able to silently fork or rewrite history for different viewers.
3. **Cacheable, CDN/Object-Store-Friendly Serving**: Compliance auditors, external witnesses, and customers must be able to fetch immutable cryptographic proof artifacts without creating hot dynamic-query load on PostgreSQL.
4. **PostgreSQL Append-Only Compatibility**: The proof storage schema must require zero in-place `UPDATE`s so PostgreSQL `BEFORE UPDATE OR DELETE` immutability triggers remain strictly enforced on all audit tables.
5. **Zero External Vendor Lock-In**: Self-hosted air-gapped enterprises and multi-cloud SaaS deployments must run identically using open, standardized cryptographic formats.

What cryptographic ledger structure and proof distribution protocol should back `vault.audit_events`, `vault.audit_merkle_tiles`, and `vault.audit_checkpoints`?

---

## 2. Decision Drivers

- **Cryptographic Standardization**: Prefer peer-reviewed IETF / C2SP specifications (`RFC 9162`, `C2SP tlog-tiles`, `C2SP tlog-checkpoint`, `C2SP tlog-witness`) over bespoke ledger formats.
- **Proof Cost & Read Amplification**: Inclusion and consistency verification at $N = 10^8$ entries per tenant must require $\le 4$ static HTTP/DB fetches ($< 32\text{ KiB}$).
- **Storage Overhead in PostgreSQL**: Avoid storing 2× rows per audit event (every internal Merkle node as its own tuple) in a multi-tenant database.
- **Independent Witness Ecosystem**: Enable enterprises to run lightweight, stateless-friendly open-source C2SP witnesses (`tlog-witness`) on customer-owned infrastructure or third-party networks.
- **Deterministic Offline Verification**: `rsv-compliance-cli` must verify full ledger integrity strictly offline from exported tiles and checkpoints before invoking HSM `CPK` decryption.

---

## 3. Considered Options

1. **Option A: RFC 9162 Domain-Separated Merkle Tree + C2SP `tlog-tiles` (`H = 8`, 256 Hashes/Tile) + C2SP Signed Checkpoints + External Witness Cosigning (Chosen)**
2. **Option B: Linear Hash Chain (`H_i = SHA-256(H_{i-1} || Entry_i)`)**
3. **Option C: Untiled RFC 6962 / Node-per-Row Merkle Tree in PostgreSQL with Dynamic Proof Endpoints**
4. **Option D: Permissioned Blockchain / Public L1-L2 Anchoring or Managed Proprietary Ledger DB**

---

## 4. Decision Outcome

**Chosen Option: Option A — RFC 9162 Domain-Separated Merkle Tree + C2SP `tlog-tiles` (`H = 8`) + C2SP Signed Checkpoints + External Witness Cosigning.**

Specifically:
- Every audit entry inserted into `vault.audit_events` receives a gap-free contiguous per-tenant `log_index` (allocated under per-tenant `pg_advisory_xact_lock`, never via gap-prone PostgreSQL `SEQUENCE`s) and computes RFC 9162 `leaf_hash = SHA-256(0x00 || CanonicalAuditEntryCBOR)`. Internal nodes compute `SHA-256(0x01 || LeftHash || RightHash)`.
- Merkle hashes are packed into immutable **C2SP `tlog-tiles`** of height `H = 8` (256 hashes = 8,192 bytes for full tiles `partial_width = 0`; `W * 32` bytes for immutable partial tiles `partial_width = W ∈ 1..255`) stored strictly append-only in `vault.audit_merkle_tiles` (`PRIMARY KEY (tenant_id, tile_level, tile_index, partial_width)`). Intermediate levels $8L+1 \dots 8L+7$ are recomputed in RAM on demand, eliminating ~50% of storage overhead.
- Checkpoints follow the C2SP `signed-note` / `tlog-checkpoint` text format and are synchronously cosigned by a configured quorum $Q_w$ (default **2-of-3**) of independent external C2SP `tlog-witness` services verifying RFC 9162 `VERIFY_CONSISTENCY` before insertion into append-only `vault.audit_checkpoints`.
- Tiles are served at static C2SP paths (`/tile/{L}/{N_c2sp}[.p/{W}]`) with `Cache-Control: public, max-age=31536000, immutable`, allowing trivial mirroring to S3/R2/CDN and pure client-side proof assembly in `rsv-audit` and `rsv-compliance-cli`.

---

## 5. Pros and Cons of the Options

### Option A: RFC 9162 + C2SP `tlog-tiles` + External Witnesses (Accepted)

- **Good**, because inclusion and consistency proofs scale at $O(\log_2 N)$ mathematically and $O(\lceil \log_{256} N \rceil)$ network requests: even at $256^4 = 4.29\text{ billion}$ events in one tenant, verifying any leaf takes **at most 4 static 8 KiB tile fetches**.
- **Good**, because packing 256 hashes per tile reduces PostgreSQL row count in `vault.audit_merkle_tiles` by **~256×** compared to node-per-row storage, dramatically reducing B-tree index bloat, tuple header overhead (23 bytes/row saved × 256), and vacuum cost.
- **Good**, because including `partial_width` in the primary key `(tenant_id, tile_level, tile_index, partial_width)` makes every tile row strictly **append-only immutable**, preserving our `BEFORE UPDATE OR DELETE` PostgreSQL immutability trigger without exception.
- **Good**, because C2SP `tlog-tiles` URLs are statically cacheable forever (`immutable`), enabling zero-load CDN/object-store distribution to auditors and witnesses.
- **Good**, because external C2SP `tlog-witness` cosigning defeats split-view attacks even under full server + database + log-signing-key compromise, while keeping witnesses completely blind to vault data and PII.
- **Good**, because `rsv-audit` shares the exact same RFC 9162 / C2SP primitives already battle-tested across the Go SumDB, Sigstore/Rekor v2, and Certificate Transparency v2 ecosystems.
- **Bad**, because partial tiles (`.p/1`..`.p/255`) accumulate minor extra rows when checkpoints publish frequently at small batch sizes (mitigated by publishing checkpoints on a bounded cadence e.g. every 1–5 seconds or 256 events, and optionally pruning superseded `.p/W` tiles from CDN mirrors once a full tile `partial_width = 0` is finalized while retaining immutable DB rows or archiving cold partitions).
- **Bad**, because synchronous witness cosigning adds ~50–150ms latency to *checkpoint publication* (NOT to individual API request commits, which commit `vault.audit_events` asynchronously from periodic checkpoint publication!).

### Option B: Linear Hash Chain (`H_i = SHA-256(H_{i-1} || Entry_i)`) (Rejected)

- **Good**, because implementation is ~20 lines of code and requires zero auxiliary node storage.
- **Bad (Disqualifying)**, because verifying inclusion of event `i` or append-only consistency between `size_1` and `size_2` requires downloading and hashing **$O(N)$ entries** linearly (scanning 10 million rows just to verify a single access event!).
- **Bad (Disqualifying)**, because external witnesses cannot verify log growth in $O(\log N)$ time, making lightweight continuous witnessing infeasible at enterprise event volumes.

### Option C: Untiled Node-per-Row Merkle Tree in PostgreSQL (Rejected)

- **Good**, because RFC 9162 proof generation is straightforward in SQL/Rust.
- **Bad (Disqualifying)**, because storing every internal node as an individual row creates ~1× extra table rows (plus 23-byte PostgreSQL tuple headers + composite PK index entries = ~100+ bytes per 32-byte hash, a **> 3× storage amplification** over tiled binary `BYTEA`).
- **Bad (Disqualifying)**, because proof endpoints (`/get-proof-by-index?index=i&tree_size=n`) have $O(N^2)$ distinct `(index, tree_size)` combinations and are **uncacheable** on CDNs, exposing PostgreSQL directly to auditor/witness read amplification and DoS.

### Option D: Blockchain / Permissioned DLT or Managed Proprietary Ledger DB (Rejected)

- **Good**, because public blockchains offer high-visibility global anchoring.
- **Bad (Disqualifying)**, because permissioned DLTs (e.g., Hyperledger) impose severe operational complexity, high write latency, consensus fragility, and poor self-hosted air-gapped ergonomics.
- **Bad (Disqualifying)**, because proprietary cloud ledger services (e.g., AWS QLDB—which AWS formally announced end-of-support for!) introduce unacceptable cloud vendor lock-in and cannot run on customer sovereign/on-premises PostgreSQL deployments.
- **Note**: Tenants who wish to anchor checkpoints to a public blockchain MAY trivially deploy a C2SP witness that batches and anchors witnessed checkpoint roots on-chain without altering RusticStack Core's protocol!

---

## 6. Quantitative Engineering Comparison (10M Audit Events in One Tenant)

| Metric ($N = 10{,}000{,}000$ Events) | Option A: RFC 9162 + C2SP `tlog-tiles` | Option B: Linear Hash Chain | Option C: Node-per-Row Merkle |
| :--- | :---: | :---: | :---: |
| **Inclusion Proof Verification Work** | **24 SHA-256 ops** ($O(\log_2 N)$) | 10,000,000 SHA-256 ops ($O(N)$) | 24 SHA-256 ops ($O(\log_2 N)$) |
| **Network Requests per Inclusion Proof** | **3 static cached tiles** ($\le 24\text{ KiB}$) | Full log dump (GBs) | 1 uncacheable dynamic DB query |
| **Auxiliary Tree Rows in PostgreSQL** | **~39,216 tile rows** | 0 | **~10,000,000 node rows** |
| **Auxiliary Storage Footprint (incl. PG headers/indexes)** | **~325 MiB** (dense 8 KiB `BYTEA`) | 0 | **~1.3 GiB+** |
| **CDN / S3 Immutable Caching** | **100% Static (`immutable`)** | Impossible | Uncacheable ($O(N^2)$ query space) |
| **Split-View Defense** | **Yes (C2SP External Witnesses)** | No (O(N) witness cost) | Hard (custom witness protocol) |

---

## 7. Consequences & Operational Guardrails

1. **Gap-Free Sequencing**: `rsv-server` MUST allocate `vault.audit_events.log_index` via per-tenant `pg_advisory_xact_lock` + tail `Index Only Scan Backward`, strictly prohibiting PostgreSQL `SEQUENCE`s to guarantee gap-free RFC 9162 leaves.
2. **Synchronous Witness Quorum Policy**: Every row committed to `vault.audit_checkpoints` MUST already contain $\ge Q_w$ verified witness cosignatures in `witness_cosignatures` JSONB so `vault.audit_checkpoints` remains 100% append-only (`BEFORE UPDATE OR DELETE` trigger never bypassed).
3. **Domain Separation Test Vectors**: `rsv-audit` unit tests MUST include canonical RFC 9162 test vectors verifying `0x00` leaf / `0x01` internal node separation, empty-tree root `SHA-256("")`, power-of-two consistency proof edge cases, excess-node rejection, and C2SP `tlog-tiles` path formatting (`x001/234.p/42`).
4. **Offline Compliance Guarantee**: `rsv-compliance-cli` MUST refuse to invoke HSM `CPK` decryption on any `compliance_envelope` until checkpoint witness quorum, prefix consistency, tile-derived inclusion proof, and hardware `HDIK` `AuditCommitment` signature all verify cleanly.
