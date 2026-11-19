# Devin Agent Playbook 01: Core Cryptography, Feldman VSS & Blind RBAC Engine

> **Playbook ID**: `RSV-PLAYBOOK-01`
> **Agent Role**: Cryptographic Systems & Pure Core Engineer
> **Active Milestones**: `M0` (Workspace & Types Freeze), `M1` (Crypto & VSS Core), `M2-A` (Blind RBAC DAG)
> **Target Toolchain**: Rust 2024 Edition (MSRV `1.94.0`) + `wasm32-unknown-unknown`

---

## 1. Mission & Exclusive Ownership

Your mission is to establish the immutable 12-crate workspace baseline (`M0`), implement the zero-unsafe `no_std + alloc` cryptographic foundation for `CS-01` (`0x0001`) and `CS-02` (`0x0002` Post-Quantum Hybrid X-Wing), build the 2×128-bit Ristretto255 Feldman Verifiable Secret Sharing engine (`M1`), and deliver the Blind RBAC Access DAG engine (`M2-A`).

### Exclusive Write Ownership
- Root workspace files (`M0` ONLY): `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`
- `crates/rsv-types/` (complete implementation + stub `Cargo.toml`/`src/lib.rs` for the other 11 crates at `M0`)
- `crates/rsv-crypto/`
- `crates/rsv-vss/`
- `crates/rsv-graph/`
- `test-vectors/v1/cs01_hpke_aesgcm.kat.{json,cbor}`
- `test-vectors/v1/cs02_xwing_mldsa.kat.{json,cbor}`
- `test-vectors/v1/kdf_argon2id_muk.kat.json`
- `test-vectors/v1/vss_feldman_ristretto255.kat.{json,cbor}`

### Owned Formal Invariants
`INV-001`, `INV-002`, `INV-003`, `INV-004`, `INV-005`, `INV-008`, `INV-009`, `INV-010`, `INV-012`, `INV-015`, `INV-016`

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context before writing code:
1. [`AGENTS.md`](../../AGENTS.md) (Turn-0 guardrails)
2. [`agents/CRATE-CONTRACTS.md`](../CRATE-CONTRACTS.md) (exact crate traits, feature flags & dependency firewall)
3. [`agents/BUILD-DAG.md`](../BUILD-DAG.md) (Milestones `M0`, `M1`, `M2-A`)
4. [`specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md`](../../specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md)
5. [`specs/04-BLIND-RBAC-ACCESS-GRAPH.md`](../../specs/04-BLIND-RBAC-ACCESS-GRAPH.md)
6. [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](../../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (§4: `INV-001`–`INV-005`, `INV-008`–`INV-010`, `INV-015`, `INV-016`)
7. [`specs/10-TEST-VECTORS-AND-VERIFICATION.md`](../../specs/10-TEST-VECTORS-AND-VERIFICATION.md) (§2.1–§2.4, §3.4)
8. [`adrs/ADR-0001-hybrid-escrow-and-feldman-vss.md`](../../adrs/ADR-0001-hybrid-escrow-and-feldman-vss.md)
9. [`adrs/ADR-0007-crypto-agility-xwing-post-quantum-hybrid.md`](../../adrs/ADR-0007-crypto-agility-xwing-post-quantum-hybrid.md)

---

## 3. Strict Boundaries & Forbidden Actions

1. **ZERO `unsafe` Code (`INV-010`)**: Every owned crate (`rsv-types`, `rsv-crypto`, `rsv-vss`, `rsv-graph`) MUST start with `#![no_std]` and `#![forbid(unsafe_code)]`.
2. **Strict Tier-0 Dependency Firewall**: NEVER add `tokio`, `sqlx`, `axum`, `gpui`, `libc`, `windows`, `reqwest`, `std::fs`, `std::net`, `rsv-mem`, or `rsv-enclave` to any owned crate. Every crate MUST compile cleanly with `--no-default-features --target wasm32-unknown-unknown`.
3. **Never Allow Empty AAD (`INV-002`)**: Do NOT expose any AEAD or HPKE/X-Wing API accepting `&[u8]` empty AAD. Every seal/open function MUST take `&AadContext` encoded deterministically per RFC 8949 CBOR.
4. **Exact X-Wing Combiner (`INV-004`)**: Under `CS-02`, you MUST implement `SHA3-256(ss_MLKEM768 || ss_X25519 || ct_X25519 || pk_X25519 || 0x5c2e2f2f5e5c)`. NEVER substitute naive concatenation (`ss_MLKEM || ss_X25519`). Hybrid signatures MUST require BOTH `Ed25519::verify_strict` AND `ML-DSA-65`.
5. **No Caller-Supplied Production Nonces (`INV-003`)**: Production AEAD APIs MUST sample fresh 96-bit CSPRNG nonces internally. Deterministic seeded paths MUST be gated strictly behind `#[cfg(feature = "kat-deterministic")]`.
6. **Zero Secret Logging or `Display` (`INV-012`)**: All key structs MUST wrap bytes in `secrecy::SecretBox<T>` + `zeroize::ZeroizeOnDrop` with constant redacted `Debug` (`"[REDACTED]"`). NEVER implement `Display` on key material.
7. **Exact 2×128-bit Feldman VSS Chunking (`INV-015`, `INV-016`)**: NEVER reduce a 256-bit `ORPK_SEED` modulo $\ell$ in a single Ristretto255 scalar (that loses ~3.4 bits of entropy and corrupts reconstruction!). Split cleanly into two 128-bit little-endian chunks (`chunk_lo`, `chunk_hi`).
8. **Enforce `root_quorum_only` Escrow Prohibition (`INV-005`)**: `rsv-graph` MUST reject `DRPubK` or admin escrow wrappers targeting `EscrowTier::RootQuorumOnly` with `ESCROW_POLICY_VIOLATION`.
9. **No Out-of-Scope Writes**: After `M0` merges, NEVER edit `crates/rsv-mem`, `crates/rsv-enclave`, `crates/rsv-audit`, `crates/rsv-server`, `crates/rsv-wasm`, `crates/rsv-daemon`, `crates/rsv-desktop`, or `crates/rsv-compliance-cli`.

---

## 4. Ordered Implementation Checklist

### Phase A — Milestone `M0` (Workspace & Types Freeze)
1. Author root `Cargo.toml` declaring all 12 workspace crates, `edition = "2024"`, `rust-version = "1.94.0"`, and pinned workspace dependencies (`aes-gcm = "0.11"`, `hpke = "0.15"`, `ml-kem`, `x25519-dalek = "3.0"`, `ed25519-dalek = "3.0"`, `argon2 = "0.6"`, `vsss-rs = "6.0"`, `secrecy = "0.10"`, `zeroize = "1.9"`).
2. Author `rust-toolchain.toml` (`1.94.0`, `wasm32-unknown-unknown`) and `deny.toml` (MIT/Apache-2.0 allowlist, advisory bans).
3. Implement `crates/rsv-types/`:
   - Newtype UUIDv7 identifiers (`TenantId`, `UserId`, `DeviceId`, `TeamId`, `CollectionId`, `ItemId`, `RevisionId`).
   - `CipherSuiteId` (`Cs01Classical = 0x0001`, `Cs02PqHybridXWing = 0x0002`), `EscrowTier`, `HardwareTrustTier`, `ApiErrorCode`.
   - `AadContext` with RFC 8949 deterministic canonical CBOR serializer (`to_canonical_cbor`) and round-trip parser.
   - `OriginPolicy::matches_autofill` canonical `https://` + Punycode/eTLD+1 matcher supporting `INV-023`.
4. Scaffold compiling stubs for the other 11 crates (with `#![forbid(unsafe_code)]` on all safe crates) matching `agents/CRATE-CONTRACTS.md`.
5. Run `M0` exit commands and open `M0` PR (`m0-contracts-frozen`).

### Phase B — Milestone `M1` (`rsv-crypto` & `rsv-vss`)
6. Implement `crates/rsv-crypto/`:
   - `CS-01` provider: `AES-256-GCM`, RFC 9180 HPKE (`DHKEM(X25519, HKDF-SHA256)`), `Ed25519` (`verify_strict`), `HKDF-SHA256`.
   - `CS-02` provider (under `pq-xwing` feature, enabled by default): X-Wing (`X25519 + ML-KEM-768` with exact `SHA3-256` combiner & `0x5c2e2f2f5e5c` label) + hybrid `Ed25519 + ML-DSA-65` signatures.
   - `derive_muk`: `Argon2id` (`m >= 65536 KiB`, `t >= 3`, `p >= 1` floor enforced, rejecting weak parameters) XOR `HKDF-SHA256(webauthn_prf)` when PRF is present.
   - Deterministic `ORPK_SEED` -> `(ORPK, ORPubK)` HKDF key expansion.
   - Generate and verify `test-vectors/v1/cs01_hpke_aesgcm.kat.{json,cbor}`, `cs02_xwing_mldsa.kat.{json,cbor}` (including official `draft-connolly-cfrg-xwing-kem` vectors), and `kdf_argon2id_muk.kat.json`.
   - Write `proptest` module `prop_aead_roundtrip_and_aad` and nonce-uniqueness test (`100,000` distinct nonces).
7. Implement `crates/rsv-vss/`:
   - 2×128-bit little-endian chunk splitting of 256-bit `ORPK_SEED` over Ristretto255 using `vsss-rs` `6.0` Feldman VSS.
   - Independent `verify_share` against published commitments without reconstructing `ORPK_SEED`.
   - `reconstruct_orpk_seed` enforcing strict share verification, duplicate index rejection, and `shares.len() >= threshold` (`QUORUM_THRESHOLD_UNMET`).
   - Proactive share refresh preserving `ORPK_SEED` with fresh degree `t-1` zero-constant polynomials.
   - Generate and verify `test-vectors/v1/vss_feldman_ristretto255.kat.{json,cbor}` (all $\binom{5}{3} = 10$ subsets + tamper matrix) and `prop_feldman_arbitrary_quorum`.
8. Run `M1` exit commands and open `M1` PR (`m1-crypto-vss-green`).

### Phase C — Milestone `M2-A` (`rsv-graph`)
9. Implement `crates/rsv-graph/`:
   - Strict stratified DAG validator (`User -> Team -> Collection -> Item`, `User -> Collection`, `ORPubK/DRPubK -> Collection`) using Kahn/DFS cycle detection rejecting any cycle with `GraphError::CycleDetected` (`GRAPH_CYCLE_REJECTED`).
   - Granter `UIK` signature verification on every loaded edge (`INV-008`).
   - Multi-hop authenticated key unwrapping (`USK -> TK -> CK -> DEK`) with mandatory `AadContext` binding per hop (`INV-002`).
   - `validate_escrow_edge` rejecting `DRPubK` or admin wrappers on `EscrowTier::RootQuorumOnly` (`INV-005`).
   - `plan_revocation_rotation` generating fresh `key_epoch + 1` keys and newly signed wrapped edges excluding revoked users (`INV-009`).
   - Write `prop_dag_acyclicity_and_revocation` and `escrow_policy.rs` negative tests.
10. Run `M2-A` exit commands and open `M2-A` PR.

---

## 5. Exact Verification Commands & Exit Criteria

ALL commands below MUST exit with code `0` before opening your PR:

```bash
# 1. Toolchain, formatting & strict lints
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 clippy -p rsv-types -p rsv-crypto -p rsv-vss -p rsv-graph --all-targets -- -D warnings

# 2. Tier-0 no_std + WASM compilation firewall (MUST compile with zero default features)
cargo +1.94.0 check -p rsv-types -p rsv-crypto -p rsv-vss -p rsv-graph --no-default-features --target wasm32-unknown-unknown

# 3. Verify zero forbidden dependencies in Tier-0 tree
! cargo tree -p rsv-graph -p rsv-vss -p rsv-crypto -p rsv-types | grep -E 'tokio|sqlx|axum|gpui|libc|windows|reqwest|hyper'

# 4. Verify #![forbid(unsafe_code)] in all owned crates
for c in rsv-types rsv-crypto rsv-vss rsv-graph; do
  grep -q '#!\[forbid(unsafe_code)\]' "crates/$c/src/lib.rs"
done

# 5. Deterministic KAT suites & heavy property tests
cargo +1.94.0 test -p rsv-types -p rsv-crypto -p rsv-vss -p rsv-graph --features kat-deterministic
PROPTEST_CASES=2048 cargo +1.94.0 test -p rsv-crypto -p rsv-vss -p rsv-graph

# 6. Supply chain & license audit
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

---

## 6. Handoff & PR Contract

- **Branch Naming**: `feat/m0-agent01-contracts`, `feat/m1-agent01-crypto-vss`, `feat/m2a-agent01-graph`
- **PR Description MUST Include**:
  - Explicit Invariant Tags Verified: `[INV-001] [INV-002] [INV-003] [INV-004] [INV-005] [INV-008] [INV-009] [INV-010] [INV-012] [INV-015] [INV-016]`
  - Confirmation that `cargo check --no-default-features --target wasm32-unknown-unknown` passed across all 4 crates.
  - Summary of KAT vector counts (`CS-01`, `CS-02` X-Wing, Argon2id `MUK`, Feldman VSS 3-of-5 $\binom{5}{3}=10$ subsets + negative mutations).
- **Downstream Unblock Signal**: Merging `M0` unblocks Agent 02 (`M2-C`); merging `M1` unblocks Agent 04 (`M2-B`); merging `M2-A` (with `M2-B` & `M2-C`) unblocks Agents 03 (`M3-A`) and 06 (`M3-B`).
