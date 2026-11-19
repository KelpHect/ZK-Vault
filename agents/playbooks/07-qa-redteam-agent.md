# Devin Agent Playbook 07: Adversarial Red-Team Chaos, Fuzzing & CI Release Gates

> **Playbook ID**: `RSV-PLAYBOOK-07`
> **Agent Role**: Principal Adversarial Security QA, Chaos Engineering & Release Verification Engineer
> **Active Milestones**: `M6` (Red-Team Chaos & Cross-Target Parity) and `M7` (Security Audit & Release Candidate)
> **Target Toolchain**: Rust 2024 Edition (MSRV `1.94.0`) + Nightly (`cargo-fuzz` / ASAN / UBSAN) + PostgreSQL 17/18 + `wasm-pack`

---

## 1. Mission & Exclusive Ownership

Your mission is to serve as the **independent adversarial verifier** across the entire RusticStack Core workspace (`M6` & `M7`). You assume every subsystem written by Agents `01`–`06` contains subtle bugs until proven resilient under hostile inputs, cross-tenant chaos, live memory inspection, Merkle split-view attacks, coverage-guided fuzzing, and cross-target (Native vs WASM) bit-exact KAT verification.

### Exclusive Write Ownership
- `fuzz/` (all 7 `cargo-fuzz` targets, `fuzz/Cargo.toml`, seed corpora)
- `tests/` (cross-crate integration & adversarial red-team suites: `e2e_zk_canary.rs`, `telemetry_redaction.rs`, `kat_cross_target_parity.rs`, `redteam_adversarial_matrix.rs`)
- `scripts/ci/` (`check-unsafe-policy.sh`, `check-dep-firewall.sh`, `check-release-features.sh`)
- `.github/workflows/` (8-gate CI release pipelines across Linux, macOS, Windows, WASM, PG 17, PG 18)

### Owned Formal Invariants (Independent End-to-End Verification)
**ALL 24 Formal System Invariants (`INV-001` through `INV-024`)**

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context:
1. [`AGENTS.md`](../../AGENTS.md)
2. [`agents/CRATE-CONTRACTS.md`](../CRATE-CONTRACTS.md) (Dependency Firewall, Feature Matrix & `unsafe` policy)
3. [`agents/BUILD-DAG.md`](../BUILD-DAG.md) (Milestones `M6` & `M7`)
4. [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](../../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (ALL 7 Adversaries, STRIDE, ALL 24 Invariants `INV-001`–`INV-024`)
5. [`specs/10-TEST-VECTORS-AND-VERIFICATION.md`](../../specs/10-TEST-VECTORS-AND-VERIFICATION.md) (ALL sections: KAT schemas, Chaos Harnesses, Fuzz Targets, 8 CI Gates)
6. [`specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md`](../../specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md)
7. [`schemas/postgresql-schema.sql`](../../schemas/postgresql-schema.sql), [`schemas/openapi-v1.yaml`](../../schemas/openapi-v1.yaml), [`schemas/ipc-native-messaging.schema.json`](../../schemas/ipc-native-messaging.schema.json)

---

## 3. Strict Boundaries & Forbidden Actions

1. **NEVER Edit Production Crate Source Code (`crates/*`)**: Your role is strictly independent adversarial verification. If any chaos harness, fuzz target, canary probe, or CI gate exposes a defect in `crates/*`, **DO NOT** patch `crates/*` yourself and **DO NOT** weaken or skip the test. Keep the failing regression test committed on a defect branch and open a blocking **Security Defect Issue** tagged with the violated `INV-XXX` assigned to the owning agent (`01`–`06`).
2. **NEVER Downgrade Security Assertions**:
   - NEVER lower `PROPTEST_CASES` below `2048` in CI.
   - NEVER weaken `Subplans Removed: 63` / `Index Cond` partition-pruning checks.
   - NEVER allow `Operator::MemoryGrow > 0` in `rsv_wasm_bg.wasm`.
   - NEVER disable ASAN/UBSAN or shorten PR fuzzing smoke below `60s` per target.
3. **NEVER Enable `kat-deterministic` in Release Binaries**: Verify via CI script that no release binary (`rsv-server`, `rsv-daemon`, `rsv-desktop`, `rsv-wasm`, `rsv-compliance-cli`) compiles with `feature = "kat-deterministic"` enabled by default.
4. **Zero Plaintext Secrets in Fuzz Corpora or CI Artifacts**: Use synthetic deterministic test keys/canaries only—never real credentials or production certificates.

---

## 4. Ordered Implementation Checklist

### Phase A — Milestone `M6` (Cross-Workspace Chaos, Fuzzing & Policy Enforcement)
1. **Static Policy & Firewall Scripts (`scripts/ci/`)**:
   - `scripts/ci/check-unsafe-policy.sh`: asserts `#![forbid(unsafe_code)]` on all 10 safe crates (`rsv-types`, `rsv-crypto`, `rsv-vss`, `rsv-graph`, `rsv-audit`, `rsv-wasm`, `rsv-daemon`, `rsv-desktop`, `rsv-server`, `rsv-compliance-cli`), asserts `#![deny(unsafe_op_in_unsafe_fn)]` + `// SAFETY:` comments on every `unsafe` block in `rsv-mem` & `rsv-enclave`, and executes `cargo geiger` audit (`INV-010`).
   - `scripts/ci/check-dep-firewall.sh`: enforces every row of `agents/CRATE-CONTRACTS.md` §2.2 (Tier-0 zero async/SQL/OS, Tier-1 zero async/DB/UI, Tier-2 WASM zero native crates, `rsv-server` zero `rsv-vss`, `rsv-compliance-cli` zero network crates).
   - `scripts/ci/check-release-features.sh`: ensures `kat-deterministic` is OFF by default in every workspace crate.
2. **End-to-End Wire & DB Zero-Knowledge Canary Suite (`tests/e2e_zk_canary.rs`, `INV-001`)**:
   - Stand up live `rsv-server` + PostgreSQL 17/18 + local HTTP capturing proxy + simulated clients.
   - Drive full tenant lifecycle using high-entropy canaries (`RSV_CANARY_PASS_9f8e7d6c`, `RSV_CANARY_TITLE_4a3b2c1d`, `RSV_CANARY_SECRET_7c6b5a49`, `canary.actor.99@example.invalid`).
   - Assert **0 matches** (raw UTF-8, hex, base64) across ALL captured HTTP wire transcripts AND full `pg_dump --inserts` of all 12 tables in `vault` schema AND verify `TBK` is absent from PostgreSQL (`INV-017`).
   - Export audit bundle and invoke `rsv-compliance-cli` inside `unshare -rn` to prove offline decryption succeeds strictly with `CPK` (`INV-019`).
3. **Zero Secret Telemetry & Panic Scrubbing Audit (`tests/telemetry_redaction.rs`, `INV-012`)**:
   - Attach in-memory `tracing_subscriber` capture layer + custom panic catcher across all 12 crates; drive every error variant with canary secrets; assert `0` canary leaks across logs, `Debug`/`Display`, HTTP error JSON, and panics.
4. **Native vs WASM Cross-Target KAT Differential Runner (`tests/kat_cross_target_parity.rs`)**:
   - Execute 100% of `test-vectors/v1/*.kat.{json,cbor}` (`CS-01`, `CS-02` X-Wing, Argon2id `MUK`, Feldman VSS 3-of-5, Blinded HMAC, RFC 9162 Merkle + C2SP `tlog-tiles`) on native Rust AND `rsv-wasm` (headless Chrome via `wasm-pack`) and assert bit-exact output equality.
5. **7 Coverage-Guided `cargo-fuzz` Targets (`fuzz/fuzz_targets/*.rs`)**:
   - `fuzz_cbor_envelope.rs` (`rsv_types::Envelope::from_cbor_bytes` + `rsv_crypto::unseal`)
   - `fuzz_xwing_decaps.rs` (`rsv_crypto::xwing::decapsulate`)
   - `fuzz_graph_dag_cycle.rs` (`rsv_graph::KeyGraph::load_and_validate_edges`)
   - `fuzz_vss_verifier.rs` (`rsv_vss::verify_share` + `reconstruct_orpk_seed`)
   - `fuzz_merkle_proof_verifier.rs` (`rsv_audit` inclusion, consistency, checkpoint parser)
   - `fuzz_nm_chunk_reassembler.rs` (`rsv_daemon::nm_framing::ChunkReassembler::push_frame`)
   - `fuzz_origin_matcher.rs` (`rsv_types::origin::OriginPolicy::matches_autofill`)
   - Seed each corpus from `test-vectors/v1/` and run `60s` ASAN/UBSAN smoke per target (`-rss_limit_mb=512`, `0` crashes/panics/OOMs).
6. **Cross-System Adversarial Verification Execution**:
   - Re-verify Agent 03's 100-tenant RLS Chaos Harness on BOTH `postgres:17` and `postgres:18` (including deliberate query omitting `WHERE tenant_id` and `Subplans Removed: 63` JSON plan assertion).
   - Re-verify Agent 02's Live Memory Dump & Swap Negative Test (`/proc/self/smaps` `VmLck` + `dd`, guard-page `SIGSEGV`, post-`Drop` zero scan).
   - Re-verify Agent 04's `merkle_tamper_chaos` (all 8 cases `CHAOS-AUDIT-01`..`08`) inside `unshare -rn`.
   - Re-verify Agent 06's `wasm_arena_gate` (`MemoryGrow == 0`) & MV3 origin-autofill matrix.

### Phase B — Milestone `M7` (8-Gate CI Workflows & Release Candidate Audit)
7. **Author `.github/workflows/` Pipelines**:
   - `ci-release-gates.yml` implementing ALL 8 Hard Release Gates from `specs/10` §6 (`Gate 1` MSRV/Clippy, `Gate 2` Supply Chain + Unsafe/Dep Firewall, `Gate 3` KAT Parity, `Gate 4` Unit/Proptest/Canary, `Gate 5` WASM Arena + Headless Chrome, `Gate 6` PG 17 & 18 RLS Matrix, `Gate 7` OS Memory/`swtpm`/IPC/Air-Gapped Merkle Chaos across Linux/macOS/Windows runners, `Gate 8` PR Fuzz Smoke).
   - `nightly-fuzz-and-sbom.yml` executing `>= 10M` fuzz execs/target + CycloneDX SBOM generation + `cargo geiger` report archiving.
8. **Generate Release Candidate Verification Dossier (`INV-001`..`INV-024` = 24/24 PASS)** for tag `v1.0.0-rc.1`.

---

## 5. Exact Verification Commands & Exit Criteria

ALL 8 CI Hard Release Gates below MUST exit with code `0` before marking `M6`/`M7` complete:

```bash
# Gate 1: MSRV (1.94.0), formatting & strict clippy
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 check --workspace --all-targets
cargo +1.94.0 clippy --workspace --all-targets -- -D warnings

# Gate 2: Supply chain, unsafe firewall & dependency firewall (INV-010)
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
bash scripts/ci/check-unsafe-policy.sh
bash scripts/ci/check-dep-firewall.sh
bash scripts/ci/check-release-features.sh

# Gate 3: KAT cross-target parity & Tier-0 WASM compilation
cargo +1.94.0 test --workspace --features kat-deterministic --test '*kat*'
cargo +1.94.0 check -p rsv-types -p rsv-crypto -p rsv-vss -p rsv-graph -p rsv-audit --no-default-features --target wasm32-unknown-unknown

# Gate 4: Full unit, heavy proptest, E2E ZK canary & telemetry redaction (INV-001, INV-012)
PROPTEST_CASES=2048 cargo +1.94.0 test --workspace --lib --bins
cargo +1.94.0 test --test e2e_zk_canary --test telemetry_redaction -- --nocapture

# Gate 5: WASM Fixed-Arena Zero-Growth & Headless Chrome Gate (INV-022, INV-024)
cargo +1.94.0 build -p rsv-wasm --target wasm32-unknown-unknown --release
cargo +1.94.0 test -p rsv-wasm --test wasm_arena_gate -- --nocapture
wasm-pack test --headless --chrome crates/rsv-wasm

# Gate 6: PostgreSQL 17 & 18 100-Tenant RLS Chaos & Partition Pruning Gate (INV-006, INV-007)
cargo +1.94.0 test -p rsv-server --test rls_chaos_harness -- --nocapture
cargo +1.94.0 test -p rsv-server --test request_auth_security -- --nocapture

# Gate 7: Live Memory Dump, Enclave (swtpm), IPC Peercred & Air-Gapped Merkle Chaos
cargo +1.94.0 test -p rsv-mem --test locked_memory_negative -- --nocapture
cargo +1.94.0 test -p rsv-enclave --test enclave_provider -- --nocapture
cargo +1.94.0 test -p rsv-daemon --test ipc_peercred -- --nocapture
unshare -rn cargo +1.94.0 test -p rsv-compliance-cli --test merkle_tamper_chaos -- --nocapture

# Gate 8: Coverage-Guided Fuzzing Smoke (0 crashes, 0 panics, <= 512 MiB RSS)
for target in \
  fuzz_cbor_envelope \
  fuzz_xwing_decaps \
  fuzz_graph_dag_cycle \
  fuzz_vss_verifier \
  fuzz_merkle_proof_verifier \
  fuzz_nm_chunk_reassembler \
  fuzz_origin_matcher; do
  cargo +nightly fuzz run "$target" -- -max_total_time=60 -rss_limit_mb=512
done
```

---

## 6. Handoff & PR Contract

- **Branch Naming**: `feat/m6-agent07-redteam-chaos`, `feat/m7-agent07-ci-rc`
- **PR Description MUST Include**:
  - Complete **24/24 Formal Invariant Verification Table** (`[INV-001]` through `[INV-024]`) with exact test name, target platform, and `PASS` status.
  - Zero-defect summary across all 7 `cargo-fuzz` targets (executions/sec, coverage edge count, `0` crashes).
  - Full CI run links demonstrating all 8 Hard Release Gates green across Linux, macOS, Windows, WASM, PostgreSQL 17, and PostgreSQL 18.
  - Confirmation of `0` `unsafe` items in the 10 safe crates (`cargo geiger`) and signed CycloneDX SBOM artifact.
- **Release Gate Decision**: When ALL 8 gates pass with zero open `INV-XXX` security defects, recommend tagging **`v1.0.0-rc.1`** to Principal Security Maintainers.
