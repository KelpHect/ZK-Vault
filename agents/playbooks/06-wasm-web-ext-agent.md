# Devin Agent Playbook 06: Fixed-Arena WASM Core, Chrome MV3 Extension & Web SPA

> **Playbook ID**: `RSV-PLAYBOOK-06`
> **Agent Role**: WebAssembly Security, Browser Extension (MV3) & Zero-Knowledge Web Frontend Engineer
> **Active Milestones**: `M3-B` (`rsv-wasm`, parallel with Agent 03 `M3-A`) and `M4-B` (`clients/extension` & `clients/web-spa`, parallel with Agent 05 `M4-A`)
> **Target Toolchain**: Rust 2024 Edition (MSRV `1.94.0`) + `wasm32-unknown-unknown` + `wasm-pack` + TypeScript (Strict Mode)

---

## 1. Mission & Exclusive Ownership

Your mission is to engineer RusticStack Core's browser-tier cryptographic sandbox and clients:
1. `rsv-wasm` (`M3-B`): `#![forbid(unsafe_code)]` WebAssembly module compiled with a **fixed, statically bounded linear memory arena** containing **zero `memory.grow` instructions** (`INV-024`) and an opaque `KeyHandle(u32)` handle table guaranteeing raw cryptographic key bytes NEVER cross into JavaScript (`INV-022`).
2. `clients/extension/` (`M4-B`): Chrome/Chromium Manifest V3 extension supporting chunked Native Messaging offload (`<= 768 KiB`) to `rsv-nm-host` (`ADR-0006`, `INV-021`), strict anti-phishing origin-bound autofill (`INV-023`), and sandboxed `rsv-wasm` fallback when native daemon is unavailable.
3. `clients/web-spa/` (`M4-B`): Zero-Knowledge Web Vault SPA & Organization RBAC Dashboard (`specs/04`) with WebAuthn PRF + Argon2id `MUK` derivation, strict CSP/SRI, and exclusive `KeyHandle(u32)` interaction.

### Exclusive Write Ownership
- `crates/rsv-wasm/`
- `clients/extension/`
- `clients/web-spa/`

### Owned Formal Invariants
`INV-001`, `INV-010`, `INV-012`, `INV-021`, `INV-022`, `INV-023`, `INV-024`

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context:
1. [`AGENTS.md`](../../AGENTS.md) (Rules 1, 2, 9, 10)
2. [`agents/CRATE-CONTRACTS.md`](../CRATE-CONTRACTS.md) (§2, §3.8, §4, §5)
3. [`agents/BUILD-DAG.md`](../BUILD-DAG.md) (Milestones `M3-B` & `M4-B`)
4. [`specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md`](../../specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md) (WASM fixed-arena zeroization section)
5. [`specs/07-OMNI-CLIENT-ARCHITECTURE.md`](../../specs/07-OMNI-CLIENT-ARCHITECTURE.md) (MV3 extension, autofill, Web SPA & WebAuthn PRF)
6. [`specs/04-BLIND-RBAC-ACCESS-GRAPH.md`](../../specs/04-BLIND-RBAC-ACCESS-GRAPH.md) (WASM Org Dashboard section)
7. [`specs/08-API-AND-WIRE-PROTOCOLS.md`](../../specs/08-API-AND-WIRE-PROTOCOLS.md)
8. [`specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md`](../../specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md)
9. [`schemas/ipc-native-messaging.schema.json`](../../schemas/ipc-native-messaging.schema.json)
10. [`schemas/openapi-v1.yaml`](../../schemas/openapi-v1.yaml)
11. [`adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md`](../../adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md)
12. [`adrs/ADR-0008-wasm-fixed-arena-zeroization-strategy.md`](../../adrs/ADR-0008-wasm-fixed-arena-zeroization-strategy.md)
13. [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](../../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (§2 `ADV-06`; §4 `INV-021`–`INV-024`)
14. [`specs/10-TEST-VECTORS-AND-VERIFICATION.md`](../../specs/10-TEST-VECTORS-AND-VERIFICATION.md) (§2.7, §3.2 Part B, §3.5)

---

## 3. Strict Boundaries & Forbidden Actions

1. **ZERO `memory.grow` in Compiled `.wasm` (`INV-024`, `ADR-0008`)**:
   - Configure fixed linear memory linker flags (`--initial-memory=16777216`, `--max-memory=16777216`, i.e., `256` pages = `16 MiB` or configured fixed bound where `initial == maximum`) and a fixed-capacity arena allocator inside `rsv-wasm` so LLVM/rustc emits **ZERO** `Operator::MemoryGrow` instructions in `rsv_wasm_bg.wasm`.
   - Arena saturation MUST return `WasmError::ArenaExhausted` cleanly—NEVER grow linear memory!
2. **ZERO Raw Keys Across JS Boundary (`INV-022`)**:
   - NEVER export a `wasm-bindgen` function that accepts or returns raw `MUK`, `USK`, `UIK`, `TK`, `CK`, `DEK`, or `ORPK` bytes (`Uint8Array` / `Vec<u8>`).
   - Export ONLY opaque `KeyHandle(u32)` tokens packing `(slot_index: u16, generation: u16)` backed by an internal zeroizing slab inside WASM linear memory.
3. **ZERO `unsafe` Code (`INV-010`)**: `crates/rsv-wasm/src/lib.rs` MUST declare `#![forbid(unsafe_code)]`.
4. **Tier-2 WASM Dependency Firewall**: `rsv-wasm` MUST depend ONLY on Tier-0 crates (`rsv-types`, `rsv-crypto`, `rsv-vss`, `rsv-graph`, `rsv-audit`) + WASM bindings (`wasm-bindgen`, `js-sys`, `getrandom`). NEVER depend on `rsv-mem`, `rsv-enclave`, `tokio`, `sqlx`, `axum`, `libc`, `windows`, `std::fs`, or `std::net`.
5. **Strict Anti-Phishing Origin & Gesture Gate (`INV-023`)**:
   - The MV3 extension MUST refuse autofill unless ALL four conditions hold: `scheme === "https:"`, exact canonical Punycode/ASCII host (or policy eTLD+1) match, top-level or strictly same-origin frame (zero cross-origin `<iframe>` fills), AND active explicit user gesture (zero silent page-load fills).
6. **Hard `768 KiB` Native Messaging Chunk Limit (`INV-021`)**: Extension chunk encoder/reassembler MUST match `schemas/ipc-native-messaging.schema.json` strictly (`<= 786,432` B per frame, `<= 16 MiB` reassembly cap, `<= 8` concurrent streams).
7. **Zero LocalStorage/SessionStorage Secret Caching (`INV-001`)**: Neither `clients/extension` nor `clients/web-spa` may persist plaintext secrets or unlocked keys into `localStorage`, `sessionStorage`, `IndexedDB`, or `chrome.storage.local`.

---

## 4. Ordered Implementation Checklist

### Phase A — Milestone `M3-B` (`crates/rsv-wasm/`)
1. Configure `crates/rsv-wasm/Cargo.toml` and `.cargo/config.toml` target flags (`-C link-arg=--initial-memory=16777216 -C link-arg=--max-memory=16777216`) + bounded arena strategy guaranteeing zero `memory.grow` opcodes (`INV-024`).
2. Implement opaque `KeyHandle(u32)` slab table (`crates/rsv-wasm/src/handle_table.rs`):
   - Packs `slot_index` (16-bit) + `generation` (16-bit) preventing ABA handle reuse.
   - Enforces per-handle inactivity TTL and `lock_vault()` bulk zeroization (`zeroize`) of every active slot (`INV-022`).
3. Expose `wasm-bindgen` entrypoints strictly accepting/returning `KeyHandle(u32)`, ciphertext bytes, public keys, and bounded ephemeral plaintext ONLY for explicit user reveal/autofill requests:
   - `derive_muk_handle(passphrase_utf8, tenant_id, salt, params, prf_opt) -> Result<KeyHandle, JsError>` (immediately zeroizes temporary passphrase buffer in WASM memory)
   - `unwrap_key_graph(...) -> Result<KeyHandle, JsError>`
   - `seal_item_envelope(...)`, `open_item_envelope(...)` (`CS-01` & `CS-02` X-Wing)
   - `verify_vss_share(...)`, `verify_merkle_checkpoint(...)`, `matches_autofill_origin(...)`, `lock_vault()`
4. Implement `crates/rsv-wasm/tests/wasm_arena_gate.rs` using `wasmparser`:
   - Inspects compiled release `.wasm` artifact and asserts `memory.maximum == Some(memory.initial)` AND `count(Operator::MemoryGrow { .. }) == 0`.
5. Implement `crates/rsv-wasm/tests/handle_table.rs` & cross-target KAT tests under `wasm-pack test --headless --chrome` verifying bit-exact parity with `test-vectors/v1/*` and `.d.ts` inspection confirming zero raw key exports.
6. Run `M3-B` exit commands and open `M3-B` PR.

### Phase B — Milestone `M4-B` (`clients/extension/` & `clients/web-spa/`)
7. **Chrome MV3 Extension (`clients/extension/`)**:
   - Author strict `manifest.json` (MV3, minimal permissions, `nativeMessaging`, strict `content_security_policy` blocking `'unsafe-inline'` and external scripts).
   - Implement Service Worker chunked Native Messaging client (`<= 768 KiB` framing matching `schemas/ipc-native-messaging.schema.json`) delegating crypto to `rsv-nm-host` when installed (`ADR-0006`), with transparent fallback to `rsv-wasm` `KeyHandle(u32)` session when standalone.
   - Implement Content Script & Origin Gate (`INV-023`): strict `https://`, Punycode normalization, cross-origin `<iframe>` detection (`window === window.top` or verified same-origin ancestry), and mandatory user-gesture verification.
   - Write automated TypeScript security tests for the full Origin-Bound Autofill Matrix (Punycode homographs, `http://`, `data:`, `javascript:`, cross-origin `<iframe>`, missing gesture) and `> 1 MiB` multi-chunk NM reassembly.
8. **Zero-Knowledge Web SPA & Org Dashboard (`clients/web-spa/`)**:
   - Implement WebAuthn Level 3 PRF + Argon2id unlock flow calling `rsv-wasm::derive_muk_handle`.
   - Implement Org RBAC Graph Dashboard (`specs/04`) visualizing Teams, Collections (`Standard` vs `Root Quorum Only`), `key_epoch` status, and executing client-side `key_epoch + 1` revocation rotations.
   - Implement strict CSP headers & build-time SRI hash generation; verify zero plaintext secret writes to browser Web Storage APIs.
9. Run `M4-B` exit commands and open `M4-B` PR.

---

## 5. Exact Verification Commands & Exit Criteria

ALL commands below MUST exit with code `0` before opening your PR:

```bash
# 1. Rust formatting, strict clippy & unsafe firewall
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 clippy -p rsv-wasm --target wasm32-unknown-unknown -- -D warnings
grep -q '#!\[forbid(unsafe_code)\]' crates/rsv-wasm/src/lib.rs

# 2. Tier-2 WASM dependency firewall
! cargo tree -p rsv-wasm --target wasm32-unknown-unknown | grep -E 'rsv-mem|rsv-enclave|tokio|sqlx|axum|gpui|libc|windows'

# 3. Release WASM build + Fixed-Arena Zero-Growth binary inspection gate (INV-024)
cargo +1.94.0 build -p rsv-wasm --target wasm32-unknown-unknown --release
cargo +1.94.0 test -p rsv-wasm --test wasm_arena_gate -- --nocapture

# 4. Headless Chrome WASM KAT parity & KeyHandle(u32) security tests (INV-022)
wasm-pack test --headless --chrome crates/rsv-wasm

# 5. Audit generated TypeScript bindings for zero raw key exports
wasm-pack build crates/rsv-wasm --target web --release
! grep -Ei 'export_raw_key|get_muk_bytes|get_usk_bytes|get_dek_bytes' crates/rsv-wasm/pkg/rsv_wasm.d.ts

# 6. Extension & Web SPA strict TypeScript typecheck, origin-autofill & NM chunk tests (INV-021, INV-023)
(cd clients/extension && npm ci && npm run typecheck && npm test && npm run build)
(cd clients/web-spa && npm ci && npm run typecheck && npm test && npm run build)

# 7. Supply chain & license compliance
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

---

## 6. Handoff & PR Contract

- **Branch Naming**: `feat/m3b-agent06-wasm`, `feat/m4b-agent06-ext-spa`
- **PR Description MUST Include**:
  - Explicit Invariant Tags Verified: `[INV-001] [INV-010] [INV-012] [INV-021] [INV-022] [INV-023] [INV-024]`
  - Raw `wasm_arena_gate` log proving `memory.initial == memory.maximum` and `Operator::MemoryGrow count == 0` in the release `.wasm` binary.
  - Headless Chrome `wasm-pack test` KAT parity output and `.d.ts` API audit confirmation (`KeyHandle(u32)` only).
  - Full Origin-Bound Autofill negative test matrix pass log (Punycode homographs, `http://`, cross-origin `<iframe>`, missing gesture).
- **Downstream Unblock Signal**: Merging `M3-B` unblocks `M4-B`; merging `M4-B` (with `M4-A` and `M5`) unblocks Agent 07 (`M6`).
