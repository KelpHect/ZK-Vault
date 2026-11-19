# Devin Agent Playbook 05: Locked Crypto Daemon, OS IPC, `rsv-nm-host` & GPUI Desktop UI

> **Playbook ID**: `RSV-PLAYBOOK-05`
> **Agent Role**: Native Desktop Systems, OS IPC & GPUI Frontend Engineer
> **Active Milestone**: `M4-A` (Executes in parallel with Agent 06 `M4-B` and Agent 04 `M5` after `m3-backend-wasm-green`)
> **Target Toolchain**: Rust 2024 Edition (MSRV `1.94.0`) — Native Linux (Vulkan), macOS (Metal), Windows (DX12)

---

## 1. Mission & Exclusive Ownership

Your mission is to implement RusticStack Core's native workstation tier:
1. `rsv-daemon`: Process-hardened, locked-memory vault daemon (`rsv-mem` + `rsv-enclave`), mutually authenticated local OS IPC (`SO_PEERCRED` on Unix, Named Pipe client SID + `GetNamedPipeClientProcessId` + owner-only SDDL DACL on Windows), TLS 1.3 `/api/v1` sync client with `HDIK` request signing & `CPubK` `X-RSV-Audit-Envelope` emission, and the Chrome Native Messaging bridge binary (`rsv-nm-host`) enforcing strict `<= 768 KiB` (`786,432` B) chunking below Chrome's `1 MiB` hard cutoff.
2. `rsv-desktop`: Native GPU-accelerated GPUI (`gpui` / `gpui-ce`) enterprise desktop vault UI communicating exclusively with `rsv-daemon` over peer-authenticated local IPC—never embedding Electron, Chromium, or WebView (`ADR-0003`).

### Exclusive Write Ownership
- `crates/rsv-daemon/` (including `rsv-nm-host` binary target)
- `crates/rsv-desktop/`
- `test-vectors/v1/nm_host_chunk_framing.kat.json`

### Owned Formal Invariants
`INV-001`, `INV-005`, `INV-010`, `INV-011`, `INV-012`, `INV-013`, `INV-014`, `INV-020`, `INV-021`, `INV-023`

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context:
1. [`AGENTS.md`](../../AGENTS.md) (Rules 2, 5, 6, 9)
2. [`agents/CRATE-CONTRACTS.md`](../CRATE-CONTRACTS.md) (§2, §3.6, §3.8, §5)
3. [`agents/BUILD-DAG.md`](../BUILD-DAG.md) (Milestone `M4-A`)
4. [`specs/07-OMNI-CLIENT-ARCHITECTURE.md`](../../specs/07-OMNI-CLIENT-ARCHITECTURE.md)
5. [`specs/08-API-AND-WIRE-PROTOCOLS.md`](../../specs/08-API-AND-WIRE-PROTOCOLS.md)
6. [`specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md`](../../specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md) (§1–§3)
7. [`specs/04-BLIND-RBAC-ACCESS-GRAPH.md`](../../specs/04-BLIND-RBAC-ACCESS-GRAPH.md)
8. [`schemas/ipc-native-messaging.schema.json`](../../schemas/ipc-native-messaging.schema.json)
9. [`schemas/openapi-v1.yaml`](../../schemas/openapi-v1.yaml)
10. [`adrs/ADR-0003-gpui-native-desktop-over-electron.md`](../../adrs/ADR-0003-gpui-native-desktop-over-electron.md)
11. [`adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md`](../../adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md)
12. [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](../../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (§4: `INV-011`, `INV-012`, `INV-014`, `INV-020`, `INV-021`, `INV-023`)
13. [`specs/10-TEST-VECTORS-AND-VERIFICATION.md`](../../specs/10-TEST-VECTORS-AND-VERIFICATION.md) (§2.7, §3.4, §3.5)

---

## 3. Strict Boundaries & Forbidden Actions

1. **ZERO `unsafe` Code (`INV-010`)**: Both `rsv-daemon` and `rsv-desktop` MUST declare `#![forbid(unsafe_code)]`. All raw OS memory-locking and enclave syscalls MUST flow strictly through `rsv-mem` and `rsv-enclave`.
2. **Hard `768 KiB` Native Messaging Cap (`INV-021`)**: Every frame emitted by `rsv-nm-host` on `stdout` MUST have 4-byte little-endian length prefix $L \le 786{,}432$ bytes (`768 KiB`, strictly below Chrome's `1,048,576`-byte crash limit). Reassembly MUST cap total logical message size at `16 MiB` and concurrent in-flight streams at `8`.
3. **Peer Authentication BEFORE Parsing (`INV-014`)**: `rsv-daemon` MUST validate `SO_PEERCRED` (Unix UID + PID executable path) or Windows Named Pipe client SID + `GetNamedPipeClientProcessId` + owner-only SDDL DACL BEFORE reading a single RPC payload byte from the pipe/socket.
4. **NEVER Persist Plaintext Secrets to Disk (`INV-001`, `INV-011`)**: Local offline cache MUST store ONLY authenticated ciphertext envelopes (`CS-01`/`CS-02`) sealed with AAD. Unlocked keys (`MUK`, `USK`, `TK`, `CK`, `DEK`) MUST live exclusively inside `rsv_mem::LockedSecretBox` inside `rsv-daemon`, zeroized immediately on idle auto-lock or explicit lock.
5. **No Secret Telemetry or Unredacted Clipboard Persistence (`INV-012`)**:
   - Call `rsv_mem::harden_process()` and `rsv_mem::install_scrubbing_panic_hook()` on `main()` entry of BOTH `rsv-daemon` and `rsv-desktop`.
   - Clipboard copy operations MUST set platform concealed-secret hints (`org.nspasteboard.ConcealedType` on macOS, `ExcludeClipboardContentFromMonitorProcessing` on Windows) and auto-clear after configurable TTL (default `30s`) if the clipboard hash still matches.
6. **NO Electron, WebView, or Server DB Crates**: NEVER depend on `sqlx`, `axum`, `rsv-server`, `rsv-wasm`, `tauri`, or `wry`.
7. **Enforce `root_quorum_only` in Desktop Sharing UI (`INV-005`)**: `rsv-desktop` MUST refuse to generate or upload `DRPubK` or admin escrow wrappers for `EscrowTier::RootQuorumOnly` collections.

---

## 4. Ordered Implementation Checklist

### Part A — `crates/rsv-daemon/`
1. **Process Startup Hardening**: Call `rsv_mem::harden_process()` and `rsv_mem::install_scrubbing_panic_hook()`; initialize `HardwareKeyProvider` via `rsv-enclave::detect_best_provider()` surfacing exact `HardwareTrustTier` (`INV-013`).
2. **Locked Vault Session Manager**:
   - Hold unlocked `MUK`, `USK`, `UIK`, and cached `TK`/`CK` keys strictly inside `rsv_mem::LockedSecretBox` entries.
   - Implement configurable idle auto-lock timer + OS sleep/screen-lock listener dropping and zeroizing all locked secret boxes immediately.
3. **Peer-Authenticated OS IPC Server (`INV-014`)**:
   - **Linux/macOS**: Create `0700` user runtime socket directory and `0600` Unix Domain Socket; authenticate every connection via `SO_PEERCRED` (`uid == current_uid`) + allowed peer binary check (`rsv-desktop`, `rsv-nm-host`).
   - **Windows**: Create Named Pipe with owner-only SDDL DACL (`D:(A;;GA;;;OW)`); validate client SID and `GetNamedPipeClientProcessId` prior to reading RPC bytes.
   - Write `crates/rsv-daemon/tests/ipc_peercred.rs` proving unauthorized peer rejection.
4. **TLS 1.3 `/api/v1` API Client (`INV-020`)**:
   - Configure `reqwest` with `rustls` TLS 1.3 (`X25519MLKEM768` where enabled by runtime).
   - Sign every outgoing request using `HardwareKeyProvider::sign_with_hdik` into `X-RSV-Request-Signature`, generate single-use UUIDv7 `Idempotency-Key`, and seal client-side `X-RSV-Audit-Envelope` to `CPubK` via `rsv-audit` (`INV-019`).
5. **Chrome Native Messaging Proxy (`rsv-nm-host` binary) (`INV-021`)**:
   - Implement `NativeMessagingFramer` matching `schemas/ipc-native-messaging.schema.json` and `agents/CRATE-CONTRACTS.md` §3.8: 4-byte LE header, automatic chunking at `<= 786,432` B, bounded reassembly (`16 MiB` / `8` streams), and strict origin verification via `rsv_types::OriginPolicy` before forwarding autofill requests (`INV-023`).
   - Generate and pass `test-vectors/v1/nm_host_chunk_framing.kat.json` (`0 B`, `768 KiB`, `768 KiB + 1 B`, `3.2 MiB`, oversize rejection, truncated EOF) + `prop_nm_chunk_roundtrip`.

### Part B — `crates/rsv-desktop/` (GPUI Enterprise Desktop UI)
6. **GPUI Application Shell (`ADR-0003`)**:
   - Build native GPU-accelerated GPUI workspace communicating exclusively with `rsv-daemon` over authenticated IPC.
   - Implement Unlock Screen (Passphrase + optional WebAuthn PRF / Touch ID / Windows Hello hardware prompt showing `HardwareTrustTier` badge).
7. **Vault Navigation, Blind RBAC & Item Editor**:
   - Collections list displaying `Standard` vs `Root Quorum Only` badges (`INV-005`), search across decrypted in-memory index (cleared on lock), masked secret fields with explicit reveal + TTL auto-clearing clipboard copy.
   - Team/Collection sharing & revocation UI triggering `rsv-graph::plan_revocation_rotation` (`key_epoch + 1`, `INV-009`).
8. **VSS Trustee Ceremony & Audit Alert Views**:
   - Interactive `t`-of-`n` Feldman VSS share verification view (`rsv-vss::verify_share`, `INV-015`).
   - Blocking critical security alert banner if `rsv-daemon` detects an audit witness split-view (`AUDIT_COMMITMENT_INVALID`, `INV-018`).

---

## 5. Exact Verification Commands & Exit Criteria

ALL commands below MUST exit with code `0` before opening your PR:

```bash
# 1. Formatting, strict clippy & unsafe firewall check
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 clippy -p rsv-daemon -p rsv-desktop --all-targets -- -D warnings
grep -q '#!\[forbid(unsafe_code)\]' crates/rsv-daemon/src/lib.rs
grep -q '#!\[forbid(unsafe_code)\]' crates/rsv-desktop/src/main.rs

# 2. Dependency firewall (no server DB, WASM, or Electron/WebView crates)
! cargo tree -p rsv-daemon -p rsv-desktop | grep -E 'sqlx|axum|rsv-server|rsv-wasm|wry|tauri'

# 3. Native Messaging sub-1MiB KATs & property tests (INV-021)
cargo +1.94.0 test -p rsv-daemon --test '*nm*' -- --nocapture
PROPTEST_CASES=2048 cargo +1.94.0 test -p rsv-daemon prop_nm_chunk_roundtrip

# 4. OS IPC peer-credential negative test (INV-014)
cargo +1.94.0 test -p rsv-daemon --test ipc_peercred -- --nocapture

# 5. Desktop unit/view-model tests & release binary compile check
cargo +1.94.0 test -p rsv-desktop
cargo +1.94.0 build -p rsv-daemon --bins

# 6. Supply chain & license compliance
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

---

## 6. Handoff & PR Contract

- **Branch Naming**: `feat/m4a-agent05-daemon-gpui`
- **PR Description MUST Include**:
  - Explicit Invariant Tags Verified: `[INV-001] [INV-005] [INV-010] [INV-011] [INV-012] [INV-013] [INV-014] [INV-020] [INV-021] [INV-023]`
  - Confirmation log of `nm_host_chunk_framing.kat.json` asserting `max(wire_frame_payload) <= 786,432` across payloads up to `3.2 MiB`.
  - Confirmation log of `ipc_peercred` rejecting unauthorized local peers before RPC deserialization.
  - Confirmation of `rsv-desktop` GPUI build and auto-lock zeroization test.
- **Downstream Unblock Signal**: Merging `M4-A` (with `M4-B` and `M5`) unblocks Agent 07 (`M6` Red-Team Chaos & E2E verification).
