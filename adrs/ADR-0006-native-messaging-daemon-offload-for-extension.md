# ADR-0006: Chrome Extension MV3 Cryptographic Offload to `rsv-daemon` via Chunked, HPKE-Encrypted Native Messaging

| Field | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0006` |
| **Project** | RusticStack Core (`ZK-Vault` — `https://github.com/KelpHect/ZK-Vault`) |
| **Status** | Accepted |
| **Date** | `2026-11-19` |
| **Target Toolchain** | Rust 2024 Edition, MSRV `1.94.0` |
| **Related Specs** | `specs/07-OMNI-CLIENT-ARCHITECTURE.md`, `adrs/ADR-0003-gpui-native-desktop-over-electron.md`, `schemas/ipc-native-messaging.schema.json` |

---

## 1. Context and Problem Statement

Browser extensions for password managers operate in one of the most adversarial execution environments in consumer and enterprise computing. Under Chrome **Manifest V3 (MV3)**:

1. **Ephemeral Service Workers Destroy Safe Key Custody**: MV3 replaces persistent background pages with event-driven Service Workers that Chromium aggressively suspends and terminates after ~30 seconds of inactivity. Persisting unlocked cryptographic keys (`UMK`, `UEK`, `UIK`, `TEK`, `CEK`) across worker restarts forces naive extensions to stash unwrapped keys in `chrome.storage.session` or `chrome.storage.local` — exposing long-term key material inside browser memory, DevTools inspection paths, and disk caches without hardware enclave protection or `mlock`/`VirtualLock`.
2. **No Hardware Enclave or Locked Memory Access**: Browser extensions cannot invoke OS locked memory (`mlock`, `VirtualLock`, `MADV_DONTDUMP`), cannot access macOS Secure Enclave or Windows TPM 2.0 / CNG Platform Crypto Providers directly for seamless biometric unlock, and cannot observe OS sleep/screen-lock signals reliably across all platforms.
3. **High Blast Radius of In-Browser Vault Storage**: If a compromised browser renderer or malicious companion extension exploits an extension flaw while the entire decrypted vault resides in browser RAM, an attacker exfiltrates the entire organizational vault rather than a single active tab's credential.
4. **Hard Native Messaging Platform Constraints**: While Chrome Native Messaging (`chrome.runtime.connectNative`) provides a zero-network `stdin`/`stdout` bridge to a native process (`rsv-nm-host`), Chrome enforces an asymmetric, non-negotiable framing ceiling:
   - Extension -> Native Host maximum message size: **64 MiB** (`67,108,864` bytes).
   - Native Host -> Extension maximum message size: **1 MiB** (`1,048,576` bytes). Any JSON message exceeding `1,048,576` bytes immediately crashes the native port.
   - Furthermore, Native Messaging does NOT authenticate the IPC leg between `rsv-nm-host` and a long-lived background daemon (`rsv-daemon`), nor does it encrypt payloads against a local process inspecting pipes unless end-to-end channel cryptography and OS peer authentication are layered on top.

How should the RusticStack Core Chrome Extension (MV3) execute cryptographic operations, authenticate to `rsv-daemon`, respect Chrome's hard 1 MiB Native Messaging cap, and remain usable on environments where installing a native daemon is impossible (e.g., Chromebooks)?

---

## 2. Decision Drivers

- **Zero Long-Term Keys in Browser Process (Primary Mode)**: Whenever `rsv-daemon` is installed, NO long-term user/org/collection keys (`UMK`, `UEK`, `UIK`, `OEK`, `TEK`, `CEK`) and NO bulk plaintext vault entries may ever enter the Chromium process.
- **Scoped Single-Origin Least Privilege**: On explicit user gesture (`event.isTrusted === true`), the extension MUST receive ONLY the single credential scoped to the verified tab origin (`PSL eTLD+1` + scheme + port).
- **Zero Localhost TCP Surface**: Communication MUST NEVER use `127.0.0.1` / `::1` HTTP or WebSocket ports (eliminating DNS rebinding, CSRF, local port squatting, and cross-user local eavesdropping).
- **Deterministic Compliance With Chrome's 1 MiB Host-to-Extension Limit**: Large responses (match lists, audit proofs, SSH keys/certificates) MUST NEVER terminate the native messaging port.
- **Defense-in-Depth Peer Authentication & Channel Encryption**: Both OS-level process provenance checks AND cryptographic channel authentication (ephemeral X25519 + SAS pairing + OS manifest `allowed_origins` pinning) MUST protect the extension-to-daemon link.
- **Chromebook / Restricted Workstation Continuity**: Users unable to install native binaries MUST still have a policy-gated, isolated fallback path.

---

## 3. Considered Options

1. **Option 1 (Chosen): Primary Native Messaging Offload to `rsv-daemon` via `rsv-nm-host` (Chunked `786432B` Frames + OS Peer Auth + HPKE X25519 + SAS Pairing) with Policy-Gated MV3 Offscreen `rsv-wasm` Fallback**
2. **Option 2: Pure In-Browser MV3 Extension Using `rsv-wasm` Only (No Native Daemon Offload)**
3. **Option 3: Localhost HTTP / WebSocket Server Bound on `127.0.0.1` in `rsv-daemon`**
4. **Option 4: Unchunked Plaintext Chrome Native Messaging Directly to `rsv-daemon` Without HPKE/SAS**

---

## 4. Decision Outcome

**Chosen Option: Option 1 — Primary Cryptographic Offload to `rsv-daemon` over Chunked, HPKE-Encrypted Native Messaging (`rsv-nm-host`), with an Isolated MV3 Offscreen Dedicated Worker `rsv-wasm` Fallback.**

### 4.1 Normative Architecture

1. **Thin Relay (`rsv-nm-host`) + Locked Custody (`rsv-daemon`)**:
   - Chrome launches `rsv-nm-host` via OS-registered, root/Administrator-protected Native Messaging manifest (`com.rusticstack.vault.json`) pinning the exact canonical Chrome Extension ID in `allowed_origins` (no wildcards).
   - `rsv-nm-host` holds **zero keys** and immediately connects to `rsv-daemon` over authenticated local OS IPC:
     - **Linux**: Unix Domain Socket (`0600` in `$XDG_RUNTIME_DIR/rusticstack/daemon.sock`) with `SO_PEERCRED` (`uid == daemon_euid`) + `/proc/<pid>/exe` canonical binary path check.
     - **macOS**: Unix Domain Socket (`0600`) with `LOCAL_PEERCRED` + `LOCAL_PEERTOKEN` (`audit_token_t` verified via `SecCodeCopyGuestWithAttributes` code-signing requirement).
     - **Windows**: Named Pipe (`\\.\pipe\rusticstack-daemon-<SID-HASH>`) created with `PIPE_REJECT_REMOTE_CLIENTS` and strict single-user SID DACL built via `ConvertStringSecurityDescriptorToSecurityDescriptorW` + `GetNamedPipeClientProcessId` + `QueryFullProcessImageNameW` + `WinVerifyTrust` Authenticode check.
2. **Deterministic Chunked Frame Enveloping (`schemas/ipc-native-messaging.schema.json`)**:
   - Every Native Messaging stdio payload (32-bit native-endian length prefix + UTF-8 JSON) MUST be a `ChunkEnvelope` containing `frame_id` (UUIDv7), `chunk_index`, `total_chunks`, and `payload_chunk` strictly capped at **`max_chunk_bytes = 786432` (768 KiB)**.
   - Including envelope JSON metadata overhead (< 512 bytes), every host-to-extension frame is deterministically `<= 787,456` bytes — providing `> 260 KiB` guaranteed safety margin below Chrome's hard `1,048,576`-byte (1 MiB) termination limit.
3. **End-to-End Ephemeral X25519 HPKE / Noise Channel + Interactive SAS Pairing**:
   - Even if `rsv-nm-host` stdio pipes were inspected, all logical IPC commands (`UnlockStatus`, `GetMatchesForOrigin`, `GetCredentialForOrigin`, `SignAuditRequest`, `LockVault`) are encrypted end-to-end between the Extension Service Worker and `rsv-daemon` using ephemeral X25519 key agreement (`DHKEM(X25519, HKDF-SHA256)` / Noise-style transcript binding) + `ChaCha20-Poly1305` with monotonic per-direction nonces.
   - First-time pairing requires the user to visually verify a **6-digit + 4-word SAS (Short Authentication String)** displayed identically in the Extension Popup and an OS-native `rsv-desktop` modal before `rsv-daemon` pins the Extension's long-term identity public key.
4. **Scoped Single-Origin Release**:
   - `rsv-daemon` never sends bulk vault dumps to the extension. Upon explicit user gesture (`isTrusted === true`), the extension requests `GetCredentialForOrigin` for the verified tab origin (`PSL eTLD+1` + scheme + port) and receives ONLY that single credential.
5. **Policy-Gated Standalone `rsv-wasm` Fallback (Chromebooks / Restricted Endpoints)**:
   - When `rsv-nm-host` is unavailable AND `tenant/manifest.allow_standalone_extension_wasm == true`, the extension falls back to executing `rsv-wasm` inside an MV3 **Offscreen Document + Dedicated Web Worker** with a bounded memory arena, strict idle auto-lock (`chrome.idle`), and zero plaintext persistence in `chrome.storage.*`.

---

## 5. Consequences

### 5.1 Positive Consequences

- **Hardware-Backed Browser Autofill**: Users unlock once via Touch ID / Windows Hello / TPM 2.0 / FIDO2 in `rsv-daemon`, seamlessly authorizing both `rsv-desktop` and Chrome autofill without keeping long-term keys in Chrome's JS heap.
- **Minimal Browser Compromise Blast Radius**: Even total compromise of the extension Service Worker yields zero master keys and zero bulk vault decryption capability — an attacker cannot bypass OS-enforced lock state or harvest credentials outside actively permitted queries.
- **Unified Instant Lock**: OS sleep, screen lock, or locking `rsv-desktop` immediately wipes `rsv-mem` in `rsv-daemon`, revoking Chrome Extension capability in `< 50 ms`.
- **Zero Chrome Port Crashes**: Deterministic `786432`-byte chunking eliminates intermittent 1 MiB Native Messaging truncation crashes across arbitrarily large items, certificates, and audit proofs.
- **No Network Exposure**: Completely eliminates local TCP listener vulnerabilities (`127.0.0.1` CSRF, DNS rebinding, unprivileged local port hijacking).

### 5.2 Negative Consequences & Mitigations

| Risk / Trade-off | Impact | Normative Mitigation |
| :--- | :--- | :--- |
| **Native Manifest Installation Complexity** | Installing `com.rusticstack.vault.json` differs across macOS (`/Library/Google/Chrome/NativeMessagingHosts/`), Linux (`/etc/opt/chrome/native-messaging-hosts/` + Chromium/Brave paths), and Windows (Registry `HKLM`/`HKCU\Software\Google\Chrome\NativeMessagingHosts\`). | Bundle automated, signed manifest registration in the `rsv-desktop` installer (`.pkg`, `.msi`, `.deb`/`.rpm`) plus a self-healing `rsv-daemon register-browser` CLI command covering Chrome, Chromium, Brave, Edge, and Arc. |
| **First-Time SAS Pairing Friction** | Users must complete a one-time 5-second SAS approval between browser and desktop app. | Required ONLY once per browser profile; subsequent reconnects authenticate silently via pinned Extension public key + fresh ephemeral X25519 PFS handshake. |
| **ChromeOS / Locked-Down Managed Endpoints** | ChromeOS does not support native Linux binaries for Chrome Native Messaging without Crostini workarounds. | Cleanly degrades to **Mode B (Standalone `rsv-wasm` Offscreen Worker)** when allowed by tenant policy, sharing the exact same `rsv-crypto` / `rsv-graph` / `rsv-audit` Rust core. |
| **Chunking Complexity & Memory Abuse** | Malicious frames could send incomplete chunks (`total_chunks = 64`) indefinitely to exhaust RAM. | Enforce strict schema limits (`1 <= total_chunks <= 64`, `max_chunk_bytes = 786432`), cap max concurrent in-flight `frame_id` buffers per connection (`<= 4`), and purge incomplete frames after `10 seconds`. |

---

## 6. Pros and Cons of Considered Alternatives

### 6.1 Option 2: Pure In-Browser MV3 Extension (`rsv-wasm` Only)
- **Pros**: Zero native installer friction; single Chrome Web Store install works everywhere.
- **Cons**: Cannot bind keys to macOS Secure Enclave / Windows TPM 2.0 / `rsv-mem` locked physical RAM; vulnerable to MV3 Service Worker suspension lifecycles; holds entire unwrapped vault key graph inside browser memory; cannot share biometric unlock state with `rsv-desktop`. **Rejected as primary mode; retained strictly as Mode B fallback.**

### 6.2 Option 3: Localhost HTTP / WebSocket Server (`127.0.0.1`)
- **Pros**: No Native Messaging manifest registration or 1 MiB message ceiling; easy browser `fetch()`/`WebSocket` integration.
- **Cons**: Historically a recurring source of high-severity password manager CVEs (DNS rebinding, malicious local websites probing localhost ports, cross-user local connections on shared machines, browser Mixed Content / Private Network Access CORS friction). Violates zero-network local IPC defense-in-depth. **Rejected.**

### 6.3 Option 4: Unchunked Plaintext Native Messaging Directly Without HPKE/SAS
- **Pros**: Simpler implementation without chunk reassembly or X25519 handshake.
- **Cons**: Crashes catastrophically whenever any response (e.g., large vault match payload, SSH cert, or C2SP audit bundle) exceeds Chrome's 1 MiB Host -> Extension cap; fails to protect secrets if an unauthorized Chromium fork or compromised `rsv-nm-host` wrapper spoofs the manifest without user-verified SAS pairing. **Rejected.**

---

## 7. Verification Criteria

This decision is verified complete when:
1. All Native Messaging wire payloads validate cleanly against `schemas/ipc-native-messaging.schema.json` (JSON Schema Draft 2020-12).
2. Fuzzing `rsv-nm-host` with logical responses from `0 B` to `48 MiB` asserts every emitted stdout frame length prefix is `<= 851,968` bytes (`< 1,048,576` bytes).
3. Platform integration tests confirm unauthorized local processes (different UID/SID or unsigned binary path) are rejected immediately at `rsv-daemon`'s IPC accept boundary (`SO_PEERCRED` / `LOCAL_PEERTOKEN` / Named Pipe DACL + `GetNamedPipeClientProcessId`).
4. Attempting any vault command prior to interactive SAS pairing approval returns `IPC_PAIRING_REQUIRED` with zero credential release.
