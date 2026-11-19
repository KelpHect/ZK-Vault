# ADR-0003: Native Rust GPUI Desktop Client (`rsv-desktop`) with Trait-Isolated Daemon Architecture Over Electron

| Field | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0003` |
| **Project** | RusticStack Core (`ZK-Vault` — `https://github.com/KelpHect/ZK-Vault`) |
| **Status** | Accepted |
| **Date** | `2026-11-19` |
| **Target Toolchain** | Rust 2024 Edition, MSRV `1.94.0` |
| **Related Specs** | `specs/07-OMNI-CLIENT-ARCHITECTURE.md`, `adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md` |

---

## 1. Context and Problem Statement

RusticStack Core (`ZK-Vault`) requires a flagship cross-platform desktop client for macOS, Windows, and Linux capable of managing post-quantum hybrid cryptographic keys (`ML-KEM-768 + X25519`, `ML-DSA-65 + Ed25519`), binding to hardware roots of trust (`rsv-enclave`: Apple Secure Enclave, Windows TPM 2.0/CNG, Linux TPM 2.0/CTAP2), holding unlocked key material strictly in locked physical memory (`rsv-mem`), and delivering instant (< 16 ms input-to-photon, 120 FPS) search and credential workflows across enterprise vaults containing tens of thousands of items.

Historically, commercial password managers have shipped desktop clients built on **Electron** (embedded Chromium + Node.js + V8) or OS WebView wrappers (**Tauri**). While web-based desktop shells accelerate initial UI prototyping, they introduce fundamental security and engineering hazards for a zero-knowledge vault:

1. **Uncontrollable Garbage-Collected Heap Retention**: V8 and WebView JavaScript engines allocate immutable UTF-16/UTF-8 strings across generational, compacting heaps. Applications cannot `mlock`/`VirtualLock` JavaScript strings or deterministically overwrite (`zeroize`) password or key copies after lock/sleep events; secrets routinely persist in uncollected V8 heap pages, swap files, and DOM layout caches long after a vault is locked.
2. **Massive Attack Surface & Patching Debt**: Bundling Chromium and Node.js introduces > 200 MB of C++ runtime attack surface, frequent zero-day browser CVEs (V8 JIT, Skia, Blink, IPC), and complex native-addon (`node-gyp` / N-API) ABI bridges to Rust crypto crates.
3. **Weak Hardware & Memory Controls**: OS memory protections (`mlock`, `MADV_DONTDUMP`, `prctl(PR_SET_DUMPABLE, 0)`, guard pages) and native OS pasteboard concealment (`org.nspasteboard.ConcealedType`, `ExcludeClipboardContentFromMonitorProcessing`) cannot be applied cleanly to Chromium renderer processes without fighting the browser sandbox architecture.
4. **Performance & Footprint**: Electron vault apps routinely consume 250–600 MB of idle RAM and exhibit noticeable cold-start and search-scroll jank on large organizational vaults.

Conversely, adopting a pure Rust GPU-accelerated UI framework (**GPUI**) in 2026 requires careful architectural engineering because the GPUI ecosystem is actively evolving across Zed Industries' upstream `gpui` repository and community standalone tracks (`gpui-ce`, `gpui-kit`).

How should RusticStack Core architect its native desktop client to achieve hardened memory security, native 120 FPS performance, and long-term immunity against UI toolkit API churn?

---

## 2. Decision Drivers

- **Hardened Key & Secret Custody**: Unlocked keys MUST reside exclusively in `rsv-mem` locked physical RAM (`mlock`/`VirtualLock` + guard pages + core-dump suppression) and MUST be deterministically zeroized within `<= 50 ms` of lock, OS sleep, or screen-lock.
- **UI-to-Crypto Isolation**: Plaintext vault secrets MUST NEVER linger in UI heap structures, DOM trees, or GPU texture/glyph caches beyond an explicit, short-lived user Reveal interaction.
- **Unified Rust Workspace**: Desktop UI, cryptographic daemon, hardware enclave adapters, and CLI tooling MUST build cleanly in a single Rust 2024 workspace (MSRV `1.94.0`) with zero Node.js/npm/C++ native-addon glue.
- **Native 120 FPS Performance & Low Footprint**: Cold launch `< 200 ms`, idle RSS `< 50 MB`, zero-jank GPU-accelerated rendering across macOS (Metal), Windows (DirectX 12 / Win32), and Linux (Vulkan over Wayland/X11).
- **UI Toolkit Longevity (2026 Ecosystem Reality)**: Upstream GPUI API changes MUST NEVER contaminate `rsv-crypto`, `rsv-mem`, `rsv-enclave`, `rsv-graph`, `rsv-audit`, or `rsv-daemon`.
- **Native OS Security Integration**: First-class access to OS pasteboard concealment flags, screen-capture exclusion (`NSWindow.sharingType = .none`, `WDA_EXCLUDEFROMCAPTURE`), and OS idle/sleep/screen-lock notifications.

---

## 3. Considered Options

1. **Option 1 (Chosen): GPUI Native Rust Desktop (`rsv-desktop`) Isolated Behind a `VaultController` Trait Boundary from Locked Cryptographic Daemon (`rsv-daemon`)**
2. **Option 2: Electron (Chromium + Node.js + N-API Rust Addon)**
3. **Option 3: Tauri v2 (System OS WebView + Rust Backend)**
4. **Option 4: Alternative Rust Native UI Toolkits (`iced`, `egui`, or `Slint`)**

---

## 4. Decision Outcome

**Chosen Option: Option 1 — GPUI Native Rust Desktop (`rsv-desktop`) isolated cleanly behind a toolkit-agnostic `VaultController` trait boundary from `rsv-daemon` and `rsv-mem`.**

### 4.1 Normative Architectural Rules

1. **Split Process & Privilege Boundary**:
   - All cryptographic keys, `rsv-mem` locked arenas, `rsv-enclave` hardware handles, sync loops, and OS IPC listeners reside exclusively inside **`rsv-daemon`**.
   - **`rsv-desktop`** holds zero long-term keys, has zero Cargo dependencies on `rsv-crypto`, `rsv-mem`, `rsv-enclave`, or `rsv-vss`, and renders strictly redacted metadata DTOs (`rsv-types`) obtained over authenticated local OS IPC (or an equivalent async trait channel in portable single-binary mode).
2. **GPUI Hexagonal Adapter Isolation**:
   - All `gpui` types (`View`, `Entity`, `Window`, `Render`, `Element`) MUST be strictly confined inside `rsv-desktop`'s UI adapter layer (`rsv-desktop/src/ui_gpui/`).
   - Business presentation state (`DesktopPresenter`, reveal timers, form validation, search state) MUST depend ONLY on `dyn VaultController` and pure Rust types, allowing `rsv-desktop` to track either a pinned upstream Zed `gpui` workspace commit (`--features gpui-upstream`) or standalone community tracks (`gpui-ce` / `gpui-kit`, `--features gpui-ce`) cleanly via Cargo feature adapters without touching any security-critical crate.
3. **GPU & Render-Frame Secret Hygiene**:
   - Secret fields MUST render masked (`••••••••••••`) by default and MUST NOT be fetched from `rsv-daemon` until explicit user Reveal/Copy.
   - Revealed values MUST be wrapped in `Zeroizing<String>` with hard auto-remask timers (`<= 30s`), window-blur wipe, screen-capture exclusion (`NSWindow.sharingType = .none`, `WDA_EXCLUDEFROMCAPTURE`), and glyph-atlas eviction / redraw on lock.
   - Clipboard writes MUST attach native concealment hints (`org.nspasteboard.ConcealedType`, `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`, `x-kde-passwordManagerHint = "secret"`) and auto-clear safely without clobbering subsequent user copies.

---

## 5. Consequences

### 5.1 Positive Consequences

- **Elimination of V8/Chromium Security & Memory Liability**: Zero GC heap secret lingering, zero Chromium 0-day emergency repackaging cycles, zero Node.js supply-chain surface in desktop binaries.
- **Deterministic Memory Safety**: Combined with `rsv-daemon` + `rsv-mem`, unlocked keys remain strictly inside `mlock`/`VirtualLock` physical pages and wipe cleanly in `< 50 ms` on lock, sleep, or screen-lock.
- **Native 120 FPS UX & Tiny Footprint**: Direct Metal, Vulkan, and DirectX 12 rendering achieves sub-frame interaction latency, instant vault search, and `< 50 MB` idle RSS compared to `300+ MB` for Electron.
- **Zero-Glue Hardware & OS Integration**: Native Rust calls directly to macOS AppKit/Security/LocalAuthentication, Windows Win32/CNG/WTS, and Linux D-Bus/Wayland/TPM2 without FFI serialization through JavaScript.
- **Shared Daemon Reuse**: Separating `rsv-daemon` enables the Chrome Extension MV3 (`ADR-0006`) and CLI tooling to share one unlocked hardware-backed cryptographic session transparently.

### 5.2 Negative Consequences & Mitigations

| Risk / Trade-off | Impact | Normative Mitigation |
| :--- | :--- | :--- |
| **GPUI Upstream API Churn (2026)** | Upstream Zed `gpui` does not guarantee long-term SemVer stability on `crates.io`. | Pin exact Git commit hash in root `Cargo.lock`; isolate ALL GPUI calls inside `rsv-desktop/src/ui_gpui/`; support swapping to `gpui-ce` / `gpui-kit` behind the `VaultController` trait with zero changes to `rsv-daemon` or core crates. |
| **Accessibility & IME Maturity** | GPU-rendered UI toolkits require explicit integration with OS accessibility trees (VoiceOver, UI Automation, AT-SPI) and CJK IMEs. | Track GPUI's native AccessKit / OS accessibility bridge in `ui_gpui`; explicitly mark password/secret fields as `Role::PasswordInput` / inaccessible to third-party screen scrapers when masked; maintain Web SPA (`SPEC-07 §6`) as full WCAG 2.2 AA fallback. |
| **GPU Driver / Headless Linux Edge Cases** | Older Linux VMs or headless environments may lack hardware Vulkan drivers. | Provide Vulkan software rasterizer fallback (`llvmpipe` / Lavapipe) with graceful diagnostic message, while keeping `rsv-daemon` completely GPU-independent so CLI and Chrome Extension continue operating uninterrupted. |
| **Separate Web SPA UI Codebase** | Desktop GPUI components cannot be directly shared as HTML/CSS with the Zero-Install Web App SPA. | Share 100% of cryptographic, graph, audit, VSS, and state-machine logic via `rsv-types`, `rsv-crypto`, `rsv-graph`, `rsv-audit`, `rsv-vss`, and `rsv-wasm`, limiting UI duplication strictly to thin presentation views. |

---

## 6. Pros and Cons of Considered Alternatives

### 6.1 Option 2: Electron (Chromium + Node.js)
- **Pros**: Mature DOM accessibility & IME support; shared React/TypeScript UI code with Web SPA; large developer pool.
- **Cons**: Unacceptable GC heap retention of revealed passwords and DOM snapshots; 200+ MB binary footprint and 300+ MB RAM overhead; continuous Chromium CVE maintenance burden; brittle N-API FFI to Rust memory-locked crypto; poor OS pasteboard and hardware-enclave ergonomics. **Rejected.**

### 6.2 Option 3: Tauri v2 (OS WebView + Rust Backend)
- **Pros**: Much smaller binary than Electron; native Rust backend; shares Web SPA HTML/CSS.
- **Cons**: Still renders secrets inside OS WebView engines (WKWebView / WebView2 / WebKitGTK) with garbage-collected JS heaps, inconsistent WebView engine versions across Linux distros (WebKitGTK rendering/Wayland glitches), unpredictable WebView process memory/cache behavior (disk cache, spellcheck dictionaries, compositor snapshots), and limited control over per-frame GPU glyph flushing. **Rejected for flagship desktop client (Web SPA remains available for zero-install browser access).**

### 6.3 Option 4: Alternative Rust Native Toolkits (`iced`, `egui`, `Slint`)
- **Pros**: Pure Rust; no Chromium/WebView runtime; deterministic memory footprint.
- **Cons**:
  - `egui`: Immediate-mode architecture complicates crisp native text layout, accessibility trees, and complex enterprise split-pane workflows.
  - `iced`: Elm-style message passing is clean, though GPUI provides stronger text-shaping, sub-pixel layout performance, hybrid retained/immediate rendering, and proven production desktop UX at 120 FPS (as demonstrated in Zed).
  - `Slint`: Introduces a proprietary `.slint` DSL and commercial licensing considerations incompatible with RusticStack Core's strict Dual MIT / Apache-2.0 open-source posture.
  - Notably, because `rsv-desktop` enforces the strict `VaultController` trait boundary, if a future platform ever required an alternate Rust renderer, it could be attached cleanly without altering `rsv-daemon`.

---

## 7. Verification Criteria

This decision is considered properly implemented when:
1. `cargo tree -p rsv-desktop` demonstrates **zero** transitive dependency on `rsv-crypto`, `rsv-mem`, `rsv-enclave`, or `rsv-vss`, and **zero** transitive dependency on `gpui` in `rsv-daemon`.
2. Automated memory snapshot tests confirm zero plaintext vault secrets in `rsv-desktop` process RAM while unlocked (without active Reveal) and zero key bytes in `rsv-daemon` within `50 ms` of lock.
3. Cold launch time measures `< 200 ms` and idle memory footprint measures `< 50 MB` RSS across macOS (Metal), Windows (DirectX 12), and Linux (Vulkan).
