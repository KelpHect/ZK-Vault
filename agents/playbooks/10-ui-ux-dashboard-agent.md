# Devin Agent Playbook 10: Client UI/UX Design System, GPUI Desktop Views, MV3 Extension UX, Web SPA & Enterprise Org Admin Dashboard

> **Playbook ID**: `RSV-PLAYBOOK-10`
> **Agent Role**: Principal Frontend Systems, GPUI Native UI, MV3 Extension UX & Enterprise Org Console Engineer
> **Active Milestone**: `M5-C` & `M6` Integration (Executes after `M4` core clients & `M5-B` KT/SCIM/SSH/Passkey/Offline hooks merge cleanly, avoiding concurrent file contention with Agents `05`, `06`, `08`, and `09`)
> **Target Toolchains**: Rust 2024 Edition (MSRV `1.94.0`, `gpui` / `gpui-ce`), TypeScript `5.8+` (`strict`), React `19`, Vite `6`, Tailwind CSS `v4`, Playwright

---

## 1. Mission & Exclusive Ownership

Your mission is to implement the cohesive, Zed/1Password-caliber **"Obsidian & Tungsten"** application experience specified in [`specs/15-CLIENT-UI-UX-AND-ORG-DASHBOARD.md`](../../specs/15-CLIENT-UI-UX-AND-ORG-DASHBOARD.md) across all four user-facing RusticStack Core (`ZK-Vault`) surfaces without weakening a single cryptographic, memory-hygiene, or origin-isolation invariant:

1. **Unified Cross-Client Design System (`packages/design-tokens/`)**: Single source of truth generating Rust GPUI theme tokens (`Obsidian` dark-first + `Alabaster` accessible light, WCAG 2.2 AA `>= 4.5:1`) and Tailwind CSS v4 tokens, self-hosted `Inter` + `JetBrains Mono` (slashed-zero `zero, ss01, tnum`), and the 9 canonical vault item type components.
2. **GPUI Native Desktop UI (`crates/rsv-desktop/src/{presenter,ui_gpui}/`)**: Full `WorkspaceRoot` entity hierarchy, Tokio-to-GPUI `ForegroundExecutor` bridge over `VaultController`, 100,000-item `uniform_list` virtualization at locked **120 FPS (`< 4.0 ms` frame budget)**, keyboard-first Command Palette (`Cmd/Ctrl+K`) + Global OS Quick-Access (`Cmd/Ctrl+Shift+Space`), `AdminModeShell`, and all 5 dedicated security modals (`SshApprovalModal`, `ConflictMergeModal`, `DevicePairingModal`, `VssCeremonyModal`, `SecurityHaltModal`).
3. **MV3 Browser Extension UX & Autofill Engine (`clients/extension/src/{content,popup,offscreen}/`)**: Closed Shadow DOM (`attachShadow({ mode: "closed" })`) inline autofill picker, multi-step login continuity, 5-point hit-test anti-clickjacking & cross-origin iframe guards, high-contrast **Phishing-Mismatch Interstitial**, Synced Passkey picker overlay (integrating with Agent `08`'s `src/passkey/`), CSPRNG password/Diceware generator (delegated strictly to `rsv-daemon`/`rsv-wasm`), and Connection Assurance Badge (`[L3]` / `[L2]` / `[L1]`).
4. **Zero-Install Web Vault SPA (`clients/web-spa/src/`)**: Strict-CSP / `COOP` / `COEP` / SHA-384 SRI React 19 shell, typed Main Thread <-> Dedicated Crypto Web Worker (`rsv-wasm`) RPC contract (`KeyHandle` only, transferable `ArrayBuffer` detachment), zero-plaintext unmount scrubbing, and 100% client-side FIDO CXF/Bitwarden/1PUX/KDBX4 Import/Export + local SLIP-0039/Bech32m Emergency Kit PDF wizards.
5. **Thick-Client Enterprise Org Admin Dashboard (Web SPA `/admin/*` AND GPUI `AdminModeShell`)**: All 6 zero-knowledge 10,000-seat governance views — (1) Blind RBAC DAG & Bulk Provisioning Workbench with real-time cycle check & `INV-025` KT verification, (2) Blind SCIM 2.0 Pending Lifecycle Queue, (3) Atomic Epoch Rotation & Blast-Radius Console, (4) Quorum Recovery & Feldman VSS Governance + Non-Reconstructive Shard Health Check, (5) Zero-Knowledge Audit Ledger & Compliance Workbench (Blinded Ops + Air-Gapped `rsv-compliance-cli` / Local HSM `CPK` Forensic Mode), and (6) Enterprise Policy, `CS-02` X-Wing Agility Histogram & OIDC Machine Identities.

### Exclusive Write Ownership
- `packages/design-tokens/` (shared tokens, theme generators, bundled WOFF2/TTF fonts, WCAG contrast verifier)
- `crates/rsv-desktop/src/presenter/` (toolkit-agnostic view state, reveal deadline timers, conflict diff presenter, keyboard action router)
- `crates/rsv-desktop/src/ui_gpui/` (all GPUI views, `uniform_list` virtualization, modals, `AdminModeShell`, theme adapter — integrating cleanly with `approval_sheet.rs` trait hooks authored by Agent `08`)
- `clients/extension/src/content/` (Isolated World DOM scanner, occlusion/hit-test guard, Closed Shadow DOM picker & Phishing-Mismatch Interstitial)
- `clients/extension/src/popup/` (Toolbar popup views, CSPRNG generator UI, SAS pairing prompt, Assurance Badge)
- `clients/extension/src/offscreen/` (Mode B fallback UI/lifecycle coordinator communicating with `rsv-wasm` Worker)
- `clients/web-spa/src/` (React 19 UI shell, `worker/protocol.ts` typed RPC client, Vault Workspace, CXF/Import/Emergency Kit wizards, all 6 Org Admin Dashboard views)
- `tests/ui-security/` (Playwright hostile-page autofill suite, zero-leak DOM/storage/clipboard negative tests, Org Admin adversarial KT/cycle/split-view E2E tests, WCAG 2.2 AA `axe-core` audit, GPUI headless 100k-row benchmarks)

### Strictly Forbidden Write Paths (Owned by Other Agents)
- NEVER modify `crates/rsv-crypto/`, `crates/rsv-vss/`, `crates/rsv-graph/`, `crates/rsv-audit/`, `crates/rsv-mem/`, `crates/rsv-enclave/`, `crates/rsv-server/`, `crates/rsv-compliance-cli/`, `crates/rsv-cli/`, or `migrations/`.
- If a missing `VaultController` or `rsv-wasm` RPC method is required, STOP and open a Contract Amendment PR against `agents/CRATE-CONTRACTS.md` rather than bypassing the trait boundary.

### Owned & Enforced Formal Invariants
- **Primary Ownership**: **`INV-033`**, **`INV-034`**, **`INV-035`**, **`INV-036`**
- **Strict Upstream Compliance**: `INV-001`, `INV-005`, `INV-010`, `INV-011`, `INV-012`, `INV-021`, `INV-022`, `INV-023`, `INV-024`, `INV-025`, `INV-030`, `INV-031`, `INV-032`

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context before writing code:
1. [`AGENTS.md`](../../AGENTS.md) (All 11 Hard Non-Negotiable Guardrails)
2. [`specs/15-CLIENT-UI-UX-AND-ORG-DASHBOARD.md`](../../specs/15-CLIENT-UI-UX-AND-ORG-DASHBOARD.md) (**Primary Normative Blueprint**)
3. [`specs/07-OMNI-CLIENT-ARCHITECTURE.md`](../../specs/07-OMNI-CLIENT-ARCHITECTURE.md) (GPUI hexagonal isolation, OS clipboard/screen-capture/idle, MV3 Native Messaging, Web SPA CSP/PRF)
4. [`specs/04-BLIND-RBAC-ACCESS-GRAPH.md`](../../specs/04-BLIND-RBAC-ACCESS-GRAPH.md) (Blind RBAC DAG, `MAX_GRAPH_DEPTH = 4`, lazy vs eager rotations, WASM Org Dashboard)
5. [`specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md`](../../specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md) (Blinded IDs, `CPubK` envelopes, RFC 9162 tiles, external witnesses)
6. [`specs/08-API-AND-WIRE-PROTOCOLS.md`](../../specs/08-API-AND-WIRE-PROTOCOLS.md) (32 endpoints, WebSocket events, 12 canonical error codes)
7. [`specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md`](../../specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md) (KT `VerifiedKtRecipient`, Blind SCIM 2.0 `/api/v1/scim/intents`, QR/SAS enrollment)
8. [`specs/12-DEVELOPER-SECRETS-SSH-PASSKEYS-AND-CLI.md`](../../specs/12-DEVELOPER-SECRETS-SSH-PASSKEYS-AND-CLI.md) (SSH Agent approval sheet, `passkey_v1`, OIDC Machine Identities)
9. [`specs/13-STREAMING-ATTACHMENTS-OFFLINE-SYNC-AND-MIGRATION.md`](../../specs/13-STREAMING-ATTACHMENTS-OFFLINE-SYNC-AND-MIGRATION.md) (STREAM 64 KiB attachments, `ConflictPair` 3-way merge, FIDO CXF v1.0, SLIP-0039/Bech32m Emergency Kit)
10. [`adrs/ADR-0003-gpui-native-desktop-over-electron.md`](../../adrs/ADR-0003-gpui-native-desktop-over-electron.md) & [`adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md`](../../adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md)
11. [`schemas/ipc-native-messaging.schema.json`](../../schemas/ipc-native-messaging.schema.json) & [`schemas/openapi-v1.yaml`](../../schemas/openapi-v1.yaml)

---

## 3. Strictly Forbidden Actions (STOP-THE-LINE RULES)

Violating ANY rule below immediately fails the PR and triggers automatic CI rejection:

1. **NEVER Use `Math.random()` for Passwords, Passphrases, Nonces, or IDs**: Every generated secret MUST originate from `rsv-daemon` (`OsRng`) or `rsv-wasm` (`getrandom` -> `crypto.getRandomValues`). ESLint `no-restricted-properties` MUST hard-ban `Math.random` across `clients/extension` and `clients/web-spa`.
2. **NEVER Persist or Leak Plaintext Secrets in UI State (`INV-033`)**:
   - NEVER write revealed secrets into DOM `data-*` attributes, ARIA plain-value attributes when masked, URL params, `localStorage`, `sessionStorage`, `IndexedDB` plaintext tables, `chrome.storage.*`, Redux/Zustand/React Context global stores, or GPUI disk caches.
   - ALWAYS render masked fields as fixed 12-bullet `••••••••••••` independent of true secret length, enforce `15 s` auto-remask (cap `30 s`), and wipe immediately on unmount, blur, navigation, or lock (`<= 50 ms`).
3. **NEVER Write Unconcealed Secrets to the OS Clipboard (`INV-034`)**: Native desktop and Mode A extension copies MUST route through `rsv-daemon` setting macOS `org.nspasteboard.ConcealedType` + `TransientType` + `AutoGeneratedType`, Windows `ExcludeClipboardContentFromMonitorProcessing` + `CanIncludeInClipboardHistory = 0` + `CanUploadClipboardDataToCloud = 0`, and Wayland/X11 `x-kde-passwordManagerHint = "secret"` (never X11 `PRIMARY`), with 30s Non-Clobber auto-clear.
4. **NEVER Auto-Fill on Page Load or Focus (`INV-035`)**: The MV3 extension MUST refuse autofill without `event.isTrusted === true`, authoritative Service Worker origin match (`https:`, exact port, PSL `eTLD+1`, shared hosting full-host check, UTS #46 Punycode), same-origin frame check (or dual-origin popup consent), and 5-point `elementsFromPoint` hit-test + computed CSS visibility check (`opacity >= 0.85`, `>= 24x16 px`). All inline UI MUST use `attachShadow({ mode: "closed" })`.
5. **NEVER Touch Raw Keys in `rsv-desktop` or React Main Thread (`INV-022`, `ADR-0003`)**:
   - `rsv-desktop/Cargo.toml` MUST declare `#![forbid(unsafe_code)]` (`INV-010`) and MUST have ZERO transitive dependency on `rsv-crypto`, `rsv-mem`, `rsv-enclave`, or `rsv-vss`.
   - Web SPA React main thread MUST NEVER receive `MUK`, `USK`, `UIK`, `TK`, `CK`, `DEK`, `ORPK`, or `CPK` bytes—ONLY opaque `KeyHandle` tokens and ephemeral reveal strings. Transferable `ArrayBuffer`s (PRF / passphrase) MUST detach to `byteLength === 0` immediately upon `postMessage`.
6. **NEVER Skip Key Transparency Verification on Org Admin Provisioning (`INV-036`, `INV-025`)**: Every Org Admin edge grant, SCIM pending intent approval, and VSS custodian share wrap MUST verify recipient `upk_uik_signature` + KT Inclusion Proof (`VerifiedKtRecipient`) against the witnessed C2SP checkpoint BEFORE sealing keys. Any KT failure MUST halt the batch immediately.
7. **NEVER Allow `DRPK` Controls on `enterprise_escrow` (`root_quorum_only`) or `strict_zk` Collections (`INV-005`)**: Delegated Recovery UI actions MUST be structurally disabled with a policy lock badge whenever `escrow_tier !== 'standard'`.
8. **NEVER Silently Overwrite Offline Conflicts (`INV-031`)**: `409 VERSION_CONFLICT` MUST launch `ConflictMergeModal` showing Base / Local / Remote side-by-side masked diffs and persisting `merge_parent_digests`.
9. **NEVER Introduce External CDNs, Fonts, Favicons, or `dangerouslySetInnerHTML`**: Zero runtime requests outside `'self'` and configured `https://<api-host>` / `wss://<api-host>`. Secure Notes MUST render via a pure static Markdown AST renderer with zero raw HTML execution.
10. **NEVER Buffer Full Attachments in UI/WASM RAM (`INV-030`, `INV-024`)**: Attachment upload/download UI MUST stream 64 KiB chunks via `StreamEncryptHandle` / `StreamDecryptHandle` with zero `memory.grow` in `rsv_wasm_bg.wasm`.
11. **NEVER Make Witness Split-View Alerts Dismissible (`INV-018`)**: Detecting a C2SP checkpoint fork or `AUDIT_COMMITMENT_INVALID` tampering MUST immediately zeroize keys and present the non-dismissible **Hard Security Halt** screen.
12. **NEVER Include AI Attribution in Git Commits**.

---

## 4. Ordered Implementation Checklist

### Workstream A — Shared "Obsidian & Tungsten" Design System (`packages/design-tokens/`)
1. Author canonical `packages/design-tokens/tokens.json` containing exact `Obsidian` (dark default) and `Alabaster` (light) semantic tokens from `SPEC-15 §2.1`, typography scales (`Inter` + `JetBrains Mono` with `zero, ss01, tnum`), 4px spacing grid, fixed row heights (`56px` / `44px`), and `prefers-reduced-motion` rules.
2. Build deterministic token codegen producing:
   - `crates/rsv-desktop/src/ui_gpui/theme_tokens.rs` (`gpui::Hsla` constants)
   - `clients/web-spa/src/styles/tokens.css` & `clients/extension/src/styles/tokens.css` (Tailwind v4 `@theme` custom properties)
   - Automated WCAG 2.2 AA contrast unit test verifying every foreground/background pair meets `>= 4.5:1` (text) and `>= 3.0:1` (controls).
3. Bundle self-hosted WOFF2/TTF subsets of `Inter` and `JetBrains Mono` locally (zero CDN links) and verify `0`/`O` and `1`/`l`/`I` glyph distinction in visual snapshots.
4. Implement the 9 canonical Vault Item Type renderers and editors (`login`, `passkey`, `ssh_key`, `api_credential`, `secure_note`, `payment_card`, `identity`, `recovery_seed`, `encrypted_attachment`) obeying `SPEC-15 §2.3` and `INV-033`.

### Workstream B — GPUI Native Desktop (`crates/rsv-desktop/src/{presenter,ui_gpui}/`)
5. **Toolkit-Agnostic Presenter Layer (`src/presenter/`)**:
   - Implement `DesktopPresenter` communicating strictly with `Arc<dyn VaultController>` over a bounded `async_channel` bridged from the 2-thread Tokio IPC runtime into GPUI `ForegroundExecutor`.
   - Implement `RevealTimerRegistry` wrapping ephemeral revealed text strictly in `Zeroizing<String>` with hard `15 s` TTL (`<= 30 s` max), instant wipe on focus loss / navigation / `Esc` / lock, and clipboard countdown toast state.
6. **Core GPUI Hierarchy & 100k-Item 120 FPS Virtualization (`src/ui_gpui/`)**:
   - Build `WorkspaceRoot`, `TitlebarChrome`, full-window `LockOverlay` (dropping `MainShell` & `AdminModeShell` completely on lock and evoking glyph-atlas eviction), `CollectionSidebar`, `VirtualizedItemList`, `ItemInspectorPane`, `StatusFooter`, `ModalLayer`, and `ToastLayer` (`SPEC-15 §3.2`).
   - Implement `VirtualizedItemList` over GPUI `uniform_list` (`56px` fixed row height) backed by a `256`-row sliding LRU slice cache requesting `fetch_item_slice(query_generation, offset, limit)` from `rsv-daemon`'s locked RAM fuzzy index (`< 4.0 ms` p99 frame paint over `100,000` synthetic items).
   - Wire OS screen-capture exclusion (`NSWindow.sharingType = .none` on macOS, `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` on Windows, opaque solid-fill clear on Linux minimize/lock) plus policy-override amber badge.
7. **Keyboard-First Command Palette & Global Hotkey**:
   - Implement in-app `QuickSwitchPalette` (`Cmd/Ctrl+K`), global OS quick-access popup (`Cmd/Ctrl+Shift+Space`), and full Vim + standard shortcut bindings (`SPEC-15 §3.4`).
8. **Dedicated Native Security Modals**:
   - `SshApprovalModal` (displaying verified PID/parent chain/binary path/code signature/fingerprint/`session-bind` host; disabling 15m caching whenever `is_forwarding == 1` or `agent_policy == "always_prompt"`; 30s auto-deny ring).
   - `ConflictMergeModal` (3-column `Base` / `Local` / `Remote` diff with masked secret diff rows, per-field radio controls, "Keep Both", `merge_parent_digests` commit, and `CONFLICT_ACCESS_REVOKED` handling).
   - `DevicePairingModal` (300s QR + 6-word EFF SAS `"rsv:enroll:sas:v1"` for new devices AND 6-digit + 4-word `"RSV-IPC-SAS-v1"` for browser extension pairing).
   - `VssCeremonyModal` (Non-Reconstructive Feldman Ristretto255 Shard Health Check + live `t`-of-`n` quorum progress gauge).
   - `SecurityHaltModal` (non-dismissible full-screen halt on Witness Split-View / `TENANT_MISMATCH` / root manifest tamper) + live radial 30s TOTP ring & Passkey inspector card.

### Workstream C — MV3 Browser Extension UI & Autofill Security (`clients/extension/src/`)
9. **Closed Shadow DOM Inline Autofill & Occlusion Guard (`src/content/`)**:
   - Implement Isolated World form/multi-step field detector (tracking transient step-1 `selected_item_id` per `(tabId, frameId, origin)` with 120s TTL — zero cached password bytes).
   - Enforce synchronous pre-mount AND pre-inject visibility + 5-point `document.elementsFromPoint(x, y)` hit-test guard (`opacity >= 0.85`, `width >= 24 && height >= 16`, `>= 80%` unclipped viewport area, reject `type="hidden"` / `aria-hidden="true"`).
   - Mount inline autofill icon, dropdown picker, TOTP `"2FA code copied"` pill, and **Phishing-Mismatch Interstitial** exclusively inside `attachShadow({ mode: "closed" })` with `all: initial` CSS reset and `event.stopImmediatePropagation()`.
   - Inject credentials using `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, secret)` + synthetic `input`/`change` events without secret data on `CustomEvent.detail`, immediately discarding string references.
10. **Synced Passkey Picker Overlay (`src/content/` <-> Agent `08`'s `src/passkey/`)**:
    - Render Closed Shadow DOM passkey chooser distinguishing `Personal Passkey` vs `Shared Team Passkey` with `L3 Hardware-Verified` badge and always-visible **`Use Security Key / OS Passkey Instead`** fallback; ensure unconditional bypass on RusticStack's own Web SPA origin.
11. **Toolbar Popup & CSPRNG Generator (`src/popup/`)**:
    - Build `360px × 540px` keyboard-navigable popup with Connection Mode & Assurance Header (`Daemon Hardware-Locked [L3]`, `Daemon Software-Locked [L2]`, `Standalone WASM [L1]`, `Pairing Required`, `Vault Locked`), Tab-Matched Quick Search, CSPRNG Password & EFF Diceware Passphrase Generator (calling `rsv-daemon` or `rsv-wasm` strictly — zero `Math.random()`), and Quick Lock.
12. **Cross-Browser Parity**: Ensure manifests and Native Messaging adapters pass build/lint checks for Chromium MV3 (`allowed_origins`), Firefox MV3 (`allowed_extensions`, `browser.*` APIs), and Safari Web Extension XPC framing compatibility (`SPEC-15 §4.5`).

### Workstream D — Zero-Install Web Vault SPA (`clients/web-spa/src/`)
13. **Strict-CSP Shell & Dedicated Crypto Worker Bridge (`src/worker/`)**:
    - Implement `crypto.worker.ts` enforcing SHA-384 SRI verification of `rsv_wasm_bg.wasm` before instantiation (`64 MiB` fixed linear memory arena, zero `memory.grow`), typed `WorkerRequest`/`WorkerResponse` protocol (`SPEC-15 §5.2`), and transferable `ArrayBuffer` detachment (`prfBuf.byteLength === 0` on main thread).
    - Implement `<EphemeralSecretField />` with `15 s` countdown bar, color-coded character classes (`alpha`/`digit`/`symbol`), instant `useEffect` unmount + `visibilitychange` + blur scrubbing, and `LockAndTerminateWorker` lifecycle (zeroizing arena, calling `worker.terminate()`, unmounting authenticated React tree, and respawning a cold Worker).
14. **Client-Side Portability & Emergency Kit Wizards (`src/features/portability/`)**:
    - Build zero-upload Import Wizard (FIDO CXF/CXP v1.0, Bitwarden JSON, 1Password `.1pux`, KeePassXC `.kdbx` v4, CSV with dry-run deduplication), policy-gated Export Wizard (`allow_cxf_export` check + WebAuthn step-up + `AuditEnvelope`), and offline vector PDF **Emergency Recovery Kit Generator** (SLIP-0039 33-word grid + Bech32m `rsvrk1...` + Level-H QR `rsv-rk://v1?...` + handwritten passphrase box).

### Workstream E — Thick-Client Enterprise Org Admin Dashboard (Web SPA `/admin/*` & GPUI `AdminModeShell`)
Implement all 6 zero-knowledge enterprise views backed identically by `rsv-wasm` Worker (Web SPA) and `rsv-daemon` (GPUI Admin Mode), strictly honoring role gating (`vault.tenant_user_role`) and opaque subgraph rendering (`[Encrypted Team — No Decryption Path]`):

15. **View 1 — Blind RBAC Graph & Provisioning Workbench**: Virtualized 10,000+ user/team/collection tree (`44px` rows), interactive stratified DAG canvas (`User -> Team -> Team [depth <= 4] -> Collection`) with diamond path highlight and instant `< 2 ms` local cycle/depth red error preview, plus bulk CSV/group provisioning executing mandatory `INV-025` KT verification (`VerifiedKtRecipient`) and halting immediately on any KT mismatch (`INV-036`).
16. **View 2 — Blind SCIM 2.0 Pending Lifecycle Queue**: Hydrates `/api/v1/scim/intents` + live `scim_intent_queued` WS events; shows locally decrypted team/collection targets, KT status, and exact cryptographic diff (new edges, revoked edges, `TK`/`CK` epoch bumps, surviving member re-wrap counts) with 1-click **"Verify KT & Cryptographically Execute"** (`/complete`) and audited Reject flow.
17. **View 3 — Atomic Epoch Rotation & Blast-Radius Console**: Interactive blast-radius impact graph, per-collection `lazy_forward` / `eager_background` / `eager_blocking` (`<= 500` items cap) controls, mandatory `ORPubK` escrow continuity indicator, upstream external-credential rotation advisory + local CSV checklist export, `409 STALE_KEY_EPOCH` auto-rebase & re-confirm prompt, and resumable eager sweep progress bar.
18. **View 4 — Quorum Recovery & Feldman VSS Governance**: `ORPubK` fingerprint + `root_manifest_signature` card, `n`-custodian roster with **Non-Reconstructive Shard Health Check** triggers (`INV-015`), interactive `initial_dkg` / `share_refresh` / `trustee_rotation` / `quorum_recovery` coordinator with live `t`-of-`n` gauge & `QUORUM_THRESHOLD_UNMET` gate, plus `DRPK` audit queue explicitly hard-locking **`DRPK DISABLED (INV-005)`** on `enterprise_escrow` (`root_quorum_only`) and `strict_zk` collections.
19. **View 5 — Zero-Knowledge Audit Ledger & Compliance Workbench**: Top C2SP `tlog-tiles` Checkpoint + External Witness Cosignature + KT Monitor status ribbon, `TBK` `blind_epoch` rotation control (`owner`), virtualized Blinded Operations stream with interactive **RFC 9162 Inclusion Proof Drawer**, Compliance Officer Forensic Mode (importing air-gapped **`rsv-compliance-cli`** verified bundles or connecting local PKCS#11/WebUSB Compliance HSM holding `CPK` — zero `CPK` on server), and 1-click air-gapped tile/checkpoint bundle export.
20. **View 6 — Enterprise Policy, `CS-02` Agility & Machine Identities**: `CS-01` -> `CS-02` (X-Wing) tenant rollout toggle with live Client-Readiness Histogram & cutover safety gate, `L3_HARDWARE_ENCLAVE` attestation & security policy switches (`SPEC-14`), OIDC/SAML & SCIM-scoped bearer token config, CI/CD OIDC **`vault.machine_identities`** registry enforcing read-only `machine_to_collection` (`permission_mask = 0x01`) + 1-click revocation/rotation, and signed `root_manifest_cbor` diff commit.

---

## 5. Exact Verification Commands & Exit Criteria

ALL commands below MUST exit with code `0` before opening your PR:

```bash
# 1. Rust formatting, strict clippy, unsafe firewall & zero-crypto desktop dependency firewall
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 clippy -p rsv-desktop --all-targets -- -D warnings
grep -q '#!\[forbid(unsafe_code)\]' crates/rsv-desktop/src/main.rs
! cargo tree -p rsv-desktop | grep -E 'rsv-crypto|rsv-mem|rsv-enclave|rsv-vss|sqlx|axum|rsv-server|wry|tauri'

# 2. Design tokens codegen parity & WCAG 2.2 AA contrast verification (>= 4.5:1 text / >= 3.0:1 UI)
(cd packages/design-tokens && npm ci && npm run generate && npm run test:contrast && git diff --exit-code)

# 3. GPUI presenter unit tests, headless snapshot tests & 100k-item 120 FPS virtualization benchmark
cargo +1.94.0 test -p rsv-desktop -- --nocapture
cargo +1.94.0 test -p rsv-desktop --release --test bench_100k_virtual_list -- --nocapture
# Required assertions inside bench_100k_virtual_list:
#   p99_frame_paint_ms < 4.0 && p99_fuzzy_search_ms < 12.0 && lock_wipe_ms <= 50.0 && secret_canary_ram_hits == 0

# 4. Fixed-arena WASM zero-grow verification (INV-024)
cargo +1.94.0 build -p rsv-wasm --target wasm32-unknown-unknown --release
cargo +1.94.0 test -p rsv-wasm --test wasm_arena_gate -- --nocapture

# 5. Extension & Web SPA strict TypeScript, static security ESLint & zero-external-CDN bundle check
(cd clients/extension && npm ci && npm run typecheck && npm run lint:security && npm test && npm run build)
(cd clients/web-spa && npm ci && npm run typecheck && npm run lint:security && npm test && npm run build)
# Verify zero Math.random(), zero dangerouslySetInnerHTML, zero external http(s) font/CDN/favicon URLs in dist/:
! grep -rnE 'Math\.random\s*\(|dangerouslySetInnerHTML|fonts\.googleapis\.com|cdn\.jsdelivr\.net|unpkg\.com' clients/extension/src clients/web-spa/src clients/web-spa/dist

# 6. Playwright E2E Negative Security Suites (INV-033, INV-034, INV-035, INV-036 + WCAG 2.2 AA)
(cd tests/ui-security && npm ci && npx playwright test \
    tests/zero-leak-dom-storage-heap.spec.ts \
    tests/concealed-clipboard-ttl.spec.ts \
    tests/hostile-autofill-12-vectors.spec.ts \
    tests/closed-shadow-dom-isolation.spec.ts \
    tests/passkey-mediation-rpid-bypass.spec.ts \
    tests/web-spa-csp-coop-coep-prf-detach.spec.ts \
    tests/org-admin-kt-poisoning-and-cycle.spec.ts \
    tests/org-admin-scim-vss-audit-splitview.spec.ts \
    tests/wcag-22-aa-keyboard-axe.spec.ts)

# 7. Native OS Clipboard Concealment & Non-Clobber Test (INV-034 — executed on macOS/Windows/Linux runners)
cargo +1.94.0 test -p rsv-desktop --test clipboard_concealed_hygiene -- --nocapture

# 8. Supply chain & license audit
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

### Mandatory Playwright Negative Test Coverage Matrix (`tests/ui-security/`)

| Test File | Mandatory Adversarial Scenarios Verified |
| :--- | :--- |
| `zero-leak-dom-storage-heap.spec.ts` (`INV-033`) | Inject unique canary password -> assert `••••••••••••` default mask -> click Reveal -> verify `0` `data-*` / ARIA secret attributes -> wait `15.5 s` (auto-remask), trigger component unmount, tab `visibilitychange`, and vault lock -> assert `0` canary matches in DOM, `localStorage`, `sessionStorage`, `IndexedDB`, `chrome.storage`, and window globals |
| `concealed-clipboard-ttl.spec.ts` (`INV-034`) | Verify copy countdown toast, automatic clipboard clear after configured TTL, immediate clear on vault lock, and Non-Clobber preservation when user copies an unrelated string prior to TTL expiry |
| `hostile-autofill-12-vectors.spec.ts` (`INV-035`) | Assert `0` leaked credentials across: (1) page-load auto-fill trap, (2) focus-triggered fill, (3) cross-origin `<iframe>`, (4) opaque `"null"` sandboxed iframe, (5) `opacity: 0.01` overlay, (6) `1x1` off-screen input, (7) `clip-path` hidden input, (8) transparent clickjacking `div` failing 5-point hit-test, (9) UTS #46 Punycode homograph `xn--`, (10) `attacker.github.io` vs `victim.github.io`, (11) `http://` downgrade, (12) `isTrusted: false` synthetic click + hidden auxiliary field injection; verify **Phishing-Mismatch Interstitial** renders and hard-blocks when `block_origin_mismatch_override = true` |
| `closed-shadow-dom-isolation.spec.ts` (`INV-035`) | Page script queries `document.querySelectorAll('*')`, checks `.shadowRoot === null` on every injected host, attempts prototype pollution of `HTMLInputElement.prototype.value`, and confirms zero scraped account titles |
| `passkey-mediation-rpid-bypass.spec.ts` (`INV-035`) | Asserts public suffix `rpId` (`github.io`) rejection, unconditional passkey-shim bypass on RusticStack Web SPA origin, hardware security key fallback escape hatch, and Shared Team Passkey `passkey.assert` audit emission |
| `web-spa-csp-coop-coep-prf-detach.spec.ts` (`INV-022`, `INV-024`) | Asserts `window.crossOriginIsolated === true`, `0` CSP console violations, `0` third-party network requests, `prfBuf.byteLength === 0` immediately post-transfer, SRI mismatch triggering pre-boot Security Halt, and `worker.terminate()` on lock |
| `org-admin-kt-poisoning-and-cycle.spec.ts` (`INV-036`, `INV-005`) | Mock server serves tampered recipient `UPK` lacking valid KT proof -> asserts hard halt & `0` `POST /api/v1/graph/edges` calls; cyclic `team_to_team` edge -> blocked locally `< 2 ms`; `enterprise_escrow` (`root_quorum_only`) -> `DRPK` button disabled & locked |
| `org-admin-scim-vss-audit-splitview.spec.ts` (`INV-015`, `INV-018`, `INV-036`) | Approves Blind SCIM 2.0 queue item verifying KT diff preview; rejects 1-bit mutated Feldman VSS share visually; verifies offline `rsv-compliance-cli` forensic bundle import + RFC 9162 Inclusion Proof drawer; simulates witness split-view -> asserts **non-dismissible Hard Security Halt** + immediate key wipe |
| `wcag-22-aa-keyboard-axe.spec.ts` | Runs `axe-core` across every Web SPA Vault & Org Admin view (`0` critical/serious issues) and completes full login -> search -> reveal -> copy -> lock journey via keyboard only |

---

## 6. PR Submission Evidence & Escalation Rules

### Required PR Description Evidence
Every PR opened under Playbook `10` MUST include:
1. **Invariant Verification Table**: Explicit PASS status for `INV-033`, `INV-034`, `INV-035`, `INV-036` plus `INV-005`, `INV-010`, `INV-018`, `INV-021`–`INV-025`, `INV-030`, `INV-031`.
2. **GPUI 100k-Row Benchmark Output**: Actual p50/p99 frame paint (`< 4.0 ms`), fuzzy search latency (`< 12.0 ms`), idle RSS (`< 80 MiB`), and lock-to-wipe latency (`<= 50 ms`).
3. **Playwright Security Suite & `axe-core` Report**: Exact pass counts across all 9 security/accessibility spec files (`0` skipped security tests).
4. **Dependency & Static Security Check Logs**: `cargo tree -p rsv-desktop`, `wasm_arena_gate`, and zero-CDN/zero-`Math.random()` grep exits.

### Mandatory Escalation / Stop Conditions
STOP immediately and escalate to the orchestrator/human lead if:
1. Any GPUI upstream API change requires modifying code outside `crates/rsv-desktop/src/ui_gpui/`.
2. Implementing a UI feature appears to require exposing raw `MUK`/`USK`/`TK`/`CK`/`DEK`/`ORPK`/`CPK` bytes across `VaultController` or the `crypto.worker.ts` `MessagePort`.
3. A browser API limitation weakens Closed Shadow DOM isolation, `crossOriginIsolated`, or OS clipboard concealment on any target browser/OS.
4. Any task requires editing crates outside Section 1's Exclusive Write Ownership list.
