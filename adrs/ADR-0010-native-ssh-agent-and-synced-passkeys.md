# ADR-0010: Native Hardware-Gated SSH Agent (RFC 9987), Synced Enterprise Passkeys & Zero-Disk CI/CD OIDC Workload Identity

| Field | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0010` |
| **Project** | RusticStack Core (`ZK-Vault` — `https://github.com/KelpHect/ZK-Vault`) |
| **Status** | Accepted |
| **Date** | `2026-11-19` |
| **Target Toolchain** | Rust 2024 Edition, MSRV `1.94.0` |
| **Related Specs** | [`SPEC-12`](../specs/12-DEVELOPER-SECRETS-SSH-PASSKEYS-AND-CLI.md), [`SPEC-03`](../specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md), [`SPEC-04`](../specs/04-BLIND-RBAC-ACCESS-GRAPH.md), [`SPEC-07`](../specs/07-OMNI-CLIENT-ARCHITECTURE.md), [`SPEC-09`](../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (`INV-028`, `INV-029`), [`ADR-0003`](ADR-0003-gpui-native-desktop-over-electron.md), [`ADR-0006`](ADR-0006-native-messaging-daemon-offload-for-extension.md) |

---

## 1. Context and Problem Statement

Engineering and platform teams are simultaneously the heaviest users and the highest-impact breach targets of enterprise vaults. Four persistent security gaps dominate developer secret management:

1. **Plaintext SSH Private Keys & Unaudited Agent Hijacking**: Developers store unencrypted `~/.ssh/id_ed25519` keys on disk (routinely harvested by macOS/Windows/Linux infostealers) or load keys into OS `ssh-agent` without caller provenance checks, biometric gating, or cryptographic audit trails. Commercial leaders such as **1Password SSH Agent** pioneered biometric SSH agent gating, yet run atop closed-source Electron/hybrid shells without post-quantum X-Wing vault envelopes, without OS-hardened `LockedSecretBox` guard pages + `PROT_NONE` dormant sealing, and without witness-cosigned RFC 9162 Merkle non-repudiation logs for every SSH/Git signature.
2. **Unaccountable Shared Root Passkeys**: As cloud providers (AWS, Cloudflare, GitHub, Stripe) mandate phishing-resistant FIDO2/WebAuthn passkeys, teams sharing break-glass or root accounts cannot pass a physical YubiKey across continents — yet syncing passkeys in browser-owned JS storage exposes PKCS#8 private keys to browser compromise and lacks cryptographic proof of *which* human engineer signed in.
3. **Plaintext `.env` Proliferation**: Developers export vault secrets into local `.env` files that linger on disks, backups, and accidental `git add .` commits.
4. **Static Long-Lived CI/CD Service Account Tokens**: Existing developer secret managers (1Password Service Accounts `OP_SERVICE_ACCOUNT_TOKEN`, Bitwarden Secrets Manager `BWS_ACCESS_TOKEN`, Doppler tokens) rely on static bearer secrets stored inside CI/CD environment variables. Leaking a single token grants unrestricted remote replay from outside the CI runner until manually rotated.

How should RusticStack Core deliver an open-source, post-quantum, hardware-gated developer secrets platform spanning SSH, Git signing, synced team passkeys, local CLI execution, and CI/CD pipelines without breaking zero-knowledge invariants (`INV-001`, `INV-011`, `INV-018`)?

---

## 2. Decision Drivers

- **Zero Plaintext Private Keys or `.env` Files on Disk (`INV-028`, `INV-029`)**: SSH private keys, passkey PKCS#8 keys, and runtime application secrets MUST NEVER materialize as persistent plaintext files.
- **Locked Physical Memory & Hardware Presence**: All developer signing keys MUST execute exclusively inside `rsv-daemon`'s `rsv-mem::LockedSecretBox` (or non-exportable Apple SE / TPM 2.0 / Windows CNG silicon for P-256), guarded by OS peer-credential checks (`SO_PEERCRED` / `LOCAL_PEERTOKEN` / Named Pipe SID) and native GPUI biometric approval.
- **Per-Signature Human Non-Repudiation**: Every SSH login, Git commit signature, shared team passkey assertion, and CLI/CI secret injection MUST emit a signed, blinded, `CPubK`-encrypted Merkle audit leaf (`INV-018`, `INV-019`).
- **Zero Static CI Bearer Tokens**: CI/CD secret retrieval MUST bind federated OIDC Workload Identity (`iss`/`sub`/`aud`/repo/ref claims) with a Proof-of-Possession machine key (`MIK`/`MSK`) as a read-only leaf in the Blind RBAC DAG (`vault.machine_identities`).
- **Memory-Safe, Zero-Electron Native Execution**: Maintain `#![forbid(unsafe_code)]` across `rsv-daemon` and `rsv-cli` (`INV-010`).

---

## 3. Considered Options

1. **Option 1 (Chosen): Native RFC 9987 SSH Agent + Virtual WebAuthn Authenticator Inside `rsv-daemon` + Thin Zero-Key `rsv-cli` (`rsv run`) + Federated OIDC Workload Machine Identities**
2. **Option 2: Export Temporary `~/.ssh/id_*` / `.env` Files with `chmod 0600` & Cleanup Hooks + Standard OS `ssh-agent`**
3. **Option 3: In-Browser Extension JS/WASM Passkey Custody + Static CI Service Account Bearer Tokens**
4. **Option 4: Centralized Online SSH CA / Secrets Proxy Server Holding Plaintext Developer Keys**

---

## 4. Decision Outcome

**Chosen Option: Option 1 — Unified `rsv-daemon` Hardware-Gated SSH Agent & Virtual WebAuthn Authenticator + Thin `rsv-cli` + Zero-Knowledge OIDC Machine Identities.**

### 4.1 Normative Architectural Summary

1. **Embedded RFC 9987 SSH Agent in `rsv-daemon` (`INV-028`)**:
   - Exposes `$XDG_RUNTIME_DIR/rusticstack/rsv-agent.sock` (Linux), App Group `agent.sock` (macOS), and `\\.\pipe\openssh-ssh-agent` / dedicated single-user SID Named Pipe (Windows).
   - Supports `ssh-ed25519`, `ecdsa-sha2-nistp256` (including silicon-resident non-exportable P-256 keys inside Apple SE / TPM 2.0 / CNG), `sk-ssh-ed25519@openssh.com`, OpenSSH certificates, and Git commit/tag signing (`gpg.format = ssh`, parsing `SSHSIG` `"git"` namespace).
   - Rejects `SSH_AGENTC_ADD_IDENTITY` by default so vault RBAC remains the single source of truth.
   - Implements OpenSSH `session-bind@openssh.com` (RFC 9987 extension): displays remote host fingerprint + caller PID/binary in a native GPUI biometric approval sheet, forces fresh hardware UV on every forwarded request, and commits a blinded `ssh.sign` Merkle leaf.
2. **Synced Enterprise Passkeys (`passkey_v1`) via Extension -> `rsv-daemon` Offload**:
   - Passkey PKCS#8 keys live encrypted inside Blind RBAC `vault.vault_items` (`BE=1, BS=1, signCount=0` per W3C WebAuthn Level 3).
   - Chrome Extension mediates `navigator.credentials.create`/`.get` with strict PSL `eTLD+1` + HTTPS + `crossOrigin` validation (`INV-023`) and an always-visible hardware security key fallback, delegating assertion signing strictly to `rsv-daemon` over chunked HPKE Native Messaging (`ADR-0006`) so private keys NEVER touch browser RAM.
   - Shared team passkeys commit a synchronous `HDIK` + `UIK` signed `passkey.assert` Merkle audit envelope proving *which* human engineer signed into AWS/Cloudflare/GitHub!
3. **Thin `rsv-cli` (`rsv://` + `rsv run`, `INV-029`) & OIDC Workload Machine Identities**:
   - `rsv run --env-file=rsv.env.template -- <cmd>` resolves `rsv://` URIs over local OS IPC, injects directly into child `envp` with zero disk `.env` persistence, scrubs parent buffers, and applies a streaming Aho-Corasick output redactor (`--mask-output`) scrubbing raw + base64/URL-encoded accidental echoes.
   - `vault.machine_identities` models CI/CD runners as read-only (`permission_mask = 0x01`) Blind RBAC leaves (`machine_to_collection` edges wrapped to `MPK`), authenticated by short-lived OIDC Workload JWTs (GitHub Actions, GitLab CI, K8s Projected SA, AWS IAM) + `MIK` Proof-of-Possession sealed in customer Cloud KMS / HSM / Confidential Runner Enclave.

### 4.2 Competitive Developer Security Comparison

| Capability | 1Password SSH Agent / CLI / Service Accounts | Bitwarden Secrets Manager (`bws`) | RusticStack Core (`ADR-0010`) |
| :--- | :--- | :--- | :--- |
| **Native SSH Agent + Biometric Sheet** | Yes (closed-source, Electron UI host) | No native SSH agent | **Yes (`RFC 9987`)** — Pure Rust `rsv-daemon` + GPUI 120 FPS + `LockedSecretBox` guard pages |
| **Silicon-Resident Non-Exportable P-256 SSH Keys** | Software-synced keys only | N/A | **Yes** — Apple SE / TPM 2.0 / CNG non-exportable P-256 + synced Ed25519 |
| **Per-Signature Witnessed Merkle Non-Repudiation** | Server-side event logs | Server-side event logs | **Yes** — `HDIK`+`UIK` signed `ssh.sign` & `passkey.assert` leaves in C2SP `tlog-tiles` |
| **Shared Team Passkeys with Human Accountability** | Shared passkeys (server logs) | Passkey sync (JS/extension memory) | **Yes** — Zero browser key custody (`rsv-daemon` offload) + cryptographic human attribution |
| **Zero-Disk `rsv run` + Streaming Output Masking** | `op run` (masking supported) | `bws run` | **Yes (`INV-029`)** — Zero-disk `envp` + `memfd` + streaming raw/base64 Aho-Corasick redactor |
| **CI/CD Auth Without Static Bearer Tokens** | Static `OP_SERVICE_ACCOUNT_TOKEN` | Static `BWS_ACCESS_TOKEN` | **Federated OIDC Workload Identity + `MIK` PoP + Blind RBAC `MPK` (Zero Static Tokens!)** |

---

## 5. Consequences

### 5.1 Positive Consequences
- **Single Locked Custody Daemon**: Unifying Vault Sync, Chrome Native Messaging (`ADR-0006`), RFC 9987 SSH Agent, Virtual WebAuthn Authenticator, and `rsv-cli` IPC inside `rsv-daemon` ensures one biometric unlock, one `rsv-mem` locked arena, and one `< 50 ms` instant wipe on OS screen lock or sleep.
- **Eliminates Static CI Secret Sprawl**: Compromising a GitHub repository variable or workflow log yields zero replayable bearer tokens; rotating a CI pipeline's access is an instant Blind RBAC `CK` epoch bump (`INV-009`).
- **Cryptographic Proof for Shared Cloud Accounts**: Resolves the long-standing compliance tension between shared root SaaS/cloud passkeys and SOC 2 / PCI-DSS individual-accountability audits.

### 5.2 Negative Consequences & Mitigations

| Risk / Trade-off | Impact | Normative Mitigation |
| :--- | :--- | :--- |
| **Windows `\\.\pipe\openssh-ssh-agent` Contention** | Built-in Windows `ssh-agent` service binds the default pipe name if enabled. | Installer detects and guides disabling the built-in Windows `ssh-agent` service (or exposes dedicated pipe `\\.\pipe\rusticstack-ssh-agent-<SID>` configurable via `SSH_AUTH_SOCK` / OpenSSH `IdentityAgent`). |
| **Legacy Tools Requiring Filesystem Key Paths** | Some Docker/Terraform/OpenSSL workflows expect a path on disk rather than an env var. | Provide `rsv inject --memfd` (Linux sealed `memfd_create`) and anonymous OS pipes so secrets remain strictly in kernel/RAM without persistent filesystem blocks (`INV-029`). |
| **Offline SSH / Shared Passkey Audit Latency** | Blocking on online Merkle submission breaks offline `git commit -S` on airplanes. | Configurable per-collection policy: `ssh.sign` allows local signed queue-and-flush when offline (bound by monotonic hardware counter), while high-privilege shared team passkeys (`require_online_audit_for_shared_passkeys = true`) fail closed offline (since cloud RP login requires internet connectivity anyway!). |
| **CI Runners Without Cloud KMS / Enclave** | Small hobby repos may not provision AWS/GCP KMS to seal `MSK`. | Document Mode 1 (Cloud KMS/HSM) as mandatory for enterprise production tiers and optionally permit ephemeral KMS-free runner keys strictly scoped to non-production collections with explicit tenant policy opt-in and audit warning tag. |

---

## 6. Pros and Cons of Considered Alternatives

### 6.1 Option 2: Temporary `chmod 0600` Files + Standard OS `ssh-agent`
- **Pros**: Zero custom RFC 9987 protocol code; compatible with all tools out of the box.
- **Cons**: Leaves plaintext private keys and `.env` secrets on SSD flash wear-leveling blocks, OS backups (Time Machine / VSS), and crash leftovers; stock `ssh-agent` lacks native biometric approval sheets, `session-bind` forwarding enforcement, and Merkle audit logging. **Rejected.**

### 6.2 Option 3: Browser-Only Passkey Storage + Static CI Bearer Tokens
- **Pros**: Faster initial shipping without Native Messaging passkey mediation or OIDC JWKS verification.
- **Cons**: Exposes shared enterprise root passkey PKCS#8 keys inside browser renderer/extension memory; forces enterprises back to static `BWS_ACCESS_TOKEN`-style CI secrets vulnerable to exfiltration and replay. **Rejected.**

### 6.3 Option 4: Online Centralized SSH CA / Secrets Proxy Server
- **Pros**: Simple stateless CI clients.
- **Cons**: Violates `INV-001` (server holds signing CA key or plaintext application secrets), creating a catastrophic single point of compromise if `rsv-server` (`ADV-01`) is breached. **Rejected.**

---

## 7. Verification Criteria

This ADR is verified complete when all automated gates in `Playbook 08` pass:
1. Live SSH authentication (`ssh-ed25519` and hardware-backed `ecdsa-sha2-nistp256`) and Git commit signing (`gpg.format = ssh`) succeed via `rsv-daemon` with zero private-key files written anywhere on disk and a verified `ssh.sign` Merkle leaf (`INV-028`).
2. `session-bind@openssh.com` forwarded agent requests always bypass TTL caching and demand interactive approval; `SSH_AGENTC_ADD_IDENTITY` returns `SSH_AGENT_FAILURE`.
3. Chromium MV3 virtual WebAuthn mediation passes full anti-phishing `rpId` / PSL `eTLD+1` negative suite, maintains zero PKCS#8 key bytes in browser JS heap, and produces verifiable `passkey.assert` `CPubK` compliance envelopes.
4. `rsv run` syscall harness confirms zero plaintext `.env` disk writes, clean child `envp` injection, chunk-boundary-safe raw/base64 output redaction, and zeroed parent memory (`INV-029`).
5. OIDC Machine Identity exchange rejects invalid `iss`/`aud`/`sub`/claims and missing/invalid `MIK` PoP signatures, and PostgreSQL enforces `permission_mask = 1` read-only on `machine_to_collection` edges plus `FORCE RLS` on `vault.machine_identities`.
