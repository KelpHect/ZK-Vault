# ADR-0009: Witnessed Key Transparency Directory, Strict `Auth != Decrypt` Enterprise SSO & Blind SCIM 2.0 Provisioning

| Field | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0009` |
| **Project** | RusticStack Core (`ZK-Vault` — `https://github.com/KelpHect/ZK-Vault`) |
| **Status** | Accepted |
| **Date** | `2026-11-19` |
| **Target Toolchain** | Rust 2024 Edition, MSRV `1.94.0` |
| **Related Specs** | [`SPEC-11`](../specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md), [`SPEC-02`](../specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md), [`SPEC-04`](../specs/04-BLIND-RBAC-ACCESS-GRAPH.md), [`SPEC-06`](../specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md), [`SPEC-09`](../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (`INV-025`, `INV-026`, `INV-027`) |

---

## 1. Context and Problem Statement

Enterprise organizations adopting a zero-knowledge secret vault demand seamless identity lifecycle integration with Okta, Microsoft Entra ID, Ping Identity, and Google Workspace via **OIDC 1.0 / SAML 2.0 SSO** and **SCIM 2.0** directory sync. However, existing open-source and commercial password managers exhibit three systemic cryptographic vulnerabilities when bridging enterprise identity providers with client-side encryption:

1. **Silent Public Key Substitution Against Untrusted Vault Servers (Bitwarden / Vaultwarden Weakness)**: In Bitwarden and Vaultwarden, confirming a new organization member or sharing a collection relies on the server returning the target user's RSA public key (`UPK`). Unless administrators manually verify a 5-word fingerprint out-of-band on every invite (which practically zero enterprises enforce at scale), a compromised server (`ADV-01`) can substitute an attacker's public key, harvest the wrapped Organization/Collection key, and forward a re-encrypted copy to the victim with zero cryptographic evidence left behind.
2. **SSO Server-Side Key Escrow Collapse (Bitwarden Key Connector Trap)**: To eliminate a separate master password after SSO, Bitwarden introduced **Key Connector** — a customer-hosted server that stores users' master decryption keys and releases them solely upon presenting a valid IdP SSO token. This collapses `Authentication` and `Decryption` into a single trust boundary: any IdP compromise ("Golden SAML", hijacked Okta admin, or Key Connector compromise) immediately decrypts every employee's vault without hardware presence or quorum approval.
3. **Privileged SCIM Key Custody**: Standard SCIM bridges either only create/delete user accounts without rotating compromised team keys (leaving departing employees cryptographically able to decrypt newly updated secrets via cached keys) OR demand live organizational key material inside the SCIM service to automate key wrapping, creating a single high-value target.

How should RusticStack Core deliver frictionless enterprise SSO, automated SCIM 2.0 onboarding/offboarding, and cryptographic protection against rogue-server public key substitution while strictly preserving `INV-001` (Zero Server Knowledge)?

---

## 2. Decision Drivers

- **Eliminate Silent Key Substitution (`INV-025`)**: Clients MUST mathematically verify recipient public keys before wrapping any `TK`, `CK`, or `DEK` without requiring manual out-of-band fingerprint checks on routine team grants.
- **Enforce `Authentication != Decryption` (`INV-026`)**: Compromise of Okta, Entra ID, SAML signing keys, or `rsv-server` MUST yield zero decrypted vault secrets.
- **Zero-Key SCIM Endpoints (`INV-027`)**: `/scim/v2/*` routes MUST hold zero cryptographic keys while still guaranteeing immediate (`< 100 ms`) logical revocation on termination and cryptographic forward secrecy (`epoch += 1`) asynchronously.
- **Reuse Proven Transparency Primitives**: Leverage RusticStack Core's existing RFC 9162 Merkle tree + C2SP `tlog-tiles` + Witness cosigning engine (`rsv-audit`, `ADR-0005`) rather than inventing bespoke transparency cryptography.
- **Post-Quantum Agility (`INV-004`)**: All KT entries, device enrollment handoffs, and graph grants MUST natively support `CS-02` (`X-Wing` + hybrid `Ed25519 + ML-DSA-65`).

---

## 3. Considered Options

1. **Option 1 (Chosen): Witnessed Key Transparency Log (`draft-ietf-keytrans-protocol` + C2SP `tlog-tiles`) + Zero-Knowledge SSO (`WebAuthn PRF` / SAS Device Cross-Signing / Quorum Fallback) + Blind Two-Phase SCIM 2.0 Intent Queue**
2. **Option 2: Bitwarden Key Connector Model (Customer-Hosted SSO Key Escrow Server) + Manual TOFU Key Fingerprints**
3. **Option 3: Vaultwarden / Traditional Server-Trusted Directory + Master-Password-Only SSO**
4. **Option 4: Blockchain / Smart-Contract Public Key Registry**

---

## 4. Decision Outcome

**Chosen Option: Option 1 — Witnessed Per-Tenant Key Transparency (`vault.key_transparency_log`), Strict `Authentication != Decryption` SSO, and Blind SCIM 2.0 Intent Queue (`vault.scim_pending_intents`).**

### 4.1 Normative Architectural Summary

1. **Auditable Key Transparency Directory (`INV-025`)**:
   - Every creation or rotation of `(tenant_id, user_id, key_epoch, UPK, UIK, HDIK_root)` appends a canonical RFC 8949 CBOR `KeyDirectoryEntry` into append-only, 64-way HASH-partitioned `vault.key_transparency_log`, hashed via RFC 9162 (`0x00 || entry_cbor`) into a per-tenant C2SP `tlog-tiles` Merkle tree (`origin = "rusticstack.io/kt/v1/tenant/<tenant_id>"`) with witness-cosigned checkpoints (`vault.key_transparency_checkpoints`) anchoring a verifiable user-latest map root (`rsv-kt-map-root`).
   - Before wrapping any `TK`/`CK`/`DEK`, every client MUST verify inclusion, consistency from its pinned checkpoint, witness cosignatures, and `UIK` continuity signatures. High-privilege custodian/root grants additionally support 60-digit / 6-word EFF SAS + QR safety numbers.
   - Every logged-in client executes periodic background self-monitoring (`kt_self_audit()`) of its *own* `user_id` chain, detecting any rogue shadow `UPK` injection deterministically.
2. **Strict `Authentication != Decryption` Enterprise SSO (`INV-026`)**:
   - OIDC 1.0 (Auth Code + PKCE `S256` + `nonce`) and SAML 2.0 (XXE/XSW-hardened XML-DSig) establish only an authenticated session (`sso_session_token`).
   - Decryption proceeds strictly client-side via: (a) **WebAuthn Level 3 `prf`** passwordless `MUK` derivation, (b) **Trusted Device Cross-Signing** (new laptop generates silicon `HDIK_B`/`HDSK_B` + ephemeral `X-Wing`/`X25519` keypair; existing GPUI desktop verifies 6-word SAS and wraps `USK`/`UIK` through a 300s one-time opaque mailbox), or (c) **Quorum Admin Approval** (`2-of-3` delegated admins or `t-of-n` Feldman VSS).
3. **Blind Two-Phase SCIM 2.0 (`INV-027`)**:
   - `/scim/v2/Users` and `/scim/v2/Groups` NEVER touch keys.
   - **Phase 1 (Synchronous, `< 100 ms`)**: On `active=false` / removal, `rsv-server` immediately revokes JWTs/refresh tokens, kills active WebSockets (`session_revoked`), blocks all reads, and inserts a row into `vault.scim_pending_intents`.
   - **Phase 2 (Cryptographic)**: Executed by the next Org Admin dashboard session OR an optional customer-hosted **HSM-Backed Provisioning Daemon (`rsv-provisioner`)** holding scoped team authority inside customer PKCS#11/HSM hardware (never DB superuser, never `ORPK`, never `root_quorum_only` vaults).

### 4.2 Competitive Architecture Comparison

| Security / Operational Dimension | Bitwarden + Key Connector | Vaultwarden (Community) | RusticStack Core (`ADR-0009`) |
| :--- | :--- | :--- | :--- |
| **Defeats Rogue-Server `UPK` Substitution?** | No (TOFU + optional manual 5-word check) | No (server controls public key directory) | **Yes (`INV-025`)** — Witnessed KT log + mandatory pre-wrap proofs + self-monitor |
| **Survives Compromised IdP ("Golden SAML")?** | **No** (IdP token retrieves keys from Key Connector) | N/A (limited/manual SSO) | **Yes (`INV-026`)** — IdP confers zero decryption capability |
| **Zero-Key SCIM 2.0 Revocation?** | Syncs directory; key rotation manual or privileged | Community SCIM workarounds | **Yes (`INV-027`)** — `< 100 ms` logical kill + blind intent queue + HSM provisioner option |
| **Passwordless Hardware Unlock Post-SSO** | Login-with-Device (classical RSA) | Master password primary | **WebAuthn L3 PRF + Silicon Enclave + X-Wing PQ SAS Enrollment** |
| **Audit Non-Repudiation** | Server-trusted DB audit logs | Server-trusted DB logs | **Witnessed RFC 9162 Merkle + `CPubK` Air-Gapped Envelopes** |

---

## 5. Consequences

### 5.1 Positive Consequences
- **Cryptographic Closure of `STRIDE-S2`**: Eliminates the highest-severity residual attack vector against zero-knowledge multi-user password managers (silent public key substitution by `ADV-01`).
- **Zero Extra Infrastructure for Most Enterprises**: Reuses existing C2SP `tlog-tiles` + witness architecture and requires zero server-side key escrow ("Key Connector") deployment for SSO.
- **Enterprise-Ready Offboarding SLA**: Satisfies SOC 2 / ISO 27001 instant-termination requirements (`< 100 ms` session & read kill) while still delivering mathematical forward secrecy (`epoch += 1`) without granting `rsv-server` key custody.

### 5.2 Negative Consequences & Mitigations

| Risk / Trade-off | Impact | Normative Mitigation |
| :--- | :--- | :--- |
| **Asynchronous Window Between SCIM Intent & Key Rotation** | Between SCIM `grant_team` and Admin/`rsv-provisioner` execution, a newly hired user cannot decrypt team secrets yet; on termination, logical reads are blocked immediately, while old cached `TK` remains valid on prior ciphertext until epoch bump. | Logical kill blocks all server access in `< 100 ms` + kills active WS clients (`rsv-mem` wipe); enterprises wanting `< 5s` automated crypto provisioning deploy optional customer-hosted HSM `rsv-provisioner`. |
| **User Loses All Devices AND Recovery Kit** | Strict `Auth != Decrypt` prevents single-click IdP password reset from decrypting private secrets. | Flow 3 (`SPEC-11` §3.5) provides governed Quorum Admin Approval (`2-of-3` delegated admins on `standard` tier, or fresh key epoch + automatic team re-grant on `enterprise_escrow`/`root_quorum_only`). |
| **KT Witness Unavailability** | If all configured external KT witnesses go offline, strict clients could fail closed on new member grants. | Configure `2-of-3` independent witness quorum (including an org-operated witness); existing vault reads and writes do NOT require fresh KT witness cosigning — ONLY new public-key directory mutations and new grants do. |

---

## 6. Pros and Cons of Considered Alternatives

### 6.1 Option 2: Bitwarden Key Connector + Manual TOFU Fingerprints
- **Pros**: Familiar enterprise UX (login with Okta opens vault immediately without passkey/second device).
- **Cons**: Fundamentally breaks zero-knowledge (`INV-001`) by placing customer master keys on an online server unlocked by SSO assertions; adds operational burden of running a highly sensitive key server; leaves public key substitution unmitigated whenever admins skip manual fingerprint checks. **Rejected.**

### 6.2 Option 3: Traditional Server-Trusted Directory + Master-Password-Only SSO
- **Pros**: Simpler server schema without KT logs or device cross-signing mailboxes.
- **Cons**: Fails modern passwordless enterprise mandates (users still manage complex master passwords alongside SSO) and leaves `ADV-01` able to execute silent `UPK` substitution during every organization invite. **Rejected.**

### 6.3 Option 4: Public Blockchain / Smart-Contract Key Registry
- **Pros**: Decentralized consensus against split views.
- **Cons**: Unacceptable transaction fees, latency, public metadata leakage of enterprise user churn, non-deterministic finality, and unnecessary operational complexity compared to C2SP `tlog-tiles` + lightweight independent witnesses. **Rejected.**

---

## 7. Verification Criteria

This ADR is verified complete when all automated gates in `Playbook 08` pass:
1. Rogue-server `UPK` substitution test deterministically triggers `KT_PROOF_INVALID` across both `rsv-daemon` and `rsv-wasm` (`INV-025`).
2. Background `kt_self_audit()` deterministically detects shadow `user_kt_version` injection and divergent witness split-view checkpoints (`KT_SPLIT_VIEW_DETECTED`).
3. Golden-SAML / compromised-IdP negative harness confirms zero unwrapped key bytes or plaintext vault data can be derived from valid OIDC/SAML assertions alone (`INV-026`).
4. SCIM 2.0 `active=false` terminates active WebSockets and blocks `/api/v1` reads within `< 100 ms`, writes a `pending` row in `vault.scim_pending_intents`, and rejects SCIM tokens on `/api/v1/*` with `403 SCIM_SCOPE_VIOLATION` (`INV-027`).
5. PostgreSQL `FORCE ROW LEVEL SECURITY` + `Subplans Removed: 63` partition pruning passes on `vault.key_transparency_log`, `vault.key_transparency_checkpoints`, and `vault.scim_pending_intents`.
