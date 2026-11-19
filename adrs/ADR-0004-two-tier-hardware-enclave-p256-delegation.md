# ADR-0004: Two-Tier Hardware Enclave Offloading with NIST P-256 Delegation

| Metadata | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0004` |
| **Status** | Accepted |
| **Date** | 2026-11-19 |
| **Deciders** | RusticStack Core Architecture Group |
| **Project** | RusticStack Core (`ZK-Vault`) — `https://github.com/KelpHect/ZK-Vault` |
| **Normative Specs** | [SPEC-02: Cryptography and Key Hierarchy](../specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md), [SPEC-03: Memory Safety and Hardware Trust](../specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md) |
| **Target Crates** | `rsv-enclave`, `rsv-mem`, `rsv-crypto`, `rsv-daemon`, `rsv-desktop` |

---

## 1. Context and Problem Statement

RusticStack Core standardizes its end-to-end vault protocol cryptography on modern, constant-time, misuse-resistant primitives: `Ed25519`, `X25519`, and `AES-256-GCM` in `CS-01`, evolving cleanly to post-quantum hybrid **X-Wing** (`X25519 + ML-KEM-768`) and `Ed25519 + ML-DSA-65` in `CS-02`.

Simultaneously, enterprise Zero-Trust deployments require **non-exportable hardware-anchored device identity and biometric/TPM-gated local key sealing** (`L3_HARDWARE_ENCLAVE`) across macOS, Linux, and Windows laptops. This creates an acute silicon compatibility conflict:

1. **Apple Secure Enclave Processor (SEP)**: Hardware silicon (`kSecAttrTokenIDSecureEnclave`) exclusively generates, stores, and executes **NIST P-256 (`secp256r1`)** ECDSA/ECDH keys. It provides zero silicon support for `Ed25519`, `X25519`, `ML-KEM`, or `ML-DSA`.
2. **TPM 2.0 Ecosystem (Linux `tss-esapi` & Windows `PCPKSP`)**: Deployed discrete and firmware TPM 2.0 modules universally implement **NIST P-256** (`TPM_ECC_NIST_P256`) and RSA-2048 under `TPMA_OBJECT_FIXEDTPM | FIXEDPARENT | SENSITIVEDATAORIGIN`. `Ed25519` and `X25519` are NOT universally supported across deployed TPM firmware and are completely absent from Windows `Microsoft Platform Crypto Provider (PCPKSP)`.
3. **Post-Quantum Silicon Lag**: Hardware enclaves in existing enterprise fleets will not natively execute FIPS 203 (`ML-KEM-768`) or FIPS 204 (`ML-DSA-65`) for years.

How should RusticStack Core achieve universal hardware enclave non-exportability across Apple Silicon, Linux TPM 2.0, and Windows TPM 2.0 **without** downgrading protocol cryptography or blocking post-quantum migration?

---

## 2. Decision Drivers

- **Universal Fleet Hardware Coverage**: MUST leverage built-in Apple Secure Enclave, Linux TPM 2.0 (`/dev/tpmrm0` via `tss-esapi`), and Windows TPM 2.0 (`PCPKSP` via `windows` crate) with zero extra hardware dongles required for `L3_HARDWARE_ENCLAVE`.
- **Non-Exportable Device Roots**: Device identity (`HDIK`) and local sealing (`HDSK`) private keys MUST NEVER enter host OS RAM in plaintext—defending against disk cloning, offline extraction, and userland memory scraping.
- **Uncompromised Protocol Cryptography**: Protocol signatures (`UIK`), HPKE key-graph wrapping (`UPK`/`USK`, `ORPubK`, `DRPubK`, `CPubK`), and `CS-02` X-Wing post-quantum agility MUST remain completely decoupled from hardware enclave curve restrictions.
- **No HNDL Regression**: Using NIST P-256 inside local hardware silicon MUST NOT expose network or database ciphertexts to Harvest-Now-Decrypt-Later (HNDL) quantum interception.
- **Graceful Degradation with Cryptographic Enforcement**: Devices without TPM/SEP MUST degrade explicitly to `L2_WEBAUTHN_ROAMING` or `L1_SOFTWARE_LOCKED_MEM`, while enterprise tenants MUST be able to strictly enforce `min_device_attestation_level = 3` in `vault.tenants`.
- **Resilience to Biometric / UEFI Firmware Changes**: Updating a laptop BIOS (altering TPM PCRs 0/2/4/7) or re-enrolling Touch ID MUST NOT cause permanent vault data loss.

---

## 3. Considered Options

### Option A: Re-Architect Entire Protocol on NIST P-256 Everywhere
- Replace `Ed25519` and `X25519` across `CS-01` with `ECDSA-P256` and `DHKEM(P-256, HKDF-SHA256)`.
- *Pros*: Uniform single elliptic curve across protocol and enclaves.
- *Cons*: **Severe architectural regression.** Breaks direct compatibility with `X-Wing` (`X25519 + ML-KEM-768`), forfeits Curve25519's cofactorless/Montgomery-ladder side-channel resistance, forces ECDSA malleability & deterministic-nonce complexity into every client/WASM implementation, AND still fails as soon as `CS-02` introduces `ML-KEM-768` and `ML-DSA-65` (which P-256 silicon still cannot run!).

### Option B: Software-Only Key Storage (`rsv-mem` Only, No Hardware Enclaves)
- Store encrypted `USK`/`MUK` on disk protected only by user password (Argon2id) and `rsv-mem` locked RAM.
- *Pros*: Identical pure-Rust codepath across all platforms; no `tss-esapi`, `Security.framework`, or `PCPKSP` FFI.
- *Cons*: **Unacceptable for enterprise security posture.** No hardware device binding, no vendor cryptographic attestation for `vault.user_devices`, no Touch ID / Windows Hello silicon-gated fast unlock, and any stolen local cache file is vulnerable to offline cracking if weak user passphrases are used.

### Option C: Mandate External Ed25519-Capable Smartcards / Hardware Tokens
- Require every enterprise user to carry a specialized OpenPGP/PIV smartcard supporting Curve25519.
- *Pros*: Keeps Curve25519 in hardware.
- *Cons*: **Operationally prohibitive.** High per-seat procurement cost, poor mobile/laptop UX, lacks OS-integrated platform attestation (TPM PCRs / Apple App Attest), and still cannot execute post-quantum `X-Wing` / `ML-DSA-65`.

### Option D (CHOSEN): Two-Tier Hardware Enclave Delegation (`HDIK`/`HDSK` P-256 Anchor -> `UIK`/`USK` Protocol Layer)
- **Tier 1 (Silicon Trust Anchor — Strictly NIST P-256, Non-Exportable)**:
  - `HDIK` (`ECDSA-P256-SHA256`, low-S normalized): Hardware device identity key used strictly for device enrollment attestation (`vault.user_devices`) and mutual cross-signing with `UIK`.
  - `HDSK` (`ECDH-P256` ECIES on Apple SEP / `PCPKSP` on Windows / `TPM2_Create` PolicyPCR sealing object on Linux TPM 2.0): Locally seals `USK` / `MUK` unlock material to physical silicon + biometric (`Touch ID` / `Windows Hello`) or TPM PCR policy (`PCR 0, 2, 4, 7`).
- **Tier 2 (Protocol Cryptography — `rsv-mem` Guarded Locked RAM)**:
  - `UIK` (`Ed25519` / `Ed25519 + ML-DSA-65`) and `UPK`/`USK` (`X25519` / `X-Wing`) perform all vault protocol operations strictly inside `rsv-mem` `LockedSecretBox` pages after local unsealing via `HDSK` (or fresh `MUK` derivation).
- **Authoritative Cloud Recovery Path**:
  - `USK` and `UIK` remain authoritatively wrapped under `MUK` in `vault.users`. If TPM PCRs change after a BIOS upgrade or Touch ID enrollment changes (`EnclaveError::BiometryInvalidated` / `PcrPolicyMismatch`), the user smoothly authenticates via password + WebAuthn PRF (`MUK`), recovers `USK`/`UIK`, and re-seals cleanly to the updated hardware baseline.

---

## 4. Decision Outcome

**Chosen Option: Option D** — Two-Tier Hardware Enclave Delegation implemented behind the normative `HardwareKeyProvider` trait in `rsv-enclave`.

### Detailed Technical Justification

1. **Zero Post-Quantum HNDL Exposure**:
   `HDSK`-sealed blobs NEVER leave the physical endpoint's local encrypted storage and are NEVER stored in PostgreSQL or transmitted across the network. Even if a future quantum computer breaks P-256, an adversary cannot run Shor's algorithm on ciphertexts they cannot intercept over the wire! Meanwhile, every network and database envelope enjoys full `CS-02` X-Wing (`ML-KEM-768 + X25519`) post-quantum confidentiality.
2. **Cryptographic Proof of Hardware Binding**:
   During device enrollment, `HDIK` signs the canonical transcript binding `(tenant_id, user_id, device_id, HDIK_pk, UIK_pk, issued_at)` while `UIK` counter-signs `(transcript || sigma_hdik || attestation_digest)`. This mutual cross-signature cryptographically proves to `rsv-server` and peer enterprise verifiers that a specific software `UIK` is genuinely anchored to a verified physical Apple SEP or TPM 2.0 chip without allowing a man-in-the-middle device substitution attack.
3. **Clean Separation of Concerns**:
   `rsv-crypto` stays 100% pure Rust, `#![no_std]`-friendly, and platform-agnostic, while all platform-specific FFI (`Security.framework`, `tss-esapi`, `windows` CNG/`PCPKSP`) is strictly quarantined inside `rsv-enclave`.

---

## 5. Cryptographic and Engineering Consequences

### Positive Consequences
- **Out-of-the-Box `L3_HARDWARE_ENCLAVE` on >95% of Enterprise Endpoints**: Works immediately on Apple Silicon Macs, modern Windows 11 PCs (TPM 2.0 mandatory), and Linux workstations/servers with TPM 2.0.
- **Instant Biometric UX Without Compromising Security**: Touch ID (`kSecAccessControlBiometryCurrentSet`) and Windows Hello unlock `USK` directly into `rsv-mem` `LockedSecretBox` without caching raw passwords on disk.
- **Zero Lock-In on Protocol Agility**: Upgrading from `CS-01` to `CS-02` (or future `CS-03`) requires ZERO changes to `HDIK`, `HDSK`, or `rsv-enclave` silicon backends!
- **Zero Firmware-Update Bricking**: Because `USK` is dual-anchored (locally sealed by `HDSK` AND remotely wrapped by `MUK` in `vault.users`), TPM PCR drift during UEFI/Secure Boot patches triggers a graceful re-seal rather than permanent lockout.

### Negative Consequences & Mitigations
- **Platform FFI Maintenance Surface**: Requires maintaining three native backend adapters (`AppleSecureEnclave`, `LinuxTpm2Esapi`, `WindowsTpm2Pcpksp`).
  - *Mitigation*: Constrain all three behind the tight, 6-method `HardwareKeyProvider` trait in `rsv-enclave` with unified integration test suites running against macOS CI, Linux `swtpm`, and Windows TPM simulator.
- **Low-S ECDSA Normalization Requirement**: Apple SEP, TPM 2.0, and Windows CNG return DER or raw ECDSA-P256 signatures that may have high-S ($s > n/2$).
  - *Mitigation*: `rsv-enclave` MUST normalize every `HDIK` signature to canonical low-S (`IEEE P1363`, 64 bytes) before returning `P256Signature`, and `rsv-server` MUST reject high-S signatures.
- **Active Session Keys Still Reside in Host RAM**: Once unsealed into `rsv-mem`, `USK`/`DEK` are accessible to a Ring-0 kernel compromise while unlocked.
  - *Mitigation*: Documented honestly in `SPEC-03` Section 2.1; minimized via `rsv-mem` guard pages, `mlock`/`VirtualLock`, `CryptProtectMemory` idle encryption, and rapid auto-lock / sleep zeroization.

---

## 6. Verification and Compliance Criteria

1. **Non-Exportability Proof**:
   - Apple backend MUST pass `kSecAttrTokenIDSecureEnclave` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; key export APIs (`SecKeyCopyExternalRepresentation`) MUST fail on private `HDIK`/`HDSK` handles.
   - Linux `tss-esapi` backend MUST assert `TPMA_OBJECT_FIXEDTPM | FIXEDPARENT | SENSITIVEDATAORIGIN` bits on both SRK and child `HDIK`/`HDSK` objects and MUST open `/dev/tpmrm0` exclusively.
   - Windows `PCPKSP` backend MUST omit `NCRYPT_ALLOW_EXPORT_FLAG` and confirm `NCryptExportKey` returns `NTE_NOT_SUPPORTED` / `NTE_PERM`.
2. **Mutual Cross-Signing Verification**:
   - `rsv-server` enrollment tests MUST verify BOTH `HDIK` (`ECDSA-P256-SHA256`, low-S) and `UIK` (`Ed25519` strict / `CS-02` hybrid) signatures over the exact `"rsv:device-bind:v1"` transcript, rejecting swapped public keys or high-S signatures.
3. **Policy Gate Enforcement**:
   - Enrolling an `L1_SOFTWARE_LOCKED_MEM` or `L2_WEBAUTHN_ROAMING` client against a tenant configured with `min_device_attestation_level = 3` MUST fail closed with `EnclaveError::AttestationPolicyRejected` / HTTP `403`.
4. **PCR Mismatch Recovery Drill**:
   - Linux `swtpm` CI test extending PCR 7 after sealing MUST return `EnclaveError::PcrPolicyMismatch`, verify fallback unlock via `MUK`, and successfully re-seal under the new PCR digest.
