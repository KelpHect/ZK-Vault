# ADR-0011: STREAM Chunked AEAD (`AES-256-GCM`) for Large Attachments and FIDO Alliance CXF v1.0 / CXP Credential Interchange

| Field | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0011` |
| **Project** | RusticStack Core (`ZK-Vault` — `https://github.com/KelpHect/ZK-Vault`) |
| **Status** | Accepted |
| **Date** | `2026-11-19` |
| **Target Toolchain** | Rust 2024 Edition, MSRV `1.94.0` |
| **Related Specs** | `specs/13-STREAMING-ATTACHMENTS-OFFLINE-SYNC-AND-MIGRATION.md`, `specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md`, `specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md`, `specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md` |

---

## 1. Context and Problem Statement

RusticStack Core (`ZK-Vault`) must solve two practical enterprise vault challenges without violating zero-knowledge confidentiality (`INV-001`), mandatory AAD context binding (`INV-002`), WASM fixed linear-memory arenas (`INV-024`), or the `< 128 MiB` Sovereign Mode server memory budget (`SPEC-14`):

1. **Large Encrypted Attachments (50–500+ MiB)**: Enterprises store TLS/mTLS PKCS#12 bundles, HSM recovery packs, signed compliance PDFs, SSH certificates, and backup archives inside vaults. RusticStack's standard `RSV1` single-shot `AES-256-GCM` envelope (`SPEC-02 §4.1`) is intentionally capped at `64 MiB` because monolithic AEAD requires buffering the entire payload prior to authentication tag verification—causing instant OOM crashes inside `rsv-wasm`'s non-growing linear arena (`INV-024`), exhausting `rsv-server` memory under concurrent uploads, and exposing decryptors to unauthenticated byte buffering DoS. Naive ad-hoc file chunking, however, historically introduces catastrophic cryptographic flaws: chunk reordering, chunk duplication, silent mid-stream truncation, and cross-file chunk splicing.
2. **Credential Migration & Vendor Lock-In**: Legacy password managers rely predominantly on **unencrypted CSV files** for import/export. Exporting plaintext CSV leaves long-lived credentials on user filesystems, OS Spotlight/Search indexes, cloud sync folders, and browser download caches—and cannot losslessly represent FIDO2 Passkeys (PKCS#8 private keys + RP ID + credential counters), TOTP parameters, SSH keys, or encrypted binary attachments.

How should RusticStack Core standardize (a) streaming authenticated encryption for multi-hundred-megabyte attachments, and (b) secure, lossless cross-vendor credential interchange?

---

## 2. Decision Drivers

- **Provable Online AEAD Security (`INV-030`)**: Chunked encryption MUST provide formal resistance against chunk reordering, duplication, mid-stream truncation, trailing extension, and cross-attachment/cross-tenant splicing.
- **Constant O(1) Memory Footprint**: Both native clients (`rsv-daemon`), browser WASM (`rsv-wasm` with zero `memory.grow()`), and `rsv-server` (`< 256 KiB` RAM per concurrent upload/download stream) MUST process 500+ MiB files in bounded chunk buffers.
- **FIPS & Cipher-Suite Parity**: Attachment encryption MUST align with `CS-01` and `CS-02` (`AES-256-GCM` with hardware AES-NI / ARMv8-CE acceleration) and obey RusticStack's hybrid escrow tiers (`DEK` + `ORPubK` + optional `DRPubK` on `standard` tier only).
- **Tamper-Evident End-to-End Object Binding**: A compromised server or object store (`ADV-01`) MUST NOT be able to substitute one ciphertext object for another without detection by the downloading client.
- **Zero-Plaintext Interoperability**: Primary export/import MUST eliminate plaintext CSV intermediaries, natively preserve FIDO2 Passkeys + SSH keys + TOTP + attachments, and execute 100% client-side offline without ever sending third-party exports to `rsv-server`.

---

## 3. Considered Options

### 3.1 Streaming Attachment Construction
1. **Option 1 (Chosen): STREAM (`AES-256-GCM`) with 64 KiB Chunks, 7B Nonce Prefix + 4B BE Counter + 1B Final Flag, Per-Chunk Canonical CBOR AAD, Multi-Wrapped `AEK`, and Incremental BLAKE3 Ciphertext Root**
2. **Option 2: Monolithic Single-Shot `AES-256-GCM` / `XChaCha20-Poly1305` Envelope**
3. **Option 3: Independent Random-Nonce Per-Chunk AEAD Without Final-Chunk Flag or Manifest Root**
4. **Option 4: `age`-Style STREAM Over `ChaCha20-Poly1305` Only (Diverging from `AES-256-GCM`)**

### 3.2 Credential Portability & Migration
1. **Option 1 (Chosen): FIDO Alliance CXF v1.0 & CXP as Primary Encrypted Interchange + Pure-Rust Client-Side Importers (Bitwarden JSON/Encrypted, 1Password `.1pux`, KeePassXC `.kdbx` v4, Hardened CSV)**
2. **Option 2: Plaintext CSV & Unencrypted JSON Export/Import Only**
3. **Option 3: Proprietary RusticStack-Only Encrypted Export Archive**

---

## 4. Decision Outcome

**Chosen Options: STREAM (`AES-256-GCM`) + Incremental BLAKE3 Root (`Option 1`) for encrypted attachments, and FIDO Alliance CXF v1.0 / CXP + Offline Pure-Rust Importers (`Option 1`) for credential interchange.**

### 4.1 Normative STREAM Rules (`SPEC-13 §2`)
1. **Fresh Per-Attachment `AEK`**: Every attachment generates a unique 256-bit CSPRNG `AEK` multi-wrapped via `RSV1` envelopes under the parent item's `DEK`, `ORPubK` (for `standard` and `enterprise_escrow` / `root_quorum_only`), and `DRPubK` (strictly `standard` tier only; `NULL` / rejected by DB `CHECK` constraint otherwise).
2. **Exact Nonce Layout**: Fixed 64 KiB (`65,536`-byte) plaintext chunks (valid range `16 KiB..=1 MiB`) encrypted under `AES-256-GCM` with 96-bit nonce `nonce_prefix (7B CSPRNG) || BE_u32(chunk_counter) || final_flag (0x00 intermediate, 0x01 final)` (Hoang–Reyhanitabar–Rogaway–Vizár STREAM construction).
3. **Per-Chunk Canonical CBOR AAD**: Every chunk binds `CBOR({1: "rsv:attach:v1", 2: tenant_id, 3: item_id, 4: attachment_id, 5: chunk_counter, 6: final_flag, 7: cipher_suite_id})`, eliminating cross-file and cross-tenant splicing.
4. **Dual BLAKE3 Commitment**: The incremental 32-byte `blake3_ciphertext_root` over `(domain || ids || nonce_prefix || chunk_size || chunk_0_ct || ... || chunk_{N-1}_ct)` is stored in `vault.vault_attachments` (HASH-64 partitioned + `FORCE RLS`) AND embedded inside the parent vault item's authenticated encrypted CBOR manifest.
5. **Bounded Streaming I/O**: Pre-signed direct-to-S3/MinIO URLs in Enterprise HA Mode and 64 KiB framed HTTP streaming to local disk in Sovereign Mode keep `rsv-server` RAM strictly `< 256 KiB` per concurrent stream.

### 4.2 Normative Portability Rules (`SPEC-13 §4`)
1. **FIDO CXF v1.0 / CXP First-Class**: RusticStack Core implements encrypted FIDO Alliance CXF v1.0 and CXP as its canonical import/export contract, supporting Passkeys (PKCS#8 + `rpId` + `credentialId` + `signCount` checks), Logins, TOTP, SSH Keys, Cards, Notes, and binary attachments with zero plaintext disk intermediates.
2. **100% Client-Side Offline Importers**: Native pure-Rust (`#![forbid(unsafe_code)]`) parsers handle Bitwarden JSON & Password-Protected Encrypted Export, 1Password `.1pux` (streaming `files/` attachments directly into STREAM), KeePassXC `.kdbx` v4, and a last-resort hardened CSV importer (`Zeroizing<String>` line streaming + formula neutralization + shred prompt).
3. **Offline Emergency Recovery Kit**: Generated 100% locally in memory encoding the 256-bit recovery secret as both **SLIP-0039 33-word mnemonic** / **Bech32m (`rsvrk1...`)** and a **Level-H QR code**, never transmitted to `rsv-server`.

---

## 5. Consequences

### 5.1 Positive Consequences

- **Constant-Memory Security Across All Targets**: A 500 MiB encrypted attachment streams cleanly through `rsv-wasm` (zero `memory.grow()`), `rsv-daemon` (`<= 160 KiB` locked buffers), and `rsv-server` (`< 256 KiB` per stream).
- **Immediate Fail-Closed Verification**: Any corrupted, reordered, truncated, or spliced chunk fails authentication within 64 KiB rather than buffering 500 MiB of attacker data.
- **Zero-Reupload Item Metadata Edits**: Updating an item's title/notes rotates `DEK` and cheaply re-wraps the 32-byte `AEK` without re-uploading a 400 MiB attachment ciphertext.
- **Standards-Aligned Zero-Lock-In**: Adopting FIDO Alliance CXF v1.0 / CXP gives enterprises safe passkey and secret portability without falling back to hazardous plaintext CSV files.

### 5.2 Negative Consequences & Mitigations

| Risk / Trade-off | Impact | Normative Mitigation |
| :--- | :--- | :--- |
| **Chunk Overhead (`16 B / 64 KiB`)** | Adds `0.024%` ciphertext size overhead (`~128 KiB` on a `512 MiB` file). | Negligible overhead compared to eliminating OOM and delayed authentication; 64 KiB aligns cleanly with OS page sizes, TLS record frames, and AES-NI pipelining. |
| **Client Complexity for Pre-Signed S3 Multipart & Local Streaming** | Clients must handle two upload transports (`presigned_s3` vs `direct_stream`). | Unified behind a single `/api/v1/items/{item_id}/attachments/init` + `/commit` state machine in `rsv-daemon` and `rsv-wasm`. |
| **CXF Ecosystem Evolution** | FIDO CXF/CXP platform OS APIs (Apple/Windows/Android/Linux) are rolling out iteratively across OS versions. | Support both direct OS CXP transport (where available) and portable encrypted CXF archive files (`Argon2id` + `AES-256-GCM`) universally across all platforms. |
| **Third-Party Format Quirks (KDBX4, 1PUX, Bitwarden)** | Malformed external exports can carry ZIP bombs, XML XXE payloads, or edge-case encodings. | Enforce strict pure-Rust `#![forbid(unsafe_code)]` parsers with bounded decompression ratios (`<= 100:1`), disabled XML DTD/entity expansion, and continuous `cargo-fuzz` targets. |

---

## 6. Pros and Cons of Considered Alternatives

### 6.1 Attachment Encryption Alternatives
- **Option 2 (Monolithic Single-Shot AEAD)**: Simple header format, zero chunk framing. **Rejected** because it breaks `INV-024` fixed-arena WASM, forces full-file buffering before tag verification, and violates `< 128 MiB` Sovereign Mode RAM budgets.
- **Option 3 (Independent Random-Nonce Chunks Without Final Flag)**: Avoids counter management, supports trivial parallel random writes. **Rejected** because without `chunk_counter` and `final_flag` authenticated in nonce/AAD, an adversary can silently truncate, drop, reorder, or duplicate chunks undetected.
- **Option 4 (`ChaCha20-Poly1305`-Only STREAM)**: Fast in software without AES-NI. **Rejected** because RusticStack Core standardizes on `AES-256-GCM` across both `CS-01` and `CS-02` for FIPS 140-3 alignment and multi-GB/s AES-NI / ARMv8-CE throughput.

### 6.2 Portability Alternatives
- **Option 2 (Plaintext CSV / JSON Only)**: Trivial to implement. **Rejected** as primary format because plaintext CSV exposes credentials on disk and cannot carry Passkeys, attachments, or structured metadata without catastrophic data loss.
- **Option 3 (Proprietary-Only Export)**: Simplifies internal schema mapping. **Rejected** because enterprise customers and sovereign self-hosters rightly demand open, standards-based exit paths (`FIDO CXF v1.0`).

---

## 7. Verification Criteria

This decision is considered properly implemented when:
1. `rsv-crypto` STREAM KATs pass bit-identically on native targets and `wasm32-unknown-unknown` with `0` `memory.grow()` calls during a 50 MiB WASM streaming encryption/decryption test.
2. Negative tamper tests achieve `100%` deterministic rejection across truncation, reordering, duplication, trailing-byte extension, cross-file splicing, and `blake3_ciphertext_root` mutation (`INV-030`).
3. `vault.vault_attachments` passes cross-tenant RLS chaos (`0` leaked rows) and `EXPLAIN (ANALYZE, FORMAT JSON)` `Subplans Removed: 63` checks.
4. Round-trip tests verify lossless offline import/export across FIDO CXF v1.0 (including Passkeys), Bitwarden Encrypted Export, 1Password `.1pux`, KeePassXC `.kdbx` v4, and hardened CSV, plus verified SLIP-0039 / Bech32m Emergency Recovery Kit generation with zero network calls.
