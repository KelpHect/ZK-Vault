# ADR-0007: Cryptographic Agility and X-Wing Post-Quantum Hybrid KEM (`CS-02`)

| Metadata | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0007` |
| **Status** | Accepted |
| **Date** | 2026-11-19 |
| **Deciders** | RusticStack Core Architecture Group |
| **Project** | RusticStack Core (`ZK-Vault`) — `https://github.com/KelpHect/ZK-Vault` |
| **Normative Specs** | [SPEC-02: Cryptography and Key Hierarchy](../specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md) |
| **Target Crates** | `rsv-crypto`, `rsv-types`, `rsv-vss`, `rsv-server` |

---

## 1. Context and Problem Statement

Enterprise secrets stored in RusticStack Core—root signing certificates, M&A records, financial credentials, and long-term compliance audit logs (`vault.audit_events`)—frequently retain confidentiality requirements for **10 to 30+ years**. Even though a Cryptographically Relevant Quantum Computer (CRQC) capable of executing Shor's algorithm against Curve25519 does not exist today, nation-state adversaries actively perform **Harvest-Now, Decrypt-Later (HNDL)** interception against encrypted database backups, replication streams, and network traffic.

Specifically, in `CS-01` (`0x0001`), while `AES-256-GCM` retains $\approx 128$-bit post-quantum security against Grover's search algorithm, every asymmetric HPKE wrap using `DHKEM(X25519, HKDF-SHA256)` (`UPK`, `ORPubK`, `DRPubK`, `CPubK`) would be completely broken once a CRQC recovers X25519 private scalars from intercepted public keys and encapsulated ciphertexts.

At the same time, deploying post-quantum cryptography prematurely without classical hedging—or implementing an incorrect hybrid KEM combiner—creates severe risks:
1. **Pure-PQ Regression Risk**: Lattice assumptions (`ML-KEM`, FIPS 203; `ML-DSA`, FIPS 204) are decades newer than elliptic-curve discrete logarithms; a classical cryptanalytic breakthrough against ML-KEM alone must NOT weaken vault security below `CS-01`.
2. **Hybrid Combiner Pitfall (`X-Wing` vs. TLS 1.3 `X25519MLKEM768`)**: Two superficially similar `X25519 + ML-KEM-768` hybrids exist in the IETF ecosystem with **fundamentally different combiners**. Mixing them in an asynchronous storage vault silently breaks IND-CCA2 security proofs and interoperability.
3. **Seed & Escrow Compatibility**: The post-quantum KEM MUST integrate cleanly with our 256-bit `ORPK_SEED` Feldman VSS recovery model (`ADR-0001`) without forcing a rewrite of custodian share formats.

How should RusticStack Core design its post-quantum hybrid suite (`CS-02`) and wire-level cryptographic agility?

---

## 2. Decision Drivers

- **HNDL Protection With Classical Hedge**: `CS-02` MUST remain IND-CCA2 secure if **either** `ML-KEM-768` (FIPS 203) **or** `X25519` (RFC 7748) remains unbroken.
- **Standalone Asynchronous Security**: Unlike TLS 1.3 handshakes, vault HPKE wraps stored in `vault.key_graph_edges`, `vault.vault_item_revisions`, and `vault.audit_events` are **offline, single-shot envelopes** with no interactive transcript. The KEM combiner itself MUST provide full ciphertext and public-key binding.
- **Exact 32-Byte Seed Compatibility**: `CS-02` KEM keypairs MUST derive deterministically from a 32-byte seed so `ORPK_SEED` (split via 2×128-bit Feldman VSS in `rsv-vss`) seamlessly derives `CS-02` `ORPK` without altering custodian share size.
- **Zero-Downtime Tenant Migration & Anti-Downgrade Binding**: Every `RSV1` envelope MUST carry an explicit authenticated `CipherSuiteId` bound into `CanonicalAadContext` so tenants can migrate smoothly from `CS-01` (`0x0001`) to `CS-02` (`0x0002`) and lock down `min_cipher_suite = 0x0002` against downgrade attacks.
- **Pure-Rust Standard Alignment**: Align directly with `hpke` `0.15`, `ml-kem` (FIPS 203), `ml-dsa` (FIPS 204), `x25519-dalek` `3.0`, `ed25519-dalek` `3.0`, and `draft-connolly-cfrg-xwing-kem`.

---

## 3. Considered Options

### Option A: Classical-Only (`CS-01` Only; Defer Post-Quantum Design Indefinitely)
- Hard-code `DHKEM(X25519)` and `Ed25519` without a `CipherSuiteId` wire header or `KemSuite` trait abstraction.
- *Pros*: Smaller public keys (`32 B`) and ciphertexts (`32 B` encapped key) in v1.
- *Cons*: **Fails HNDL defense and enterprise CNSA 2.0 / NIST post-quantum readiness roadmaps.** Retrofitting `1216 B` public keys, `1120 B` encapsulated keys, and suite negotiation into a non-agile schema later requires breaking database migrations and flag-day upgrades.

### Option B: Pure `ML-KEM-768` / `ML-KEM-1024` (Non-Hybrid)
- Replace `X25519` directly with standalone FIPS 203 `ML-KEM-768`.
- *Pros*: Slightly simpler than hybrid; avoids X25519 code path.
- *Cons*: **Single-assumption risk and regulatory friction.** If a novel classical attack weakens ML-KEM or an implementation bug appears in a fresh lattice crate, confidentiality collapses completely; furthermore, several enterprise FIPS/European (BSI/ANSSI) security frameworks explicitly mandate hybrid PQ+classical key encapsulation during the transition period.

### Option C: Naive Concatenation Combiner Copied From TLS 1.3 `X25519MLKEM768` (`0x11EC`)
- Compute `ss = ss_M || ss_X` (64 bytes) or `HKDF-Extract(salt, ss_M || ss_X)` without hashing `ct_X` and `pk_X`, mirroring `draft-ietf-tls-ecdhe-mlkem`.
- *Pros*: Reuses code mental model from TLS 1.3 libraries.
- *Cons*: **CRYPTOGRAPHICALLY UNSAFE FOR OFFLINE VAULT ENVELOPES.**
  - In TLS 1.3, `X25519MLKEM768` safely concatenates `ss_M || ss_X` ONLY because the TLS 1.3 Key Schedule immediately hashes the **entire interactive TLS handshake transcript** (including client/server key shares `pk_X`, `ct_X`, `pk_M`, `ct_M`) into every traffic key.
  - Inside an asynchronous HPKE / vault storage envelope without a TLS handshake transcript, omitting `ct_X` and `pk_X` from the KEM combiner violates **Ciphertext Second-Preimage Resistance (C2PRI)** and opens key-substitution / re-encapsulation attacks against X25519 if ML-KEM is broken!

### Option D (CHOSEN): Crypto-Agile `RSV1` Envelope (`CS-01` + `CS-02`) With **X-Wing** (`draft-connolly-cfrg-xwing-kem`) & Hybrid `Ed25519 + ML-DSA-65`
- **`CS-01` (`0x0001`)** remains the mandatory v1 baseline (`AES-256-GCM`, RFC 9180 HPKE `DHKEM(X25519)`, `Ed25519`, `Argon2id`).
- **`CS-02` (`0x0002`)** pairs `AES-256-GCM` with:
  - **X-Wing KEM** (`draft-connolly-cfrg-xwing-kem`, RFC 9180 HPKE KEM `0x647a`): `ML-KEM-768` + `X25519` with the exact C2PRI-proven combiner:
    $$\mathsf{ss} = \mathsf{SHA3\text{-}256}\left(\mathsf{ss}_M \parallel \mathsf{ss}_X \parallel \mathsf{ct}_X \parallel \mathsf{pk}_X \parallel \text{0x5c2e2f2f5e5c}\right)$$
  - **Hybrid Protocol Signatures**: `Ed25519 + ML-DSA-65` (FIPS 204) binding BOTH public keys into a pre-hashed domain transcript with mandatory strict AND verification.
  - **Symmetric AEAD Unchanged**: `AES-256-GCM` (256-bit key already provides $\approx 128$-bit quantum resistance under Grover's algorithm).

---

## 4. Decision Outcome

**Chosen Option: Option D** — Build crypto-agility into `RSV1` envelopes and `rsv-crypto` traits from day one (`CS-01` = `0x0001`, `CS-02` = `0x0002`), strictly mandating **X-Wing (`draft-connolly-cfrg-xwing-kem`)** for `CS-02` HPKE wraps and **strictly forbidding** use of the TLS 1.3 `X25519MLKEM768` concatenation combiner inside vault envelopes.

### Critical Combiner Guardrail for Implementation Agents

Autonomous implementation agents and contributors implementing `rsv-crypto` MUST observe the following strict architectural separation:

| Property | **X-Wing (`CS-02` Vault / HPKE Envelopes)** | **TLS 1.3 `X25519MLKEM768` (`0x11EC`, HTTPS Transport)** |
| :--- | :--- | :--- |
| **Specification** | `draft-connolly-cfrg-xwing-kem` + `draft-ietf-hpke-pq` (`0x647a`) | `draft-ietf-tls-ecdhe-mlkem` (`0x11EC`) |
| **Shared Secret Combiner** | `SHA3-256(ss_M \|\| ss_X \|\| ct_X \|\| pk_X \|\| 0x5c2e2f2f5e5c)` | Raw concatenation `ss_M \|\| ss_X` (fed into TLS 1.3 Key Schedule) |
| **Combiner Input Size** | `32 + 32 + 32 + 32 + 6 = 134 B` (fits in **1** SHA3-256 Keccak block = `136 B`) | `64 B` (no internal hashing) |
| **Why `ct_M` & `pk_M` Omitted?** | ML-KEM-768 (Fujisaki-Okamoto transform) is ALREADY C2PRI / binding internally | Handled externally by TLS 1.3 handshake transcript |
| **Why `ct_X` & `pk_X` Included?** | X25519 alone lacks ciphertext/PK binding; hashing them restores full hybrid IND-CCA2 | Handled externally by TLS 1.3 handshake transcript |
| **Permitted Usage** | **ONLY** valid combiner for `rsv-crypto` `CS-02` envelopes | **ONLY** inside TLS 1.3 HTTPS transport (`rustls` / reverse proxy) |

### Key Synergy: 32-Byte X-Wing Deterministic Seed Derivation

X-Wing defines `GenerateKeyPairDerand(sk)` from a single **32-byte (`256`-bit)** seed:
- `(d, z, sk_X) = SHAKE256(sk, 96)` -> `(ek_M, dk_M) = ML-KEM-768.KeyGen_internal(d, z)` and `pk_X = X25519(sk_X, BASEPOINT)`.
- Therefore, `rsv-vss` splits a 256-bit `ORPK_SEED` using the exact same 2×128-bit padded Feldman VSS protocol (`ADR-0001`) for BOTH `CS-01` and `CS-02`, changing ONLY the HKDF derivation label (`"rsv:orpk:cs01-x25519:v1"` -> `"rsv:orpk:cs02-xwing:v2"`).

---

## 5. Cryptographic and Engineering Consequences

### Positive Consequences
- **Provable Hybrid IND-CCA2 Confidentiality**: Even if either X25519 (via Shor's algorithm on a CRQC) OR ML-KEM-768 (via future classical lattice breakthrough) is completely broken, `CS-02` HPKE wraps remain IND-CCA2 secure.
- **Single-Permutation Combiner Speed**: The 134-byte SHA3-256 input executes in a single Keccak-$f[1600]$ permutation; total X-Wing encapsulate + decapsulate executes in $< 150\;\mu\text{s}$ on modern x86_64/ARM64 CPUs.
- **Anti-Downgrade Cryptographic Lock**: Because `CipherSuiteId` sits both in `RSV1` header bytes `6..8` AND inside `CanonicalAadContext` (CBOR key `9`), an untrusted server cannot silently downgrade a `CS-02` tenant back to `CS-01` or splice `CS-01` wraps into `CS-02` records.
- **Zero-Downtime Incremental Migration**: Dual-read clients decrypt existing `0x0001` envelopes while writing all new mutations in `0x0002`, rotating active keys cleanly without maintenance windows.

### Negative Consequences & Mitigations
- **Larger Public Keys & Asymmetric Envelopes**:
  - `UPK` / `ORPubK` / `DRPubK` / `CPubK` grow from `32 B` (`CS-01`) to `1216 B` (`CS-02`).
  - `EncappedKey` per HPKE envelope grows from `32 B` to `1120 B`.
  - `UIK` public key grows from `32 B` to `1984 B`, and signatures grow from `64 B` to `3373 B`.
  - *Mitigation*: PostgreSQL `BYTEA` columns (`vault.users`, `vault.key_graph_edges`, `vault.vault_item_revisions`, `vault.audit_events`) store variable-length envelopes cleanly without fixed-length `BYTEA(32)` constraints; `RSV1` `EncappedKeyLen` is a `u16` supporting up to `65,535 B`.
- **WASM Binary & Memory Footprint**: Including `ml-kem` and `ml-dsa` adds ~`80–140 KiB` to compressed `rsv-wasm` `.wasm` size and increases temporary decapsulation stack/arena allocations (`dk_M = 2400 B`).
  - *Mitigation*: Pre-sized `16 MiB` fixed WASM linear memory (`2 MiB` `WasmSecretArena` in `ADR-0008`) comfortably accommodates expanded X-Wing keys without `memory.grow()`.
- **Draft Standard Evolution Risk**: `draft-connolly-cfrg-xwing-kem` and `draft-ietf-hpke-pq` are nearing RFC finalization.
  - *Mitigation*: Pin exact X-Wing KAT vectors in `rsv-crypto`; if final IETF RFC alters any label or KEM codepoint prior to `CS-02` GA, assign a fresh `CipherSuiteId` (`0x0003`) rather than silently mutating `0x0002` wire semantics.

---

## 6. Verification and Compliance Criteria

1. **Official X-Wing Known Answer Tests (KATs)**:
   - `rsv-crypto` CI MUST pass 100% of official `draft-connolly-cfrg-xwing-kem` KAT vectors (`GenerateKeyPairDerand`, `EncapsulateDerand`, `Decapsulate`), verifying byte-for-byte equality of `pk` (`1216 B`), `ct` (`1120 B`), and `ss` (`32 B`) using label `0x5c2e2f2f5e5c`.
2. **Combiner Non-Confusion Negative Test**:
   - CI MUST include an explicit negative test asserting that `X-Wing.Combiner(ss_M, ss_X, ct_X, pk_X)` differs from `SHA3-256(ss_M || ss_X)` AND changes completely if a single bit of `ct_X` or `pk_X` is flipped.
3. **Hybrid Signature Strict AND Tests**:
   - Mutating 1 bit in EITHER the `Ed25519` component (`64 B`) OR the `ML-DSA-65` component (`3309 B`) of a `CS-02` signature MUST return `CryptoError::InvalidSignature`.
   - Swapping either public key without regenerating the signature MUST fail verification via the dual-PK pre-hash binding.
4. **Anti-Downgrade Enforcement Tests**:
   - Submitting a `CS-01` (`0x0001`) envelope to a tenant configured with `min_cipher_suite = 0x0002` MUST fail closed with `CryptoError::UnsupportedCipherSuite(0x0001)`.
   - Modifying `RSV1` header bytes `6..8` from `0x0002` to `0x0001` MUST fail AEAD authentication.
5. **Schema Column Capacity Check**:
   - Database migration tests MUST confirm `vault.users`, `vault.tenants`, `vault.key_graph_edges`, `vault.vault_item_revisions`, and `vault.audit_events` accept `1216 B` X-Wing public keys, `1984 B` hybrid verifying keys, `3373 B` hybrid signatures, and `1120 B` HPKE encapsulated keys without truncation.
