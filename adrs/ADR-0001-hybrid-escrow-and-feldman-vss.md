# ADR-0001: Hybrid Dual-Tier Asymmetric Escrow and Feldman VSS over Ristretto255

| Metadata | Value |
| :--- | :--- |
| **ADR ID** | `ADR-0001` |
| **Status** | Accepted |
| **Date** | 2026-11-19 |
| **Deciders** | RusticStack Core Architecture Group |
| **Project** | RusticStack Core (`ZK-Vault`) — `https://github.com/KelpHect/ZK-Vault` |
| **Normative Specs** | [SPEC-02: Cryptography and Key Hierarchy](../specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md) |
| **Target Crates** | `rsv-vss`, `rsv-crypto`, `rsv-compliance-cli`, `rsv-server` |

---

## 1. Context and Problem Statement

Enterprise password and secret vaults face a fundamental cryptographic tension:

1. **Strict Zero-Knowledge Invariant**: The RusticStack server (`rsv-server`) and its hosting cloud operator MUST NEVER hold plaintext access to customer secrets, `DEK`s, `CK`s, `USK`s, or any organizational recovery key.
2. **Corporate Business Continuity & Legal Discovery**: If an engineer leaves abruptly, loses their device/passkey, or becomes incapacitated, the enterprise cannot permanently forfeit production cloud root credentials, signing keys, or regulated financial records.
3. **Operational Ergonomics vs. Executive Quorum**: Individual user lockouts occur weekly in large enterprises, whereas catastrophic root-key recovery or crown-jewel legal discovery is rare. Forcing an air-gapped 3-of-5 executive threshold ceremony for every forgotten employee password destroys operational usability; conversely, giving a single IT helpdesk administrator unrestricted recovery over crown-jewel secrets destroys insider-threat isolation.
4. **Silent Share Rot & Post-Quantum Seed Compatibility**: Traditional non-verifiable Shamir Secret Sharing (SSS) allows corrupted shares (bit-rot, transcription errors, or malicious tampering) to remain undetected for years until an emergency ceremony fails catastrophically. Furthermore, the secret-sharing mathematics MUST losslessly split arbitrary **256-bit** seeds (`ORPK_SEED`) so the exact same VSS engine derives both `CS-01` (`X25519`) and `CS-02` (`X-Wing` `GenerateKeyPairDerand(seed)`) asymmetric recovery keys cleanly without modulo bias or discrete-logarithm weakening.

How should RusticStack Core design its organizational recovery escrow and threshold secret-sharing architecture?

---

## 2. Decision Drivers

- **Zero Server-Side Plaintext**: `ORPK_SEED` and `ORPK` MUST NEVER exist in plaintext at rest anywhere (neither on `rsv-server` nor on any single custodian device).
- **Non-Interactive Share Verification**: Custodians MUST be able to verify share integrity periodically (e.g., quarterly drills) without communicating with each other and without reconstructing `ORPK_SEED`.
- **Two-Tier Operational Split**: Routine individual user lockouts on `standard` collections MUST be recoverable without invoking the executive quorum, while `root_quorum_only` crown-jewel collections MUST remain mathematically unreachable by daily helpdesk recovery keys.
- **Zero Modulo Bias & Full 126-Bit Commitment Hiding**: Splitting a 256-bit seed over Ristretto255 ($\ell \approx 2^{252.5}$) MUST avoid entropy truncation AND MUST defeat Pollard's Kangaroo ($2^{64}$) attacks on public commitments.
- **Post-Quantum HNDL Resilience**: Stored ceremony data in `vault.tenant_vss_ceremonies` MUST NOT allow a future Cryptographically Relevant Quantum Computer (CRQC) dumping the database to recover `ORPK_SEED` via Shor's algorithm on public elliptic-curve commitments.
- **Proactive Resharing**: Custodians MUST be able to refresh polynomial shares on a schedule (defeating slow mobile adversaries) without changing `ORPubK` or re-encrypting millions of `vault_item_revisions`.
- **Pure-Rust Ecosystem Alignment**: MUST integrate cleanly with `vsss-rs` `6.0`, Rust 2024 Edition (MSRV `1.94.0`), `secrecy` `0.10`, and `zeroize` `1.9`.

---

## 3. Considered Options

### Option A: Pure Zero-Knowledge Without Organizational Escrow
- Users hold personal Recovery Kits only; no organizational root key exists.
- *Pros*: Simplest cryptography; minimal key graph complexity.
- *Cons*: **Dealbreaker for enterprise adoption.** A departing or incapacitated admin holding sole ownership of a critical collection causes permanent, unrecoverable data loss; fails enterprise SOC 2 / ISO 27001 availability and e-discovery mandates.

### Option B: Cloud KMS / Server-Held Organizational Escrow Key
- Each `DEK` is wrapped by an AWS KMS / GCP KMS / HashiCorp Vault key controlled by the server or tenant cloud IAM.
- *Pros*: Easy daily recovery; no custodian ceremony tooling.
- *Cons*: **Violates zero-knowledge security guarantees.** A single compromised IAM role, cloud provider subpoena, or rogue cloud admin can silently unwrap all tenant secrets without quorum visibility or tamper-evident ceremony receipts.

### Option C: Non-Verifiable Shamir Secret Sharing (SSS) over $\mathbb{F}_{2^8}$ (GF(256))
- Byte-wise Shamir splitting of 32-byte `ORPK_SEED` over `GF(256)`.
- *Pros*: Trivial byte-aligned splitting; information-theoretically hiding even against quantum computers (no elliptic curve commitments).
- *Cons*: **No non-interactive verifiability.** A custodian cannot confirm their offline share is intact without gathering $t$ custodians to reconstruct the live secret! Corrupted or maliciously forged shares are only discovered during a crisis, and Herzberg proactive refresh cannot be cryptographically verified against dishonest participants.

### Option D: Naive Unpadded 2×128-Bit Feldman VSS or Pedersen VSS over Ristretto255
- *Sub-option D1 (Unpadded 2×128-bit Feldman)*: Embed low/high 128-bit chunks $c_0, c_1 \in [0, 2^{128})$ directly as constant terms of two Ristretto255 polynomials with public $C_{k,0} = c_k \cdot G$.
  - *Fatal Flaw*: Because $c_k < 2^{128}$, an adversary holding $C_{k,0}$ can execute **Pollard's Kangaroo algorithm** in $O(\sqrt{2^{128}}) = O(2^{64})$ group operations—computationally feasible for a well-funded attacker!
- *Sub-option D2 (Pedersen VSS)*: Commit via $C_{k,0} = c_k \cdot G + r_k \cdot H$ with two independent blinding polynomials.
  - *Pros*: Information-theoretic hiding of $c_k$ even against CRQC.
  - *Cons*: **Doubles every custodian's share size** (must store both $f_k(i)$ and blinding evaluation $h_k(i)$ = 128 bytes of secret share material instead of 64 bytes), complicates paper/QR/smartcard custodian UX, and requires custom Pedersen ceremony state outside standard single-polynomial Feldman workflows.

### Option E (CHOSEN): Hybrid Dual-Tier Escrow (`ORPubK` + Scoped `DRPubK`) + Padded 2×128-Bit Feldman VSS over Ristretto255 with Encrypted Commitments
- **Dual-Tier Asymmetric Escrow**:
  - `ORPubK` / `ORPK` (Organization Root Recovery Keypair) escrows EVERY item `DEK` across all collections.
  - `DRPubK` / `DRPK` (Delegated Recovery Keypair, itself escrowed under `ORPubK`) escrows `DEK`s ONLY for `standard` tier collections and is **cryptographically forbidden** (enforced via client fail-closed API, server schema check, and Canonical AAD CBOR key `10`) on `root_quorum_only` crown-jewel collections.
- **2×128-Bit Chunk Splitting with 124-Bit High-Order CSPRNG Scalar Padding (`vsss-rs` 6.0)**:
  - Split 256-bit `ORPK_SEED` into $\text{chunk}_0, \text{chunk}_1 \in \{0,1\}^{128}$.
  - Construct two 252-bit scalars $s_k = \text{LE}(\text{chunk}_k) + 2^{128} \cdot r_k < 2^{252} < \ell$ where $r_k \xleftarrow{\$} [0, 2^{124})$ is fresh CSPRNG padding.
  - Run standard Feldman VSS (`vsss-rs` 6.0) over Ristretto255 on $s_0, s_1$ with default `3`-of-`5` threshold ($2 \le t \le n \le 255$).
  - Upon reconstruction, discard upper 124 padding bits and extract $\text{ORPK\_SEED} = B_0[0..16] \parallel B_1[0..16]$.
- **Custodian-Encrypted Commitments (HNDL Defense)**:
  - Store `SHA-256(ceremony_transcript)` in plaintext in `vault.tenant_vss_ceremonies` for audit immutability, while HPKE-encrypting raw Ristretto255 points $\{C_{k,j}\}$ individually to each custodian's `UPK` so an untrusted database dump NEVER exposes raw EC points to a future Shor's-algorithm CRQC.
- **Proactive Share Refresh**:
  - Support Herzberg zero-polynomial addition ($g_k(0) = 0$) preserving $s_k$ and $C_{k,0}$ while invalidating any pre-refresh shares.

---

## 4. Decision Outcome

**Chosen Option: Option E** — Hybrid Dual-Tier Asymmetric Escrow (`ORPubK` + scoped `DRPubK`) backed by **2×128-Bit Padded Feldman VSS (`vsss-rs` 6.0) over Ristretto255** with custodian-encrypted commitments and Herzberg proactive resharing.

### Mathematical & Architectural Justification

1. **Eliminates Pollard's Kangaroo ($2^{64} \to 2^{126}$) With Zero Share Bloat**:
   Because $\ell = 2^{252} + 27742317777372353535851937790883648493 > 2^{252}$, embedding `chunk_k` in bits `0..127` and CSPRNG padding `r_k` in bits `128..251` produces a scalar $s_k$ uniformly distributed over $[0, 2^{252}) \subset \mathbb{F}_\ell$. This guarantees:
   - Zero modular reduction and zero modulo bias;
   - Full $\Theta(\sqrt{2^{252}}) = \Theta(2^{126})$ DLP security for $C_{k,0} = s_k \cdot G$ without Pedersen's $2\times$ share expansion;
   - Lossless 256-bit `ORPK_SEED` recovery feeding BOTH `CS-01` (`HKDF-SHA256` -> X25519) and `CS-02` (`HKDF-SHA256` -> X-Wing `GenerateKeyPairDerand`).
2. **Defeats HNDL Quantum Exposure of Feldman Commitments**:
   Encrypting $\{C_{k,j}\}$ under custodian `UPK`s (migrating automatically to `CS-02` X-Wing) while publishing only the SHA-256 commitment digest in `vault.tenant_vss_ceremonies` eliminates the classic complaint that Feldman commitments leak secrets to a future quantum computer scraping server backups.
3. **Solves Real-World Enterprise Operations**:
   Separating `standard` (`ORPubK` + `DRPubK`) from `root_quorum_only` (`ORPubK` ONLY) lets Helpdesk/Security Operations resolve 95%+ of routine employee lockouts in minutes while guaranteeing cryptographic executive-quorum isolation for production signing keys and crown jewels.

---

## 5. Cryptographic and Engineering Consequences

### Positive Consequences
- **Zero-Knowledge Preserved Under Enterprise Recovery**: `rsv-server` holds only HPKE ciphertexts wrapped to `ORPubK`/`DRPubK` and SHA-256 ceremony digests—never recovery private keys.
- **Offline Drill Verification**: Custodians can verify share integrity via `rsv-compliance-cli verify-share` quarterly without reconstructing `ORPK_SEED` or convening other custodians.
- **Seamless Post-Quantum Readiness**: Splitting a generic 256-bit `ORPK_SEED` works identically when upgrading `ORPubK` from `CS-01` (X25519) to `CS-02` (X-Wing), because X-Wing derives its entire ML-KEM-768 + X25519 keypair deterministically from a 32-byte seed!
- **Mobile Adversary Resistance**: Herzberg proactive refresh rotates custodian shares on a 90–180 day cadence with zero database re-encryption.

### Negative Consequences & Mitigations
- **Increased Item Storage Overhead**: Storing dual escrow envelopes (`ORPubK` + `DRPubK`) adds ~`180 B` per item revision in `CS-01` and ~`2.4 KiB` in `CS-02` (X-Wing `1120 B` encapped key per wrap).
  - *Mitigation*: Enterprise secret items are small (`< 16 KiB`), and `DEK`-level wrapping is tiny relative to PostgreSQL TOAST/SSD capacities; `root_quorum_only` items omit `DRPubK` entirely.
- **Ceremony UX Complexity**: Air-gapped `3`-of-`5` ceremonies require disciplined operational runbooks.
  - *Mitigation*: Provide deterministic, read-only `rsv-compliance-cli` recovery station tooling with QR/smartcard share import, automatic Feldman share pre-verification, and signed ceremony audit receipts.
- **Custodian Compromise of Encrypted Commitments Under CRQC**: If a malicious custodian leaks raw $\{C_{k,j}\}$ AND a CRQC later breaks Ristretto255 DLP, `ORPK_SEED` could be recovered from $C_{k,0}$.
  - *Mitigation*: Enforce `L3_HARDWARE_ENCLAVE` for all custodians, rotate `orpk_epoch` whenever any custodian departs untrusted, and preserve trait extensibility in `rsv-vss` for future hash/lattice VSS commitments if long-term public PQ verifiability is ever required.

---

## 6. Verification and Compliance Criteria

An implementation of `ADR-0001` is verified ONLY when CI passes all gates below:

1. **Exhaustive Quorum Matrix**: For $(t, n) \in \{(2, 3), (3, 5), (4, 7)\}$, every $\binom{n}{t}$ share subset MUST reconstruct bit-exact `ORPK_SEED`; every subset of size $t - 1$ MUST fail with `VssError::InsufficientShares`.
2. **Padding & Bias Audit**: Over `10,000` randomized splits, verify `(s_k.to_bytes()[31] & 0xF0) == 0` on `100%` of scalars, `ORPK_SEED` round-trips bit-identically, and upper 124 padding bits exhibit full CSPRNG entropy (NIST/chi-squared uniformity check).
3. **Constant-Time Verification**: Share verification MUST execute `y_{k,i} * G` via constant-time basepoint multiplication (`RistrettoPoint::mul_base`).
4. **Proactive Refresh Integrity**: Refreshed shares MUST verify against updated commitments $C'_{k,j}$ (with $C'_{k,0} == C_{k,0}$ asserted), reconstruct identical `ORPK_SEED`, and reject any mixed old/new share combinations.
5. **Dual-Tier Enforcement**: Attempting to wrap a `root_quorum_only` `DEK` under `DRPubK` MUST fail closed in both `rsv-crypto` (`CryptoError::PolicyViolation`) and `rsv-server` (HTTP `400`/`422`), and mutating `escrow_tier` in DB metadata MUST trigger `CryptoError::AadMismatch` on client open.
6. **Commitment Confidentiality Audit**: Database schema inspection on `vault.tenant_vss_ceremonies` MUST confirm no plaintext Ristretto255 commitment point column exists—only `commitment_digest` (`BYTEA(32)`) and per-custodian HPKE-wrapped commitment envelopes.
