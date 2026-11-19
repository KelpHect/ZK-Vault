# Security Policy — RusticStack Core (`ZK-Vault`)

## Scope

RusticStack Core (`ZK-Vault`) is an enterprise zero-knowledge secrets management specification and upcoming open-source Rust implementation. We welcome rigorous cryptographic review, formal verification feedback, and vulnerability reports against both the **Normative Specifications (`specs/`, `schemas/`, `adrs/`)** and any future implementation milestones (`M0`–`M7`).

## Reporting a Security Vulnerability or Architectural Flaw

**DO NOT open a public GitHub issue for suspected cryptographic weaknesses, RLS bypasses, memory-safety flaws, or protocol exploits.**

Instead, report vulnerabilities privately via one of the following channels:

1. **GitHub Security Advisories (Preferred):** Use the **Security → Advisories → Report a vulnerability** button on [`KelpHect/ZK-Vault`](https://github.com/KelpHect/ZK-Vault/security/advisories).
2. **Direct Maintainer Contact:** Reach out to the repository maintainer via GitHub security reporting with the subject prefix `[SECURITY][ZK-Vault]`.

### What to Include in a Report

- Affected specification section (`SPEC-01`–`SPEC-15`), ADR (`ADR-0001`–`ADR-0012`), schema, or crate/component.
- Violated formal invariant ID (`INV-001` through `INV-036`, indexed in [`specs/00-INDEX.md`](specs/00-INDEX.md) and [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md)).
- Precise attack scenario, adversary model (`ADV-01` through `ADV-07`), and concrete reproduction steps or mathematical counterexample.
- Suggested remediation or protocol hardening.

### Response Timeline

- **Acknowledgment:** Within 48 hours.
- **Triage & Severity Assessment:** Within 5 business days.
- **Specification / Patch Advisory:** Coordinated disclosure aligned with severity; credit is given to reporters upon request.

---

## Core Security Guarantees Under Review

We specifically incentivize scrutiny of the following high-value areas:

| Area | Normative Document(s) | High-Value Findings |
| :--- | :--- | :--- |
| **Cryptographic Envelopes & Combiners** | [`specs/02`](specs/02-CRYPTOGRAPHY-AND-KEY-HIERARCHY.md), [`specs/13`](specs/13-STREAMING-ATTACHMENTS-OFFLINE-SYNC-AND-MIGRATION.md) | Nonce reuse vectors, missing AAD bindings, X-Wing combiner deviations, Feldman VSS commitment/padding flaws, STREAM chunk truncation/splicing |
| **Memory Lifecycle & Hardware Enclaves** | [`specs/03`](specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md) | `mlock`/`VirtualLock` bypasses, core dump leakage, Apple SE / TPM 2.0 sealing flaws, WASM `memory.grow()` secret copies |
| **Blind RBAC & Key Transparency** | [`specs/04`](specs/04-BLIND-RBAC-ACCESS-GRAPH.md), [`specs/11`](specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md) | Post-revocation decryption windows, silent server key-substitution bypassing KT, OIDC/SAML `Auth != Decrypt` leakage, SCIM key exposure |
| **PostgreSQL RLS & Partitioning** | [`specs/05`](specs/05-MULTI-TENANT-DATABASE.md), [`postgresql-schema.sql`](schemas/postgresql-schema.sql) | Cross-tenant bleed via pooler GUC leakage, non-LEAKPROOF policy regressions, partition-pruning bypasses |
| **Verifiable Audit Ledger** | [`specs/06`](specs/06-ZERO-KNOWLEDGE-AUDIT-LEDGER.md) | Frequency-analysis deanonymization of blinded IDs, Merkle second-preimage attacks, witness split-view evasion |
| **Developer Secrets & SSH / Passkeys** | [`specs/12`](specs/12-DEVELOPER-SECRETS-SSH-PASSKEYS-AND-CLI.md) | SSH agent forwarding UV bypasses, plaintext `.env` disk leaks in `rsv run`, OIDC workload claim spoofing |
| **Omni-Client, Autofill & Org Dashboard** | [`specs/07`](specs/07-OMNI-CLIENT-ARCHITECTURE.md), [`specs/15`](specs/15-CLIENT-UI-UX-AND-ORG-DASHBOARD.md) | Cross-origin autofill exfiltration, IPC peer spoofing (`SO_PEERCRED`/Named Pipe SID), Native Messaging >1 MiB truncation, clipboard/DOM secret leaks |

---

## Explicit Out-of-Scope Threats

Per [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md), active root/ring-0 kernel compromise or physical hardware keyloggers on a currently unlocked endpoint can observe live decrypted secrets displayed to the user. While Apple Secure Enclave and TPM 2.0 prevent exfiltration of non-exportable device keys (`HDIK`/`HDSK`), no userland software can stop a compromised kernel from capturing active keystrokes or framebuffers.
