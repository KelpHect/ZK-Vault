# Contributing to RusticStack Core (`ZK-Vault`)

Thank you for contributing to **RusticStack Core (`ZK-Vault`)**. Whether you are a human systems engineer reviewing cryptographic proofs or an autonomous coding agent executing a milestone playbook, every contribution MUST uphold the repository's formal security invariants and architectural rigor.

---

## 1. Current Repository Phase

This repository is currently in its **Normative Specification Phase (`v1.0-spec`)**.

- **Allowed today:** Refinements to `specs/`, new or superseding `adrs/`, schema improvements in `schemas/`, test-vector expansions, and playbook hardening in `agents/`.
- **Deferred until Milestone `M0` kickoff:** Rust workspace scaffolding (`Cargo.toml`, `crates/`), TypeScript/Web SPA code, and Chrome Extension implementation. Do not open implementation PRs before Milestone `M0` is formally opened.

---

## 2. Specification & ADR Governance

1. **RFC-2119 Precision:** Normative clauses MUST use uppercase `MUST`, `MUST NOT`, `SHOULD`, `MAY` accurately. Avoid vague wording ("try to", "ideally", "probably").
2. **Single Source of Truth:** If you modify a table name, column, API route, error code, crate name, or cryptographic parameter, you MUST update ALL referencing documents in the same PR:
   - `AGENTS.md` (keeping total size strictly **< 16,384 bytes**)
   - Affected `specs/*.md`
   - Affected machine-readable schemas in `schemas/` (`postgresql-schema.sql`, `openapi-v1.yaml`, `ipc-native-messaging.schema.json`)
   - Affected agent playbooks in `agents/playbooks/`
3. **Immutability of Accepted ADRs:** Never rewrite an `Accepted` ADR to flip a decision. Author a new `ADR-NNNN` file and mark the superseded ADR's status accordingly.
4. **Diagram Hygiene:** All Mermaid diagrams MUST use standard GitHub-supported diagram types (`flowchart`, `sequenceDiagram`, `stateDiagram-v2`, `classDiagram`, `erDiagram`) with double-quoted labels whenever parentheses, brackets, or colons appear.

---

## 3. Autonomous Agent Implementation Guidelines (Milestones `M0`–`M7`)

When implementing milestones from this specification:

1. Read [`AGENTS.md`](AGENTS.md) and [`agents/BUILD-DAG.md`](agents/BUILD-DAG.md) first.
2. Lock strictly to [`agents/CRATE-CONTRACTS.md`](agents/CRATE-CONTRACTS.md) and your domain playbook under `agents/playbooks/`.
3. Tag every pull request with the exact Milestone ID (`M0`–`M7`) and the Formal Invariant IDs (`INV-XXX`) covered by automated tests.
4. Every PR MUST pass 100% of mandatory verification gates documented in `AGENTS.md` and `specs/10-TEST-VECTORS-AND-VERIFICATION.md` before review.

---

## 4. Commit Message Convention

We follow [Conventional Commits v1.0.0](https://www.conventionalcommits.org/):

```text
<type>(<scope>): <concise imperative summary>

[optional body explaining architectural rationale]
```

**Allowed types:** `spec`, `adr`, `schema`, `agents`, `docs`, `feat`, `fix`, `sec`, `test`, `chore`, `refactor`.

**Examples:**
- `spec(crypto): specify Feldman VSS 2x128-bit Ristretto255 chunking`
- `schema(postgres): enforce NOBYPASSRLS and append-only audit triggers`
- `adr(0007): document X-Wing SHA3-256 combiner vs TLS X25519MLKEM768`

---

## 5. Licensing

All contributions submitted to this repository are dual-licensed under **MIT OR Apache-2.0**, as specified in [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE), without any additional terms or conditions.
