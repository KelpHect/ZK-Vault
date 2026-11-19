## Summary

Describe the specification, schema, ADR, or milestone implementation change in this pull request.

## Milestone & Invariant Traceability

- **Phase / Milestone:** `v1.0-spec` / `M0` / `M1` / `M2` / `M3` / `M4` / `M5` / `M6` / `M7`
- **Formal Invariants Covered:** `INV-___`
- **Related Specs / ADRs:** `SPEC-___`, `ADR-____`

## Checklist

- [ ] Cross-document consistency verified across `specs/`, `adrs/`, `schemas/`, `agents/`, and `AGENTS.md`
- [ ] Root `AGENTS.md` remains strictly `< 16,384` bytes (Devin Turn-0 injection window)
- [ ] No accepted ADR was mutated in place (decisions evolved via new superseding `ADR-NNNN`)
- [ ] Zero plaintext secrets, zero forbidden `unsafe` outside `rsv-mem`/`rsv-enclave`, and all required verification gates pass
- [ ] Commit messages follow Conventional Commits (`spec`, `adr`, `schema`, `agents`, `feat`, `fix`, `sec`, `test`)
