# Devin Agent Playbook 08: Key Transparency, Zero-Knowledge SSO/SCIM, Native SSH Agent, Synced Passkeys & Developer CLI

> **Playbook ID**: `RSV-PLAYBOOK-08`
> **Agent Role**: Enterprise Identity, Key Transparency & Developer Secrets Systems Engineer
> **Active Milestones**: `M5-B` (Enterprise Identity & Developer Secrets Extension Pack, immediately following `m4-clients-green`) and `M6` Integration
> **Target Toolchain**: Rust 2024 Edition (MSRV `1.94.0`) + `wasm32-unknown-unknown` + PostgreSQL 17/18

---

## 1. Mission & Exclusive Ownership

Your mission is to implement RusticStack Core's enterprise identity and developer secrets capabilities across two tightly bounded tracks:

1. **Track A — Auditable Key Transparency, Zero-Knowledge Enterprise SSO & Blind SCIM 2.0 (`SPEC-11`, `ADR-0009`)**:
   - Deterministic CBOR `KeyDirectoryEntry` verification, witness-cosigned C2SP `tlog-tiles` KT proofs, 60-digit/6-word EFF SAS safety numbers, and periodic background self-monitoring (`kt_self_audit`) in `rsv-audit` / `rsv-graph` / `rsv-daemon` / `rsv-wasm`.
   - PostgreSQL extension migrations for `vault.key_transparency_log` (64-way HASH, append-only, `FORCE RLS`), `vault.key_transparency_checkpoints`, and `vault.scim_pending_intents`.
   - Zero-knowledge OIDC 1.0 (PKCE `S256` + `nonce`) and XXE/XSW-hardened SAML 2.0 endpoints (`/api/v1/auth/sso/*`), 300s one-time Trusted Device Cross-Signing mailboxes (`/api/v1/auth/device-enroll/*`), and blind RFC 7643/7644 `/scim/v2/*` endpoints executing `< 100 ms` logical revocation + intent queueing with zero key custody.
2. **Track B — Native RFC 9987 SSH Agent, Synced Enterprise Passkeys, Developer CLI (`rsv-cli`) & OIDC Machine Identities (`SPEC-12`, `ADR-0010`)**:
   - Native RFC 9987 SSH Agent listener inside `rsv-daemon` (`rsv-agent.sock` / `\\.\pipe\openssh-ssh-agent`) supporting `ssh-ed25519`, silicon/locked `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com`, OpenSSH certs, Git `SSHSIG` signing (`gpg.format = ssh`), `session-bind@openssh.com` forwarding detection, native GPUI biometric approval sheet, and `ssh.sign` Merkle audit emission.
   - `passkey_v1` encrypted vault item schema (`BE=1, BS=1, signCount=0`) + Chrome MV3 Extension -> `rsv-daemon` virtual WebAuthn mediation with strict PSL `eTLD+1` / `rpId` anti-phishing validation and per-signature human non-repudiation (`passkey.assert`).
   - Developer & CI binary `crates/rsv-cli/` (`#![forbid(unsafe_code)]`) implementing `rsv://` URI parsing, zero-disk `rsv run` child `envp` injection + streaming Aho-Corasick `--mask-output` redactor, `rsv-ssh-sign`, and `vault.machine_identities` federated OIDC Workload Identity + `MIK` Proof-of-Possession read-only (`permission_mask = 0x01`) Blind RBAC resolution.

### Exclusive Write Ownership
- `crates/rsv-audit/src/key_transparency.rs` (pure `no_std + alloc` KT proof/entry/SAS module)
- `crates/rsv-server/migrations/` (additive migration files for `vault.key_transparency_log`, `vault.key_transparency_checkpoints`, `vault.scim_pending_intents`, `vault.machine_identities`, and `machine_to_collection` edge constraint)
- `crates/rsv-server/src/kt/`, `crates/rsv-server/src/sso/`, `crates/rsv-server/src/scim/`, `crates/rsv-server/src/machines/`
- `crates/rsv-daemon/src/ssh_agent/`, `crates/rsv-daemon/src/passkey/`, `crates/rsv-daemon/src/kt_monitor.rs`
- `crates/rsv-desktop/src/ui_gpui/approval_sheet.rs` (SSH, Passkey, SAS Device Enrollment & `rsv run` native approval modals)
- `crates/rsv-cli/` (developer workstation & headless CI CLI binary)
- `clients/extension/src/passkey/` (MV3 virtual WebAuthn mediation & Closed Shadow DOM passkey picker)
- `test-vectors/v1/kt_directory_proofs.kat.{json,cbor}`, `test-vectors/v1/rsv_uri_and_ssh_agent.kat.json`

### Owned Formal Invariants
`INV-001`, `INV-002`, `INV-006`, `INV-007`, `INV-010`, `INV-011`, `INV-014`, `INV-018`, `INV-023`, **`INV-025`**, **`INV-026`**, **`INV-027`**, **`INV-028`**, **`INV-029`**

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context:
1. [`AGENTS.md`](../../AGENTS.md)
2. [`agents/CRATE-CONTRACTS.md`](../CRATE-CONTRACTS.md)
3. [`agents/BUILD-DAG.md`](../BUILD-DAG.md)
4. [`specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md`](../../specs/11-KEY-TRANSPARENCY-SSO-AND-SCIM.md)
5. [`specs/12-DEVELOPER-SECRETS-SSH-PASSKEYS-AND-CLI.md`](../../specs/12-DEVELOPER-SECRETS-SSH-PASSKEYS-AND-CLI.md)
6. [`adrs/ADR-0009-key-transparency-and-blind-scim-sso.md`](../../adrs/ADR-0009-key-transparency-and-blind-scim-sso.md)
7. [`adrs/ADR-0010-native-ssh-agent-and-synced-passkeys.md`](../../adrs/ADR-0010-native-ssh-agent-and-synced-passkeys.md)
8. [`schemas/postgresql-schema.sql`](../../schemas/postgresql-schema.sql) (RLS InitPlan pattern, 64-way HASH partitions, immutability triggers)
9. [`specs/08-API-AND-WIRE-PROTOCOLS.md`](../../specs/08-API-AND-WIRE-PROTOCOLS.md) & [`specs/07-OMNI-CLIENT-ARCHITECTURE.md`](../../specs/07-OMNI-CLIENT-ARCHITECTURE.md)

---

## 3. Strict Boundaries & Forbidden Actions

1. **ZERO `unsafe` Code (`INV-010`)**: `rsv-audit`, `rsv-server`, `rsv-daemon`, `rsv-desktop`, `rsv-wasm`, and `rsv-cli` MUST declare `#![forbid(unsafe_code)]`. All OS memory locking (`LockedSecretBox`) and silicon signing (`HDIK`/`HDSK`/P-256 SSH) MUST invoke audited APIs in `rsv-mem` and `rsv-enclave`.
2. **NEVER Build a Key Connector or IdP Key Escrow (`INV-026`)**: OIDC/SAML handlers in `rsv-server` MUST NEVER accept, derive, store, or release `MUK`, `USK`, `UIK` private keys, `TK`, `CK`, or `DEK`.
3. **NEVER Bypass KT Pre-Wrap Checks (`INV-025`)**: Any code path wrapping `TK`/`CK`/`DEK` to a recipient `UPK` MUST require a verified `VerifiedKtRecipient` proof token produced by `rsv-audit::key_transparency` (type-state enforcement).
4. **NEVER Let SCIM Touch Cryptographic Keys (`INV-027`)**: `/scim/v2/*` routes MUST accept ONLY SCIM-scoped bearer tokens (rejected on `/api/v1/*` with `403 SCIM_SCOPE_VIOLATION`), MUST NEVER wrap/unwrap keys, and MUST strictly write logical status + `vault.scim_pending_intents` rows inside `TenantScopedTx`.
5. **NEVER Write Plaintext SSH Keys or `.env` Files to Disk (`INV-028`, `INV-029`)**: `rsv-daemon` MUST reject `SSH_AGENTC_ADD_IDENTITY` by default and NEVER write `~/.ssh/id_*` private keys; `rsv-cli` (`rsv run`) MUST NEVER create temporary `.env` files in the working directory or `/tmp`.
6. **NEVER Expose Passkey PKCS#8 Private Keys to Browser JS**: In Mode A (Daemon-Backed), passkey signing executes strictly inside `rsv-daemon` (`rsv-mem`); browser extension JS handles ONLY public descriptors, `clientDataJSON`, and signed assertions over chunked (`<= 768 KiB`) HPKE Native Messaging (`INV-021`).
7. **NEVER Accept Unvalidated `rpId` or `session-bind` Forwarding**: Reject public suffixes (`github.io`, `co.uk`, `amazonaws.com`) in WebAuthn mediation, bypass interception on RusticStack's own Web SPA origin, and ALWAYS force fresh biometric UV on forwarded SSH agent requests (`is_forwarding == 1`).
8. **NEVER Weakly Grant Machine Identities**: Enforce `permission_mask = 1` (`READ` ONLY) on every `machine_to_collection` edge in both `rsv-server` and PostgreSQL check constraints; reject static non-OIDC machine bearer tokens.
9. **Tier-0 Firewall Preserved**: Additions in `rsv-audit/src/key_transparency.rs` MUST remain `no_std + alloc` and compile cleanly to `wasm32-unknown-unknown`.

---

## 4. Ordered Implementation Checklist

### Phase A — Key Transparency Core & Schema Extensions (`SPEC-11` Part A + §5)
1. Implement `crates/rsv-audit/src/key_transparency.rs` (`no_std + alloc`):
   - Canonical RFC 8949 CBOR encoder/decoder for `KeyDirectoryEntry` (keys `1..=16`), domain-separated `entry_tbs_digest` (`"rsv:kt:entry:sig:v1"`), `hdik_root_hash` (`"rsv:kt:hdik-root:v1"`), and RFC 9162 leaf hashing (`0x00 || full_entry_cbor`).
   - `verify_kt_grant_bundle()` checking witnessed C2SP `signed-note` checkpoint, `rsv-kt-map-root`, RFC 9162 consistency proof from pinned checkpoint, inclusion proof at `kt_index`, and `UIK` continuity signatures — returning a type-state `VerifiedKtRecipient` required by `rsv-graph` edge wrapping (`INV-025`).
   - Deterministic 60-digit numeric safety number (`"rsv:kt:num60:v1"`), 6-word EFF Diceware SAS (`"rsv:kt:sas-words:v1"`), and `rsv-kt://v1/...` QR encoder/parser.
   - Generate deterministic KATs in `test-vectors/v1/kt_directory_proofs.kat.{json,cbor}`.
2. Author additive SQL migration in `crates/rsv-server/migrations/`:
   - Create `vault.key_transparency_log` (64 HASH partitions `p00..p63`, append-only `prevent_immutable_mutation()` + leaf `TRUNCATE` triggers, `FORCE RLS`), `vault.key_transparency_checkpoints` (append-only, `FORCE RLS`), `vault.scim_pending_intents` (`FORCE RLS`), and `vault.machine_identities` (`FORCE RLS`).
   - Add `'machine_to_collection'` to `vault.graph_edge_type` plus check constraint enforcing `edge_type <> 'machine_to_collection' OR permission_mask = 1`.
3. Implement `/api/v1/kt/*` routes in `crates/rsv-server/src/kt/` (strictly via `TenantScopedTx` + explicit `WHERE tenant_id = $1`) and background `kt_self_audit()` monitor in `rsv-daemon/src/kt_monitor.rs` and `rsv-wasm`.

### Phase B — Zero-Knowledge Enterprise SSO & Blind SCIM 2.0 (`SPEC-11` Parts B & C)
4. Implement `crates/rsv-server/src/sso/`:
   - OIDC Core 1.0 Authorization Code + PKCE `S256` + `nonce` + JWKS signature verification (`RS256`/`ES256`/`EdDSA`; reject `alg=none` & `HS*`).
   - SAML 2.0 XML-DSig verifier with XXE disabled, `exc-c14n`, signed-subtree-only extraction (XSW defense), replay cache, and `NotBefore`/`NotOnOrAfter` enforcement.
   - Ephemeral 300s one-time Trusted Device Cross-Signing mailbox (`/api/v1/auth/device-enroll/{start,approve,claim}`) with atomic `DELETE ... RETURNING` claim and 6-word SAS binding (`"rsv:enroll:sas:v1"`).
5. Implement `crates/rsv-server/src/scim/`:
   - Dedicated SCIM middleware enforcing SCIM-only token scope (`403 SCIM_SCOPE_VIOLATION` on `/api/v1/*`) and single-tenant RLS binding.
   - RFC 7643/7644 `/scim/v2/Users` and `/scim/v2/Groups` handlers performing immediate (`< 100 ms`) JWT/refresh/WebSocket revocation on `active=false` or removal while queuing `vault.scim_pending_intents` rows and emitting `scim_intent_queued` sync events.
   - Admin `/api/v1/scim/intents` listing & atomic `/complete` execution endpoints.

### Phase C — Native RFC 9987 SSH Agent & Synced Enterprise Passkeys (`SPEC-12` Parts A & B)
6. Implement `crates/rsv-daemon/src/ssh_agent/`:
   - OS transport listeners: Linux `$XDG_RUNTIME_DIR/rusticstack/rsv-agent.sock` (`0600`), macOS App Group `agent.sock` (`0600`), Windows `\\.\pipe\openssh-ssh-agent` / dedicated single-user SID SDDL pipe (`PIPE_REJECT_REMOTE_CLIENTS`).
   - RFC 9987 codec with `max_frame_bytes = 262_144`, `SSH_AGENTC_REQUEST_IDENTITIES (11)`, `SSH_AGENTC_SIGN_REQUEST (13)`, `SSH_AGENTC_EXTENSION (27)` (`session-bind@openssh.com`), and default rejection of `SSH_AGENTC_ADD_IDENTITY (17)`.
   - Payload classifier distinguishing RFC 4252 userauth, Git `SSHSIG` (`namespace == "git"`), and unclassified payloads; peer provenance inspector (`SO_PEERCRED` / `LOCAL_PEERTOKEN` / `GetNamedPipeClientProcessId`); native GPUI approval sheet integration in `rsv-desktop`; signing in `rsv-mem::LockedSecretBox` or silicon P-256 enclave; `ssh.sign` `AuditEnvelope` submission.
7. Implement synced enterprise passkeys (`passkey_v1`) in `crates/rsv-daemon/src/passkey/` and `clients/extension/src/passkey/`:
   - CBOR `passkey_v1` codec (`ES256`/`EdDSA`/`RS256`, `BE=1`, `BS=1`, `signCount=0`).
   - Chrome MV3 `navigator.credentials.{create,get}` mediation with hardware-key escape hatch, RusticStack SPA bypass, strict PSL `eTLD+1` + HTTPS + `crossOrigin` verifier (`INV-023`), chunked HPKE Native Messaging offload (`<= 768 KiB`), and synchronous `passkey.assert` `HDIK`+`UIK` Merkle audit commitment for shared team passkeys.

### Phase D — Developer CLI (`rsv-cli`) & OIDC Workload Machine Identities (`SPEC-12` Part C)
8. Implement `crates/rsv-cli/` (`#![forbid(unsafe_code)]`):
   - Strict RFC 5234 ABNF `rsv://` parser (`collection/item/field[?version=&epoch=&encoding=]`) with zero plaintext slug transmission to `rsv-server`.
   - `rsv run --env-file=... [--mask-output] -- <cmd>`: OS IPC resolution from `rsv-daemon`, direct child `envp` injection (zero disk `.env`), `ZeroizeOnDrop` parent buffer scrub, streaming Aho-Corasick stdout/stderr redactor handling chunk boundaries + raw/base64/URL-encoded variants, plus `rsv inject --memfd` (Linux) and `rsv-ssh-sign` Git signing helper.
   - `rsv ci run`: headless OIDC Workload Identity exchange (`POST /api/v1/auth/oidc/machine/exchange` with OIDC JWT + `MIK` PoP signature), `rsv-mem` locked decryption of `machine_to_collection` read-only edges, `envp` injection, `MIK`-signed `AuditEnvelope`, and full arena wipe.
9. Implement `crates/rsv-server/src/machines/`:
   - `/api/v1/machines` CRUD + `/api/v1/auth/oidc/machine/exchange` verifying pinned IdP JWKS, `iss`, `aud`, `sub` pattern, `oidc_required_claims`, `exp`/`nbf`, and `MIK` PoP signature, minting `<= 300s` non-renewable read-only tokens.

---

## 5. Exact Verification Commands & Exit Criteria

ALL commands below MUST exit with code `0` before opening your PR:

```bash
# 1. Workspace lint, formatting & strict unsafe firewall
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 clippy --workspace --all-targets -- -D warnings
for f in crates/rsv-audit/src/lib.rs crates/rsv-server/src/lib.rs crates/rsv-daemon/src/lib.rs crates/rsv-cli/src/main.rs; do
    grep -q '#!\[forbid(unsafe_code)\]' "$f"
done

# 2. Tier-0 no_std + WASM firewall preserved for KT module
cargo +1.94.0 check -p rsv-audit -p rsv-graph -p rsv-types --no-default-features --target wasm32-unknown-unknown

# 3. Key Transparency KATs, rogue-UPK substitution & split-view self-monitor tests (INV-025)
cargo +1.94.0 test -p rsv-audit --features kat-deterministic key_transparency
cargo +1.94.0 test -p rsv-server --test kt_rogue_upk_substitution -- --nocapture
cargo +1.94.0 test -p rsv-daemon --test kt_self_monitor_shadow_key -- --nocapture

# 4. Zero-Knowledge SSO ("Golden SAML" negative test) & Blind SCIM instant revocation (INV-026, INV-027)
cargo +1.94.0 test -p rsv-server --test sso_auth_ne_decrypt_security -- --nocapture
cargo +1.94.0 test -p rsv-server --test scim_blind_revocation_and_scope -- --nocapture

# 5. PostgreSQL 17/18 FORCE RLS & 64-way HASH partition pruning on extension tables (INV-006, INV-007)
cargo +1.94.0 test -p rsv-server --test rls_extension_tables_chaos -- --nocapture

# 6. RFC 9987 SSH Agent, session-bind forwarding, Git SSHSIG & zero-disk forensics (INV-028)
cargo +1.94.0 test -p rsv-daemon --test ssh_agent_rfc9987_security -- --nocapture

# 7. Synced Enterprise Passkey anti-phishing & shared-team non-repudiation audit
cargo +1.94.0 test -p rsv-daemon --test passkey_shared_nonrepudiation -- --nocapture
npm --prefix clients/extension run test:passkey-antiphishing

# 8. rsv-cli zero-disk envp injection, streaming output redactor & OIDC Machine Identity (INV-029)
cargo +1.94.0 test -p rsv-cli --test rsv_run_zero_disk_and_redactor -- --nocapture
cargo +1.94.0 test -p rsv-server --test oidc_machine_identity_security -- --nocapture

# 9. Dependency audit & license gate
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

---

## 6. Handoff & PR Contract

- **Branch Naming**: `feat/m5b-agent08-kt-sso-scim`, `feat/m5b-agent08-ssh-passkeys-cli`
- **PR Description MUST Include**:
  - Explicit Invariant Tags Verified: `[INV-001] [INV-002] [INV-006] [INV-007] [INV-010] [INV-011] [INV-014] [INV-018] [INV-023] [INV-025] [INV-026] [INV-027] [INV-028] [INV-029]`
  - `EXPLAIN (ANALYZE, FORMAT JSON)` snippet proving `Subplans Removed: 63` on `vault.key_transparency_log` and `0` rows returned when `app.current_tenant_id` is unset across all 4 extension tables.
  - Measured latency of SCIM `active=false` -> WebSocket `session_revoked` + `/api/v1` rejection (`< 100 ms`).
  - Pass evidence for rogue-server `UPK` substitution rejection, Golden-SAML zero-decryption test, forwarded SSH agent mandatory UV test, `rsv run` zero-disk `strace`/syscall verification, and OIDC Machine Identity PoP negative matrix.
- **Downstream Unblock Signal**: Merging both PRs feeds directly into Agent 07's `M6` Red-Team Chaos & Release Candidate (`M7`) gates.
