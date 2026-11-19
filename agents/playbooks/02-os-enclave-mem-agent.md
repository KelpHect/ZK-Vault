# Devin Agent Playbook 02: Hostile-OS Memory Hardening & Hardware Enclave Trust

> **Playbook ID**: `RSV-PLAYBOOK-02`
> **Agent Role**: Systems Security, OS Memory Isolation & Hardware Security Module Engineer
> **Active Milestone**: `M2-C` (Can execute immediately after `m0-contracts-frozen` in parallel with `M1`!)
> **Target Toolchain**: Rust 2024 Edition (MSRV `1.94.0`) — Native Linux, macOS, Windows

---

## 1. Mission & Exclusive Ownership

Your mission is to engineer RusticStack Core's **only two crates permitted to contain audited `unsafe` OS FFI code**:
1. `rsv-mem`: Hostile-OS secret memory isolation (`LockedSecretBox<T>`, page-aligned allocations flanked by `PROT_NONE`/`PAGE_NOACCESS` guard pages, `mlock`/`VirtualLock`, `MADV_DONTDUMP`/`PR_SET_DUMPABLE(0)`, Windows `CryptProtectMemory` + process DACL, volatile zeroize-on-drop).
2. `rsv-enclave`: Two-Tier Hardware Trust (`HardwareKeyProvider`) isolating non-exportable **NIST P-256** `HDIK`/`HDSK` keys inside Apple Secure Enclave, Linux TPM 2.0 (`tss-esapi`), and Windows CNG/PCPKSP, with an explicitly tagged `Tier2SoftwareFallback`.

### Exclusive Write Ownership
- `crates/rsv-mem/`
- `crates/rsv-enclave/`

### Owned Formal Invariants
`INV-010`, `INV-011`, `INV-012`, `INV-013`

---

## 2. Required Reading List (Bounded Context Load)

Load ONLY these documents into your session context:
1. [`AGENTS.md`](../../AGENTS.md) (Turn-0 guardrails — pay special attention to Rules 2, 5, and 6!)
2. [`agents/CRATE-CONTRACTS.md`](../CRATE-CONTRACTS.md) (§2, §3.6, §4, §5 `unsafe` containment policy)
3. [`agents/BUILD-DAG.md`](../BUILD-DAG.md) (Milestone `M2-C`)
4. [`specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md`](../../specs/03-MEMORY-SAFETY-AND-HARDWARE-TRUST.md)
5. [`specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md`](../../specs/09-THREAT-MODEL-AND-FORMAL-INVARIANTS.md) (§2 `ADV-03`, `ADV-04`; §4 `INV-010`–`INV-013`; §6 honest kernel boundary)
6. [`specs/10-TEST-VECTORS-AND-VERIFICATION.md`](../../specs/10-TEST-VECTORS-AND-VERIFICATION.md) (§3.2 Part A, §3.5)
7. [`adrs/ADR-0004-two-tier-hardware-enclave-p256-delegation.md`](../../adrs/ADR-0004-two-tier-hardware-enclave-p256-delegation.md)

---

## 3. Strict Boundaries & Forbidden Actions

1. **Audited `unsafe` Hygiene (`INV-010`)**:
   - Both `rsv-mem/src/lib.rs` and `rsv-enclave/src/lib.rs` MUST declare `#![deny(unsafe_op_in_unsafe_fn)]`.
   - Isolate ALL `unsafe` OS calls inside `src/platform/{linux,macos,windows}.rs`.
   - Every single `unsafe { ... }` block MUST have an immediately preceding `// SAFETY:` proof comment detailing pointer validity, alignment, ownership, and OS syscall invariants.
2. **NO Hardware Security Theater (`INV-013`, `ADR-0004`)**:
   - Apple Secure Enclave natively isolates **NIST P-256 ONLY** (never Ed25519 or X25519). TPM 2.0 widely supports NIST P-256/RSA, not Ed25519.
   - Implement Two-Tier Hardware Trust strictly: non-exportable silicon **NIST P-256** `HDIK` (ECDSA signing) and `HDSK` (ECIES/TPM sealing) protect software vault keys. NEVER claim or fake hardware Ed25519 inside Apple SE.
3. **Explicit Tier-2 Tagging (`INV-013`)**: `SoftwareFallbackProvider` MUST return `HardwareTrustTier::Tier2SoftwareFallback` and NEVER masquerade as Tier-1 hardware.
4. **Tier-1 Dependency Firewall**: NEVER add `tokio`, `sqlx`, `axum`, `gpui`, `reqwest`, `hyper`, or `wasm-bindgen` to `rsv-mem` or `rsv-enclave`.
5. **No Secret Printing (`INV-012`)**: `LockedSecretBox<T>` MUST print `"[REDACTED]"` for `Debug`, MUST NOT implement `Display`, and MUST NOT implement `Clone` unless explicitly returning a freshly allocated locked box.
6. **Zero Silent Lock Failures (`INV-011`)**: If `mlock`/`VirtualLock` or guard-page allocation fails (e.g., `RLIMIT_MEMLOCK` exceeded), `LockedSecretBox::try_new` MUST return `Err(MemError::MemoryLockFailed)` — NEVER silently fall back to unlocked heap memory!

---

## 4. Ordered Implementation Checklist

### Part A — `crates/rsv-mem/`
1. Implement `harden_process() -> Result<ProcessHardeningReport, MemError>`:
   - **Linux**: `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, {0, 0})`.
   - **macOS**: `setrlimit(RLIMIT_CORE, {0, 0})`, `ptrace(PT_DENY_ATTACH, ...)` gated on `#[cfg(not(debug_assertions))]` so debuggers still work in local dev while release binaries lock down.
   - **Windows**: `SetProcessMitigationPolicy` (disable dynamic code / strict handle checks as supported), restrictive owner-only process DACL denying `PROCESS_VM_READ` to non-owner tokens.
2. Implement `LockedSecretBox<T: Zeroize>`:
   - Compute OS page size (`sysconf(_SC_PAGESIZE)` / `GetSystemInfo`), allocate `(data_pages + 2) * page_size` via `mmap(MAP_PRIVATE | MAP_ANONYMOUS)` (Unix) or `VirtualAlloc(MEM_COMMIT | MEM_RESERVE)` (Windows).
   - Mark leading page `[base .. base + page_size]` and trailing page `[base + (1 + data_pages) * page_size .. end]` as `PROT_NONE` (`mprotect`) / `PAGE_NOACCESS` (`VirtualProtect`).
   - Lock payload pages via `mlock` (Unix) / `VirtualLock` (Windows).
   - On Linux, apply `madvise(MADV_DONTDUMP)` (and `MADV_WIPEONFORK` where kernel supports it, checking `EINVAL` gracefully).
   - On Windows, provide `CryptProtectMemory` sealed-at-rest helper for dormant locked sessions.
   - On `Drop`: invoke `zeroize::Zeroize::zeroize` + `core::sync::atomic::compiler_fence(Ordering::SeqCst)`, `munlock`/`VirtualUnlock`, then `munmap`/`VirtualFree`.
3. Install `install_scrubbing_panic_hook()` ensuring panic output omits dynamic payload buffers (`INV-012`).
4. Implement `crates/rsv-mem/tests/locked_memory_negative.rs`:
   - Linux `/proc/self/smaps` check asserting `VmLck >= 4 kB` AND `VmFlags` contains `dd` (`VM_DONTDUMP`).
   - Assert `prctl(PR_GET_DUMPABLE) == 0`.
   - Subprocess test proving leading AND trailing guard-page reads raise `SIGSEGV` (Unix) / `0xC0000005` (Windows).
   - Post-`Drop` zeroization test proving 0 surviving canary bytes in backing page and `/proc/self/mem` scan.

### Part B — `crates/rsv-enclave/`
5. Define `HardwareKeyProvider` trait matching `agents/CRATE-CONTRACTS.md` §3.6.
6. Implement Linux TPM 2.0 backend (`#[cfg(all(target_os = "linux", feature = "tpm2"))]`) via `tss-esapi`:
   - Primary/child NIST P-256 `HDIK` (ECDSA-SHA256) and `HDSK` (ECDH/sealing) created with `fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth` (strictly non-exportable).
   - Full integration testing against `swtpm` (software TPM 2.0 simulator in CI).
7. Implement macOS Apple Secure Enclave backend (`#[cfg(all(target_os = "macos", feature = "apple-se"))]`) via `security-framework`:
   - NIST P-256 `HDIK` & `HDSK` with `kSecAttrTokenIDSecureEnclave`, `kSecAttrIsPermanent`, and biometric/device-passcode access control flags; ECIES P-256 sealing for `seal_local_secret` / `unseal_local_secret`.
8. Implement Windows CNG / PCPKSP backend (`#[cfg(all(target_os = "windows", feature = "win-cng"))]`) via `windows`:
   - `NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER)` creating non-exportable `NCRYPT_ECDSA_P256_ALGORITHM` (`HDIK`) and `NCRYPT_ECDH_P256_ALGORITHM` (`HDSK`) without `NCRYPT_ALLOW_EXPORT_FLAG`.
9. Implement `SoftwareFallbackProvider` (`feature = "software-fallback"`):
   - Stores P-256 keys strictly in `LockedSecretBox`, explicitly returns `HardwareTrustTier::Tier2SoftwareFallback`, and exposes `detect_best_provider()` returning Tier-1 when available or explicitly reporting fallback reason.
10. Implement `crates/rsv-enclave/tests/enclave_provider.rs` testing `HDIK` sign/verify, `HDSK` seal/unseal round-trip into `LockedSecretBox`, export failure verification (on `swtpm`/hardware), and explicit Tier-2 tagging.

---

## 5. Exact Verification Commands & Exit Criteria

ALL commands below MUST exit with code `0` before opening your PR:

```bash
# 1. Formatting & strict lints
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 clippy -p rsv-mem -p rsv-enclave --all-targets -- -D warnings

# 2. Verify every unsafe block carries a // SAFETY: proof comment
python3 -c '
import pathlib, re, sys
for crate in ("rsv-mem", "rsv-enclave"):
    for p in pathlib.Path(f"crates/{crate}/src").rglob("*.rs"):
        lines = p.read_text().splitlines()
        for i, line in enumerate(lines):
            if re.search(r"\bunsafe\s*\{", line):
                window = "\n".join(lines[max(0, i-6):i])
                if "SAFETY:" not in window:
                    print(f"Missing // SAFETY: before {p}:{i+1}", file=sys.stderr)
                    sys.exit(1)
print("All unsafe blocks have SAFETY proofs.")
'

# 3. Verify Tier-1 dependency firewall (zero async/HTTP/DB/UI deps)
! cargo tree -p rsv-mem -p rsv-enclave | grep -E 'tokio|sqlx|axum|gpui|reqwest|hyper|wasm-bindgen'

# 4. Run live locked-memory negative test (smaps VmLck + dd, guard pages, post-Drop zero scan)
cargo +1.94.0 test -p rsv-mem --test locked_memory_negative -- --nocapture

# 5. Run enclave provider tests (with swtpm socket on Linux CI; platform native on macOS/Windows)
cargo +1.94.0 test -p rsv-enclave --all-targets -- --nocapture

# 6. Supply chain & license compliance
cargo audit --deny warnings
cargo deny check advisories bans licenses sources
```

---

## 6. Handoff & PR Contract

- **Branch Naming**: `feat/m2c-agent02-mem-enclave`
- **PR Description MUST Include**:
  - Explicit Invariant Tags Verified: `[INV-010] [INV-011] [INV-012] [INV-013]`
  - Complete inventory table of every `unsafe` block in `rsv-mem` and `rsv-enclave` (file, line, syscall/FFI, safety invariant summary).
  - Captured output from `locked_memory_negative` showing `VmLck`, `VmFlags: ... dd`, `PR_GET_DUMPABLE == 0`, guard-page `SIGSEGV`, and `0` canary bytes post-`Drop`.
  - Captured output from `swtpm`/platform `enclave_provider` tests showing P-256 non-exportability and Tier-1/Tier-2 tagging.
- **Downstream Unblock Signal**: Merging `M2-C` unblocks Agent 05 (`M4-A` `rsv-daemon`/`rsv-desktop`) and Agent 04 (`M5` `rsv-compliance-cli`).
