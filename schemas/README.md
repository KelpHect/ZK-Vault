# RusticStack Core (`ZK-Vault`) — Normative Machine-Readable Schemas

This directory contains the authoritative, machine-readable wire protocol schemas for **RusticStack Core (`ZK-Vault`)**. All server handlers (`rsv-server`), native clients (`rsv-daemon`, `rsv-desktop`, `rsv-nm-host`, `rsv-compliance-cli`), WASM modules (`rsv-wasm`), and browser surfaces (Chrome Extension MV3 & Web App SPA) **MUST** conform strictly to these contracts.

---

## 1. Schema Inventory

| File | Standard | Normative Companion Spec | Scope |
| :--- | :--- | :--- | :--- |
| [`openapi-v1.yaml`](./openapi-v1.yaml) | **OpenAPI 3.1.0** (`jsonSchemaDialect: Draft 2020-12`) | [`specs/08-API-AND-WIRE-PROTOCOLS.md`](../specs/08-API-AND-WIRE-PROTOCOLS.md) | All 32 `/api/v1` blind REST, WebAuthn + PRF, cryptographic RBAC key-graph, encrypted vault item, VSS recovery, C2SP `tlog-tiles` audit log, and WebSocket/SSE sync endpoints, mandatory headers, and canonical error codes. |
| [`ipc-native-messaging.schema.json`](./ipc-native-messaging.schema.json) | **JSON Schema Draft 2020-12** | [`specs/07-OMNI-CLIENT-ARCHITECTURE.md`](../specs/07-OMNI-CLIENT-ARCHITECTURE.md), [`adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md`](../adrs/ADR-0006-native-messaging-daemon-offload-for-extension.md) | Chunked Chrome Native Messaging framing (`ChunkEnvelope`, `max_chunk_bytes = 786432` < 1 MiB Chrome cap), HPKE/X25519 handshake (`HandshakeInit`, `HandshakeComplete`), and authenticated daemon RPC (`IpcRequest`, `IpcResponse`, `UnlockStatus`, `GetMatchesForOrigin`, `GetCredentialForOrigin`, `SignAuditRequest`, `LockVault`, `IpcError`). |

---

## 2. Automated Validation Commands (CI & Local Development)

Every pull request modifying any schema file or wire-facing Rust/TypeScript crate (`rsv-types`, `rsv-server`, `rsv-daemon`, `rsv-wasm`, browser extension, or Web SPA) **MUST** pass all validation gates below.

### 2.1 OpenAPI 3.1.0 Validation (`openapi-v1.yaml`)

Using **Redocly CLI** (recommended primary OpenAPI 3.1 linter):
```bash
npx --yes @redocly/cli@latest lint schemas/openapi-v1.yaml
```

Using **Python (`openapi-spec-validator` + `PyYAML`)**:
```bash
python -m pip install --quiet openapi-spec-validator pyyaml
python -c "
import yaml
from openapi_spec_validator import validate
with open('schemas/openapi-v1.yaml', 'r', encoding='utf-8') as f:
    spec = yaml.safe_load(f)
validate(spec)
print('openapi-v1.yaml: VALID OpenAPI', spec['openapi'], 'with', len(spec['paths']), 'paths')
"
```

Using **Spectral** (optional style & security ruleset):
```bash
npx --yes @stoplight/spectral-cli@latest lint schemas/openapi-v1.yaml
```

### 2.2 JSON Schema Draft 2020-12 Validation (`ipc-native-messaging.schema.json`)

Meta-schema validation and payload fixture testing using **AJV CLI (Draft 2020-12)**:
```bash
npx --yes ajv-cli@latest compile --spec=draft2020 -s schemas/ipc-native-messaging.schema.json
```

Using **Python (`jsonschema` Draft 2020-12 Validator)**:
```bash
python -m pip install --quiet jsonschema
python -c "
import json
from jsonschema import Draft202012Validator
with open('schemas/ipc-native-messaging.schema.json', 'r', encoding='utf-8') as f:
    schema = json.load(f)
Draft202012Validator.check_schema(schema)
print('ipc-native-messaging.schema.json: VALID Draft 2020-12 schema with', len(schema['\$defs']), 'definitions')
"
```

### 2.3 Chunk Boundary & Wire Invariant Test Requirement

Any implementation of `rsv-nm-host` or the Chrome Extension chunk multiplexer MUST assert during CI:
1. Every serialized `ChunkEnvelope` emitted by `rsv-nm-host` validates against `schemas/ipc-native-messaging.schema.json`.
2. Every `payload_chunk` has length `<= 786432` bytes (`768 KiB`) and every complete serialized UTF-8 JSON `ChunkEnvelope` has byte length `<= 851968` bytes (`832 KiB`), strictly below Chrome's hard `1,048,576`-byte (`1 MiB`) Native Host -> Extension ceiling.
3. Every `rsv-server` integration test response body and error payload validates against `schemas/openapi-v1.yaml` (including all 12 canonical error codes in `#/components/schemas/ErrorCode`).

---

## 3. Code Generation & Type Binding Policy

- **Rust (`rsv-types`, `rsv-server`, `rsv-daemon`)**: Domain wire structs MUST match field names, enum variants, `#[serde(deny_unknown_fields)]` on mutating security inputs, and UUIDv7/Base64URL formatting identically to `openapi-v1.yaml` and `ipc-native-messaging.schema.json`. Contract tests MUST serialize golden Rust fixtures and validate them directly against these schemas in CI.
- **TypeScript (Chrome Extension MV3 & Web SPA)**: Typed client DTOs SHOULD be generated directly from `schemas/openapi-v1.yaml` (e.g., `openapi-typescript`) and `schemas/ipc-native-messaging.schema.json` (e.g., `json-schema-to-typescript`), eliminating hand-maintained type drift.
- **Cryptographic CBOR Envelopes**: Binary fields named `*_cbor` or `*_bundle` carry **RFC 8949 Section 4.2 Deterministic CBOR** encoded as unpadded Base64URL. JSON/OpenAPI schemas validate the outer transport framing and Base64URL syntax; inner CBOR structure and canonicality are validated exclusively by `rsv-types` / `rsv-crypto` / `rsv-audit`.

---

## 4. Schema Versioning & Compatibility Policy

1. **Additive-Only Minor Changes Within Major Version (`v1`)**:
   - Within `/api/v1` and IPC `protocol_version: 1`, changes MUST be strictly backward-compatible: adding optional response fields, adding new endpoints, or adding new optional query parameters is permitted ONLY if existing clients continue operating without modification.
   - Renaming fields, narrowing types, changing enum strings, adding new required request properties on existing endpoints, or altering canonical signing inputs (`RSV-REQ-SIG-V1`) is **FORBIDDEN** inside `v1`.
2. **Breaking Changes Require Major Version Bump**:
   - Any breaking REST wire change MUST introduce `/api/v2` and a new `schemas/openapi-v2.yaml` while preserving `/api/v1` for the documented deprecation window (minimum 12 months for enterprise deployments).
   - Any breaking Native Messaging framing or handshake change MUST increment `protocol_version` (e.g., `protocol_version: 2`) negotiated during `HandshakeInit` / `HandshakeComplete`, returning `IPC_PROTOCOL_VERSION_UNSUPPORTED` on incompatible peers.
3. **Cipher Suite Agility Without Schema Breaks**:
   - New post-quantum or FIPS cipher suites are introduced by appending new canonical identifiers to the `CipherSuite` enum (e.g., `RSV-HYBRID-2026-V1`, `RSV-HYBRID-FIPS-2026-V1`) and advertising support dynamically via `GET /api/v1/health` and `GET /api/v1/tenant/manifest`.
4. **Canonical Source of Truth**:
   - Whenever prose documentation and a machine-readable schema diverge, treat the mismatch as a release-blocking defect and update both atomically in the same pull request.
