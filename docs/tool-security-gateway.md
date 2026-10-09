# Tool Security Gateway

SafeHarness can place tool execution behind an independent service boundary.
The Agent process retains lifecycle policy enforcement, while the gateway owns
the canonical tool registry, capability signer, real executor, and external
credentials.

```text
LangGraph Agent / SafeHarness PEP                 Tool Security Gateway

bind trusted user intent
        |
        +--- POST /v1/capabilities/issue ------> trusted registry + grant check
        |<-- exact, single-use signed token ----- gateway-only signing key
        |
        +--- POST /v1/capabilities/inspect ----> verify, do not consume
        |
local schema, intent, Judge, approval, recovery checks
        |
        +--- control plane signs allow receipt ------ exact policy decision proof
        |
        +--- POST /v1/tools/execute -----------> verify + atomically consume
                                                  receipt and capability
                                                  invoke server executor
                                                  use server-side credentials
        <---------------- sanitized JSON result
```

## HTTP API

- `GET /health` reports process readiness to an authenticated caller.
- `POST /v1/capabilities/issue` grants one exact invocation.
- `POST /v1/capabilities/inspect` validates without consuming the grant.
- `POST /v1/tools/execute` consumes before dispatch and rejects replay.

Every protected endpoint requires `Authorization: Bearer <api-key>`. Each key
is bound to one configured tenant and Agent ID; a key cannot submit another
tenant or Agent identity. Request
bodies use strict JSON and have a bounded size. The client applies fixed network
timeouts and bounded responses. The service never accepts client-supplied tool
descriptors or executors. The returned capability includes the gateway's
canonical tool-integrity digest, and the Agent rejects it when local policy
metadata does not match the gateway registry.

## Deployment rules

1. Run the gateway under a separate workload identity from the Agent.
2. Put `SAFEHARNESS_TOOL_GATEWAY_SIGNING_KEY` and NMS credentials only in the
   gateway's `config/gateway.env` or secret store; never load that file into an Agent.
3. Give the Agent only `SAFEHARNESS_TOOL_GATEWAY_URL` and a narrowly scoped API
   key. Use a unique key per tenant/Agent principal and rotate it if the Agent
   host is compromised.
4. Use TLS; prefer mTLS and short-lived workload credentials in production.
5. Replace the reference in-memory replay store before running multiple gateway
   replicas. The bundled SQLite store is restart-safe but remains single-node.
6. Never retry an ambiguous write execution with the same token.
7. Add server-side compensation/transactions before registering write tools.

The gateway fails closed when a required pre-dispatch audit record cannot be
persisted: it returns HTTP 503 with `gateway_audit_unavailable`, consumes an
already-authorized single-use token, and does not call the executor. If the
executor has already been dispatched but its terminal audit cannot be stored,
the gateway returns `gateway_audit_commit_failed`. That response explicitly
means external state may have changed and the caller must not retry
automatically.

## Enforcement receipts

Set `SAFEHARNESS_REQUIRE_ENFORCEMENT_RECEIPT=true` to make the gateway require a
second, independently signed authorization proof. SafeHarness issues it only
after schema, capability inspection, intent binding, Judge, approval, recovery,
and adapter-obligation checks have produced an executable decision. The receipt
binds audience, issuer, receipt ID, tenant, Agent, session, run, canonical tool
version and integrity digest, exact invocation digest, intent digest, policy
version, decision ID, event ID, workload ID, issuance, expiry, and an `allow`
disposition. Raw prompts, arguments, results, capabilities, and credentials are
never receipt claims.

The receipt is deliberately outside `invocation_digest`; instead, it signs that
digest. This avoids a signature cycle while preserving exact argument,
resource, call-ID, and intent binding. Receipt IDs use an independent SQLite or
Redis replay namespace and are consumed separately from capability IDs. The
gateway audit stores only a SHA-256 receipt fingerprint, never the receipt.

The dependency-free `shr1` compatibility path uses
`SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY` for HMAC. This is useful for the
local staging stack but gives both processes signing authority. The `shr2`
path signs a strict algorithm/key-ID header and canonical claims. The Agent-side
control plane holds an Ed25519 private key or external KMS/HSM signer, while the
gateway selects only configured public verification keys. Unknown key IDs,
algorithm mismatches, non-canonical headers/claims, signature tampering, expiry,
identity changes, and replay all fail closed.

Install Ed25519 support with `pip install -e ".[crypto]"` for a minimal SDK
installation or use `.[production]` for the deployed gateway. Generate a local
PEM pair with a current OpenSSL build:

```powershell
openssl genpkey -algorithm ED25519 -out receipt-private.pem
openssl pkey -in receipt-private.pem -pubout -out receipt-public.pem
```

Protect the private file with the operating-system secret store and file ACLs.
Do not generate or copy it into a gateway image. Configure the Agent/control
plane `.env` as follows:

```dotenv
SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE=ed25519
SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID=noc-control-plane-2026-07
SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE=C:/secure/receipt-private.pem
SAFEHARNESS_ENFORCEMENT_RECEIPT_ISSUER=safeharness-control-plane
```

Configure only public verification material in `config/gateway.env`:

```dotenv
SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE=ed25519
SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID=noc-control-plane-2026-07
SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE=C:/secure/receipt-public.pem
SAFEHARNESS_ENFORCEMENT_RECEIPT_ISSUER=safeharness-control-plane
SAFEHARNESS_REQUIRE_ENFORCEMENT_RECEIPT=true
```

For rotation, deploy the new public key before switching the signer and replace
the gateway's singular key settings with a JSON map. Do not configure
`SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID` at the same time:

```dotenv
SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILES={"noc-control-plane-2026-07":"C:/secure/receipt-2026-07-public.pem","noc-control-plane-2026-06":"C:/secure/receipt-2026-06-public.pem"}
```

Retain the old public key beyond the maximum receipt TTL, clock-skew allowance,
and in-flight request window, then remove it in a separate rollout. A gateway
process refuses Ed25519 startup if its environment contains the private-key
variable or ambiguous HMAC settings.

`ExternalEnforcementReceiptSigner` accepts a synchronous or asynchronous
callback for an organization-specific KMS/HSM SDK. The callback receives the
exact `shr2` signing input and returns signature bytes:

```python
from safeharness.backends import (
    AsymmetricEnforcementReceiptIssuer,
    ExternalEnforcementReceiptSigner,
)

async def kms_sign(message: bytes) -> bytes:
    return await company_kms.sign_ed25519(key_version="receipt-42", message=message)

issuer = AsymmetricEnforcementReceiptIssuer(
    ExternalEnforcementReceiptSigner(
        algorithm="EdDSA",
        key_id="receipt-42",
        sign=kms_sign,
    )
)
```

Provider authentication, authorization, audit, hashing conventions, retry
semantics, and public-key distribution remain provider-specific. SafeHarness
does not silently fall back to HMAC when an asymmetric signer fails.

Compatibility mode remains the default (`false`). It preserves existing
clients but does not mitigate a compromised Agent calling capability issuance
directly. Strict mode is the production target.

## TLS and workload identity

The reference server accepts a TLS context and can require client certificates.
The gateway entrypoint reads:

```dotenv
SAFEHARNESS_TOOL_GATEWAY_TLS_CERT=/run/secrets/gateway-cert.pem
SAFEHARNESS_TOOL_GATEWAY_TLS_KEY=/run/secrets/gateway-key.pem
SAFEHARNESS_TOOL_GATEWAY_CLIENT_CA=/run/secrets/workload-ca.pem
SAFEHARNESS_REQUIRE_MTLS=true
SAFEHARNESS_TOOL_GATEWAY_WORKLOAD_ID=spiffe://fiberhome/safeharness/noc-agent
```

Strict mTLS refuses startup unless TLS uses `CERT_REQUIRED` and an expected
workload identity is configured. Identity is taken only from exactly one
verified `spiffe://` URI SAN in the actual peer certificate; headers cannot
supply or override it. The same workload ID can be bound into the receipt.
Certificate issuance, rotation, revocation, and real CA interoperability still
require deployment-specific integration tests.

The Agent client accepts an explicit verification context. The LangGraph demo
builds it from `SAFEHARNESS_TOOL_GATEWAY_CA`,
`SAFEHARNESS_TOOL_GATEWAY_CLIENT_CERT`, and
`SAFEHARNESS_TOOL_GATEWAY_CLIENT_KEY` when the gateway URL is HTTPS. It never
disables hostname or CA verification.

## Persistent state

The reference NOC gateway reads `SAFEHARNESS_TOOL_GATEWAY_DATABASE` and defaults
to `data/tool-gateway.sqlite3`. This database stores:

- atomically consumed capability IDs until expiry, so a process restart does
  not make an old token reusable;
- sanitized issuance, inspection, dispatch, success, failure, and denial audit
  records;
- no raw tool arguments, results, capability tokens, signing keys, or NMS
  credentials.

Agent lifecycle audit is configured separately with
`SAFEHARNESS_AUDIT_DATABASE`. Keeping the files separate preserves the process
boundary; a centralized production audit service can later implement the same
`AuditSink` and `GatewayAuditSink` ports.

Inspect either SQLite database without granting write access to the query tool:

```powershell
python -m safeharness.audit_cli data/tool-gateway.sqlite3 --source gateway
python -m safeharness.audit_cli data/tool-gateway.sqlite3 --action tool_execute --format jsonl
```

The reader requires an existing SafeHarness schema and opens it in SQLite
read-only mode. The CLI cannot update audit rows, consume replay tokens, create
a missing database, or perform schema migration.

## Multi-replica persistence

Install the optional drivers in the gateway image:

```powershell
pip install -e ".[production,observability]"
```

Initialize PostgreSQL once with a migration identity. The DSN is read only from
the process environment and is never accepted as a command-line argument:

```powershell
$env:SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN = "postgresql://migration-user:..."
safeharness-postgres-init
```

If the database roles already exist, and the migration identity owns the audit
tables/sequences, the migration command can install the table grants in the
same transaction. The database administrator must separately grant `CONNECT`
and schema `USAGE`, as shown by the staging bootstrap script:

```powershell
$env:SAFEHARNESS_TOOL_GATEWAY_POSTGRES_RUNTIME_ROLE = "safeharness_writer"
$env:SAFEHARNESS_TOOL_GATEWAY_POSTGRES_READER_ROLE = "safeharness_reader"
safeharness-postgres-init
```

The runtime role receives schema usage, schema-version `SELECT`, audit `INSERT`,
and identity-sequence usage. The reader role receives `SELECT` for operations
and data-only backup. Neither role receives DDL, `UPDATE`, `DELETE`, or
`TRUNCATE`. Role names are validated as identifiers before any SQL is built.

Then run gateway replicas with a lower-privilege PostgreSQL writer identity and
the following gateway-only configuration:

```dotenv
SAFEHARNESS_TOOL_GATEWAY_REPLAY_BACKEND=redis
SAFEHARNESS_TOOL_GATEWAY_AUDIT_BACKEND=postgres
SAFEHARNESS_TOOL_GATEWAY_REDIS_URL=rediss://gateway-user:...@redis.internal:6379/0
SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN=postgresql://gateway-writer:...@postgres.internal/safeharness?sslmode=verify-full
SAFEHARNESS_TOOL_GATEWAY_POSTGRES_TABLE=safeharness_audit_records
```

Redis replay consumption is one atomic `SET NX PXAT` per capability or receipt.
Only SHA-256 ID digests and constant markers are stored in independent key
namespaces; raw tokens, receipts, and raw IDs are not. The
PostgreSQL sink uses one transaction per append and rolls back on failure. Its
runtime constructor does not perform DDL by default.

Authenticated `GET /health` now checks the selected replay and audit backends.
It returns `gateway_not_ready` with HTTP 503 when either is unavailable and does
not expose dependency names, URLs, DSNs, or exception messages. A Redis failure
between health checks and execution returns
`capability_replay_store_unavailable`; no tool is dispatched.

## OpenTelemetry

Set `SAFEHARNESS_OTEL_ENABLED=true` and configure the standard
`OTEL_EXPORTER_OTLP_*` variables. The gateway exports request counts, duration,
status, normalized route, and SafeHarness error code. It never exports prompts,
tool inputs/results, tenant or Agent identity, request IDs, capability values,
arbitrary URL paths, or persistence connection strings. Telemetry is a
non-authoritative side channel: export failure cannot permit, deny, or change a
tool execution result.

Use TLS for OTLP, Redis, and PostgreSQL. Production deployment still needs
secret-manager injection, certificate rotation, backups, retention policy,
database roles that deny `UPDATE`/`DELETE`, and staging failover tests.

## Reproducible staging stack

The reference topology under `deploy/` includes placeholder/secret-reuse
preflight validation, PostgreSQL, Redis ACLs, two
non-root/read-only gateway replicas, OpenTelemetry Collector, Prometheus,
Grafana provisioning, alerts, PostgreSQL backup/isolated-restore jobs, normal
path smoke tests, and dependency-failure smoke tests. It is deliberately a
local staging stack: ports bind to loopback and its internal traffic is not
TLS-protected.

The staging configuration enables strict HMAC receipt enforcement and shares
its receipt key with the smoke-test control-plane client. This validates receipt
binding and cross-replica Redis replay behavior once Docker integration runs;
it is not an asymmetric production trust boundary.

```powershell
Copy-Item config/deployment.env.example config/deployment.env
# Replace every placeholder with a distinct URL-safe random value (hex works).
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml up -d
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile test run --rm smoke-test
```

Run the separate Ed25519 profile to generate isolated key volumes, mount only
public verification material into two gateway replicas, mount only the private
key into the control-plane smoke container, and repeat the cross-replica audit,
replay, and OTLP checks:

```powershell
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile asymmetric-test run --rm --build asymmetric-smoke-test
```

This validates the local private/public process split. It does not validate a
managed KMS, enterprise key rotation, or TLS.

Grafana is available at `http://127.0.0.1:33000` and Prometheus at
`http://127.0.0.1:39090`. The smoke test proves authenticated readiness,
gateway execution, cross-replica Redis atomic replay rejection, hashed replay
keys, Redis ACL denial, PostgreSQL audit minimization, writer permissions,
append-only triggers, and OTLP metric arrival. It never calls a real NMS.

Run and inspect a verified custom-format backup with:

```powershell
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile backup run --rm postgres-backup
```

The backup contains audit rows only, plus SHA-256 and schema-version sidecars.
Run a real restore into an automatically created, isolated database and verify
the schema version, archive checksum, restored rows, and append-only trigger:

```powershell
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile restore run --rm postgres-restore-check
```

The temporary database name is restricted to a generated
`safeharness_restore_check_*` prefix and is removed after the check. The
reference job retains 30 days. Production retention must come from the
company's audit classification, legal hold, RPO, and RTO; validate restores in
a separate database before deleting any backup.

Exercise real Redis/PostgreSQL client failures without stopping the healthy
staging services:

```powershell
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile failure-test up --build --abort-on-container-exit `
  --exit-code-from dependency-failure-test dependency-failure-test
```

The two fault-injection gateways use unreachable loopback dependency endpoints.
The test requires authenticated health to return generic 503 responses and tool
execution to fail before dispatch with the expected replay/audit error codes.
This proves fail-closed behavior, not database or Redis HA failover.

See [`staging-validation-2026-07-20.md`](staging-validation-2026-07-20.md) for
the latest checked-in local execution evidence and its explicit claim limits.

Use managed TLS endpoints,
external secret injection, immutable/off-site backup copies, certificate
rotation, and at least two gateway replicas before claiming production HA.

## Residual risk and next milestone

Strict receipt mode now authenticates a concrete policy decision, `shr2`
separates signing from gateway verification, and optional mTLS can bind the
caller to a verified SPIFFE workload identity. The local Compose topology
remains HMAC/plain HTTP for reproducibility. Real KMS authorization and key
rotation, certificate lifecycle integration, and authoritative multi-Agent
communication enforcement are the next deployment and architecture milestones.
