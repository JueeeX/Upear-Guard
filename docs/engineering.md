# SafeHarness Core Alpha

This directory documents the first engineering extraction from the paper
reproduction code. The new `safeharness` package is framework-independent and
uses only the Python standard library.

## Protection boundary

SafeHarness can fully enforce only lifecycle operations exposed through an
adapter. The reusable generic tool adapter protects wrapped tool calls. The
`Guard` generic Agent attachment separately protects common Agent entry inputs
and final outputs. Neither can intercept memory, handoffs, arbitrary code, or
other framework internals that are not routed through its wrapper. Use each
adapter's `AdapterCapabilities` declaration when reporting coverage.

The in-process SDK is a policy enforcement helper, not a hard security boundary
against a compromised Agent process. Production tools and their credentials
should live behind a separate gateway or sandbox that the Agent cannot bypass.
Repository-wide assumptions, invariants, attacker stories, and severity
calibration are documented in [`threat-model.md`](threat-model.md).

## Core concepts

- `SafeHarnessRuntime` is reusable and contains immutable policy/backend references.
- `SecuritySession` isolates mutable state for one tenant and Agent run.
- `SecurityEvent` normalizes Agent lifecycle events.
- `Decision` supports allow, deny, modify, approval, and defer outcomes.
- `ToolDescriptor` declares schemas, capabilities, side effects, reversibility,
  sandbox requirements, and a digest over the complete security metadata.
- Ports inject tool catalogs, capability authorities, judges, state backends,
  compensators, approval brokers, and audit sinks.

Default behavior is fail-closed. An unknown tool, missing authorization backend,
missing capability, invalid schema, unavailable required approval/checkpoint/
compensation backend, or policy exception prevents execution.

## Recovery semantics

- `READ_ONLY`: no recovery obligation.
- `TRANSACTIONAL`: requires a state checkpoint and reports whether restoration
  actually succeeded.
- `COMPENSATABLE`: requires a compensation provider and reports the compensation
  receipt independently from checkpoint restoration.
- `IRREVERSIBLE`: requires an approval receipt with both approval ID and approver.

No code should describe an irreversible external effect as rollback-capable.

## Signed tool gateway

`SignedCapabilityGateway` is the reference authorization backend for an
external tool gateway. It issues an opaque, HMAC-authenticated capability for
one exact `ToolInvocation`. The claim is bound to the tenant, agent, session,
run, canonical tool version and integrity digest, plus a canonical digest of
the tool name, arguments, `call_id`, version, and resource. At verification,
the gateway checks all bindings and atomically consumes the token before tool
dispatch. A changed argument, cross-session use, expired token, invalid
signature, missing token, or replay is denied.

Use the gateway as the `capability_authority` and issue the token immediately
before dispatching the already-planned call. Pass it with `execute_tool(...,
capability_token=grant.token)`. For `wrap_tool`, provide a per-invocation
`capability_token_provider` that receives the complete invocation and obtains a
new token; a fixed token can be used only once. Capability tokens and token IDs
are redacted from default audit records.

The included `InMemoryCapabilityReplayStore` is only a local/test backend.
`SQLiteCapabilityReplayStore` provides atomic, restart-persistent replay
protection for a single-node gateway. A horizontally scaled production gateway
still needs a distributed consistency backend retained beyond the maximum token
lifetime. The in-process implementation protects against accidental bypasses,
not a compromised agent process with direct access to the underlying executor.

Enforcement receipts add an independent control-plane proof after the local
policy decision is executable. They bind the same canonical invocation digest
to tenant/Agent/session/run identity, tool integrity, intent, policy version,
decision/event IDs, expiry, and optional workload identity. The gateway can
require and atomically consume this proof separately from the capability.

`SignedEnforcementReceiptAuthority` preserves a dependency-free `shr1` HMAC
compatibility path. The `shr2` path separates
`AsymmetricEnforcementReceiptIssuer` from
`AsymmetricEnforcementReceiptVerifier`, signs a strict algorithm/key-ID header,
supports a public-key rotation set, and includes Ed25519 PEM implementations.
`ExternalEnforcementReceiptSigner` adapts an asynchronous KMS/HSM SDK callback
without giving the gateway signing authority. Ed25519 requires the optional
`crypto` or `production` dependencies; importing the core package does not.

## Agent communication gateway

`safeharness.communication` is the first enforced cross-Agent boundary. Its
control plane registers trusted tenant/Agent principals, permits only explicit
source-to-target message kinds, validates session/run-bound delegation grants,
and applies quarantine before sending or claiming messages. The HTTP server
binds each Bearer API key to one registered principal and rejects a message body
that claims a different sender.

The request order is fixed: strict protocol parsing, authenticated identity,
clock/TTL, topology/delegation authorization, `EventKind.INTER_AGENT` content
inspection, then one store transaction for replay, delegation use, mailbox,
and append-only audit. Receive uses an atomic lease and ACK contract. ACK keeps
the content digest for correlation but clears message content, metadata, and
requested capability values. A second recipient-side inspection prevents an
older or externally inserted unsafe message from reaching an Agent.

The bundled `SQLiteCommunicationStore` is a restart-persistent single-node
reference implementation. It rejects unknown schema versions, serializes
writers with `BEGIN IMMEDIATE`, and rolls back replay, delegation, mailbox,
lease, ACK, and audit state together. It is not a horizontally scalable or
high-availability backend.

`PostgreSQLCommunicationStore` implements the shared-state path. Replay
consumption, delegation counters, mailbox insertion, and audit commit together;
mailbox workers use `FOR UPDATE SKIP LOCKED` for disjoint leases across replicas.
ACK locks one row before validating its lease, and a separately granted retention
role can remove expired mailbox/replay rows without delete access to audit. The
implementation is ready for integration testing, but production failover and
capacity evidence are still pending.

Authenticated communication requests can use a Redis fixed-window limiter shared
by all gateway replicas. The limiter hashes the tenant/Agent bucket, is restricted
to one Redis key prefix and the commands needed for `INCR` plus absolute expiry,
returns `429` when exhausted, and fails closed with `503` if Redis is unavailable.
The communication maintenance command runs bounded mailbox/replay retention with
the delete-only retention identity. It can also read minimized audit through the
reader identity and export ordered HTTPS batches; its `(occurred_at, record_id)`
cursor advances only after the receiver accepts a batch. Receiver-side append-only
storage and durability remain operator responsibilities.

`PersistentCoordinationControlPlane` now persists Agent registration, topology,
delegation, revocation, and quarantine as a canonical snapshot plus an
HMAC-SHA256-linked append-only mutation history. `SQLiteCoordinationStore` is
the local backend; `PostgreSQLCoordinationStore` adds shared row locking and
optimistic versions. Authorization refreshes and verifies durable state before
each decision, and an optional admin-key HTTP surface provides strict management
operations. This closes restart durability and provides a shared mailbox code
path, but not enterprise IAM, management-network isolation, or proven production
failover.
See [`agent-communication-gateway.md`](agent-communication-gateway.md) for the
protocol, runbook, and residual boundaries.

## Persistent audit

`SQLiteAuditSink` stores both Agent lifecycle `AuditRecord` values and sanitized
`GatewayAuditRecord` values in one queryable schema. Raw prompts, tool results,
arguments, credentials, capability tokens, and token IDs are not stored. The
gateway audit stores only exact invocation/tool digests and a SHA-256 capability
fingerprint for correlation. Database triggers reject updates and deletes so
the reference log is append-only at the SQL layer.

`SQLiteAuditReader` opens an existing database with SQLite `mode=ro` and
`query_only`; it never initializes or migrates a database. The bundled
`safeharness-audit` command filters by tenant, session, source, and action and
can emit a compact table, JSON, or JSONL:

```powershell
safeharness-audit data/tool-gateway.sqlite3 --source gateway --limit 20
safeharness-audit data/tool-gateway.sqlite3 --session-id noc-session --format json
```

Use `python -m safeharness.audit_cli ...` when running directly from a source
checkout without installing the console script.

SQLite is the bundled single-node reference implementation, not a claim of
distributed durability. `PostgreSQLAuditSink` and
`RedisCapabilityReplayStore` implement the same ports for horizontally scaled
gateways without changing policies or adapters. Both are optional dependencies,
so the framework-independent core remains dependency-free.

The PostgreSQL writer reuses exactly the same audit minimization function as
SQLite and installs database triggers that reject updates and deletes. Runtime
gateway credentials need only `INSERT` and readiness access after an operator
runs `safeharness-postgres-init` with a separate migration identity. Redis uses
one atomic `SET NX PXAT` and stores only a SHA-256 digest of each token ID until
the signed expiry.

Gateway OpenTelemetry is deliberately non-authoritative: exporter failures do
not alter a security decision or HTTP result. Its attribute allowlist contains
only HTTP method, normalized route, status code, SafeHarness error code, and
duration. Tenant IDs, Agent IDs, request IDs, prompts, arguments, results,
tokens, arbitrary URL paths, and backend connection strings are excluded.
The communication gateway uses the same low-cardinality request observation model
under its own metric namespace, with Prometheus alerts for missing telemetry,
server errors, rate-limiter failure, and sustained throttling.

## Quick validation

From the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python examples/generic_tool.py
python -m tests.performance_budget
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile communication-test up --build --abort-on-container-exit `
  --exit-code-from communication-smoke-test communication-smoke-test
```

`tests.performance_budget` is a deterministic local regression gate, not an SLA. It
compares the same-process no-guard baseline with default policies plus in-memory audit.
It covers input, final output, read-only tools, memory read/write, sub-Agent handoff,
4 KiB checkpoint authentication, local signed capability issue/consume, and the local
semantic-judge adapter. Output includes p50/p95/p99, sequential throughput, CPU time,
and peak Python allocation. Absolute p95/p99 budgets fail the command; input/output use
1/2 ms and read-only tool round-trip uses 2/4 ms. Remote judges, persistent audit,
HTTP gateways, models, network concurrency, saturation, and deployment p99 still need
environment-specific load tests. Security checks must not be disabled to meet latency.

The latest checked-in local integration evidence is recorded in
[`staging-validation-2026-07-20.md`](staging-validation-2026-07-20.md).
The separate Ed25519 trust-boundary run is recorded in
[`asymmetric-receipt-validation-2026-07-20.md`](asymmetric-receipt-validation-2026-07-20.md).

The compatibility facade is intentionally temporary. It lets the existing
paper Harness implementations call the new runtime through the old synchronous
`filter_context` and `check_action` surface while adapters are migrated.

## Unified Agent attachment facade

`safeharness.Guard` is the stable application-facing entry point. Its default
`production` mode accepts only an Adapter that satisfies
`PRODUCTION_REQUIRED_CAPABILITIES`. Missing enforcement fails attachment before
an Agent session is exposed. The resulting `AttachmentReport` contains the
 selected Adapter, required and missing capabilities, protected entrypoints,
 warnings, and caller-declared deployment controls.

Auto-detection tries application-registered Adapters and then built-in framework
Adapters. It does not silently choose the generic fallback. The generic proxy is
available only when both `security_mode="baseline"` and
`adapter="generic-agent"` are explicit; it exists for migration tests and is not
a production integration path. Framework support is extended by implementing the
small `AgentAdapter` protocol and registering it once.

One `Guard` owns one mutable security session. Sequential conversation turns may
reuse it, but concurrent Agent calls must use separate `Guard` instances.

`adapter_lifecycle_complete` names only in-framework lifecycle enforcement. It
does not imply process isolation. Caller-supplied `DeclaredDeploymentControls`
are inventory, not attestation; they cannot make `production_ready` true. Trusted
`ToolDescriptor` metadata, capability configuration, returned guarded objects,
and independently validated deployment controls remain mandatory.

## Adapter lifecycle and conformance TCK

`ExplicitLifecycleAdapter` is the framework-neutral layer for operations beyond
ordinary tool calls. It guards input, framework messages, final output, memory
reads/writes, and explicit sub-Agent creation. `SubagentConstraints` independently
enforces the target Agent allowlist, maximum nesting depth, and requested-capability
subset before the factory or handoff can run. Memory audit stores a key fingerprint
instead of the raw namespace/key.

`AdapterConformanceTestKit` exercises six controlled malicious paths: input, tool,
message, sub-Agent creation, memory write, and final output. For every declared
`enforce` boundary it requires interception, a stable denial reason, and zero
downstream calls. It does not certify arbitrary-code isolation, raw checkpoint
integrity, deployment egress policy, or framework operations that were not routed
through the adapter.

## LangGraph adapter

`Guard.attach(LangGraphAgent(...))` builds a fixed guarded ReAct topology from a
declarative specification. It does not rewrite or trust an already compiled graph.
The Adapter provides guarded input, model, tool, output, store, and explicit
subgraph/Agent nodes. Its tool node binds every call to the canonical
descriptor, arguments, call ID, resource, session, and signed single-use
capability before execution. `GuardedLangGraphStore` wraps sync/async `get`,
`put`, `delete`, `search`, and batch operations. `SafeHarnessSubagentNode` routes
an explicitly registered subgraph or Agent through target/depth/capability checks.
The network-operations example under `examples/langgraph_noc` demonstrates the
adapter with a simulated NMS.

Coverage is explicit rather than implied. `guard.report.capabilities` is calculated
from the concrete `LangGraphAgent` surfaces:

| Adapter boundary | Coverage | Enforced surface |
| --- | --- | --- |
| Input, tool pre/post, argument rewrite, final output | `enforce` | Guarded graph nodes and canonical tool dispatch. |
| Framework message | `enforce` | Message content entering guarded model/tool nodes. |
| Memory | `enforce` when configured | Operations routed through `GuardedLangGraphStore`. |
| Handoff and sub-Agent creation | `enforce` when configured | Calls routed through `SafeHarnessSubagentNode`. |
| Checkpoint rehydration | `enforce` when configured | Authenticated restored content is re-inspected. |
| State checkpoint | `enforce` when configured | HMAC-SHA256 covers checkpoint, metadata, channel blob, and pending-write payloads. |
| Arbitrary-code isolation | `none` | The in-process adapter is not a sandbox. |

Checkpoint mode requires an explicit key of at least 32 bytes and wraps the
configured LangGraph `BaseCheckpointSaver` with its native `EncryptedSerializer`
interface plus a standard-library HMAC cipher. Loads reject unsigned, malformed,
type-downgraded, or modified payloads. This provides payload integrity only: it
does not provide confidentiality, storage authorization, key rotation, database
immutability, or replay prevention. SafeHarness also re-inspects restored messages,
replaces blocked/sanitized content by message ID, and strips tool calls from blocked
assistant messages.

The NOC Supervisor/Diagnosis example separately routes its explicit `DELEGATE`,
`QUERY`, and `RESULT` messages through the communication gateway. Arbitrary
side-channel messaging remains outside the adapter. LangGraph checkpoints
restore graph state only and do not prove that an external network action was
undone.

## OpenAI Agents SDK adapter

Install the optional integration with `pip install -e ".[agents]"`. The adapter
targets the public `openai-agents` 0.18.x contracts and exposes:

- SafeHarness input/output guardrails and Agent lifecycle hooks;
- descriptor-bound `FunctionTool` wrapping with strict JSON and policy-effective
  argument dispatch;
- guarded handoffs that create constrained child session contexts;
- `guard_agent()`, which rejects unwrapped handoffs, MCP servers, missing trusted
  descriptors, and unsupported tool types instead of claiming partial coverage;
- `GuardedOpenAIAgentsSession` for guarded Session reads, writes, pop, clear, and
  rehydration;
- `GuardedOpenAIAgentsRunner`, returned by `Guard.attach()`, which fixes the guarded
  Agent tree and guarded Session into every supported run.
- caller-defined Agent/Run hooks, Agent/FunctionTool guardrails, Handoff input filters,
  RunConfig rewrite callbacks, and ModelSettings provider rewrite fields are rejected;
  FunctionTool failure handlers are
  disabled so SafeHarness denials cannot become model-visible results;
- SDK traces always exclude sensitive payloads, and the guarded Agent tree is
  revalidated before model/tool execution. SafeHarness audit/telemetry remains the
  supported observation path.

`OPENAI_AGENTS_ADAPTER_CAPABILITIES` declares enforcement for the six TCK
boundaries plus handoff tracking. Concrete `Guard.attach()` reports only enabled
surfaces: memory when a Session is supplied, and handoff/sub-Agent when the Agent tree
contains handoffs. Framework checkpoint and `RunState` coverage remain `none`, so
`adapter_lifecycle_complete` is false. Streaming, `RunState` resume, server-managed
Conversations/response chaining, Responses compaction, MCP, and `Agent.as_tool()`
nested runs are rejected. Directly calling an original Agent, tool, handoff, Session,
socket, file, or alternate broker remains outside this adapter.

## Next milestones

1. Bind verified enterprise workload/certificate identity to tenant and Agent,
   then add dynamic secret, certificate, and signing-key rotation.
2. Validate the shared PostgreSQL/Redis paths under TLS-enabled multi-host
   failover, capacity, backup/restore, long-running retention, and stated RPO/RTO.
3. Integrate real NMS, alarm, topology, ticketing, and company authorization
   services in place of the simulated demo tools.
4. Enforce host/container egress and filesystem policy so direct sockets, files,
   shared memory, alternate brokers, and unwrapped framework objects cannot bypass
   the supported adapters and gateways.
5. Decide whether to add more framework adapters, a dedicated policy/audit/admin
   frontend, and a separate benchmark package; these are not production claims in
   the current Alpha.
