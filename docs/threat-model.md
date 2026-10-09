# SafeHarness Threat Model

## Overview

SafeHarness is a framework-neutral lifecycle security runtime for AI agents. Its
primary runtime surface is the `safeharness` Python package: typed lifecycle
events, policy evaluation, framework adapters, capability authorization,
recovery/approval services, audit backends, an independent HTTP Tool Security
Gateway, and an authenticated Agent Communication Gateway. LangGraph and OpenAI
Agents SDK adapters cover explicitly routed framework lifecycle operations. The
LangGraph NOC application is a concrete telecom
operations integration using simulated tools; older paper-reproduction code is
not the production enforcement boundary.

The assets that matter most are NMS/tool credentials, ability to invoke
effectful tools, tenant and Agent identity, trusted user intent, policy and tool
metadata integrity, approval records, signing/verification keys, replay state,
audit integrity, and tool results that may contain operational data.

## Threat Model, Trust Boundaries, and Assumptions

- User, retrieved, tool, memory, and inter-Agent content is attacker-controlled
  unless explicit provenance establishes a stronger source. The model output is
  untrusted planning input and cannot grant itself authority.
- Agent adapters and in-process policy code form a policy enforcement point, not
  a hard isolation boundary from a fully compromised Agent process. Real tools,
  external credentials, canonical descriptors, and capability keys belong
  behind the Tool Security Gateway.
- Adapter coverage applies only when the application uses the guarded graph node,
  store, Agent, handoff, tool, and Session objects. A caller that retains and uses
  an original object, direct socket, file, shared-memory channel, or alternate
  broker is outside the in-process enforcement claim.
- The gateway trusts its configured registry, executor code, verifier material,
  replay backends, audit backend, CA store, and operator configuration. It does
  not trust request context, arguments, receipt/capability values, arbitrary
  headers, or client-supplied tool metadata.
- The Agent Communication Gateway trusts its Agent registry, default-deny
  topology, delegation grants, content inspector, clock, and authoritative
  mailbox/audit store. It does not trust message-body identity, content,
  metadata, timestamps, delegation requests, message IDs, or lease IDs.
- Every communication API key is bound server-side to exactly one tenant and
  Agent. TLS protects messages in transit; the current client-certificate option
  authenticates a workload but does not yet map a certificate identity to an
  Agent principal, so the API-key binding remains authoritative.
- Tenant, Agent, session, run, call, resource, intent, tool version/integrity,
  and workload identity must not be retargetable after authorization.
- Capability and enforcement-receipt signing authority are distinct logical
  roles. The dependency-free HMAC demo shares receipt signing material between
  control plane and gateway. The `shr2` path gives the control plane an
  Ed25519/KMS signer and gives the gateway only a configured public-key rotation
  set; production must use that separation and protect signer authorization.
- Strict workload identity is accepted only after TLS client-certificate
  verification and from exactly one SPIFFE URI SAN. API keys remain a separate
  application credential and headers cannot assert workload identity.
- Redis/PostgreSQL/SQLite availability is a security dependency in strict mode.
  Replay or pre-dispatch audit failure must deny execution.
- Operator-controlled inputs include policy/tool catalogs, grants, CA and
  certificates, backend DSNs, secret injection, retention, and approval broker
  behavior. Developer-controlled inputs include adapter wiring and registered
  executors. Misconfiguration of either can invalidate security claims.

Security invariants:

1. A tool is dispatched only after canonicalization, schema validation,
   capability verification, applicable lifecycle policies, obligations, and
   strict-mode receipt verification succeed.
2. Capabilities and receipts bind the exact invocation and security identity,
   expire quickly, and are consumed at most once in independent replay stores.
3. Caller-provided receipts never enter the Agent policy path; the runtime
   issues them only after an executable decision.
4. Raw prompt/content, arguments, results, tokens, receipts, credentials, and
   signing keys do not enter persisted audit or telemetry.
5. Unknown tools, invalid schemas, backend failures, unsupported obligations,
   identity mismatches, and ambiguous security state fail closed.
6. Recovery claims distinguish rollback, compensation, and irreversible
   effects; no external effect is described as undone without evidence.
7. An inter-Agent message is enqueued only after authenticated-principal,
   timestamp/TTL, topology, delegation, and `InformPolicy` checks succeed.
8. Message replay, delegation use, enqueue, lease, ACK, content scrubbing, and
   communication audit update atomically. An unavailable authoritative store or
   audit path fails closed.
9. An enabled communication rate limiter runs after principal authentication and
   before request-body processing. Exhaustion returns `429`; backend uncertainty
   returns an audited `503` and never permits the request.
10. For an adapter-declared `enforce` boundary, a denial must occur before the
    wrapped downstream operation. The TCK requires a stable reason code and zero
    downstream calls for its malicious conformance payload.

## Attack Surface, Mitigations, and Attacker Stories

- Prompt injection and untrusted tool/RAG content can redirect model planning.
  `InformPolicy`, provenance, intent binding, optional semantic judging, and
  guarded input/output/tool/message/memory/sub-Agent boundaries reduce this risk
  when the supported adapters are used. Novel semantic attacks remain possible
  and must not bypass deterministic authority.
- Tool substitution can change arguments, resource, call ID, version, tenant,
  Agent, session, run, or intent after approval. Canonical invocation digests,
  server-side descriptors/resource resolution, signed capabilities, and signed
  enforcement receipts bind these values.
- Replay and concurrent dispatch can duplicate effects. In-memory locks support
  tests; SQLite persists single-node state; Redis uses atomic `SET NX PXAT` with
  hashed identifiers and separate capability/receipt namespaces.
- A stolen Agent API key can request capabilities. Strict receipt mode requires
  a second policy proof. mTLS can additionally bind requests to a verified
  workload. A compromised HMAC key can forge proofs from either process. With
  `shr2`, compromise of gateway public-key material cannot sign, but compromise
  of the control-plane signer or its KMS authorization can still forge proofs.
- Cross-tenant impersonation is mitigated by API-key-to-principal binding,
  signed identity claims, context checks, and optional SPIFFE matching. Any path
  that trusts a tenant/Agent header without these checks is out of policy.
- Parser and protocol confusion is mitigated by exact JSON fields, duplicate-key
  rejection, finite canonical JSON for signed values, protocol versions, body
  and response limits, redirect refusal by the client, and strict `shr2`
  algorithm/key-ID matching before signed claims are parsed.
- Secret or operations-data leakage is mitigated by gateway-owned credentials,
  audit minimization, receipt/capability fingerprints only, content-free
  telemetry, generic errors, and separate Agent/gateway dotenv guidance.
- Audit tampering and silent loss are mitigated by append-only SQL triggers,
  least-privilege PostgreSQL roles, pre-dispatch durable audit, and explicit
  ambiguous post-dispatch failure semantics. Communication audit can be exported
  in ordered HTTPS batches without advancing the cursor after a failed delivery.
  The external receiver's immutability, availability, and retention remain
  deployment responsibilities.
- Authenticated request floods are bounded across communication replicas by a
  per-principal Redis fixed window using hashed bucket keys and a dedicated ACL.
  This limits one application-level abuse path but does not replace edge/network
  rate limiting, connection limits, or backend capacity controls.
- Backend compromise, malicious registered executors, CA compromise, and host
  kernel/container escape are outside the Python runtime's isolation guarantee;
  they require platform hardening, secret management, network policy, code
  review, and certificate lifecycle controls.
- Explicit multi-Agent messages can now cross an enforced gateway with
  API-key-to-principal binding, a default-deny source/target/kind topology,
  session/run/expiry/count-bound delegation, replay protection, leased delivery,
  ACK scrubbing, and pre-enqueue plus pre-delivery injection inspection.
  LangGraph explicit subgraph/Agent nodes and OpenAI Agents handoffs can also be
  constrained before activation; their guarded stores/Sessions inspect memory.
  Unwrapped dynamic creation, arbitrary side channels, direct shared-memory
  writes, compromised host processes, and communication outside the client
  adapter remain bypass paths that deployment isolation must address.
- Quarantine is checked inline before send and receive. Post-hoc trust scores or
  cascade analysis are not treated as real-time isolation. Signed SQLite and
  PostgreSQL coordination stores now persist administrative state and revocation;
  enterprise IAM binding and validated multi-host failover remain production work.

## Severity Calibration (Critical, High, Medium, Low)

- Critical: cross-tenant or unauthenticated dispatch of high-impact NMS actions;
  extraction of production capability/receipt signing authority enabling
  arbitrary tool execution; bypass of both policy proof and gateway authority.
- High: replay/concurrency causing duplicate irreversible operations; acceptance
  of a mismatched tenant, invocation, tool integrity, intent, or verified
  workload identity; cross-Agent impersonation or delegation escalation; raw
  credentials or sensitive NMS results persisted in broadly accessible
  audit/telemetry.
- Medium: denial of service through replay-store exhaustion or deliberate proof
  consumption without tool dispatch; incomplete audit records that do not
  enable execution; prompt-injection bypass limited to read-only simulated data
  with no downstream authority.
- Low: content-free telemetry inaccuracies, overly verbose local-only errors,
  documentation/configuration defects with no deployed path, or issues confined
  to paper-reproduction/test code without access to runtime assets.

Severity depends on the registered tool and deployment. The same identity or
replay defect is materially more severe for irreversible availability-changing
operations than for the bundled read-only simulated NOC tools.

Repository: F:\AgentSecurity\SafeHarness
Version: working-tree-snapshot-2026-07-22
