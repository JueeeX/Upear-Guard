# Asymmetric Receipt Validation Record - 2026-07-20

This record captures local validation of the SafeHarness `shr2` asymmetric
enforcement-receipt boundary. It supplements, rather than replaces, the HMAC
staging record in `staging-validation-2026-07-20.md`.

## Scope and environment

- Repository base commit: `9d9602bd388a219902162e4616fe95972abe75ed`
- Validation time zone: Asia/Shanghai
- Docker Desktop: 4.82.0
- Docker Engine: 29.6.1
- Receipt algorithm: Ed25519 (`EdDSA`)
- Receipt envelope: `shr2` with a signed, strict algorithm/key-ID header
- Gateway persistence: Redis replay protection and PostgreSQL append-only audit
- Telemetry path: OTLP Collector and Prometheus metrics

The working tree contained the implementation under validation. The base
commit identifies the starting repository state; this record must be read with
the current working-tree diff.

## Trust split exercised

The `asymmetric-test` Compose profile uses four temporary services:

1. A network-disabled keygen bootstrap writes a private and public key into
   separate named volumes. It runs with a read-only root filesystem, drops all
   capabilities, and adds only `CHOWN` to hand key files to the non-root runtime
   user.
2. Two gateway replicas mount only the public-key volume and enforce strict
   receipts with a shared Redis receipt-replay namespace.
3. The control-plane smoke container mounts only the private-key volume and has
   no capability-signing key or HMAC receipt key.
4. The smoke path issues one exact `shr2` receipt, races the same invocation
   across both replicas, and requires exactly one successful dispatch.

Observed file and process boundaries:

```text
gateway-public=444,safeharness:safeharness
gateway-public=444,safeharness:safeharness
control-private=400,safeharness:safeharness
```

Both gateways also passed runtime checks that the private-key path was absent
and `SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY` was empty. The control-plane
container passed the inverse mount check and also had no HMAC receipt key.

## Results

| Validation | Result | Evidence |
| --- | --- | --- |
| Full unit suite | PASS | 166 passed, 1 skipped because `openssl` was unavailable to the test process |
| Scoped Ruff | PASS | `src/safeharness`, `tests`, `examples`, and `deploy` |
| Python compile | PASS | SDK, tests, examples, deployment modules, and `llm_api.py` |
| Package build | PASS | sdist and wheel include asymmetric and environment-composition modules |
| Compose expansion | PASS | Default and `asymmetric-test` profiles parsed |
| Asymmetric key bootstrap | PASS | Existing pair validated; incomplete pairs fail closed |
| Two-gateway asymmetric smoke | PASS | Gateway, cross-replica replay, audit, and OTLP checks passed |
| Runtime key isolation | PASS | Public-only gateways and private-only control-plane mount confirmed |
| Diff whitespace | PASS | `git diff --check` returned no errors |

The key integration outputs were:

```text
SafeHarness staging smoke test passed: gateway, replay, audit, and OTLP.
SafeHarness asymmetric receipt smoke test passed: private/public trust split.
```

Focused tests also covered signature tampering, unknown key IDs, algorithm
confusion, identity substitution, expiry, replay, public-key rotation sets,
HMAC compatibility, gateway rejection of private-key configuration, an async
KMS/HSM-style signing callback, and a real HTTP client/server round trip.

## Reproduction

Run from the repository root with the ignored staging environment already
configured:

```powershell
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile asymmetric-test run --rm --build asymmetric-smoke-test
```

The key volumes are retained so the next run validates and reuses the same
pair. Stop and remove temporary profile containers after inspection:

```powershell
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile asymmetric-test stop asymmetric-gateway asymmetric-gateway-replica
docker compose --env-file config/deployment.env -f deploy/compose/compose.yaml `
  --profile asymmetric-test rm -f asymmetric-gateway `
  asymmetric-gateway-replica receipt-keygen asymmetric-smoke-test
```

## Claims not established

This validation does not establish:

- a real cloud KMS or HSM integration, its IAM policy, audit trail, retry
  semantics, quotas, availability, or key-destruction workflow;
- enterprise PKI, TLS/mTLS certificate issuance, rotation, and revocation;
- an operational public-key rotation rollout under production traffic;
- protection from compromise of the Agent-side control plane or its authority
  to request KMS signatures;
- Redis/PostgreSQL HA failover, immutable off-site backups, or multi-region
  recovery;
- authoritative Agent-to-Agent communication enforcement.

Those require pre-production infrastructure and organization-specific controls.
