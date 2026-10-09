"""Standalone Tool Security Gateway for the simulated NOC backend."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from safeharness import Reversibility
from safeharness.backends import (
    SignedCapabilityGateway,
    SignedEnforcementReceiptAuthority,
    build_enforcement_receipt_verifier_from_environment,
)
from safeharness.gateway import (
    GatewayPersistence,
    RegisteredTool,
    ToolGatewayApplication,
    ToolRegistry,
    build_gateway_persistence,
    create_gateway_server,
    create_server_tls_context,
    gateway_telemetry_from_environment,
)
from safeharness.ports import EnforcementReceiptVerifier

from examples.langgraph_noc.domain import (
    DEFAULT_NOC_READ_ONLY_GRANTS,
    NetworkOperationsEnvironment,
    build_noc_tools,
)


def build_gateway_application(
    *,
    signing_key: str,
    tenant_id: str = "fiberhome-demo",
    agent_id: str = "noc-operator-agent",
    environment: NetworkOperationsEnvironment | None = None,
    database_path: str | Path | None = None,
    persistence: GatewayPersistence | None = None,
    replay_backend: str = "sqlite",
    audit_backend: str = "sqlite",
    redis_url: str | None = None,
    postgres_dsn: str | None = None,
    postgres_table: str = "safeharness_audit_records",
    redis_key_prefix: str = "safeharness:capability-replay:",
    redis_receipt_key_prefix: str = "safeharness:receipt-replay:",
    enforcement_receipt_key: str | None = None,
    enforcement_receipt_verifier: EnforcementReceiptVerifier | None = None,
    require_enforcement_receipt: bool = False,
    workload_identity: str | None = None,
) -> tuple[ToolGatewayApplication, NetworkOperationsEnvironment]:
    """Build a read-only reference gateway with server-owned NMS executors."""

    environment = environment or NetworkOperationsEnvironment()
    tools = [
        tool
        for tool in build_noc_tools(environment)
        if tool.descriptor.reversibility is Reversibility.READ_ONLY
        and not tool.descriptor.side_effects
        and tool.descriptor.required_capabilities <= DEFAULT_NOC_READ_ONLY_GRANTS
    ]
    registry = ToolRegistry(
        RegisteredTool(
            tool.descriptor,
            tool.executor,
            resource_resolver=tool.resource_resolver,
        )
        for tool in tools
    )
    if persistence is None and (
        database_path is not None or replay_backend != "sqlite" or audit_backend != "sqlite"
    ):
        persistence = build_gateway_persistence(
            replay_backend=replay_backend,
            audit_backend=audit_backend,
            sqlite_path=database_path,
            redis_url=redis_url,
            postgres_dsn=postgres_dsn,
            postgres_table=postgres_table,
            redis_key_prefix=redis_key_prefix,
            redis_receipt_key_prefix=redis_receipt_key_prefix,
        )
    capabilities = SignedCapabilityGateway(
        signing_key,
        {(tenant_id, agent_id): DEFAULT_NOC_READ_ONLY_GRANTS},
        replay_store=persistence.replay_store if persistence is not None else None,
    )
    if enforcement_receipt_key and enforcement_receipt_verifier is not None:
        raise ValueError(
            "configure either an HMAC receipt key or an explicit receipt verifier"
        )
    receipt_verifier = enforcement_receipt_verifier
    if enforcement_receipt_key:
        receipt_verifier = SignedEnforcementReceiptAuthority(
            enforcement_receipt_key,
            replay_store=(
                persistence.receipt_replay_store if persistence is not None else None
            ),
        )
    return ToolGatewayApplication(
        registry=registry,
        capability_gateway=capabilities,
        audit_sink=persistence.audit_sink if persistence is not None else None,
        readiness_checks=persistence.readiness_checks if persistence is not None else (),
        enforcement_receipt_verifier=receipt_verifier,
        require_enforcement_receipt=require_enforcement_receipt,
        workload_identity=workload_identity,
    ), environment


def main() -> None:
    import llm_api

    default_env = Path(__file__).resolve().parents[2] / "config" / "gateway.env"
    gateway_env = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_ENV_FILE")
    llm_api.load_env_file(gateway_env or default_env)
    parser = argparse.ArgumentParser(
        description="SafeHarness standalone NOC Tool Security Gateway"
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SAFEHARNESS_TOOL_GATEWAY_HOST", "127.0.0.1"),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SAFEHARNESS_TOOL_GATEWAY_PORT", "38100")),
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get(
            "SAFEHARNESS_TOOL_GATEWAY_TENANT_ID", "fiberhome-demo"
        ),
    )
    parser.add_argument(
        "--agent-id",
        default=os.environ.get("SAFEHARNESS_TOOL_GATEWAY_AGENT_ID", "noc-operator-agent"),
    )
    parser.add_argument(
        "--database",
        default=os.environ.get(
            "SAFEHARNESS_TOOL_GATEWAY_DATABASE",
            str(Path("data") / "tool-gateway.sqlite3"),
        ),
        help="SQLite path for replay protection and structured gateway audit.",
    )
    parser.add_argument(
        "--replay-backend",
        choices=("sqlite", "redis"),
        default=os.environ.get("SAFEHARNESS_TOOL_GATEWAY_REPLAY_BACKEND", "sqlite"),
    )
    parser.add_argument(
        "--audit-backend",
        choices=("sqlite", "postgres"),
        default=os.environ.get("SAFEHARNESS_TOOL_GATEWAY_AUDIT_BACKEND", "sqlite"),
    )
    args = parser.parse_args()

    api_key = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_API_KEY", "")
    signing_key = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_SIGNING_KEY", "")
    require_receipt = _environment_flag(
        "SAFEHARNESS_REQUIRE_ENFORCEMENT_RECEIPT", default=False
    )
    if len(api_key) < 32:
        parser.error(
            "SAFEHARNESS_TOOL_GATEWAY_API_KEY must contain at least 32 characters"
        )
    if len(signing_key.encode("utf-8")) < 32:
        parser.error(
            "SAFEHARNESS_TOOL_GATEWAY_SIGNING_KEY must contain at least 32 bytes"
        )
    try:
        persistence = build_gateway_persistence(
            replay_backend=args.replay_backend,
            audit_backend=args.audit_backend,
            sqlite_path=args.database,
            redis_url=os.environ.get("SAFEHARNESS_TOOL_GATEWAY_REDIS_URL"),
            postgres_dsn=os.environ.get("SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN"),
            postgres_table=os.environ.get(
                "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_TABLE",
                "safeharness_audit_records",
            ),
            redis_key_prefix=os.environ.get(
                "SAFEHARNESS_TOOL_GATEWAY_REDIS_KEY_PREFIX",
                "safeharness:capability-replay:",
            ),
            redis_receipt_key_prefix=os.environ.get(
                "SAFEHARNESS_TOOL_GATEWAY_REDIS_RECEIPT_KEY_PREFIX",
                "safeharness:receipt-replay:",
            ),
        )
        receipt_verifier = build_enforcement_receipt_verifier_from_environment(
            replay_store=persistence.receipt_replay_store,
        )
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    if require_receipt and receipt_verifier is None:
        parser.error("strict receipt mode requires a configured receipt verifier")

    application, _ = build_gateway_application(
        signing_key=signing_key,
        tenant_id=args.tenant_id,
        agent_id=args.agent_id,
        persistence=persistence,
        enforcement_receipt_verifier=receipt_verifier,
        require_enforcement_receipt=require_receipt,
        workload_identity=os.environ.get("SAFEHARNESS_TOOL_GATEWAY_WORKLOAD_ID") or None,
    )
    telemetry = gateway_telemetry_from_environment()
    tls_context = None
    tls_certificate = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_TLS_CERT", "")
    tls_private_key = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_TLS_KEY", "")
    client_ca = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_CLIENT_CA", "")
    require_mtls = _environment_flag("SAFEHARNESS_REQUIRE_MTLS", default=False)
    if tls_certificate or tls_private_key or client_ca or require_mtls:
        if not tls_certificate or not tls_private_key:
            parser.error("TLS requires SAFEHARNESS_TOOL_GATEWAY_TLS_CERT and TLS_KEY")
        tls_context = create_server_tls_context(
            certificate=tls_certificate,
            private_key=tls_private_key,
            client_ca=client_ca or None,
            require_client_certificate=require_mtls,
        )
    server = create_gateway_server(
        application,
        host=args.host,
        port=args.port,
        api_key=api_key,
        tenant_id=args.tenant_id,
        agent_id=args.agent_id,
        telemetry=telemetry,
        tls_context=tls_context,
        require_mtls_identity=require_mtls,
    )
    scheme = "https" if tls_context is not None else "http"
    print(f"SafeHarness Tool Security Gateway listening on {scheme}://{args.host}:{args.port}")
    print("Exposed NOC tools: read-only diagnosis only")
    if args.replay_backend == args.audit_backend == "sqlite":
        print(f"Persistent state: {Path(args.database).resolve()}")
    else:
        print(
            "Persistent backends: "
            f"replay={args.replay_backend}, audit={args.audit_backend}"
        )
    print(f"OpenTelemetry: {'enabled' if telemetry is not None else 'disabled'}")
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nTool Security Gateway stopped.")
    finally:
        server.server_close()


def _environment_flag(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


if __name__ == "__main__":
    main()
