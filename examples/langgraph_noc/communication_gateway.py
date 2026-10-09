"""Standalone Agent Communication Gateway for the NOC multi-Agent demo."""

from __future__ import annotations

import argparse
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from safeharness.communication import (
    AgentCommunicationApplication,
    AgentRegistration,
    CoordinationControlPlane,
    DelegationGrant,
    MessageKind,
    CommunicationStore,
    SQLiteCommunicationStore,
    SQLiteCoordinationControlPlane,
    PostgreSQLCommunicationStore,
    PostgreSQLCoordinationControlPlane,
    TopologyRule,
    create_communication_server,
    create_communication_tls_context,
)
from safeharness.communication.rate_limit import (
    communication_rate_limiter_from_environment,
)
from safeharness.gateway.telemetry import gateway_telemetry_from_environment


DEFAULT_TENANT_ID = "fiberhome-demo"
DEFAULT_SUPERVISOR_ID = "noc-supervisor-agent"
DEFAULT_DIAGNOSIS_ID = "noc-diagnosis-agent"
DEFAULT_SESSION_ID = "noc-multi-agent-session"
DEFAULT_RUN_ID = "noc-multi-agent-run"
DEFAULT_DELEGATION_ID = "noc-read-only-diagnosis"
DIAGNOSIS_CAPABILITY = "nms:alarms:read"


def build_communication_gateway(
    *,
    database_path: str | Path,
    tenant_id: str = DEFAULT_TENANT_ID,
    supervisor_agent_id: str = DEFAULT_SUPERVISOR_ID,
    diagnosis_agent_id: str = DEFAULT_DIAGNOSIS_ID,
    session_id: str = DEFAULT_SESSION_ID,
    run_id: str = DEFAULT_RUN_ID,
    delegation_id: str = DEFAULT_DELEGATION_ID,
    delegation_max_messages: int = 1000,
    delegation_ttl: timedelta = timedelta(hours=24),
    coordination_signing_key: bytes | None = None,
    coordination_backend: str = "sqlite",
    coordination_postgres_dsn: str | None = None,
    communication_backend: str = "sqlite",
    communication_postgres_dsn: str | None = None,
    communication_postgres_initialize: bool = False,
    now=None,
) -> tuple[AgentCommunicationApplication, CommunicationStore]:
    """Build a session-bound, default-deny NOC communication control plane.

    Passing ``coordination_signing_key`` enables restart-persistent, signed
    policy state. ``coordination_backend='sqlite'`` stores it beside the mailbox;
    ``'postgres'`` uses the shared PostgreSQL policy store. The omitted-key path
    remains available for unit tests and explicitly local in-memory examples.
    """

    clock = now or (lambda: datetime.now(timezone.utc))
    current = clock()
    if current.tzinfo is None:
        raise ValueError("the communication gateway clock must be timezone-aware")
    if delegation_ttl <= timedelta(0):
        raise ValueError("delegation_ttl must be positive")
    normalized_communication_backend = communication_backend.strip().lower()
    if normalized_communication_backend not in {"sqlite", "postgres"}:
        raise ValueError("communication_backend must be sqlite or postgres")
    if normalized_communication_backend == "postgres" and not communication_postgres_dsn:
        raise ValueError(
            "communication_postgres_dsn is required for the postgres communication backend"
        )
    agents = (
        AgentRegistration(
            tenant_id,
            supervisor_agent_id,
            roles=frozenset({"supervisor"}),
            delegable_capabilities=frozenset({DIAGNOSIS_CAPABILITY}),
        ),
        AgentRegistration(
            tenant_id,
            diagnosis_agent_id,
            roles=frozenset({"diagnosis"}),
            accepted_capabilities=frozenset({DIAGNOSIS_CAPABILITY}),
        ),
    )
    topology = (
        TopologyRule(
            tenant_id,
            supervisor_agent_id,
            diagnosis_agent_id,
            frozenset({MessageKind.QUERY, MessageKind.DELEGATE}),
        ),
        TopologyRule(
            tenant_id,
            diagnosis_agent_id,
            supervisor_agent_id,
            frozenset({MessageKind.RESPONSE, MessageKind.RESULT}),
        ),
    )
    delegation = DelegationGrant(
        tenant_id=tenant_id,
        grantor_agent_id=supervisor_agent_id,
        grantee_agent_id=diagnosis_agent_id,
        capabilities=frozenset({DIAGNOSIS_CAPABILITY}),
        session_id=session_id,
        run_id=run_id,
        expires_at=current + delegation_ttl,
        max_messages=delegation_max_messages,
        delegation_id=delegation_id,
    )
    normalized_backend = coordination_backend.strip().lower()
    if normalized_backend not in {"sqlite", "postgres"}:
        raise ValueError("coordination_backend must be sqlite or postgres")
    if coordination_signing_key is None and normalized_backend != "sqlite":
        raise ValueError(
            "coordination_signing_key is required for a persistent coordination backend"
        )
    if coordination_signing_key is None:
        control_plane = CoordinationControlPlane(
            agents,
            topology,
            (delegation,),
            now=clock,
        )
    elif normalized_backend == "sqlite":
        control_plane = SQLiteCoordinationControlPlane(
            database_path,
            coordination_signing_key,
            agents=agents,
            topology=topology,
            delegations=(delegation,),
            now=clock,
        )
    else:
        if not coordination_postgres_dsn:
            raise ValueError(
                "coordination_postgres_dsn is required for the postgres coordination backend"
            )
        control_plane = PostgreSQLCoordinationControlPlane(
            coordination_signing_key,
            coordination_postgres_dsn,
            agents=agents,
            topology=topology,
            delegations=(delegation,),
            now=clock,
        )
    if normalized_communication_backend == "sqlite":
        store = SQLiteCommunicationStore(database_path, now=clock)
    elif normalized_communication_backend == "postgres":
        store = PostgreSQLCommunicationStore(
            communication_postgres_dsn,
            initialize=communication_postgres_initialize,
            now=clock,
        )
    return (
        AgentCommunicationApplication(
            control_plane=control_plane,
            store=store,
            now=clock,
        ),
        store,
    )


def main() -> None:
    import llm_api

    default_env = Path(__file__).resolve().parents[2] / "config" / "communication.env"
    configured_env = os.environ.get("SAFEHARNESS_COMMUNICATION_GATEWAY_ENV_FILE")
    llm_api.load_env_file(configured_env or default_env)
    parser = argparse.ArgumentParser(
        description="SafeHarness standalone NOC Agent Communication Gateway"
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SAFEHARNESS_COMMUNICATION_GATEWAY_HOST", "127.0.0.1"),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SAFEHARNESS_COMMUNICATION_GATEWAY_PORT", "38200")),
    )
    parser.add_argument(
        "--database",
        default=os.environ.get(
            "SAFEHARNESS_COMMUNICATION_DATABASE",
            str(Path("data") / "agent-communication.sqlite3"),
        ),
    )
    args = parser.parse_args()

    tenant_id = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_TENANT_ID", DEFAULT_TENANT_ID
    )
    supervisor_agent_id = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_SUPERVISOR_AGENT_ID", DEFAULT_SUPERVISOR_ID
    )
    diagnosis_agent_id = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_AGENT_ID", DEFAULT_DIAGNOSIS_ID
    )
    supervisor_key = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_SUPERVISOR_API_KEY", ""
    )
    supervisor_previous_key = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_SUPERVISOR_PREVIOUS_API_KEY", ""
    )
    diagnosis_key = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_API_KEY", ""
    )
    diagnosis_previous_key = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_PREVIOUS_API_KEY", ""
    )
    admin_key = os.environ.get("SAFEHARNESS_COMMUNICATION_ADMIN_API_KEY", "")
    admin_previous_key = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_ADMIN_PREVIOUS_API_KEY", ""
    )
    admin_actor = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_ADMIN_ACTOR",
        "noc-security-admin",
    )
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}", admin_actor) is None:
        parser.error("SAFEHARNESS_COMMUNICATION_ADMIN_ACTOR is invalid")
    if not _valid_api_key(supervisor_key) or not _valid_api_key(diagnosis_key):
        parser.error(
            "both communication Agent API keys must be non-placeholder values "
            "with at least 32 characters"
        )
    if supervisor_key == diagnosis_key:
        parser.error("the Supervisor and Diagnosis Agent must use different API keys")
    if not _valid_api_key(admin_key):
        parser.error(
            "the communication administration API key must be a non-placeholder "
            "value with at least 32 characters"
        )
    for name, previous_key in (
        (
            "SAFEHARNESS_COMMUNICATION_SUPERVISOR_PREVIOUS_API_KEY",
            supervisor_previous_key,
        ),
        (
            "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_PREVIOUS_API_KEY",
            diagnosis_previous_key,
        ),
        (
            "SAFEHARNESS_COMMUNICATION_ADMIN_PREVIOUS_API_KEY",
            admin_previous_key,
        ),
    ):
        if previous_key and not _valid_api_key(previous_key):
            parser.error(
                f"{name} must be empty or a non-placeholder value with at least 32 characters"
            )

    supervisor_keys = tuple(
        key for key in (supervisor_key, supervisor_previous_key) if key
    )
    diagnosis_keys = tuple(
        key for key in (diagnosis_key, diagnosis_previous_key) if key
    )
    admin_keys = tuple(key for key in (admin_key, admin_previous_key) if key)

    session_id = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_SESSION_ID", DEFAULT_SESSION_ID
    )
    run_id = os.environ.get("SAFEHARNESS_COMMUNICATION_RUN_ID", DEFAULT_RUN_ID)
    delegation_id = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_DELEGATION_ID", DEFAULT_DELEGATION_ID
    )
    coordination_key = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_COORDINATION_SIGNING_KEY", ""
    )
    coordination_backend = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_COORDINATION_BACKEND",
        "sqlite",
    ).strip().lower()
    coordination_dsn = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_COORDINATION_POSTGRES_DSN",
        "",
    ).strip()
    communication_backend = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_BACKEND",
        "sqlite",
    ).strip().lower()
    communication_dsn = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_POSTGRES_DSN",
        "",
    ).strip()
    communication_initialize = _environment_flag(
        "SAFEHARNESS_COMMUNICATION_POSTGRES_INITIALIZE",
        default=False,
    )
    if coordination_backend not in {"sqlite", "postgres"}:
        parser.error(
            "SAFEHARNESS_COMMUNICATION_COORDINATION_BACKEND must be sqlite or postgres"
        )
    if coordination_backend == "postgres" and not coordination_dsn:
        parser.error(
            "SAFEHARNESS_COMMUNICATION_COORDINATION_POSTGRES_DSN is required for postgres"
        )
    if communication_backend not in {"sqlite", "postgres"}:
        parser.error(
            "SAFEHARNESS_COMMUNICATION_BACKEND must be sqlite or postgres"
        )
    if communication_backend == "postgres" and not communication_dsn:
        parser.error(
            "SAFEHARNESS_COMMUNICATION_POSTGRES_DSN is required for postgres"
        )
    if len(coordination_key.encode("utf-8")) < 32 or coordination_key.lower().startswith(
        "replace-"
    ):
        parser.error(
            "SAFEHARNESS_COMMUNICATION_COORDINATION_SIGNING_KEY must be a non-placeholder "
            "secret of at least 32 bytes"
        )
    configured_secrets = (
        *supervisor_keys,
        *diagnosis_keys,
        *admin_keys,
        coordination_key,
    )
    if len(set(configured_secrets)) != len(configured_secrets):
        parser.error(
            "all current/previous Agent, admin, and coordination secrets must be distinct"
        )
    try:
        delegation_max_messages = int(
            os.environ.get("SAFEHARNESS_COMMUNICATION_DELEGATION_MAX_MESSAGES", "1000")
        )
        delegation_ttl = timedelta(
            seconds=int(
                os.environ.get("SAFEHARNESS_COMMUNICATION_DELEGATION_TTL_SECONDS", "86400")
            )
        )
        application, _ = build_communication_gateway(
            database_path=args.database,
            tenant_id=tenant_id,
            supervisor_agent_id=supervisor_agent_id,
            diagnosis_agent_id=diagnosis_agent_id,
            session_id=session_id,
            run_id=run_id,
            delegation_id=delegation_id,
            delegation_max_messages=delegation_max_messages,
            delegation_ttl=delegation_ttl,
            coordination_signing_key=coordination_key.encode("utf-8"),
            coordination_backend=coordination_backend,
            coordination_postgres_dsn=coordination_dsn or None,
            communication_backend=communication_backend,
            communication_postgres_dsn=communication_dsn or None,
            communication_postgres_initialize=communication_initialize,
        )
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))
    except Exception as exc:
        parser.error(
            "communication gateway initialization failed "
            f"({type(exc).__name__})"
        )

    tls_context = None
    certificate = os.environ.get("SAFEHARNESS_COMMUNICATION_TLS_CERT", "")
    private_key = os.environ.get("SAFEHARNESS_COMMUNICATION_TLS_KEY", "")
    client_ca = os.environ.get("SAFEHARNESS_COMMUNICATION_CLIENT_CA", "")
    require_mtls = _environment_flag(
        "SAFEHARNESS_COMMUNICATION_REQUIRE_MTLS", default=False
    )
    if certificate or private_key or client_ca or require_mtls:
        if not certificate or not private_key:
            parser.error("communication TLS requires both TLS_CERT and TLS_KEY")
        tls_context = create_communication_tls_context(
            certificate=certificate,
            private_key=private_key,
            client_ca=client_ca or None,
            require_client_certificate=require_mtls,
        )

    try:
        rate_limiter = communication_rate_limiter_from_environment()
        telemetry = gateway_telemetry_from_environment(
            default_service_name="safeharness-agent-communication-gateway",
            instrumentation_scope="safeharness.communication.gateway",
            metric_prefix="safeharness.communication.gateway",
            component_description="Agent Communication Gateway",
        )
    except (RuntimeError, ValueError) as exc:
        parser.error(str(exc))

    server = create_communication_server(
        application,
        api_keys={
            (tenant_id, supervisor_agent_id): supervisor_keys,
            (tenant_id, diagnosis_agent_id): diagnosis_keys,
        },
        admin_api_keys={admin_actor: admin_keys},
        host=args.host,
        port=args.port,
        rate_limiter=rate_limiter,
        telemetry=telemetry,
        tls_context=tls_context,
    )
    scheme = "https" if tls_context is not None else "http"
    print(
        "SafeHarness Agent Communication Gateway listening on "
        f"{scheme}://{args.host}:{args.port}"
    )
    print(
        "Allowed topology: "
        f"{supervisor_agent_id} -> {diagnosis_agent_id} [query, delegate]; "
        f"{diagnosis_agent_id} -> {supervisor_agent_id} [response, result]"
    )
    coordination_location = (
        "configured PostgreSQL"
        if coordination_backend == "postgres"
        else str(Path(args.database).resolve())
    )
    print(
        "Mailbox state: "
        f"{Path(args.database).resolve() if communication_backend == 'sqlite' else 'configured PostgreSQL'}; "
        f"communication backend: {communication_backend}; coordination backend: "
        f"{coordination_backend} ({coordination_location})"
    )
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nAgent Communication Gateway stopped.")
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


def _valid_api_key(value: str) -> bool:
    return len(value) >= 32 and not value.lower().startswith("replace-")


if __name__ == "__main__":
    main()
