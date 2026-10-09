"""Exercise the real Redis/PostgreSQL/OTLP staging topology."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import os
import time
from urllib.request import urlopen
from uuid import uuid4

import psycopg
from redis import Redis
from redis.exceptions import NoPermissionError

from examples.langgraph_noc.domain import build_noc_tools, NetworkOperationsEnvironment
from safeharness import SessionContext, ToolInvocation
from safeharness.backends import (
    RedisCapabilityReplayStore,
    RedisEnforcementReceiptReplayStore,
    build_enforcement_receipt_issuer_from_environment,
)
from safeharness.gateway import RemoteToolGatewayClient, ToolGatewayError


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


async def _gateway_round_trip() -> tuple[str, tuple[str, ...]]:
    api_key = _required("SAFEHARNESS_TOOL_GATEWAY_API_KEY")
    primary = RemoteToolGatewayClient(
        _required("SAFEHARNESS_TOOL_GATEWAY_URL"),
        api_key,
    )
    replica = RemoteToolGatewayClient(
        _required("SAFEHARNESS_SMOKE_GATEWAY_REPLICA_URL"),
        api_key,
    )
    for health in await asyncio.gather(primary.health(), replica.health()):
        if (
            health.get("service") != "safeharness-tool-gateway"
            or health.get("status") != "ready"
        ):
            raise AssertionError("gateway replica health response is not ready")

    tools = build_noc_tools(NetworkOperationsEnvironment())
    tool = next(item for item in tools if item.descriptor.name == "get_device_snapshot")
    session_id = f"staging-smoke-{uuid4()}"
    context = SessionContext(
        tenant_id="fiberhome-demo",
        agent_id="noc-operator-agent",
        session_id=session_id,
        framework="staging-smoke",
    )
    invocation = ToolInvocation(
        tool.descriptor.name,
        {"device_id": "NE-WH-OLT-01"},
        tool_version=tool.descriptor.version,
        resource="NE-WH-OLT-01",
    )
    grant = await primary.issue(context, tool.descriptor, invocation)
    receipt_issuer = build_enforcement_receipt_issuer_from_environment()
    if receipt_issuer is None:
        raise RuntimeError("an enforcement receipt issuer is required")
    receipt = await receipt_issuer.issue(
        context,
        tool.descriptor,
        invocation,
        decision_id=f"staging-decision-{uuid4()}",
        event_id=f"staging-event-{uuid4()}",
        policy_version="staging-smoke.v1",
    )
    authorized = ToolInvocation(
        invocation.tool_name,
        invocation.arguments,
        call_id=invocation.call_id,
        tool_version=invocation.tool_version,
        resource=invocation.resource,
        capability_token=grant.token,
        enforcement_receipt=receipt,
    )
    results = await asyncio.gather(
        primary.execute(context, authorized),
        replica.execute(context, authorized),
        return_exceptions=True,
    )
    successes = [result for result in results if not isinstance(result, Exception)]
    failures = [result for result in results if isinstance(result, ToolGatewayError)]
    if len(successes) != 1 or successes[0].get("device_id") != "NE-WH-OLT-01":
        raise AssertionError("gateway returned an unexpected simulated NMS result")
    replay_codes = {"capability_token_replayed", "enforcement_receipt_replayed"}
    if len(failures) != 1 or failures[0].code not in replay_codes:
        raise AssertionError("gateway replicas did not share atomic replay state")
    try:
        await primary.execute(context, authorized)
    except ToolGatewayError as exc:
        if exc.code not in replay_codes:
            raise
    else:
        raise AssertionError("a consumed capability token was accepted twice")
    return session_id, (api_key, grant.token, receipt, "NE-WH-OLT-01", "AN6000")


async def _redis_checks() -> None:
    gateway_url = _required("SAFEHARNESS_TOOL_GATEWAY_REDIS_URL")
    token_id = f"raw-staging-token-{uuid4()}"
    expiry = datetime.now(timezone.utc) + timedelta(minutes=2)
    stores = (
        RedisCapabilityReplayStore(gateway_url),
        RedisCapabilityReplayStore(gateway_url),
    )
    try:
        consumed = await asyncio.gather(
            stores[0].consume(token_id, expiry),
            stores[1].consume(token_id, expiry),
        )
        if sorted(consumed) != [False, True]:
            raise AssertionError("Redis did not atomically consume exactly one token")
    finally:
        await asyncio.gather(*(store.close() for store in stores))

    receipt_id = f"raw-staging-receipt-{uuid4()}"
    receipt_stores = (
        RedisEnforcementReceiptReplayStore(gateway_url),
        RedisEnforcementReceiptReplayStore(gateway_url),
    )
    try:
        consumed = await asyncio.gather(
            receipt_stores[0].consume(receipt_id, expiry),
            receipt_stores[1].consume(receipt_id, expiry),
        )
        if sorted(consumed) != [False, True]:
            raise AssertionError("Redis receipt replay consumption was not atomic")
    finally:
        await asyncio.gather(*(store.close() for store in receipt_stores))

    gateway_client = Redis.from_url(gateway_url, decode_responses=True)
    try:
        try:
            gateway_client.get("safeharness:capability-replay:health")
        except NoPermissionError:
            pass
        else:
            raise AssertionError("Redis gateway user unexpectedly has GET permission")
    finally:
        gateway_client.close()

    admin = Redis.from_url(
        _required("SAFEHARNESS_SMOKE_REDIS_ADMIN_URL"),
        decode_responses=True,
    )
    try:
        expected = "safeharness:capability-replay:" + hashlib.sha256(
            token_id.encode("utf-8")
        ).hexdigest()
        keys = set(admin.scan_iter(match="safeharness:capability-replay:*"))
        if expected not in keys or any(token_id in key for key in keys):
            raise AssertionError("Redis replay keys did not minimize raw token identifiers")
        expected_receipt = "safeharness:receipt-replay:" + hashlib.sha256(
            receipt_id.encode("utf-8")
        ).hexdigest()
        receipt_keys = set(admin.scan_iter(match="safeharness:receipt-replay:*"))
        if expected_receipt not in receipt_keys or any(
            receipt_id in key for key in receipt_keys
        ):
            raise AssertionError("Redis receipt keys did not minimize raw identifiers")
    finally:
        admin.close()


def _postgres_checks(session_id: str, forbidden_values: tuple[str, ...]) -> None:
    reader_dsn = _required("SAFEHARNESS_SMOKE_POSTGRES_READER_DSN")
    writer_dsn = _required("SAFEHARNESS_SMOKE_POSTGRES_WRITER_DSN")
    migrator_dsn = _required("SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN")

    with psycopg.connect(reader_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*), COALESCE(string_agg(to_jsonb(a)::text, ' '), '') "
                "FROM safeharness_audit_records AS a WHERE session_id = %s",
                (session_id,),
            )
            count, payloads = cursor.fetchone()
            if count < 4:
                raise AssertionError("expected gateway audit records were not persisted")
            if any(value and value in payloads for value in forbidden_values):
                raise AssertionError("raw capability, arguments, or results reached audit payloads")

    with psycopg.connect(writer_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT has_table_privilege(current_user, 'safeharness_audit_records', 'INSERT'), "
                "has_table_privilege(current_user, 'safeharness_audit_records', 'UPDATE'), "
                "has_table_privilege(current_user, 'safeharness_audit_records', 'DELETE')"
            )
            if cursor.fetchone() != (True, False, False):
                raise AssertionError("PostgreSQL writer role is not INSERT-only")
            try:
                cursor.execute(
                    "UPDATE safeharness_audit_records SET outcome = outcome "
                    "WHERE session_id = %s",
                    (session_id,),
                )
            except psycopg.errors.InsufficientPrivilege:
                connection.rollback()
            else:
                raise AssertionError("PostgreSQL writer unexpectedly updated audit data")

    connection = psycopg.connect(migrator_dsn)
    try:
        with connection.cursor() as cursor:
            try:
                cursor.execute(
                    "UPDATE safeharness_audit_records SET outcome = outcome "
                    "WHERE session_id = %s",
                    (session_id,),
                )
            except psycopg.errors.RaiseException:
                connection.rollback()
            else:
                raise AssertionError("append-only trigger accepted an UPDATE")
    finally:
        connection.close()


def _otel_checks(forbidden_values: tuple[str, ...]) -> None:
    endpoint = _required("SAFEHARNESS_SMOKE_OTEL_METRICS_URL")
    deadline = time.monotonic() + 20
    metrics = ""
    while time.monotonic() < deadline:
        with urlopen(endpoint, timeout=3) as response:
            metrics = response.read(2 * 1024 * 1024).decode("utf-8")
        if "safeharness_gateway_http_requests" in metrics:
            break
        time.sleep(1)
    else:
        raise AssertionError("OTLP metrics did not reach the collector")
    if any(value and value in metrics for value in forbidden_values):
        raise AssertionError("sensitive gateway values reached telemetry")


async def main() -> None:
    session_id, forbidden_values = await _gateway_round_trip()
    await _redis_checks()
    _postgres_checks(session_id, forbidden_values)
    _otel_checks((*forbidden_values, "fiberhome-demo", "noc-operator-agent"))
    print("SafeHarness staging smoke test passed: gateway, replay, audit, and OTLP.")


if __name__ == "__main__":
    asyncio.run(main())
