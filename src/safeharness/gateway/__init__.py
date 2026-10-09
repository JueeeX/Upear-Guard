"""Independent Tool Security Gateway service and client."""

from safeharness.gateway.client import RemoteToolGatewayClient, ToolGatewayError
from safeharness.gateway.protocol import PROTOCOL_VERSION
from safeharness.gateway.persistence import GatewayPersistence, build_gateway_persistence
from safeharness.gateway.service import (
    RegisteredTool,
    ToolGatewayApplication,
    ToolGatewayHTTPServer,
    ToolRegistry,
    create_gateway_server,
    create_server_tls_context,
)
from safeharness.gateway.telemetry import (
    GatewayRequestObservation,
    GatewayTelemetry,
    OpenTelemetryGatewayTelemetry,
    gateway_telemetry_from_environment,
)

__all__ = [
    "PROTOCOL_VERSION",
    "RegisteredTool",
    "RemoteToolGatewayClient",
    "ToolGatewayApplication",
    "ToolGatewayError",
    "ToolGatewayHTTPServer",
    "ToolRegistry",
    "GatewayPersistence",
    "GatewayRequestObservation",
    "GatewayTelemetry",
    "OpenTelemetryGatewayTelemetry",
    "build_gateway_persistence",
    "gateway_telemetry_from_environment",
    "create_gateway_server",
    "create_server_tls_context",
]
