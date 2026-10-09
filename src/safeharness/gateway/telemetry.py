"""Low-cardinality, content-free OpenTelemetry for gateway HTTP requests."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class GatewayRequestObservation:
    method: str
    route: str
    status_code: int
    error_code: str
    started_ns: int
    ended_ns: int

    @property
    def duration_ms(self) -> float:
        return max(0, self.ended_ns - self.started_ns) / 1_000_000

    @property
    def attributes(self) -> dict[str, str | int]:
        attributes: dict[str, str | int] = {
            "http.request.method": self.method,
            "http.route": self.route,
            "http.response.status_code": self.status_code,
        }
        if self.error_code:
            attributes["error.type"] = self.error_code
        return attributes


class GatewayTelemetry(Protocol):
    def record_request(self, observation: GatewayRequestObservation) -> None:
        """Record one sanitized request without influencing its outcome."""

    def shutdown(self) -> None:
        """Flush telemetry providers during server shutdown."""


class OpenTelemetryGatewayTelemetry:
    """Emit sanitized spans and metrics through injected OpenTelemetry objects."""

    def __init__(
        self,
        *,
        tracer: Any,
        meter: Any,
        shutdown_callbacks: tuple[Callable[[], Any], ...] = (),
        metric_prefix: str = "safeharness.gateway",
        span_name: str = "safeharness.gateway.http",
        component_description: str = "Tool Security Gateway",
    ) -> None:
        self._tracer = tracer
        self._span_name = span_name
        self._request_count = meter.create_counter(
            f"{metric_prefix}.http.requests",
            unit="{request}",
            description=f"Sanitized {component_description} HTTP request count.",
        )
        self._request_duration = meter.create_histogram(
            f"{metric_prefix}.http.duration",
            unit="ms",
            description=f"Sanitized {component_description} HTTP request duration.",
        )
        self._shutdown_callbacks = shutdown_callbacks

    def record_request(self, observation: GatewayRequestObservation) -> None:
        attributes = observation.attributes
        span = self._tracer.start_span(
            self._span_name,
            start_time=observation.started_ns,
            attributes=attributes,
        )
        span.end(end_time=observation.ended_ns)
        self._request_count.add(1, attributes)
        self._request_duration.record(observation.duration_ms, attributes)

    def shutdown(self) -> None:
        for callback in self._shutdown_callbacks:
            callback()


def gateway_telemetry_from_environment(
    environ: Mapping[str, str] | None = None,
    *,
    default_service_name: str = "safeharness-tool-gateway",
    instrumentation_scope: str = "safeharness.gateway",
    metric_prefix: str = "safeharness.gateway",
    component_description: str = "Tool Security Gateway",
) -> OpenTelemetryGatewayTelemetry | None:
    """Build an OTLP exporter when explicitly enabled in gateway configuration."""

    values = os.environ if environ is None else environ
    enabled = _boolean(values.get("SAFEHARNESS_OTEL_ENABLED", "false"))
    if not enabled:
        return None
    service_name = values.get(
        "SAFEHARNESS_OTEL_SERVICE_NAME",
        default_service_name,
    ).strip()
    if not service_name or len(service_name) > 128:
        raise ValueError("SAFEHARNESS_OTEL_SERVICE_NAME must contain 1-128 characters")
    return _otlp_telemetry(
        service_name,
        instrumentation_scope=instrumentation_scope,
        metric_prefix=metric_prefix,
        component_description=component_description,
    )


def _otlp_telemetry(
    service_name: str,
    *,
    instrumentation_scope: str,
    metric_prefix: str,
    component_description: str,
) -> OpenTelemetryGatewayTelemetry:
    try:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        raise RuntimeError(
            "OpenTelemetry export requires: pip install 'safeharness[observability]'"
        ) from exc

    resource = Resource.create({"service.name": service_name})
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    metric_reader = PeriodicExportingMetricReader(OTLPMetricExporter())
    meter_provider = MeterProvider(resource=resource, metric_readers=(metric_reader,))
    return OpenTelemetryGatewayTelemetry(
        tracer=tracer_provider.get_tracer(instrumentation_scope),
        meter=meter_provider.get_meter(instrumentation_scope),
        shutdown_callbacks=(meter_provider.shutdown, tracer_provider.shutdown),
        metric_prefix=metric_prefix,
        span_name=f"{metric_prefix}.http",
        component_description=component_description,
    )


def _boolean(value: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError("SAFEHARNESS_OTEL_ENABLED must be true or false")
