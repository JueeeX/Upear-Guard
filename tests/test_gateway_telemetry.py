from __future__ import annotations

import unittest
from unittest.mock import patch

from safeharness.gateway.telemetry import (
    GatewayRequestObservation,
    OpenTelemetryGatewayTelemetry,
    gateway_telemetry_from_environment,
)


class GatewayTelemetryTests(unittest.TestCase):
    def test_observation_attributes_are_content_free(self) -> None:
        observation = GatewayRequestObservation(
            method="POST",
            route="/v1/tools/execute",
            status_code=503,
            error_code="gateway_not_ready",
            started_ns=1_000_000,
            ended_ns=3_500_000,
        )

        self.assertEqual(
            observation.attributes,
            {
                "http.request.method": "POST",
                "http.route": "/v1/tools/execute",
                "http.response.status_code": 503,
                "error.type": "gateway_not_ready",
            },
        )
        self.assertEqual(observation.duration_ms, 2.5)

    def test_injected_otel_objects_receive_the_same_sanitized_attributes(self) -> None:
        tracer = _FakeTracer()
        meter = _FakeMeter()
        telemetry = OpenTelemetryGatewayTelemetry(tracer=tracer, meter=meter)
        observation = GatewayRequestObservation(
            method="GET",
            route="/health",
            status_code=200,
            error_code="",
            started_ns=10,
            ended_ns=20,
        )

        telemetry.record_request(observation)

        self.assertEqual(tracer.spans[0].attributes, observation.attributes)
        self.assertEqual(meter.counter.records[0], (1, observation.attributes))
        self.assertEqual(meter.histogram.records[0], (0.00001, observation.attributes))

    def test_environment_is_opt_in_and_validates_boolean(self) -> None:
        self.assertIsNone(gateway_telemetry_from_environment({}))
        with self.assertRaises(ValueError):
            gateway_telemetry_from_environment({"SAFEHARNESS_OTEL_ENABLED": "maybe"})
        with patch(
            "safeharness.gateway.telemetry._otlp_telemetry",
            return_value="telemetry",
        ) as factory:
            result = gateway_telemetry_from_environment(
                {
                    "SAFEHARNESS_OTEL_ENABLED": "true",
                    "SAFEHARNESS_OTEL_SERVICE_NAME": "noc-gateway",
                }
            )

        self.assertEqual(result, "telemetry")
        factory.assert_called_once_with(
            "noc-gateway",
            instrumentation_scope="safeharness.gateway",
            metric_prefix="safeharness.gateway",
            component_description="Tool Security Gateway",
        )


class _FakeSpan:
    def __init__(self, attributes) -> None:
        self.attributes = attributes
        self.end_time = None

    def end(self, *, end_time) -> None:
        self.end_time = end_time


class _FakeTracer:
    def __init__(self) -> None:
        self.spans = []

    def start_span(self, name, *, start_time, attributes):
        span = _FakeSpan(attributes)
        self.spans.append(span)
        return span


class _FakeInstrument:
    def __init__(self) -> None:
        self.records = []

    def add(self, value, attributes) -> None:
        self.records.append((value, attributes))

    def record(self, value, attributes) -> None:
        self.records.append((value, attributes))


class _FakeMeter:
    def __init__(self) -> None:
        self.counter = _FakeInstrument()
        self.histogram = _FakeInstrument()

    def create_counter(self, name, **kwargs):
        return self.counter

    def create_histogram(self, name, **kwargs):
        return self.histogram


if __name__ == "__main__":
    unittest.main()
