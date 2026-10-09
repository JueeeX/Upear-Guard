"""Deterministic network-operations domain used by the LangGraph demo."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from safeharness import Reversibility, ToolDescriptor
from safeharness.adapters import LangGraphTool


class NetworkOperationsEnvironment:
    """Small simulated NMS backend; no real network element is contacted."""

    def __init__(self) -> None:
        self.devices: dict[str, dict[str, Any]] = {
            "NE-WH-OLT-01": {
                "site": "Wuhan-Core-1",
                "vendor": "FiberHome",
                "model": "AN6000",
                "status": "degraded",
                "software": "R3.2.1",
            },
            "NE-WH-RT-02": {
                "site": "Wuhan-Core-2",
                "vendor": "FiberHome",
                "model": "FitRouter",
                "status": "online",
                "software": "R8.1.4",
            },
        }
        self.alarms: dict[str, dict[str, Any]] = {
            "ALM-1001": {
                "device_id": "NE-WH-OLT-01",
                "severity": "critical",
                "name": "PON uplink packet loss",
                "first_seen": "2026-07-14T01:12:00Z",
                "status": "active",
                "probable_cause": "uplink optical power fluctuation",
            },
            "ALM-1002": {
                "device_id": "NE-WH-OLT-01",
                "severity": "major",
                "name": "CPU utilization high",
                "first_seen": "2026-07-14T01:18:00Z",
                "status": "active",
                "probable_cause": "retransmission storm",
            },
        }
        self.metrics: dict[str, dict[str, float]] = {
            "NE-WH-OLT-01": {
                "cpu_percent": 91.4,
                "memory_percent": 68.2,
                "uplink_loss_percent": 12.8,
                "uplink_rx_dbm": -24.7,
            },
            "NE-WH-RT-02": {
                "cpu_percent": 32.0,
                "memory_percent": 45.5,
                "uplink_loss_percent": 0.1,
                "uplink_rx_dbm": -16.4,
            },
        }
        self.tickets: dict[str, dict[str, Any]] = {}
        self.operation_log: list[dict[str, Any]] = []

    def list_active_alarms(
        self,
        severity: str | None = None,
        device_id: str | None = None,
    ) -> list[dict[str, Any]]:
        results = []
        for alarm_id, alarm in self.alarms.items():
            if alarm["status"] != "active":
                continue
            if severity and alarm["severity"] != severity.lower():
                continue
            if device_id and alarm["device_id"] != device_id:
                continue
            results.append({"alarm_id": alarm_id, **deepcopy(alarm)})
        return results

    def get_device_snapshot(self, device_id: str) -> dict[str, Any]:
        device = self._device(device_id)
        return {
            "device_id": device_id,
            **deepcopy(device),
            "metrics": deepcopy(self.metrics.get(device_id, {})),
            "active_alarm_count": len(
                self.list_active_alarms(device_id=device_id)
            ),
        }

    def query_performance(
        self,
        device_id: str,
        metric: str,
        window_minutes: int = 30,
    ) -> dict[str, Any]:
        if not 1 <= window_minutes <= 1440:
            raise ValueError("window_minutes must be between 1 and 1440")
        self._device(device_id)
        values = self.metrics.get(device_id, {})
        if metric not in values:
            raise ValueError(f"unknown metric: {metric}")
        current = values[metric]
        return {
            "device_id": device_id,
            "metric": metric,
            "window_minutes": window_minutes,
            "current": current,
            "minimum": round(current * 0.72, 2),
            "maximum": round(current * 1.06, 2),
            "trend": "rising" if current > 80 or "loss" in metric else "stable",
        }

    def search_runbook(self, symptom: str) -> dict[str, Any]:
        normalized = symptom.lower()
        if "loss" in normalized or "packet" in normalized or "丢包" in symptom:
            return {
                "runbook_id": "RB-NOC-PON-LOSS-001",
                "title": "PON uplink packet-loss triage",
                "recommended_steps": [
                    "Confirm correlated optical-power and interface alarms.",
                    "Compare uplink loss with CPU and retransmission metrics.",
                    "Inspect fiber and optical module before changing configuration.",
                    "Escalate to controlled remediation with operator approval.",
                ],
            }
        return {
            "runbook_id": "RB-NOC-GENERIC-001",
            "title": "Generic network-element incident triage",
            "recommended_steps": [
                "Collect active alarms and current metrics.",
                "Correlate recent changes and affected services.",
                "Open an incident ticket before remediation.",
            ],
        }

    def create_incident_ticket(
        self,
        title: str,
        device_id: str,
        severity: str,
        summary: str,
    ) -> dict[str, Any]:
        self._device(device_id)
        if severity.lower() not in {"critical", "major", "minor", "warning"}:
            raise ValueError("unsupported ticket severity")
        ticket_id = f"INC-{len(self.tickets) + 1:04d}"
        ticket = {
            "ticket_id": ticket_id,
            "title": title,
            "device_id": device_id,
            "severity": severity.lower(),
            "summary": summary,
            "status": "open",
        }
        self.tickets[ticket_id] = ticket
        self.operation_log.append({"action": "create_ticket", **ticket})
        return deepcopy(ticket)

    def restart_interface(
        self,
        device_id: str,
        interface: str,
        reason: str,
        ticket_id: str,
    ) -> dict[str, Any]:
        self._device(device_id)
        if ticket_id not in self.tickets:
            raise ValueError("a valid incident ticket is required")
        operation = {
            "action": "restart_interface",
            "device_id": device_id,
            "interface": interface,
            "reason": reason,
            "ticket_id": ticket_id,
            "status": "simulated_success",
        }
        for alarm in self.alarms.values():
            if alarm["device_id"] == device_id:
                alarm["status"] = "cleared"
                alarm["cleared_by"] = "simulated_interface_restart"
        if device_id in self.metrics:
            self.metrics[device_id]["uplink_loss_percent"] = 0.1
            self.metrics[device_id]["uplink_rx_dbm"] = -16.2
        self.devices[device_id]["status"] = "online"
        self.operation_log.append(operation)
        return deepcopy(operation)

    def close_incident_ticket(
        self,
        ticket_id: str,
        reason: str = "SafeHarness compensation",
    ) -> dict[str, Any]:
        try:
            ticket = self.tickets[ticket_id]
        except KeyError as exc:
            raise ValueError("unknown incident ticket") from exc
        ticket["status"] = "closed"
        operation = {
            "action": "close_ticket",
            "ticket_id": ticket_id,
            "reason": reason,
            "status": "compensated",
        }
        self.operation_log.append(operation)
        return deepcopy(operation)

    def _device(self, device_id: str) -> dict[str, Any]:
        try:
            return self.devices[device_id]
        except KeyError as exc:
            raise ValueError(f"unknown network element: {device_id}") from exc


def build_noc_tools(environment: NetworkOperationsEnvironment) -> list[LangGraphTool]:
    """Build trusted metadata and executors for the simulated NMS backend."""

    return [
        LangGraphTool(
            ToolDescriptor(
                name="list_active_alarms",
                description="List active NMS alarms, optionally filtered by severity or device.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "severity": {"type": ["string", "null"]},
                        "device_id": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
                required_capabilities=frozenset({"nms:alarms:read"}),
                data_classifications=frozenset({"network_operations"}),
            ),
            environment.list_active_alarms,
            resource_resolver=lambda args: str(args.get("device_id") or "all-devices"),
        ),
        LangGraphTool(
            ToolDescriptor(
                name="get_device_snapshot",
                description="Get inventory, health, metrics, and alarm count for one network element.",
                input_schema={
                    "type": "object",
                    "properties": {"device_id": {"type": "string"}},
                    "required": ["device_id"],
                    "additionalProperties": False,
                },
                required_capabilities=frozenset({"nms:devices:read"}),
                data_classifications=frozenset({"network_operations"}),
            ),
            environment.get_device_snapshot,
            resource_resolver=lambda args: str(args.get("device_id", "")),
        ),
        LangGraphTool(
            ToolDescriptor(
                name="query_performance",
                description="Query a recent performance metric for one network element.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "device_id": {"type": "string"},
                        "metric": {"type": "string"},
                        "window_minutes": {
                            "type": "integer",
                        },
                    },
                    "required": ["device_id", "metric"],
                    "additionalProperties": False,
                },
                required_capabilities=frozenset({"nms:performance:read"}),
                data_classifications=frozenset({"network_operations"}),
            ),
            environment.query_performance,
            resource_resolver=lambda args: str(args.get("device_id", "")),
        ),
        LangGraphTool(
            ToolDescriptor(
                name="search_runbook",
                description="Search approved operations runbooks for a fault symptom.",
                input_schema={
                    "type": "object",
                    "properties": {"symptom": {"type": "string"}},
                    "required": ["symptom"],
                    "additionalProperties": False,
                },
                required_capabilities=frozenset({"noc:runbook:read"}),
            ),
            environment.search_runbook,
            resource_resolver=lambda args: "approved-runbooks",
        ),
        LangGraphTool(
            ToolDescriptor(
                name="create_incident_ticket",
                description="Create a simulated NOC incident ticket for an identified fault.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "device_id": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "major", "minor", "warning"],
                        },
                        "summary": {"type": "string"},
                    },
                    "required": ["title", "device_id", "severity", "summary"],
                    "additionalProperties": False,
                },
                required_capabilities=frozenset({"noc:tickets:write"}),
                side_effects=frozenset({"ticketing_system"}),
                data_classifications=frozenset({"network_operations"}),
                reversibility=Reversibility.COMPENSATABLE,
                compensator="close_incident_ticket",
                idempotent=False,
            ),
            environment.create_incident_ticket,
            resource_resolver=lambda args: str(args.get("device_id", "")),
        ),
        LangGraphTool(
            ToolDescriptor(
                name="restart_interface",
                description=(
                    "Restart a network interface. This simulated irreversible action "
                    "requires an incident ticket and explicit operator approval."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "device_id": {"type": "string"},
                        "interface": {"type": "string"},
                        "reason": {"type": "string"},
                        "ticket_id": {"type": "string"},
                    },
                    "required": ["device_id", "interface", "reason", "ticket_id"],
                    "additionalProperties": False,
                },
                required_capabilities=frozenset({"nms:interface:restart"}),
                side_effects=frozenset({"network_availability"}),
                data_classifications=frozenset({"network_operations"}),
                reversibility=Reversibility.IRREVERSIBLE,
                idempotent=False,
            ),
            environment.restart_interface,
            resource_resolver=lambda args: (
                f"{args.get('device_id', '')}:{args.get('interface', '')}"
            ),
        ),
    ]


DEFAULT_NOC_GRANTS = frozenset(
    {
        "nms:alarms:read",
        "nms:devices:read",
        "nms:performance:read",
        "noc:runbook:read",
        "noc:tickets:write",
        "nms:interface:restart",
    }
)

DEFAULT_NOC_READ_ONLY_GRANTS = frozenset(
    {
        "nms:alarms:read",
        "nms:devices:read",
        "nms:performance:read",
        "noc:runbook:read",
    }
)
