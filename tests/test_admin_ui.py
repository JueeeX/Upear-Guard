from __future__ import annotations

import json
import hashlib
import hmac
import os
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import Mock, patch

from safeharness.admin_ui import AdminUISettings, create_admin_ui_server
from safeharness.admin_ui.server import _load_admin_ui_config, main


ADMIN_KEY = "a" * 32
UI_TOKEN = "u" * 32
MUTATION_KEY = "m" * 32


def _mutation_envelope(action="agent.quarantine"):
    tenant_id = "fiberhome"
    target_field = "delegation_id" if action == "delegation.revoke" else "agent_id"
    target_id = "delegation-1" if target_field == "delegation_id" else "diagnosis"
    resource_kind = "delegation" if target_field == "delegation_id" else "agent"
    return {
        "schema_version": "1.0",
        "action": action,
        "tenant_id": tenant_id,
        target_field: target_id,
        "resource": f"tenant/{tenant_id}/{resource_kind}/{target_id}",
        "effect": {
            "agent.quarantine": "deny_agent_communication",
            "agent.restore": "restore_agent_communication",
            "delegation.revoke": "revoke_delegated_authority",
        }[action],
        "operator_id": "user-1",
        "reason": "Incident containment",
        "decision_id": "decision-1",
        "approval_id": "approval-1",
        "policy_version": "safeharness.mutations.v1",
        "idempotency_key": "mutation-key-0001",
    }


def _application_envelope(action="capability.enable"):
    target = {
        "capability.enable": {"kind": "skill", "item_id": "skill-1"},
        "plugin.disable": {"install_id": "plugin-1"},
        "automation.run": {"task_id": "task-1"},
    }[action]
    tenant_id = "fiberhome"
    kind, identifier = {
        "capability.enable": ("capability/skill", "skill-1"),
        "plugin.disable": ("plugin", "plugin-1"),
        "automation.run": ("automation", "task-1"),
    }[action]
    return {
        "schema_version": "1.0",
        "action": action,
        "tenant_id": tenant_id,
        **target,
        "resource": f"tenant/{tenant_id}/{kind}/{identifier}",
        "effect": {
            "capability.enable": "enable_capability",
            "plugin.disable": "disable_plugin",
            "automation.run": "schedule_automation_run",
        }[action],
        "operator_id": "user-1",
        "reason": "Controlled application change",
        "decision_id": "decision-1",
        "approval_id": "approval-1",
        "policy_version": "safeharness.mutations.v1",
        "idempotency_key": "mutation-key-0001",
    }


class _UpstreamHandler(BaseHTTPRequestHandler):
    server: ThreadingHTTPServer

    def do_GET(self) -> None:
        self._record()
        self._write(
            {
                "ok": True,
                "version": 1,
                "signature": "signed-state",
                "occurred_at": "2026-07-23T08:00:00+00:00",
                "operation": "bootstrap",
                "actor": "operator",
                "state": {
                    "agents": [],
                    "topology": [],
                    "delegations": [],
                    "quarantined": [],
                    "revoked_delegations": [],
                },
            }
        )

    def do_POST(self) -> None:
        self._record()
        self._write(
            {
                "ok": True,
                "version": 2,
                "signature": "signed-state-2",
                "occurred_at": "2026-07-23T08:01:00+00:00",
                "operation": "quarantine_agent",
                "actor": "operator",
                "state": {
                    "agents": [],
                    "topology": [],
                    "delegations": [],
                    "quarantined": [],
                    "revoked_delegations": [],
                },
            }
        )

    def _record(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.server.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization", ""),
                "body": self.rfile.read(length).decode("utf-8") if length else "",
            }
        )

    def _write(self, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


@contextmanager
def _running(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield "http://" + host + ":" + str(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _json_request(url, path, *, token="", mutation_key="", method="GET", body=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["X-SafeHarness-UI-Token"] = token
    if mutation_key:
        headers["X-SafeHarness-Mutation-Key"] = mutation_key
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url + path, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        finally:
            exc.close()


class AdminUITests(unittest.TestCase):
    def test_static_ui_and_overview_proxy_keep_admin_key_server_side(self) -> None:
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        upstream.requests = []
        with _running(upstream) as upstream_url:
            settings = AdminUISettings(
                upstream_url=upstream_url,
                admin_key=ADMIN_KEY,
                access_token=UI_TOKEN,
            )
            ui = create_admin_ui_server(settings, host="127.0.0.1", port=0)
            with _running(ui) as ui_url:
                with urlopen(ui_url + "/", timeout=3) as response:
                    page = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertIn("SafeHarness 管理控制台", page)
                    self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
                for path, marker in (
                    ("/static/app.css", "--blue-600"),
                    ("/static/app.js", "refreshOverview"),
                ):
                    with urlopen(ui_url + path, timeout=3) as response:
                        self.assertEqual(response.status, 200)
                        self.assertIn(marker, response.read().decode("utf-8"))

                status, denied = _json_request(ui_url, "/api/overview")
                self.assertEqual(status, 401)
                self.assertEqual(denied["error"]["code"], "ui_unauthorized")

                status, overview = _json_request(ui_url, "/api/overview", token=UI_TOKEN)
                self.assertEqual(status, 200)
                self.assertEqual(overview["version"], 1)
                self.assertNotIn(ADMIN_KEY, json.dumps(overview))
                self.assertEqual(len(upstream.requests), 1)
                self.assertEqual(
                    upstream.requests[0]["authorization"],
                    "Bearer " + ADMIN_KEY,
                )
                self.assertEqual(upstream.requests[0]["path"], "/v1/admin/coordination")

    def test_proxy_allows_only_strict_agent_operations(self) -> None:
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        upstream.requests = []
        with _running(upstream) as upstream_url:
            ui = create_admin_ui_server(
                AdminUISettings(
                    upstream_url=upstream_url,
                    admin_key=ADMIN_KEY,
                    access_token=UI_TOKEN,
                    mutation_key=MUTATION_KEY,
                ),
                host="127.0.0.1",
                port=0,
            )
            with _running(ui) as ui_url:
                status, invalid = _json_request(
                    ui_url,
                    "/api/agents/quarantine",
                    token=UI_TOKEN,
                    mutation_key=MUTATION_KEY,
                    method="POST",
                    body=b'{"tenant_id":"one","tenant_id":"two","agent_id":"diagnosis"}',
                )
                self.assertEqual(status, 400)
                self.assertEqual(invalid["error"]["code"], "invalid_request")
                self.assertEqual(upstream.requests, [])

                status, denied = _json_request(
                    ui_url,
                    "/api/agents/quarantine",
                    token=UI_TOKEN,
                    method="POST",
                    body=_mutation_envelope(),
                )
                self.assertEqual(status, 401)
                self.assertEqual(denied["error"]["code"], "mutation_unauthorized")
                self.assertEqual(upstream.requests, [])

                status, result = _json_request(
                    ui_url,
                    "/api/agents/quarantine",
                    token=UI_TOKEN,
                    mutation_key=MUTATION_KEY,
                    method="POST",
                    body=_mutation_envelope(),
                )
                self.assertEqual(status, 200)
                self.assertEqual(result["version"], 2)
                self.assertEqual(len(upstream.requests), 1)
                self.assertEqual(
                    upstream.requests[0]["path"],
                    "/v1/admin/agents/quarantine",
                )
                self.assertEqual(
                    json.loads(upstream.requests[0]["body"]),
                    _mutation_envelope(),
                )

                status, _ = _json_request(
                    ui_url,
                    "/api/delegations/revoke",
                    token=UI_TOKEN,
                    mutation_key=MUTATION_KEY,
                    method="POST",
                    body=_mutation_envelope("delegation.revoke"),
                )
                self.assertEqual(status, 200)
                self.assertEqual(upstream.requests[1]["path"], "/v1/admin/delegations/revoke")

    def test_partial_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "configured together"):
            create_admin_ui_server(
                AdminUISettings(upstream_url="http://127.0.0.1:38200"),
                host="127.0.0.1",
                port=38309,
            )

    def test_application_authorization_is_strict_and_signed_without_upstream_write(self) -> None:
        ui = create_admin_ui_server(
            AdminUISettings(
                upstream_url="http://127.0.0.1:9",
                admin_key=ADMIN_KEY,
                access_token=UI_TOKEN,
                mutation_key=MUTATION_KEY,
            ),
            host="127.0.0.1",
            port=0,
        )
        with _running(ui) as ui_url:
            invalid = {**_application_envelope(), "item_id": "other"}
            status, body = _json_request(
                ui_url,
                "/api/application-mutations/authorize",
                token=UI_TOKEN,
                mutation_key=MUTATION_KEY,
                method="POST",
                body=invalid,
            )
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_request")

            envelope = _application_envelope("automation.run")
            status, authorization = _json_request(
                ui_url,
                "/api/application-mutations/authorize",
                token=UI_TOKEN,
                mutation_key=MUTATION_KEY,
                method="POST",
                body=envelope,
            )
            encoded = json.dumps(
                envelope, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            expected = hmac.new(
                MUTATION_KEY.encode(),
                b"safeharness-application-authorization-v1\0" + encoded,
                hashlib.sha256,
            ).hexdigest()
            self.assertEqual(status, 200)
            self.assertEqual(authorization["signature"], expected)
            self.assertEqual(authorization["envelope_digest"], hashlib.sha256(encoded).hexdigest())
            self.assertFalse(authorization["persistent"])
            self.assertFalse(authorization["gateway_verified"])

    def test_admin_ui_config_is_allowlisted_and_environment_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "admin-ui.env"
            path.write_text(
                "\n".join(
                    (
                        "SAFEHARNESS_ADMIN_UI_HOST=127.0.0.1",
                        "SAFEHARNESS_ADMIN_UI_PORT=39308",
                        "SAFEHARNESS_ADMIN_UI_UPSTREAM_URL=http://127.0.0.1:38200",
                        "SAFEHARNESS_ADMIN_UI_ADMIN_KEY=" + ADMIN_KEY,
                        "SAFEHARNESS_ADMIN_UI_ACCESS_TOKEN=" + UI_TOKEN,
                    )
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"SAFEHARNESS_ADMIN_UI_ACCESS_TOKEN": "e" * 32},
                clear=True,
            ):
                self.assertEqual(_load_admin_ui_config(str(path)), path)
                settings = AdminUISettings.from_environment()
                self.assertEqual(os.environ["SAFEHARNESS_ADMIN_UI_PORT"], "39308")
                self.assertEqual(settings.access_token, "e" * 32)
                self.assertEqual(settings.configured_upstream_url, "http://127.0.0.1:38200")

            path.write_text("NOT_AN_ADMIN_UI_SETTING=value\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported admin UI config key"):
                _load_admin_ui_config(str(path))

    def test_main_uses_host_and_port_from_admin_ui_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "admin-ui.env"
            path.write_text(
                "SAFEHARNESS_ADMIN_UI_HOST=127.0.0.1\n"
                "SAFEHARNESS_ADMIN_UI_PORT=39308\n",
                encoding="utf-8",
            )
            server = Mock()
            with (
                patch.dict(os.environ, {}, clear=True),
                patch("safeharness.admin_ui.server.create_admin_ui_server", return_value=server) as create,
            ):
                self.assertEqual(main(["--config", str(path)]), 0)
            create.assert_called_once_with(host="127.0.0.1", port=39308)
            server.serve_forever.assert_called_once_with()
            server.server_close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
