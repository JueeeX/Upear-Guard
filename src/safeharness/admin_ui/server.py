"""Loopback-first management UI that keeps coordination admin keys server-side."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from safeharness.backends.sqlite import SQLiteAuditReader
from safeharness.communication.protocol import strict_json_loads


logger = logging.getLogger(__name__)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_ACTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_MAX_REQUEST_BYTES = 8 * 1024
_MAX_UPSTREAM_BYTES = 1024 * 1024
_DEFAULT_CONFIG_PATH = "config/admin-ui.env"
_CONFIG_KEYS = frozenset(
    {
        "SAFEHARNESS_ADMIN_UI_HOST",
        "SAFEHARNESS_ADMIN_UI_PORT",
        "SAFEHARNESS_ADMIN_UI_UPSTREAM_URL",
        "SAFEHARNESS_ADMIN_UI_ADMIN_KEY",
        "SAFEHARNESS_ADMIN_UI_ACCESS_TOKEN",
        "SAFEHARNESS_ADMIN_UI_MUTATION_KEY",
        "SAFEHARNESS_ADMIN_UI_AUDIT_DATABASE",
        "SAFEHARNESS_ADMIN_UI_TIMEOUT_SECONDS",
    }
)
_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
_MUTATION_ROUTES = {
    "/api/agents/quarantine": "/v1/admin/agents/quarantine",
    "/api/agents/restore": "/v1/admin/agents/restore",
    "/api/delegations/revoke": "/v1/admin/delegations/revoke",
}
_MUTATION_SPECS = {
    "/api/agents/quarantine": ("agent.quarantine", "agent_id", "agent", "deny_agent_communication"),
    "/api/agents/restore": ("agent.restore", "agent_id", "agent", "restore_agent_communication"),
    "/api/delegations/revoke": (
        "delegation.revoke", "delegation_id", "delegation", "revoke_delegated_authority"
    ),
}
_APPLICATION_MUTATION_ROUTE = "/api/application-mutations/authorize"
_APPLICATION_MUTATION_SPECS = {
    "capability.enable": ({"kind", "item_id"}, "enable_capability"),
    "capability.disable": ({"kind", "item_id"}, "disable_capability"),
    "plugin.enable": ({"install_id"}, "enable_plugin"),
    "plugin.disable": ({"install_id"}, "disable_plugin"),
    "automation.run": ({"task_id"}, "schedule_automation_run"),
}


@dataclass(frozen=True)
class AdminUISettings:
    """Runtime-only UI settings populated from process environment."""

    upstream_url: str = ""
    admin_key: str = ""
    access_token: str = ""
    mutation_key: str = ""
    audit_database: str = ""
    request_timeout_seconds: float = 5.0

    @classmethod
    def from_environment(cls) -> "AdminUISettings":
        raw_timeout = os.environ.get("SAFEHARNESS_ADMIN_UI_TIMEOUT_SECONDS", "5")
        try:
            timeout = float(raw_timeout)
        except ValueError:
            timeout = 5.0
        return cls(
            upstream_url=os.environ.get("SAFEHARNESS_ADMIN_UI_UPSTREAM_URL", ""),
            admin_key=os.environ.get("SAFEHARNESS_ADMIN_UI_ADMIN_KEY", ""),
            access_token=os.environ.get("SAFEHARNESS_ADMIN_UI_ACCESS_TOKEN", ""),
            mutation_key=os.environ.get("SAFEHARNESS_ADMIN_UI_MUTATION_KEY", ""),
            audit_database=os.environ.get("SAFEHARNESS_ADMIN_UI_AUDIT_DATABASE", ""),
            request_timeout_seconds=timeout,
        )

    def validate(self) -> None:
        upstream = self.upstream_url.strip()
        admin_key = self.admin_key.strip()
        access_token = self.access_token.strip()
        if bool(upstream) != bool(admin_key):
            raise ValueError(
                "SAFEHARNESS_ADMIN_UI_UPSTREAM_URL and "
                "SAFEHARNESS_ADMIN_UI_ADMIN_KEY must be configured together"
            )
        if upstream:
            _normalise_upstream_url(upstream)
            if len(admin_key) < 32:
                raise ValueError("SAFEHARNESS_ADMIN_UI_ADMIN_KEY must be at least 32 characters")
            if len(access_token) < 32:
                raise ValueError(
                    "SAFEHARNESS_ADMIN_UI_ACCESS_TOKEN must be at least 32 characters"
                )
        elif access_token:
            raise ValueError(
                "SAFEHARNESS_ADMIN_UI_ACCESS_TOKEN requires a configured upstream URL"
            )
        if self.audit_database and len(access_token) < 32:
            raise ValueError(
                "SAFEHARNESS_ADMIN_UI_AUDIT_DATABASE requires an access token"
            )
        if self.mutation_key and len(self.mutation_key.strip()) < 32:
            raise ValueError("SAFEHARNESS_ADMIN_UI_MUTATION_KEY must be at least 32 characters")
        if not 1 <= self.request_timeout_seconds <= 30:
            raise ValueError("SAFEHARNESS_ADMIN_UI_TIMEOUT_SECONDS must be between 1 and 30")

    @property
    def configured_upstream_url(self) -> str:
        return _normalise_upstream_url(self.upstream_url.strip()) if self.upstream_url else ""


class AdminUIHTTPServer(ThreadingHTTPServer):
    """Threaded loopback console server with a deliberately narrow proxy surface."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        settings: AdminUISettings,
    ) -> None:
        settings.validate()
        host = server_address[0].strip().lower()
        if host not in {"127.0.0.1", "::1", "localhost"} and not settings.access_token:
            raise ValueError("a non-loopback UI listener requires an access token")
        self.settings = settings
        super().__init__(server_address, AdminUIRequestHandler)


class AdminUIRequestHandler(BaseHTTPRequestHandler):
    """Serve static assets and proxy only named coordination admin operations."""

    server: AdminUIHTTPServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path in _ASSETS:
            self._serve_asset(parsed.path)
            return
        if parsed.path == "/api/overview":
            if not self._require_browser_token():
                return
            self._write_upstream("GET", "/v1/admin/coordination")
            return
        if parsed.path == "/api/audit":
            if not self._require_browser_token():
                return
            self._read_audit(parsed.query)
            return
        self._write_json(
            HTTPStatus.NOT_FOUND,
            _error("not_found", "The requested UI resource does not exist."),
        )

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == _APPLICATION_MUTATION_ROUTE:
            if not self._require_browser_token() or not self._require_mutation_key():
                return
            payload = self._read_application_authorization()
            if payload is not None:
                self._write_json(HTTPStatus.OK, _application_authorization(payload, self.server.settings.mutation_key))
            return
        upstream_route = _MUTATION_ROUTES.get(parsed.path)
        if upstream_route is None:
            self._write_json(
                HTTPStatus.NOT_FOUND,
                _error("not_found", "The requested UI operation does not exist."),
            )
            return
        if not self._require_browser_token():
            return
        if not self._require_mutation_key():
            return
        payload = self._read_controlled_operation()
        if payload is None:
            return
        self._write_upstream("POST", upstream_route, payload)

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def log_message(self, format: str, *args: Any) -> None:
        path = urlsplit(self.path).path
        logger.info(
            "SafeHarness admin UI: method=%s route=%s",
            self.command if self.command in {"GET", "POST"} else "OTHER",
            path if path in {*_ASSETS, "/api/overview", "/api/audit", _APPLICATION_MUTATION_ROUTE, *_MUTATION_ROUTES} else "unmatched",
        )

    def _serve_asset(self, route: str) -> None:
        name, content_type = _ASSETS[route]
        try:
            body = resources.files("safeharness.admin_ui").joinpath("static", name).read_bytes()
        except (FileNotFoundError, ModuleNotFoundError):
            self._write_json(
                HTTPStatus.NOT_FOUND,
                _error("asset_not_found", "The requested UI asset does not exist."),
            )
            return
        self._write(HTTPStatus.OK, body, content_type)

    def _require_browser_token(self) -> bool:
        expected = self.server.settings.access_token
        if not expected:
            self._write_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                _error(
                    "configuration_required",
                    "The management UI upstream and access token are not configured.",
                ),
            )
            return False
        supplied = self.headers.get("X-SafeHarness-UI-Token", "")
        if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
            self._write_json(
                HTTPStatus.UNAUTHORIZED,
                _error("ui_unauthorized", "A valid management UI access token is required."),
            )
            return False
        return True

    def _read_controlled_operation(self) -> dict[str, str] | None:
        value = self._read_json_body()
        if value is None:
            return None
        expected_action, target_field, resource_kind, expected_effect = _MUTATION_SPECS[
            urlsplit(self.path).path
        ]
        required = {
            "schema_version", "action", "tenant_id", target_field, "resource", "effect",
            "operator_id", "reason", "decision_id", "approval_id", "policy_version",
            "idempotency_key",
        }
        if set(value) != required:
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                _error("invalid_request", "The UI request body is invalid."),
            )
            return None
        tenant_id = value.get("tenant_id")
        target_id = value.get(target_field)
        action = value.get("action")
        if not (
            value.get("schema_version") == "1.0"
            and action == expected_action
            and isinstance(tenant_id, str)
            and isinstance(target_id, str)
            and _IDENTIFIER.fullmatch(tenant_id)
            and _IDENTIFIER.fullmatch(target_id)
            and value.get("resource") == f"tenant/{tenant_id}/{resource_kind}/{target_id}"
            and value.get("effect") == expected_effect
            and all(
                isinstance(value.get(name), str)
                and _IDENTIFIER.fullmatch(value[name])
                for name in (
                    "operator_id", "decision_id", "approval_id", "policy_version",
                    "idempotency_key",
                )
            )
            and isinstance(value.get("reason"), str)
            and 3 <= len(value["reason"].strip()) <= 500
        ):
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                _error("invalid_request", "The UI request body is invalid."),
            )
            return None
        return value

    def _read_application_authorization(self) -> dict[str, str] | None:
        value = self._read_json_body()
        if value is None:
            return None
        action = value.get("action") if isinstance(value, dict) else None
        spec = _APPLICATION_MUTATION_SPECS.get(action)
        if spec is None:
            self._invalid_request()
            return None
        target_fields, expected_effect = spec
        required = {
            "schema_version", "action", "tenant_id", *target_fields, "resource", "effect",
            "operator_id", "reason", "decision_id", "approval_id", "policy_version",
            "idempotency_key",
        }
        tenant_id = value.get("tenant_id")
        identifiers = ("tenant_id", *target_fields, "operator_id", "decision_id", "approval_id", "policy_version", "idempotency_key")
        if (
            set(value) != required
            or value.get("schema_version") != "1.0"
            or value.get("effect") != expected_effect
            or not all(isinstance(value.get(name), str) and _IDENTIFIER.fullmatch(value[name]) for name in identifiers)
            or not isinstance(value.get("reason"), str)
            or not 3 <= len(value["reason"].strip()) <= 500
            or value.get("resource") != _application_resource(action, tenant_id, value)
            or ("kind" in target_fields and value.get("kind") not in {"skill", "agent", "mcp"})
        ):
            self._invalid_request()
            return None
        return value

    def _read_json_body(self) -> dict[str, Any] | None:
        if self.headers.get("Transfer-Encoding"):
            self._invalid_request()
            return None
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._write_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                _error("content_type_required", "Content-Type must be application/json."),
            )
            return None
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length < 0 or length > _MAX_REQUEST_BYTES:
            self._invalid_request()
            return None
        try:
            value = strict_json_loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._invalid_request()
            return None
        if not isinstance(value, dict):
            self._invalid_request()
            return None
        return value

    def _invalid_request(self) -> None:
        self._write_json(
            HTTPStatus.BAD_REQUEST,
            _error("invalid_request", "The UI request body is invalid."),
        )

    def _require_mutation_key(self) -> bool:
        expected = self.server.settings.mutation_key.strip()
        supplied = self.headers.get("X-SafeHarness-Mutation-Key", "")
        if not expected:
            self._write_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                _error("mutation_channel_unavailable", "The controlled mutation channel is not configured."),
            )
            return False
        if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
            self._write_json(
                HTTPStatus.UNAUTHORIZED,
                _error("mutation_unauthorized", "A valid server mutation key is required."),
            )
            return False
        return True

    def _read_audit(self, query: str) -> None:
        database = self.server.settings.audit_database
        if not database:
            self._write_json(HTTPStatus.OK, {"ok": True, "available": False, "records": []})
            return
        try:
            filters = _audit_filters(query)
            reader = SQLiteAuditReader(database)
            records = asyncio.run(reader.query(**filters))
        except (OSError, RuntimeError, ValueError):
            self._write_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                _error("audit_unavailable", "The configured audit source is unavailable."),
            )
            return
        self._write_json(HTTPStatus.OK, {"ok": True, "available": True, "records": records})

    def _write_upstream(
        self,
        method: str,
        path: str,
        payload: dict[str, str] | None = None,
    ) -> None:
        status, response = _upstream_request(
            self.server.settings,
            method=method,
            path=path,
            payload=payload,
        )
        self._write_json(status, response)

    def _method_not_allowed(self) -> None:
        self._write_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            _error("method_not_allowed", "The HTTP method is not supported."),
        )

    def _write_json(self, status: int | HTTPStatus, payload: dict[str, Any]) -> None:
        self._write(
            status,
            json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
                "utf-8"
            ),
            "application/json; charset=utf-8",
        )

    def _write(self, status: int | HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", _content_security_policy())
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _application_resource(action: str, tenant_id: str, value: dict[str, Any]) -> str:
    kind, identifier = {
        "capability.enable": (f"capability/{value.get('kind')}", value.get("item_id")),
        "capability.disable": (f"capability/{value.get('kind')}", value.get("item_id")),
        "plugin.enable": ("plugin", value.get("install_id")),
        "plugin.disable": ("plugin", value.get("install_id")),
        "automation.run": ("automation", value.get("task_id")),
    }[action]
    return f"tenant/{tenant_id}/{kind}/{identifier}"


def _application_authorization(payload: dict[str, str], mutation_key: str) -> dict[str, Any]:
    encoded = json.dumps(
        payload, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    signature = hmac.new(
        mutation_key.strip().encode("utf-8"),
        b"safeharness-application-authorization-v1\0" + encoded,
        hashlib.sha256,
    ).hexdigest()
    return {
        "ok": True,
        "schema_version": "1.0",
        "operation": "authorize_application_mutation",
        "action": payload["action"],
        "authorization_id": signature,
        "signature": signature,
        "envelope_digest": digest,
        "audit_reference": f"application-authorization:{signature}",
        "integrity": "hmac_envelope_signature",
        "persistent": False,
        "gateway_verified": False,
        "production_ready": False,
    }


def create_admin_ui_server(
    settings: AdminUISettings | None = None,
    *,
    host: str = "127.0.0.1",
    port: int = 38308,
) -> AdminUIHTTPServer:
    """Create the UI server without starting it."""

    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return AdminUIHTTPServer((host, port), settings or AdminUISettings.from_environment())


def main(argv: list[str] | None = None) -> int:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument(
        "--config",
        default=os.environ.get("SAFEHARNESS_ADMIN_UI_CONFIG_FILE") or _DEFAULT_CONFIG_PATH,
        help="Optional admin UI dotenv file (default: config/admin-ui.env when present).",
    )
    config_args, _ = config_parser.parse_known_args(argv)
    config_path = config_args.config
    try:
        _load_admin_ui_config(config_path)
    except (OSError, UnicodeError, ValueError) as exc:
        config_parser.error(str(exc))

    parser = argparse.ArgumentParser(
        parents=[config_parser],
        description="Serve the SafeHarness management UI on a loopback interface by default."
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SAFEHARNESS_ADMIN_UI_HOST", "127.0.0.1"),
        help="Listener address (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SAFEHARNESS_ADMIN_UI_PORT", "38308")),
        help="Listener port (default: 38308).",
    )
    args = parser.parse_args(argv)
    try:
        server = create_admin_ui_server(host=args.host, port=args.port)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _load_admin_ui_config(path: str) -> Path | None:
    """Load an allowlisted dotenv-style config without overriding process environment."""

    config_path = Path(path).expanduser()
    if not config_path.exists():
        return None
    if not config_path.is_file():
        raise ValueError(f"admin UI config path is not a file: {config_path}")

    for line_number, raw_line in enumerate(
        config_path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or _ENV_NAME.fullmatch(name) is None:
            raise ValueError(f"invalid admin UI config assignment at line {line_number}")
        if name not in _CONFIG_KEYS:
            raise ValueError(f"unsupported admin UI config key at line {line_number}: {name}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(name, value)
    return config_path


def _normalise_upstream_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("SAFEHARNESS_ADMIN_UI_UPSTREAM_URL must be an http(s) base URL")
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


def _upstream_request(
    settings: AdminUISettings,
    *,
    method: str,
    path: str,
    payload: dict[str, str] | None,
) -> tuple[int, dict[str, Any]]:
    if not settings.configured_upstream_url or not settings.admin_key:
        return (
            HTTPStatus.SERVICE_UNAVAILABLE,
            _error(
                "configuration_required",
                "The management UI upstream is not configured.",
            ),
        )
    body = None
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + settings.admin_key,
    }
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(
        settings.configured_upstream_url + path,
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with build_opener(_NoRedirect()).open(
            request,
            timeout=settings.request_timeout_seconds,
        ) as response:
            raw = response.read(_MAX_UPSTREAM_BYTES + 1)
            if len(raw) > _MAX_UPSTREAM_BYTES:
                raise ValueError("upstream response exceeds the UI limit")
            value = strict_json_loads(raw)
            if not isinstance(value, dict):
                raise ValueError("upstream response must be an object")
            return int(response.status), value
    except HTTPError as exc:
        exc.close()
        return (
            HTTPStatus.BAD_GATEWAY,
            _error("upstream_rejected", "The coordination service rejected the UI request."),
        )
    except (OSError, URLError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return (
            HTTPStatus.SERVICE_UNAVAILABLE,
            _error("upstream_unavailable", "The coordination service is unavailable."),
        )


def _audit_filters(query: str) -> dict[str, Any]:
    parsed = parse_qs(query, keep_blank_values=False, strict_parsing=False)
    tenant_id = _single_query_value(parsed, "tenant_id")
    source = _single_query_value(parsed, "source")
    action = _single_query_value(parsed, "action")
    raw_limit = _single_query_value(parsed, "limit") or "50"
    try:
        limit = int(raw_limit)
    except ValueError as exc:
        raise ValueError("audit limit is invalid") from exc
    if not 1 <= limit <= 200:
        raise ValueError("audit limit is invalid")
    if tenant_id and _IDENTIFIER.fullmatch(tenant_id) is None:
        raise ValueError("tenant_id is invalid")
    if source and source not in {"agent", "gateway"}:
        raise ValueError("source is invalid")
    if action and _ACTION.fullmatch(action) is None:
        raise ValueError("action is invalid")
    return {
        "tenant_id": tenant_id or None,
        "source": source or None,
        "action": action or None,
        "limit": limit,
    }


def _single_query_value(values: dict[str, list[str]], name: str) -> str:
    items = values.get(name, [])
    if len(items) > 1:
        raise ValueError(f"{name} is ambiguous")
    return items[0] if items else ""


def _content_security_policy() -> str:
    return (
        "default-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; connect-src 'self'; img-src 'self' data:; "
        "script-src 'self'; style-src 'self'"
    )


def _error(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message}}


if __name__ == "__main__":
    raise SystemExit(main())
