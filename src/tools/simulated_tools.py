"""
Simulated tool execution environment.

Instead of touching real file-systems or networks, every tool invocation
is recorded and returns a plausible mock result.  This keeps the
experiment safe and reproducible while exercising all harness & safety
code paths.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    tool_name: str
    arguments: dict[str, Any]
    result: str = ""
    blocked: bool = False
    block_reason: str = ""


@dataclass
class SimulatedEnvironment:
    """Keeps an audit log of every tool call made during one task."""

    history: list[ToolCall] = field(default_factory=list)
    filesystem: dict[str, str] = field(default_factory=dict)

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> ToolCall:
        handler = _HANDLERS.get(tool_name, _generic_handler)
        result = handler(self, arguments)
        call = ToolCall(tool_name=tool_name, arguments=arguments, result=result)
        self.history.append(call)
        return call

    def record_blocked(self, tool_name: str, arguments: dict[str, Any],
                       reason: str) -> ToolCall:
        call = ToolCall(
            tool_name=tool_name, arguments=arguments,
            blocked=True, block_reason=reason,
        )
        self.history.append(call)
        return call


def _handle_send_email(env: SimulatedEnvironment, args: dict) -> str:
    return json.dumps({
        "status": "sent",
        "to": args.get("to", ""),
        "subject": args.get("subject", ""),
    })


def _handle_file_read(env: SimulatedEnvironment, args: dict) -> str:
    path = args.get("path", "")
    content = env.filesystem.get(path, f"[simulated] File at {path} not found.")
    return content


def _handle_file_write(env: SimulatedEnvironment, args: dict) -> str:
    path = args.get("path", "")
    content = args.get("content", "")
    env.filesystem[path] = content
    return f"[simulated] Wrote {len(content)} chars to {path}."


def _handle_file_delete(env: SimulatedEnvironment, args: dict) -> str:
    path = args.get("path", "")
    env.filesystem.pop(path, None)
    return f"[simulated] Deleted {path}."


def _handle_list_dir(env: SimulatedEnvironment, args: dict) -> str:
    path = args.get("path", "/")
    matches = [k for k in env.filesystem if k.startswith(path)]
    return json.dumps(matches) if matches else f"[simulated] {path}: config.yaml, README.md, src/"


def _handle_run_code(env: SimulatedEnvironment, args: dict) -> str:
    code = args.get("code", "")
    return f"[simulated] Executed code ({len(code)} chars). stdout: OK"


def _handle_run_shell(env: SimulatedEnvironment, args: dict) -> str:
    cmd = args.get("command", "")
    return f"[simulated] $ {cmd}\n(exit 0)"


def _handle_http_get(env: SimulatedEnvironment, args: dict) -> str:
    return json.dumps({"status": 200, "body": "[simulated] page content"})


def _handle_http_post(env: SimulatedEnvironment, args: dict) -> str:
    return json.dumps({"status": 200, "body": "[simulated] post accepted"})


def _handle_search(env: SimulatedEnvironment, args: dict) -> str:
    return json.dumps({"results": [
        {"title": "Result 1", "snippet": "[simulated] relevant information"}
    ]})


def _handle_download_file(env: SimulatedEnvironment, args: dict) -> str:
    dest = args.get("dest", "/tmp/download")
    env.filesystem[dest] = "[simulated] downloaded binary content"
    return f"[simulated] Downloaded to {dest}."


def _handle_search_doctors(env: SimulatedEnvironment, args: dict) -> str:
    return json.dumps([{"doctor_id": "d1", "name": "Dr. Smith",
                        "available": ["2026-04-01 10:00"]}])


def _handle_make_appointment(env: SimulatedEnvironment, args: dict) -> str:
    return json.dumps({"status": "booked", "doctor_id": args.get("doctor_id"),
                       "time": args.get("time")})


def _handle_destructive(env: SimulatedEnvironment, args: dict) -> str:
    return "[simulated] Destructive operation executed."


def _generic_handler(env: SimulatedEnvironment, args: dict) -> str:
    return json.dumps({"status": "ok", "args": args})


_HANDLERS = {
    "send_email": _handle_send_email,
    "file_read": _handle_file_read,
    "file_write": _handle_file_write,
    "file_delete": _handle_file_delete,
    "list_dir": _handle_list_dir,
    "run_code": _handle_run_code,
    "run_shell": _handle_run_shell,
    "http_get": _handle_http_get,
    "http_post": _handle_http_post,
    "search": _handle_search,
    "download_file": _handle_download_file,
    "search_doctors": _handle_search_doctors,
    "make_appointment": _handle_make_appointment,
    "drop_database": _handle_destructive,
    "rm_rf": _handle_destructive,
    "format_disk": _handle_destructive,
}
