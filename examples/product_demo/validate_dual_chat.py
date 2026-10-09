"""Validate SUMC standard and SafeHarness-protected chat against a local mock model."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import httpx


MOCK_API_KEY = "sumc-local-mock-key"
MOCK_MODEL = "sumc-local-mock"
MOCK_RESPONSE = "SUMC_MOCK_OK"


class MockOpenAIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        if self.headers.get("Authorization") != f"Bearer {MOCK_API_KEY}":
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > 256 * 1024:
                raise ValueError("invalid request size")
            payload = json.loads(self.rfile.read(length))
            if payload.get("model") != MOCK_MODEL or not isinstance(payload.get("messages"), list):
                raise ValueError("invalid request")
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return

        if payload.get("stream"):
            chunks = [
                {
                    "id": "chatcmpl-sumc-mock",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": MOCK_MODEL,
                    "choices": [
                        {"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}
                    ],
                },
                {
                    "id": "chatcmpl-sumc-mock",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": MOCK_MODEL,
                    "choices": [
                        {"index": 0, "delta": {"content": MOCK_RESPONSE}, "finish_reason": None}
                    ],
                },
                {
                    "id": "chatcmpl-sumc-mock",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": MOCK_MODEL,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
                },
            ]
            body = b"".join(
                f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n".encode() for chunk in chunks
            ) + b"data: [DONE]\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        body = json.dumps(
            {
                "id": "chatcmpl-sumc-mock",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": MOCK_MODEL,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": MOCK_RESPONSE},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
            },
            separators=(",", ":"),
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _login(client: httpx.Client, password: str) -> None:
    response = client.post(
        "/login",
        data={"username": "admin", "password": password, "redirect": "/"},
        follow_redirects=False,
    )
    if response.status_code != 303:
        raise RuntimeError(f"login failed with HTTP {response.status_code}")
    location = response.headers.get("location", "")
    code = parse_qs(urlparse(location).query).get("ticket", [""])[0]
    if not code:
        raise RuntimeError("login did not return a ticket")
    exchange = client.post("/v1/auth/ticket/exchange", json={"code": code})
    exchange.raise_for_status()


def _sse_events(response: httpx.Response) -> list[dict]:
    events: list[dict] = []
    for line in response.iter_lines():
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _contains_response(events: list[dict]) -> bool:
    return MOCK_RESPONSE in json.dumps(events, ensure_ascii=False)


def validate(backend_url: str, mock_port: int, password: str) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", mock_port), MockOpenAIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(base_url=backend_url, timeout=90.0) as client:
            _login(client, password)
            created = client.post(
                "/v1/models/providers",
                json={
                    "display_name": "SUMC local mock",
                    "provider_type": "chat",
                    "provider": "openai_compatible",
                    "base_url": f"http://127.0.0.1:{mock_port}/v1",
                    "api_key": MOCK_API_KEY,
                    "model_name": MOCK_MODEL,
                    "extra_config": {"context_length": 8192},
                    "is_active": True,
                },
            )
            created.raise_for_status()
            provider_id = created.json()["data"]["provider_id"]
            assigned = client.put(
                "/v1/models/roles/main_agent", json={"provider_id": provider_id}
            )
            assigned.raise_for_status()

            suffix = uuid.uuid4().hex
            with client.stream(
                "POST",
                "/v1/chats/stream",
                json={
                    "chat_id": f"mock-standard-{suffix}",
                    "message": "Return the configured mock response.",
                    "chat_mode": "fast",
                    "safeharness_protected": False,
                },
            ) as response:
                response.raise_for_status()
                standard_events = _sse_events(response)
            if not _contains_response(standard_events):
                raise RuntimeError("standard AgentScope chat did not return the mock response")

            with client.stream(
                "POST",
                "/v1/safeharness/chat/stream",
                json={
                    "conversation_id": f"mock-protected-{suffix}",
                    "agent_id": "main_agent",
                    "message": "Return the configured mock response.",
                },
            ) as response:
                response.raise_for_status()
                protected_events = _sse_events(response)
            event_types = {str(event.get("type", "")) for event in protected_events}
            if not _contains_response(protected_events):
                raise RuntimeError("protected chat did not return the mock response")
            if not {"policy_decision", "run_finished"}.issubset(event_types):
                raise RuntimeError("protected chat did not return its security timeline")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    print("PASS: standard AgentScope chat returned local mock response")
    print("PASS: protected chat returned local mock response and security timeline")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-url", default="http://127.0.0.1:3001")
    parser.add_argument("--mock-port", type=int, default=38444)
    args = parser.parse_args()
    password = os.getenv("SUMC_DEMO_ADMIN_PASSWORD", "")
    if not password:
        raise SystemExit("SUMC_DEMO_ADMIN_PASSWORD is required")
    validate(args.backend_url.rstrip("/"), args.mock_port, password)


if __name__ == "__main__":
    main()
