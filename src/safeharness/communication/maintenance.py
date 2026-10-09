"""Bounded mailbox retention and ordered off-site audit export."""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


@dataclass(frozen=True, slots=True, order=True)
class AuditCursor:
    occurred_at: datetime
    record_id: str

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            raise ValueError("audit cursor timestamp must be timezone-aware")
        if not self.record_id:
            raise ValueError("audit cursor record_id must not be empty")


@dataclass(frozen=True, slots=True)
class MaintenanceResult:
    purged_rows: int
    exported_records: int


class RetentionStore(Protocol):
    async def purge_expired(self, *, retention: timedelta) -> int: ...


class AuditReader(Protocol):
    async def scan_audit(
        self,
        *,
        after: AuditCursor | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]: ...


class AuditExporter(Protocol):
    async def export(self, records: Sequence[Mapping[str, Any]]) -> None: ...


class AuditCursorFile:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()

    def load(self) -> AuditCursor | None:
        if not self.path.exists():
            return None
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or set(payload) != {"occurred_at", "record_id"}:
            raise ValueError("audit cursor file has an invalid schema")
        occurred_at = _parse_datetime(payload["occurred_at"])
        return AuditCursor(occurred_at, str(payload["record_id"]))

    def save(self, cursor: AuditCursor) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f"{self.path.name}.tmp")
        temporary.write_text(
            json.dumps(
                {
                    "occurred_at": cursor.occurred_at.astimezone(timezone.utc).isoformat(),
                    "record_id": cursor.record_id,
                },
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        temporary.replace(self.path)


class HTTPSAuditExporter:
    """Send minimized audit batches to an authenticated append-only receiver."""

    def __init__(
        self,
        url: str,
        bearer_token: str,
        *,
        timeout: float = 10.0,
        ca_file: str | None = None,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("audit export URL must be HTTPS without embedded credentials")
        if parsed.fragment:
            raise ValueError("audit export URL must not contain a fragment")
        if len(bearer_token) < 32:
            raise ValueError("audit export bearer token must contain at least 32 characters")
        if timeout <= 0:
            raise ValueError("audit export timeout must be positive")
        self.url = url
        self._bearer_token = bearer_token
        self.timeout = float(timeout)
        self._ssl_context = ssl.create_default_context(cafile=ca_file)
        self._opener = opener

    async def export(self, records: Sequence[Mapping[str, Any]]) -> None:
        if not records:
            return
        await asyncio.to_thread(self._export, records)

    def _export(self, records: Sequence[Mapping[str, Any]]) -> None:
        body = json.dumps(
            {
                "schema": "safeharness.communication-audit.v1",
                "records": list(records),
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._bearer_token}",
                "Content-Type": "application/json",
                "Idempotency-Key": hashlib.sha256(body).hexdigest(),
            },
        )
        with self._opener(
            request,
            timeout=self.timeout,
            context=self._ssl_context,
        ) as response:
            status = int(getattr(response, "status", 0))
            if not 200 <= status < 300:
                raise RuntimeError(f"audit receiver returned HTTP {status}")


class CommunicationMaintenance:
    def __init__(
        self,
        retention_store: RetentionStore,
        *,
        retention: timedelta = timedelta(days=7),
        audit_reader: AuditReader | None = None,
        exporter: AuditExporter | None = None,
        cursor_file: AuditCursorFile | None = None,
        batch_size: int = 500,
        max_batches: int = 100,
    ) -> None:
        if not timedelta(hours=1) <= retention <= timedelta(days=90):
            raise ValueError("retention must be between 1 hour and 90 days")
        if not 1 <= batch_size <= 1000:
            raise ValueError("batch_size must be between 1 and 1000")
        if not 1 <= max_batches <= 1000:
            raise ValueError("max_batches must be between 1 and 1000")
        export_parts = (audit_reader, exporter, cursor_file)
        if any(part is not None for part in export_parts) and not all(
            part is not None for part in export_parts
        ):
            raise ValueError("audit reader, exporter, and cursor file must be configured together")
        self.retention_store = retention_store
        self.retention = retention
        self.audit_reader = audit_reader
        self.exporter = exporter
        self.cursor_file = cursor_file
        self.batch_size = int(batch_size)
        self.max_batches = int(max_batches)

    async def run_once(self) -> MaintenanceResult:
        purged = await self.retention_store.purge_expired(retention=self.retention)
        exported = 0
        if self.audit_reader is None or self.exporter is None or self.cursor_file is None:
            return MaintenanceResult(purged, exported)
        cursor = self.cursor_file.load()
        for _ in range(self.max_batches):
            records = await self.audit_reader.scan_audit(
                after=cursor,
                limit=self.batch_size,
            )
            if not records:
                break
            await self.exporter.export(records)
            cursor = _cursor_from_record(records[-1])
            self.cursor_file.save(cursor)
            exported += len(records)
            if len(records) < self.batch_size:
                break
        return MaintenanceResult(purged, exported)


def _cursor_from_record(record: Mapping[str, Any]) -> AuditCursor:
    occurred_at = _parse_datetime(record.get("occurred_at", ""))
    return AuditCursor(occurred_at, str(record.get("record_id", "")))


def _parse_datetime(value: Any) -> datetime:
    text = str(value)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("audit cursor timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("audit cursor timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)
