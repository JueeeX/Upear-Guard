"""Dangerous-SQL inspection for inbound content and tool-call arguments.

Regex-shape classifier (no SQL-parser dependency): recognises SQL statement
shapes, classifies read/write/DDL/admin/exec intent, and extracts table
references for allowlist checks. Comment stripping defeats inline-comment
obfuscation ("DEL/**/ETE", "DELETE -- x\nFROM"). An AST upgrade (sqlglot) can
replace :func:`inspect_sql` later without touching the wiring.

Two enforcement faces:

- ``CONTENT_RECEIVED`` — deny *dangerous* (write/DDL/admin/exec/multi-statement/
  exfil) SQL embedded in inbound text. Read-only SQL in free text is left to the
  semantic judge: flagging every "SELECT ... FROM" mention would false-positive
  on benign discussion.
- ``TOOL_CALL_PROPOSED`` — deny dangerous statements in SQL-bearing arguments
  and, when an allowlist is configured, deny reads touching unlisted tables.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from safeharness.api.decisions import Disposition, Reason, RiskAssessment, Severity
from safeharness.api.events import ContentSource, EventKind, SecurityEvent
from safeharness.policies.base import PolicyContext, PolicyVote

policy_id = "safeharness.sqlguard.dangerous_sql"

# Faces whose text originates outside the agent boundary. Model-generated
# content (inter-agent relays, agent output) frequently *discusses* SQL in
# remediation prose; blocking it there would break benign flows, and the
# semantic judge still covers that face.
_ENFORCED_CONTENT_SOURCES = frozenset(
    {
        ContentSource.USER_INPUT.value,
        ContentSource.RETRIEVED.value,
        ContentSource.TOOL_OUTPUT.value,
    }
)

_COMMENT_LINE_RE = re.compile(r"--[^\n]*|#[^\n]*")
_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STATEMENT_SPLIT_RE = re.compile(r";")
_EXFIL_RE = re.compile(
    r"\binto\s+(?:outfile|dumpfile)\b|\bload_file\s*\(", re.IGNORECASE
)
# Statement shapes: keyword plus the structural tail that only a real statement
# has. Bare keywords ("update the ticket") must not match.
_SQL_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("write", re.compile(r"\bdelete\s+from\s+[`'\"]?[A-Za-z_]", re.IGNORECASE)),
    ("write", re.compile(r"\binsert\s+into\s+[`'\"]?[A-Za-z_]", re.IGNORECASE)),
    (
        "write",
        re.compile(
            r"\bupdate\s+[`'\"]?[A-Za-z_][\w$]*(?:\s*\.\s*[`'\"]?[A-Za-z_][\w$]*)*\s+set\b",
            re.IGNORECASE,
        ),
    ),
    (
        "write",
        re.compile(r"\b(?:merge\s+into|replace\s+into)\s+[`'\"]?[A-Za-z_]", re.IGNORECASE),
    ),
    (
        "ddl",
        re.compile(
            r"\bdrop\s+(?:table|index|view|database|schema|procedure|function|trigger)\b",
            re.IGNORECASE,
        ),
    ),
    ("ddl", re.compile(r"\btruncate\s+(?:table\s+)?[`'\"]?[A-Za-z_]", re.IGNORECASE)),
    ("ddl", re.compile(r"\balter\s+table\b", re.IGNORECASE)),
    (
        "ddl",
        re.compile(
            r"\bcreate\s+(?:table|index|view|database|schema|procedure|function|trigger)\b",
            re.IGNORECASE,
        ),
    ),
    ("ddl", re.compile(r"\brename\s+table\b", re.IGNORECASE)),
    ("admin", re.compile(r"\b(?:grant|revoke)\b[^;\n]{0,200}\bon\b", re.IGNORECASE)),
    (
        "exec",
        re.compile(
            r"\b(?:call|exec|execute)\s+[`'\"]?[A-Za-z_]\w*\s*\("
            r"|\bexec(?:ute)?\s+(?:sp_|xp_|fn_)\w+",
            re.IGNORECASE,
        ),
    ),
    (
        "read",
        re.compile(r"\bselect\b[^;]{0,600}?\bfrom\s+[`'\"]?[A-Za-z_]", re.IGNORECASE | re.DOTALL),
    ),
    (
        "read",
        re.compile(
            r"\b(?:show|describe|explain)\s+(?:tables|databases|schemas|create\s+table)\b",
            re.IGNORECASE,
        ),
    ),
)
_TABLE_RE = re.compile(
    r"\b(?:from|join|into|update|table)\s+[`'\"]?([A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)*)",
    re.IGNORECASE,
)

_DANGEROUS_KINDS = frozenset({"write", "ddl", "admin", "exec"})
DEFAULT_SQL_ARGUMENT_KEYS = ("sql", "query", "statement", "expression")


@dataclass(frozen=True, slots=True)
class SqlVerdict:
    """Outcome of inspecting one piece of text for dangerous SQL."""

    is_sql: bool
    dangerous: bool
    statement_kinds: tuple[str, ...]
    tables: tuple[str, ...]
    multi_statement: bool
    reason_code: str | None
    matched_table: str | None


def _strip_comments(text: str) -> str:
    text = _COMMENT_BLOCK_RE.sub(" ", text)
    text = _COMMENT_LINE_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text)


def _normalise_table(name: str) -> str:
    return name.strip("`'\"").lower()


def _table_matches(table: str, allowed: Iterable[str]) -> bool:
    normalised = _normalise_table(table)
    bare = normalised.rsplit(".", 1)[-1]
    for entry in allowed:
        allowed_name = _normalise_table(entry)
        if normalised == allowed_name or bare == allowed_name.rsplit(".", 1)[-1]:
            return True
    return False


def inspect_sql(
    text: str,
    *,
    allowed_tables: Iterable[str] | None = None,
) -> SqlVerdict:
    """Classify text into an SQL verdict.

    ``allowed_tables=None`` disables table checks entirely; otherwise every
    table reference must match an allowlist entry (schema-qualified names match
    on the bare table name too).
    """

    if not isinstance(text, str) or not text.strip():
        return SqlVerdict(False, False, (), (), False, None, None)
    cleaned = _strip_comments(text)
    segments = [s for s in _STATEMENT_SPLIT_RE.split(cleaned) if s.strip()]
    kinds: list[str] = []
    tables: list[str] = []
    matched_shapes = 0
    for segment in segments:
        segment_kinds = [kind for kind, shape in _SQL_SHAPES if shape.search(segment)]
        if segment_kinds:
            matched_shapes += 1
            kinds.extend(segment_kinds)
        tables.extend(_normalise_table(m) for m in _TABLE_RE.findall(segment))
    multi_statement = matched_shapes >= 2
    # A batch is only dangerous when it carries a destructive statement —
    # chained read queries ("SELECT 1; SELECT 2"), in prose or in a batch
    # argument, are not an attack by themselves.
    dangerous = (
        any(kind in _DANGEROUS_KINDS for kind in kinds)
        or bool(_EXFIL_RE.search(cleaned))
    )
    reason: str | None = None
    matched_table: str | None = None
    if dangerous:
        reason = "dangerous_sql_detected"
    elif allowed_tables is not None:
        allowed = tuple(allowed_tables)
        for table in tables:
            if not _table_matches(table, allowed):
                reason = "unauthorized_sql_table"
                matched_table = table
                break
    is_sql = bool(kinds)
    return SqlVerdict(
        is_sql=is_sql,
        dangerous=dangerous,
        statement_kinds=tuple(kinds),
        tables=tuple(dict.fromkeys(tables)),
        multi_statement=multi_statement,
        reason_code=reason,
        matched_table=matched_table,
    )


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _walk_strings(item)


class SqlGuardPolicy:
    """Deny dangerous SQL in inbound content and SQL-bearing tool arguments."""

    policy_id = policy_id
    subscribed_events = frozenset(
        {EventKind.CONTENT_RECEIVED, EventKind.TOOL_CALL_PROPOSED}
    )

    def __init__(
        self,
        *,
        allowed_tables: Iterable[str] | None = None,
        sql_argument_keys: tuple[str, ...] = DEFAULT_SQL_ARGUMENT_KEYS,
    ) -> None:
        self.allowed_tables = (
            frozenset(allowed_tables) if allowed_tables is not None else None
        )
        self.sql_argument_keys = tuple(sql_argument_keys)

    def _argument_verdict(self, arguments: Any) -> SqlVerdict:
        if not isinstance(arguments, Mapping):
            return SqlVerdict(False, False, (), (), False, None, None)
        candidates: list[str] = []
        for key, value in arguments.items():
            name = str(key).strip().lower()
            if name in self.sql_argument_keys and isinstance(value, str):
                candidates.append(value)
        if not candidates:
            return SqlVerdict(False, False, (), (), False, None, None)
        for candidate in candidates:
            verdict = inspect_sql(candidate, allowed_tables=self.allowed_tables)
            if verdict.reason_code is not None:
                return verdict
        return SqlVerdict(False, False, (), (), False, None, None)

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        if event.kind is EventKind.CONTENT_RECEIVED:
            source = event.payload.get("source")
            source_value = source.value if isinstance(source, ContentSource) else str(source or "")
            if source_value not in _ENFORCED_CONTENT_SOURCES:
                return PolicyVote.abstain()
            content = event.payload.get("content")
            if not isinstance(content, str):
                return PolicyVote.abstain()
            verdict = inspect_sql(content, allowed_tables=self.allowed_tables)
            if not verdict.dangerous:
                return PolicyVote.abstain()
            payload = dict(event.payload)
            payload["content"] = "[BLOCKED BY SAFEHARNESS]"
            return PolicyVote(
                disposition=Disposition.DENY,
                risk=RiskAssessment(0.9, Severity.HIGH, ("dangerous_sql",)),
                reasons=(
                    Reason(
                        "dangerous_sql_detected",
                        (
                            "Inbound content contains a destructive SQL statement "
                            f"(kinds={','.join(verdict.statement_kinds) or 'unknown'})."
                        ),
                        self.policy_id,
                    ),
                ),
                replacement_payload=payload,
            )
        if event.kind is EventKind.TOOL_CALL_PROPOSED:
            verdict = self._argument_verdict(event.payload.get("arguments"))
            if verdict.reason_code is None:
                return PolicyVote.abstain()
            detail = (
                f"tables={verdict.matched_table}"
                if verdict.reason_code == "unauthorized_sql_table"
                else f"kinds={','.join(verdict.statement_kinds) or 'unknown'}"
            )
            return PolicyVote(
                disposition=Disposition.DENY,
                risk=RiskAssessment(0.9, Severity.HIGH, ("dangerous_sql",)),
                reasons=(
                    Reason(
                        verdict.reason_code,
                        f"Tool arguments contain prohibited SQL ({detail}).",
                        self.policy_id,
                    ),
                ),
            )
        return PolicyVote.abstain()


__all__ = [
    "DEFAULT_SQL_ARGUMENT_KEYS",
    "SqlGuardPolicy",
    "SqlVerdict",
    "inspect_sql",
    "policy_id",
]
