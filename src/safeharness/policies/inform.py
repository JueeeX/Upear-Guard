"""Framework-neutral structural and pattern-based inbound-content policy."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any, Pattern

from safeharness.api._mapping import json_safe
from safeharness.api.decisions import Disposition, Reason, RiskAssessment, Severity
from safeharness.api.events import ContentSource, EventKind, SecurityEvent
from safeharness.policies.base import PolicyContext, PolicyVote
from safeharness.ports import JudgeRequest, JudgeResult


_DEFAULT_PATTERNS = (
    r"ignore\s*(?:all\s*)?(?:previous|prior|earlier|above)\s*"
    r"(?:instructions?|rules?|prompts?)",
    r"disregard\s*(?:all\s*)?(?:previous|prior|earlier|above)",
    r"system prompt override",
    r"you must now",
    r"forget everything",
    r"override.*(?:policy|instruction)",
    r"act as.*(?:admin|root|sudo)",
    r"bypass.*(?:filter|restriction|guardrail)",
    r"\[\s*(?:SYSTEM[\s_-]?UPDATE|ORCHESTRATOR|EMERGENCY[\s_-]?PROTOCOL)\s*\]",
    r"bypass\s+(?:all\s+)?(?:safety|security)\s+checks?",
    r"(?:impersonate|pretend\s+to\s+be|pose\s+as|roleplay\s+as|assume\s+the\s+role\s+of)"
    r".{0,24}\b(?:admin(?:istrator)?|root|superuser|sysadmin|operator|supervisor|system)\b",
    r"\byou\s+are\s+(?:now\s+)?(?:the\s+)?(?:admin|administrator|root|sysadmin|operator)\b",
    r"\bI\s+am\s+(?:the\s+)?(?:admin(?:istrator)?|root|sysadmin|superuser|operator|supervisor)\b",
    r"\bsudo\s+[a-z][\w.-]*",
    r"(?:\u5192\u5145|\u4f2a\u88c5\u6210|\u5047\u626e|\u626e\u6f14|\u5047\u88c5\u662f|\u81ea\u79f0)"
    r".{0,12}(?:\u7ba1\u7406\u5458|\u7cfb\u7edf\u7ba1\u7406\u5458|\u8fd0\u7ef4|\u4e3b\u7ba1|root|\u8d85\u7ea7\u7528\u6237)",
    r"\u6211\u662f.{0,8}(?:\u7ba1\u7406\u5458|\u7cfb\u7edf\u7ba1\u7406\u5458|\u8d85\u7ea7\u7ba1\u7406\u5458|\u8fd0\u7ef4\u4e3b\u7ba1|root)",
    r"(?:\u4ee5|\u7528).{0,8}(?:\u7ba1\u7406\u5458|root|\u8fd0\u7ef4|\u4e3b\u7ba1|\u8d85\u7ea7\u7528\u6237)"
    r".{0,6}(?:\u8eab\u4efd|\u6743\u9650|\u8d26\u53f7).{0,10}"
    r"(?:\u6267\u884c|\u8fd0\u884c|\u67e5\u8be2|\u767b\u5f55|\u64cd\u4f5c|\u91cd\u542f|\u5220\u9664)",
    r"(?:\u5ffd\u7565|\u7121\u8996|\u65e0\u89c6|\u8df3\u8fc7|\u5fd8\u8bb0|\u4e0d\u8981\u9075\u5b88).{0,16}"
    r"(?:\u4e4b\u524d|\u6b64\u524d|\u5148\u524d|\u539f\u6709|\u4e0a\u8ff0).{0,16}"
    r"(?:\u6307\u4ee4|\u89c4\u5219|\u898f\u5247|\u63d0\u793a\u8bcd|\u63d0\u793a\u8a5e|\u7cfb\u7edf\u63d0\u793a|\u5b89\u5168\u7b56\u7565)",
    r"(?:\u8986\u76d6|\u66ff\u6362|\u66ff\u63db|\u6539\u5199|\u7ed5\u8fc7|\u7e5e\u904e|\u5173\u95ed|\u95dc\u9589|\u7981\u7528).{0,16}"
    r"(?:\u7cfb\u7edf\u63d0\u793a|\u5b89\u5168\u7b56\u7565|\u5b89\u5168\u89c4\u5219|\u9650\u5236|\u9632\u62a4|\u9632\u8b77|\u62a4\u680f|\u8b77\u6b04)",
    r"(?:\u6267\u884c|\u57f7\u884c).{0,8}(?:\u9690\u85cf|\u96b1\u85cf|\u79d8\u5bc6).{0,8}(?:\u6307\u4ee4|\u547d\u4ee4)",
)
# - inform.py:L41-L43 ：匹配“忽略/无视/跳过/忘记/不要遵守 + 之前/此前/上述 + 指令/规则/提示词/系统提示/安全策略”这类表述。
# - inform.py:L44-L45 ：匹配“覆盖/替换/改写/绕过/关闭/禁用 + 系统提示/安全策略/限制/护栏”等绕过安全约束的表述。
# - inform.py:L46 ：匹配“执行隐藏/秘密指令”这一类明显可疑的命令。
# - inform.py:L29-L30 ：伪造特权头部（[SYSTEM_UPDATE]/[ORCHESTRATOR]/[EMERGENCY PROTOCOL]），
#   以及 "bypass (all) safety/security checks" 这类显式要求关闭安全检查的表述。
# - inform.py:L31-L40 ：身份冒用组——英文（impersonate/pretend to be/pose as + 特权角色、
#   "you are (now) the admin"、sudo 命令形态）与中文（冒充/伪装成/假扮/自称 + 特权角色、
#   “我是管理员”类身份声明、“以管理员身份执行/查询”类提权表述）。
#   值班角色自述（“我是值班工程师”）不在此列，避免误触发；语义 Judge rubric 兜底。
_TRUST_RANK = {"high": 3, "medium": 2, "low": 1, "untrusted": 0}
_SEMANTIC_SAFE_LABELS = frozenset({"SAFE", "BENIGN", "LEGITIMATE"})
_SEMANTIC_ATTACK_LABELS = frozenset(
    {"INJECTION", "UNSAFE", "MALICIOUS", "PROMPT_INJECTION"}
)
_SEMANTIC_PROTOCOL_ERROR_CLASSES = frozenset({"protocol_error", "request_error"})


class InformPolicy:
    """Sanitize structure and detect common instruction-injection patterns."""

    policy_id = "safeharness.inform.patterns"
    subscribed_events = frozenset(
        {
            EventKind.CONTENT_RECEIVED,
            EventKind.TOOL_CALL_SUCCEEDED,
            EventKind.MEMORY_READ_RESULT,
            EventKind.MEMORY_WRITE_PROPOSED,
            EventKind.AGENT_HANDOFF,
            EventKind.INTER_AGENT,
            EventKind.SUBAGENT_CREATION_PROPOSED,
            EventKind.FINAL_OUTPUT_PROPOSED,
        }
    )

    _hidden_chars = re.compile(
        "[\u200b\u200c\u200d\u2060\ufeff\u00ad\u200e\u200f"
        "\u202a-\u202e\u2066-\u2069]"
    )
    _html_comment = re.compile(r"<!--.*?-->", re.DOTALL)

    def __init__(
        self,
        patterns: tuple[str, ...] = _DEFAULT_PATTERNS,
        *,
        on_injection: Disposition = Disposition.DENY,
        semantic_min_confidence: float = 0.5,
    ) -> None:
        if on_injection not in (Disposition.DENY, Disposition.MODIFY):
            raise ValueError("on_injection must be DENY or MODIFY")
        self._patterns: tuple[Pattern[str], ...] = tuple(
            re.compile(pattern, re.IGNORECASE) for pattern in patterns
        )
        self.on_injection = on_injection
        if not 0.0 <= semantic_min_confidence <= 1.0:
            raise ValueError("semantic_min_confidence must be between 0.0 and 1.0")
        self.semantic_min_confidence = semantic_min_confidence

    async def evaluate(self, event: SecurityEvent, context: PolicyContext) -> PolicyVote:
        content_key = self._content_key(event)
        if content_key is None:
            return PolicyVote.abstain()
        source = self._source(event)
        original = event.payload.get(content_key)
        if (
            content_key == "content"
            and not isinstance(original, str)
            and event.kind is not EventKind.MEMORY_WRITE_PROPOSED
        ):
            return PolicyVote.abstain()
        cleaned, pattern_matched, changed = self._sanitize_value(original)
        semantic_result = None
        if not pattern_matched and self._requires_semantic_check(source, event):
            semantic_result = await self._semantic_check(
                cleaned, source=source, event=event, context=context
            )
        semantic_label = (
            semantic_result.label.strip().upper() if semantic_result is not None else ""
        )
        semantic_attack = semantic_label in _SEMANTIC_ATTACK_LABELS
        semantic_safe = (
            semantic_label in _SEMANTIC_SAFE_LABELS
            and semantic_result is not None
            and semantic_result.confidence >= self.semantic_min_confidence
        )
        semantic_result_class = self._semantic_result_class(semantic_result)
        semantic_protocol_error = semantic_result_class in _SEMANTIC_PROTOCOL_ERROR_CLASSES
        semantic_uncertain = semantic_result is not None and not (
            semantic_attack or semantic_safe
        )
        matched = pattern_matched or semantic_attack
        payload = dict(event.payload)
        trust = "untrusted" if (matched or semantic_uncertain) else self._effective_trust(
            source, payload
        )
        payload["provenance"] = {
            "source": source,
            "trust": trust,
            "sanitized": changed,
            "injection_detected": matched,
            "original_sha256": self._content_digest(original),
            "semantic_checked": semantic_result is not None,
            "semantic_label": semantic_label,
            "semantic_confidence": (
                semantic_result.confidence if semantic_result is not None else None
            ),
            "semantic_provider": (
                semantic_result.provider if semantic_result is not None else ""
            ),
            "semantic_model": semantic_result.model if semantic_result is not None else "",
        }

        if (matched or semantic_uncertain) and self.on_injection is Disposition.DENY:
            payload[content_key] = "[BLOCKED BY SAFEHARNESS]"
            code = (
                "safeharness_judge_protocol_error"
                if semantic_protocol_error
                else "prompt_injection_detected"
                if pattern_matched
                else "semantic_prompt_injection_detected"
                if semantic_attack
                else "semantic_prompt_injection_uncertain"
            )
            return PolicyVote(
                disposition=Disposition.DENY,
                risk=RiskAssessment(0.9, Severity.HIGH, ("prompt_injection",)),
                reasons=(
                    Reason(
                        code,
                        (
                            "Inbound content matched an instruction-injection policy."
                            if pattern_matched
                            else "Semantic inspection rejected or could not clear inbound content."
                        ),
                        self.policy_id,
                        self._semantic_evidence(semantic_result),
                    ),
                ),
                replacement_payload=payload,
            )

        if matched or semantic_uncertain:
            cleaned = (
                "[REMOVED BY SAFEHARNESS]"
                if semantic_attack or semantic_uncertain
                else self._remove_suspicious_value(cleaned)
            )
        if changed or matched or semantic_uncertain:
            payload[content_key] = cleaned
            return PolicyVote.modify(
                payload,
                Reason(
                    "content_sanitized",
                    "Inbound content was structurally sanitized.",
                    self.policy_id,
                ),
                risk=RiskAssessment(
                    0.7 if matched else 0.1,
                    Severity.MEDIUM if matched else Severity.LOW,
                    ("prompt_injection",) if matched else ("content_obfuscation",),
                ),
            )
        return PolicyVote.allow(
            replacement_payload=payload,
            reasons=(
                Reason(
                    "content_provenance_attached",
                    "Inbound content was tagged with its effective trust provenance.",
                    self.policy_id,
                ),
            ),
            risk=RiskAssessment(0.0, Severity.INFO, ("content_provenance",)),
        )

    async def _semantic_check(
        self,
        value: Any,
        *,
        source: str,
        event: SecurityEvent,
        context: PolicyContext,
    ) -> JudgeResult | None:
        judge = context.services.judge_provider
        if judge is None:
            return None
        return await judge.judge(
            JudgeRequest(
                purpose="prompt_injection_detection",
                content={
                    "source": source,
                    "event_kind": event.kind.value,
                    "content": json_safe(value),
                },
                risk_hint=0.65 if source != ContentSource.USER_INPUT.value else 0.5,
            )
        )

    @staticmethod
    def _requires_semantic_check(source: str, event: SecurityEvent) -> bool:
        return event.kind is not EventKind.FINAL_OUTPUT_PROPOSED and source not in {
            ContentSource.SYSTEM.value,
            ContentSource.AGENT_OUTPUT.value,
        }

    def _semantic_result_class(self, result: JudgeResult | None) -> str:
        if result is None:
            return "not_called"
        explicit = str(getattr(result, "judge_result_class", "") or "").strip().lower()
        status = str(getattr(result, "judge_status", "") or "").strip().lower()
        if explicit in _SEMANTIC_PROTOCOL_ERROR_CLASSES:
            return explicit
        if status in _SEMANTIC_PROTOCOL_ERROR_CLASSES:
            return status
        label = result.label.strip().upper()
        if label in _SEMANTIC_ATTACK_LABELS:
            return "detected"
        if label in _SEMANTIC_SAFE_LABELS:
            return "safe" if result.confidence >= self.semantic_min_confidence else "low_confidence_safe"
        if label == "UNCERTAIN":
            return "uncertain"
        return explicit or "uncertain"

    def _semantic_evidence(self, result: JudgeResult | None) -> dict[str, Any]:
        if result is None:
            return {}
        try:
            judge_calls = max(1, int(getattr(result, "judge_calls", 1) or 1))
        except (TypeError, ValueError):
            judge_calls = 1
        return {
            "semantic_label": result.label.strip().upper(),
            "semantic_confidence": result.confidence,
            "judge_status": str(getattr(result, "judge_status", "ok") or "ok"),
            "judge_calls": judge_calls,
            "judge_model": result.model,
            "judge_result_class": self._semantic_result_class(result),
            "provider": result.provider,
            "model": result.model,
        }

    @staticmethod
    def _source(event: SecurityEvent) -> str:
        default = (
            ContentSource.AGENT_OUTPUT.value
            if event.kind is EventKind.FINAL_OUTPUT_PROPOSED
            else ContentSource.INTER_AGENT.value
            if event.kind in {EventKind.AGENT_HANDOFF, EventKind.INTER_AGENT}
            else ContentSource.TOOL_OUTPUT.value
        )
        source_value = event.payload.get("source", default)
        return (
            source_value.value
            if isinstance(source_value, ContentSource)
            else str(source_value)
        )

    def _effective_trust(self, source: str, payload: Mapping[str, Any]) -> str:
        trust = self._default_trust(source)
        attributes = payload.get("attributes")
        if not isinstance(attributes, Mapping):
            return trust
        upstream = attributes.get("upstream_provenance")
        if not isinstance(upstream, Mapping):
            return trust
        upstream_trust = str(upstream.get("trust", "")).lower()
        if upstream_trust not in _TRUST_RANK:
            return trust
        return min((trust, upstream_trust), key=lambda item: _TRUST_RANK[item])

    @classmethod
    def _structural_clean(cls, content: str) -> str:
        content = cls._hidden_chars.sub("", content)
        content = cls._html_comment.sub("", content)
        return unicodedata.normalize("NFKC", content)

    def _remove_suspicious_lines(self, content: str) -> str:
        return "\n".join(
            line for line in content.splitlines()
            if not any(pattern.search(line) for pattern in self._patterns)
        )

    def _sanitize_value(self, value):
        if isinstance(value, str):
            cleaned = self._structural_clean(value)
            matched = any(pattern.search(cleaned) for pattern in self._patterns)
            return cleaned, matched, cleaned != value
        if isinstance(value, Mapping):
            output = {}
            matched = False
            changed = False
            for key, item in value.items():
                cleaned_item, item_matched, item_changed = self._sanitize_value(item)
                output[str(key)] = cleaned_item
                matched = matched or item_matched
                changed = changed or item_changed
            return output, matched, changed
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            output = []
            matched = False
            changed = False
            for item in value:
                cleaned_item, item_matched, item_changed = self._sanitize_value(item)
                output.append(cleaned_item)
                matched = matched or item_matched
                changed = changed or item_changed
            return output, matched, changed
        return value, False, False

    def _remove_suspicious_value(self, value):
        if isinstance(value, str):
            return self._remove_suspicious_lines(value)
        if isinstance(value, Mapping):
            return {
                str(key): self._remove_suspicious_value(item)
                for key, item in value.items()
            }
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self._remove_suspicious_value(item) for item in value]
        return value

    @staticmethod
    def _content_digest(value) -> str:
        canonical = json.dumps(
            json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _content_key(event: SecurityEvent) -> str | None:
        if event.kind in (
            EventKind.CONTENT_RECEIVED,
            EventKind.MEMORY_WRITE_PROPOSED,
            EventKind.AGENT_HANDOFF,
            EventKind.INTER_AGENT,
            EventKind.SUBAGENT_CREATION_PROPOSED,
            EventKind.FINAL_OUTPUT_PROPOSED,
        ):
            return "content"
        if event.kind in (EventKind.TOOL_CALL_SUCCEEDED, EventKind.MEMORY_READ_RESULT):
            return "result"
        return None

    @staticmethod
    def _default_trust(source: str) -> str:
        if source == ContentSource.SYSTEM.value:
            return "high"
        if source in (ContentSource.USER_INPUT.value, ContentSource.INTER_AGENT.value):
            return "medium"
        return "low"
