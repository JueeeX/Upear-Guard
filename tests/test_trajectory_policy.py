"""TrajectoryPolicy: cross-tool chains, repeated attempts, entropy payloads.

Pins the additive contract: an unconfigured policy abstains on everything;
configured checks deny within one session only; success resets denial
pressure; evidence never carries raw payload values.
"""

import asyncio

import pytest
from safeharness.api.context import SessionContext
from safeharness.api.decisions import Disposition
from safeharness.api.events import EventKind, EventMeta, SecurityEvent
from safeharness.policies.base import PolicyContext
from safeharness.policies.trajectory import ChainRule, TrajectoryPolicy
from safeharness.runtime.services import RuntimeServices

_SEQUENCE = {"n": 0}


def _eval(policy, event, context):
    return asyncio.run(policy.evaluate(event, context))


def _context(session_id: str = "s1") -> PolicyContext:
    return PolicyContext(
        session=SessionContext(tenant_id="t", agent_id="a", session_id=session_id, run_id="r"),
        state={},
        services=RuntimeServices(),
    )


def _event(kind: EventKind, tool: str = "tool_b", arguments: dict | None = None) -> SecurityEvent:
    _SEQUENCE["n"] += 1
    meta = EventMeta(
        tenant_id="t", session_id="s1", run_id="r", agent_id="a",
        sequence=_SEQUENCE["n"], framework="test", trace_id="tr",
    )
    payload = {"tool_name": tool}
    if arguments is not None:
        payload["arguments"] = arguments
    return SecurityEvent(kind, meta, payload)


_CHAIN = ChainRule(name="read_then_send", first="secret.*", then="http.*|email.*", reason="读取敏感后外发")


def test_unconfigured_policy_abstains_on_everything():
    policy = TrajectoryPolicy()
    assert policy.configured is False
    context = _context()
    for kind, tool in [
        (EventKind.TOOL_CALL_PROPOSED, "http.post"),
        (EventKind.TOOL_CALL_SUCCEEDED, "secret.read"),
        (EventKind.TOOL_CALL_FAILED, "http.post"),
    ]:
        assert _eval(policy, _event(kind, tool), context).disposition is None


def test_chain_rule_fires_within_session():
    policy = TrajectoryPolicy([_CHAIN])
    context = _context()
    assert _eval(policy, _event(EventKind.TOOL_CALL_FAILED, "secret.read"), context).disposition is None
    vote = _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context)
    assert vote.disposition is Disposition.DENY
    reason = vote.reasons[0]
    assert reason.code == "trajectory_chain_rule"
    assert reason.evidence["chain_rule"] == "read_then_send"
    assert reason.evidence["first_tool"] == "secret.read"


def test_chain_rule_without_first_tool_abstains():
    policy = TrajectoryPolicy([_CHAIN])
    context = _context()
    vote = _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context)
    assert vote.disposition is None


def test_chain_rule_respects_max_gap():
    policy = TrajectoryPolicy([ChainRule(name="gapped", first="secret.*", then="http.*", max_gap=1)])
    context = _context()
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), context)
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "middle.step"), context)
    # middle.step sits at gap 0, secret.read at gap 1 — outside max_gap=1.
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context).disposition is None

    wide = TrajectoryPolicy([ChainRule(name="gapped", first="secret.*", then="http.*", max_gap=2)])
    context2 = _context()
    _eval(wide, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), context2)
    _eval(wide, _event(EventKind.TOOL_CALL_SUCCEEDED, "middle.step"), context2)
    vote = _eval(wide, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context2)
    assert vote.disposition is Disposition.DENY


def test_repeated_attempts_threshold_and_success_reset():
    policy = TrajectoryPolicy(repeated_attempt_threshold=2)
    context = _context()
    _eval(policy, _event(EventKind.TOOL_CALL_FAILED, "internet_search"), context)
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "internet_search"), context).disposition is None
    _eval(policy, _event(EventKind.TOOL_CALL_FAILED, "internet_search"), context)
    vote = _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "internet_search"), context)
    assert vote.disposition is Disposition.DENY
    assert vote.reasons[0].code == "trajectory_repeated_attempts"
    # A different tool is unaffected.
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "other.tool"), context).disposition is None
    # Success resets the pressure counter.
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "internet_search"), context)
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "internet_search"), context).disposition is None


def test_entropy_payload_detected_without_leaking_value():
    policy = TrajectoryPolicy(entropy_threshold=5.5, entropy_min_length=32)
    context = _context()
    high_entropy = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    vote = _eval(policy, 
        _event(EventKind.TOOL_CALL_PROPOSED, "file.write", {"blob": high_entropy}),
        context,
    )
    assert vote.disposition is Disposition.DENY
    evidence = vote.reasons[0].evidence
    assert evidence["argument"] == "blob"
    assert high_entropy not in str(evidence)
    low = _eval(policy, 
        _event(EventKind.TOOL_CALL_PROPOSED, "file.write", {"blob": "a" * 64}),
        context,
    )
    assert low.disposition is None


def test_sessions_are_isolated():
    policy = TrajectoryPolicy([_CHAIN])
    first = _context("session-a")
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), first)
    second = _context("session-b")
    vote = _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), second)
    assert vote.disposition is None


def test_chain_rule_validation():
    with pytest.raises(ValueError):
        ChainRule(name="bad", first="(unclosed", then="http.*")
    with pytest.raises(ValueError):
        ChainRule(name="bad", first="secret.*", then="http.*", max_gap=-1)


# --- tag-aware chain rules (descriptor tags enter policy context) ----------

from safeharness.api.tools import ToolDescriptor
from safeharness.backends.memory import StaticToolCatalog


def _tagged_context(descriptors, session_id: str = "s1") -> PolicyContext:
    return PolicyContext(
        session=SessionContext(tenant_id="t", agent_id="a", session_id=session_id, run_id="r"),
        state={},
        services=RuntimeServices(tool_catalog=StaticToolCatalog(list(descriptors))),
    )


_TAG_CHAIN = ChainRule(name="tag_chain", first_tags=("secret",), then_tags=("network",))


def _descriptor(name: str, tags: frozenset[str] = frozenset()) -> ToolDescriptor:
    return ToolDescriptor(name=name, tags=tags)


def test_tag_only_chain_fires_on_descriptor_tags():
    policy = TrajectoryPolicy([_TAG_CHAIN])
    assert policy.configured is True
    context = _tagged_context(
        [_descriptor("secret.read", frozenset({"secret"})),
         _descriptor("http.post", frozenset({"network"}))]
    )
    assert _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), context).disposition is None
    vote = _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context)
    assert vote.disposition is Disposition.DENY
    reason = vote.reasons[0]
    assert reason.code == "trajectory_chain_rule"
    assert reason.evidence["chain_rule"] == "tag_chain"
    assert list(reason.evidence["first_tags"]) == ["secret"]
    assert list(reason.evidence["then_tags"]) == ["network"]


def test_tag_chain_without_catalog_abstains():
    policy = TrajectoryPolicy([_TAG_CHAIN])
    context = _context()  # no tool_catalog: tag conditions cannot match
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), context)
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context).disposition is None


def test_tag_chain_with_untagged_tools_abstains():
    policy = TrajectoryPolicy([_TAG_CHAIN])
    context = _tagged_context([_descriptor("secret.read"), _descriptor("http.post")])
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), context)
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context).disposition is None


def test_regex_and_tags_endpoint_is_and():
    policy = TrajectoryPolicy(
        [ChainRule(name="strict", first="secret.*", first_tags=("secret",), then="http.*")]
    )
    matched = _tagged_context(
        [_descriptor("secret.read", frozenset({"secret"})),
         _descriptor("http.post", frozenset({"anything"}))]
    )
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), matched)
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), matched).disposition is Disposition.DENY

    # Name matches but the tag set does not: the AND endpoint fails.
    mismatched = _tagged_context(
        [_descriptor("secret.read", frozenset({"public"})),
         _descriptor("http.post", frozenset({"anything"}))]
    )
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), mismatched)
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), mismatched).disposition is None


def test_name_regex_chain_unaffected_by_tag_support():
    # Name-only rules must behave exactly as before on tagged and untagged tools.
    policy = TrajectoryPolicy([_CHAIN])
    context = _tagged_context(
        [_descriptor("secret.read", frozenset({"secret"})),
         _descriptor("http.post", frozenset({"network"}))]
    )
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), context)
    vote = _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context)
    assert vote.disposition is Disposition.DENY


def test_sequence_records_descriptor_tags():
    policy = TrajectoryPolicy([_TAG_CHAIN])
    context = _tagged_context(
        [_descriptor("secret.read", frozenset({"secret"})),
         _descriptor("http.post", frozenset({"network"}))]
    )
    _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "secret.read"), context)
    trajectory = context.state["safeharness.trajectory.v1"]
    assert trajectory["sequence"][0][0] == "secret.read"
    assert trajectory["sequence"][0][2] == ["secret"]


def test_chain_rule_endpoint_validation():
    with pytest.raises(ValueError):
        ChainRule(name="no_first", then="http.*")
    with pytest.raises(ValueError):
        ChainRule(name="no_then", first="secret.*")
    with pytest.raises(ValueError):
        ChainRule(name="empty_tag", first_tags=("secret",), then_tags=["  "])
    with pytest.raises(ValueError):
        ChainRule(name="too_many", first_tags=tuple(f"t{i}" for i in range(17)), then_tags=("n",))
    # Valid minimal shape.
    ChainRule(name="ok", first_tags=("secret",), then_tags=("network",))


def test_tag_rules_skip_catalog_resolution_when_unused():
    # Name-only chains must not touch the catalog at all (previous failure
    # surface unchanged): a catalog whose resolve raises is never consulted.
    class _ExplodingCatalog:
        def resolve(self, name, version=None):
            raise RuntimeError("catalog must not be consulted")

    policy = TrajectoryPolicy([_CHAIN])
    context = PolicyContext(
        session=SessionContext(tenant_id="t", agent_id="a", session_id="s1", run_id="r"),
        state={},
        services=RuntimeServices(tool_catalog=_ExplodingCatalog()),
    )
    _eval(policy, _event(EventKind.TOOL_CALL_SUCCEEDED, "secret.read"), context)
    assert _eval(policy, _event(EventKind.TOOL_CALL_PROPOSED, "http.post"), context).disposition is Disposition.DENY
