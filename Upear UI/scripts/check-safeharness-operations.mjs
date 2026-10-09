import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  defaultProductionReady,
  demoAgentCatalog,
  pairSet,
  unavailableEvaluationEvidence,
} from '../src/components/safeharness/securityOperationsData.ts';
import {
  buildSecurityLogExport,
  securityLogToText,
  summarizeInvocationEvidence,
  summarizeSecurityTurn,
} from '../src/components/canvas/securityContextData.ts';

assert.deepEqual([...pairSet([['tenant-a', 'agent-1'], ['tenant-a', 'agent-2']])], [
  'tenant-a:agent-1',
  'tenant-a:agent-2',
]);
assert.deepEqual([...pairSet([{ tenant_id: 'tenant-b', agent_id: 'agent-3' }, ['invalid']])], [
  'tenant-b:agent-3',
]);
assert.equal(pairSet(null).size, 0);
assert.deepEqual(unavailableEvaluationEvidence.map(({ key }) => key), [
  'deterministic',
  'live-model',
  'remote-infrastructure',
  'production-evidence',
]);
assert.ok(unavailableEvaluationEvidence.every(({ status, source, observedAt, conclusion }) => (
  status === '未运行' && source === '未配置' && observedAt === '未知' && conclusion === '不可判定'
)));
assert.equal(defaultProductionReady, false);
assert.deepEqual(demoAgentCatalog.filter(({ category }) => category === 'operations').map(({ agent_id }) => agent_id), [
  'platform-supervisor-agent',
  'noc-supervisor-agent',
  'noc-diagnosis-agent',
  'config-change-agent',
]);
assert.deepEqual(demoAgentCatalog.filter(({ category }) => category === 'general').map(({ agent_id }) => agent_id), [
  'main_agent',
  'internet-search-agent',
  'knowledge-qa-agent',
]);
assert.equal(demoAgentCatalog.find(({ agent_id }) => agent_id === 'config-change-agent').availability, 'unavailable');
assert.equal(demoAgentCatalog.find(({ agent_id }) => agent_id === 'knowledge-qa-agent').availability, 'unavailable');
const allowedEvents = [
  { type: 'policy_decision', data: { disposition: 'allow', policy_version: 'safeharness.default.v1' } },
  { type: 'run_finished', data: { status: 'completed' } },
];
assert.equal(summarizeSecurityTurn({ events: allowedEvents }, true).status, 'allowed');
assert.equal(summarizeSecurityTurn({ events: [{ type: 'policy_decision', data: { disposition: 'modify', reason_code: 'content_sanitized' } }] }, true).status, 'sanitized');
assert.equal(summarizeSecurityTurn({ events: [{ type: 'blocked', data: { reason_code: 'prompt_injection_detected' } }] }, true).status, 'blocked');
const restoredBlockedEvents = [
  { type: 'policy_decision', data: { disposition: 'deny', reason_code: 'prompt_injection_detected', judge_calls: 0 } },
  { type: 'run_finished', data: { status: 'blocked', model_calls: 0 } },
];
assert.equal(summarizeSecurityTurn({ events: restoredBlockedEvents }, true).status, 'blocked');
assert.equal(summarizeInvocationEvidence(restoredBlockedEvents).blockedReason, 'prompt_injection_detected');
const blockedSummary = summarizeSecurityTurn({ events: [
  { type: 'blocked', data: { reason_code: 'prompt_injection_detected', action: 'INPUT_BLOCKED; MODEL_SKIPPED', model_calls: 0, tool_calls_proposed: 0, tool_calls_started: 0, agent_chain: 'platform-supervisor-agent -> noc-supervisor-agent -> noc-diagnosis-agent' } },
  { type: 'run_finished', data: { status: 'blocked', route: 'platform-supervisor-agent -> noc-supervisor-agent -> noc-diagnosis-agent', agent_chain: 'platform-supervisor-agent -> noc-supervisor-agent -> noc-diagnosis-agent', model_calls: 0, tool_calls_proposed: 0, tool_calls_started: 0 } },
] }, true);
assert.equal(blockedSummary.modelCalls, 0);
assert.equal(blockedSummary.toolCallsProposed, 0);
assert.equal(blockedSummary.toolCallsStarted, 0);
assert.match(blockedSummary.agentChain, /platform-supervisor-agent/);
assert.equal(summarizeSecurityTurn({ events: [{ type: 'error', data: { code: 'stream_error' } }] }, true).status, 'error');
assert.equal(summarizeSecurityTurn({ events: [] }, false).status, 'unevaluated');
assert.equal(summarizeSecurityTurn({ events: [], isStreaming: true }, true).status, 'checking');
const invocation = summarizeInvocationEvidence([
  { type: 'execution', data: { stage: 'dispatch', status: 'dispatched', agent_id: 'platform-supervisor-agent' } },
  { type: 'execution', data: { stage: 'tool', status: 'started', tool_name: 'internet_search', agent_id: 'internet-search-agent' } },
  { type: 'blocked', data: { reason_code: 'semantic_prompt_injection_detected' } },
], [
  { name: 'call_subagent', status: 'success', input: { agent_id: 'research-agent' } },
  { name: 'call_skill', status: 'success', input: { skill_name: 'web-debug-search' } },
]);
assert.deepEqual(invocation.agents, ['platform-supervisor-agent', 'internet-search-agent', 'research-agent']);
assert.deepEqual(invocation.tools, ['internet_search']);
assert.deepEqual(invocation.skills, ['web-debug-search']);
assert.equal(invocation.blockedReason, 'semantic_prompt_injection_detected');
assert.deepEqual(summarizeInvocationEvidence([], [{ name: 'call_skill', status: 'pending', input: { skill_name: 'not-called' } }]).skills, []);
const securityLog = buildSecurityLogExport('chat-1', true, [{ ts: 1, events: allowedEvents }], null);
assert.equal(securityLog.schema_version, 'sumc.security-log.v1');
assert.equal(securityLog.production_ready, false);
assert.match(securityLogToText(securityLog), /本轮会话|当前会话/);
assert.doesNotMatch(JSON.stringify(securityLog), /api_key|raw_payload|message_content/i);
const redactedLog = buildSecurityLogExport('chat-2', true, [{ events: [{ type: 'policy_decision', data: { disposition: 'allow', api_key: 'secret', content: 'private message' } }] }], null);
assert.doesNotMatch(JSON.stringify(redactedLog), /secret|private message/i);
const pageConfigDefaults = readFileSync(
  new URL('../src/utils/pageConfigDefaults.ts', import.meta.url),
  'utf8',
);
assert.match(pageConfigDefaults, /sidebar_items:[\s\S]*includes\('security_operations'\)/);
const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
assert.match(appSource, /if \(authChecking \|\| !authUserId\) return;\s+void fetchEdition\(\)/);
assert.match(appSource, /安全监控：\{securityStatusLabel\}[\s\S]*onClick=\{openSecuritySidebar\}|onClick=\{openSecuritySidebar\}[\s\S]*安全监控：\{securityStatusLabel\}/);
