import type { SafeHarnessSecurityReport } from '../../safeharnessApi';
import type { SafeHarnessSecurityTimelineEvent } from '../../types';
import type { ToolCall } from '../../types';

export type SecurityTurnInput = {
  ts?: number;
  isStreaming?: boolean;
  events: SafeHarnessSecurityTimelineEvent[];
};

export type SecuritySummaryStatus = 'checking' | 'allowed' | 'sanitized' | 'blocked' | 'error' | 'unevaluated';

export type SecurityToolSummary = {
  name: string;
  execution: string;
};

export type SecurityTurnSummary = {
  status: SecuritySummaryStatus;
  label: string;
  reason: string;
  checks: number;
  sanitized: number;
  tools: number;
  blocked: number;
  approval: string;
  route: string;
  agentChain: string;
  modelCalls: number;
  toolCallsProposed: number;
  toolCallsStarted: number;
  finalStatus: string;
  toolDetails: SecurityToolSummary[];
  judgeStatus: string;
  judgeCalls: number;
  judgeModel: string;
};

export type InvocationEvidence = {
  agents: string[];
  tools: string[];
  skills: string[];
  blockedReason: string;
};

export type SecurityLogExport = {
  schema_version: 'sumc.security-log.v1';
  exported_at: string;
  product: 'Upear';
  conversation_id: string;
  protected: boolean;
  production_ready: false;
  turns: Array<{
    timestamp?: number;
    summary: SecurityTurnSummary;
    events: SafeHarnessSecurityTimelineEvent[];
  }>;
  startup_self_check: SafeHarnessSecurityReport | null;
};

const EXPORT_BLOCKED_FIELDS = new Set(['content', 'raw_payload', 'api_key', 'authorization', 'stack', 'traceback']);

function exportEvents(events: SafeHarnessSecurityTimelineEvent[]): SafeHarnessSecurityTimelineEvent[] {
  return events.map((event) => ({
    ...event,
    data: event.type === 'blocked'
      ? {
          ...Object.fromEntries(Object.entries(event.data).filter(([key]) => !EXPORT_BLOCKED_FIELDS.has(key.toLowerCase()) && key !== 'message')),
          message: 'SafeHarness 已阻断本轮请求。',
        }
      : Object.fromEntries(
          Object.entries(event.data).filter(([key]) => !EXPORT_BLOCKED_FIELDS.has(key.toLowerCase())),
        ),
  }));
}

function valueOf(event: SafeHarnessSecurityTimelineEvent | undefined, key: string): string {
  const value = event?.data[key];
  return value === undefined ? '' : String(value);
}

function numberOf(event: SafeHarnessSecurityTimelineEvent | undefined, key: string): number | null {
  const value = event?.data[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function isModified(event: SafeHarnessSecurityTimelineEvent): boolean {
  return event.type === 'policy_decision'
    && (valueOf(event, 'disposition') === 'modify' || valueOf(event, 'reason_code') === 'content_sanitized');
}

function reasonFor(events: SafeHarnessSecurityTimelineEvent[], status: SecuritySummaryStatus, protectedEnabled: boolean): string {
  if (status === 'unevaluated') {
    return protectedEnabled ? '本轮尚未收到 SafeHarness 安全事件。' : '当前会话关闭安全保护，本轮未经过 SafeHarness 评估。';
  }
  if (status === 'checking') return '安全检查正在进行。';
  const blocked = events.find((event) => event.type === 'blocked')
    || events.find((event) => event.type === 'policy_decision' && valueOf(event, 'disposition').toLowerCase() === 'deny');
  if (blocked) {
    const reasonCode = valueOf(blocked, 'reason_code');
    if (reasonCode === 'prompt_injection_detected') return '检测到提示注入，已阻止本轮请求。';
    if (reasonCode === 'unauthorized_tool') return '工具未获授权，已阻止本轮请求。';
    return '策略已阻止本轮请求。';
  }
  const error = events.find((event) => event.type === 'error');
  if (error) {
    const code = valueOf(error, 'code');
    if (code === 'protected_chat_unavailable') return '受保护对话服务不可用，已停止本轮处理。';
    return '安全检查发生错误，已停止本轮处理。';
  }
  if (status === 'sanitized') return '检测到风险内容，已清洗后继续处理。';
  return '本轮请求已通过安全检查。';
}

export function summarizeSecurityTurn(turn: SecurityTurnInput, protectedEnabled: boolean): SecurityTurnSummary {
  const events = turn.events || [];
  const hasError = events.some((event) => event.type === 'error');
  const hasBlocked = events.some((event) => event.type === 'blocked'
    || (event.type === 'policy_decision' && valueOf(event, 'disposition').toLowerCase() === 'deny'));
  const hasModified = events.some(isModified);
  const hasFinished = events.some((event) => event.type === 'run_finished');
  let status: SecuritySummaryStatus = 'allowed';
  if (!protectedEnabled) status = 'unevaluated';
  else if (hasError) status = 'error';
  else if (hasBlocked) status = 'blocked';
  else if (!events.length) status = turn.isStreaming ? 'checking' : 'unevaluated';
  else if (hasModified) status = 'sanitized';
  else if (turn.isStreaming && !hasFinished) status = 'checking';

  const labels: Record<SecuritySummaryStatus, string> = {
    checking: '检查中',
    allowed: '通过',
    sanitized: '清洗后通过',
    blocked: '已拦截',
    error: '检查失败',
    unevaluated: '未评估',
  };
  const tools = new Map<string, string>();
  events.filter((event) => event.type === 'tool_proposal' || (event.type === 'execution' && valueOf(event, 'stage') !== 'dispatch')).forEach((event) => {
    const name = valueOf(event, 'tool_name');
    if (name) tools.set(name, event.type === 'execution' ? valueOf(event, 'status') || '已调用' : '已提出');
  });
  const finished = events.find((event) => event.type === 'run_finished');
  const blockedEvent = events.find((event) => event.type === 'blocked')
    || events.find((event) => event.type === 'policy_decision' && valueOf(event, 'disposition').toLowerCase() === 'deny');
  const route = valueOf(finished, 'route') || valueOf(events.find((event) => event.type === 'policy_decision'), 'route');
  const agentChain = valueOf(finished, 'agent_chain') || route;
  const judgeEvent = finished || blockedEvent || events.find((event) => valueOf(event, 'judge_status'));
  return {
    status,
    label: labels[status],
    reason: reasonFor(events, status, protectedEnabled),
    checks: events.filter((event) => event.type === 'policy_decision').length,
    sanitized: events.filter(isModified).length,
    tools: tools.size,
    blocked: events.filter((event) => event.type === 'blocked' || (event.type === 'policy_decision' && valueOf(event, 'disposition') === 'deny')).length,
    approval: valueOf(events.find((event) => event.type === 'approval'), 'status') || '无需审批',
    route,
    agentChain,
    modelCalls: numberOf(finished, 'model_calls') ?? numberOf(blockedEvent, 'model_calls') ?? 0,
    toolCallsProposed: numberOf(finished, 'tool_calls_proposed') ?? numberOf(blockedEvent, 'tool_calls_proposed') ?? events.filter((event) => event.type === 'tool_proposal').length,
    toolCallsStarted: numberOf(finished, 'tool_calls_started') ?? numberOf(blockedEvent, 'tool_calls_started') ?? events.filter((event) => event.type === 'execution' && valueOf(event, 'stage') === 'tool' && valueOf(event, 'status') === 'started').length,
    finalStatus: valueOf(finished, 'status') || (status === 'checking' ? '进行中' : status === 'unevaluated' ? '未开始' : status === 'blocked' || status === 'error' ? '已停止' : '未返回终态'),
    toolDetails: [...tools.entries()].map(([name, execution]) => ({ name, execution })),
    judgeStatus: valueOf(judgeEvent, 'judge_status'),
    judgeCalls: numberOf(judgeEvent, 'judge_calls') ?? 0,
    judgeModel: valueOf(judgeEvent, 'judge_model'),
  };
}

export function summarizeInvocationEvidence(
  events: SafeHarnessSecurityTimelineEvent[] = [],
  toolCalls: ToolCall[] = [],
): InvocationEvidence {
  const summary = summarizeSecurityTurn({ events }, true);
  const finished = events.find((event) => event.type === 'run_finished');
  const agents = new Set<string>();
  if (valueOf(finished, 'status') === 'completed') {
    summary.agentChain.split(/\s*->\s*/).filter(Boolean).forEach((agent) => agents.add(agent));
  } else {
    events.filter((event) => event.type === 'execution').forEach((event) => {
      const agent = valueOf(event, 'agent_id');
      if (agent) agents.add(agent);
    });
  }
  const tools = new Set<string>();
  events.filter((event) => event.type === 'execution' && valueOf(event, 'stage') === 'tool').forEach((event) => {
    const name = valueOf(event, 'tool_name');
    if (name) tools.add(name);
  });
  const skills = new Set<string>();
  toolCalls.filter((call) => call.status === 'success' || call.status === 'running').forEach((call) => {
    const name = String(call.name || '').replace(/^mcp__[^_]+__/, '');
    if (name === 'call_subagent') {
      const input = call.input as Record<string, unknown> | undefined;
      const agent = input && (input.agent_id || input.agent || input.name);
      if (typeof agent === 'string' && agent) agents.add(agent);
    } else if (name === 'call_skill' || name === 'use_skill') {
      const input = call.input as Record<string, unknown> | undefined;
      const skill = input && (input.skill_name || input.skill || input.name);
      if (typeof skill === 'string' && skill) skills.add(skill);
    } else if (name === 'view_text_file') {
      const input = call.input as Record<string, unknown> | undefined;
      const path = input && (input.path || input.file_path);
      const match = typeof path === 'string' ? path.replace(/\\/g, '/').match(/\/([^/]+)\/SKILL\.md$/i) : null;
      if (match) skills.add(match[1]);
      else tools.add(name);
    } else if (name) {
      tools.add(name);
    }
  });
  const blocked = events.find((event) => event.type === 'blocked')
    || events.find((event) => event.type === 'policy_decision' && valueOf(event, 'disposition').toLowerCase() === 'deny');
  return {
    agents: [...agents],
    tools: [...tools],
    skills: [...skills],
    blockedReason: blocked ? valueOf(blocked, 'reason_code') : '',
  };
}

export function buildSecurityLogExport(
  conversationId: string,
  protectedEnabled: boolean,
  turns: SecurityTurnInput[],
  startupSelfCheck: SafeHarnessSecurityReport | null,
): SecurityLogExport {
  return {
    schema_version: 'sumc.security-log.v1',
    exported_at: new Date().toISOString(),
    product: 'Upear',
    conversation_id: conversationId,
    protected: protectedEnabled,
    production_ready: false,
    turns: turns.map((turn) => ({
      timestamp: turn.ts,
      summary: summarizeSecurityTurn(turn, protectedEnabled),
      events: exportEvents(turn.events),
    })),
    startup_self_check: startupSelfCheck,
  };
}

export function securityLogToText(log: SecurityLogExport): string {
  const lines = [
    'Upear 安全日志',
    `导出时间：${log.exported_at}`,
    `会话：${log.conversation_id}`,
    `安全保护：${log.protected ? '开启' : '关闭'}`,
    '生产就绪：否',
    '',
    '当前会话',
  ];
  log.turns.forEach((turn, index) => {
    const summary = turn.summary;
    lines.push(`第 ${index + 1} 轮：${summary.label}`);
    lines.push(`原因：${summary.reason}`);
    if (summary.agentChain) lines.push(`分发链：${summary.agentChain}`);
    lines.push(`统计：检查 ${summary.checks} 项；Judge ${summary.judgeCalls} 次；模型 ${summary.modelCalls} 次；工具提议 ${summary.toolCallsProposed} 次；工具启动 ${summary.toolCallsStarted} 次；清洗 ${summary.sanitized} 项；审批 ${summary.approval}；拦截 ${summary.blocked} 项；最终状态 ${summary.finalStatus}`);
    if (summary.toolDetails.length) lines.push(`工具：${summary.toolDetails.map((tool) => `${tool.name}（${tool.execution}）`).join('、')}`);
    lines.push(`详细事件：${turn.events.length} 条`);
    lines.push('');
  });
  lines.push('启动自检');
  if (!log.startup_self_check) lines.push('报告不可用');
  else log.startup_self_check.scenarios.forEach((scenario) => {
    lines.push(`${scenario.name}：${scenario.passed ? 'PASS' : 'FAIL'}；拦截阶段：${scenario.blocked_stage}；${scenario.description}`);
  });
  return lines.join('\n');
}
