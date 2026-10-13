import { SAFEHARNESS_CAPABILITIES, type SafeHarnessCapability } from './edition';

export type SafeHarnessCapabilities = Record<SafeHarnessCapability, boolean>;

export interface SafeHarnessContext {
  tenantId: string | null;
  userId: string | null;
  role: string | null;
  conversationId: string | null;
  agentId: string | null;
  projectId: string | null;
  traceId: string | null;
}

export interface SafeHarnessCapabilityDiscovery {
  available: boolean;
  source: 'backend' | 'unavailable';
  capabilities: SafeHarnessCapabilities;
  context: SafeHarnessContext | null;
  correlationId: string | null;
}

export interface SafeHarnessDiscoveryContext {
  conversationId?: string;
  agentId?: string;
  projectId?: string;
}

export interface SafeHarnessOverview {
  ok: true;
  version?: string;
  occurred_at?: string;
  operation?: string;
  actor?: string;
  state?: Record<string, unknown>;
  correlation_id?: string;
}

export interface SafeHarnessAuditQuery {
  tenant_id?: string;
  source?: 'agent' | 'gateway';
  action?: string;
  limit?: number;
}

export interface SafeHarnessAuditResponse {
  ok: true;
  available: boolean;
  records: Array<Record<string, unknown>>;
  correlation_id?: string;
}

export interface SafeHarnessMutationPrepare {
  schema_version: '1.0';
  action: 'agent.quarantine' | 'agent.restore' | 'delegation.revoke'
    | 'capability.enable' | 'capability.disable'
    | 'plugin.enable' | 'plugin.disable' | 'automation.run';
  target: { tenant_id: string; agent_id: string }
    | { tenant_id: string; delegation_id: string }
    | { tenant_id: string; kind: 'skill' | 'agent' | 'mcp'; item_id: string }
    | { tenant_id: string; install_id: string }
    | { tenant_id: string; task_id: string };
  reason: string;
  idempotency_key: string;
  reauth: { method: 'password'; credential: string };
}

export interface SafeHarnessMutationResult {
  status: 'pending' | 'denied' | 'completed' | 'accepted' | 'rejected';
  approval_id: string;
  idempotency_key: string;
  receipt?: Record<string, unknown>;
}

export interface SafeHarnessPolicyResponse {
  schema_version: '1.0';
  tenant_id: string;
  packages: Array<Record<string, unknown>>;
  diff: Record<string, unknown>;
  publishing: { available: false };
  rollback: { available: false };
}

export interface SafeHarnessPolicySimulation {
  schema_version: '1.0';
  tenant_id: string;
  package_id: string;
  operation: string;
  mode: 'deterministic_read_only';
  decision: string;
  impact: Record<string, unknown>;
}

export interface SafeHarnessPolicyRule {
  name: string;
  pattern: string;
  severity?: string;
  category?: string;
  reason?: string;
  action?: string;
}

export interface SafeHarnessPolicyRulesState {
  enabled: boolean;
  version: number;
  rules: SafeHarnessPolicyRule[];
  history: Array<{
    version: number;
    rules: SafeHarnessPolicyRule[];
    enabled: boolean;
    saved_at: string;
    saved_by: string;
  }>;
  updated_at: string;
  updated_by: string;
  effective: { runtime_rule_count: number; runtime_rules: string[] };
}

export interface SafeHarnessPolicyRulesTestResult {
  hit: boolean;
  changed: boolean;
  cleaned: string;
  matched_rule: {
    name: string;
    severity: string;
    category: string;
    reason: string;
    source: string;
  } | null;
  rule_count: number;
}

export interface SafeHarnessPolicyRulesDraftResult {
  draft: SafeHarnessPolicyRule[];
  validation_errors: string[];
  sample_results: Array<{ text: string; hit: boolean; matched_rule: string | null }>;
  model: string;
  notice: string;
}

export interface SafeHarnessSecurityReport {
  schema_version: '1.0';
  generated_at: string;
  overall_status: 'pass' | 'fail';
  production_ready: false;
  scenarios: Array<{
    name: string;
    blocked_stage: string;
    description: string;
    passed: boolean;
    evidence: Record<string, string | number | boolean>;
  }>;
}

export interface SafeHarnessTestScenario {
  scenario_id: string;
  name: string;
  blocked_stage: string;
  input_schema: Record<string, unknown>;
  expected: Record<string, unknown>;
  capability: string;
}

export interface SafeHarnessTestRun {
  run_id: string;
  scenario_id: string;
  status: 'pass' | 'fail';
  expected: Record<string, unknown>;
  observed: Array<Record<string, unknown>>;
  reason_code: string;
  production_ready: false;
}

export interface ConfigAgentState {
  config_key: string;
  agent_id: string;
  version: string;
  updated_at?: string | null;
}

export interface ConfigDraft {
  draft_id: string;
  config_key: string;
  agent_id: string;
  base_version: string;
  payload: Record<string, unknown>;
  validation: Record<string, unknown>;
  status: string;
  diff?: Array<Record<string, unknown>>;
  updated_at?: string | null;
}

export interface SafeHarnessErrorPayload {
  code: number;
  message: string;
  data: { error: { code: string } };
  trace_id: string;
  timestamp: number;
}

export class SafeHarnessApiError extends Error {
  readonly status: number;
  readonly payload: unknown;

  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = 'SafeHarnessApiError';
    this.status = status;
    this.payload = payload;
  }
}

const ROUTES = Object.freeze({
  // Same-origin BFF routes. The backend remains fail-closed until configured.
  capabilities: '/v1/meta/safeharness',
  overview: '/v1/safeharness/overview',
  audit: '/v1/safeharness/audit',
  mutations: '/v1/safeharness/mutations',
  policies: '/v1/safeharness/policies',
  policyRules: '/v1/safeharness/policy-rules',
  protectedChatStream: '/v1/safeharness/chat/stream',
  securityReport: '/v1/safeharness/security-report',
  testScenarios: '/v1/safeharness/test-scenarios',
  testRuns: '/v1/safeharness/test-runs',
  configState: '/v1/config-center/state',
  configValidate: '/v1/config-center/validate',
  configDrafts: '/v1/config-center/drafts',
  configHistory: '/v1/config-center/history',
  configRollback: '/v1/config-center/rollback',
});

function emptyCapabilities(): SafeHarnessCapabilities {
  return { ...SAFEHARNESS_CAPABILITIES };
}

function unavailableDiscovery(): SafeHarnessCapabilityDiscovery {
  return {
    available: false,
    source: 'unavailable',
    capabilities: Object.fromEntries(
      Object.keys(SAFEHARNESS_CAPABILITIES).map((key) => [key, false]),
    ) as SafeHarnessCapabilities,
    context: null,
    correlationId: null,
  };
}

function apiBase(): string {
  const configured = import.meta.env.VITE_SAFEHARNESS_API_BASE ?? import.meta.env.VITE_API_BASE_URL;
  return typeof configured === 'string' && configured.trim()
    ? configured.trim().replace(/\/$/, '')
    : '/api';
}

function urlFor(path: string): string {
  return `${apiBase()}${path}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function readErrorMessage(payload: unknown, fallback: string): string {
  if (isRecord(payload) && isRecord(payload.error) && typeof payload.error.message === 'string') {
    return payload.error.message;
  }
  if (isRecord(payload) && typeof payload.message === 'string') return payload.message;
  if (isRecord(payload) && isRecord(payload.detail) && typeof payload.detail.message === 'string') {
    return payload.detail.message;
  }
  return fallback;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(urlFor(path), {
    ...init,
    credentials: 'include',
    headers: { Accept: 'application/json', ...(init.headers || {}) },
  });
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new SafeHarnessApiError('SafeHarness API returned invalid JSON.', response.status, null);
  }
  if (!response.ok || (isRecord(payload) && payload.ok === false)) {
    throw new SafeHarnessApiError(
      readErrorMessage(payload, 'SafeHarness API request failed.'),
      response.status,
      payload,
    );
  }
  if (isRecord(payload) && 'data' in payload && ('code' in payload || 'trace_id' in payload)) {
    if (isRecord(payload.data) && typeof payload.trace_id === 'string' && !('correlation_id' in payload.data)) {
      return { ...payload.data, correlation_id: payload.trace_id } as T;
    }
    return payload.data as T;
  }
  return payload as T;
}

function readContext(value: unknown): SafeHarnessContext | null {
  if (!isRecord(value)) return null;
  const text = (key: string): string | null => typeof value[key] === 'string' ? value[key] as string : null;
  return {
    tenantId: text('tenant_id'),
    userId: text('user_id'),
    role: text('role'),
    conversationId: text('conversation_id'),
    agentId: text('agent_id'),
    projectId: text('project_id'),
    traceId: text('trace_id'),
  };
}

function normalizeDiscovery(value: unknown): SafeHarnessCapabilityDiscovery {
  if (!isRecord(value) || value.available !== true) return unavailableDiscovery();
  const discovered = isRecord(value.capabilities) ? value.capabilities : {};
  const capabilities = emptyCapabilities();
  (Object.keys(capabilities) as SafeHarnessCapability[]).forEach((key) => {
    capabilities[key] = discovered[key] === true;
  });
  return {
    available: true,
    source: 'backend',
    capabilities,
    context: readContext(value.context),
    correlationId: typeof value.correlation_id === 'string' ? value.correlation_id : null,
  };
}

export async function discoverSafeHarnessCapabilities(
  context: SafeHarnessDiscoveryContext = {},
  signal?: AbortSignal,
): Promise<SafeHarnessCapabilityDiscovery> {
  try {
    const params = new URLSearchParams();
    if (context.conversationId) params.set('conversation_id', context.conversationId);
    if (context.agentId) params.set('agent_id', context.agentId);
    if (context.projectId) params.set('project_id', context.projectId);
    const encoded = params.toString();
    const query = encoded ? `?${encoded}` : '';
    return normalizeDiscovery(await request(`${ROUTES.capabilities}${query}`, { signal }));
  } catch {
    return unavailableDiscovery();
  }
}

export async function openProtectedChatStream(
  input: { conversationId: string; agentId: string; projectId?: string; message: string; modelProviderId?: string },
  signal?: AbortSignal,
): Promise<Response> {
  return fetch(urlFor(ROUTES.protectedChatStream), {
    method: 'POST',
    credentials: 'include',
    signal,
    headers: {
      Accept: 'text/event-stream',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      conversation_id: input.conversationId,
      agent_id: input.agentId,
      ...(input.projectId ? { project_id: input.projectId } : {}),
      message: input.message,
      ...(input.modelProviderId ? { model_provider_id: input.modelProviderId } : {}),
    }),
  });
}

export function isDiscoveredCapabilityEnabled(
  discovery: SafeHarnessCapabilityDiscovery,
  capability: SafeHarnessCapability,
): boolean {
  return discovery.available && discovery.capabilities[capability] === true;
}

export const safeharnessApi = {
  discoverCapabilities: discoverSafeHarnessCapabilities,
  openProtectedChatStream,
  getOverview: (signal?: AbortSignal) => request<SafeHarnessOverview>(ROUTES.overview, { signal }),
  getAudit: (query: SafeHarnessAuditQuery = {}, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    Object.entries(query).forEach(([key, value]) => {
      if (value !== undefined) params.set(key, String(value));
    });
    return request<SafeHarnessAuditResponse>(`${ROUTES.audit}?${params.toString()}`, { signal });
  },
  getPolicies: (signal?: AbortSignal) => request<SafeHarnessPolicyResponse>(ROUTES.policies, { signal }),
  getPolicyRules: (signal?: AbortSignal) => request<SafeHarnessPolicyRulesState>(ROUTES.policyRules, { signal }),
  putPolicyRules: (body: { enabled: boolean; rules: SafeHarnessPolicyRule[] }) => request<SafeHarnessPolicyRulesState>(ROUTES.policyRules, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }),
  testPolicyRules: (text: string) => request<SafeHarnessPolicyRulesTestResult>(`${ROUTES.policyRules}/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  }),
  draftPolicyRules: (body: { description: string; sample_texts?: string[] }) => request<SafeHarnessPolicyRulesDraftResult>(`${ROUTES.policyRules}/draft`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }),
  rollbackPolicyRules: (version: number) => request<SafeHarnessPolicyRulesState>(`${ROUTES.policyRules}/rollback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ version }),
  }),
  getSecurityReport: (signal?: AbortSignal) => request<SafeHarnessSecurityReport>(ROUTES.securityReport, { signal }),
  getTestScenarios: (signal?: AbortSignal) => request<{ scenarios: SafeHarnessTestScenario[] }>(ROUTES.testScenarios, { signal }),
  createTestRun: (scenarioId: string, parameters: Record<string, unknown> = {}) => request<SafeHarnessTestRun>(ROUTES.testRuns, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario_id: scenarioId, parameters }),
  }),
  getTestEventsUrl: (runId: string) => urlFor(`${ROUTES.testRuns}/${encodeURIComponent(runId)}/events`),
  getConfigState: (signal?: AbortSignal) => request<{ versions: ConfigAgentState[] }>(ROUTES.configState, { signal }),
  validateConfig: (agentId: string, payload: Record<string, unknown>) => request<Record<string, unknown>>(ROUTES.configValidate, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_id: agentId, payload }),
  }),
  createConfigDraft: (agentId: string, baseVersion: string, payload: Record<string, unknown>) => request<ConfigDraft>(ROUTES.configDrafts, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_id: agentId, base_version: baseVersion, payload }),
  }),
  getConfigDraft: (draftId: string) => request<ConfigDraft>(`${ROUTES.configDrafts}/${encodeURIComponent(draftId)}`),
  submitConfigDraft: (draftId: string) => request<ConfigDraft>(`${ROUTES.configDrafts}/${encodeURIComponent(draftId)}/submit`, { method: 'POST' }),
  decideConfigDraft: (draftId: string, decision: 'approve' | 'reject') => request<ConfigDraft>(`${ROUTES.configDrafts}/${encodeURIComponent(draftId)}/approve`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision }),
  }),
  publishConfigDraft: (draftId: string) => request<Record<string, unknown>>(`${ROUTES.configDrafts}/${encodeURIComponent(draftId)}/publish`, { method: 'POST' }),
  getConfigHistory: (signal?: AbortSignal) => request<{ versions: Array<Record<string, unknown>> }>(ROUTES.configHistory, { signal }),
  rollbackConfig: (versionId: string) => request<Record<string, unknown>>(`${ROUTES.configRollback}?version_id=${encodeURIComponent(versionId)}`, { method: 'POST' }),
  simulatePolicy: (packageId: string, operation: string) => request<SafeHarnessPolicySimulation>(`${ROUTES.policies}/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ schema_version: '1.0', package_id: packageId, operation }),
  }),
  prepareMutation: (input: SafeHarnessMutationPrepare) => request<SafeHarnessMutationResult>(ROUTES.mutations, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  }),
  decideMutation: (approvalId: string, idempotencyKey: string, decision: 'allow' | 'deny') => request<SafeHarnessMutationResult>(`${ROUTES.mutations}/${encodeURIComponent(approvalId)}/decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ schema_version: '1.0', decision, idempotency_key: idempotencyKey }),
  }),
} as const;
