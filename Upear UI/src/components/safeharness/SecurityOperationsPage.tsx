import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Card, Descriptions, Empty, Input, Modal, Select, Space, Spin,
  Statistic, Switch, Table, Tag, Tabs, Timeline, Typography, message,
} from 'antd';
import type { TableProps } from 'antd';
import {
  CheckCircleOutlined, ExclamationCircleOutlined, LockOutlined, ReloadOutlined,
  SafetyCertificateOutlined, StopOutlined,
} from '@ant-design/icons';
import { safeharnessApi, type SafeHarnessAuditResponse, type SafeHarnessCapabilityDiscovery, type SafeHarnessMutationPrepare, type SafeHarnessOverview, type SafeHarnessPolicyResponse, type SafeHarnessPolicyRule, type SafeHarnessPolicyRulesDraftResult, type SafeHarnessPolicyRulesState, type SafeHarnessPolicyRulesTestResult, type SafeHarnessPolicySimulation, type SafeHarnessSecurityReport } from '../../safeharnessApi';
import { useEditionStore } from '../../stores';
import { useAgentStore } from '../../stores/agentStore';
import { parseServerTime } from '../../utils/date';
import { defaultProductionReady, demoAgentCatalog, pairSet, unavailableEvaluationEvidence, type AgentCatalogItem } from './securityOperationsData';
// Tab-level lazy: these two sections carry their own API surfaces and are the
// heaviest code in the page — keep them out of the SecurityOperations chunk
// until their tab is first activated (antd Tabs mounts children on activation).
const ControlCenterSection = lazy(() => import('./ControlCenterSection').then((m) => ({ default: m.ControlCenterSection })));
const ReviewWorkbenchSection = lazy(() => import('./ReviewWorkbenchSection').then((m) => ({ default: m.ReviewWorkbenchSection })));
const ExternalAgentsSection = lazy(() => import('./ExternalAgentsSection').then((m) => ({ default: m.ExternalAgentsSection })));

const SECTION_SUSPENSE_FALLBACK = <Spin size="small" style={{ display: 'block', margin: '48px auto' }} />;

type JsonRecord = Record<string, unknown>;
type AgentRecord = JsonRecord & Partial<AgentCatalogItem> & { tenant_id?: string; agent_id?: string; active?: boolean };

const UNKNOWN = '未知';

function record(value: unknown): JsonRecord {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : {};
}

function array(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.filter((item): item is JsonRecord => !!item && typeof item === 'object') : [];
}

function text(value: unknown): string {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : UNKNOWN;
}

function list(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}

function number(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function stateOf(overview: SafeHarnessOverview | null): JsonRecord {
  return record(overview?.state);
}

function agentsOf(overview: SafeHarnessOverview | null): AgentRecord[] {
  const merged = new Map<string, AgentRecord>(demoAgentCatalog.map((agent) => [agent.agent_id, agent]));
  array(stateOf(overview).agents).forEach((agent) => {
    const agentId = typeof agent.agent_id === 'string' ? agent.agent_id : '';
    if (!agentId) return;
    merged.set(agentId, { ...(merged.get(agentId) || {}), ...agent });
  });
  return [...merged.values()];
}

function quarantinedOf(overview: SafeHarnessOverview | null): Set<string> {
  return pairSet(stateOf(overview).quarantined);
}

function metric(state: JsonRecord, names: string[]): number | null {
  for (const name of names) {
    const direct = number(state[name]);
    if (direct !== null) return direct;
    const nested = record(state.metrics)[name];
    const nestedNumber = number(nested);
    if (nestedNumber !== null) return nestedNumber;
  }
  return null;
}

function statusTag(status: string) {
  const normalized = status.toLowerCase();
  if (status === '活动' || status === '已连接' || status === '有效' || ['allow', 'allowed', 'approved', 'delivered', 'issued', 'ready', 'success', 'succeeded'].includes(normalized)) return <Tag color="success">{status}</Tag>;
  if (status === '已隔离' || status === '拒绝' || status === '已撤销' || ['deny', 'denied', 'blocked', 'failed', 'rejected'].includes(normalized)) return <Tag color="error">{status}</Tag>;
  if (status === '未知' || status === '不可用') return <Tag>{status}</Tag>;
  return <Tag color="warning">{status}</Tag>;
}

function formatTime(value: unknown): string {
  if (typeof value !== 'string' && typeof value !== 'number') return UNKNOWN;
  const ts = parseServerTime(value);
  return Number.isNaN(ts) ? UNKNOWN : new Date(ts).toLocaleString();
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : 'SafeHarness 控制面请求失败。';
}

function agentPresentation(agent: AgentRecord): { name: string; type: string; responsibility: string } {
  const agentId = text(agent.agent_id);
  if (agentId === 'noc-supervisor-agent') return { name: '运维监督 Agent', type: '模拟 NOC 控制面', responsibility: '监控运维状态、管理受控委派' };
  if (agentId === 'noc-diagnosis-agent') return { name: '告警诊断 Agent', type: '模拟 NOC 控制面', responsibility: '分析告警、返回诊断结果' };
  return {
    name: text(agent.name),
    type: text(agent.type) === UNKNOWN ? '控制面 Agent' : text(agent.type),
    responsibility: text(agent.responsibility) === UNKNOWN ? '职责由控制面配置提供' : text(agent.responsibility),
  };
}

const auditColumns: TableProps<JsonRecord>['columns'] = [
  { title: '时间', dataIndex: 'occurred_at', render: formatTime },
  { title: '来源', dataIndex: 'source', render: text },
  { title: '动作', dataIndex: 'action', render: text },
  { title: '结果', dataIndex: 'outcome', render: (value) => statusTag(text(value)) },
  { title: 'Agent', dataIndex: 'agent_id', render: text },
  { title: '原因', dataIndex: 'reason_code', render: text },
];

type MutationIntent = {
  action: SafeHarnessMutationPrepare['action'];
  target: SafeHarnessMutationPrepare['target'];
  title: string;
  targetLabel: string;
  success: string;
  danger: boolean;
};

export function SecurityOperationsPage() {
  const { agents: userAgents, fetchAgents } = useAgentStore();
  const features = useEditionStore((state) => state.features);
  const [discovery, setDiscovery] = useState<SafeHarnessCapabilityDiscovery | null>(null);
  const [overview, setOverview] = useState<SafeHarnessOverview | null>(null);
  const [audit, setAudit] = useState<SafeHarnessAuditResponse | null>(null);
  const [policies, setPolicies] = useState<SafeHarnessPolicyResponse | null>(null);
  const [policySimulation, setPolicySimulation] = useState<SafeHarnessPolicySimulation | null>(null);
  const [securityReport, setSecurityReport] = useState<SafeHarnessSecurityReport | null>(null);
  const [loadingOverview, setLoadingOverview] = useState(true);
  const [loadingAudit, setLoadingAudit] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [source, setSource] = useState<'agent' | 'gateway' | undefined>();
  const [action, setAction] = useState('');
  const [pendingMutation, setPendingMutation] = useState<MutationIntent | null>(null);
  const [pendingApproval, setPendingApproval] = useState<{ approvalId: string; idempotencyKey: string } | null>(null);
  const [mutationReason, setMutationReason] = useState('');
  const [reauthPassword, setReauthPassword] = useState('');
  const [mutating, setMutating] = useState(false);

  const loadOverview = useCallback(async (signal?: AbortSignal) => {
    try {
      setOverview(await safeharnessApi.getOverview(signal));
    } catch {
      if (!signal?.aborted) setOverview(null);
    } finally {
      if (!signal?.aborted) setLoadingOverview(false);
    }
  }, []);

  const loadAudit = useCallback(async (query: { source?: 'agent' | 'gateway'; action?: string } = {}, signal?: AbortSignal) => {
    try {
      setAudit(await safeharnessApi.getAudit({ ...query, limit: 50 }, signal));
    } catch {
      if (!signal?.aborted) setAudit(null);
    } finally {
      if (!signal?.aborted) setLoadingAudit(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void fetchAgents();
    void safeharnessApi.discoverCapabilities({}, controller.signal).then((value) => {
      if (!controller.signal.aborted) setDiscovery(value);
    });
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadOverview(controller.signal);
    void loadAudit({}, controller.signal);
    void safeharnessApi.getPolicies(controller.signal).then(setPolicies).catch(() => setPolicies(null));
    void safeharnessApi.getSecurityReport(controller.signal).then(setSecurityReport).catch(() => setSecurityReport(null));
    return () => controller.abort();
  }, [fetchAgents, loadAudit, loadOverview]);

  const reload = () => {
    const controller = new AbortController();
    setLoadingOverview(true);
    setLoadingAudit(true);
    void loadOverview(controller.signal);
    void loadAudit({ source, action: action.trim() || undefined }, controller.signal);
  };

  const searchAudit = () => {
    setLoadingAudit(true);
    void loadAudit({ source, action: action.trim() || undefined });
  };

  const agents = useMemo(() => agentsOf(overview), [overview]);
  const operationsAgents = useMemo(() => agents.filter((agent) => agent.category === 'operations'), [agents]);
  const generalAgents = useMemo(() => agents.filter((agent) => agent.category === 'general'), [agents]);
  const quarantined = useMemo(() => quarantinedOf(overview), [overview]);
  const state = stateOf(overview);
  const manageable = discovery?.available === true && discovery.context?.role === 'super_admin';
  const controlPlaneStatus = overview ? '已连接' : loadingOverview ? '未知' : '不可用';
  const activeAgents = agents.filter((agent) => agent.active === true && !quarantined.has(`${text(agent.tenant_id)}:${text(agent.agent_id)}`)).length;
  const topology = array(state.topology);
  const delegations = array(state.delegations);
  const revokedDelegations = pairSet(state.revoked_delegations);

  const resetMutation = () => {
    setPendingMutation(null);
    setPendingApproval(null);
    setMutationReason('');
    setReauthPassword('');
  };

  const confirmMutation = async () => {
    if (!pendingMutation || !manageable) return;
    setMutating(true);
    try {
      if (!pendingApproval) {
        if (mutationReason.trim().length < 3 || !reauthPassword) return;
        const idempotencyKey = crypto.randomUUID();
        const prepared = await safeharnessApi.prepareMutation({
          schema_version: '1.0', action: pendingMutation.action, target: pendingMutation.target,
          reason: mutationReason.trim(), idempotency_key: idempotencyKey,
          reauth: { method: 'password', credential: reauthPassword },
        });
        setPendingApproval({ approvalId: prepared.approval_id, idempotencyKey });
        setReauthPassword('');
        message.info('一次性审批已准备；再次点击“允许并执行”才会写入控制面。');
        return;
      }
      const result = await safeharnessApi.decideMutation(pendingApproval.approvalId, pendingApproval.idempotencyKey, 'allow');
      if (result.status === 'rejected') throw new Error('受控操作被后端拒绝；目标不存在、无权访问、状态不允许或执行服务不可用。');
      message.success(pendingMutation.success);
      resetMutation();
      reload();
    } catch (error) {
      message.error(errorText(error));
    } finally {
      setMutating(false);
    }
  };

  const cancelMutation = async () => {
    if (pendingApproval) {
      setMutating(true);
      try {
        await safeharnessApi.decideMutation(pendingApproval.approvalId, pendingApproval.idempotencyKey, 'deny');
      } catch (error) {
        message.error(errorText(error));
      } finally {
        setMutating(false);
      }
    }
    resetMutation();
  };

  const agentColumns: TableProps<AgentRecord>['columns'] = [
    { title: '名称', render: (_, agent) => agentPresentation(agent).name },
    { title: '技术 ID', dataIndex: 'agent_id', render: text },
    { title: '类型', render: (_, agent) => agentPresentation(agent).type },
    { title: '职责', render: (_, agent) => agentPresentation(agent).responsibility },
    { title: '来源', dataIndex: 'source', render: text },
    { title: 'SafeHarness 覆盖', render: (_, agent) => statusTag(agent.security_coverage === 'runtime-protected' ? '运行时保护' : '仅目录声明') },
    { title: '角色', dataIndex: 'roles', render: (value) => list(value).map((item) => <Tag key={item}>{item}</Tag>) },
    {
      title: '状态',
      render: (_, agent) => {
        const quarantinedAgent = quarantined.has(`${text(agent.tenant_id)}:${text(agent.agent_id)}`);
        return statusTag(quarantinedAgent ? '已隔离' : agent.availability === 'unavailable' ? '未接入' : agent.active === true ? '活动' : agent.active === false ? '已停用' : '未知');
      },
    },
    { title: '当前可调用', render: (_, agent) => statusTag(agent.availability === 'active' && agent.security_coverage === 'runtime-protected' ? '允许' : '不可调用') },
    { title: '可委派能力', dataIndex: 'delegable_capabilities', render: (value) => list(value).map((item) => <Tag key={item} color="blue">{item}</Tag>) },
    {
      title: '操作',
      render: (_, agent) => {
        const restore = quarantined.has(`${text(agent.tenant_id)}:${text(agent.agent_id)}`);
        return <Button size="small" danger={!restore} disabled={!manageable || agent.manageable !== true || agent.availability !== 'active'} onClick={() => {
          const tenantId = text(agent.tenant_id); const agentId = text(agent.agent_id);
          if (tenantId !== UNKNOWN && agentId !== UNKNOWN) setPendingMutation({
            action: restore ? 'agent.restore' : 'agent.quarantine',
            target: { tenant_id: tenantId, agent_id: agentId },
            title: restore ? '恢复 Agent' : '隔离 Agent', targetLabel: agentId,
            success: restore ? 'Agent 已恢复。' : 'Agent 已隔离。', danger: !restore,
          });
        }}>{restore ? '恢复' : '隔离'}</Button>;
      },
    },
  ];

  if (features.security_operations !== true) return <Alert type="warning" showIcon message="安全运营能力未启用。" />;

  return (
    <div className="sh-operations-page">
      <div className="sh-operations-toolbar">
        <Space>
          {statusTag(controlPlaneStatus)}
          {discovery?.context?.tenantId && <Typography.Text type="secondary">Tenant: {discovery.context.tenantId}</Typography.Text>}
        </Space>
        <Button icon={<ReloadOutlined />} onClick={reload} loading={loadingOverview || loadingAudit}>刷新</Button>
      </div>
      <Tabs activeKey={activeTab} onChange={setActiveTab} items={[
        { key: 'control-center', label: '测试与配置中心', children: <Suspense fallback={SECTION_SUSPENSE_FALLBACK}><ControlCenterSection agents={userAgents} /></Suspense> },
        { key: 'review-workbench', label: '人工复核', children: <Suspense fallback={SECTION_SUSPENSE_FALLBACK}><ReviewWorkbenchSection /></Suspense> },
        { key: 'overview', label: '安全总览', children: <OverviewSection state={state} overview={overview} agents={agents} operationsAgents={operationsAgents} generalAgents={generalAgents} activeAgents={activeAgents} quarantined={quarantined.size} /> },
        { key: 'operations-agents', label: '运维智能体', children: <>
          <Alert type="info" showIcon message="运维智能体负责告警、排障和配置类业务；所有运行请求先经过平台总控 Supervisor 与 SafeHarness。" />
          <Table rowKey={(row) => `${text(row.tenant_id)}:${text(row.agent_id)}`} columns={agentColumns} dataSource={operationsAgents} loading={loadingOverview} locale={{ emptyText: loadingOverview ? <Spin /> : <Empty description="暂无运维智能体记录" /> }} pagination={{ pageSize: 20, hideOnSinglePage: true }} scroll={{ x: 1450 }} />
        </> },
        { key: 'general-agents', label: '通用智能体', children: <>
          <Alert type="info" showIcon message="通用智能体处理对话、联网和知识问答；未接入项只展示目录状态，不可从当前聊天调用。" />
          <Table rowKey={(row) => `${text(row.tenant_id)}:${text(row.agent_id)}`} columns={agentColumns} dataSource={generalAgents} loading={loadingOverview} locale={{ emptyText: loadingOverview ? <Spin /> : <Empty description="暂无通用智能体记录" /> }} pagination={{ pageSize: 20, hideOnSinglePage: true }} scroll={{ x: 1450 }} />
          <Typography.Title level={5} style={{ marginTop: 16 }}>外部智能体（真实开源框架接入，聊天中 @ 可选）</Typography.Title>
          <Suspense fallback={SECTION_SUSPENSE_FALLBACK}><ExternalAgentsSection /></Suspense>
        </> },
        { key: 'runs', label: '运行追踪', children: <RunTraceSection records={audit?.records || []} loading={loadingAudit} available={audit?.available === true} /> },
        { key: 'tools', label: '工具权限', children: <ToolPermissionSection agents={agents} loading={loadingOverview} /> },
        { key: 'application', label: '受控应用操作', children: <ControlledApplicationSection tenantId={discovery?.context?.tenantId || null} manageable={manageable} onMutate={setPendingMutation} /> },
        { key: 'communication', label: '通信安全', children: <CommunicationSection topology={topology} delegations={delegations} revoked={revokedDelegations} loading={loadingOverview} manageable={manageable} onRevoke={(item) => {
          const tenantId = text(item.tenant_id); const delegationId = text(item.delegation_id);
          if (tenantId !== UNKNOWN && delegationId !== UNKNOWN) setPendingMutation({
            action: 'delegation.revoke', target: { tenant_id: tenantId, delegation_id: delegationId },
            title: '撤销委派', targetLabel: delegationId, success: '委派已撤销。', danger: true,
          });
        }} /> },
        { key: 'evaluation', label: '安全评估', children: <EvaluationSection /> },
        { key: 'test-report', label: '测试报告', children: <SecurityTestReportSection report={securityReport} /> },
        { key: 'policies', label: '策略中心', children: <>
          <PolicySection policies={policies} simulation={policySimulation} onSimulate={async (packageId, operation) => {
            try { setPolicySimulation(await safeharnessApi.simulatePolicy(packageId, operation)); }
            catch (error) { message.error(errorText(error)); }
          }} />
          <PolicyRulesCard />
        </> },
        { key: 'audit', label: '审计', children: <AuditSection audit={audit} loading={loadingAudit} source={source} action={action} setSource={setSource} setAction={setAction} onSearch={searchAudit} /> },
      ]} />
      <Descriptions size="small" column={{ xs: 1, sm: 2, md: 3 }} items={[
        { key: 'trace', label: '关联 ID', children: overview?.correlation_id || discovery?.correlationId || UNKNOWN },
        { key: 'version', label: '控制面版本', children: text(overview?.version) },
        { key: 'updated', label: '状态时间', children: formatTime(overview?.occurred_at) },
      ]} />
      <Modal open={!!pendingMutation} title={pendingMutation?.title} okText={pendingApproval ? '允许并执行' : '准备审批'} cancelText={pendingApproval ? '拒绝' : '取消'} okButtonProps={{ danger: pendingMutation?.danger, disabled: !manageable || (!pendingApproval && (mutationReason.trim().length < 3 || !reauthPassword)) }} cancelButtonProps={{ disabled: mutating }} confirmLoading={mutating} onOk={() => void confirmMutation()} onCancel={() => void cancelMutation()} maskClosable={false}>
        <Typography.Paragraph>目标：{pendingMutation?.targetLabel}。{pendingApproval ? '审批已绑定该目标；允许后将写入签名控制面 mutation log。' : '先重新认证并准备一次性审批，不会立即执行。'}</Typography.Paragraph>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Input.TextArea disabled={!!pendingApproval} value={mutationReason} onChange={(event) => setMutationReason(event.target.value)} placeholder="操作原因（至少 3 个字符）" maxLength={500} autoSize={{ minRows: 2, maxRows: 4 }} />
          {!pendingApproval && <Input.Password value={reauthPassword} onChange={(event) => setReauthPassword(event.target.value)} placeholder="当前密码（重新认证）" maxLength={512} autoComplete="current-password" />}
        </Space>
      </Modal>
    </div>
  );
}

function SecurityTestReportSection({ report }: { report: SafeHarnessSecurityReport | null }) {
  if (!report) return <Alert type="warning" showIcon message="安全测试报告不可用；请确认启动器已完成确定性场景检查。" />;
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <Alert
      type={report.overall_status === 'pass' ? 'success' : 'error'}
      showIcon
      message={`确定性安全场景：${report.overall_status === 'pass' ? '全部通过' : '存在失败'}`}
      description={`生成时间：${formatTime(report.generated_at)}；production_ready=${String(report.production_ready)}`}
    />
    <Table
      rowKey="name"
      dataSource={report.scenarios}
      pagination={false}
      columns={[
        { title: '场景', dataIndex: 'name' },
        { title: '阻断阶段', dataIndex: 'blocked_stage' },
        { title: '结果', dataIndex: 'passed', render: (value: boolean) => statusTag(value ? 'PASS' : 'FAIL') },
        { title: '说明', dataIndex: 'description' },
      ]}
    />
    <Alert type="info" showIcon message="该报告来自确定性离线场景；它证明当前本地安全链路行为，不证明真实模型安全效果或生产就绪。" />
  </Space>;
}

function OverviewSection({ state, overview, agents, operationsAgents, generalAgents, activeAgents, quarantined }: { state: JsonRecord; overview: SafeHarnessOverview | null; agents: AgentRecord[]; operationsAgents: AgentRecord[]; generalAgents: AgentRecord[]; activeAgents: number; quarantined: number }) {
  const gateway = text(record(state.health).gateway ?? state.gateway_health ?? state.gateway);
  const backend = text(record(state.health).backend ?? state.backend_health ?? state.backend);
  const risk = metric(state, ['risk', 'risk_count', 'risks']);
  const deny = metric(state, ['deny', 'deny_count', 'denies']);
  const approvals = metric(state, ['approval', 'approval_count', 'approvals']);
  return <>
    <div className="sh-operations-metrics">
      <Card><Statistic title="智能体总数" value={agents.length} prefix={<SafetyCertificateOutlined />} /></Card>
      <Card><Statistic title="运维智能体" value={operationsAgents.length} /></Card>
      <Card><Statistic title="通用智能体" value={generalAgents.length} /></Card>
      <Card><Statistic title="活动" value={activeAgents} prefix={<CheckCircleOutlined />} /></Card>
      <Card><Statistic title="隔离" value={quarantined} prefix={<StopOutlined />} /></Card>
      <Card><Statistic title="风险" value={risk ?? UNKNOWN} prefix={<ExclamationCircleOutlined />} /></Card>
      <Card><Statistic title="拒绝" value={deny ?? UNKNOWN} prefix={<LockOutlined />} /></Card>
      <Card><Statistic title="审批" value={approvals ?? UNKNOWN} /></Card>
    </div>
    <div className="sh-operations-health">
      <Card title="控制面健康" size="small"><Space wrap><span>Gateway {statusTag(gateway)}</span><span>Backend {statusTag(backend)}</span></Space></Card>
      <Card title="最近状态" size="small"><Descriptions size="small" column={1} items={[{ key: 'operation', label: '操作', children: text(overview?.operation) }, { key: 'actor', label: '主体', children: text(overview?.actor) }]} /></Card>
    </div>
    <Alert type="info" showIcon message="安全评估证据尚未接入控制面，deterministic、live-model、remote infrastructure 和 production evidence 状态保持未知。" />
  </>;
}

function RunTraceSection({ records, loading, available }: { records: JsonRecord[]; loading: boolean; available: boolean }) {
  const runs = useMemo(() => {
    const ids = new Set<string>();
    records.forEach((item) => {
      if (typeof item.run_id === 'string' && item.run_id) ids.add(item.run_id);
    });
    return [...ids];
  }, [records]);
  const [runId, setRunId] = useState<string>();
  const selectedRunId = runId && runs.includes(runId) ? runId : runs[0];
  const selected = records
    .filter((item) => selectedRunId && item.run_id === selectedRunId)
    .sort((left, right) => (number(left.sequence) ?? 0) - (number(right.sequence) ?? 0));
  if (loading) return <Spin />;
  if (!available) return <Alert type="warning" showIcon message="运行审计不可用，追踪状态未知。" />;
  if (!runs.length) return <Empty description="当前有界审计窗口内无 run_id" />;
  return <>
    <div className="sh-operations-filters"><Select value={selectedRunId} onChange={setRunId} options={runs.map((value) => ({ value, label: value }))} /></div>
    <Timeline items={selected.map((item, index) => ({
      key: text(item.record_id) === UNKNOWN ? `${text(item.action)}:${index}` : text(item.record_id),
      color: ['deny', 'denied', 'blocked', 'failed', 'rejected'].includes(text(item.outcome).toLowerCase()) ? 'red' : 'blue',
      children: <div className="sh-operations-timeline-item"><Space wrap><Typography.Text strong>{text(item.action)}</Typography.Text>{statusTag(text(item.outcome))}<Typography.Text type="secondary">#{text(item.sequence)}</Typography.Text></Space><Typography.Text type="secondary">{formatTime(item.occurred_at)} · {text(item.source)} · trace {text(item.trace_id)}</Typography.Text></div>,
    }))} />
    <Alert type="info" showIcon message="当前追踪仅覆盖最多 50 条已脱敏审计记录；checkpoint、compensation 和 receipt 缺失时保持未知。" />
  </>;
}

function ToolPermissionSection({ agents, loading }: { agents: AgentRecord[]; loading: boolean }) {
  const columns: TableProps<AgentRecord>['columns'] = [
    { title: 'Agent', dataIndex: 'agent_id', render: text },
    { title: '接受能力', dataIndex: 'accepted_capabilities', render: (value) => list(value).map((item) => <Tag key={item} color="blue">{item}</Tag>) },
    { title: '可委派能力', dataIndex: 'delegable_capabilities', render: (value) => list(value).map((item) => <Tag key={item}>{item}</Tag>) },
  ];
  return <>
    <Table rowKey={(row) => `${text(row.tenant_id)}:${text(row.agent_id)}`} columns={columns} dataSource={agents} loading={loading} pagination={{ pageSize: 20, hideOnSinglePage: true }} scroll={{ x: 680 }} />
    <Alert type="info" showIcon message="当前权威数据仅覆盖 Agent capability；Tool Catalog、schema、资源绑定、副作用和审批要求尚未接入，状态未知。" />
  </>;
}

function ControlledApplicationSection({ tenantId, manageable, onMutate }: { tenantId: string | null; manageable: boolean; onMutate: (intent: MutationIntent) => void }) {
  const [action, setAction] = useState<SafeHarnessMutationPrepare['action']>('capability.enable');
  const [kind, setKind] = useState<'skill' | 'agent' | 'mcp'>('skill');
  const [identifier, setIdentifier] = useState('');
  const capability = action.startsWith('capability.');
  const targetName = capability ? '能力 ID' : action.startsWith('plugin.') ? 'Plugin install_id' : 'Automation task_id';
  const submit = () => {
    const id = identifier.trim();
    if (!tenantId || !id) return;
    const target = capability
      ? { tenant_id: tenantId, kind, item_id: id }
      : action.startsWith('plugin.')
        ? { tenant_id: tenantId, install_id: id }
        : { tenant_id: tenantId, task_id: id };
    onMutate({
      action,
      target,
      title: '受控应用操作',
      targetLabel: `${targetName}: ${id}`,
      success: action === 'automation.run' ? 'Automation 已受理调度。' : '受控操作已完成。',
      danger: action.endsWith('.disable'),
    });
  };
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <Alert type="info" showIcon message="旧 catalog/plugin/automation 写端点已 fail-closed；这里只提交 re-auth、一次性审批和目标绑定 mutation。" />
    <Space wrap>
      <Select value={action} onChange={setAction} style={{ width: 190 }} options={[
        { value: 'capability.enable', label: '启用能力' },
        { value: 'capability.disable', label: '停用能力' },
        { value: 'plugin.enable', label: '启用 Plugin' },
        { value: 'plugin.disable', label: '停用 Plugin' },
        { value: 'automation.run', label: '运行 Automation' },
      ]} />
      {capability && <Select value={kind} onChange={setKind} style={{ width: 110 }} options={['skill', 'agent', 'mcp'].map((value) => ({ value, label: value }))} />}
      <Input value={identifier} onChange={(event) => setIdentifier(event.target.value)} placeholder={targetName} maxLength={256} style={{ width: 280 }} />
      <Button type="primary" disabled={!manageable || !tenantId || !identifier.trim()} onClick={submit}>准备受控操作</Button>
    </Space>
    <Alert type="warning" showIcon message="Automation receipt 仅表示 accepted/scheduled，不表示执行完成；Gateway 未验证，production_ready=false。" />
  </Space>;
}

function CommunicationSection({ topology, delegations, revoked, loading, manageable, onRevoke }: { topology: JsonRecord[]; delegations: JsonRecord[]; revoked: Set<string>; loading: boolean; manageable: boolean; onRevoke: (item: JsonRecord) => void }) {
  const topologyColumns: TableProps<JsonRecord>['columns'] = [
    { title: '源 Agent', dataIndex: 'source_agent_id', render: text },
    { title: '目标 Agent', dataIndex: 'target_agent_id', render: text },
    { title: '允许消息类型', dataIndex: 'allowed_kinds', render: (value) => list(value).map((item) => <Tag key={item} color="blue">{item}</Tag>) },
  ];
  const delegationColumns: TableProps<JsonRecord>['columns'] = [
    { title: '委派 ID', dataIndex: 'delegation_id', render: text },
    { title: '授权方', dataIndex: 'grantor_agent_id', render: text },
    { title: '接收方', dataIndex: 'grantee_agent_id', render: text },
    { title: '能力', dataIndex: 'capabilities', render: (value) => list(value).map((item) => <Tag key={item}>{item}</Tag>) },
    { title: '消息上限', dataIndex: 'max_messages', render: text },
    { title: '到期时间', dataIndex: 'expires_at', render: formatTime },
    { title: '状态', render: (_, item) => statusTag(revoked.has(`${text(item.tenant_id)}:${text(item.delegation_id)}`) ? '已撤销' : '有效') },
    { title: '操作', render: (_, item) => {
      const isRevoked = revoked.has(`${text(item.tenant_id)}:${text(item.delegation_id)}`);
      return <Button size="small" danger disabled={!manageable || isRevoked} onClick={() => onRevoke(item)}>{isRevoked ? '已撤销' : '撤销'}</Button>;
    } },
  ];
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <section><Typography.Title level={5}>允许通信路径</Typography.Title><Table rowKey={(row) => `${text(row.tenant_id)}:${text(row.source_agent_id)}:${text(row.target_agent_id)}`} columns={topologyColumns} dataSource={topology} loading={loading} pagination={{ pageSize: 20, hideOnSinglePage: true }} scroll={{ x: 620 }} /></section>
    <section><Typography.Title level={5}>委派</Typography.Title><Table rowKey={(row) => `${text(row.tenant_id)}:${text(row.delegation_id)}`} columns={delegationColumns} dataSource={delegations} loading={loading} pagination={{ pageSize: 20, hideOnSinglePage: true }} scroll={{ x: 900 }} /></section>
    <Alert type="info" showIcon message="mailbox、lease、ACK 和 replay 状态未包含在 coordination snapshot 中，当前未知。" />
  </Space>;
}

function EvaluationSection() {
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <Alert type="warning" showIcon message="未发现可公开的运行评估报告；测试、配置和脚本不作为当前评估结果。" />
    <div className="sh-operations-evidence">
      {unavailableEvaluationEvidence.map((item) => <Card key={item.key} title={item.label} size="small">
        <Descriptions size="small" column={1} items={[
          { key: 'status', label: '状态', children: statusTag(item.status) },
          { key: 'source', label: '证据来源', children: item.source },
          { key: 'observed', label: '观测时间', children: item.observedAt },
          { key: 'conclusion', label: '结论', children: item.conclusion },
        ]} />
      </Card>)}
    </div>
    <Alert type="info" showIcon message={`缺少独立部署证据时 production_ready=${String(defaultProductionReady)}；不得据此声明 live-model efficacy 或 production readiness。`} />
  </Space>;
}

function PolicySection({ policies, simulation, onSimulate }: { policies: SafeHarnessPolicyResponse | null; simulation: SafeHarnessPolicySimulation | null; onSimulate: (packageId: string, operation: string) => Promise<void> }) {
  if (!policies) return <Alert type="warning" showIcon message="策略数据不可用。" />;
  const packages = policies.packages;
  const columns: TableProps<JsonRecord>['columns'] = [
    { title: '版本', dataIndex: 'id', render: text },
    { title: '状态', dataIndex: 'status', render: (value) => statusTag(text(value)) },
    { title: '受控操作', dataIndex: 'operations', render: (value) => list(value).map((item) => <Tag key={item}>{item}</Tag>) },
    { title: '执行点', dataIndex: 'enforcement', render: (value) => list(value).map((item) => <Tag key={item} color="blue">{item}</Tag>) },
    { title: '操作', render: (_, item) => <Space wrap>{list(item.operations).map((operation) => <Button key={operation} size="small" onClick={() => void onSimulate(text(item.id), operation)}>模拟 {operation}</Button>)}</Space> },
  ];
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <Table rowKey={(row) => text(row.id)} columns={columns} dataSource={packages} pagination={false} scroll={{ x: 900 }} />
    <Alert type="info" showIcon message="当前无候选策略版本，diff unavailable；发布和回滚保持关闭。模拟仅重放已声明的确定性规则，不执行工具或控制面写入。" />
    {simulation && <Card title="影响预览" size="small"><Descriptions size="small" column={{ xs: 1, sm: 2 }} items={[
      { key: 'package', label: '策略版本', children: simulation.package_id },
      { key: 'operation', label: '操作', children: simulation.operation },
      { key: 'decision', label: '决策', children: statusTag(simulation.decision) },
      ...Object.entries(simulation.impact).map(([key, value]) => ({ key, label: key, children: String(value) })),
    ]} /></Card>}
  </Space>;
}

function PolicyRulesCard() {
  const [state, setState] = useState<SafeHarnessPolicyRulesState | null>(null);
  const [draft, setDraft] = useState('[]');
  const [testText, setTestText] = useState('');
  const [testResult, setTestResult] = useState<SafeHarnessPolicyRulesTestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [aiOpen, setAiOpen] = useState(false);
  const [aiDescription, setAiDescription] = useState('');
  const [aiSamples, setAiSamples] = useState('');
  const [aiBusy, setAiBusy] = useState(false);
  const [aiResult, setAiResult] = useState<SafeHarnessPolicyRulesDraftResult | null>(null);

  const runAiDraft = async () => {
    const description = aiDescription.trim();
    if (!description) {
      message.warning('请先描述要拦截的内容。');
      return;
    }
    const sample_texts = aiSamples.split('\n').map((line) => line.trim()).filter(Boolean).slice(0, 5);
    setAiBusy(true);
    try {
      const result = await safeharnessApi.draftPolicyRules({ description, sample_texts });
      setAiResult(result);
      message.success(`草稿已生成（${result.draft.length} 条，模型 ${result.model}）`);
    } catch (error) {
      message.error(errorText(error));
    } finally {
      setAiBusy(false);
    }
  };

  const applyAiDraft = () => {
    if (!aiResult || aiResult.draft.length === 0) return;
    setDraft(JSON.stringify(aiResult.draft, null, 2));
    setAiOpen(false);
    message.success('草稿已填入编辑器；请检查后手动保存才会生效。');
  };

  const load = useCallback(async () => {
    try {
      const next = await safeharnessApi.getPolicyRules();
      setState(next);
      setDraft(JSON.stringify(next.rules ?? [], null, 2));
    } catch (error) {
      message.error(errorText(error));
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const save = async (enabled: boolean) => {
    let rules: SafeHarnessPolicyRule[];
    try {
      rules = JSON.parse(draft) as SafeHarnessPolicyRule[];
    } catch {
      message.error('规则 JSON 无法解析；请检查格式（规则对象数组）。');
      return;
    }
    setBusy(true);
    try {
      const next = await safeharnessApi.putPolicyRules({ enabled, rules });
      setState(next);
      setDraft(JSON.stringify(next.rules ?? [], null, 2));
      message.success(enabled ? `已启用并热生效（版本 ${next.version}）` : `已保存为停用状态（版本 ${next.version}）`);
    } catch (error) {
      const payload = (error as { payload?: { data?: { errors?: string[] } } }).payload;
      const errors = payload?.data?.errors;
      message.error(errors?.length ? errors.join('；') : errorText(error));
    } finally {
      setBusy(false);
    }
  };

  const runTest = async () => {
    if (!testText.trim()) return;
    try {
      setTestResult(await safeharnessApi.testPolicyRules(testText));
    } catch (error) {
      message.error(errorText(error));
    }
  };

  const rollback = async (version: number) => {
    setBusy(true);
    try {
      const next = await safeharnessApi.rollbackPolicyRules(version);
      setState(next);
      setDraft(JSON.stringify(next.rules ?? [], null, 2));
      message.success(`已回滚版本 ${version}（生成新版本 ${next.version}）`);
    } catch (error) {
      message.error(errorText(error));
    } finally {
      setBusy(false);
    }
  };

  const columns: TableProps<SafeHarnessPolicyRule>['columns'] = [
    { title: '名称', dataIndex: 'name', render: text },
    { title: '级别', dataIndex: 'severity', render: (value) => <Tag color={text(value) === 'critical' || text(value) === 'high' ? 'red' : 'blue'}>{text(value)}</Tag> },
    { title: '类别', dataIndex: 'category', render: text },
    { title: '模式', dataIndex: 'pattern', render: (value) => <Typography.Text code>{text(value)}</Typography.Text> },
    { title: '说明', dataIndex: 'reason', render: text },
  ];

  return <Card
    title="自定义注入规则（补充层）"
    size="small"
    extra={<Space>
      <span>启用</span>
      <Switch checked={state?.enabled === true} loading={busy} onChange={(checked) => void save(checked)} />
      <Button size="small" onClick={() => { setAiOpen(true); setAiResult(null); }}>AI 起草</Button>
      <Button size="small" loading={busy} onClick={() => void save(state?.enabled === true)}>保存</Button>
    </Space>}
  >
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Table
        rowKey="name"
        columns={columns}
        dataSource={state?.rules ?? []}
        pagination={false}
        locale={{ emptyText: <Empty description="暂无自定义规则（内置默认防线始终生效）" /> }}
      />
      <Input.TextArea
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        placeholder='[{"name":"block_demo","pattern":"demo\\.evil","severity":"high","reason":"演示规则"}]'
        autoSize={{ minRows: 4, maxRows: 12 }}
      />
      <Space wrap>
        <Input
          value={testText}
          onChange={(event) => setTestText(event.target.value)}
          placeholder="输入文本测试当前生效规则"
          maxLength={2000}
          style={{ width: 420 }}
          onPressEnter={() => void runTest()}
        />
        <Button onClick={() => void runTest()}>测试</Button>
        {state && state.history.length > 0 && <Select
          placeholder="回滚到历史版本"
          style={{ width: 200 }}
          value={null}
          onChange={(version) => { if (version) void rollback(version); }}
          options={state.history.map((item) => ({ value: item.version, label: `版本 ${item.version}（${item.rules.length} 条，${item.saved_at}）` }))}
        />}
      </Space>
      {testResult && <Descriptions size="small" column={{ xs: 1, sm: 2 }} items={[
        { key: 'hit', label: '命中', children: statusTag(testResult.hit ? 'DENY' : 'ALLOW') },
        { key: 'rule', label: '命中规则', children: testResult.matched_rule ? `${testResult.matched_rule.name}（${testResult.matched_rule.reason || '无说明'}）` : '内置默认防线' },
        { key: 'count', label: '生效模式数', children: testResult.rule_count },
      ]} />}
      <Alert type="info" showIcon message={`补充层只增不减：内置默认防线（${testResult?.rule_count ? `${testResult.rule_count} 条模式` : '含默认 20 条模式'}）始终生效；此处规则只支持 deny。启用后对本进程立即生效，无需重启；后端重启后打开本页会自动重新同步。`} />
      <Modal
        title="AI 起草规则（草稿不自动生效）"
        open={aiOpen}
        onCancel={() => setAiOpen(false)}
        footer={null}
        width={640}
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Input.TextArea
            value={aiDescription}
            onChange={(event) => setAiDescription(event.target.value)}
            placeholder="描述要拦截的内容，例如：阻止诱导模型忽略安全规则并泄露系统提示词的输入"
            autoSize={{ minRows: 3, maxRows: 6 }}
            maxLength={2000}
          />
          <Input.TextArea
            value={aiSamples}
            onChange={(event) => setAiSamples(event.target.value)}
            placeholder={'可选：应被命中的示例文本，每行一条（最多 5 条）'}
            autoSize={{ minRows: 2, maxRows: 4 }}
          />
          <Space>
            <Button type="primary" loading={aiBusy} onClick={() => void runAiDraft()}>生成草稿</Button>
            {aiResult && aiResult.draft.length > 0 && (
              <Button onClick={applyAiDraft} disabled={aiResult.validation_errors.length > 0}>
                填入编辑器
              </Button>
            )}
          </Space>
          {aiResult && (
            <>
              {aiResult.validation_errors.length > 0 && (
                <Alert type="error" showIcon message="草稿未通过校验（不会套用）"
                  description={<ul style={{ margin: 0, paddingLeft: 18 }}>{aiResult.validation_errors.map((e, i) => <li key={i}>{e}</li>)}</ul>} />
              )}
              {aiResult.sample_results.length > 0 && (
                <Table
                  size="small"
                  rowKey="text"
                  columns={[
                    { title: '样本', dataIndex: 'text', render: text },
                    { title: '命中', dataIndex: 'hit', width: 80, render: (v: boolean) => statusTag(v ? 'DENY' : 'ALLOW') },
                    { title: '命中规则', dataIndex: 'matched_rule', render: (v: string | null) => v || '未命中' },
                  ]}
                  dataSource={aiResult.sample_results}
                  pagination={false}
                />
              )}
              <Input.TextArea
                value={JSON.stringify(aiResult.draft, null, 2)}
                readOnly
                autoSize={{ minRows: 4, maxRows: 12 }}
              />
              <Alert type="warning" showIcon message="草稿仅供参考：请人工核对正则与理由后，点“填入编辑器”再手动保存才会热生效。" />
            </>
          )}
        </Space>
      </Modal>
    </Space>
  </Card>;
}

function AuditSection({ audit, loading, source, action, setSource, setAction, onSearch }: { audit: SafeHarnessAuditResponse | null; loading: boolean; source?: 'agent' | 'gateway'; action: string; setSource: (value: 'agent' | 'gateway' | undefined) => void; setAction: (value: string) => void; onSearch: () => void }) {
  return <>
    <div className="sh-operations-filters"><Space wrap><Select allowClear placeholder="来源" value={source} onChange={setSource} options={[{ value: 'agent', label: 'Agent' }, { value: 'gateway', label: 'Gateway' }]} /><Input placeholder="动作" value={action} onChange={(event) => setAction(event.target.value)} onPressEnter={onSearch} /><Button type="primary" onClick={onSearch}>查询</Button></Space></div>
    {!audit && !loading && <Alert type="warning" showIcon message="审计源不可用或当前身份无权查看。" />}
    {audit && !audit.available && <Alert type="warning" showIcon message="审计源未配置，记录状态未知。" />}
    <Table rowKey={(row, index) => `${text(row.occurred_at)}:${text(row.action)}:${index}`} columns={auditColumns} dataSource={audit?.records || []} loading={loading} locale={{ emptyText: loading ? <Spin /> : <Empty description="暂无已脱敏审计记录" /> }} pagination={{ pageSize: 20, hideOnSinglePage: true }} scroll={{ x: 760 }}
      expandable={{
        expandedRowRender: (row) => (
          <Descriptions size="small" column={1} items={Object.entries(row).map(([key, value]) => ({
            key,
            label: key,
            children: <Typography.Text code style={{ wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
              {(typeof value === 'string' ? value : JSON.stringify(value) ?? '').slice(0, 600) || '—'}
            </Typography.Text>,
          }))} />
        ),
      }} />
  </>;
}
