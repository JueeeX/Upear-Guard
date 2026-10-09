import { useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Card, Descriptions, Empty, Input, Select, Space, Table, Tag, Typography,
  message,
} from 'antd';
import { DownloadOutlined, PlayCircleOutlined, ReloadOutlined, SaveOutlined } from '@ant-design/icons';
import { safeharnessApi, type ConfigDraft, type SafeHarnessTestRun, type SafeHarnessTestScenario } from '../../safeharnessApi';
import type { UserAgentItem } from '../../stores/agentStore';

type JsonRecord = Record<string, unknown>;

function readJson(value: string): JsonRecord {
  const parsed: unknown = JSON.parse(value);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('必须是 JSON 对象');
  return parsed as JsonRecord;
}

function downloadJson(name: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function ControlCenterSection({ agents }: { agents: UserAgentItem[] }) {
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <TestCenterSection />
    <ConfigCenterSection agents={agents} />
  </Space>;
}

function TestCenterSection() {
  const [scenarios, setScenarios] = useState<SafeHarnessTestScenario[]>([]);
  const [scenarioId, setScenarioId] = useState('all');
  const [running, setRunning] = useState(false);
  const [run, setRun] = useState<SafeHarnessTestRun | null>(null);
  const [events, setEvents] = useState<string[]>([]);

  useEffect(() => {
    const controller = new AbortController();
    void safeharnessApi.getTestScenarios(controller.signal)
      .then((value) => setScenarios(value.scenarios || []))
      .catch(() => setScenarios([]));
    return () => controller.abort();
  }, []);

  const execute = async () => {
    setRunning(true);
    setEvents([]);
    try {
      const result = await safeharnessApi.createTestRun(scenarioId);
      setRun(result);
    } catch (error) {
      message.error(error instanceof Error ? error.message : '测试执行失败');
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    if (!run) return;
    const source = new EventSource(safeharnessApi.getTestEventsUrl(run.run_id));
    const onStage = (event: Event) => setEvents((current) => [...current, event.type]);
    source.addEventListener('test_started', onStage);
    source.addEventListener('test_finished', onStage);
    source.onerror = () => source.close();
    return () => source.close();
  }, [run]);

  const scenarioRows = useMemo(() => run?.observed || [], [run]);
  return <Card title="测试中心" extra={<Space>
    <Select value={scenarioId} onChange={setScenarioId} style={{ width: 240 }} options={[
      { value: 'all', label: '全部确定性场景' },
      ...scenarios.map((item) => ({ value: item.scenario_id, label: `${item.name} (${item.scenario_id})` })),
    ]} />
    <Button type="primary" icon={<PlayCircleOutlined />} loading={running} onClick={() => void execute()}>执行测试</Button>
    {run && <Button icon={<DownloadOutlined />} onClick={() => downloadJson(`${run.run_id}.json`, run)}>导出脱敏结果</Button>}
  </Space>}>
    <Typography.Paragraph type="secondary">测试由后端确定性适配器执行。结果只证明本地 SafeHarness 行为，production_ready 始终为 false。</Typography.Paragraph>
    {!scenarios.length && <Alert type="warning" showIcon message="测试场景目录不可用；请确认后端已启动。" />}
    {run && <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Descriptions size="small" column={{ xs: 1, sm: 3 }} items={[
        { key: 'run', label: '运行 ID', children: run.run_id },
        { key: 'status', label: '结果', children: <Tag color={run.status === 'pass' ? 'success' : 'error'}>{run.status.toUpperCase()}</Tag> },
        { key: 'reason', label: 'reason_code', children: run.reason_code },
      ]} />
      <Space wrap>{events.map((event) => <Tag key={event}>{event}</Tag>)}</Space>
      <Table
        size="small"
        rowKey={(item, index) => `${String(item.name)}-${index}`}
        pagination={false}
        dataSource={scenarioRows}
        columns={[
          { title: '场景', dataIndex: 'name' },
          { title: '阻断阶段', dataIndex: 'blocked_stage' },
          { title: '结果', dataIndex: 'passed', render: (value: boolean) => <Tag color={value ? 'success' : 'error'}>{value ? 'PASS' : 'FAIL'}</Tag> },
          { title: '证据', dataIndex: 'evidence', render: (value: unknown) => <Typography.Text code>{JSON.stringify(value)}</Typography.Text> },
        ]}
      />
    </Space>}
    {!run && <Empty description="尚未执行测试" />}
  </Card>;
}

function ConfigCenterSection({ agents }: { agents: UserAgentItem[] }) {
  const [agentId, setAgentId] = useState<string>();
  const [configText, setConfigText] = useState('{}');
  const [baseVersion, setBaseVersion] = useState('V1.0');
  const [validation, setValidation] = useState<JsonRecord | null>(null);
  const [draft, setDraft] = useState<ConfigDraft | null>(null);
  const [history, setHistory] = useState<Array<Record<string, unknown>>>([]);
  const selectedAgent = agents.find((item) => item.agent_id === agentId);

  useEffect(() => {
    if (!agentId && agents[0]) setAgentId(agents[0].agent_id);
  }, [agentId, agents]);

  useEffect(() => {
    if (!selectedAgent) return;
    const extra = selectedAgent.extra_config || {};
    setBaseVersion(selectedAgent.version || String(extra.version || 'V1.0'));
    setConfigText(JSON.stringify({ agent_card: extra.agent_card || null, planning: extra.planning || {} }, null, 2));
    setValidation(null);
    setDraft(null);
  }, [selectedAgent]);

  const reloadHistory = async () => {
    try { setHistory((await safeharnessApi.getConfigHistory()).versions || []); }
    catch (error) { message.error(error instanceof Error ? error.message : '加载配置历史失败'); }
  };

  useEffect(() => { void reloadHistory(); }, []);

  const payload = () => readJson(configText);
  const validate = async () => {
    if (!agentId) return;
    try {
      const result = await safeharnessApi.validateConfig(agentId, payload());
      setValidation(result as JsonRecord);
      message.success(result.valid === true ? '配置校验通过' : '配置校验失败');
    } catch (error) { message.error(error instanceof Error ? error.message : '配置校验失败'); }
  };
  const saveDraft = async () => {
    if (!agentId) return;
    try {
      const result = await safeharnessApi.createConfigDraft(agentId, baseVersion, payload());
      setDraft(result);
      message.success('草稿已创建，已生成 Diff');
    } catch (error) { message.error(error instanceof Error ? error.message : '创建草稿失败'); }
  };
  const act = async (action: 'submit' | 'approve' | 'publish') => {
    if (!draft) return;
    try {
      const next = action === 'submit'
        ? await safeharnessApi.submitConfigDraft(draft.draft_id)
        : action === 'approve'
          ? await safeharnessApi.decideConfigDraft(draft.draft_id, 'approve')
          : await safeharnessApi.publishConfigDraft(draft.draft_id).then(() => ({ ...draft, status: 'published' }));
      setDraft(next);
      await reloadHistory();
      message.success(action === 'submit' ? '已提交审批' : action === 'approve' ? '已批准' : '已发布');
    } catch (error) { message.error(error instanceof Error ? error.message : '配置操作失败'); }
  };
  const rollback = async (versionId: unknown) => {
    if (typeof versionId !== 'string') return;
    try { await safeharnessApi.rollbackConfig(versionId); await reloadHistory(); message.success('已生成回滚版本'); }
    catch (error) { message.error(error instanceof Error ? error.message : '回滚失败'); }
  };

  return <Card title="配置中心" extra={<Space>
    <Select value={agentId} onChange={setAgentId} placeholder="选择 Agent" style={{ width: 260 }} options={agents.map((agent) => ({ value: agent.agent_id, label: `${agent.name} (${agent.agent_id})` }))} />
    <Button icon={<ReloadOutlined />} onClick={() => { void reloadHistory(); }}>刷新历史</Button>
  </Space>}>
    <Typography.Paragraph type="secondary">当前编辑范围：用户 Agent 的 AgentCard 和 planning。所有输入由后端重新校验；密钥、内部 endpoint、handler 和系统提示词不可进入配置。</Typography.Paragraph>
    {!selectedAgent && <Empty description="没有可编辑的用户 Agent" />}
    {selectedAgent && <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Input.TextArea value={configText} onChange={(event) => setConfigText(event.target.value)} autoSize={{ minRows: 12, maxRows: 28 }} spellCheck={false} />
      <Space wrap>
        <Button onClick={() => void validate()}>后端校验</Button>
        <Button type="primary" icon={<SaveOutlined />} onClick={() => void saveDraft()}>创建草稿并生成 Diff</Button>
        {draft?.status === 'draft' && <Button onClick={() => void act('submit')}>提交审批</Button>}
        {draft?.status === 'pending_approval' && <Button onClick={() => void act('approve')}>管理员批准</Button>}
        {draft?.status === 'approved' && <Button type="primary" onClick={() => void act('publish')}>发布</Button>}
      </Space>
      {validation && <Alert type={validation.valid === true ? 'success' : 'error'} showIcon message={`校验：${String(validation.valid === true ? '通过' : '失败')}`} description={<Typography.Text code>{JSON.stringify(validation.validation || validation)}</Typography.Text>} />}
      {draft && <Card size="small" title={`草稿 ${draft.draft_id} · ${draft.status}`}>
        <Table size="small" pagination={false} dataSource={draft.diff || []} rowKey={(item, index) => `${String(item.path)}-${index}`} columns={[
          { title: '路径', dataIndex: 'path' }, { title: '类型', dataIndex: 'kind' },
          { title: '变更', render: (_, item) => <Typography.Text code>{JSON.stringify(item)}</Typography.Text> },
        ]} />
      </Card>}
      <Card size="small" title="版本历史">
        <Table size="small" pagination={{ pageSize: 5 }} dataSource={history.filter((item) => !agentId || item.agent_id === agentId)} rowKey={(item) => String(item.version_id)} columns={[
          { title: '版本', dataIndex: 'version' }, { title: '来源', dataIndex: 'source' }, { title: '审计引用', dataIndex: 'audit_reference' },
          { title: '操作', render: (_, item) => <Button size="small" onClick={() => void rollback(item.version_id)}>回滚为新版本</Button> },
        ]} />
      </Card>
    </Space>}
  </Card>;
}
