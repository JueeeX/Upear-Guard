import { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, Card, Col, Empty, Input, InputNumber, Modal, Row, Select, Space, Spin, Switch, Tag, Typography, message,
} from 'antd';
import { ReloadOutlined, RocketOutlined, SaveOutlined } from '@ant-design/icons';
import {
  getExternalAgentCard,
  getExternalAgentMemoryConfig,
  listExternalAgents,
  listModelProviders,
  putExternalAgentCard,
  putExternalAgentMemoryConfig,
  putExternalAgentModelSetting,
  runExternalAgent,
  type ExternalAgentMemoryConfig,
  type ExternalAgentRunResult,
  type ExternalAgentsResponse,
} from '../../api';
import { t } from '../../i18n';

const DEFAULT_OPTION = '__follow_default__';

/** 外部智能体：真实第三方框架接入（smolagents / openai-agents / autogen）。
 * 每个智能体可单独指定模型供应商，也可跟随统一默认（再回退平台主模型）。 */
export function ExternalAgentsSection() {
  const [data, setData] = useState<ExternalAgentsResponse | null>(null);
  const [providers, setProviders] = useState<{ id: string; label: string }[]>([]);
  const [providersLoading, setProvidersLoading] = useState(true);
  const [loading, setLoading] = useState(true);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string>('');
  const [messageText, setMessageText] = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ExternalAgentRunResult | null>(null);
  const [cardDraft, setCardDraft] = useState<{ agentId: string; text: string } | null>(null);
  const [savingCard, setSavingCard] = useState(false);
  const [memoryConfig, setMemoryConfig] = useState<ExternalAgentMemoryConfig | null>(null);
  const [savingMemory, setSavingMemory] = useState(false);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      setData(await listExternalAgents());
    } catch {
      if (!signal?.aborted) setData(null);
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    setProvidersLoading(true);
    listModelProviders()
      .then((rows) => {
        if (controller.signal.aborted) return;
        setProviders(
          rows
            .filter((row) => row.provider_id && row.display_name)
            .map((row) => ({
              id: String(row.provider_id),
              label: `${row.display_name} · ${row.model_name ?? ''}`.trim(),
            })),
        );
      })
      .catch(() => setProviders([]))
      .finally(() => {
        if (!controller.signal.aborted) setProvidersLoading(false);
      });
    getExternalAgentMemoryConfig()
      .then((cfg) => { if (!controller.signal.aborted) setMemoryConfig(cfg); })
      .catch(() => { /* memory config is admin-surface; absence hides the card inputs */ });
    return () => controller.abort();
  }, [load]);

  const settings = data?.model_settings;
  const saveSetting = async (scope: string, providerId: string | null) => {
    setSavingKey(scope);
    try {
      const next = await putExternalAgentModelSetting(scope, providerId);
      setData((prev) => (prev ? { ...prev, model_settings: next } : prev));
      message.success(t('模型设置已保存'));
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('保存失败'));
    } finally {
      setSavingKey(null);
    }
  };

  const saveMemoryConfig = async () => {
    if (!memoryConfig) return;
    setSavingMemory(true);
    try {
      const next = await putExternalAgentMemoryConfig(memoryConfig);
      setMemoryConfig(next);
      message.success(t('记忆配置已保存'));
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('保存失败'));
    } finally {
      setSavingMemory(false);
    }
  };

  const run = async () => {
    if (!selectedId || !messageText.trim()) return;
    setRunning(true);
    setResult(null);
    try {
      setResult(await runExternalAgent(selectedId, messageText.trim()));
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('运行失败'));
    } finally {
      setRunning(false);
    }
  };

  const openCard = async (agentId: string) => {
    try {
      const card = await getExternalAgentCard(agentId);
      setCardDraft({ agentId, text: JSON.stringify(card, null, 2) });
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('读取 AgentCard 失败'));
    }
  };

  const saveCard = async () => {
    if (!cardDraft) return;
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(cardDraft.text) as Record<string, unknown>;
    } catch {
      message.error(t('AgentCard 不是合法 JSON'));
      return;
    }
    setSavingCard(true);
    try {
      const saved = await putExternalAgentCard(cardDraft.agentId, parsed);
      setCardDraft({ agentId: cardDraft.agentId, text: JSON.stringify(saved, null, 2) });
      message.success(t('AgentCard 已保存'));
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('保存失败'));
    } finally {
      setSavingCard(false);
    }
  };

  if (loading && !data) return <Spin />;
  if (!data) return <Alert type="warning" showIcon message={t('外部智能体目录不可用。')} />;

  const modelOptions = [
    { value: DEFAULT_OPTION, label: t('跟随统一默认') },
    ...providers.map((provider) => ({ value: provider.id, label: provider.label })),
  ];
  const selected = data.agents.find((agent) => agent.agent_id === selectedId) || null;

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        message={t('这些智能体来自真实开源框架（各自代码在本平台运行），模型可单独设置或统一指定；所有输入先经 SafeHarness 结构检查。')}
      />
      <Card size="small" title={t('统一默认模型')} extra={
        <Button icon={<ReloadOutlined />} size="small" onClick={() => void load()} loading={loading}>{t('刷新')}</Button>
      }>
        <Space wrap>
          <Select
            style={{ width: 320 }}
            value={settings?.default_provider_id ?? DEFAULT_OPTION}
            loading={providersLoading}
            options={[
              { value: DEFAULT_OPTION, label: t('跟随平台主模型') },
              ...providers.map((provider) => ({ value: provider.id, label: provider.label })),
            ]}
            onChange={(value) => void saveSetting('default', value === DEFAULT_OPTION ? null : value)}
            disabled={savingKey === 'default'}
          />
          <Typography.Text type="secondary">{t('未指定时所有外部智能体使用平台主模型。')}</Typography.Text>
        </Space>
      </Card>

      <Card size="small" title={t('记忆配置')}>
        {memoryConfig ? (
          <Space wrap size={16} align="center">
            <Space size={4}>
              <Typography.Text type="secondary">{t('会话窗口')}</Typography.Text>
              <InputNumber
                size="small" min={0} max={50} value={memoryConfig.history_window}
                onChange={(v) => setMemoryConfig({ ...memoryConfig, history_window: Number(v ?? 12) })}
              />
              <Typography.Text type="secondary">{t('条')}</Typography.Text>
            </Space>
            <Space size={4}>
              <Typography.Text type="secondary">{t('长期记忆')}</Typography.Text>
              <Switch
                size="small" checked={memoryConfig.long_term_enabled}
                onChange={(v) => setMemoryConfig({ ...memoryConfig, long_term_enabled: v })}
              />
            </Space>
            <Space size={4}>
              <Typography.Text type="secondary">{t('注入预算')}</Typography.Text>
              <InputNumber
                size="small" min={0} max={16000} step={200} value={memoryConfig.long_term_max_chars}
                onChange={(v) => setMemoryConfig({ ...memoryConfig, long_term_max_chars: Number(v ?? 2000) })}
              />
              <Typography.Text type="secondary">{t('字符')}</Typography.Text>
            </Space>
            <Space size={4}>
              <Typography.Text type="secondary">{t('检索条数')}</Typography.Text>
              <InputNumber
                size="small" min={1} max={20} value={memoryConfig.long_term_limit}
                onChange={(v) => setMemoryConfig({ ...memoryConfig, long_term_limit: Number(v ?? 5) })}
              />
            </Space>
            <Button size="small" icon={<SaveOutlined />} loading={savingMemory} onClick={() => void saveMemoryConfig()}>
              {t('保存')}
            </Button>
          </Space>
        ) : (
          <Typography.Text type="secondary">{t('记忆配置不可用（需要管理权限）。')}</Typography.Text>
        )}
      </Card>

      <Row gutter={[12, 12]}>
        {data.agents.map((agent) => {
          const override = settings?.agents[agent.agent_id] ?? null;
          return (
            <Col xs={24} md={8} key={agent.agent_id}>
              <Card
                size="small"
                hoverable
                onClick={() => { setSelectedId(agent.agent_id); setResult(null); }}
                style={selectedId === agent.agent_id ? { borderColor: '#1677ff' } : undefined}
                title={
                  <Space wrap size={4}>
                    <span>{agent.name}</span>
                    <Tag color={agent.available ? 'green' : 'red'}>{agent.available ? t('可用') : t('不可用')}</Tag>
                    <Button
                      size="small"
                      type="text"
                      onClick={(event) => { event.stopPropagation(); void openCard(agent.agent_id); }}
                    >
                      {t('AgentCard')}
                    </Button>
                  </Space>
                }
              >
                <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
                  {agent.framework} · {agent.project}
                </Typography.Paragraph>
                <div onClick={(event) => event.stopPropagation()}>
                  <Select
                    style={{ width: '100%' }}
                    size="small"
                    value={override ?? DEFAULT_OPTION}
                    loading={providersLoading || savingKey === agent.agent_id}
                    options={modelOptions}
                    onChange={(value) => void saveSetting(agent.agent_id, value === DEFAULT_OPTION ? null : value)}
                  />
                </div>
              </Card>
            </Col>
          );
        })}
      </Row>

      <Card size="small" title={selected ? `${t('运行')}: ${selected.name}` : t('运行外部智能体')}>
        {!selected && <Empty description={t('先在上方选择一个智能体')} />}
        {selected && (
          <Space direction="vertical" size={8} style={{ width: '100%' }}>
            <Input.TextArea
              value={messageText}
              onChange={(event) => setMessageText(event.target.value)}
              placeholder={t('输入任务消息，例如：用一句话说明告警分级')}
              autoSize={{ minRows: 2, maxRows: 5 }}
              maxLength={10000}
              disabled={running || !selected.available}
            />
            <Space>
              <Button
                type="primary"
                icon={<RocketOutlined />}
                loading={running}
                disabled={!selected.available || !messageText.trim()}
                onClick={() => void run()}
              >
                {t('运行')}
              </Button>
              {!selected.available && <Typography.Text type="warning">{t('该框架未安装，智能体不可用。')}</Typography.Text>}
            </Space>
            {result && (
              <Card size="small" type="inner" title={t('回复')}>
                <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 8 }}>{result.reply}</Typography.Paragraph>
                <Space wrap size={4}>
                  <Tag color="blue">{result.evidence.framework}</Tag>
                  <Tag>{result.evidence.model}</Tag>
                  <Tag color="green">{t('守卫')}: {result.evidence.guard}</Tag>
                  <Tag>{result.evidence.duration_ms} ms</Tag>
                  {result.evidence.model_source && <Tag color="purple">{result.evidence.model_source}</Tag>}
                  {typeof result.evidence.steps === 'number' && <Tag>{t('步数')}: {result.evidence.steps}</Tag>}
                  {result.evidence.memory && (
                    <Tag color="cyan">{t('记忆')}: {result.evidence.memory.window_turns}/{result.evidence.memory.window_configured} · {t('长期')}: {result.evidence.memory.long_term_read}</Tag>
                  )}
                </Space>
                {(result.evidence.tools?.length ?? 0) > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('工具调用（经 Tool Gateway 授权+回执）')}</Typography.Text>
                    {result.evidence.tools!.map((call) => (
                      <div key={call.call_id} style={{ marginTop: 4 }}>
                        <Space wrap size={4}>
                          <Tag color={call.ok ? 'green' : 'red'}>{call.tool}</Tag>
                          <Tag>{call.duration_ms} ms</Tag>
                          {call.receipt && <Tag color="geekblue">回执: {call.receipt}</Tag>}
                          {call.error_code && <Tag color="red">{call.error_code}</Tag>}
                        </Space>
                      </div>
                    ))}
                  </div>
                )}
                {(result.evidence.supervision?.interventions?.length ?? 0) > 0 && (
                  <Alert
                    type="warning" showIcon style={{ marginTop: 8 }}
                    message={t('运行监督已干预')}
                    description={result.evidence.supervision!.interventions.map((iv, idx) => (
                      <div key={idx}>{`${iv.trigger ?? ''} — ${iv.detail ?? ''}`}</div>
                    ))}
                  />
                )}
              </Card>
            )}
          </Space>
        )}
      </Card>
      <Modal
        open={!!cardDraft}
        title={`AgentCard — ${cardDraft?.agentId ?? ''}`}
        width={720}
        okText={t('保存')}
        cancelText={t('取消')}
        confirmLoading={savingCard}
        onOk={() => void saveCard()}
        onCancel={() => setCardDraft(null)}
        maskClosable={false}
      >
        <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 8 }}>
          {t('A2A 标准 AgentCard（camelCase 规范字段；未知字段保留以向前兼容）。')}
        </Typography.Text>
        <Input.TextArea
          value={cardDraft?.text ?? ''}
          onChange={(event) => setCardDraft((prev) => (prev ? { ...prev, text: event.target.value } : prev))}
          autoSize={{ minRows: 14, maxRows: 26 }}
          style={{ fontFamily: 'monospace', fontSize: 12 }}
        />
      </Modal>
    </Space>
  );
}
