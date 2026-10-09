import { useCallback, useEffect, useState } from 'react';
import { Button, Card, Col, Drawer, Empty, Input, Modal, Row, Select, Space, Statistic, Table, Tag, Typography, message } from 'antd';
import type { TableProps } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { listReviewQueue, resolveReviewItem, type ReviewQueueItem, type ReviewQueueResponse, type ReviewResolvedItem } from '../../api';
import { formatTime } from '../../utils/date';
import { t } from '../../i18n';

const text = (value: unknown) => (value === null || value === undefined || value === '' ? '-' : String(value));

function durationLabel(ms: number | null | undefined) {
  if (ms === null || ms === undefined) return '-';
  const minutes = Math.floor(ms / 60000);
  if (minutes < 60) return `${minutes} 分钟`;
  const hours = Math.floor(minutes / 60);
  return `${hours} 小时 ${minutes % 60} 分`;
}

function statusTag(status: string) {
  const color = status === 'completed' ? 'green' : status === 'failed' ? 'red' : status === 'manual_review' ? 'orange' : 'blue';
  return <Tag color={color}>{text(status)}</Tag>;
}

/** 人工复核工作台：manual_review 计划的证据包队列与结案操作。 */
export function ReviewWorkbenchSection() {
  const [queue, setQueue] = useState<ReviewQueueResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<ReviewQueueItem | null>(null);
  const [resolving, setResolving] = useState<ReviewQueueItem | null>(null);
  const [resolution, setResolution] = useState<'close_acknowledged' | 'close_rejected'>('close_acknowledged');
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      setQueue(await listReviewQueue());
    } catch {
      if (!signal?.aborted) setQueue(null);
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const submitResolution = async () => {
    if (!resolving) return;
    setSubmitting(true);
    try {
      await resolveReviewItem(resolving.plan_id, resolution, note.trim());
      message.success(t('复核结论已登记'));
      setResolving(null);
      setNote('');
      await load();
    } catch {
      message.error(t('结案失败，请重试'));
    } finally {
      setSubmitting(false);
    }
  };

  const columns: TableProps<ReviewQueueItem>['columns'] = [
    { title: '计划', dataIndex: 'title', render: (value: unknown, row: ReviewQueueItem) => (
      <Space size={4}>
        <Typography.Text strong>{text(value)}</Typography.Text>
        {row.kind === 'supervision' && <Tag color="orange">{t('监督干预')}</Tag>}
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>{text(row.plan_id)}</Typography.Text>
      </Space>
    ) },
    { title: '任务', dataIndex: 'task_input', ellipsis: true, render: (value: unknown) => text(typeof value === 'string' ? value : JSON.stringify(value)) },
    { title: '执行进度', key: 'progress', render: (_: unknown, row: ReviewQueueItem) => `${row.completed_steps ?? '—'}/${row.total_steps ?? '—'}` },
    { title: '等待时长', dataIndex: 'waiting_ms', render: (value: number | null) => (
      <Tag color={value !== null && value > 3600000 ? 'red' : 'default'}>{durationLabel(value)}</Tag>
    ) },
    { title: '进入复核', dataIndex: 'updated_at', render: (value: string | null) => formatTime(value) },
    { title: '操作', key: 'actions', render: (_: unknown, row: ReviewQueueItem) => (
      <Space size={4}>
        <Button size="small" onClick={() => setDetail(row)}>{t('证据包')}</Button>
        <Button size="small" type="primary" onClick={() => setResolving(row)}>{t('结案')}</Button>
      </Space>
    ) },
  ];

  const resolvedColumns: TableProps<ReviewResolvedItem>['columns'] = [
    { title: '计划', dataIndex: 'title', ellipsis: true },
    { title: '结论', dataIndex: 'resolution', render: (value: string | null) => value === 'close_rejected' ? <Tag color="red">{t('违规确认')}</Tag> : <Tag color="green">{t('无违规结案')}</Tag> },
    { title: '复核人', dataIndex: 'reviewer', render: (value: string | null) => text(value) },
    { title: '耗时', dataIndex: 'duration_ms', render: (value: number | null) => durationLabel(value) },
    { title: '结案时间', dataIndex: 'resolved_at', render: (value: string | null) => formatTime(value) },
  ];

  return (
    <Space direction="vertical" size={12} style={{ width: '100%' }}>
      <Row gutter={12}>
        <Col span={6}><Card size="small"><Statistic title={t('待复核')} value={queue?.items.length ?? 0} /></Card></Col>
        <Col span={6}><Card size="small"><Statistic title={t('已结案')} value={queue?.stats.resolved_count ?? 0} /></Card></Col>
        <Col span={6}><Card size="small"><Statistic title={t('平均复核时长')} value={durationLabel(queue?.stats.avg_duration_ms)} /></Card></Col>
        <Col span={6}><Card size="small"><Statistic title={t('最长复核时长')} value={durationLabel(queue?.stats.max_duration_ms)} /></Card></Col>
      </Row>

      <Card size="small" title={t('人工复核队列')} extra={<Button icon={<ReloadOutlined />} size="small" onClick={() => void load()}>{t('刷新')}</Button>}>
        <Table
          size="small"
          rowKey="plan_id"
          loading={loading}
          columns={columns}
          dataSource={queue?.items ?? []}
          locale={{ emptyText: <Empty description={t('暂无待复核计划')} /> }}
          pagination={{ pageSize: 8 }}
        />
      </Card>

      <Card size="small" title={t('复核记录')}>
        <Table
          size="small"
          rowKey="plan_id"
          columns={resolvedColumns}
          dataSource={queue?.resolved ?? []}
          locale={{ emptyText: <Empty description={t('暂无复核记录')} /> }}
          pagination={{ pageSize: 5 }}
        />
      </Card>

      <Drawer title={t('复核证据包')} width={520} open={detail !== null} onClose={() => setDetail(null)}>
        {detail && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Card size="small" title={text(detail.title)}>
              <p><Typography.Text type="secondary">{t('任务')}：</Typography.Text>{text(typeof detail.task_input === 'string' ? detail.task_input : JSON.stringify(detail.task_input))}</p>
              <p><Typography.Text type="secondary">{t('状态')}：</Typography.Text>{statusTag(detail.status)}</p>
              <p><Typography.Text type="secondary">{t('执行结果')}：</Typography.Text>{text(detail.result_summary)}</p>
              <p><Typography.Text type="secondary">{t('进入复核')}：</Typography.Text>{formatTime(detail.updated_at)}（{t('已等待')} {durationLabel(detail.waiting_ms)}）</p>
            </Card>
            <Card size="small" title={t('FSM 运行时')}>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 12 }}>{JSON.stringify(detail.fsm_runtime ?? {}, null, 2)}</pre>
            </Card>
            {detail.kind === 'supervision' && (
              <Card size="small" title={t('监督证据')}>
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 12 }}>{JSON.stringify(detail.evidence ?? {}, null, 2)}</pre>
              </Card>
            )}
            <Card size="small" title={t('执行步骤')}>
              <Table
                size="small"
                rowKey="step_id"
                dataSource={detail.steps ?? []}
                columns={[
                  { title: '步骤', dataIndex: 'title', render: text },
                  { title: '状态', dataIndex: 'status', render: statusTag },
                  { title: '错误', dataIndex: 'error_message', render: text, ellipsis: true },
                ]}
                pagination={false}
              />
            </Card>
            <Button type="primary" onClick={() => { setResolving(detail); setDetail(null); }}>{t('登记复核结论')}</Button>
          </Space>
        )}
      </Drawer>

      <Modal
        title={t('登记复核结论')}
        open={resolving !== null}
        onCancel={() => setResolving(null)}
        onOk={submitResolution}
        confirmLoading={submitting}
        okText={t('提交')}
        cancelText={t('取消')}
      >
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <Select
            style={{ width: '100%' }}
            value={resolution}
            onChange={setResolution}
            options={[
              { value: 'close_acknowledged', label: t('无违规结案（放行归档）') },
              { value: 'close_rejected', label: t('违规确认（关闭计划）') },
            ]}
          />
          <Input.TextArea rows={3} value={note} onChange={(e) => setNote(e.target.value)} placeholder={t('复核备注（可选）')} />
        </Space>
      </Modal>
    </Space>
  );
}
