import { Button, Dropdown } from 'antd';
import type { MenuProps } from 'antd';
import { CheckCircleOutlined, CloseCircleOutlined, DownloadOutlined, InsertRowRightOutlined, SafetyCertificateOutlined, WarningOutlined } from '@ant-design/icons';
import { useEffect, useMemo, useState } from 'react';

import { t } from '../../i18n';
import { useCanvasStore, useChatStore } from '../../stores';
import { IS_SAFEHARNESS_EDITION_BUILD } from '../../edition';
import { ContentErrorBoundary } from '../common';
import { CanvasPanel } from './CanvasPanel';
import { IndustryChainCanvas } from './IndustryChainCanvas';
import { OntologySidebarPanel } from './OntologySidebarPanel';
import { safeharnessApi, type SafeHarnessSecurityReport } from '../../safeharnessApi';
import { buildSecurityLogExport, securityLogToText, summarizeSecurityTurn, type SecurityTurnInput } from './securityContextData';

const scenarioLabels: Record<string, string> = {
  'input-injection': '用户提示注入',
  'nested-tool-result': '嵌套工具结果注入',
  'restored-tool-call': '恢复消息中的恶意工具调用',
  'restored-history': '恢复历史中的恶意内容',
};

const stageLabels: Record<string, string> = {
  input_guard: '输入检查',
  post_tool_guard: '工具结果检查',
  restored_message_guard: '恢复消息检查',
  restored_history_guard: '恢复历史检查',
};

function downloadSecurityLog(currentChatId: string, protectedEnabled: boolean, turns: SecurityTurnInput[], report: SafeHarnessSecurityReport | null, format: 'json' | 'txt'): void {
  const log = buildSecurityLogExport(currentChatId || 'current', protectedEnabled, turns, report);
  const stamp = new Date().toISOString().replace(/[.:]/g, '-');
  const extension = format === 'json' ? 'json' : 'txt';
  const safeChatId = (currentChatId || 'current').replace(/[^A-Za-z0-9._-]/g, '-');
  const content = format === 'json' ? JSON.stringify(log, null, 2) : securityLogToText(log);
  const blob = new Blob([content], { type: format === 'json' ? 'application/json;charset=utf-8' : 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `sumc-security-${safeChatId}-${stamp}.${extension}`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function traceText(summary: ReturnType<typeof summarizeSecurityTurn>, events: SecurityTurnInput['events']): string {
  const blocked = events.find((event) => event.type === 'blocked');
  const policy = events.find((event) => event.type === 'policy_decision');
  const disposition = String(policy?.data.disposition || (summary.status === 'blocked' ? 'DENY' : 'ALLOW')).toUpperCase();
  const reason = String(blocked?.data.reason_code || policy?.data.reason_code || '');
  const lines = [
    summary.status === 'blocked'
      ? `SafeHarness> 已阻断（${reason || 'policy_denied'}）`
      : summary.status === 'error'
        ? 'SafeHarness> 检查失败'
        : 'SafeHarness> 已通过',
  ];
  if (summary.agentChain) lines.push(summary.agentChain);
  if (summary.status === 'blocked') {
    lines.push(`content_received  ${disposition}  ${String(blocked?.data.action || 'INPUT_BLOCKED; MODEL_SKIPPED')}`);
  } else {
    lines.push(`content_received  ${disposition}  ${disposition === 'ALLOW' ? 'CONTENT_ACCEPTED' : 'CONTENT_BLOCKED'}`);
  }
  lines.push(`证据汇总：judge_calls=${summary.judgeCalls}, model_calls=${summary.modelCalls}, tool_calls_proposed=${summary.toolCallsProposed}, tool_calls_started=${summary.toolCallsStarted}`);
  return lines.join('\n');
}

function SecurityPanel() {
  const currentChatId = useChatStore((state) => state.currentChatId);
  const chat = useChatStore((state) => state.store.chats[state.currentChatId]);
  const [report, setReport] = useState<SafeHarnessSecurityReport | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    void safeharnessApi.getSecurityReport(controller.signal).then(setReport).catch(() => setReport(null));
    return () => controller.abort();
  }, []);
  const turns = useMemo<SecurityTurnInput[]>(() => (chat?.messages || [])
    .filter((message) => message.role === 'assistant')
    .map((message) => ({ ts: message.ts, isStreaming: message.isStreaming, events: message.securityTimeline || [] })), [chat?.messages]);
  const protectedEnabled = chat?.safeharnessProtected !== false;
  const exportItems: MenuProps['items'] = [
    { key: 'json', label: '导出 JSON（详细）' },
    { key: 'txt', label: '导出 TXT（可读）' },
  ];
  const onExport: MenuProps['onClick'] = ({ key }) => downloadSecurityLog(currentChatId || 'current', protectedEnabled, turns, report, key === 'json' ? 'json' : 'txt');
  return (
    <aside className="jx-rightSidebar jx-securityContext" aria-label={t('安全能力')}>
      <div className="jx-securityContext-header">
        <SafetyCertificateOutlined />
        <div><strong>{t('安全能力')}</strong><span>本轮运行时判定；不代表生产就绪或真实模型安全效果</span></div>
        <Dropdown menu={{ items: exportItems, onClick: onExport }} trigger={['click']}>
          <Button size="small" icon={<DownloadOutlined />} aria-label="导出安全日志">导出日志</Button>
        </Dropdown>
      </div>
      <section>
        <h3>{t('当前会话')}</h3>
        {!protectedEnabled && <div className="jx-securityContext-status warning"><WarningOutlined />{t('当前发送模式未保护')}</div>}
        {turns.length === 0 && <div className="jx-securityContext-empty">发送消息后显示本轮安全结论。</div>}
        {turns.map((turn, index) => {
          const summary = summarizeSecurityTurn(turn, protectedEnabled);
          const icon = summary.status === 'allowed' || summary.status === 'sanitized'
            ? <CheckCircleOutlined />
            : summary.status === 'checking' || summary.status === 'unevaluated'
              ? <WarningOutlined />
              : <CloseCircleOutlined />;
          const policyVersion = turn.events.find((event) => event.type === 'policy_decision')?.data.policy_version;
          const tone = summary.status === 'allowed' || summary.status === 'sanitized' ? 'safe' : summary.status === 'checking' || summary.status === 'unevaluated' ? 'warning' : 'danger';
          return (
            <article className="jx-securityContext-card" key={`${currentChatId}:${turn.ts ?? index}`}>
              <header className={tone}>{icon}{summary.label}</header>
              <p className="jx-securityContext-reason">{summary.reason}</p>
              <div className="jx-securityContext-stats">
                <span>检查 {summary.checks} 项</span>
                <span>Judge {summary.judgeCalls} 次</span>
                <span>模型 {summary.modelCalls} 次</span>
                <span>工具提议 {summary.toolCallsProposed} 次</span>
                <span>工具启动 {summary.toolCallsStarted} 次</span>
                <span>清洗 {summary.sanitized} 项</span>
                <span>工具 {summary.tools} 次</span>
                <span>审批：{summary.approval}</span>
                <span>拦截 {summary.blocked} 项</span>
                <span>最终：{summary.finalStatus}</span>
              </div>
              {policyVersion && <div className="jx-securityContext-meta">策略版本：{String(policyVersion)}</div>}
              {summary.judgeStatus && <div className="jx-securityContext-meta">Judge：{summary.judgeStatus}{summary.judgeModel ? `（${summary.judgeModel}）` : ''}</div>}
              {(summary.agentChain || summary.status === 'blocked' || summary.status === 'error') && <details className="jx-securityContext-trace">
                <summary>安全轨迹</summary>
                <pre>{traceText(summary, turn.events)}</pre>
              </details>}
              {summary.toolDetails.length > 0 && <div className="jx-securityContext-tools">
                <b>工具调用</b>
                {summary.toolDetails.map((tool) => <span key={tool.name}>{tool.name}：{tool.execution}</span>)}
              </div>}
            </article>
          );
        })}
      </section>
      <section>
        <h3>{t('启动自检')}</h3>
        {!report && <div className="jx-securityContext-empty">{t('本轮自检报告不可用')}</div>}
        {report?.scenarios.map((scenario) => (
          <article className="jx-securityContext-card" key={scenario.name}>
            <header className={scenario.passed ? 'safe' : 'danger'}>
              {scenario.passed ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
              {scenarioLabels[scenario.name] || scenario.name}：{scenario.passed ? 'PASS' : 'FAIL'}
            </header>
            <div className="jx-securityContext-meta">拦截阶段：{stageLabels[scenario.blocked_stage] || scenario.blocked_stage}</div>
          </article>
        ))}
      </section>
    </aside>
  );
}

export function RightSidebarPanel() {
  const activeView = useCanvasStore((state) => state.activeView);
  const artifact = useCanvasStore((state) => state.artifact);
  const ontologyTarget = useCanvasStore((state) => state.ontologyTarget);
  const industryChainTarget = useCanvasStore((state) => state.industryChainTarget);

  if (activeView === 'file' && artifact) return <CanvasPanel />;
  if (activeView === 'industry_chain') {
    return <IndustryChainCanvas key={`${industryChainTarget?.chatId ?? ''}:${industryChainTarget?.toolId ?? ''}`} />;
  }
  if (activeView === 'ontology') {
    return (
      <ContentErrorBoundary
        resetKey={`ontology:${ontologyTarget?.chatId ?? ''}:${ontologyTarget?.messageTs ?? ''}`}
        fallback={(
          <aside className="jx-rightSidebar jx-rightSidebar--ontology" role="alert">
            <div className="jx-rightSidebar-empty">
              <strong>{t('本体校验结果暂时无法显示')}</strong>
              <span>{t('当前会话仍可继续使用，请稍后重新打开结果。')}</span>
            </div>
          </aside>
        )}
      >
        <OntologySidebarPanel />
      </ContentErrorBoundary>
    );
  }
  if (IS_SAFEHARNESS_EDITION_BUILD) return <SecurityPanel />;
  return (
    <aside className="jx-rightSidebar jx-rightSidebar--blank" aria-label={t('右侧面板')}>
      <div className="jx-rightSidebar-body">
        <div className="jx-rightSidebar-empty">
          <InsertRowRightOutlined />
          <strong>{t('暂无可展示内容')}</strong>
          <span>{t('预览文件或运行本体校验后，内容会显示在这里。')}</span>
        </div>
      </div>
    </aside>
  );
}
