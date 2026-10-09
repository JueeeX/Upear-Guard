import { useEffect, useMemo, useState } from 'react';
import { Alert } from 'antd';
import { useChatStore, useCatalogStore, useAuthStore, useAutomationStore, useEditionStore } from '../../stores';
import { staggerStyle } from '../../utils/motionTokens';
import { t } from '../../i18n';
import { useAppConfig, usePanelHeader } from '../../hooks/usePageConfig';
import { BUILTIN_APPS, type AppItem } from '../../stores/pageConfigStore';
import { AutomationPanel } from '../lab/AutomationPanel';

const PLAN_MODE_ITEM: AppItem =
  BUILTIN_APPS.find((a) => a.id === 'plan_mode') ?? BUILTIN_APPS[0];
const AUTOMATION_ITEM: AppItem | undefined = BUILTIN_APPS.find((a) => a.id === 'automation');
const BATCH_RUNNER_ITEM: AppItem | undefined = BUILTIN_APPS.find((a) => a.id === 'batch_runner');

const PLACEHOLDER_ITEM: AppItem = {
  id: 'coming_soon',
  enabled: false,
  name: '更多应用',
  icon: '/home/random-icons/Frame 460.svg',
  description: '基于 AI 能力的场景化应用将陆续开放',
  url: '',
};

function buildExternalUrl(base: string, token?: string | null): string {
  if (!base) return base;
  if (!token) return base;
  const separator = base.includes('?') ? '&' : '?';
  return `${base}${separator}token=${encodeURIComponent(token)}`;
}

export default function AppCenterPanel() {
  const { enterChatMode } = useChatStore();
  const { setPanel } = useCatalogStore();
  const ssoToken = useAuthStore((s) => s.authUser?.sso_token ?? null);
  const allowedApps = useAuthStore((s) => s.authUser?.allowed_apps ?? null);
  const automationSelectedTaskId = useAutomationStore((s) => s.selectedTaskId);
  const executionEnabled = useEditionStore((s) => s.features.application_execution === true);
  const appConfig = useAppConfig();
  const { title, subtitle } = usePanelHeader('app_center', {
    title: '应用中心',
    subtitle: '基于 AI 能力的场景化智能应用',
  });

  // If an automation task is already selected when opening the app center (jumped in from the sidebar), go straight into the automation sub-panel
  const [subPanel, setSubPanel] = useState<string | null>(
    automationSelectedTaskId && executionEnabled ? 'automation' : null,
  );

  useEffect(() => {
    if (automationSelectedTaskId && executionEnabled) setSubPanel('automation');
  }, [automationSelectedTaskId, executionEnabled]);

  const items = useMemo<AppItem[]>(() => {
    const allowedSet = Array.isArray(allowedApps) ? new Set(allowedApps) : null;
    const isAllowed = (id: string) => allowedSet === null || allowedSet.has(id);

    const result: AppItem[] = [];
    if (isAllowed(PLAN_MODE_ITEM.id)) result.push(PLAN_MODE_ITEM);
    if (AUTOMATION_ITEM && isAllowed(AUTOMATION_ITEM.id)) result.push(AUTOMATION_ITEM);
    if (BATCH_RUNNER_ITEM && isAllowed(BATCH_RUNNER_ITEM.id)) result.push(BATCH_RUNNER_ITEM);

    for (const app of appConfig.apps) {
      if (!app.enabled) continue;
      if (!isAllowed(app.id)) continue;
      result.push(app);
    }

    if (result.length === 0) result.push(PLACEHOLDER_ITEM);
    return result;
  }, [appConfig.apps, allowedApps]);

  const openExternal = (url: string) => {
    if (!url) return;
    window.open(buildExternalUrl(url, ssoToken), '_blank', 'noopener,noreferrer');
  };

  const handleClick = (app: AppItem) => {
    if (!app.enabled || !executionEnabled) return;
    if (app.id === 'plan_mode') {
      enterChatMode('plan');
      setPanel('chat');
      return;
    }
    if (app.id === 'automation') {
      setSubPanel('automation');
      return;
    }
    if (app.id === 'batch_runner') {
      enterChatMode('batch');
      setPanel('chat');
      return;
    }
    openExternal(app.url);
  };

  if (subPanel === 'automation' && executionEnabled) {
    return <AutomationPanel onBack={() => setSubPanel(null)} />;
  }

  return (
    <div className="jx-agentPage">
      <div className="jx-agentPage-header">
        <div>
          <div className="jx-agentPage-title">{title}</div>
          {subtitle ? <div className="jx-agentPage-subtitle">{subtitle}</div> : null}
        </div>
      </div>

      {!executionEnabled && (
        <Alert
          type="warning"
          showIcon
          message={t('应用执行尚未接入受保护链路')}
          description={t('Plan、批量、自动化和外部应用入口保持只读；策略、审批、Gateway 与执行回执接入前不会启动运行。')}
        />
      )}

      <div
        className="jx-agentPage-grid jx-anim-stagger"
        style={{ '--stagger-step': '30ms' } as React.CSSProperties}
      >
        {items.map((app, idx) => {
          const runnable = app.enabled && executionEnabled;
          return <div
            key={app.id}
            className={`jx-agentCard jx-card-lift${!runnable ? ' jx-agentCard--disabled' : ''}`}
            style={staggerStyle(idx)}
            onClick={() => handleClick(app)}
            role={runnable ? 'button' : undefined}
            tabIndex={runnable ? 0 : undefined}
          >
            <div className="jx-agentCard-body">
              <div className="jx-agentCard-head">
                {app.icon ? (
                  <img
                    src={app.icon}
                    alt=""
                    width={28}
                    height={28}
                    style={{ borderRadius: '50%', objectFit: 'cover', display: 'block' }}
                  />
                ) : (
                  <div
                    style={{
                      width: 28,
                      height: 28,
                      borderRadius: '50%',
                      background: '#E3E6EA',
                    }}
                  />
                )}
                <div className="jx-agentCard-nameRow">
                  <span className="jx-agentCard-name">{t(app.name)}</span>
                  <span className={`jx-agentCard-badge${runnable ? ' jx-agentCard-badge--enabled' : ''}`}>
                    {runnable ? t('可用') : app.enabled ? t('未接入保护链路') : t('即将上线')}
                  </span>
                </div>
              </div>
              <div className="jx-agentCard-desc">{t(app.description)}</div>
            </div>
          </div>;
        })}
      </div>
    </div>
  );
}
