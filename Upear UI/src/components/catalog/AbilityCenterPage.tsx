import { useCallback, useEffect, useState } from 'react';
import { Alert } from 'antd';
import { useCatalogStore, useEditionStore } from '../../stores';
import { t } from '../../i18n';
import { SkillsPage } from './SkillsPage';
import { McpPage } from './McpPage';
import { PluginsPage } from './PluginsPage';

type AbilityTabKey = 'skills' | 'mcp' | 'plugins';

export function AbilityCenterPage() {
  const { panel, panelEntryNonce, setManageQuery } = useCatalogStore();
  const writesEnabled = useEditionStore((state) => state.features.capability_writes === true);
  const [activeTab, setActiveTab] = useState<AbilityTabKey>('skills');
  const [hasDetail, setHasDetail] = useState(false);

  useEffect(() => {
    if (panel !== 'ability_center') return;
    setActiveTab('skills');
    setHasDetail(false);
    setManageQuery('');
  }, [panel, panelEntryNonce, setManageQuery]);

  const switchTab = (nextTab: AbilityTabKey) => {
    setActiveTab(nextTab);
    setHasDetail(false);
    setManageQuery('');
  };

  const handleDetailChange = useCallback((detail: boolean) => {
    setHasDetail(detail);
  }, []);

  return (
    <div className={`jx-abilityCenter${hasDetail ? ' jx-abilityCenter--detail' : ''}`}>
      {!hasDetail && (
        <div className="jx-abilityCenterHeader">
          <div className="jx-abilityCenterHero">
            <div className="jx-abilityCenterTabs" role="tablist" aria-label={t('能力中心分类')}>
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'skills'}
                className={`jx-abilityCenterTab${activeTab === 'skills' ? ' active' : ''}`}
                onClick={() => switchTab('skills')}
              >
                <span className="jx-abilityCenterTabLabel">{t('技能库')}</span>
              </button>
              <span className="jx-abilityCenterDivider" aria-hidden="true" />
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'mcp'}
                className={`jx-abilityCenterTab${activeTab === 'mcp' ? ' active' : ''}`}
                onClick={() => switchTab('mcp')}
              >
                <span className="jx-abilityCenterTabLabel">{t('MCP工具库')}</span>
              </button>
              <span className="jx-abilityCenterDivider" aria-hidden="true" />
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'plugins'}
                className={`jx-abilityCenterTab${activeTab === 'plugins' ? ' active' : ''}`}
                onClick={() => switchTab('plugins')}
              >
                <span className="jx-abilityCenterTabLabel">{t('插件')}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="jx-abilityCenterBody">
        {!writesEnabled && !hasDetail && (
          <Alert
            type="warning"
            showIcon
            message={t('当前为只读能力目录')}
            description={t('ToolDescriptor、Adapter coverage、策略包与副作用尚未接入权威安全模型；安装、启用、删除和导入保持禁用。')}
          />
        )}
        <div
          className={`jx-abilityCenterPane${activeTab === 'skills' ? ' active' : ''}`}
          aria-hidden={activeTab !== 'skills'}
        >
          <SkillsPage embedded writesEnabled={writesEnabled} onDetailChange={handleDetailChange} />
        </div>
        <div
          className={`jx-abilityCenterPane${activeTab === 'mcp' ? ' active' : ''}`}
          aria-hidden={activeTab !== 'mcp'}
        >
          <McpPage embedded writesEnabled={writesEnabled} onDetailChange={handleDetailChange} />
        </div>
        <div
          className={`jx-abilityCenterPane${activeTab === 'plugins' ? ' active' : ''}`}
          aria-hidden={activeTab !== 'plugins'}
        >
          <PluginsPage embedded writesEnabled={writesEnabled} onDetailChange={handleDetailChange} />
        </div>
      </div>
    </div>
  );
}
