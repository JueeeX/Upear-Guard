import { Alert, Tag } from 'antd';
import { t } from '../../i18n';
import type { CapabilitySecurityMetadata } from '../../types';

export function CapabilitySecuritySummary({
  security,
}: {
  security?: CapabilitySecurityMetadata;
}) {
  const source = security?.source.type || 'unknown';
  const mapped = security?.tool_descriptor.status === 'mapped';
  const adapterCovered = security?.adapter_coverage.status === 'mapped';
  const policyMapped = security?.policy_package.status === 'mapped';
  const executionReady = security?.execution.status === 'ready';

  return (
    <Alert
      type={executionReady ? 'success' : 'warning'}
      showIcon
      message={t('SafeHarness 安全映射')}
      description={(
        <div>
          <Tag>{t('来源：{source}', { source })}</Tag>
          <Tag color={mapped ? 'green' : 'default'}>
            {mapped ? t('ToolDescriptor 已映射') : t('ToolDescriptor 未映射')}
          </Tag>
          <Tag color={adapterCovered ? 'green' : 'default'}>
            {adapterCovered ? t('Adapter coverage 已验证') : t('Adapter coverage 未知')}
          </Tag>
          <Tag color={policyMapped ? 'green' : 'default'}>
            {policyMapped ? t('策略包已绑定') : t('策略包未绑定')}
          </Tag>
          <Tag color={executionReady ? 'green' : 'orange'}>
            {executionReady ? t('执行已就绪') : t('执行已阻断')}
          </Tag>
        </div>
      )}
    />
  );
}
