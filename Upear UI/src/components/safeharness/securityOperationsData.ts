export function pairSet(value: unknown): Set<string> {
  if (!Array.isArray(value)) return new Set();
  return new Set(value.flatMap((item) => {
    if (Array.isArray(item) && typeof item[0] === 'string' && typeof item[1] === 'string') {
      return [`${item[0]}:${item[1]}`];
    }
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const pair = item as Record<string, unknown>;
      if (typeof pair.tenant_id === 'string' && typeof pair.agent_id === 'string') {
        return [`${pair.tenant_id}:${pair.agent_id}`];
      }
    }
    return [];
  }));
}

export const unavailableEvaluationEvidence = [
  { key: 'deterministic', label: 'Deterministic', status: '未运行', source: '未配置', observedAt: '未知', conclusion: '不可判定' },
  { key: 'live-model', label: 'Live-model', status: '未运行', source: '未配置', observedAt: '未知', conclusion: '不可判定' },
  { key: 'remote-infrastructure', label: 'Remote infrastructure', status: '未运行', source: '未配置', observedAt: '未知', conclusion: '不可判定' },
  { key: 'production-evidence', label: 'Production evidence', status: '未运行', source: '未配置', observedAt: '未知', conclusion: '不可判定' },
] as const;

export const defaultProductionReady = false;

export type AgentCategory = 'operations' | 'general';
export type AgentAvailability = 'active' | 'unavailable';
export type SecurityCoverage = 'runtime-protected' | 'catalog-only';

export type AgentCatalogItem = {
  tenant_id: string;
  agent_id: string;
  name: string;
  category: AgentCategory;
  type: string;
  responsibility: string;
  source: string;
  availability: AgentAvailability;
  security_coverage: SecurityCoverage;
  active: boolean;
  manageable: boolean;
  accepted_capabilities: string[];
  delegable_capabilities: string[];
};

export const demoAgentCatalog: AgentCatalogItem[] = [
  {
    tenant_id: 'fiberhome-demo', agent_id: 'platform-supervisor-agent', name: '平台总控 Supervisor',
    category: 'operations', type: '确定性分发控制器', responsibility: '统一分发运维与通用任务', source: '平台路由层',
    availability: 'active', security_coverage: 'runtime-protected', active: true, manageable: false,
    accepted_capabilities: ['dispatch'], delegable_capabilities: ['operations', 'general'],
  },
  {
    tenant_id: 'fiberhome-demo', agent_id: 'noc-supervisor-agent', name: '运维监督 Agent',
    category: 'operations', type: '运维智能体', responsibility: '接收运维请求、发起受控排障委派', source: 'SafeHarness Communication Gateway',
    availability: 'active', security_coverage: 'runtime-protected', active: true, manageable: true,
    accepted_capabilities: ['alarm.query', 'diagnosis.delegate'], delegable_capabilities: ['alarm.diagnosis'],
  },
  {
    tenant_id: 'fiberhome-demo', agent_id: 'noc-diagnosis-agent', name: '告警诊断 Agent',
    category: 'operations', type: '运维智能体', responsibility: '执行只读告警分析和排障建议', source: 'SafeHarness Communication Gateway',
    availability: 'active', security_coverage: 'runtime-protected', active: true, manageable: true,
    accepted_capabilities: ['alarm.diagnosis'], delegable_capabilities: [],
  },
  {
    tenant_id: 'fiberhome-demo', agent_id: 'config-change-agent', name: '配置变更 Agent',
    category: 'operations', type: '高危运维智能体', responsibility: '受审批约束的配置变更', source: '平台目录',
    availability: 'unavailable', security_coverage: 'catalog-only', active: false, manageable: false,
    accepted_capabilities: ['config.change'], delegable_capabilities: [],
  },
  {
    tenant_id: 'fiberhome-demo', agent_id: 'main_agent', name: '通用对话 Agent',
    category: 'general', type: '通用智能体', responsibility: '通用对话、分析、写作和推理', source: 'SUMC protected chat',
    availability: 'active', security_coverage: 'runtime-protected', active: true, manageable: false,
    accepted_capabilities: ['conversation', 'analysis'], delegable_capabilities: [],
  },
  {
    tenant_id: 'fiberhome-demo', agent_id: 'internet-search-agent', name: '联网 Agent',
    category: 'general', type: '通用智能体', responsibility: '在授权后检索公开网络信息', source: 'SafeHarness internet_search',
    availability: 'active', security_coverage: 'runtime-protected', active: true, manageable: false,
    accepted_capabilities: ['internet:search'], delegable_capabilities: [],
  },
  {
    tenant_id: 'fiberhome-demo', agent_id: 'knowledge-qa-agent', name: '知识问答 Agent',
    category: 'general', type: '通用智能体', responsibility: '基于知识库回答内部问题', source: '平台目录',
    availability: 'unavailable', security_coverage: 'catalog-only', active: false, manageable: false,
    accepted_capabilities: ['knowledge:query'], delegable_capabilities: [],
  },
];
