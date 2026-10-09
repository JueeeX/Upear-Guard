import type {
  FSMAgentCard,
  FSMCapability,
  FSMPlanV1,
  FSMRuntime,
  FSMState,
  FSMTransition,
} from '../../types';

export type FSMGraphStatus =
  | 'pending'
  | 'running'
  | 'success'
  | 'failed'
  | 'awaiting_approval'
  | 'manual_review';

export interface FSMGraphNode {
  id: string;
  number: number;
  state: FSMState;
  title: string;
  agentName?: string;
  capability?: FSMCapability;
  status: FSMGraphStatus;
  shape: 'round-rectangle' | 'diamond' | 'ellipse';
  isInitial: boolean;
  isTerminal: boolean;
  resultSummary?: string;
  errorClass?: string;
}

export interface FSMGraphEdge {
  id: string;
  source: string;
  target: string;
  condition: string;
  abnormal: boolean;
}

export interface FSMGraphModel {
  nodes: FSMGraphNode[];
  edges: FSMGraphEdge[];
  initialStateId: string;
}

export function fsmNodeLabel(node: Pick<FSMGraphNode, 'number' | 'title' | 'agentName' | 'state'>): string {
  const subtitle = node.state.kind === 'agent'
    ? `智能体：${node.agentName || node.state.agent_id || '未指定智能体'}`
    : node.state.kind === 'approval' ? '审批' : '终态';
  return `${node.number}. ${node.title}\n${subtitle}`;
}

const ABNORMAL_CONDITIONS = new Set([
  'failure',
  'failed',
  'timeout',
  'error',
  'rejected',
  'manual_review',
]);

export function fsmStateStatus(state: FSMState, runtime?: FSMRuntime): FSMGraphStatus {
  if (runtime?.current_state_id === state.state_id) {
    if (runtime.status === 'awaiting_approval' && state.kind === 'approval') return 'awaiting_approval';
    if (runtime.status === 'manual_review' && state.kind === 'terminal') return 'manual_review';
    if (runtime.status === 'failed') return 'failed';
    if (state.kind !== 'terminal') return 'running';
  }
  if (runtime?.completed_state_ids?.includes(state.state_id)) {
    const outcome = runtime.state_outcomes?.[state.state_id];
    return outcome && ABNORMAL_CONDITIONS.has(outcome) ? 'failed' : 'success';
  }
  if (state.kind === 'terminal' && runtime?.status === 'completed' && state.state_id === 'complete') {
    return 'success';
  }
  return 'pending';
}

export function isAbnormalTransition(condition: string): boolean {
  const normalized = condition.trim().toLowerCase();
  return ABNORMAL_CONDITIONS.has(normalized) || normalized.includes('timeout') || normalized.includes('failure');
}

function resultSummary(stateId: string, runtime?: FSMRuntime): string | undefined {
  const output = runtime?.outputs?.[stateId];
  const summary = output && typeof output.summary === 'string' ? output.summary.trim() : '';
  return summary || runtime?.state_outcomes?.[stateId] || undefined;
}

function errorClass(stateId: string, runtime?: FSMRuntime): string | undefined {
  const output = runtime?.outputs?.[stateId];
  return output && typeof output.error_class === 'string' ? output.error_class : undefined;
}

function findAgent(agentId: string | undefined, registry?: FSMAgentCard[]): FSMAgentCard | undefined {
  return agentId ? registry?.find((agent) => agent.agent_id === agentId) : undefined;
}

export function buildFSMGraphModel(
  fsm: FSMPlanV1,
  runtime?: FSMRuntime,
  registry?: FSMAgentCard[],
  agentNameMap?: Record<string, string>,
): FSMGraphModel {
  const nodes = fsm.states.map((state, index) => {
    const agent = findAgent(state.agent_id, registry);
    return {
      id: state.state_id,
      number: index + 1,
      state,
      title: state.title || state.state_id,
      agentName: agent?.name || (state.agent_id ? agentNameMap?.[state.agent_id] || state.agent_id : undefined),
      capability: agent?.capabilities.find((item) => item.capability_id === state.capability_id),
      status: fsmStateStatus(state, runtime),
      shape: state.kind === 'approval' ? 'diamond' : state.kind === 'terminal' ? 'ellipse' : 'round-rectangle',
      isInitial: state.state_id === fsm.initial_state,
      isTerminal: fsm.terminal_states.includes(state.state_id),
      resultSummary: resultSummary(state.state_id, runtime),
      errorClass: errorClass(state.state_id, runtime),
    } satisfies FSMGraphNode;
  });
  const edges = fsm.transitions.map((transition: FSMTransition, index) => ({
    id: `transition_${index}_${transition.from_state}_${transition.to_state}`,
    source: transition.from_state,
    target: transition.to_state,
    condition: transition.condition,
    abnormal: isAbnormalTransition(transition.condition),
  } satisfies FSMGraphEdge));
  return { nodes, edges, initialStateId: fsm.initial_state };
}
