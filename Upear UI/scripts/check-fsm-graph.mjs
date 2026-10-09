import assert from 'node:assert/strict';
import { buildFSMGraphModel, fsmNodeLabel, isAbnormalTransition } from '../src/components/chat/fsmGraphModel.ts';

const fsm = {
  schema_version: 'fsm.v1',
  task: {},
  initial_state: 'query',
  states: [
    { state_id: 'query', kind: 'agent', title: '查询', agent_id: 'noc', capability_id: 'alarm.query' },
    { state_id: 'approve', kind: 'approval', title: '审批', approval_for: 'restart' },
    { state_id: 'complete', kind: 'terminal', title: '完成' },
  ],
  transitions: [
    { from_state: 'query', condition: 'success', to_state: 'approve' },
    { from_state: 'query', condition: 'timeout', to_state: 'complete' },
    { from_state: 'approve', condition: 'approved', to_state: 'complete' },
  ],
  terminal_states: ['complete'],
};

const registry = [{
  agent_id: 'noc',
  name: 'NOC Agent',
  description: 'Read-only diagnosis',
  capabilities: [{
    capability_id: 'alarm.query',
    description: 'Query alarms',
    risk_level: 'low',
    outcomes: ['success', 'failure'],
  }],
}];

const model = buildFSMGraphModel(fsm, {
  status: 'awaiting_approval',
  current_state_id: 'approve',
  completed_state_ids: ['query'],
  state_outcomes: { query: 'success' },
}, registry);

assert.deepEqual(model.nodes.map((node) => [node.number, node.id]), [[1, 'query'], [2, 'approve'], [3, 'complete']]);
assert.equal(model.nodes[0].agentName, 'NOC Agent');
assert.equal(fsmNodeLabel(model.nodes[0]), '1. 查询\n智能体：NOC Agent');
assert.equal(model.nodes[0].capability?.capability_id, 'alarm.query');
assert.equal(model.nodes[0].shape, 'round-rectangle');
assert.equal(model.nodes[1].status, 'awaiting_approval');
assert.equal(model.nodes[1].shape, 'diamond');
assert.equal(model.nodes[2].shape, 'ellipse');
assert.equal(model.edges.find((edge) => edge.condition === 'timeout')?.abnormal, true);
assert.equal(model.edges.find((edge) => edge.condition === 'success')?.abnormal, false);
assert.equal(isAbnormalTransition('failure'), true);
assert.equal(isAbnormalTransition('success'), false);

const fallback = buildFSMGraphModel(fsm, undefined, undefined, { noc: 'Fallback agent' });
assert.equal(fallback.nodes[0].agentName, 'Fallback agent');
assert.equal(fsmNodeLabel(fallback.nodes[0]), '1. 查询\n智能体：Fallback agent');
assert.equal(fsmNodeLabel(buildFSMGraphModel(fsm).nodes[0]), '1. 查询\n智能体：noc');
assert.equal(fsmNodeLabel({ number: 4, title: '未分配', state: { state_id: 'unassigned', kind: 'agent' } }), '4. 未分配\n智能体：未指定智能体');
console.log('FSM graph model check OK');
