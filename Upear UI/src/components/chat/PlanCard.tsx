import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Modal } from 'antd';
import { AnimatePresence, motion } from 'motion/react';
import {
  CheckCircleFilled, CloseCircleFilled, LoadingOutlined,
  RightOutlined,
  ToolOutlined, AppstoreOutlined, SafetyCertificateOutlined,
  ThunderboltOutlined, OrderedListOutlined, RobotOutlined,
} from '@ant-design/icons';
import { DUR, EASE, SPRING, staggerStyle } from '../../utils/motionTokens';
import { CollapseHeight } from '../common/CollapseHeight';
import { FsmGraph } from './FsmGraph';
import { buildFSMGraphModel, fsmStateStatus, type FSMGraphNode } from './fsmGraphModel';
import { t } from '../../i18n';
import type { FSMAgentCard, FSMPlanV1, FSMRuntime, PlanApproval, PlanApprovalDecision } from '../../types';

/* ───────────────────────────────────────────
   Plan Card — structured plan rendering
   ─────────────────────────────────────────── */

export interface PlanStepData {
  step_order: number;
  title: string;
  description?: string;
  expected_tools?: string[];
  expected_skills?: string[];
  expected_agents?: string[];
  acceptance_criteria?: string;
  status?: 'pending' | 'running' | 'success' | 'failed' | 'skipped' | 'awaiting_approval' | 'manual_review';
  summary?: string;
  text?: string;          // live progress text during execution
}

export interface PlanCardProps {
  mode: 'preview' | 'executing' | 'complete';
  title: string;
  description?: string;
  steps: PlanStepData[];
  completedSteps?: number;
  totalSteps?: number;
  resultText?: string;    // final report for 'complete' mode
  isStreaming?: boolean;
  agentNameMap?: Record<string, string>;
  agentRegistry?: FSMAgentCard[];
  fsm?: FSMPlanV1;
  fsmRuntime?: FSMRuntime;
  validationStatus?: string;
  planHash?: string;
  agentRegistryHash?: string;
  approval?: PlanApproval;
  onApproval?: (decision: Exclude<PlanApprovalDecision, 'expired'>) => Promise<void> | void;
  /**
   * Override the footer rendered in 'preview' mode.
   * - `undefined` → default "please reply to confirm execution" prompt (chat scenario)
   * - `null`       → hide the footer
   * - ReactNode    → custom footer content
   */
  previewFooter?: ReactNode | null;
  /** Extra className, for variant styles (such as embed) */
  className?: string;
  /** Expand steps by default (in preview mode) */
  defaultExpandSteps?: boolean;
}

/* ── StepStatusIcon transition animation config (module-level constants, not rebuilt on high-frequency SSE re-renders) ── */
const STATUS_ICON_INITIAL = { scale: 0.8, opacity: 0 };
const STATUS_ICON_INITIAL_SUCCESS = { scale: 0.4, opacity: 0 };
const STATUS_ICON_ANIMATE = { scale: 1, opacity: 1 };
const STATUS_ICON_EXIT = { scale: 0.8, opacity: 0, transition: { duration: 0.1, ease: EASE.exit } };
const STATUS_ICON_SWAP = { duration: DUR.fast, ease: EASE.standard };

/* ── Status icon helper ── */
function StepStatusIcon({ status }: { status?: string }) {
  const key = status || 'pending';
  let icon: ReactNode;
  switch (status) {
    case 'success':
      icon = <CheckCircleFilled className="jx-plan-stepIcon jx-plan-stepIcon--success" />;
      break;
    case 'failed':
      icon = <CloseCircleFilled className="jx-plan-stepIcon jx-plan-stepIcon--error" />;
      break;
    case 'running':
      icon = <LoadingOutlined className="jx-plan-stepIcon jx-plan-stepIcon--running" spin />;
      break;
    case 'awaiting_approval':
      icon = <SafetyCertificateOutlined className="jx-plan-stepIcon jx-plan-stepIcon--approval" />;
      break;
    case 'manual_review':
      icon = <CloseCircleFilled className="jx-plan-stepIcon jx-plan-stepIcon--error" />;
      break;
    case 'skipped':
      icon = <span className="jx-plan-stepIcon jx-plan-stepIcon--skipped">—</span>;
      break;
    default:
      icon = <span className="jx-plan-stepIcon jx-plan-stepIcon--pending" />;
  }
  // The animation key binds only to status: high-frequency SSE re-renders won't replay it; the transition only fires when the status flips.
  // initial={false} makes it not play on history load / first mount (avoiding the whole column of checks popping at once).
  // success uses a spring pop-in — the only deliberate bounce "reward moment" in the whole design.
  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.span
        key={key}
        className="jx-plan-stepIconWrap"
        initial={key === 'success' ? STATUS_ICON_INITIAL_SUCCESS : STATUS_ICON_INITIAL}
        animate={STATUS_ICON_ANIMATE}
        exit={STATUS_ICON_EXIT}
        transition={key === 'success' ? SPRING.pop : STATUS_ICON_SWAP}
      >
        {icon}
      </motion.span>
    </AnimatePresence>
  );
}

/* ── Single step row ── */
function PlanStepRow({ step, index, mode, agentNameMap, defaultExpanded }: { step: PlanStepData; index: number; mode: string; agentNameMap?: Record<string, string>; defaultExpanded?: boolean }) {
  const [expanded, setExpanded] = useState(!!defaultExpanded);
  const hasDetails = !!(step.description || step.expected_tools?.length || step.expected_skills?.length || step.expected_agents?.length || step.acceptance_criteria);
  const showExpand = mode === 'preview' && hasDetails;
  const isActive = step.status === 'running';
  const progressText = step.text ?? '';

  // Fire a one-shot background flash on the frame status actually flips to success;
  // the ref's initial value takes the first-frame status — rows already in success on history load don't flash.
  // setState is triggered asynchronously via setTimeout to avoid a synchronous setState cascade render inside the effect.
  const prevStatusRef = useRef(step.status);
  const [justDone, setJustDone] = useState(false);
  useEffect(() => {
    const prev = prevStatusRef.current;
    prevStatusRef.current = step.status;
    if (step.status === 'success' && prev && prev !== 'success') {
      const onTimer = window.setTimeout(() => setJustDone(true), 0);
      const offTimer = window.setTimeout(() => setJustDone(false), 600);
      return () => {
        window.clearTimeout(onTimer);
        window.clearTimeout(offTimer);
      };
    }
  }, [step.status]);

  return (
    // Entry stagger: the container .jx-plan-steps carries .jx-anim-stagger (40ms step),
    // row number starts at 1 (label occupies 0), capped at 6 → replicating the original nth-child 40~240ms delay ramp.
    <div
      className={`jx-plan-step ${isActive ? 'jx-plan-step--active' : ''} ${step.status === 'success' ? 'jx-plan-step--done' : ''} ${justDone ? 'jx-plan-step--justDone' : ''}`}
      style={staggerStyle(index + 1, 6)}
    >
      <div className="jx-plan-stepHeader" onClick={showExpand ? () => setExpanded(!expanded) : undefined} style={showExpand ? { cursor: 'pointer' } : undefined}>
        <div className="jx-plan-stepLeft">
          {mode === 'preview' ? (
            <span className="jx-plan-stepNum">{index + 1}</span>
          ) : (
            <StepStatusIcon status={step.status} />
          )}
          <span className="jx-plan-stepTitle">{step.title}</span>
        </div>
        {showExpand && (
          <motion.span
            className="jx-plan-stepExpand"
            initial={false}
            animate={{ rotate: expanded ? 90 : 0 }}
            transition={{ duration: DUR.fast, ease: EASE.standard }}
          >
            <RightOutlined />
          </motion.span>
        )}
      </div>

      {/* Preview mode: expandable details (height-auto expand; CollapseHeight defaults to initial=false so defaultExpandSteps initial expansion doesn't play) */}
      <CollapseHeight show={expanded && mode === 'preview'} duration={0.18}>
        <div className="jx-plan-stepDetails">
          {step.description && <p className="jx-plan-stepDesc">{step.description}</p>}
          {step.expected_tools && step.expected_tools.length > 0 && (
            <div className="jx-plan-stepMeta">
              <ToolOutlined className="jx-plan-metaIcon" />
              <span className="jx-plan-metaLabel">{t('MCP 工具')}</span>
              <div className="jx-plan-tags">
                {step.expected_tools.map((t, i) => <span key={i} className="jx-plan-tag jx-plan-tag--tool">{t}</span>)}
              </div>
            </div>
          )}
          {step.expected_skills && step.expected_skills.length > 0 && (
            <div className="jx-plan-stepMeta">
              <AppstoreOutlined className="jx-plan-metaIcon" />
              <span className="jx-plan-metaLabel">{t('技能')}</span>
              <div className="jx-plan-tags">
                {step.expected_skills.map((s, i) => <span key={i} className="jx-plan-tag jx-plan-tag--skill">{s}</span>)}
              </div>
            </div>
          )}
          {step.expected_agents && step.expected_agents.length > 0 && (
            <div className="jx-plan-stepMeta">
              <RobotOutlined className="jx-plan-metaIcon" />
              <span className="jx-plan-metaLabel">{t('子智能体')}</span>
              <div className="jx-plan-tags">
                {step.expected_agents.map((a, i) => <span key={i} className="jx-plan-tag jx-plan-tag--agent">{agentNameMap?.[a] || a}</span>)}
              </div>
            </div>
          )}
          {step.acceptance_criteria && (
            <div className="jx-plan-stepMeta">
              <SafetyCertificateOutlined className="jx-plan-metaIcon" />
              <span className="jx-plan-metaLabel">{t('验收标准')}</span>
              <span className="jx-plan-metaVal">{step.acceptance_criteria}</span>
            </div>
          )}
        </div>
      </CollapseHeight>

      {/* Execution mode: summary or live progress */}
      {mode !== 'preview' && step.summary && (
        <div className="jx-plan-stepSummary">{step.summary}</div>
      )}
      {/* The progress block appears/disappears via height-auto; the inner streaming text isn't animated (outer overflow hidden) */}
      {mode !== 'preview' && (
        <CollapseHeight show={!!(isActive && step.text)} duration={0.22}>
          <div className="jx-plan-stepProgress">
            {progressText.length > 300 ? progressText.slice(-300) : progressText}
          </div>
        </CollapseHeight>
      )}
    </div>
  );
}

/* ── Progress bar ── */
function ProgressBar({ completed, total }: { completed: number; total: number }) {
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
  return (
    <div className="jx-plan-progress">
      <div className="jx-plan-progressTrack">
        <div className="jx-plan-progressFill" style={{ width: `${pct}%` }} />
      </div>
      <span className="jx-plan-progressLabel">{completed}/{total}</span>
    </div>
  );
}

const STATUS_LABELS: Record<FSMGraphNode['status'], string> = {
  pending: '未执行',
  running: '运行中',
  success: '成功',
  failed: '失败',
  awaiting_approval: '待审批',
  manual_review: '需人工介入',
};

function DetailItem({ label, children }: { label: string; children?: ReactNode }) {
  if (children == null || children === '') return null;
  return (
    <div className="jx-fsmDetailItem">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function FsmStateDetail({ node, fsm }: { node?: FSMGraphNode; fsm: FSMPlanV1 }) {
  if (!node) return <aside className="jx-fsmDetail" aria-label={t('状态详情')} />;
  const state = node.state;
  const agent = node.agentName;
  const registryAgent = node.state.agent_id;
  const outgoing = fsm.transitions.filter((edge) => edge.from_state === state.state_id);
  const numbering = new Map(fsm.states.map((item, index) => [item.state_id, index + 1]));
  const bindings = Object.entries(state.input_bindings || {});
  const kindLabel = state.kind === 'approval' ? t('审批') : state.kind === 'terminal' ? t('终态') : t('Agent');
  return (
    <aside className="jx-fsmDetail" aria-label={t('状态详情')}>
      <div className="jx-fsmDetailHeader">
        <span className="jx-fsmDetailNumber">{node.number}</span>
        <div>
          <strong>{node.title}</strong>
          <code>{node.id}</code>
        </div>
      </div>
      <dl>
        <DetailItem label={t('类型')}>{kindLabel}</DetailItem>
        <DetailItem label={t('说明')}>{state.description}</DetailItem>
        <DetailItem label={t('Agent')}>{agent || registryAgent}</DetailItem>
        <DetailItem label={t('能力')}>{state.capability_id}</DetailItem>
        <DetailItem label={t('能力说明')}>{node.capability?.description}</DetailItem>
        <DetailItem label={t('风险等级')}>{node.capability?.risk_level}</DetailItem>
        <DetailItem label={t('可逆性')}>{node.capability?.reversibility}</DetailItem>
        <DetailItem label={t('允许结果')}>
          {node.capability?.outcomes?.map((outcome) => <code key={outcome}>{outcome}</code>)}
        </DetailItem>
        <DetailItem label={t('输入绑定')}>
          {bindings.map(([name, binding]) => (
            <div key={name}><code>{name}</code><span> ← {binding.source === 'state' ? `${binding.state_id}.${binding.key}` : `task.${binding.key}`}</span></div>
          ))}
        </DetailItem>
        <DetailItem label={t('出边')}>
          {outgoing.map((edge, index) => (
            <div key={`${edge.condition}-${edge.to_state}-${index}`}><code>{edge.condition}</code><span> → {numbering.get(edge.to_state) || '?'} · {edge.to_state}</span></div>
          ))}
        </DetailItem>
        <DetailItem label={t('运行状态')}><span className={`jx-fsmStatus jx-fsmStatus--${node.status}`}>{t(STATUS_LABELS[node.status])}</span></DetailItem>
        <DetailItem label={t('结果摘要')}>{node.resultSummary}</DetailItem>
        {node.errorClass && <DetailItem label={t('异常类别')}><code>{node.errorClass}</code></DetailItem>}
      </dl>
    </aside>
  );
}

function FsmStateList({
  nodes,
  selectedStateId,
  onSelect,
  rowRefs,
}: {
  nodes: FSMGraphNode[];
  selectedStateId?: string;
  onSelect: (stateId: string) => void;
  rowRefs: React.MutableRefObject<Record<string, HTMLButtonElement | null>>;
}) {
  return (
    <div className="jx-fsmStateList" role="listbox" aria-label={t('FSM 状态列表')}>
      {nodes.map((node) => (
        <button
          key={node.id}
          type="button"
          ref={(element) => { rowRefs.current[node.id] = element; }}
          role="option"
          aria-selected={selectedStateId === node.id}
          className={selectedStateId === node.id ? 'is-selected' : ''}
          onClick={() => onSelect(node.id)}
        >
          <span className="jx-fsmStateNumber">{node.number}</span>
          <StepStatusIcon status={node.status} />
          <span className="jx-fsmStateText"><strong>{node.title}</strong><small>{node.agentName || node.state.capability_id || node.id}</small></span>
          <span className={`jx-fsmStateKind jx-fsmStateKind--${node.state.kind}`}>{node.state.kind === 'approval' ? t('审批') : node.state.kind === 'terminal' ? t('终态') : t('Agent')}</span>
        </button>
      ))}
    </div>
  );
}

/* ── Main PlanCard ── */
export function PlanCard({ mode, title, description, steps, completedSteps, totalSteps, resultText, isStreaming, agentNameMap, agentRegistry, fsm, fsmRuntime, validationStatus, planHash, agentRegistryHash, approval, onApproval, previewFooter, className, defaultExpandSteps }: PlanCardProps) {
  const [stepsCollapsed, setStepsCollapsed] = useState(false);
  const [fsmView, setFsmView] = useState<'graph' | 'states'>('graph');
  const [selectedStateId, setSelectedStateId] = useState<string | undefined>(fsm?.initial_state);
  const [fsmExpanded, setFsmExpanded] = useState(false);
  const [approvalBusy, setApprovalBusy] = useState(false);
  const expandButtonRef = useRef<HTMLButtonElement | null>(null);
  const stateRowRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const isFsm = !!fsm?.states?.length;
  const graphModel = isFsm ? buildFSMGraphModel(fsm!, fsmRuntime, agentRegistry, agentNameMap) : undefined;
  const selectedNode = graphModel?.nodes.find((node) => node.id === selectedStateId);
  const openFsmExpanded = useCallback((trigger: HTMLButtonElement) => {
    expandButtonRef.current = trigger;
    setFsmExpanded(true);
  }, []);
  const closeFsmExpanded = useCallback(() => {
    setFsmExpanded(false);
  }, []);
  useEffect(() => {
    if (!fsm?.states?.length) {
      setSelectedStateId(undefined);
      return;
    }
    setSelectedStateId((current) => fsm.states.some((state) => state.state_id === current) ? current : fsm.initial_state);
  }, [fsm]);
  useEffect(() => {
    if (fsmView !== 'states' || !selectedStateId) return;
    stateRowRefs.current[selectedStateId]?.scrollIntoView({ block: 'nearest' });
  }, [fsmView, selectedStateId]);
  const fsmSteps: PlanStepData[] = isFsm
    ? fsm!.states.map((state, index) => ({
        step_order: index + 1,
        title: state.title || state.state_id,
        description: state.description || (state.kind === 'approval' && state.approval_for ? `${t('审批对象')}：${state.approval_for}` : undefined),
        expected_agents: state.agent_id ? [state.agent_id] : [],
        expected_tools: state.capability_id ? [state.capability_id] : [],
        status: fsmStateStatus(state, fsmRuntime),
        summary: graphModel?.nodes[index]?.resultSummary,
      }))
    : steps;
  const visibleSteps = fsm ? fsmSteps : steps;
  const completed = completedSteps ?? visibleSteps.filter(s => s.status === 'success').length;
  const total = totalSteps ?? (fsm ? fsm.states.filter(state => state.kind !== 'terminal').length : steps.length);
  const isComplete = mode === 'complete';
  const isExecuting = mode === 'executing';
  const runtimeStatus = fsmRuntime?.status || '';
  const activeApproval = approval || fsmRuntime?.approval || undefined;
  const waitingForApproval = runtimeStatus === 'awaiting_approval' || (!!activeApproval && !activeApproval.used);
  const statusLabel = isComplete
    ? runtimeStatus === 'manual_review' ? t('需人工介入') : t('已完成')
    : waitingForApproval ? t('等待审批') : isExecuting ? t('执行中') : '';
  // Complete on first mount (history load) doesn't play the completion celebration; only executing→complete within this session plays it.
  const [wasCompleteOnMount] = useState(isComplete);
  const justCompleted = isComplete && !wasCompleteOnMount;
  const showSteps = !isFsm && (isComplete && resultText ? !stepsCollapsed : true);

  const handleApproval = async (decision: Exclude<PlanApprovalDecision, 'expired'>) => {
    if (!activeApproval || !onApproval || approvalBusy) return;
    setApprovalBusy(true);
    try {
      await onApproval(decision);
    } finally {
      setApprovalBusy(false);
    }
  };

  return (
    <div className={`jx-plan-card ${isComplete ? 'jx-plan-card--complete' : ''} ${isExecuting ? 'jx-plan-card--executing' : ''} ${justCompleted ? 'jx-plan-card--justCompleted' : ''} ${className ?? ''}`} data-plan-hash={planHash || undefined} data-agent-registry-hash={agentRegistryHash || undefined}>
      <div className="jx-plan-header">
        <div className="jx-plan-headerIcon">
          {isComplete && runtimeStatus !== 'manual_review' ? (
            <CheckCircleFilled style={{ fontSize: 18, color: 'var(--color-success)' }} />
          ) : waitingForApproval ? (
            <SafetyCertificateOutlined style={{ fontSize: 18, color: 'var(--color-warning)' }} />
          ) : isExecuting ? (
            <ThunderboltOutlined style={{ fontSize: 18, color: 'var(--color-primary)' }} />
          ) : (
            <OrderedListOutlined style={{ fontSize: 18, color: 'var(--color-primary)' }} />
          )}
        </div>
        <div className="jx-plan-headerText">
          <h3 className="jx-plan-title">{title}</h3>
          {description && <p className="jx-plan-desc">{description}</p>}
          {isFsm && <div className="jx-plan-fsmMeta">FSM · {validationStatus === 'verified' ? t('已验证') : (validationStatus || t('受约束流程'))}</div>}
        </div>
        {(isExecuting || isComplete) && statusLabel && (
          <div className="jx-plan-headerBadge">
            <span className={`jx-plan-badge ${isComplete && runtimeStatus !== 'manual_review' ? 'jx-plan-badge--done' : waitingForApproval ? 'jx-plan-badge--approval' : 'jx-plan-badge--running'}`}>
              {statusLabel}
            </span>
          </div>
        )}
      </div>

      {(isExecuting || isComplete) && <ProgressBar completed={completed} total={total} />}

      {waitingForApproval && isFsm && (
        <div className="jx-plan-stateApproval jx-plan-stateApproval--fsm" role="status" aria-live="polite">
          <div className="jx-plan-stateApprovalTitle"><SafetyCertificateOutlined /> {t('需要审批后继续')}</div>
          <div className="jx-plan-stateApprovalDesc">{activeApproval?.approval_for ? `${t('审批对象')}：${activeApproval.approval_for}` : t('高风险状态等待人工确认')}</div>
          {activeApproval?.used ? (
            <div className="jx-plan-footerTip jx-plan-footerTip--decided">{t('审批结果')}：{activeApproval.decision || t('已处理')}</div>
          ) : onApproval ? (
            <div className="jx-plan-approveBtns">
              <button type="button" className="jx-plan-approveBtn jx-plan-approveBtn--ghost" disabled={approvalBusy} onClick={() => void handleApproval('rejected')}>{t('拒绝')}</button>
              <button type="button" className="jx-plan-approveBtn jx-plan-approveBtn--primary" disabled={approvalBusy} onClick={() => void handleApproval('approved')}>{approvalBusy ? t('处理中...') : t('批准继续')}</button>
            </div>
          ) : null}
        </div>
      )}

      {isFsm && (
        <div className="jx-plan-viewTabs" role="tablist" aria-label={t('FSM 展示方式')}>
          <button type="button" role="tab" aria-selected={fsmView === 'graph'} className={fsmView === 'graph' ? 'active' : ''} onClick={() => setFsmView('graph')}>{t('流程图')}</button>
          <button type="button" role="tab" aria-selected={fsmView === 'states'} className={fsmView === 'states' ? 'active' : ''} onClick={() => setFsmView('states')}>{t('状态列表')}</button>
        </div>
      )}

      {isFsm && fsmView === 'graph' && (
        <div className="jx-plan-fsmWorkspace">
          <div className="jx-plan-fsmMain">
            <FsmGraph
              fsm={fsm!}
              runtime={fsmRuntime}
              agentRegistry={agentRegistry}
              agentNameMap={agentNameMap}
              selectedStateId={selectedStateId}
              onSelectState={setSelectedStateId}
              onExpand={openFsmExpanded}
            />
          </div>
          <FsmStateDetail node={selectedNode} fsm={fsm!} />
        </div>
      )}

      {isFsm && (
        <Modal
          title={t('FSM 流程图')}
          open={fsmExpanded}
          onCancel={closeFsmExpanded}
          afterClose={() => expandButtonRef.current?.focus()}
          footer={null}
          width="calc(100vw - 48px)"
          centered
          destroyOnClose
          className="jx-fsmModal"
          rootClassName="jx-fsmModalRoot"
          styles={{ body: { padding: 0 } }}
        >
          <div className="jx-plan-fsmModalWorkspace">
            <div className="jx-plan-fsmMain">
              <FsmGraph
                fsm={fsm!}
                runtime={fsmRuntime}
                agentRegistry={agentRegistry}
                agentNameMap={agentNameMap}
                selectedStateId={selectedStateId}
                onSelectState={setSelectedStateId}
              />
            </div>
            <FsmStateDetail node={selectedNode} fsm={fsm!} />
          </div>
        </Modal>
      )}

      {isFsm && fsmView === 'states' && (
        <div className="jx-plan-fsmWorkspace">
          <div className="jx-plan-fsmMain">
            <FsmStateList
              nodes={graphModel?.nodes || []}
              selectedStateId={selectedStateId}
              onSelect={setSelectedStateId}
              rowRefs={stateRowRefs}
            />
          </div>
          <FsmStateDetail node={selectedNode} fsm={fsm!} />
        </div>
      )}

      {isComplete && resultText && !isFsm && (
        <div className="jx-plan-stepsToggle" onClick={() => setStepsCollapsed(!stepsCollapsed)}>
          <span>{stepsCollapsed ? t('展开步骤详情') : t('收起步骤详情')}</span>
          <motion.span style={{ display: 'inline-flex', fontSize: 10 }} initial={false} animate={{ rotate: stepsCollapsed ? 0 : 90 }} transition={{ duration: DUR.fast, ease: EASE.standard }}>
            <RightOutlined />
          </motion.span>
        </div>
      )}

      <CollapseHeight show={showSteps} duration={0.25}>
        <div className="jx-plan-steps jx-anim-stagger">
          <div className="jx-plan-stepsLabel">
            {isFsm ? t('FSM 状态（共 {n} 个）', { n: visibleSteps.length }) : mode === 'preview' ? t('执行计划（共 {n} 步）', { n: steps.length }) : t('步骤进度')}
          </div>
          {visibleSteps.map((step, idx) => (
            <PlanStepRow key={step.step_order ?? idx} step={step} index={idx} mode={mode} agentNameMap={agentNameMap} defaultExpanded={mode === 'preview' && defaultExpandSteps} />
          ))}
        </div>
      </CollapseHeight>

      {isExecuting && isStreaming && (
        <div className="jx-plan-streamingHint">
          <LoadingOutlined spin style={{ fontSize: 12 }} />
          <span>{t('正在执行中...')}</span>
        </div>
      )}

      {waitingForApproval && !isFsm && (
        <div className="jx-plan-stateApproval">
          <div className="jx-plan-stateApprovalTitle"><SafetyCertificateOutlined /> {t('需要审批后继续')}</div>
          <div className="jx-plan-stateApprovalDesc">{activeApproval?.approval_for ? `${t('审批对象')}：${activeApproval.approval_for}` : t('高风险状态等待人工确认')}</div>
          {activeApproval?.used ? (
            <div className="jx-plan-footerTip jx-plan-footerTip--decided">{t('审批结果')}：{activeApproval.decision || t('已处理')}</div>
          ) : onApproval ? (
            <div className="jx-plan-approveBtns">
              <button type="button" className="jx-plan-approveBtn jx-plan-approveBtn--ghost" disabled={approvalBusy} onClick={() => void handleApproval('rejected')}>{t('拒绝')}</button>
              <button type="button" className="jx-plan-approveBtn jx-plan-approveBtn--primary" disabled={approvalBusy} onClick={() => void handleApproval('approved')}>{approvalBusy ? t('处理中...') : t('批准继续')}</button>
            </div>
          ) : null}
        </div>
      )}

      {mode === 'preview' && previewFooter !== null && (
        <div className="jx-plan-footer">
          {previewFooter ?? <div className="jx-plan-footerTip">{t('请回复')} <strong>"{t('确认执行')}"</strong> {t('开始按步骤执行此计划，或回复其他内容修改需求。')}</div>}
        </div>
      )}

      {isComplete && (
        <motion.div key="completeFooter" style={{ overflow: 'hidden' }} initial={justCompleted ? { height: 0, opacity: 0 } : false} animate={{ height: 'auto', opacity: 1 }} transition={{ duration: DUR.normal, ease: EASE.brandOut, delay: 0.3 }}>
          <div className="jx-plan-completeFooter">
            {runtimeStatus === 'manual_review' ? <SafetyCertificateOutlined style={{ color: 'var(--color-warning)', fontSize: 13 }} /> : <CheckCircleFilled style={{ color: 'var(--color-success)', fontSize: 13 }} />}
            <span>{runtimeStatus === 'manual_review' ? t('执行暂停：需要人工介入') : t('执行完成：共 {total} 步，完成 {completed} 步', { total, completed })}</span>
          </div>
        </motion.div>
      )}
    </div>
  );
}
