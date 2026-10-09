import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AimOutlined,
  FullscreenOutlined,
  ReloadOutlined,
  ZoomInOutlined,
  ZoomOutOutlined,
} from '@ant-design/icons';
import cytoscape, { type Core, type ElementDefinition, type LayoutOptions } from 'cytoscape';
import { t } from '../../i18n';
import type { FSMAgentCard, FSMPlanV1, FSMRuntime } from '../../types';
import { buildFSMGraphModel, fsmNodeLabel, type FSMGraphNode } from './fsmGraphModel';

interface FsmGraphProps {
  fsm: FSMPlanV1;
  runtime?: FSMRuntime;
  agentRegistry?: FSMAgentCard[];
  agentNameMap?: Record<string, string>;
  selectedStateId?: string;
  onSelectState: (stateId: string) => void;
  onExpand?: (trigger: HTMLButtonElement) => void;
}

function nodeClasses(node: FSMGraphNode): string {
  return `kind-${node.state.kind} status-${node.status}${node.isInitial ? ' is-initial' : ''}`;
}

function layoutOptions(vertical: boolean, initialStateId: string): LayoutOptions {
  return {
    name: 'breadthfirst',
    directed: true,
    roots: [initialStateId],
    circle: false,
    grid: false,
    spacingFactor: 1.35,
    padding: 44,
    animate: false,
    maximal: false,
    transform: (_node, position) => vertical ? position : { x: position.y, y: position.x },
  };
}

export function FsmGraph({
  fsm,
  runtime,
  agentRegistry,
  agentNameMap,
  selectedStateId,
  onSelectState,
  onExpand,
}: FsmGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | undefined>(undefined);
  const onSelectRef = useRef(onSelectState);
  const selectedStateRef = useRef(selectedStateId);
  const [vertical, setVertical] = useState(() => window.matchMedia('(max-width: 720px)').matches);
  const topologyModel = useMemo(
    () => buildFSMGraphModel(fsm, undefined, agentRegistry, agentNameMap),
    [fsm, agentRegistry, agentNameMap],
  );
  const liveModel = useMemo(
    () => buildFSMGraphModel(fsm, runtime, agentRegistry, agentNameMap),
    [fsm, runtime, agentRegistry, agentNameMap],
  );

  useEffect(() => {
    onSelectRef.current = onSelectState;
  }, [onSelectState]);

  useEffect(() => {
    selectedStateRef.current = selectedStateId;
  }, [selectedStateId]);

  useEffect(() => {
    const query = window.matchMedia('(max-width: 720px)');
    const update = () => setVertical(query.matches);
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;
    const elements: ElementDefinition[] = [
      ...topologyModel.nodes.map((node) => ({
        group: 'nodes' as const,
        data: {
          id: node.id,
          order: node.number,
          label: fsmNodeLabel(node),
        },
        classes: nodeClasses(node),
      })),
      ...topologyModel.edges.map((edge) => ({
        group: 'edges' as const,
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.condition,
          displayLabel: edge.abnormal ? '' : edge.condition,
          abnormal: edge.abnormal,
        },
        classes: edge.abnormal ? 'edge-abnormal' : 'edge-main',
      })),
    ];
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      minZoom: 0.35,
      maxZoom: 4,
      wheelSensitivity: 0.18,
      boxSelectionEnabled: false,
      style: [
        {
          selector: 'node',
          style: {
            'width': '188px',
            'height': '68px',
            'shape': 'roundrectangle',
            'background-color': '#f8fafc',
            'border-width': 2,
            'border-color': '#94a3b8',
            'label': 'data(label)',
            'font-size': 13,
            'font-weight': 600,
            'color': '#243047',
            'text-wrap': 'wrap',
            'text-max-width': '168px',
            'text-valign': 'center',
            'text-halign': 'center',
            'overlay-opacity': 0,
          },
        },
        { selector: 'node.kind-agent', style: { 'width': '210px', 'height': '76px', 'shape': 'rectangle', 'background-color': '#eaf3ff', 'border-width': 3, 'border-color': '#1677ff', 'color': '#123e73', 'text-max-width': '190px' } },
        { selector: 'node.kind-approval', style: { 'width': '118px', 'height': '88px', 'shape': 'diamond', 'background-color': '#fff7ed', 'border-color': '#d97706', 'color': '#92400e' } },
        { selector: 'node.kind-terminal', style: { 'width': '136px', 'height': '66px', 'shape': 'ellipse', 'background-color': '#f1f5f9', 'border-color': '#64748b' } },
        { selector: 'node.status-running', style: { 'border-width': 4, 'border-color': '#1677ff', 'background-color': '#eff6ff' } },
        { selector: 'node.status-success', style: { 'border-width': 4, 'border-color': '#16a34a', 'background-color': '#f0fdf4' } },
        { selector: 'node.status-failed, node.status-manual_review', style: { 'border-width': 4, 'border-color': '#dc2626', 'background-color': '#fef2f2' } },
        { selector: 'node.status-awaiting_approval', style: { 'border-width': 4, 'border-color': '#d97706', 'background-color': '#fff7ed' } },
        { selector: 'node.kind-agent.status-running', style: { 'background-color': '#dbeafe', 'border-color': '#126dff' } },
        { selector: 'node.kind-agent.status-success', style: { 'background-color': '#eaf3ff', 'border-color': '#16a34a' } },
        { selector: 'node.kind-agent.status-failed, node.kind-agent.status-manual_review', style: { 'background-color': '#eaf3ff', 'border-color': '#dc2626' } },
        { selector: 'node.kind-terminal.status-success', style: { 'background-color': '#f0fdf4', 'border-color': '#16a34a', 'color': '#166534' } },
        { selector: 'node.is-initial', style: { 'border-style': 'double' } },
        { selector: 'node.is-selected', style: { 'overlay-color': '#1677ff', 'overlay-opacity': 0.12, 'overlay-padding': '7px' } },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
            'target-arrow-shape': 'triangle',
            'curve-style': 'taxi',
            'taxi-direction': vertical ? 'downward' : 'rightward',
            'taxi-turn': 22,
            'label': 'data(displayLabel)',
            'font-size': 10,
            'color': '#475569',
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
            'text-rotation': 'autorotate',
            'arrow-scale': 0.85,
            'overlay-opacity': 0,
          },
        },
        { selector: 'edge.edge-abnormal', style: { 'line-style': 'dashed', 'line-color': '#cbd5e1', 'target-arrow-color': '#cbd5e1', 'width': 1.5 } },
        { selector: 'edge.is-emphasized', style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444', 'color': '#b91c1c' } },
      ],
    });
    cyRef.current = cy;
    cy.layout(layoutOptions(vertical, topologyModel.initialStateId)).run();
    cy.fit(undefined, 24);
    const readableZoom = vertical ? 0.55 : 0.72;
    if (cy.zoom() < readableZoom) {
      cy.zoom(readableZoom);
      cy.center(cy.getElementById(topologyModel.initialStateId));
    }

    const showAbnormalForNode = (stateId: string, visible: boolean) => {
      cy.edges('.edge-abnormal').forEach((edge) => {
        if (edge.source().id() !== stateId && edge.target().id() !== stateId) return;
        edge.data('displayLabel', visible ? edge.data('label') : '');
        edge.toggleClass('is-emphasized', visible);
      });
    };
    cy.on('tap', 'node', (event) => onSelectRef.current(event.target.id()));
    cy.on('mouseover', 'node', (event) => showAbnormalForNode(event.target.id(), true));
    cy.on('mouseout', 'node', (event) => {
      if (event.target.id() !== selectedStateRef.current) showAbnormalForNode(event.target.id(), false);
    });
    cy.on('mouseover', 'edge.edge-abnormal', (event) => {
      event.target.data('displayLabel', event.target.data('label'));
      event.target.addClass('is-emphasized');
    });
    cy.on('mouseout', 'edge.edge-abnormal', (event) => {
      const edge = event.target;
      const selected = selectedStateRef.current;
      const keep = selected && (edge.source().id() === selected || edge.target().id() === selected);
      if (!keep) {
        edge.data('displayLabel', '');
        edge.removeClass('is-emphasized');
      }
    });

    const observer = new ResizeObserver(() => cy.resize());
    observer.observe(containerRef.current);
    return () => {
      observer.disconnect();
      cy.destroy();
      cyRef.current = undefined;
    };
  }, [onExpand, topologyModel, vertical]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    for (const node of liveModel.nodes) {
      const element = cy.getElementById(node.id);
      element.classes(nodeClasses(node));
    }
  }, [liveModel]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass('is-selected');
    cy.edges('.edge-abnormal').forEach((edge) => {
      const emphasized = !!selectedStateId && (edge.source().id() === selectedStateId || edge.target().id() === selectedStateId);
      edge.data('displayLabel', emphasized ? edge.data('label') : '');
      edge.toggleClass('is-emphasized', emphasized);
    });
    if (selectedStateId) cy.getElementById(selectedStateId).addClass('is-selected');
  }, [selectedStateId]);

  const moveSelection = (offset: number) => {
    const nodes = liveModel.nodes;
    const current = Math.max(0, nodes.findIndex((node) => node.id === selectedStateId));
    const next = nodes[(current + offset + nodes.length) % nodes.length];
    if (next) onSelectState(next.id);
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      event.preventDefault();
      moveSelection(1);
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      event.preventDefault();
      moveSelection(-1);
    } else if (event.key === 'Enter' && selectedStateId) {
      event.preventDefault();
      onSelectState(selectedStateId);
    }
  };

  const fit = () => cyRef.current?.fit(undefined, 24);
  const reset = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.layout(layoutOptions(vertical, topologyModel.initialStateId)).run();
    cy.fit(undefined, 24);
  };

  return (
    <div className="jx-fsmGraphShell">
      <div className="jx-fsmGraphToolbar" aria-label={t('流程图工具')}>
        <button type="button" title={t('放大')} aria-label={t('放大')} onClick={() => { const cy = cyRef.current; if (cy) cy.zoom({ level: Math.min(4, cy.zoom() * 1.2), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); }}><ZoomInOutlined /></button>
        <button type="button" title={t('缩小')} aria-label={t('缩小')} onClick={() => { const cy = cyRef.current; if (cy) cy.zoom({ level: Math.max(0.35, cy.zoom() / 1.2), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); }}><ZoomOutOutlined /></button>
        <button type="button" title={t('适应画布')} aria-label={t('适应画布')} onClick={fit}><AimOutlined /></button>
        <button type="button" title={t('重置布局')} aria-label={t('重置布局')} onClick={reset}><ReloadOutlined /></button>
        {onExpand && (
          <button type="button" title={t('大图查看')} aria-label={t('大图查看')} onClick={(event) => onExpand(event.currentTarget)}><FullscreenOutlined /></button>
        )}
      </div>
      <div className="jx-fsmGraphLegend" aria-label={t('流程图图例')}>
        <span><i className="is-agent" />{t('智能体')}</span>
        <span><i className="is-approval" />{t('审批')}</span>
        <span><i className="is-terminal" />{t('终态')}</span>
      </div>
      <div
        ref={containerRef}
        className="jx-fsmGraphCanvas"
        role="application"
        tabIndex={0}
        aria-label={t('交互式 FSM 流程图，使用方向键切换状态，Enter 查看详情')}
        onKeyDown={handleKeyDown}
      />
    </div>
  );
}
