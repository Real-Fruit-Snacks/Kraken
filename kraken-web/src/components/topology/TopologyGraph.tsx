// Main topology graph component using React Flow + ELK layout

import { useCallback, useEffect, useState } from 'react';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
} from '@xyflow/react';
import ELK from 'elkjs/lib/elk.bundled.js';
import '@xyflow/react/dist/style.css';

import { ImplantNode } from './ImplantNode';
import { C2Edge, edgeAnimationStyles } from './C2Edge';
import { TopologyControls } from './TopologyControls';
import { TopologyLegend } from './TopologyLegend';
import type {
  TopologyNodeData,
  TopologyEdgeData,
  LayoutDirection,
} from './types';

// Type aliases for our specific node/edge types
type TopologyNode = Node<TopologyNodeData>;
type TopologyEdge = Edge<TopologyEdgeData>;

// Register custom node and edge types
const nodeTypes = {
  implant: ImplantNode,
  'c2-server': ImplantNode, // Same component handles both
};

const edgeTypes = {
  c2: C2Edge,
};

// ELK layout instance
const elk = new ELK();

interface TopologyGraphProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  onNodeClick?: (nodeId: string) => void;
  onNodeDoubleClick?: (nodeId: string) => void;
}

function TopologyGraphInner({
  nodes: initialNodes,
  edges: initialEdges,
  onNodeClick,
  onNodeDoubleClick,
}: TopologyGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [direction, setDirection] = useState<LayoutDirection>('LR');
  const { fitView } = useReactFlow();

  // Compute layout with ELK
  const computeLayout = useCallback(async (
    inputNodes: TopologyNode[],
    inputEdges: TopologyEdge[],
    layoutDirection: LayoutDirection
  ) => {
    if (inputNodes.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    // Convert to ELK format
    const elkGraph = {
      id: 'root',
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': layoutDirection === 'LR' ? 'RIGHT' :
                         layoutDirection === 'RL' ? 'LEFT' :
                         layoutDirection === 'TB' ? 'DOWN' : 'UP',
        'elk.spacing.nodeNode': '50',
        'elk.layered.spacing.nodeNodeBetweenLayers': '150',
        'elk.layered.nodePlacement.bk.fixedAlignment': 'BALANCED',
        'elk.hierarchyHandling': 'INCLUDE_CHILDREN',
      },
      children: inputNodes.map((node) => ({
        id: node.id,
        width: node.data?.type === 'c2-server' ? 120 : 160,
        height: node.data?.type === 'c2-server' ? 90 : 70,
      })),
      edges: inputEdges.map((edge) => ({
        id: edge.id,
        sources: [edge.source],
        targets: [edge.target],
      })),
    };

    try {
      const layoutedGraph = await elk.layout(elkGraph);

      // Apply positions to nodes
      const layoutedNodes = inputNodes.map((node) => {
        const elkNode = layoutedGraph.children?.find((n) => n.id === node.id);
        return {
          ...node,
          position: {
            x: elkNode?.x ?? 0,
            y: elkNode?.y ?? 0,
          },
        };
      });

      // Set edges with custom type
      const layoutedEdges = inputEdges.map((edge) => ({
        ...edge,
        type: 'c2',
      }));

      setNodes(layoutedNodes);
      setEdges(layoutedEdges);

      // Fit view after layout with a small delay
      setTimeout(() => {
        fitView({ padding: 0.2, duration: 300 });
      }, 50);
    } catch (err) {
      console.error('ELK layout failed:', err);
      // Fallback: just position nodes in a grid
      const cols = Math.ceil(Math.sqrt(inputNodes.length));
      const layoutedNodes = inputNodes.map((node, i) => ({
        ...node,
        position: {
          x: (i % cols) * 200,
          y: Math.floor(i / cols) * 120,
        },
      }));
      setNodes(layoutedNodes);
      setEdges(inputEdges.map((e) => ({ ...e, type: 'c2' })));
    }
  }, [setNodes, setEdges, fitView]);

  // Recompute layout when inputs or direction change
  useEffect(() => {
    computeLayout(initialNodes, initialEdges, direction);
  }, [initialNodes, initialEdges, direction, computeLayout]);

  // Handle node click
  const handleNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    onNodeClick?.(node.id);
  }, [onNodeClick]);

  // Handle node double click
  const handleNodeDoubleClick = useCallback((_: React.MouseEvent, node: Node) => {
    onNodeDoubleClick?.(node.id);
  }, [onNodeDoubleClick]);

  return (
    <div className="w-full h-full relative">
      {/* Inject animation styles */}
      <style>{edgeAnimationStyles}</style>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        onNodeDoubleClick={handleNodeDoubleClick}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        minZoom={0.1}
        maxZoom={2}
        defaultEdgeOptions={{
          type: 'c2',
          animated: true,
        }}
        proOptions={{ hideAttribution: true }}
        className="bg-base"
      >
        <Background
          color="#45475a"
          gap={20}
          size={1}
        />
        <MiniMap
          nodeColor={(node) => {
            const data = node.data as TopologyNodeData | undefined;
            if (data?.type === 'c2-server') return '#cba6f7';
            const state = (data as any)?.state || 'active';
            switch (state) {
              case 'active': return '#a6e3a1';
              case 'dormant': return '#f9e2af';
              case 'dead':
              case 'burned': return '#f38ba8';
              default: return '#6c7086';
            }
          }}
          maskColor="rgba(30, 30, 46, 0.8)"
          className="!bg-mantle !border-surface0"
        />
      </ReactFlow>

      <TopologyControls
        direction={direction}
        onDirectionChange={setDirection}
      />

      <TopologyLegend />
    </div>
  );
}

// Wrapper with ReactFlowProvider
export function TopologyGraph(props: TopologyGraphProps) {
  return (
    <ReactFlowProvider>
      <TopologyGraphInner {...props} />
    </ReactFlowProvider>
  );
}
