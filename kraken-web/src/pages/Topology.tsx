// Topology page - mesh network visualization

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { meshClient, implantClient } from '../api/client';
import { TopologyGraph } from '../components/topology';
import type {
  TopologyNode,
  TopologyEdge,
  ImplantNodeData,
  C2ServerNodeData,
  EdgeProtocol,
  EdgeState,
} from '../components/topology/types';
import {
  MeshTransportType,
  MeshLinkState,
  MeshRoleType,
} from '../gen/kraken_pb';

// Helper to convert bytes to hex string
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Helper to get short ID for display
function shortId(bytes: Uint8Array): string {
  return bytesToHex(bytes).slice(0, 8);
}

// Map proto transport type to our edge protocol
function mapTransport(transport: MeshTransportType): EdgeProtocol {
  switch (transport) {
    case MeshTransportType.MESH_TRANSPORT_SMB:
      return 'smb';
    case MeshTransportType.MESH_TRANSPORT_TCP:
      return 'tcp';
    default:
      return 'tcp';
  }
}

// Map proto link state to our edge state
function mapLinkState(state: MeshLinkState): EdgeState {
  switch (state) {
    case MeshLinkState.MESH_LINK_CONNECTING:
    case MeshLinkState.MESH_LINK_HANDSHAKING:
      return 'connecting';
    case MeshLinkState.MESH_LINK_ACTIVE:
      return 'established';
    case MeshLinkState.MESH_LINK_DEGRADED:
      return 'degraded';
    case MeshLinkState.MESH_LINK_FAILED:
      return 'failed';
    default:
      return 'established';
  }
}

// Map proto role type
function mapRole(role: MeshRoleType): 'leaf' | 'relay' | 'hub' {
  switch (role) {
    case MeshRoleType.MESH_ROLE_RELAY:
      return 'relay';
    case MeshRoleType.MESH_ROLE_HUB:
      return 'hub';
    default:
      return 'leaf';
  }
}

// Detect OS from string
function detectOs(os: string): 'windows' | 'linux' | 'macos' | 'unknown' {
  const lower = os.toLowerCase();
  if (lower.includes('windows')) return 'windows';
  if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('debian')) return 'linux';
  if (lower.includes('mac') || lower.includes('darwin')) return 'macos';
  return 'unknown';
}

export function Topology() {
  const navigate = useNavigate();

  // Fetch topology data
  const { data: topologyData, isLoading: topologyLoading } = useQuery({
    queryKey: ['topology'],
    queryFn: () => meshClient.getTopology({}),
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  // Fetch implant details to enrich nodes
  const { data: implantsData } = useQuery({
    queryKey: ['implants'],
    queryFn: () => implantClient.listImplants({}),
    refetchInterval: 5000,
  });

  // Build graph nodes and edges
  const { nodes, edges } = useMemo(() => {
    const nodes: TopologyNode[] = [];
    const edges: TopologyEdge[] = [];

    // Create implant lookup
    const implantMap = new Map<string, any>();
    implantsData?.implants?.forEach((implant) => {
      if (implant.id?.value) {
        const id = bytesToHex(implant.id.value);
        implantMap.set(id, implant);
      }
    });

    // Add C2 server as root node
    const c2NodeData: C2ServerNodeData = {
      type: 'c2-server',
      name: 'Kraken C2',
      protocol: 'https',
    };
    nodes.push({
      id: 'c2-server',
      type: 'c2-server',
      position: { x: 0, y: 0 },
      data: c2NodeData,
    });

    // Track which nodes have egress (direct connection to C2)
    const nodesWithEgress = new Set<string>();

    // Process mesh nodes
    topologyData?.nodes?.forEach((meshNode) => {
      const nodeId = bytesToHex(meshNode.implantId);
      const implant = implantMap.get(nodeId);

      if (meshNode.hasEgress) {
        nodesWithEgress.add(nodeId);
      }

      const nodeData: ImplantNodeData = {
        type: 'implant',
        implantId: nodeId,
        hostname: implant?.hostname || `Implant-${shortId(meshNode.implantId)}`,
        username: implant?.username || 'unknown',
        os: implant ? detectOs(implant.os) : 'unknown',
        state: implant?.state === 0 ? 'active' :
               implant?.state === 1 ? 'dormant' :
               implant?.state === 2 ? 'dead' : 'active',
        isElevated: implant?.isElevated || false,
        hasEgress: meshNode.hasEgress,
        role: mapRole(meshNode.role),
      };

      nodes.push({
        id: nodeId,
        type: 'implant',
        position: { x: 0, y: 0 }, // Will be computed by ELK
        data: nodeData,
      });
    });

    // Process mesh links
    topologyData?.links?.forEach((link, index) => {
      const fromId = bytesToHex(link.fromId);
      const toId = bytesToHex(link.toId);
      const state = mapLinkState(link.state);

      edges.push({
        id: `edge-${index}`,
        source: fromId,
        target: toId,
        type: 'c2',
        data: {
          protocol: mapTransport(link.transport),
          state,
          latencyMs: link.latencyMs > 0 ? link.latencyMs : undefined,
          animated: state === 'established',
        },
      });
    });

    // Add edges from C2 to nodes with egress
    nodesWithEgress.forEach((nodeId) => {
      edges.push({
        id: `edge-c2-${nodeId}`,
        source: 'c2-server',
        target: nodeId,
        type: 'c2',
        data: {
          protocol: 'https',
          state: 'established',
          animated: true,
        },
      });
    });


    return { nodes, edges };
  }, [topologyData, implantsData]);

  // Handle node click - navigate to session detail
  const handleNodeClick = (nodeId: string) => {
    if (nodeId !== 'c2-server') {
      // Could show a tooltip or highlight
    }
  };

  // Handle node double click - navigate to session
  const handleNodeDoubleClick = (nodeId: string) => {
    if (nodeId !== 'c2-server') {
      navigate(`/sessions/${nodeId}`);
    }
  };

  if (topologyLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-subtext0">Loading topology...</div>
      </div>
    );
  }

  // Only the C2 server node present with no edges means no mesh implants yet
  if (nodes.length <= 1 && edges.length === 0) {
    return (
      <div className="h-full flex flex-col">
        <div className="flex-none px-6 py-4 border-b border-surface0">
          <h1 className="text-xl font-semibold text-text">Network Topology</h1>
          <p className="text-sm text-subtext0 mt-1">
            Visualize implant mesh network and pivot chains. Double-click a node to interact.
          </p>
        </div>
        <div className="flex-1 flex flex-col items-center justify-center text-ctp-subtext0">
          <svg className="w-16 h-16 mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          <h3 className="text-lg font-medium mb-2 text-ctp-subtext1">No Mesh Topology</h3>
          <p className="text-sm">Deploy implants with mesh capability to see the network topology.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-surface0">
        <h1 className="text-xl font-semibold text-text">Network Topology</h1>
        <p className="text-sm text-subtext0 mt-1">
          Visualize implant mesh network and pivot chains. Double-click a node to interact.
        </p>
      </div>

      {/* Graph */}
      <div className="flex-1 min-h-0">
        <TopologyGraph
          nodes={nodes}
          edges={edges}
          onNodeClick={handleNodeClick}
          onNodeDoubleClick={handleNodeDoubleClick}
        />
      </div>
    </div>
  );
}
