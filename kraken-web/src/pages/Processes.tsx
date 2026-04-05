import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import { taskClient } from '../api/client';
import { DispatchTaskRequest, GetTaskRequest, TaskStatus } from '../gen/kraken_pb';

interface ProcessEntry {
  pid: number;
  name: string;
  path: string;
  user: string;
  cpuPercent: number;
  memoryBytes: number;
}

interface ProcessListResult {
  processes: ProcessEntry[];
}

type SortField = 'pid' | 'name' | 'path' | 'user' | 'cpu' | 'memory';
type SortOrder = 'asc' | 'desc';

export function Processes() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [searchQuery, setSearchQuery] = useState('');
  const [filterUser, setFilterUser] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('pid');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const queryClient = useQueryClient();

  // Fetch process list
  const { data: processResult, isLoading, refetch } = useQuery({
    queryKey: ['processes', sessionId],
    queryFn: async () => {
      if (!sessionId) return null;

      // Create ProcessTask with List operation
      const processTask = {
        operation: {
          case: 'list' as const,
          value: {},
        },
      };

      // Serialize ProcessTask to bytes
      const taskData = new TextEncoder().encode(JSON.stringify(processTask));

      // Dispatch task
      const dispatchRequest = new DispatchTaskRequest({
        implantId: { value: hexToBytes(sessionId) },
        taskType: 'process',
        taskData,
      });

      const dispatchResponse = await taskClient.dispatchTask(dispatchRequest);
      const taskId = dispatchResponse.taskId;

      if (!taskId) {
        throw new Error('No task ID returned from dispatch');
      }

      // Poll for task completion
      const maxAttempts = 30; // 30 seconds timeout
      for (let i = 0; i < maxAttempts; i++) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second

        const taskRequest = new GetTaskRequest({ taskId });
        const taskInfo = await taskClient.getTask(taskRequest);

        if (taskInfo.status === TaskStatus.COMPLETED) {
          // Parse result_data as JSON
          const resultJson = new TextDecoder().decode(taskInfo.resultData);
          const result = JSON.parse(resultJson) as ProcessListResult;
          return result;
        } else if (taskInfo.status === TaskStatus.FAILED || taskInfo.status === TaskStatus.CANCELLED) {
          throw new Error('Task failed or was cancelled');
        }
      }

      throw new Error('Task timed out waiting for result');
    },
    enabled: !!sessionId,
    retry: false,
    staleTime: 30000,
  });

  // Kill process mutation
  const killMutation = useMutation({
    mutationFn: async (pid: number) => {
      if (!sessionId) throw new Error('No session');

      const processTask = {
        operation: {
          case: 'kill' as const,
          value: {
            pid,
          },
        },
      };

      const taskData = new TextEncoder().encode(JSON.stringify(processTask));

      const request = new DispatchTaskRequest({
        implantId: { value: hexToBytes(sessionId) },
        taskType: 'process',
        taskData,
      });

      await taskClient.dispatchTask(request);
    },
    onSuccess: () => {
      // Refetch process list after kill
      queryClient.invalidateQueries({ queryKey: ['processes', sessionId] });
    },
  });

  const handleKill = (process: ProcessEntry) => {
    if (confirm(`Kill process ${process.name} (PID ${process.pid})? This cannot be undone.`)) {
      killMutation.mutate(process.pid);
    }
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  // Get unique users for filter
  const uniqueUsers = Array.from(
    new Set(processResult?.processes.map(p => p.user) || [])
  ).sort();

  // Filter and sort processes
  const filteredProcesses = processResult?.processes
    .filter((process) => {
      // Search filter
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch =
        searchQuery === '' ||
        process.name.toLowerCase().includes(searchLower) ||
        process.path.toLowerCase().includes(searchLower) ||
        process.pid.toString().includes(searchQuery);

      // User filter
      const matchesUser = filterUser === 'all' || process.user === filterUser;

      return matchesSearch && matchesUser;
    })
    .sort((a, b) => {
      let aVal: string | number;
      let bVal: string | number;

      switch (sortField) {
        case 'pid':
          aVal = a.pid;
          bVal = b.pid;
          break;
        case 'name':
          aVal = a.name;
          bVal = b.name;
          break;
        case 'path':
          aVal = a.path;
          bVal = b.path;
          break;
        case 'user':
          aVal = a.user;
          bVal = b.user;
          break;
        case 'cpu':
          aVal = a.cpuPercent;
          bVal = b.cpuPercent;
          break;
        case 'memory':
          aVal = a.memoryBytes;
          bVal = b.memoryBytes;
          break;
        default:
          aVal = a.pid;
          bVal = b.pid;
      }

      if (typeof aVal === 'string' && typeof bVal === 'string') {
        return sortOrder === 'asc'
          ? aVal.localeCompare(bVal)
          : bVal.localeCompare(aVal);
      }

      return sortOrder === 'asc'
        ? (aVal as number) - (bVal as number)
        : (bVal as number) - (aVal as number);
    });

  if (!sessionId) {
    return (
      <div className="text-center py-12">
        <p className="text-ctp-subtext0">No session selected. Go to Sessions page to select an implant.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Process List</h1>
        <button
          onClick={() => refetch()}
          disabled={isLoading}
          className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium text-ctp-crust transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {/* Filters */}
      <div className="mb-4 flex gap-4">
        {/* Search Input */}
        <div className="flex-1">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by name, path, or PID..."
            className="w-full px-4 py-2 bg-ctp-surface0 border border-ctp-surface1 rounded-lg text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:ring-2 focus:ring-ctp-mauve"
          />
        </div>

        {/* User Filter */}
        <div>
          <select
            value={filterUser}
            onChange={(e) => setFilterUser(e.target.value)}
            className="px-4 py-2 bg-ctp-surface0 border border-ctp-surface1 rounded-lg text-ctp-text focus:outline-none focus:ring-2 focus:ring-ctp-mauve"
          >
            <option value="all">All Users</option>
            {uniqueUsers.map((user) => (
              <option key={user} value={user}>
                {user}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Stats */}
      {filteredProcesses && (
        <div className="mb-4 text-sm text-ctp-subtext0">
          Showing {filteredProcesses.length} of {processResult?.processes.length || 0} processes
        </div>
      )}

      {/* Process Table */}
      <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
        <table className="w-full">
          <thead className="bg-ctp-crust">
            <tr>
              <SortableHeader field="pid" label="PID" currentField={sortField} order={sortOrder} onSort={handleSort} />
              <SortableHeader field="name" label="Name" currentField={sortField} order={sortOrder} onSort={handleSort} />
              <SortableHeader field="path" label="Path" currentField={sortField} order={sortOrder} onSort={handleSort} />
              <SortableHeader field="user" label="User" currentField={sortField} order={sortOrder} onSort={handleSort} />
              <SortableHeader field="cpu" label="CPU %" currentField={sortField} order={sortOrder} onSort={handleSort} />
              <SortableHeader field="memory" label="Memory" currentField={sortField} order={sortOrder} onSort={handleSort} />
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ctp-surface0">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-ctp-subtext0">
                  Loading processes...
                </td>
              </tr>
            ) : filteredProcesses?.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-ctp-subtext0">
                  No processes found.
                </td>
              </tr>
            ) : (
              filteredProcesses?.map((process) => (
                <tr
                  key={process.pid}
                  className="hover:bg-ctp-surface0/30"
                >
                  <td className="px-4 py-3 font-mono text-sm">{process.pid}</td>
                  <td className="px-4 py-3 font-medium">{process.name}</td>
                  <td className="px-4 py-3 text-sm text-ctp-subtext0 truncate max-w-md" title={process.path}>
                    {process.path}
                  </td>
                  <td className="px-4 py-3 text-sm">{process.user}</td>
                  <td className="px-4 py-3 text-sm">
                    <span className={`${
                      process.cpuPercent > 50 ? 'text-ctp-red' :
                      process.cpuPercent > 20 ? 'text-ctp-yellow' :
                      'text-ctp-text'
                    }`}>
                      {process.cpuPercent.toFixed(1)}%
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{formatMemory(process.memoryBytes)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleKill(process)}
                      disabled={killMutation.isPending}
                      className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/40 disabled:opacity-50"
                    >
                      Kill
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Sortable header component
function SortableHeader({
  field,
  label,
  currentField,
  order,
  onSort,
}: {
  field: SortField;
  label: string;
  currentField: SortField;
  order: SortOrder;
  onSort: (field: SortField) => void;
}) {
  const isActive = currentField === field;

  return (
    <th
      className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0 cursor-pointer hover:text-ctp-text transition-colors select-none"
      onClick={() => onSort(field)}
    >
      <div className="flex items-center gap-2">
        {label}
        <div className="flex flex-col">
          <svg
            className={`w-3 h-3 ${isActive && order === 'asc' ? 'text-ctp-mauve' : 'text-ctp-surface1'}`}
            fill="currentColor"
            viewBox="0 0 20 20"
          >
            <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
          </svg>
        </div>
      </div>
    </th>
  );
}

// Helper functions
function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function formatMemory(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
