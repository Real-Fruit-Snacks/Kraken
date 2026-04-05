import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import { taskClient } from '../api/client';
import { DispatchTaskRequest, GetTaskRequest, TaskStatus, ListActiveTransfersRequest } from '../gen/kraken_pb';

interface FileEntry {
  name: string;
  path: string;
  size: number;
  isDirectory: boolean;
  modified: number;
  permissions?: string;
}

interface FileListResult {
  entries: FileEntry[];
  currentPath: string;
}

interface ActiveTransfer {
  transferId: string;
  filePath: string;
  totalSize: number;
  bytesTransferred: number;
  state: string;
  error?: string;
}

export function Files() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [currentPath, setCurrentPath] = useState('/');
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadPath, setUploadPath] = useState('');
  const queryClient = useQueryClient();

  // Fetch file list for current directory
  const { data: fileList, isLoading } = useQuery({
    queryKey: ['files', sessionId, currentPath],
    queryFn: async () => {
      if (!sessionId) return null;

      // Create FileTask with FileList operation
      const fileTask = {
        operation: {
          case: 'list' as const,
          value: {
            path: currentPath,
            recursive: false,
          },
        },
      };

      // Serialize FileTask to bytes
      const taskData = new TextEncoder().encode(JSON.stringify(fileTask));

      // Dispatch task
      const dispatchRequest = new DispatchTaskRequest({
        implantId: { value: hexToBytes(sessionId) },
        taskType: 'file',
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
          const result = JSON.parse(resultJson) as FileListResult;

          // Add parent directory entry if not at root
          if (currentPath !== '/') {
            result.entries = [
              {
                name: '..',
                path: getParentPath(currentPath),
                size: 0,
                isDirectory: true,
                modified: Date.now(),
              },
              ...result.entries,
            ];
          }

          return result;
        } else if (taskInfo.status === TaskStatus.FAILED || taskInfo.status === TaskStatus.CANCELLED) {
          throw new Error('Task failed or was cancelled');
        }
      }

      throw new Error('Task timed out waiting for result');
    },
    enabled: !!sessionId,
    retry: false, // Don't retry on failure
    staleTime: 30000, // Consider data fresh for 30 seconds
  });

  // Fetch active transfers for this session
  const { data: activeTransfers } = useQuery({
    queryKey: ['transfers', sessionId],
    queryFn: async () => {
      if (!sessionId) return [];

      const request = new ListActiveTransfersRequest({
        implantId: { value: hexToBytes(sessionId) },
      });

      const response = await taskClient.listActiveTransfers(request);

      return response.transfers.map(t => ({
        transferId: t.transferId,
        filePath: t.filePath,
        totalSize: Number(t.totalSize),
        bytesTransferred: Number(t.bytesTransferred),
        state: getTransferStateName(t.state),
        error: t.error,
      })) as ActiveTransfer[];
    },
    enabled: !!sessionId,
    refetchInterval: 1000, // Poll every second for progress updates
  });

  // Download file mutation
  const downloadMutation = useMutation({
    mutationFn: async (file: FileEntry) => {
      if (!sessionId) throw new Error('No session');

      const fileTask = {
        operation: {
          case: 'download' as const,
          value: {
            remotePath: file.path,
          },
        },
      };

      const taskData = new TextEncoder().encode(JSON.stringify(fileTask));

      const request = new DispatchTaskRequest({
        implantId: { value: hexToBytes(sessionId) },
        taskType: 'file',
        taskData,
      });

      await taskClient.dispatchTask(request);
    },
    onSuccess: () => {
      // Refetch transfers to show new download progress
      queryClient.invalidateQueries({ queryKey: ['transfers', sessionId] });
    },
  });

  // Upload file mutation
  const uploadMutation = useMutation({
    mutationFn: async ({ file, remotePath }: { file: File; remotePath: string }) => {
      if (!sessionId) throw new Error('No session');

      const CHUNK_SIZE = 1024 * 1024; // 1MB chunks
      const MAX_SIMPLE_UPLOAD = 10 * 1024 * 1024; // 10MB threshold

      if (file.size <= MAX_SIMPLE_UPLOAD) {
        // Simple upload for small files
        const fileData = await file.arrayBuffer();
        const fileTask = {
          operation: {
            case: 'upload' as const,
            value: {
              remotePath,
              data: new Uint8Array(fileData),
            },
          },
        };

        const taskData = new TextEncoder().encode(JSON.stringify(fileTask));
        const request = new DispatchTaskRequest({
          implantId: { value: hexToBytes(sessionId) },
          taskType: 'file',
          taskData,
        });

        await taskClient.dispatchTask(request);
      } else {
        // Chunked upload for large files
        const transferId = crypto.randomUUID();
        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

        for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
          const start = chunkIndex * CHUNK_SIZE;
          const end = Math.min(start + CHUNK_SIZE, file.size);
          const chunkData = await file.slice(start, end).arrayBuffer();

          // Calculate SHA256 checksum for this chunk
          const hashBuffer = await crypto.subtle.digest('SHA-256', chunkData);

          const fileTask = {
            operation: {
              case: 'upload_chunked' as const,
              value: {
                transferId,
                remotePath,
                totalSize: file.size,
                chunkIndex,
                totalChunks,
                chunkData: new Uint8Array(chunkData),
                checksum: new Uint8Array(hashBuffer),
              },
            },
          };

          const taskData = new TextEncoder().encode(JSON.stringify(fileTask));
          const request = new DispatchTaskRequest({
            implantId: { value: hexToBytes(sessionId) },
            taskType: 'file',
            taskData,
          });

          await taskClient.dispatchTask(request);
        }
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['files', sessionId, currentPath] });
      queryClient.invalidateQueries({ queryKey: ['transfers', sessionId] });
      setUploadModalOpen(false);
      setSelectedFile(null);
      setUploadPath('');
    },
  });

  // Delete file mutation
  const deleteMutation = useMutation({
    mutationFn: async (file: FileEntry) => {
      if (!sessionId) throw new Error('No session');

      const fileTask = {
        operation: {
          case: 'delete' as const,
          value: {
            path: file.path,
            recursive: file.isDirectory,
          },
        },
      };

      const taskData = new TextEncoder().encode(JSON.stringify(fileTask));

      const request = new DispatchTaskRequest({
        implantId: { value: hexToBytes(sessionId) },
        taskType: 'file',
        taskData,
      });

      await taskClient.dispatchTask(request);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['files', sessionId, currentPath] });
    },
  });

  const navigateToDirectory = (path: string) => {
    setCurrentPath(path);
  };

  const handleDownload = (file: FileEntry) => {
    if (confirm(`Download ${file.name}?`)) {
      downloadMutation.mutate(file);
    }
  };

  const handleDelete = (file: FileEntry) => {
    if (confirm(`Delete ${file.name}? This cannot be undone.`)) {
      deleteMutation.mutate(file);
    }
  };

  const handleUpload = () => {
    if (!selectedFile) return;

    const remotePath = uploadPath || `${currentPath}/${selectedFile.name}`;
    uploadMutation.mutate({ file: selectedFile, remotePath });
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setUploadPath(`${currentPath}/${file.name}`);
    }
  };

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
        <h1 className="text-2xl font-bold">File Browser</h1>
        <button
          onClick={() => setUploadModalOpen(true)}
          className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium text-ctp-crust transition-colors"
        >
          Upload File
        </button>
      </div>

      {/* Breadcrumb navigation */}
      <div className="mb-4 flex items-center gap-2 text-sm">
        <button
          onClick={() => navigateToDirectory('/')}
          className="text-ctp-mauve hover:underline"
        >
          Root
        </button>
        {currentPath.split('/').filter(Boolean).map((part, idx, arr) => {
          const path = '/' + arr.slice(0, idx + 1).join('/');
          return (
            <span key={path} className="flex items-center gap-2">
              <span className="text-ctp-subtext0">/</span>
              <button
                onClick={() => navigateToDirectory(path)}
                className="text-ctp-mauve hover:underline"
              >
                {part}
              </button>
            </span>
          );
        })}
      </div>

      {/* Active Transfers */}
      {activeTransfers && activeTransfers.length > 0 && (
        <div className="mb-4 bg-ctp-mantle rounded-lg border border-ctp-surface0 p-4">
          <h3 className="text-sm font-medium text-ctp-subtext0 mb-3">Active Transfers</h3>
          <div className="space-y-3">
            {activeTransfers.map((transfer) => {
              const progress = transfer.totalSize > 0
                ? (transfer.bytesTransferred / transfer.totalSize) * 100
                : 0;

              return (
                <div key={transfer.transferId} className="space-y-1">
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-ctp-text truncate flex-1">{transfer.filePath}</span>
                    <span className={`ml-2 px-2 py-0.5 rounded text-xs font-medium ${
                      transfer.state === 'completed' ? 'bg-ctp-green/20 text-ctp-green' :
                      transfer.state === 'failed' ? 'bg-ctp-red/20 text-ctp-red' :
                      transfer.state === 'in_progress' ? 'bg-ctp-blue/20 text-ctp-blue' :
                      'bg-ctp-surface0 text-ctp-subtext0'
                    }`}>
                      {transfer.state}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-ctp-surface0 rounded-full h-2 overflow-hidden">
                      <div
                        className="h-full bg-ctp-mauve transition-all duration-300"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                    <span className="text-xs text-ctp-subtext0 min-w-[80px] text-right">
                      {formatFileSize(transfer.bytesTransferred)} / {formatFileSize(transfer.totalSize)}
                    </span>
                  </div>
                  {transfer.error && (
                    <p className="text-xs text-ctp-red">{transfer.error}</p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* File list */}
      <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
        <table className="w-full">
          <thead className="bg-ctp-crust">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Name</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Size</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Modified</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Permissions</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ctp-surface0">
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-ctp-subtext0">
                  Loading files...
                </td>
              </tr>
            ) : fileList?.entries.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-ctp-subtext0">
                  No files found.
                </td>
              </tr>
            ) : (
              fileList?.entries.map((file) => (
                <tr
                  key={file.path}
                  className="hover:bg-ctp-surface0/30 cursor-pointer"
                  onClick={() => file.isDirectory && navigateToDirectory(file.path)}
                >
                  <td className="px-4 py-3 flex items-center gap-2">
                    {file.isDirectory ? (
                      <svg className="w-5 h-5 text-ctp-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                      </svg>
                    ) : (
                      <svg className="w-5 h-5 text-ctp-text" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                      </svg>
                    )}
                    <span className={file.isDirectory ? 'font-medium text-ctp-blue' : ''}>
                      {file.name}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-ctp-subtext0">
                    {file.isDirectory ? '-' : formatFileSize(file.size)}
                  </td>
                  <td className="px-4 py-3 text-sm text-ctp-subtext0">
                    {new Date(file.modified).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-sm text-ctp-subtext0 font-mono">
                    {file.permissions || '-'}
                  </td>
                  <td className="px-4 py-3 flex gap-2" onClick={(e) => e.stopPropagation()}>
                    {!file.isDirectory && file.name !== '..' && (
                      <>
                        <button
                          onClick={() => handleDownload(file)}
                          disabled={downloadMutation.isPending}
                          className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-green/20 text-ctp-green hover:bg-ctp-green/40 disabled:opacity-50"
                        >
                          Download
                        </button>
                        <button
                          onClick={() => handleDelete(file)}
                          disabled={deleteMutation.isPending}
                          className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/40 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Upload Modal */}
      {uploadModalOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-ctp-mantle rounded-lg p-6 max-w-md w-full">
            <h2 className="text-xl font-bold mb-4">Upload File</h2>

            <div className="space-y-4">
              {/* File Selection */}
              <div>
                <label className="block text-sm font-medium text-ctp-subtext0 mb-2">
                  Select File
                </label>
                <input
                  type="file"
                  onChange={handleFileSelect}
                  className="block w-full text-sm text-ctp-text
                    file:mr-4 file:py-2 file:px-4
                    file:rounded-lg file:border-0
                    file:text-sm file:font-medium
                    file:bg-ctp-mauve file:text-ctp-crust
                    hover:file:bg-ctp-mauve/80
                    file:cursor-pointer cursor-pointer"
                />
              </div>

              {/* Upload Path */}
              {selectedFile && (
                <div>
                  <label className="block text-sm font-medium text-ctp-subtext0 mb-2">
                    Remote Path
                  </label>
                  <input
                    type="text"
                    value={uploadPath}
                    onChange={(e) => setUploadPath(e.target.value)}
                    placeholder="/path/to/destination"
                    className="w-full px-3 py-2 bg-ctp-surface0 border border-ctp-surface1 rounded-lg text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:ring-2 focus:ring-ctp-mauve"
                  />
                  <p className="mt-1 text-xs text-ctp-subtext0">
                    File size: {formatFileSize(selectedFile.size)}
                    {selectedFile.size > 10 * 1024 * 1024 && (
                      <span className="ml-2 text-ctp-yellow">
                        (will use chunked upload)
                      </span>
                    )}
                  </p>
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setUploadModalOpen(false);
                  setSelectedFile(null);
                  setUploadPath('');
                }}
                disabled={uploadMutation.isPending}
                className="flex-1 px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleUpload}
                disabled={!selectedFile || uploadMutation.isPending}
                className="flex-1 px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium text-ctp-crust transition-colors disabled:opacity-50"
              >
                {uploadMutation.isPending ? 'Uploading...' : 'Upload'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
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

function getParentPath(path: string): string {
  if (path === '/') return '/';
  const parts = path.split('/').filter(Boolean);
  parts.pop();
  return '/' + parts.join('/');
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function getTransferStateName(state: number): string {
  switch (state) {
    case 1: return 'initializing';
    case 2: return 'in_progress';
    case 3: return 'paused';
    case 4: return 'completed';
    case 5: return 'failed';
    default: return 'unknown';
  }
}
