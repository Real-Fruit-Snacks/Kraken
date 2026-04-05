import { useState, useEffect, useCallback, useRef } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { taskClient } from '../../api';
import { Modal } from '../Modal';
import {
  FileTask,
  FileList,
  FileRead,
  FileDownload,
  FileUpload,
  DirectoryListing,
  FileContents,
  TaskStatus,
} from '../../gen/kraken_pb.js';
import type { TaskInfo } from '../../gen/kraken_pb.js';

interface FileBrowserProps {
  sessionId: string;
  osName?: string;
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function isWindows(osName: string | undefined): boolean {
  return osName?.toLowerCase().includes('windows') ?? false;
}

function getDefaultPath(osName: string | undefined): string {
  return isWindows(osName) ? 'C:\\' : '/';
}

function getPathSeparator(osName: string | undefined): string {
  return isWindows(osName) ? '\\' : '/';
}

function joinPath(basePath: string, name: string, osName: string | undefined): string {
  const sep = getPathSeparator(osName);
  if (basePath.endsWith(sep)) {
    return basePath + name;
  }
  return basePath + sep + name;
}

function getParentPath(path: string, osName: string | undefined): string | null {
  const sep = getPathSeparator(osName);
  const isWin = isWindows(osName);

  // Handle root cases
  if (isWin) {
    // Windows: C:\ or similar
    if (/^[A-Za-z]:\\?$/.test(path)) return null;
  } else {
    if (path === '/') return null;
  }

  // Remove trailing separator
  let normalized = path.endsWith(sep) ? path.slice(0, -1) : path;
  const lastSepIndex = normalized.lastIndexOf(sep);

  if (lastSepIndex === -1) return null;

  // For Windows, keep the backslash after drive letter
  if (isWin && lastSepIndex === 2) {
    return normalized.slice(0, 3);
  }

  // For Unix root
  if (!isWin && lastSepIndex === 0) {
    return '/';
  }

  return normalized.slice(0, lastSepIndex);
}

function parseBreadcrumbs(path: string, osName: string | undefined): { name: string; path: string }[] {
  const isWin = isWindows(osName);
  const parts: { name: string; path: string }[] = [];

  if (isWin) {
    // Windows path: C:\Users\foo
    const match = path.match(/^([A-Za-z]:)(\\.*)?$/);
    if (match) {
      parts.push({ name: match[1], path: match[1] + '\\' });
      if (match[2]) {
        const subParts = match[2].split('\\').filter(Boolean);
        let currentPath = match[1] + '\\';
        for (const part of subParts) {
          currentPath += part + '\\';
          parts.push({ name: part, path: currentPath.slice(0, -1) });
        }
      }
    }
  } else {
    // Unix path: /home/user
    parts.push({ name: '/', path: '/' });
    const subParts = path.split('/').filter(Boolean);
    let currentPath = '/';
    for (const part of subParts) {
      currentPath += part + '/';
      parts.push({ name: part, path: currentPath.slice(0, -1) });
    }
  }

  return parts;
}

function formatSize(bytes: bigint | number): string {
  const n = typeof bytes === 'bigint' ? Number(bytes) : bytes;
  if (n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function formatDate(timestamp: bigint | undefined): string {
  if (!timestamp) return '-';
  const date = new Date(Number(timestamp) * 1000);
  return date.toLocaleString();
}

interface DirectoryEntry {
  name: string;
  isDir: boolean;
  size: bigint;
  modified?: bigint;
  permissions?: string;
}

export function FileBrowser({ sessionId, osName }: FileBrowserProps) {
  const [currentPath, setCurrentPath] = useState(() => getDefaultPath(osName));
  const [entries, setEntries] = useState<DirectoryEntry[]>([]);
  const [pendingTaskId, setPendingTaskId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [viewingFile, setViewingFile] = useState<{ path: string; content: string } | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Dispatch file list task
  const listMutation = useMutation({
    mutationFn: async (path: string) => {
      const fileList = new FileList({ path, recursive: false });
      const fileTask = new FileTask({ operation: { case: 'list', value: fileList } });
      const taskData = new Uint8Array(fileTask.toBinary()) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'file',
        taskData,
      });

      return response.taskId;
    },
    onSuccess: (taskId) => {
      if (taskId?.value) {
        const hex = Array.from(taskId.value).map(b => b.toString(16).padStart(2, '0')).join('');
        setPendingTaskId(hex);
      }
    },
    onError: (err) => {
      setError(err instanceof Error ? err.message : 'Failed to list directory');
    },
  });

  // Poll for task completion
  const { data: tasks } = useQuery({
    queryKey: ['tasks', sessionId],
    queryFn: async () => {
      const response = await taskClient.listTasks({
        implantId: { value: hexToUint8Array(sessionId) },
        limit: 50,
      });
      return response.tasks ?? [];
    },
    refetchInterval: pendingTaskId ? 1000 : false,
    enabled: !!pendingTaskId,
  });

  // Process completed task
  useEffect(() => {
    if (!pendingTaskId || !tasks) return;

    const task = tasks.find((t: TaskInfo) => {
      const taskHex = t.taskId?.value
        ? Array.from(t.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      return taskHex === pendingTaskId;
    });

    if (!task) return;

    if (task.status === TaskStatus.COMPLETED && task.resultData && task.resultData.length > 0) {
      try {
        const listing = DirectoryListing.fromBinary(task.resultData);
        setEntries(listing.entries.map(e => ({
          name: e.name,
          isDir: e.isDir,
          size: e.size,
          modified: e.modified,
          permissions: e.permissions,
        })));
        setError(null);
      } catch (err) {
        // Maybe it's file contents (from read operation)
        try {
          const contents = FileContents.fromBinary(task.resultData);
          const decoder = new TextDecoder();
          setViewingFile({
            path: contents.path,
            content: decoder.decode(contents.data),
          });
        } catch {
          setError('Failed to parse response');
        }
      }
      setPendingTaskId(null);
    } else if (task.status === TaskStatus.FAILED) {
      setError('Task failed');
      setPendingTaskId(null);
    }
  }, [pendingTaskId, tasks]);

  // Initial load
  useEffect(() => {
    listMutation.mutate(currentPath);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const navigateTo = useCallback((path: string) => {
    setCurrentPath(path);
    setEntries([]);
    setError(null);
    listMutation.mutate(path);
  }, [listMutation]);

  const handleEntryClick = useCallback((entry: DirectoryEntry) => {
    if (entry.isDir) {
      navigateTo(joinPath(currentPath, entry.name, osName));
    }
  }, [currentPath, osName, navigateTo]);

  const handleReadFile = useCallback((entry: DirectoryEntry) => {
    const fullPath = joinPath(currentPath, entry.name, osName);
    const fileRead = new FileRead({ path: fullPath });
    const fileTask = new FileTask({ operation: { case: 'read', value: fileRead } });
    const taskData = new Uint8Array(fileTask.toBinary()) as Uint8Array<ArrayBuffer>;

    taskClient.dispatchTask({
      implantId: { value: hexToUint8Array(sessionId) },
      taskType: 'file',
      taskData,
    }).then((response) => {
      if (response.taskId?.value) {
        const hex = Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('');
        setPendingTaskId(hex);
      }
    }).catch((err) => {
      setError(err instanceof Error ? err.message : 'Failed to read file');
    });
  }, [currentPath, osName, sessionId]);

  const handleDownload = useCallback((entry: DirectoryEntry) => {
    const fullPath = joinPath(currentPath, entry.name, osName);
    const fileDownload = new FileDownload({ remotePath: fullPath });
    const fileTask = new FileTask({ operation: { case: 'download', value: fileDownload } });
    const taskData = new Uint8Array(fileTask.toBinary()) as Uint8Array<ArrayBuffer>;

    taskClient.dispatchTask({
      implantId: { value: hexToUint8Array(sessionId) },
      taskType: 'file',
      taskData,
    }).then(() => {
      // Download task dispatched - result will come through task stream
    }).catch((err) => {
      setError(err instanceof Error ? err.message : 'Failed to download file');
    });
  }, [currentPath, osName, sessionId]);

  const handleRefresh = useCallback(() => {
    listMutation.mutate(currentPath);
  }, [currentPath, listMutation]);

  const handleGoUp = useCallback(() => {
    const parent = getParentPath(currentPath, osName);
    if (parent) {
      navigateTo(parent);
    }
  }, [currentPath, osName, navigateTo]);

  const handleUploadFile = useCallback(async (file: File) => {
    const remotePath = joinPath(currentPath, file.name, osName);
    setIsUploading(true);
    setUploadProgress(`Uploading ${file.name}...`);
    setError(null);
    try {
      const arrayBuffer = await file.arrayBuffer();
      const data = new Uint8Array(arrayBuffer) as Uint8Array<ArrayBuffer>;
      const fileUpload = new FileUpload({ remotePath, data });
      const fileTask = new FileTask({ operation: { case: 'upload', value: fileUpload } });
      const taskData = new Uint8Array(fileTask.toBinary()) as Uint8Array<ArrayBuffer>;
      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType: 'file',
        taskData,
      });
      setUploadProgress(null);
      listMutation.mutate(currentPath);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to upload file');
      setUploadProgress(null);
    } finally {
      setIsUploading(false);
    }
  }, [currentPath, osName, sessionId, listMutation]);

  const handleUploadClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleFileInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleUploadFile(file);
    }
    // Reset input so the same file can be re-selected
    e.target.value = '';
  }, [handleUploadFile]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleUploadFile(file);
    }
  }, [handleUploadFile]);

  const breadcrumbs = parseBreadcrumbs(currentPath, osName);
  const isLoading = listMutation.isPending || !!pendingTaskId;
  const sortedEntries = [...entries].sort((a, b) => {
    // Directories first
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-ctp-surface0 bg-ctp-crust">
        <button
          onClick={handleGoUp}
          disabled={!getParentPath(currentPath, osName) || isLoading}
          className="p-1.5 rounded hover:bg-ctp-surface0 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          title="Go up"
        >
          <svg className="w-4 h-4 text-ctp-subtext0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
          </svg>
        </button>
        <button
          onClick={handleRefresh}
          disabled={isLoading}
          className="p-1.5 rounded hover:bg-ctp-surface0 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          title="Refresh"
        >
          <svg className={`w-4 h-4 text-ctp-subtext0 ${isLoading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
        <button
          onClick={handleUploadClick}
          disabled={isUploading || isLoading}
          className="p-1.5 rounded hover:bg-ctp-surface0 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          title="Upload file"
        >
          <svg className="w-4 h-4 text-ctp-subtext0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
          </svg>
        </button>
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={handleFileInputChange}
        />
        <div className="h-4 w-px bg-ctp-surface0" />
        {/* Breadcrumbs */}
        <div className="flex items-center gap-1 text-sm overflow-x-auto">
          {breadcrumbs.map((crumb, i) => (
            <span key={crumb.path} className="flex items-center">
              {i > 0 && <span className="text-ctp-overlay0 mx-1">/</span>}
              <button
                onClick={() => navigateTo(crumb.path)}
                disabled={isLoading}
                className="text-ctp-blue hover:text-ctp-sapphire hover:underline disabled:opacity-50 disabled:no-underline"
              >
                {crumb.name}
              </button>
            </span>
          ))}
        </div>
      </div>

      {/* Error display */}
      {error && (
        <div className="px-4 py-2 bg-ctp-red/20 text-ctp-red text-sm">
          {error}
        </div>
      )}

      {/* Upload progress */}
      {uploadProgress && (
        <div className="px-4 py-2 bg-ctp-blue/10 text-ctp-blue text-sm flex items-center gap-2">
          <svg className="w-4 h-4 animate-spin shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          {uploadProgress}
        </div>
      )}

      {/* File list */}
      <div
        className={`flex-1 overflow-auto relative transition-colors ${dragOver ? 'ring-2 ring-inset ring-ctp-blue bg-ctp-blue/5' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {dragOver && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
            <div className="bg-ctp-base border-2 border-dashed border-ctp-blue rounded-lg px-8 py-6 text-ctp-blue text-sm font-medium">
              Drop file to upload
            </div>
          </div>
        )}
        {isLoading && entries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-ctp-subtext0">
            Loading...
          </div>
        ) : sortedEntries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-ctp-subtext0">
            Empty directory
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-ctp-crust sticky top-0">
              <tr className="text-left text-ctp-subtext0">
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium w-24 text-right">Size</th>
                <th className="px-4 py-2 font-medium w-44">Modified</th>
                <th className="px-4 py-2 font-medium w-24">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {sortedEntries.map((entry) => (
                <tr
                  key={entry.name}
                  className="hover:bg-ctp-surface0/50 cursor-pointer"
                  onClick={() => handleEntryClick(entry)}
                >
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      {entry.isDir ? (
                        <svg className="w-4 h-4 text-ctp-yellow" fill="currentColor" viewBox="0 0 20 20">
                          <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                        </svg>
                      ) : (
                        <svg className="w-4 h-4 text-ctp-subtext0" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
                        </svg>
                      )}
                      <span className="text-ctp-text truncate">{entry.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2 text-right text-ctp-subtext0 font-mono text-xs">
                    {entry.isDir ? '-' : formatSize(entry.size)}
                  </td>
                  <td className="px-4 py-2 text-ctp-subtext0 text-xs">
                    {formatDate(entry.modified)}
                  </td>
                  <td className="px-4 py-2">
                    {!entry.isDir && (
                      <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleReadFile(entry)}
                          className="p-1 rounded hover:bg-ctp-surface1 text-ctp-blue"
                          title="View"
                        >
                          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => handleDownload(entry)}
                          className="p-1 rounded hover:bg-ctp-surface1 text-ctp-green"
                          title="Download"
                        >
                          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                          </svg>
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* File viewer modal */}
      <Modal
        isOpen={!!viewingFile}
        onClose={() => setViewingFile(null)}
        title={viewingFile?.path || 'File'}
        size="xl"
      >
        <pre className="text-xs font-mono text-ctp-text whitespace-pre-wrap">
          {viewingFile?.content}
        </pre>
      </Modal>
    </div>
  );
}
