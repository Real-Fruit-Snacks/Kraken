import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { useRealtime } from '../hooks/useRealtime';
import { TaskEventData } from '../types/websocket';
import { jobClient } from '../api/client';
import { JobListRequest, GetJobOutputRequest, JobKillRequest } from '../gen/kraken_pb';
import { JobStatus as ProtoJobStatus } from '../gen/kraken_pb';
import type { Job, JobStatus } from '../types';

// Convert proto JobStatus enum to string
function protoStatusToString(status: number): JobStatus {
  switch (status) {
    case ProtoJobStatus.COMPLETED:
      return 'completed';
    case ProtoJobStatus.FAILED:
      return 'failed';
    case ProtoJobStatus.CANCELLED:
      return 'cancelled';
    case ProtoJobStatus.RUNNING:
    default:
      return 'running';
  }
}

// Convert task_id bytes to hex string for display
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function Jobs() {
  const queryClient = useQueryClient();
  const [selectedJob, setSelectedJob] = useState<Job | null>(null);
  const [filterStatus, setFilterStatus] = useState<string>('all');

  // Fetch jobs list
  const { data: jobs, isLoading } = useQuery({
    queryKey: ['jobs'],
    queryFn: async () => {
      const response = await jobClient.listJobs(new JobListRequest());
      return response.jobs.map(job => ({
        job_id: job.jobId,
        task_id: job.taskId,
        description: job.description,
        status: protoStatusToString(job.status),
        progress: job.progress,
        created_at: Number(job.createdAt),
        completed_at: job.completedAt ? Number(job.completedAt) : undefined,
      })) as Job[];
    },
  });

  // Kill job mutation
  const killJobMutation = useMutation({
    mutationFn: async (jobId: number) => {
      const request = new JobKillRequest({ jobId });
      return await jobClient.killJob(request);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
    },
  });

  // Real-time updates for job progress
  useRealtime<TaskEventData>('TaskComplete', (data) => {
    queryClient.setQueryData<Job[]>(['jobs'], (old) => {
      if (!old) return old;
      const taskIdHex = data.task_id;
      return old.map((job) => {
        const jobTaskIdHex = bytesToHex(job.task_id);
        return jobTaskIdHex === taskIdHex
          ? { ...job, status: 'completed' as JobStatus, progress: 100, completed_at: Date.now() }
          : job;
      });
    });
  });

  useRealtime<TaskEventData>('TaskFailed', (data) => {
    queryClient.setQueryData<Job[]>(['jobs'], (old) => {
      if (!old) return old;
      const taskIdHex = data.task_id;
      return old.map((job) => {
        const jobTaskIdHex = bytesToHex(job.task_id);
        return jobTaskIdHex === taskIdHex
          ? { ...job, status: 'failed' as JobStatus, completed_at: Date.now() }
          : job;
      });
    });
  });

  const filteredJobs = jobs?.filter((job) => {
    if (filterStatus === 'all') return true;
    if (filterStatus === 'running') return job.status === 'running';
    if (filterStatus === 'completed') return job.status === 'completed';
    if (filterStatus === 'failed') return job.status === 'failed';
    return true;
  });

  const formatDuration = (start: number, end?: number) => {
    const duration = (end || Date.now()) - start;
    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Background Jobs</h1>
        <div className="text-sm text-ctp-subtext0">
          {filteredJobs?.length ?? 0} jobs
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2 mb-4">
        {['all', 'running', 'completed', 'failed'].map((filter) => (
          <button
            key={filter}
            onClick={() => setFilterStatus(filter)}
            className={`px-3 py-1 rounded-full text-sm transition-colors capitalize ${
              filterStatus === filter
                ? 'bg-ctp-mauve text-ctp-crust'
                : 'bg-ctp-surface0 hover:bg-ctp-surface1'
            }`}
          >
            {filter}
          </button>
        ))}
      </div>

      {/* Jobs Table */}
      <div className="bg-ctp-mantle rounded-lg overflow-hidden border border-ctp-surface0">
        <table className="w-full">
          <thead className="bg-ctp-crust">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">ID</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Description</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Status</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Progress</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Duration</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-ctp-subtext0">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ctp-surface0">
            {isLoading ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-ctp-subtext0">
                  Loading jobs...
                </td>
              </tr>
            ) : filteredJobs?.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-ctp-subtext0">
                  No jobs found.
                </td>
              </tr>
            ) : (
              filteredJobs?.map((job) => (
                <tr
                  key={job.job_id}
                  className="hover:bg-ctp-surface0/30 cursor-pointer"
                  onClick={() => setSelectedJob(job)}
                >
                  <td className="px-4 py-3 font-mono text-sm">{job.job_id}</td>
                  <td className="px-4 py-3">{job.description}</td>
                  <td className="px-4 py-3">
                    <JobStatusBadge status={job.status} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2 bg-ctp-surface0 rounded-full overflow-hidden">
                        <div
                          className={`h-full transition-all ${
                            job.status === 'completed'
                              ? 'bg-ctp-green'
                              : job.status === 'failed'
                              ? 'bg-ctp-red'
                              : 'bg-ctp-mauve'
                          }`}
                          style={{ width: `${job.progress}%` }}
                        />
                      </div>
                      <span className="text-sm text-ctp-subtext0 w-12">{job.progress}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-ctp-subtext0">
                    {formatDuration(job.created_at, job.completed_at)}
                  </td>
                  <td className="px-4 py-3 flex gap-2" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => setSelectedJob(job)}
                      className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-mauve text-ctp-crust hover:bg-ctp-mauve/80"
                    >
                      View Output
                    </button>
                    {job.status === 'running' && (
                      <button
                        onClick={() => killJobMutation.mutate(job.job_id)}
                        disabled={killJobMutation.isPending}
                        className="px-3 py-1 text-xs font-medium rounded transition-colors bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/40 disabled:opacity-50"
                      >
                        {killJobMutation.isPending ? 'Killing...' : 'Kill'}
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Job Detail Modal */}
      {selectedJob && (
        <JobDetailModal
          job={selectedJob}
          onClose={() => setSelectedJob(null)}
          onKill={(jobId) => killJobMutation.mutate(jobId)}
        />
      )}
    </div>
  );
}

function JobStatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    running: 'bg-ctp-blue/20 text-ctp-blue',
    completed: 'bg-ctp-green/20 text-ctp-green',
    failed: 'bg-ctp-red/20 text-ctp-red',
    cancelled: 'bg-ctp-overlay0/20 text-ctp-overlay1',
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[status] || colors.running}`}>
      {status}
    </span>
  );
}

function JobDetailModal({ job, onClose, onKill }: { job: Job; onClose: () => void; onKill: (jobId: number) => void }) {
  const { data: output, isLoading: outputLoading } = useQuery({
    queryKey: ['job-output', job.job_id],
    queryFn: async () => {
      const request = new GetJobOutputRequest({ jobId: job.job_id });
      const response = await jobClient.getJobOutput(request);

      // Combine all output chunks
      const combinedOutput = response.outputChunks
        .map(chunk => new TextDecoder().decode(chunk))
        .join('');

      return {
        output: combinedOutput,
        isComplete: response.isComplete,
        finalStatus: response.finalStatus ? protoStatusToString(response.finalStatus) : undefined,
      };
    },
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="bg-ctp-mantle rounded-lg p-6 max-w-3xl w-full max-h-[80vh] overflow-auto border border-ctp-surface0"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-between items-start mb-4">
          <div>
            <h2 className="text-xl font-bold">Job #{job.job_id}</h2>
            <p className="text-sm text-ctp-subtext0">{job.description}</p>
          </div>
          <button
            onClick={onClose}
            className="text-ctp-subtext0 hover:text-ctp-text transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-xs text-ctp-subtext0 uppercase">Status</div>
              <div className="mt-1">
                <JobStatusBadge status={job.status} />
              </div>
            </div>
            <div>
              <div className="text-xs text-ctp-subtext0 uppercase">Progress</div>
              <div className="mt-1 text-sm">{job.progress}%</div>
            </div>
            <div>
              <div className="text-xs text-ctp-subtext0 uppercase">Task ID</div>
              <div className="mt-1 text-sm font-mono">{bytesToHex(job.task_id)}</div>
            </div>
            <div>
              <div className="text-xs text-ctp-subtext0 uppercase">Created</div>
              <div className="mt-1 text-sm">{new Date(job.created_at).toLocaleString()}</div>
            </div>
          </div>

          <div>
            <div className="text-xs text-ctp-subtext0 uppercase mb-2">Output</div>
            <div className="bg-ctp-base rounded-lg p-4 font-mono text-sm max-h-96 overflow-auto">
              {outputLoading ? (
                <div className="text-ctp-subtext0">Loading output...</div>
              ) : output?.output ? (
                <pre className="whitespace-pre-wrap">{output.output}</pre>
              ) : (
                <div className="text-ctp-subtext0">No output available yet...</div>
              )}
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-ctp-surface0">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm text-ctp-subtext1 hover:text-ctp-text transition-colors"
            >
              Close
            </button>
            {job.status === 'running' && (
              <button
                onClick={() => {
                  onKill(job.job_id);
                  onClose();
                }}
                className="px-4 py-2 text-sm bg-ctp-red/20 hover:bg-ctp-red/30 text-ctp-red rounded-lg font-medium transition-colors"
              >
                Kill Job
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
