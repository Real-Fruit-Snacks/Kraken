// Reports - Engagement reporting and export functionality
// Supports PDF, JSON, Markdown, and CSV exports

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Modal } from '../components/Modal';
import { implantClient, taskClient, lootClient, reportClient } from '../api/index.js';
import type { ReportRecord } from '../api/index.js';
import { Timestamp } from '../gen/kraken_pb.js';

type ReportType = 'engagement' | 'ioc' | 'executive' | 'timeline' | 'loot';
type OutputFormat = 'pdf' | 'json' | 'markdown' | 'csv' | 'html';

interface GeneratedReport {
  id: string;
  title: string;
  reportType: ReportType;
  outputFormat: OutputFormat;
  generatedAt: Date;
  generatedBy: string;
  dateRange: { start: string; end: string };
  sessionCount: number;
  taskCount: number;
  size: number;
  content: string;
}

interface ReportFormState {
  title: string;
  reportType: ReportType;
  dateRange: { start: string; end: string };
  outputFormat: OutputFormat;
  includeSessions: boolean;
  includeTasks: boolean;
  includeLoot: boolean;
  includeTimeline: boolean;
  includeIOCs: boolean;
}

const REPORT_TYPE_INFO: Record<ReportType, { label: string; description: string; icon: string }> = {
  engagement: {
    label: 'Engagement Report',
    description: 'Full report with sessions, tasks, and findings',
    icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  },
  ioc: {
    label: 'IOC Report',
    description: 'Indicators of compromise for blue team',
    icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
  },
  executive: {
    label: 'Executive Summary',
    description: 'High-level overview for stakeholders',
    icon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  },
  timeline: {
    label: 'Activity Timeline',
    description: 'Chronological event log for analysis',
    icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
  },
  loot: {
    label: 'Loot Summary',
    description: 'Collected credentials and files',
    icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
  },
};

const OUTPUT_FORMAT_INFO: Record<OutputFormat, { label: string; ext: string; mime: string }> = {
  pdf: { label: 'PDF', ext: '.pdf', mime: 'application/pdf' },
  json: { label: 'JSON', ext: '.json', mime: 'application/json' },
  markdown: { label: 'Markdown', ext: '.md', mime: 'text/markdown' },
  csv: { label: 'CSV', ext: '.csv', mime: 'text/csv' },
  html: { label: 'HTML', ext: '.html', mime: 'text/html' },
};

function markdownToHtml(md: string): string {
  let html = md
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^## (.*$)/gim, '<h2>$1</h2>')
    .replace(/^# (.*$)/gim, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br>');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Kraken Report</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
    h1, h2, h3 { color: #333; }
    table { border-collapse: collapse; width: 100%; margin: 1em 0; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #f5f5f5; }
  </style>
</head>
<body>
<p>${html}</p>
</body>
</html>`;
}

function bytesToHex(bytes: Uint8Array | undefined): string {
  if (!bytes || bytes.length === 0) return '';
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function mapReport(r: ReportRecord): GeneratedReport {
  return {
    id: bytesToHex(r.id),
    title: r.title,
    reportType: (r.reportType || 'engagement') as ReportType,
    outputFormat: (r.outputFormat || 'markdown') as OutputFormat,
    generatedAt: r.generatedAt ? new Date(Number(r.generatedAt.millis)) : new Date(),
    generatedBy: r.generatedBy,
    dateRange: {
      start: r.startDate ? new Date(Number(r.startDate.millis)).toISOString().split('T')[0] : '',
      end: r.endDate ? new Date(Number(r.endDate.millis)).toISOString().split('T')[0] : '',
    },
    sessionCount: r.sessionCount,
    taskCount: r.taskCount,
    size: Number(r.size),
    content: '',
  };
}

export function Reports() {
  const queryClient = useQueryClient();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [viewReport, setViewReport] = useState<GeneratedReport | null>(null);
  // Cache report content (bytes) by report ID — only available for reports generated this session
  const [contentCache, setContentCache] = useState<Map<string, Uint8Array<ArrayBuffer>>>(new Map());
  const [form, setForm] = useState<ReportFormState>({
    title: '',
    reportType: 'engagement',
    dateRange: { start: '', end: '' },
    outputFormat: 'markdown',
    includeSessions: true,
    includeTasks: true,
    includeLoot: true,
    includeTimeline: false,
    includeIOCs: false,
  });

  // Fetch generated reports from backend
  const { data: reports = [] } = useQuery({
    queryKey: ['reports'],
    queryFn: async () => {
      const res = await reportClient.listReports({});
      return res.reports.map(mapReport);
    },
  });

  // Fetch data counts for report preview
  const { data: sessions = [] } = useQuery({
    queryKey: ['implants'],
    queryFn: async () => {
      const res = await implantClient.listImplants({});
      return res.implants;
    },
  });

  const { data: tasks = [] } = useQuery({
    queryKey: ['tasks'],
    queryFn: async () => {
      const res = await taskClient.listTasks({});
      return res.tasks;
    },
  });

  const { data: loot = [] } = useQuery({
    queryKey: ['loot'],
    queryFn: async () => {
      const res = await lootClient.listLoot({});
      return res.entries;
    },
  });

  function openModal(type?: ReportType) {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    setForm(prev => ({
      ...prev,
      title: '',
      reportType: type ?? 'engagement',
      dateRange: {
        start: thirtyDaysAgo.toISOString().split('T')[0],
        end: now.toISOString().split('T')[0],
      },
    }));
    setIsModalOpen(true);
  }

  function closeModal() {
    setIsModalOpen(false);
    setIsGenerating(false);
  }


  async function handleGenerate() {
    setIsGenerating(true);
    try {
      const startDate = form.dateRange.start
        ? new Timestamp({ millis: BigInt(new Date(form.dateRange.start).getTime()) })
        : undefined;
      const endDate = form.dateRange.end
        ? new Timestamp({ millis: BigInt(new Date(form.dateRange.end + 'T23:59:59').getTime()) })
        : undefined;

      const response = await reportClient.generateReport({
        title: form.title || REPORT_TYPE_INFO[form.reportType].label,
        reportType: form.reportType,
        outputFormat: form.outputFormat,
        startDate,
        endDate,
        includeSessions: form.includeSessions,
        includeTasks: form.includeTasks,
        includeLoot: form.includeLoot,
        includeTimeline: form.includeTimeline,
        includeIocs: form.includeIOCs,
      });

      // Refresh report list and cache content for immediate download/view
      const reportId = response.report ? bytesToHex(response.report.id) : '';
      if (reportId && response.content && response.content.length > 0) {
        setContentCache(prev => new Map(prev).set(reportId, response.content));
      }

      queryClient.invalidateQueries({ queryKey: ['reports'] });
      closeModal();
    } catch (error) {
      console.error('Failed to generate report:', error);
    } finally {
      setIsGenerating(false);
    }
  }

  async function handleDeleteReport(id: string) {
    try {
      await reportClient.deleteReport({ reportId: hexToBytes(id) });
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    } catch (error) {
      console.error('Failed to delete report:', error);
    }
  }

  function downloadReport(report: GeneratedReport) {
    const content = contentCache.get(report.id);
    if (!content) return;
    const formatInfo = OUTPUT_FORMAT_INFO[report.outputFormat];
    let blobContent: BlobPart = content;
    if (report.outputFormat === 'html') {
      const decoded = new TextDecoder().decode(content);
      blobContent = markdownToHtml(decoded);
    }
    const blob = new Blob([blobContent], { type: formatInfo.mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.title.toLowerCase().replace(/\s+/g, '-')}-${report.generatedAt.toISOString().split('T')[0]}${formatInfo.ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function formatSize(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  const reportTypes = Object.keys(REPORT_TYPE_INFO) as ReportType[];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-ctp-text">Reports</h1>
          <p className="text-ctp-subtext0 mt-1">Generate and export engagement reports</p>
        </div>
        <button
          onClick={() => openModal()}
          className="px-4 py-2 bg-ctp-mauve hover:bg-ctp-mauve/80 rounded-lg text-sm font-medium transition-colors text-ctp-crust flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Generate Report
        </button>
      </div>

      {/* Report Type Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
        {reportTypes.map(type => (
          <button
            key={type}
            onClick={() => openModal(type)}
            className="bg-ctp-mantle rounded-xl p-4 text-left hover:bg-ctp-surface0/50 transition-colors border border-ctp-surface0 hover:border-ctp-mauve/50"
          >
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-lg bg-ctp-mauve/20 flex items-center justify-center">
                <svg className="w-5 h-5 text-ctp-mauve" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={REPORT_TYPE_INFO[type].icon} />
                </svg>
              </div>
            </div>
            <h3 className="font-medium text-ctp-text text-sm">{REPORT_TYPE_INFO[type].label}</h3>
            <p className="text-xs text-ctp-subtext0 mt-1">{REPORT_TYPE_INFO[type].description}</p>
          </button>
        ))}
      </div>

      {/* Generated Reports Table */}
      <div className="bg-ctp-mantle rounded-xl border border-ctp-surface0">
        <div className="px-4 py-3 border-b border-ctp-surface0">
          <h2 className="font-semibold text-ctp-text">Generated Reports</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-ctp-crust/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Title</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Format</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Generated</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Size</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-ctp-subtext0 uppercase tracking-wide">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ctp-surface0">
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center">
                    <svg className="w-12 h-12 mx-auto text-ctp-overlay0 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <p className="text-ctp-subtext0">No reports generated yet</p>
                    <p className="text-sm text-ctp-overlay0 mt-1">Click a report type above to get started</p>
                  </td>
                </tr>
              ) : (
                reports.map(report => (
                  <tr key={report.id} className="hover:bg-ctp-surface0/30">
                    <td className="px-4 py-3">
                      <span className="font-medium text-ctp-text">{report.title}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 text-xs rounded-full bg-ctp-surface0 text-ctp-subtext1">
                        {REPORT_TYPE_INFO[report.reportType].label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 text-xs rounded bg-ctp-blue/20 text-ctp-blue font-mono">
                        {OUTPUT_FORMAT_INFO[report.outputFormat].label}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-ctp-subtext0">
                      {report.generatedAt.toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-sm text-ctp-subtext0">
                      {formatSize(report.size)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setViewReport(report)}
                          className="px-3 py-1.5 text-xs font-medium rounded bg-ctp-surface0 text-ctp-subtext1 hover:bg-ctp-surface1 transition-colors"
                        >
                          View
                        </button>
                        {contentCache.has(report.id) && (
                          <button
                            onClick={() => downloadReport(report)}
                            className="px-3 py-1.5 text-xs font-medium rounded bg-ctp-green/20 text-ctp-green hover:bg-ctp-green/30 transition-colors"
                          >
                            Download
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteReport(report.id)}
                          className="px-3 py-1.5 text-xs font-medium rounded bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/30 transition-colors"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Generate Report Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={closeModal}
        title="Generate Report"
        size="lg"
        footer={
          <>
            <button
              onClick={closeModal}
              disabled={isGenerating}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-ctp-surface0 hover:bg-ctp-surface1 text-ctp-text transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              onClick={handleGenerate}
              disabled={isGenerating}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-ctp-mauve hover:bg-ctp-mauve/80 text-ctp-crust transition-colors disabled:opacity-60 flex items-center gap-2"
            >
              {isGenerating && (
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {isGenerating ? 'Generating...' : 'Generate Report'}
            </button>
          </>
        }
      >
        <div className="space-y-5">
          {/* Report Title */}
          <div>
            <label className="block text-sm font-medium text-ctp-text mb-1.5">Report Title</label>
            <input
              type="text"
              value={form.title}
              onChange={e => setForm(prev => ({ ...prev, title: e.target.value }))}
              placeholder={REPORT_TYPE_INFO[form.reportType].label}
              className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-mauve transition-colors"
            />
          </div>

          {/* Report Type */}
          <div>
            <label className="block text-sm font-medium text-ctp-text mb-1.5">Report Type</label>
            <select
              value={form.reportType}
              onChange={e => setForm(prev => ({ ...prev, reportType: e.target.value as ReportType }))}
              className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
            >
              {reportTypes.map(type => (
                <option key={type} value={type}>
                  {REPORT_TYPE_INFO[type].label}
                </option>
              ))}
            </select>
          </div>

          {/* Date Range */}
          <div>
            <label className="block text-sm font-medium text-ctp-text mb-1.5">Date Range</label>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-ctp-subtext0 mb-1">Start</label>
                <input
                  type="date"
                  value={form.dateRange.start}
                  onChange={e => setForm(prev => ({ ...prev, dateRange: { ...prev.dateRange, start: e.target.value } }))}
                  className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
                />
              </div>
              <div>
                <label className="block text-xs text-ctp-subtext0 mb-1">End</label>
                <input
                  type="date"
                  value={form.dateRange.end}
                  onChange={e => setForm(prev => ({ ...prev, dateRange: { ...prev.dateRange, end: e.target.value } }))}
                  className="w-full bg-ctp-surface0 border border-ctp-surface1 rounded-lg px-3 py-2 text-sm text-ctp-text focus:outline-none focus:border-ctp-mauve transition-colors"
                />
              </div>
            </div>
          </div>

          {/* Output Format */}
          <div>
            <label className="block text-sm font-medium text-ctp-text mb-1.5">Output Format</label>
            <div className="grid grid-cols-5 gap-2">
              {(Object.keys(OUTPUT_FORMAT_INFO) as OutputFormat[]).map(fmt => (
                <button
                  key={fmt}
                  type="button"
                  onClick={() => setForm(prev => ({ ...prev, outputFormat: fmt }))}
                  className={`px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
                    form.outputFormat === fmt
                      ? 'bg-ctp-mauve/20 border-ctp-mauve text-ctp-mauve'
                      : 'bg-ctp-surface0 border-ctp-surface1 text-ctp-subtext1 hover:border-ctp-mauve/50'
                  }`}
                >
                  {OUTPUT_FORMAT_INFO[fmt].label}
                </button>
              ))}
            </div>
          </div>

          {/* Include Options */}
          <div>
            <label className="block text-sm font-medium text-ctp-text mb-2">Include Sections</label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { key: 'includeSessions', label: 'Sessions' },
                { key: 'includeTasks', label: 'Task History' },
                { key: 'includeLoot', label: 'Collected Loot' },
                { key: 'includeTimeline', label: 'Activity Timeline' },
                { key: 'includeIOCs', label: 'IOC Summary' },
              ].map(opt => (
                <label
                  key={opt.key}
                  className="flex items-center gap-2 p-2 rounded-lg bg-ctp-surface0 cursor-pointer hover:bg-ctp-surface0/80"
                >
                  <input
                    type="checkbox"
                    checked={form[opt.key as keyof ReportFormState] as boolean}
                    onChange={e => setForm(prev => ({ ...prev, [opt.key]: e.target.checked }))}
                    className="w-4 h-4 rounded bg-ctp-surface1 border-ctp-surface2 text-ctp-mauve focus:ring-ctp-mauve"
                  />
                  <span className="text-sm text-ctp-text">{opt.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Data Summary */}
          <div className="p-3 rounded-lg bg-ctp-surface0/50 border border-ctp-surface1">
            <p className="text-xs text-ctp-subtext0 mb-2">Report will include:</p>
            <div className="flex gap-4 text-sm">
              <span className="text-ctp-text">{sessions.length} sessions</span>
              <span className="text-ctp-text">{tasks.length} tasks</span>
              <span className="text-ctp-text">{loot.length} loot items</span>
            </div>
          </div>
        </div>
      </Modal>

      {/* View Report Modal */}
      {viewReport && (
        <Modal
          isOpen={true}
          onClose={() => setViewReport(null)}
          title={viewReport.title}
          size="xl"
          footer={
            <>
              <button
                onClick={() => setViewReport(null)}
                className="px-4 py-2 rounded-lg text-sm font-medium bg-ctp-surface0 hover:bg-ctp-surface1 text-ctp-text transition-colors"
              >
                Close
              </button>
              {contentCache.has(viewReport.id) && (
                <button
                  onClick={() => downloadReport(viewReport)}
                  className="px-4 py-2 rounded-lg text-sm font-medium bg-ctp-green text-ctp-crust hover:bg-ctp-green/90 transition-colors flex items-center gap-2"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  Download
                </button>
              )}
            </>
          }
        >
          <div className="space-y-4">
            <div className="flex items-center gap-4 text-sm text-ctp-subtext0">
              <span>Type: {REPORT_TYPE_INFO[viewReport.reportType].label}</span>
              <span>Format: {OUTPUT_FORMAT_INFO[viewReport.outputFormat].label}</span>
              <span>Size: {formatSize(viewReport.size)}</span>
            </div>
            <div className="max-h-[60vh] overflow-auto rounded-lg bg-ctp-crust p-4">
              {contentCache.has(viewReport.id) ? (
                <pre className="text-sm text-ctp-text whitespace-pre-wrap font-mono">
                  {new TextDecoder().decode(contentCache.get(viewReport.id))}
                </pre>
              ) : (
                <p className="text-sm text-ctp-subtext0 text-center py-8">
                  Content not available — report was generated in a previous session.
                </p>
              )}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

export default Reports;
