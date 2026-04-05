// Defender Dashboard - Defensive transparency for defenders
// Shows IOCs, YARA rules, Sigma rules, and OPSEC information
//
// Data source: currently static (built-in). To add live data, replace
// `useStaticDefenderData()` with a `useQuery` hook once DefenderService
// is available in the proto.

import { useState } from 'react';
import { IocViewer, RuleViewer, getDefenderStats } from '../components/defender';

// ---------------------------------------------------------------------------
// Data hook — swap this out when DefenderService is available
// ---------------------------------------------------------------------------
type DataSource = 'static' | 'live';

function useDefenderData() {
  // TODO: replace with useQuery(defenderServiceClient.getStats, {}) when ready
  const stats = getDefenderStats();
  const dataSource: DataSource = 'static';
  return { stats, dataSource };
}

type DefenderTab = 'overview' | 'iocs' | 'rules';

// Icon components using inline SVG
function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
}

function AlertTriangleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
}

function FileCodeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
    </svg>
  );
}

function ActivityIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
    </svg>
  );
}

function GlobeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
    </svg>
  );
}

function ServerIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m19.5 0a3 3 0 01-3 3H5.25a3 3 0 01-3-3m19.5 0a3 3 0 00-3-3H5.25a3 3 0 00-3 3m16.5 0h.008v.008h-.008v-.008zm-3 0h.008v.008h-.008v-.008z" />
    </svg>
  );
}

function CpuIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25zm.75-12h9v9h-9v-9z" />
    </svg>
  );
}

function EyeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  );
}

function DownloadIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
    </svg>
  );
}

interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: number;
  subtext?: string;
  color: string;
}

function StatCard({ icon, label, value, subtext, color }: StatCardProps) {
  return (
    <div className="bg-surface0 rounded-lg p-4 border border-surface1">
      <div className="flex items-center gap-3">
        <div
          className="p-2 rounded-lg"
          style={{ backgroundColor: `${color}20` }}
        >
          <div style={{ color }}>{icon}</div>
        </div>
        <div>
          <p className="text-2xl font-bold text-text">{value}</p>
          <p className="text-sm text-subtext0">{label}</p>
          {subtext && <p className="text-xs text-subtext1 mt-0.5">{subtext}</p>}
        </div>
      </div>
    </div>
  );
}

function DataSourceBanner({ source }: { source: DataSource }) {
  return (
    <div className="mb-6 p-4 bg-ctp-surface0 rounded-lg border border-ctp-surface1">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-ctp-blue/20 flex items-center justify-center">
          <svg className="w-5 h-5 text-ctp-blue" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <div>
          <h3 className="text-sm font-medium text-ctp-text">Detection Content</h3>
          <p className="text-xs text-ctp-subtext0">
            {source === 'static'
              ? 'Showing built-in detection rules and IOCs. Connect to a live server for real-time updates.'
              : 'Showing live detection rules and IOCs from the connected server.'}
          </p>
        </div>
        <div className="ml-auto">
          <span className="px-2 py-1 text-xs font-medium rounded bg-ctp-surface1 text-ctp-subtext1">
            {source === 'static' ? 'Static Data' : 'Live Data'}
          </span>
        </div>
      </div>
    </div>
  );
}

function OverviewTab() {
  const { stats, dataSource } = useDefenderData();

  const handleExportAll = () => {
    // Export comprehensive defender report
    const report = {
      generated: new Date().toISOString(),
      framework: 'Kraken C2',
      version: '1.0.0',
      summary: {
        totalIocs: stats.networkIocs + stats.hostIocs + stats.memoryIocs + stats.behavioralIocs,
        highRiskIocs: stats.highRiskIocs,
        totalRules: stats.yaraRules + stats.sigmaRules,
        criticalRules: stats.criticalRules,
      },
      documentation: {
        iocs: '/wiki/detection/iocs.md',
        yaraRules: '/wiki/detection/yara/',
        sigmaRules: '/wiki/detection/sigma/',
        detectionOverview: '/wiki/detection/overview.md',
      },
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'kraken-defender-report.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-6">
      {/* Data source indicator */}
      <DataSourceBanner source={dataSource} />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-text">Defensive Transparency</h2>
          <p className="text-sm text-subtext0 mt-1">
            Complete visibility into what defenders see - IOCs, detection rules, and behavioral patterns.
          </p>
        </div>
        <button
          onClick={handleExportAll}
          className="flex items-center gap-2 px-4 py-2 bg-mauve text-crust rounded-lg hover:bg-mauve/90 transition-colors"
        >
          <DownloadIcon className="w-4 h-4" />
          Export Full Report
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          icon={<GlobeIcon className="w-5 h-5" />}
          label="Network IOCs"
          value={stats.networkIocs}
          subtext="URLs, headers, ports"
          color="#89b4fa"
        />
        <StatCard
          icon={<ServerIcon className="w-5 h-5" />}
          label="Host IOCs"
          value={stats.hostIocs}
          subtext="Strings, imports, env vars"
          color="#a6e3a1"
        />
        <StatCard
          icon={<CpuIcon className="w-5 h-5" />}
          label="Memory IOCs"
          value={stats.memoryIocs}
          subtext="Patterns, signatures"
          color="#f9e2af"
        />
        <StatCard
          icon={<ActivityIcon className="w-5 h-5" />}
          label="Behavioral IOCs"
          value={stats.behavioralIocs}
          subtext="Timing, network patterns"
          color="#cba6f7"
        />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <StatCard
          icon={<FileCodeIcon className="w-5 h-5" />}
          label="YARA Rules"
          value={stats.yaraRules}
          subtext="Binary/memory detection"
          color="#f9e2af"
        />
        <StatCard
          icon={<ShieldIcon className="w-5 h-5" />}
          label="Sigma Rules"
          value={stats.sigmaRules}
          subtext="Log-based detection"
          color="#89b4fa"
        />
        <StatCard
          icon={<AlertTriangleIcon className="w-5 h-5" />}
          label="Critical Rules"
          value={stats.criticalRules}
          subtext="High-confidence detections"
          color="#f38ba8"
        />
      </div>

      {/* Detection Philosophy */}
      <div className="bg-surface0 rounded-lg p-6 border border-surface1">
        <h3 className="text-lg font-semibold text-text mb-4 flex items-center gap-2">
          <EyeIcon className="w-5 h-5 text-mauve" />
          Detection Philosophy
        </h3>
        <div className="grid md:grid-cols-2 gap-6 text-sm">
          <div>
            <h4 className="font-medium text-text mb-2">What This Page Provides</h4>
            <ul className="space-y-1 text-subtext0">
              <li>- Complete IOC catalog for Kraken framework</li>
              <li>- YARA rules for binary and memory scanning</li>
              <li>- Sigma rules for log-based detection</li>
              <li>- MITRE ATT&CK technique mapping</li>
              <li>- Export capabilities for threat intel platforms</li>
            </ul>
          </div>
          <div>
            <h4 className="font-medium text-text mb-2">Detection Layers</h4>
            <ul className="space-y-1 text-subtext0">
              <li>- <span className="text-blue">Network:</span> Protocol analysis, timing, destinations</li>
              <li>- <span className="text-green">Endpoint:</span> Process behavior, memory artifacts</li>
              <li>- <span className="text-yellow">Log Analysis:</span> Proxy, firewall, auth logs</li>
              <li>- <span className="text-peach">Behavioral:</span> Absence-based detection</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Phase Detection Table */}
      <div className="bg-surface0 rounded-lg border border-surface1 overflow-hidden">
        <div className="px-4 py-3 border-b border-surface1">
          <h3 className="font-semibold text-text">Detection by Implementation Phase</h3>
        </div>
        <table className="w-full text-sm">
          <thead className="bg-mantle">
            <tr className="text-subtext0">
              <th className="px-4 py-2 text-left">Phase</th>
              <th className="px-4 py-2 text-left">Techniques</th>
              <th className="px-4 py-2 text-left">Detection Focus</th>
            </tr>
          </thead>
          <tbody className="text-text">
            <tr className="border-t border-surface1">
              <td className="px-4 py-2 font-medium">Phase 1</td>
              <td className="px-4 py-2 text-subtext0">HTTP transport, crypto, check-in</td>
              <td className="px-4 py-2 text-subtext0">Network signatures, timing</td>
            </tr>
            <tr className="border-t border-surface1">
              <td className="px-4 py-2 font-medium">Phase 2</td>
              <td className="px-4 py-2 text-subtext0">Shell, file, BOF modules</td>
              <td className="px-4 py-2 text-subtext0">Endpoint behavior, commands</td>
            </tr>
            <tr className="border-t border-surface1">
              <td className="px-4 py-2 font-medium">Phase 3</td>
              <td className="px-4 py-2 text-subtext0">Dynamic module loading</td>
              <td className="px-4 py-2 text-subtext0">Memory scanning, module sigs</td>
            </tr>
            <tr className="border-t border-surface1">
              <td className="px-4 py-2 font-medium">Phase 4</td>
              <td className="px-4 py-2 text-subtext0">OPSEC features (ETW, AMSI, sleep mask)</td>
              <td className="px-4 py-2 text-subtext0">Evasion detection, anomalies</td>
            </tr>
            <tr className="border-t border-surface1">
              <td className="px-4 py-2 font-medium">Phase 5</td>
              <td className="px-4 py-2 text-subtext0">Mesh networking</td>
              <td className="px-4 py-2 text-subtext0">Lateral movement, peer comms</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Quick Links */}
      <div className="grid md:grid-cols-3 gap-4">
        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 p-4 bg-surface0 rounded-lg border border-surface1 hover:border-mauve transition-colors"
        >
          <ShieldIcon className="w-8 h-8 text-blue" />
          <div>
            <p className="font-medium text-text">MITRE ATT&CK</p>
            <p className="text-xs text-subtext0">View technique references</p>
          </div>
        </a>
        <a
          href="https://github.com/SigmaHQ/sigma"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 p-4 bg-surface0 rounded-lg border border-surface1 hover:border-mauve transition-colors"
        >
          <FileCodeIcon className="w-8 h-8 text-yellow" />
          <div>
            <p className="font-medium text-text">Sigma Documentation</p>
            <p className="text-xs text-subtext0">Rule syntax reference</p>
          </div>
        </a>
        <a
          href="https://yara.readthedocs.io/"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 p-4 bg-surface0 rounded-lg border border-surface1 hover:border-mauve transition-colors"
        >
          <ActivityIcon className="w-8 h-8 text-green" />
          <div>
            <p className="font-medium text-text">YARA Documentation</p>
            <p className="text-xs text-subtext0">Pattern matching reference</p>
          </div>
        </a>
      </div>
    </div>
  );
}

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}

function TabButton({ active, onClick, icon, label }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`
        flex items-center gap-2 px-4 py-2 border-b-2 transition-colors
        ${active
          ? 'border-mauve text-mauve'
          : 'border-transparent text-subtext0 hover:text-text'
        }
      `}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

export function Defender() {
  const [activeTab, setActiveTab] = useState<DefenderTab>('overview');

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-surface0">
        <div className="flex items-center gap-3">
          <ShieldIcon className="w-6 h-6 text-mauve" />
          <div>
            <h1 className="text-xl font-semibold text-text">Defender Dashboard</h1>
            <p className="text-sm text-subtext0 mt-0.5">
              Detection transparency - see what defenders see
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-4 mt-4 -mb-4">
          <TabButton
            active={activeTab === 'overview'}
            onClick={() => setActiveTab('overview')}
            icon={<EyeIcon className="w-4 h-4" />}
            label="Overview"
          />
          <TabButton
            active={activeTab === 'iocs'}
            onClick={() => setActiveTab('iocs')}
            icon={<AlertTriangleIcon className="w-4 h-4" />}
            label="IOC Catalog"
          />
          <TabButton
            active={activeTab === 'rules'}
            onClick={() => setActiveTab('rules')}
            icon={<FileCodeIcon className="w-4 h-4" />}
            label="Detection Rules"
          />
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 min-h-0 overflow-auto">
        {activeTab === 'overview' && <OverviewTab />}
        {activeTab === 'iocs' && <IocViewer />}
        {activeTab === 'rules' && <RuleViewer />}
      </div>
    </div>
  );
}
