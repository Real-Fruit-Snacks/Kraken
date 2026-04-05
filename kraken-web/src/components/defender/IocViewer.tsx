// IOC Viewer Component - displays Network, Host, Memory, Behavioral IOCs

import { useState, useMemo } from 'react';
import type { IocRisk } from './types';
import { RISK_COLORS } from './types';
import {
  NETWORK_IOCS,
  HOST_IOCS,
  MEMORY_IOCS,
  BEHAVIORAL_IOCS,
} from './data';

type IocTab = 'network' | 'host' | 'memory' | 'behavioral';

// Icon components using inline SVG (Heroicons style)
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

function ActivityIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
    </svg>
  );
}

function CopyIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
    </svg>
  );
}

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
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

function ChevronDownIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
    </svg>
  );
}

function ChevronRightIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
    </svg>
  );
}

interface RiskBadgeProps {
  risk: IocRisk;
}

function RiskBadge({ risk }: RiskBadgeProps) {
  const colors = RISK_COLORS[risk];
  return (
    <span
      className="px-2 py-0.5 rounded text-xs font-medium uppercase"
      style={{
        backgroundColor: colors.bg,
        color: colors.text,
      }}
    >
      {risk}
    </span>
  );
}

interface CopyButtonProps {
  value: string;
}

function CopyButton({ value }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded hover:bg-surface1 text-subtext0 hover:text-text transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <CheckIcon className="w-4 h-4 text-green" />
      ) : (
        <CopyIcon className="w-4 h-4" />
      )}
    </button>
  );
}

interface IocRowProps {
  type: string;
  value: string;
  risk: IocRisk;
  description: string;
  extra?: Record<string, string>;
}

function IocRow({ type, value, risk, description, extra }: IocRowProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border-b border-surface0 last:border-b-0">
      <div
        className="flex items-center gap-3 px-4 py-3 hover:bg-surface0/50 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <button className="text-subtext0">
          {expanded ? (
            <ChevronDownIcon className="w-4 h-4" />
          ) : (
            <ChevronRightIcon className="w-4 h-4" />
          )}
        </button>
        <span className="text-xs text-subtext0 uppercase w-24 flex-shrink-0">
          {type}
        </span>
        <code className="flex-1 text-sm font-mono text-text truncate">
          {value}
        </code>
        <RiskBadge risk={risk} />
        <CopyButton value={value} />
      </div>
      {expanded && (
        <div className="px-4 pb-3 pl-12 text-sm text-subtext0">
          <p>{description}</p>
          {extra && Object.entries(extra).map(([key, val]) => (
            <p key={key} className="mt-1">
              <span className="text-subtext1">{key}:</span> {val}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  count: number;
}

function TabButton({ active, onClick, icon, label, count }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`
        flex items-center gap-2 px-4 py-2 rounded-t-lg border-b-2 transition-colors
        ${active
          ? 'border-mauve text-mauve bg-surface0'
          : 'border-transparent text-subtext0 hover:text-text hover:bg-surface0/50'
        }
      `}
    >
      {icon}
      <span>{label}</span>
      <span className={`
        px-1.5 py-0.5 rounded text-xs
        ${active ? 'bg-mauve text-crust' : 'bg-surface1 text-subtext0'}
      `}>
        {count}
      </span>
    </button>
  );
}

export function IocViewer() {
  const [activeTab, setActiveTab] = useState<IocTab>('network');
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<IocRisk | 'all'>('all');

  // Filter IOCs based on search and risk
  const filterIocs = <T extends { value: string; risk: IocRisk; description: string }>(
    iocs: T[]
  ): T[] => {
    return iocs.filter((ioc) => {
      const matchesSearch =
        searchQuery === '' ||
        ioc.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
        ioc.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesRisk = riskFilter === 'all' || ioc.risk === riskFilter;
      return matchesSearch && matchesRisk;
    });
  };

  const filteredNetwork = useMemo(
    () => filterIocs(NETWORK_IOCS),
    [searchQuery, riskFilter]
  );
  const filteredHost = useMemo(
    () => filterIocs(HOST_IOCS),
    [searchQuery, riskFilter]
  );
  const filteredMemory = useMemo(
    () => filterIocs(MEMORY_IOCS),
    [searchQuery, riskFilter]
  );
  const filteredBehavioral = useMemo(
    () => filterIocs(BEHAVIORAL_IOCS),
    [searchQuery, riskFilter]
  );

  const handleExport = () => {
    const data = {
      exported: new Date().toISOString(),
      network: NETWORK_IOCS,
      host: HOST_IOCS,
      memory: MEMORY_IOCS,
      behavioral: BEHAVIORAL_IOCS,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'kraken-iocs.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderIocList = () => {
    switch (activeTab) {
      case 'network':
        return filteredNetwork.map((ioc, i) => (
          <IocRow
            key={i}
            type={ioc.type}
            value={ioc.value}
            risk={ioc.risk}
            description={ioc.description}
            extra={ioc.profile ? { Profile: ioc.profile } : undefined}
          />
        ));
      case 'host':
        return filteredHost.map((ioc, i) => (
          <IocRow
            key={i}
            type={ioc.type}
            value={ioc.value}
            risk={ioc.risk}
            description={ioc.description}
            extra={{ Confidence: ioc.confidence }}
          />
        ));
      case 'memory':
        return filteredMemory.map((ioc, i) => (
          <IocRow
            key={i}
            type={ioc.type}
            value={ioc.value}
            risk={ioc.risk}
            description={ioc.description}
          />
        ));
      case 'behavioral':
        return filteredBehavioral.map((ioc, i) => (
          <IocRow
            key={i}
            type={ioc.type}
            value={ioc.value}
            risk={ioc.risk}
            description={ioc.description}
          />
        ));
    }
  };

  const currentCount = {
    network: filteredNetwork.length,
    host: filteredHost.length,
    memory: filteredMemory.length,
    behavioral: filteredBehavioral.length,
  }[activeTab];

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-4 px-4 py-3 border-b border-surface0">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-subtext0" />
          <input
            type="text"
            placeholder="Search IOCs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-surface0 border border-surface1 rounded-lg text-sm text-text placeholder:text-subtext0 focus:outline-none focus:border-mauve"
          />
        </div>

        {/* Risk filter */}
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value as IocRisk | 'all')}
          className="px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-sm text-text focus:outline-none focus:border-mauve"
        >
          <option value="all">All Risks</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Export */}
        <button
          onClick={handleExport}
          className="flex items-center gap-2 px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-sm text-text hover:bg-surface1 transition-colors"
        >
          <DownloadIcon className="w-4 h-4" />
          Export JSON
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-4 pt-3 border-b border-surface0">
        <TabButton
          active={activeTab === 'network'}
          onClick={() => setActiveTab('network')}
          icon={<GlobeIcon className="w-4 h-4" />}
          label="Network"
          count={NETWORK_IOCS.length}
        />
        <TabButton
          active={activeTab === 'host'}
          onClick={() => setActiveTab('host')}
          icon={<ServerIcon className="w-4 h-4" />}
          label="Host"
          count={HOST_IOCS.length}
        />
        <TabButton
          active={activeTab === 'memory'}
          onClick={() => setActiveTab('memory')}
          icon={<CpuIcon className="w-4 h-4" />}
          label="Memory"
          count={MEMORY_IOCS.length}
        />
        <TabButton
          active={activeTab === 'behavioral'}
          onClick={() => setActiveTab('behavioral')}
          icon={<ActivityIcon className="w-4 h-4" />}
          label="Behavioral"
          count={BEHAVIORAL_IOCS.length}
        />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {currentCount === 0 ? (
          <div className="flex items-center justify-center h-32 text-subtext0">
            No IOCs match your filters
          </div>
        ) : (
          <div className="divide-y divide-surface0">{renderIocList()}</div>
        )}
      </div>
    </div>
  );
}
