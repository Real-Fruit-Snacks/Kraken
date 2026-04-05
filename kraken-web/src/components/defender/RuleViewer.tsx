// YARA and Sigma Rule Viewer with syntax highlighting

import { useState, useMemo } from 'react';
import type { YaraRule, SigmaRule, RuleSeverity } from './types';
import { SEVERITY_COLORS } from './types';
import { YARA_RULES, SIGMA_RULES } from './data';

type RuleType = 'yara' | 'sigma';

// Icon components using inline SVG
function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
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

function DownloadIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
    </svg>
  );
}

function ExternalLinkIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
    </svg>
  );
}

function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
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

interface SeverityBadgeProps {
  severity: RuleSeverity;
}

function SeverityBadge({ severity }: SeverityBadgeProps) {
  const colors = SEVERITY_COLORS[severity];
  return (
    <span
      className="px-2 py-0.5 rounded text-xs font-medium uppercase"
      style={{
        backgroundColor: colors.bg,
        color: colors.text,
      }}
    >
      {severity}
    </span>
  );
}

interface MitreTagProps {
  technique: string;
}

function MitreTag({ technique }: MitreTagProps) {
  const url = `https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-surface1 text-blue hover:bg-surface2 transition-colors"
    >
      {technique}
      <ExternalLinkIcon className="w-3 h-3" />
    </a>
  );
}

interface CopyButtonProps {
  value: string;
  label?: string;
}

function CopyButton({ value, label }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-surface1 text-subtext0 hover:bg-surface2 hover:text-text transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <>
          <CheckIcon className="w-3 h-3 text-green" />
          Copied
        </>
      ) : (
        <>
          <CopyIcon className="w-3 h-3" />
          {label || 'Copy'}
        </>
      )}
    </button>
  );
}

// Simple syntax highlighting for YARA rules
function highlightYara(code: string): React.ReactNode {
  const lines = code.split('\n');
  return lines.map((line, i) => {
    let highlighted = line;

    // Keywords
    highlighted = highlighted.replace(
      /\b(rule|meta|strings|condition|import|include|private|global)\b/g,
      '<span class="text-mauve font-medium">$1</span>'
    );

    // Operators
    highlighted = highlighted.replace(
      /\b(and|or|not|all|any|of|them|at|in|for|true|false)\b/g,
      '<span class="text-blue">$1</span>'
    );

    // Strings
    highlighted = highlighted.replace(
      /"([^"]*)"/g,
      '<span class="text-green">"$1"</span>'
    );

    // Hex patterns
    highlighted = highlighted.replace(
      /\{([^}]*)\}/g,
      '<span class="text-peach">{$1}</span>'
    );

    // Comments
    highlighted = highlighted.replace(
      /(\/\/.*)$/g,
      '<span class="text-overlay0 italic">$1</span>'
    );

    // Variables
    highlighted = highlighted.replace(
      /(\$\w+)/g,
      '<span class="text-yellow">$1</span>'
    );

    return (
      <div key={i} className="flex">
        <span className="w-8 text-right pr-3 text-overlay0 select-none">
          {i + 1}
        </span>
        <span dangerouslySetInnerHTML={{ __html: highlighted }} />
      </div>
    );
  });
}

// Simple syntax highlighting for Sigma rules (YAML)
function highlightSigma(code: string): React.ReactNode {
  const lines = code.split('\n');
  return lines.map((line, i) => {
    let highlighted = line;

    // Keys
    highlighted = highlighted.replace(
      /^(\s*)(\w+):/gm,
      '$1<span class="text-mauve">$2</span>:'
    );

    // Strings
    highlighted = highlighted.replace(
      /'([^']*)'/g,
      '<span class="text-green">\'$1\'</span>'
    );

    // Comments
    highlighted = highlighted.replace(
      /(#.*)$/g,
      '<span class="text-overlay0 italic">$1</span>'
    );

    // List items
    highlighted = highlighted.replace(
      /^(\s*)-(\s)/gm,
      '$1<span class="text-blue">-</span>$2'
    );

    // Booleans
    highlighted = highlighted.replace(
      /\b(true|false)\b/g,
      '<span class="text-peach">$1</span>'
    );

    return (
      <div key={i} className="flex">
        <span className="w-8 text-right pr-3 text-overlay0 select-none">
          {i + 1}
        </span>
        <span dangerouslySetInnerHTML={{ __html: highlighted }} />
      </div>
    );
  });
}

interface YaraRuleCardProps {
  rule: YaraRule;
  expanded: boolean;
  onToggle: () => void;
}

function YaraRuleCard({ rule, expanded, onToggle }: YaraRuleCardProps) {
  return (
    <div className="border border-surface0 rounded-lg overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center gap-3 px-4 py-3 bg-surface0/50 cursor-pointer hover:bg-surface0 transition-colors"
        onClick={onToggle}
      >
        <button className="text-subtext0">
          {expanded ? (
            <ChevronDownIcon className="w-4 h-4" />
          ) : (
            <ChevronRightIcon className="w-4 h-4" />
          )}
        </button>
        <FileCodeIcon className="w-4 h-4 text-yellow" />
        <span className="font-medium text-text flex-1">{rule.name}</span>
        <div className="flex items-center gap-2">
          {rule.mitreTechniques.map((t) => (
            <MitreTag key={t} technique={t} />
          ))}
          <SeverityBadge severity={rule.severity} />
        </div>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-surface0">
          {/* Metadata */}
          <div className="px-4 py-3 bg-mantle border-b border-surface0">
            <p className="text-sm text-subtext0 mb-2">{rule.description}</p>
            <div className="flex flex-wrap gap-4 text-xs text-subtext0">
              <span>Author: {rule.author}</span>
              <span>Date: {rule.date}</span>
              <span>Category: {rule.category}</span>
            </div>
          </div>

          {/* Code */}
          <div className="relative">
            <div className="absolute top-2 right-2 z-10">
              <CopyButton value={rule.content} label="Copy Rule" />
            </div>
            <pre className="p-4 bg-crust text-sm font-mono overflow-x-auto">
              <code>{highlightYara(rule.content)}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

interface SigmaRuleCardProps {
  rule: SigmaRule;
  expanded: boolean;
  onToggle: () => void;
}

function SigmaRuleCard({ rule, expanded, onToggle }: SigmaRuleCardProps) {
  return (
    <div className="border border-surface0 rounded-lg overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center gap-3 px-4 py-3 bg-surface0/50 cursor-pointer hover:bg-surface0 transition-colors"
        onClick={onToggle}
      >
        <button className="text-subtext0">
          {expanded ? (
            <ChevronDownIcon className="w-4 h-4" />
          ) : (
            <ChevronRightIcon className="w-4 h-4" />
          )}
        </button>
        <ShieldIcon className="w-4 h-4 text-blue" />
        <span className="font-medium text-text flex-1">{rule.title}</span>
        <div className="flex items-center gap-2">
          <span className={`
            px-2 py-0.5 rounded text-xs
            ${rule.status === 'stable' ? 'bg-green/20 text-green' :
              rule.status === 'experimental' ? 'bg-yellow/20 text-yellow' :
              'bg-red/20 text-red'}
          `}>
            {rule.status}
          </span>
          <SeverityBadge severity={rule.level} />
        </div>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-surface0">
          {/* Metadata */}
          <div className="px-4 py-3 bg-mantle border-b border-surface0">
            <p className="text-sm text-subtext0 mb-2">{rule.description}</p>
            <div className="flex flex-wrap gap-4 text-xs text-subtext0 mb-2">
              <span>ID: {rule.id}</span>
              <span>Author: {rule.author}</span>
              <span>Date: {rule.date}</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {rule.tags.filter(t => t.startsWith('attack.t')).map((tag) => (
                <MitreTag key={tag} technique={tag.replace('attack.', '').toUpperCase()} />
              ))}
            </div>
          </div>

          {/* Code */}
          <div className="relative">
            <div className="absolute top-2 right-2 z-10">
              <CopyButton value={rule.content} label="Copy Rule" />
            </div>
            <pre className="p-4 bg-crust text-sm font-mono overflow-x-auto">
              <code>{highlightSigma(rule.content)}</code>
            </pre>
          </div>
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

export function RuleViewer() {
  const [ruleType, setRuleType] = useState<RuleType>('yara');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<RuleSeverity | 'all'>('all');
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set());

  const toggleRule = (id: string) => {
    const newExpanded = new Set(expandedRules);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedRules(newExpanded);
  };

  const filteredYara = useMemo(() => {
    return YARA_RULES.filter((rule) => {
      const matchesSearch =
        searchQuery === '' ||
        rule.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        rule.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesSeverity =
        severityFilter === 'all' || rule.severity === severityFilter;
      return matchesSearch && matchesSeverity;
    });
  }, [searchQuery, severityFilter]);

  const filteredSigma = useMemo(() => {
    return SIGMA_RULES.filter((rule) => {
      const matchesSearch =
        searchQuery === '' ||
        rule.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        rule.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesSeverity =
        severityFilter === 'all' || rule.level === severityFilter;
      return matchesSearch && matchesSeverity;
    });
  }, [searchQuery, severityFilter]);

  const handleExport = () => {
    const data = ruleType === 'yara' ? filteredYara : filteredSigma;
    const content = data.map((r) => r.content).join('\n\n---\n\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kraken-${ruleType}-rules.${ruleType === 'yara' ? 'yar' : 'yml'}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const expandAll = () => {
    const rules = ruleType === 'yara' ? filteredYara : filteredSigma;
    const ids = rules.map((r) => ('name' in r ? r.name : r.id));
    setExpandedRules(new Set(ids));
  };

  const collapseAll = () => {
    setExpandedRules(new Set());
  };

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-4 px-4 py-3 border-b border-surface0">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-subtext0" />
          <input
            type="text"
            placeholder="Search rules..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-surface0 border border-surface1 rounded-lg text-sm text-text placeholder:text-subtext0 focus:outline-none focus:border-mauve"
          />
        </div>

        {/* Severity filter */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as RuleSeverity | 'all')}
          className="px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-sm text-text focus:outline-none focus:border-mauve"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Expand/Collapse */}
        <button
          onClick={expandAll}
          className="px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-sm text-text hover:bg-surface1 transition-colors"
        >
          Expand All
        </button>
        <button
          onClick={collapseAll}
          className="px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-sm text-text hover:bg-surface1 transition-colors"
        >
          Collapse
        </button>

        {/* Export */}
        <button
          onClick={handleExport}
          className="flex items-center gap-2 px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-sm text-text hover:bg-surface1 transition-colors"
        >
          <DownloadIcon className="w-4 h-4" />
          Export
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-4 pt-3 border-b border-surface0">
        <TabButton
          active={ruleType === 'yara'}
          onClick={() => setRuleType('yara')}
          icon={<FileCodeIcon className="w-4 h-4" />}
          label="YARA Rules"
          count={YARA_RULES.length}
        />
        <TabButton
          active={ruleType === 'sigma'}
          onClick={() => setRuleType('sigma')}
          icon={<ShieldIcon className="w-4 h-4" />}
          label="Sigma Rules"
          count={SIGMA_RULES.length}
        />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-4 space-y-3">
        {ruleType === 'yara' ? (
          filteredYara.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-subtext0">
              No YARA rules match your filters
            </div>
          ) : (
            filteredYara.map((rule) => (
              <YaraRuleCard
                key={rule.name}
                rule={rule}
                expanded={expandedRules.has(rule.name)}
                onToggle={() => toggleRule(rule.name)}
              />
            ))
          )
        ) : filteredSigma.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-subtext0">
            No Sigma rules match your filters
          </div>
        ) : (
          filteredSigma.map((rule) => (
            <SigmaRuleCard
              key={rule.id}
              rule={rule}
              expanded={expandedRules.has(rule.id)}
              onToggle={() => toggleRule(rule.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}
