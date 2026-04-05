// ProcessBrowser - Process listing and injection targeting UI
// Based on Mythic/Cobalt Strike process browser patterns

import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Modal } from '../Modal';
import { RiskBadge, RiskMeter } from '../opsec/RiskIndicator';
import {
  INJECTION_TECHNIQUE_PROFILES,
  InjectionTechnique,
  RiskLevel,
} from '../opsec/types';
import { injectClient } from '../../api/index.js';
import { ProcessIntegrity } from '../../gen/kraken_pb.js';

// Types matching proto definitions
interface ProcessEntry {
  pid: number;
  ppid: number;
  name: string;
  path: string;
  user: string;
  arch: string;
  integrity: 'unknown' | 'low' | 'medium' | 'high' | 'system' | 'protected';
  isElevated: boolean;
  isCurrent: boolean;
  isInjectable: boolean;
  warning?: string;
}

interface ProcessBrowserProps {
  sessionId: string;
  sessionArch: string;
  onInject?: (pid: number, name: string) => void;
}

// Color utilities for Catppuccin Mocha
const getIntegrityColor = (integrity: string): string => {
  switch (integrity) {
    case 'system': return 'text-ctp-red';
    case 'protected': return 'text-ctp-maroon';
    case 'high': return 'text-ctp-peach';
    case 'medium': return 'text-ctp-text';
    case 'low': return 'text-ctp-subtext0';
    default: return 'text-ctp-overlay0';
  }
};

const getArchBadge = (arch: string, sessionArch: string): { bg: string; text: string } => {
  const matches = arch.toLowerCase() === sessionArch.toLowerCase();
  if (arch === 'x64') {
    return { bg: 'bg-ctp-blue/20', text: matches ? 'text-ctp-blue' : 'text-ctp-red' };
  }
  return { bg: 'bg-ctp-yellow/20', text: matches ? 'text-ctp-yellow' : 'text-ctp-red' };
};

// Process denylist for injection
const BLOCKED_PROCESSES = ['csrss.exe', 'smss.exe', 'lsass.exe', 'services.exe', 'wininit.exe'];
const AV_PROCESSES = ['msmpeng.exe', 'mssense.exe', 'csfalconservice.exe', 'cb.exe', 'cylancesvc.exe'];
const EDR_PROCESSES = ['mssense.exe', 'csfalconservice.exe', 'cb.exe', 'cylancesvc.exe', 'carbonblack.exe', 'taniumclient.exe'];

function isBlocked(name: string): boolean {
  return BLOCKED_PROCESSES.includes(name.toLowerCase());
}

function isAVProcess(name: string): boolean {
  return AV_PROCESSES.includes(name.toLowerCase());
}

function isEDRProcess(name: string): boolean {
  return EDR_PROCESSES.includes(name.toLowerCase());
}

// Derive a per-process risk level for the inline risk column
function getProcessRiskLevel(proc: ProcessEntry): RiskLevel {
  if (isEDRProcess(proc.name)) return 'critical';
  if (isAVProcess(proc.name)) return 'high';
  if (isBlocked(proc.name)) return 'high';
  if (proc.integrity === 'system' || proc.isElevated) return 'medium';
  return 'low';
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function mapIntegrity(i: ProcessIntegrity): ProcessEntry['integrity'] {
  switch (i) {
    case ProcessIntegrity.LOW: return 'low';
    case ProcessIntegrity.MEDIUM: return 'medium';
    case ProcessIntegrity.HIGH: return 'high';
    case ProcessIntegrity.SYSTEM: return 'system';
    case ProcessIntegrity.PROTECTED: return 'protected';
    default: return 'unknown';
  }
}

export function ProcessBrowser({ sessionId, sessionArch, onInject }: ProcessBrowserProps) {
  const [filter, setFilter] = useState('');
  const [showSystem, setShowSystem] = useState(false);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [injectModalOpen, setInjectModalOpen] = useState(false);

  const { data: processes = [], isLoading, error: fetchError, refetch } = useQuery({
    queryKey: ['processes', sessionId],
    queryFn: async () => {
      const res = await injectClient.listProcesses({
        implantId: { value: hexToBytes(sessionId) },
        includeSystem: true,
      });
      return res.processes.map(p => ({
        pid: p.pid,
        ppid: p.ppid,
        name: p.name,
        path: p.path,
        user: p.user,
        arch: p.arch || sessionArch,
        integrity: mapIntegrity(p.integrity),
        isElevated: p.isElevated,
        isCurrent: p.isCurrent,
        isInjectable: p.isInjectable,
        warning: p.warning || undefined,
      } satisfies ProcessEntry));
    },
    enabled: !!sessionId,
    refetchInterval: 30000,
  });

  const filteredProcesses = useMemo(() => {
    return processes.filter(p => {
      if (!showSystem && p.integrity === 'system') return false;
      if (filter && !p.name.toLowerCase().includes(filter.toLowerCase())) return false;
      return true;
    });
  }, [processes, filter, showSystem]);

  const selectedProcess = processes.find(p => p.pid === selectedPid);

  const handleInjectClick = (pid: number) => {
    const proc = processes.find(p => p.pid === pid);
    if (!proc) return;

    if (isBlocked(proc.name)) {
      alert(`Injection into ${proc.name} is blocked for safety`);
      return;
    }

    setSelectedPid(pid);
    setInjectModalOpen(true);
  };

  return (
    <div className="flex flex-col h-full bg-ctp-base">
      {/* Header */}
      <div className="flex-none flex items-center justify-between p-3 border-b border-ctp-surface0">
        <div className="flex items-center gap-3">
          <h3 className="font-semibold text-ctp-text">Processes</h3>
          <span className="text-xs text-ctp-subtext0 bg-ctp-surface0 px-2 py-1 rounded">
            {filteredProcesses.length} shown
          </span>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Filter..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-2 py-1 text-sm bg-ctp-surface0 border border-ctp-surface1 rounded text-ctp-text placeholder-ctp-subtext0 focus:outline-none focus:border-ctp-mauve"
          />
          <label className="flex items-center gap-1 text-xs text-ctp-subtext0">
            <input
              type="checkbox"
              checked={showSystem}
              onChange={(e) => setShowSystem(e.target.checked)}
              className="rounded border-ctp-surface1"
            />
            SYSTEM
          </label>
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="px-2 py-1 text-xs bg-ctp-surface0 hover:bg-ctp-surface1 text-ctp-text rounded transition-colors disabled:opacity-50"
          >
            {isLoading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Error state */}
      {fetchError && (
        <div className="px-3 py-2 bg-ctp-red/10 border-b border-ctp-red/30 text-ctp-red text-xs">
          Failed to load processes: {fetchError instanceof Error ? fetchError.message : 'Unknown error'}
        </div>
      )}

      {/* Process Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-ctp-mantle">
            <tr className="text-left text-ctp-subtext0 text-xs uppercase tracking-wider">
              <th className="px-3 py-2">PID</th>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">User</th>
              <th className="px-3 py-2">Arch</th>
              <th className="px-3 py-2">Integrity</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ctp-surface0">
            {filteredProcesses.map((proc) => {
              const archBadge = getArchBadge(proc.arch, sessionArch);
              const blocked = isBlocked(proc.name);
              const isAV = isAVProcess(proc.name);
              const isEDR = isEDRProcess(proc.name);
              const riskLevel = getProcessRiskLevel(proc);

              return (
                <tr
                  key={proc.pid}
                  className={`
                    hover:bg-ctp-surface0/50
                    ${proc.isCurrent ? 'bg-ctp-blue/10' : ''}
                    ${isEDR ? 'bg-ctp-red/5 border-l-2 border-ctp-red/40' : ''}
                  `}
                >
                  <td className="px-3 py-2 font-mono text-ctp-blue">{proc.pid}</td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <span className={`${getIntegrityColor(proc.integrity)} ${proc.isElevated ? 'font-semibold' : ''} ${isEDR ? 'text-ctp-red font-semibold' : ''}`}>
                        {proc.name}
                      </span>
                      {proc.isCurrent && (
                        <span className="text-xs bg-ctp-green/20 text-ctp-green px-1 rounded">current</span>
                      )}
                      {isEDR && (
                        <span className="text-xs bg-ctp-red/20 text-ctp-red px-1 rounded font-medium" title="EDR/Security sensor process">EDR</span>
                      )}
                      {isAV && !isEDR && (
                        <span className="text-xs bg-ctp-peach/20 text-ctp-peach px-1 rounded" title="Security product">AV</span>
                      )}
                      {blocked && (
                        <span className="text-xs bg-ctp-red/20 text-ctp-red px-1 rounded">blocked</span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-ctp-subtext0 truncate max-w-[150px]" title={proc.user}>
                    {proc.user}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 text-xs rounded ${archBadge.bg} ${archBadge.text}`}>
                      {proc.arch}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`text-xs ${getIntegrityColor(proc.integrity)}`}>
                      {proc.integrity}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <RiskBadge level={riskLevel} />
                  </td>
                  <td className="px-3 py-2">
                    <button
                      onClick={() => handleInjectClick(proc.pid)}
                      disabled={blocked || !proc.isInjectable}
                      className={`px-2 py-1 text-xs rounded transition-colors ${
                        blocked || !proc.isInjectable
                          ? 'bg-ctp-surface0 text-ctp-overlay0 cursor-not-allowed'
                          : 'bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/30'
                      }`}
                    >
                      Inject
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Inject Modal */}
      {injectModalOpen && selectedProcess && (
        <ShellcodeInjectModal
          process={selectedProcess}
          sessionId={sessionId}
          onClose={() => setInjectModalOpen(false)}
          onInject={(shellcode, method) => {
            console.log('Injecting', shellcode.length, 'bytes into', selectedProcess.pid, 'via', method);
            setInjectModalOpen(false);
            onInject?.(selectedProcess.pid, selectedProcess.name);
          }}
        />
      )}
    </div>
  );
}

// Shellcode Inject Modal
interface ShellcodeInjectModalProps {
  process: ProcessEntry;
  sessionId: string;
  onClose: () => void;
  onInject: (shellcode: Uint8Array, method: string) => void;
}

// Ordered by OPSEC score descending for display
const TECHNIQUE_ORDER: InjectionTechnique[] = ['ntapi', 'auto', 'apc', 'win32', 'thread_hijack'];

function ShellcodeInjectModal({ process, sessionId: _sessionId, onClose, onInject }: ShellcodeInjectModalProps) {
  const [shellcode, setShellcode] = useState<Uint8Array | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [method, setMethod] = useState<InjectionTechnique>('auto');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [opsecModeOnly, setOpsecModeOnly] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      setShellcode(new Uint8Array(reader.result as ArrayBuffer));
    };
    reader.readAsArrayBuffer(file);
  };

  const handleSubmit = () => {
    if (!shellcode) return;
    setIsSubmitting(true);
    onInject(shellcode, method);
  };

  const isAV = isAVProcess(process.name);
  const isEDR = isEDRProcess(process.name);

  // Techniques filtered by OPSEC mode toggle (score > 60 = safe)
  const visibleTechniques = TECHNIQUE_ORDER.filter((t) => {
    const profile = INJECTION_TECHNIQUE_PROFILES[t];
    if (opsecModeOnly && profile.opsecScore <= 60) return false;
    return true;
  });

  // If the currently selected technique was filtered out, reset to first visible
  const effectiveMethod: InjectionTechnique =
    visibleTechniques.includes(method) ? method : (visibleTechniques[0] ?? 'auto');

  const selectedProfile = INJECTION_TECHNIQUE_PROFILES[effectiveMethod];

  return (
    <Modal isOpen={true} onClose={onClose} title={`Inject into ${process.name} (PID ${process.pid})`}>
      <div className="space-y-4">
        {/* OPSEC Warning */}
        {(isAV || isEDR) && (
          <div className={`p-3 rounded-lg border ${isEDR ? 'bg-ctp-red/10 border-ctp-red/30' : 'bg-ctp-peach/10 border-ctp-peach/30'}`}>
            <div className={`flex items-center gap-2 text-sm font-medium ${isEDR ? 'text-ctp-red' : 'text-ctp-peach'}`}>
              <svg className="w-4 h-4 flex-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              {isEDR ? 'EDR PROCESS — CRITICAL RISK' : 'OPSEC WARNING'}
            </div>
            <p className="text-xs text-ctp-subtext0 mt-1">
              {isEDR
                ? 'This is an EDR sensor process. Injection will almost certainly trigger an immediate alert and may crash the sensor.'
                : 'This process appears to be a security product. Injection may trigger alerts.'}
            </p>
          </div>
        )}

        {/* Shellcode Upload */}
        <div>
          <label className="block text-sm font-medium text-ctp-text mb-2">Shellcode</label>
          <div className="border-2 border-dashed border-ctp-surface1 rounded-lg p-4 text-center hover:border-ctp-mauve transition-colors">
            <input
              type="file"
              accept=".bin,.raw,.sc"
              onChange={handleFileChange}
              className="hidden"
              id="shellcode-upload"
            />
            <label htmlFor="shellcode-upload" className="cursor-pointer">
              {shellcode ? (
                <div className="text-sm">
                  <span className="text-ctp-green">✓</span>{' '}
                  <span className="text-ctp-text">{fileName}</span>{' '}
                  <span className="text-ctp-subtext0">({shellcode.length} bytes)</span>
                </div>
              ) : (
                <div className="text-ctp-subtext0 text-sm">
                  Drop .bin/.raw shellcode or click to upload
                </div>
              )}
            </label>
          </div>
        </div>

        {/* Technique Picker Header */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <label className="text-sm font-medium text-ctp-text">Injection Technique</label>
            {/* OPSEC Mode Toggle */}
            <button
              type="button"
              onClick={() => setOpsecModeOnly((v) => !v)}
              className={`
                flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium
                border transition-all duration-150
                ${opsecModeOnly
                  ? 'bg-ctp-green/20 border-ctp-green/40 text-ctp-green'
                  : 'bg-ctp-surface0 border-ctp-surface1 text-ctp-subtext0 hover:border-ctp-surface2'}
              `}
            >
              <svg
                className={`w-3 h-3 transition-colors ${opsecModeOnly ? 'text-ctp-green' : 'text-ctp-overlay1'}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              OPSEC Safe Only
            </button>
          </div>

          {/* Technique Cards */}
          <div className="space-y-2">
            {visibleTechniques.map((techKey) => {
              const profile = INJECTION_TECHNIQUE_PROFILES[techKey];
              const isSelected = effectiveMethod === techKey;
              // Invert opsecScore: higher score = lower detection risk
              const detectionRisk = 100 - profile.opsecScore;

              return (
                <label
                  key={techKey}
                  className={`
                    block p-3 rounded-lg border cursor-pointer transition-all duration-150
                    ${isSelected
                      ? 'border-ctp-mauve bg-ctp-mauve/10 ring-1 ring-ctp-mauve/30'
                      : 'border-ctp-surface1 bg-ctp-surface0/40 hover:border-ctp-surface2 hover:bg-ctp-surface0'}
                  `}
                >
                  <input
                    type="radio"
                    name="method"
                    value={techKey}
                    checked={isSelected}
                    onChange={() => setMethod(techKey)}
                    className="sr-only"
                  />

                  {/* Card top row: name + risk badge */}
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {isSelected && (
                        <span className="w-2 h-2 rounded-full bg-ctp-mauve flex-none" />
                      )}
                      <span className={`text-sm font-medium ${isSelected ? 'text-ctp-text' : 'text-ctp-subtext1'}`}>
                        {profile.name}
                      </span>
                    </div>
                    <RiskBadge level={profile.riskLevel} />
                  </div>

                  {/* Description */}
                  <p className="text-xs text-ctp-subtext0 mb-2 leading-relaxed">
                    {profile.description}
                  </p>

                  {/* OPSEC Score meter */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-ctp-overlay1">Detection risk</span>
                      <span className="text-xs font-mono text-ctp-subtext0">{detectionRisk}/100</span>
                    </div>
                    <RiskMeter score={detectionRisk} showLabel={false} />
                  </div>

                  {/* Detection vectors (collapsed summary) */}
                  {isSelected && profile.detectionVectors.length > 0 && (
                    <div className="mt-3 pt-2 border-t border-ctp-surface1 space-y-1.5">
                      <span className="text-xs text-ctp-overlay1 uppercase tracking-wide">Detection Vectors</span>
                      {profile.detectionVectors.map((vec, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <span className={`text-xs font-medium mt-0.5 flex-none ${
                            vec.likelihood === 'high' ? 'text-ctp-red' :
                            vec.likelihood === 'medium' ? 'text-ctp-yellow' : 'text-ctp-green'
                          }`}>
                            {vec.likelihood === 'high' ? '●' : vec.likelihood === 'medium' ? '◐' : '○'}
                          </span>
                          <div>
                            <span className="text-xs text-ctp-subtext1 font-medium">{vec.name}</span>
                            <span className="text-xs text-ctp-subtext0"> — {vec.description}</span>
                          </div>
                        </div>
                      ))}
                      {profile.bestFor.length > 0 && (
                        <div className="pt-1 text-xs text-ctp-subtext0">
                          <span className="text-ctp-overlay1">Best for: </span>
                          {profile.bestFor.join(', ')}
                        </div>
                      )}
                    </div>
                  )}
                </label>
              );
            })}

            {visibleTechniques.length === 0 && (
              <div className="p-4 text-center text-xs text-ctp-subtext0 bg-ctp-surface0 rounded-lg border border-ctp-surface1">
                No techniques pass the OPSEC filter. Disable "OPSEC Safe Only" to see all options.
              </div>
            )}
          </div>
        </div>

        {/* Warning */}
        <div className="p-3 bg-ctp-surface0 rounded-lg text-xs text-ctp-subtext0">
          Injection may crash the target process or trigger security alerts.
          {selectedProfile && selectedProfile.requirements.length > 0 && (
            <span className="block mt-1 text-ctp-overlay1">
              Requires: {selectedProfile.requirements.join(', ')}
            </span>
          )}
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-ctp-text bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={!shellcode || isSubmitting || visibleTechniques.length === 0}
            className="px-4 py-2 text-sm text-ctp-crust bg-ctp-red hover:bg-ctp-red/90 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? 'Injecting...' : 'Inject'}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export default ProcessBrowser;
