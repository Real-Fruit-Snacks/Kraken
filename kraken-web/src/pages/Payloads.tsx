// Payload Generator - Professional implant generation UI
// Based on Sliver/Mythic/Cobalt Strike patterns

import { useState, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { listenerClient, payloadClient } from '../api/index.js';
import { WorkingHours } from '../api/index.js';
import { Modal } from '../components/Modal';

// Payload configuration types
type PayloadFormat = 'exe' | 'dll' | 'shellcode' | 'service' | 'powershell';
type PayloadArch = 'x64' | 'x86';
type PayloadOS = 'windows' | 'linux' | 'darwin';
type TransportType = 'http' | 'https' | 'dns' | 'tcp' | 'smb';

interface PayloadConfig {
  name: string;
  os: PayloadOS;
  arch: PayloadArch;
  format: PayloadFormat;
  transport: TransportType;
  listenerId: string;
  c2Endpoints: string[];
  // Evasion options
  obfuscation: boolean;
  antiDebug: boolean;
  antiSandbox: boolean;
  sleepMask: boolean;
  // Behavior options
  jitter: number;
  sleepTime: number;
  killDate: string;
  workingHours: { start: string; end: string } | null;
}

interface GeneratedPayload {
  id: string;
  name: string;
  config: PayloadConfig;
  generatedAt: Date;
  size: number;
  hash: string;
}

const FORMAT_INFO: Record<PayloadFormat, { label: string; description: string; icon: string }> = {
  exe: {
    label: 'Executable (.exe)',
    description: 'Standalone Windows executable',
    icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  },
  dll: {
    label: 'Dynamic Library (.dll)',
    description: 'DLL for injection or sideloading',
    icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10',
  },
  shellcode: {
    label: 'Shellcode (raw)',
    description: 'Position-independent code for loaders',
    icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
  },
  service: {
    label: 'Windows Service',
    description: 'Service binary for persistence',
    icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01',
  },
  powershell: {
    label: 'PowerShell Stager',
    description: 'Encoded PowerShell one-liner',
    icon: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
  },
};

const OS_INFO: Record<PayloadOS, { label: string; formats: PayloadFormat[] }> = {
  windows: {
    label: 'Windows',
    formats: ['exe', 'dll', 'shellcode', 'service', 'powershell'],
  },
  linux: {
    label: 'Linux',
    formats: ['shellcode'],
  },
  darwin: {
    label: 'macOS',
    formats: ['shellcode'],
  },
};

function uuidToHex(uuid: { value: Uint8Array } | undefined): string {
  if (!uuid?.value) return '';
  return Array.from(uuid.value).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function Payloads() {
  const [config, setConfig] = useState<PayloadConfig>({
    name: '',
    os: 'windows',
    arch: 'x64',
    format: 'exe',
    transport: 'https',
    listenerId: '',
    c2Endpoints: [],
    obfuscation: true,
    antiDebug: true,
    antiSandbox: false,
    sleepMask: true,
    jitter: 20,
    sleepTime: 60,
    killDate: '',
    workingHours: null,
  });

  const [generating, setGenerating] = useState(false);
  const [generatedPayloads, setGeneratedPayloads] = useState<GeneratedPayload[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [previewModal, setPreviewModal] = useState<GeneratedPayload | null>(null);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // Fetch existing payloads from backend
  const { data: backendPayloads = [] } = useQuery({
    queryKey: ['payloads'],
    queryFn: async () => {
      const res = await payloadClient.listPayloads({});
      return res.payloads.map(p => mapBackendPayload(p));
    },
  });

  // Fetch listeners for C2 endpoint selection
  const { data: listeners = [] } = useQuery({
    queryKey: ['listeners'],
    queryFn: async () => {
      const res = await listenerClient.listListeners({});
      return res.listeners.map(l => ({
        id: uuidToHex(l.id),
        name: `${l.listenerType.toUpperCase()} :${l.bindPort}`,
        type: l.listenerType,
        host: l.bindHost,
        port: l.bindPort,
        running: l.isRunning,
      }));
    },
  });

  // Available formats for selected OS
  const availableFormats = useMemo(() => {
    return OS_INFO[config.os].formats;
  }, [config.os]);

  // Reset format if not available for OS
  const handleOsChange = (os: PayloadOS) => {
    const formats = OS_INFO[os].formats;
    setConfig(prev => ({
      ...prev,
      os,
      format: formats.includes(prev.format) ? prev.format : formats[0],
    }));
  };

  const hexToBytes = (hex: string): Uint8Array<ArrayBuffer> => {
    const buffer = new ArrayBuffer(hex.length / 2);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
  };

  const mapBackendPayload = (p: { id: Uint8Array; name: string; os: string; arch: string; format: string; transport: string; generatedAt?: { millis: bigint } | undefined; size: bigint; hash: string }): GeneratedPayload => ({
    id: Array.from(p.id).map(b => b.toString(16).padStart(2, '0')).join(''),
    name: p.name,
    config: {
      name: p.name,
      os: p.os as PayloadOS,
      arch: p.arch as PayloadArch,
      format: p.format as PayloadFormat,
      transport: p.transport as TransportType,
      listenerId: '',
      c2Endpoints: [],
      obfuscation: false,
      antiDebug: false,
      antiSandbox: false,
      sleepMask: false,
      jitter: 0,
      sleepTime: 60,
      killDate: '',
      workingHours: null,
    },
    generatedAt: p.generatedAt ? new Date(Number(p.generatedAt.millis)) : new Date(),
    size: Number(p.size),
    hash: p.hash,
  });

  const handleGenerate = async () => {
    if (!config.name || !config.listenerId) return;

    setGenerating(true);
    setGenerateError(null);
    try {
      const response = await payloadClient.generatePayload({
        name: config.name,
        os: config.os,
        arch: config.arch,
        format: config.format,
        transport: config.transport,
        listenerId: hexToBytes(config.listenerId),
        c2Endpoints: config.c2Endpoints,
        obfuscation: config.obfuscation,
        antiDebug: config.antiDebug,
        antiSandbox: config.antiSandbox,
        sleepMask: config.sleepMask,
        jitter: config.jitter,
        sleepTime: config.sleepTime,
        killDate: config.killDate,
        workingHours: config.workingHours
          ? new WorkingHours({ start: config.workingHours.start, end: config.workingHours.end })
          : undefined,
      });

      // Download the binary content if present
      if (response.content && response.content.length > 0) {
        const blob = new Blob([response.content], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${config.name}.${config.format}`;
        a.click();
        URL.revokeObjectURL(url);
      }

      // Add to local list and invalidate backend list
      if (response.payload) {
        const mapped = mapBackendPayload(response.payload as Parameters<typeof mapBackendPayload>[0]);
        setGeneratedPayloads(prev => [mapped, ...prev]);
      }
      await queryClient.invalidateQueries({ queryKey: ['payloads'] });
      setConfig(prev => ({ ...prev, name: '' }));
    } catch (error) {
      console.error('Failed to generate payload:', error);
      setGenerateError(error instanceof Error ? error.message : 'Failed to generate payload');
    } finally {
      setGenerating(false);
    }
  };

  const handleDeletePayload = async (id: string) => {
    try {
      await payloadClient.deletePayload({ payloadId: hexToBytes(id) });
      setGeneratedPayloads(prev => prev.filter(p => p.id !== id));
      await queryClient.invalidateQueries({ queryKey: ['payloads'] });
    } catch (error) {
      console.error('Failed to delete payload:', error);
    }
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ctp-text">Payload Generator</h1>
          <p className="text-ctp-subtext0 mt-1">Generate implants for target deployment</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration Panel */}
        <div className="lg:col-span-2 space-y-6">
          {/* Basic Configuration */}
          <div className="bg-ctp-mantle rounded-xl border border-ctp-surface0 p-6">
            <h2 className="text-lg font-semibold text-ctp-text mb-4">Configuration</h2>

            {/* Payload Name */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-ctp-subtext1 mb-1">
                Payload Name
              </label>
              <input
                type="text"
                value={config.name}
                onChange={e => setConfig(prev => ({ ...prev, name: e.target.value }))}
                placeholder="e.g., target-finance-01"
                className="w-full px-4 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-mauve"
              />
            </div>

            {/* OS & Architecture */}
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-ctp-subtext1 mb-1">
                  Target OS
                </label>
                <div className="flex gap-2">
                  {(Object.keys(OS_INFO) as PayloadOS[]).map(os => (
                    <button
                      key={os}
                      onClick={() => handleOsChange(os)}
                      className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                        config.os === os
                          ? 'bg-ctp-mauve text-ctp-crust'
                          : 'bg-ctp-surface0 text-ctp-subtext1 hover:bg-ctp-surface1'
                      }`}
                    >
                      {OS_INFO[os].label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-ctp-subtext1 mb-1">
                  Architecture
                </label>
                <div className="flex gap-2">
                  {(['x64', 'x86'] as PayloadArch[]).map(arch => (
                    <button
                      key={arch}
                      onClick={() => setConfig(prev => ({ ...prev, arch }))}
                      className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                        config.arch === arch
                          ? 'bg-ctp-mauve text-ctp-crust'
                          : 'bg-ctp-surface0 text-ctp-subtext1 hover:bg-ctp-surface1'
                      }`}
                    >
                      {arch}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Format Selection */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-ctp-subtext1 mb-2">
                Output Format
              </label>
              <div className="grid grid-cols-2 gap-2">
                {availableFormats.map(format => (
                  <button
                    key={format}
                    onClick={() => setConfig(prev => ({ ...prev, format }))}
                    className={`p-3 rounded-lg text-left transition-colors border ${
                      config.format === format
                        ? 'bg-ctp-mauve/10 border-ctp-mauve text-ctp-text'
                        : 'bg-ctp-surface0 border-ctp-surface1 text-ctp-subtext1 hover:border-ctp-surface2'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={FORMAT_INFO[format].icon} />
                      </svg>
                      <div>
                        <div className="text-sm font-medium">{FORMAT_INFO[format].label}</div>
                        <div className="text-xs text-ctp-overlay0">{FORMAT_INFO[format].description}</div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Listener Selection */}
            <div className="mb-4">
              <label className="block text-sm font-medium text-ctp-subtext1 mb-1">
                C2 Listener
              </label>
              <select
                value={config.listenerId}
                onChange={e => setConfig(prev => ({ ...prev, listenerId: e.target.value }))}
                className="w-full px-4 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve"
              >
                <option value="">Select a listener...</option>
                {listeners.filter(l => l.running).map(listener => (
                  <option key={listener.id} value={listener.id}>
                    {listener.name} ({listener.host}:{listener.port})
                  </option>
                ))}
              </select>
              {listeners.filter(l => l.running).length === 0 && (
                <p className="text-xs text-ctp-yellow mt-1">
                  No active listeners. Start a listener first.
                </p>
              )}
            </div>
          </div>

          {/* Evasion Options */}
          <div className="bg-ctp-mantle rounded-xl border border-ctp-surface0 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-ctp-text">Evasion Options</h2>
              <span className="px-2 py-1 text-xs rounded bg-ctp-red/20 text-ctp-red">OPSEC</span>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {[
                { key: 'obfuscation', label: 'String Obfuscation', desc: 'Encrypt static strings' },
                { key: 'antiDebug', label: 'Anti-Debug', desc: 'Detect debugger attachment' },
                { key: 'antiSandbox', label: 'Anti-Sandbox', desc: 'Detect analysis environments' },
                { key: 'sleepMask', label: 'Sleep Masking', desc: 'Encrypt memory during sleep' },
              ].map(opt => (
                <label
                  key={opt.key}
                  className="flex items-start gap-3 p-3 rounded-lg bg-ctp-surface0 cursor-pointer hover:bg-ctp-surface0/80"
                >
                  <input
                    type="checkbox"
                    checked={config[opt.key as keyof PayloadConfig] as boolean}
                    onChange={e => setConfig(prev => ({ ...prev, [opt.key]: e.target.checked }))}
                    className="mt-0.5 w-4 h-4 rounded bg-ctp-surface1 border-ctp-surface2 text-ctp-mauve focus:ring-ctp-mauve"
                  />
                  <div>
                    <div className="text-sm font-medium text-ctp-text">{opt.label}</div>
                    <div className="text-xs text-ctp-overlay0">{opt.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Advanced Options (Collapsible) */}
          <div className="bg-ctp-mantle rounded-xl border border-ctp-surface0">
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="w-full p-4 flex items-center justify-between text-left"
            >
              <span className="font-semibold text-ctp-text">Advanced Options</span>
              <svg
                className={`w-5 h-5 text-ctp-subtext0 transition-transform ${showAdvanced ? 'rotate-180' : ''}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {showAdvanced && (
              <div className="px-6 pb-6 space-y-4 border-t border-ctp-surface0 pt-4">
                {/* Sleep & Jitter */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-ctp-subtext1 mb-1">
                      Sleep Time (seconds)
                    </label>
                    <input
                      type="number"
                      value={config.sleepTime}
                      onChange={e => setConfig(prev => ({ ...prev, sleepTime: parseInt(e.target.value) || 60 }))}
                      min={5}
                      max={86400}
                      className="w-full px-4 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-ctp-subtext1 mb-1">
                      Jitter (%)
                    </label>
                    <input
                      type="number"
                      value={config.jitter}
                      onChange={e => setConfig(prev => ({ ...prev, jitter: parseInt(e.target.value) || 0 }))}
                      min={0}
                      max={100}
                      className="w-full px-4 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve"
                    />
                  </div>
                </div>

                {/* Kill Date */}
                <div>
                  <label className="block text-sm font-medium text-ctp-subtext1 mb-1">
                    Kill Date (optional)
                  </label>
                  <input
                    type="date"
                    value={config.killDate}
                    onChange={e => setConfig(prev => ({ ...prev, killDate: e.target.value }))}
                    className="w-full px-4 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 focus:outline-none focus:border-ctp-mauve"
                  />
                  <p className="text-xs text-ctp-overlay0 mt-1">
                    Implant will terminate after this date
                  </p>
                </div>

                {/* Working Hours */}
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-ctp-subtext1 mb-2">
                    <input
                      type="checkbox"
                      checked={config.workingHours !== null}
                      onChange={e => setConfig(prev => ({
                        ...prev,
                        workingHours: e.target.checked ? { start: '09:00', end: '17:00' } : null,
                      }))}
                      className="w-4 h-4 rounded bg-ctp-surface1 border-ctp-surface2 text-ctp-mauve focus:ring-ctp-mauve"
                    />
                    Working Hours Only
                  </label>
                  {config.workingHours && (
                    <div className="flex items-center gap-2 ml-6">
                      <input
                        type="time"
                        value={config.workingHours.start}
                        onChange={e => setConfig(prev => ({
                          ...prev,
                          workingHours: { ...prev.workingHours!, start: e.target.value },
                        }))}
                        className="px-3 py-1.5 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 text-sm"
                      />
                      <span className="text-ctp-subtext0">to</span>
                      <input
                        type="time"
                        value={config.workingHours.end}
                        onChange={e => setConfig(prev => ({
                          ...prev,
                          workingHours: { ...prev.workingHours!, end: e.target.value },
                        }))}
                        className="px-3 py-1.5 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 text-sm"
                      />
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Error display */}
          {generateError && (
            <div className="px-4 py-3 rounded-lg bg-ctp-red/10 border border-ctp-red/30 text-ctp-red text-sm">
              {generateError}
            </div>
          )}

          {/* Generate Button */}
          <button
            onClick={handleGenerate}
            disabled={generating || !config.name || !config.listenerId}
            className={`w-full py-4 rounded-xl font-semibold text-lg transition-all flex items-center justify-center gap-3 ${
              generating || !config.name || !config.listenerId
                ? 'bg-ctp-surface0 text-ctp-overlay0 cursor-not-allowed'
                : 'bg-ctp-mauve text-ctp-crust hover:bg-ctp-mauve/90'
            }`}
          >
            {generating ? (
              <>
                <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Generating Payload...
              </>
            ) : (
              <>
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
                </svg>
                Generate Payload
              </>
            )}
          </button>
        </div>

        {/* Generated Payloads */}
        <div className="space-y-4">
          <div className="bg-ctp-mantle rounded-xl border border-ctp-surface0 p-4">
            <h2 className="text-lg font-semibold text-ctp-text mb-4">Generated Payloads</h2>

            {(() => {
              // Merge backend payloads with session-generated ones, dedup by id
              const sessionIds = new Set(generatedPayloads.map(p => p.id));
              const allPayloads = [
                ...generatedPayloads,
                ...backendPayloads.filter(p => !sessionIds.has(p.id)),
              ];
              return allPayloads.length === 0 ? (
                <div className="text-center py-8 text-ctp-subtext0">
                  <svg className="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                  </svg>
                  <p className="text-sm">No payloads generated yet</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {allPayloads.map(payload => (
                    <div
                      key={payload.id}
                      className="p-3 rounded-lg bg-ctp-surface0 hover:bg-ctp-surface0/80 transition-colors"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium text-ctp-text text-sm">{payload.name}</span>
                        <span className="text-xs text-ctp-overlay0">
                          {payload.generatedAt.toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-ctp-subtext0 mb-3">
                        <span className="px-1.5 py-0.5 rounded bg-ctp-surface1">
                          {payload.config.os}/{payload.config.arch}
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-ctp-surface1">
                          {payload.config.format}
                        </span>
                        <span>{formatSize(payload.size)}</span>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => setPreviewModal(payload)}
                          className="flex-1 px-3 py-1.5 rounded text-xs font-medium bg-ctp-surface1 text-ctp-subtext1 hover:bg-ctp-surface2 transition-colors"
                        >
                          Details
                        </button>
                        <button
                          onClick={() => handleDeletePayload(payload.id)}
                          className="px-3 py-1.5 rounded text-xs font-medium bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/30 transition-colors"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>

          {/* Quick Tips */}
          <div className="bg-ctp-mantle rounded-xl border border-ctp-surface0 p-4">
            <h3 className="text-sm font-semibold text-ctp-text mb-3">OPSEC Tips</h3>
            <ul className="space-y-2 text-xs text-ctp-subtext0">
              <li className="flex gap-2">
                <svg className="w-4 h-4 text-ctp-yellow flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Use unique payloads per target to prevent lateral detection
              </li>
              <li className="flex gap-2">
                <svg className="w-4 h-4 text-ctp-green flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Set kill dates to limit exposure window
              </li>
              <li className="flex gap-2">
                <svg className="w-4 h-4 text-ctp-blue flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Working hours reduce beacon noise
              </li>
              <li className="flex gap-2">
                <svg className="w-4 h-4 text-ctp-mauve flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                Sleep masking hides beacon in memory
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Payload Details Modal */}
      {previewModal && (
        <Modal
          isOpen={true}
          onClose={() => setPreviewModal(null)}
          title="Payload Details"
          size="lg"
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-ctp-subtext0">Name</span>
                <p className="font-medium text-ctp-text">{previewModal.name}</p>
              </div>
              <div>
                <span className="text-ctp-subtext0">Generated</span>
                <p className="font-medium text-ctp-text">{previewModal.generatedAt.toLocaleString()}</p>
              </div>
              <div>
                <span className="text-ctp-subtext0">Platform</span>
                <p className="font-medium text-ctp-text">{previewModal.config.os}/{previewModal.config.arch}</p>
              </div>
              <div>
                <span className="text-ctp-subtext0">Format</span>
                <p className="font-medium text-ctp-text">{FORMAT_INFO[previewModal.config.format].label}</p>
              </div>
              <div>
                <span className="text-ctp-subtext0">Size</span>
                <p className="font-medium text-ctp-text">{formatSize(previewModal.size)}</p>
              </div>
              <div>
                <span className="text-ctp-subtext0">Transport</span>
                <p className="font-medium text-ctp-text">{previewModal.config.transport.toUpperCase()}</p>
              </div>
            </div>

            <div>
              <span className="text-sm text-ctp-subtext0">SHA-256 Hash</span>
              <p className="font-mono text-xs text-ctp-text bg-ctp-surface0 p-2 rounded mt-1 break-all">
                {previewModal.hash}
              </p>
            </div>

            <div>
              <span className="text-sm text-ctp-subtext0">Evasion Features</span>
              <div className="flex flex-wrap gap-2 mt-1">
                {previewModal.config.obfuscation && (
                  <span className="px-2 py-1 text-xs rounded bg-ctp-green/20 text-ctp-green">Obfuscation</span>
                )}
                {previewModal.config.antiDebug && (
                  <span className="px-2 py-1 text-xs rounded bg-ctp-green/20 text-ctp-green">Anti-Debug</span>
                )}
                {previewModal.config.antiSandbox && (
                  <span className="px-2 py-1 text-xs rounded bg-ctp-green/20 text-ctp-green">Anti-Sandbox</span>
                )}
                {previewModal.config.sleepMask && (
                  <span className="px-2 py-1 text-xs rounded bg-ctp-green/20 text-ctp-green">Sleep Mask</span>
                )}
              </div>
            </div>

            <div className="flex gap-3 pt-4 border-t border-ctp-surface0">
              <button
                onClick={() => setPreviewModal(null)}
                className="flex-1 py-2 rounded-lg bg-ctp-surface0 text-ctp-text hover:bg-ctp-surface1 transition-colors"
              >
                Close
              </button>
              <button className="flex-1 py-2 rounded-lg bg-ctp-blue text-ctp-crust hover:bg-ctp-blue/90 transition-colors">
                Download
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

export default Payloads;
