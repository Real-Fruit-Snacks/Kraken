// BOF Execution Panel - Professional BOF browser and execution UI
// Based on research: Category browser, typed arguments, OPSEC warnings

import { useState, useMemo } from 'react';
import {
  BOFManifest,
  BOFCategory,
  BOF_COLORS,
  CATEGORY_CONFIG,
  ARG_TYPE_CONFIG,
  assessBOFOpsec,
} from './types';

interface BOFExecutionPanelProps {
  sessionOs: string;
  sessionArch: string;
  bofs: BOFManifest[];
  onExecute: (bofId: string, args: Record<string, unknown>) => Promise<void>;
}

export function BOFExecutionPanel({
  sessionOs,
  sessionArch,
  bofs,
  onExecute,
}: BOFExecutionPanelProps) {
  const [selectedCategory, setSelectedCategory] = useState<BOFCategory | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedBof, setSelectedBof] = useState<BOFManifest | null>(null);
  const [args, setArgs] = useState<Record<string, string | number>>({});
  const [isExecuting, setIsExecuting] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  // Filter BOFs by category and search
  const filteredBofs = useMemo(() => {
    return bofs.filter((bof) => {
      const matchesCategory = selectedCategory === 'all' || bof.category === selectedCategory;
      const matchesSearch =
        !searchQuery ||
        bof.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        bof.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        bof.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchesCategory && matchesSearch;
    });
  }, [bofs, selectedCategory, searchQuery]);

  // OPSEC assessment for selected BOF
  const opsecAssessment = useMemo(() => {
    if (!selectedBof) return null;
    return assessBOFOpsec(selectedBof, sessionOs, sessionArch);
  }, [selectedBof, sessionOs, sessionArch]);

  const handleExecute = async () => {
    if (!selectedBof) return;

    setIsExecuting(true);
    try {
      await onExecute(selectedBof.id, args);
    } finally {
      setIsExecuting(false);
      setShowConfirm(false);
    }
  };

  const handleArgChange = (name: string, value: string | number) => {
    setArgs((prev) => ({ ...prev, [name]: value }));
  };

  const categories = Object.keys(CATEGORY_CONFIG) as BOFCategory[];

  return (
    <div className="flex h-full bg-ctp-base">
      {/* Category Sidebar */}
      <div className="w-56 border-r border-ctp-surface0 flex flex-col">
        <div className="p-3 border-b border-ctp-surface0">
          <div className="relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ctp-overlay0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search BOFs..."
              className="w-full pl-9 pr-3 py-2 text-sm rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-mauve"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-2">
          <button
            onClick={() => setSelectedCategory('all')}
            className={`w-full px-3 py-2 rounded-lg text-left text-sm transition-colors ${
              selectedCategory === 'all'
                ? 'bg-ctp-surface0 text-ctp-text'
                : 'text-ctp-subtext1 hover:bg-ctp-surface0/50'
            }`}
          >
            All BOFs ({bofs.length})
          </button>

          <div className="mt-2 space-y-1">
            {categories.map((cat) => {
              const count = bofs.filter((b) => b.category === cat).length;
              return (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`w-full px-3 py-2 rounded-lg text-left text-sm transition-colors flex items-center gap-2 ${
                    selectedCategory === cat
                      ? 'bg-ctp-surface0 text-ctp-text'
                      : 'text-ctp-subtext1 hover:bg-ctp-surface0/50'
                  }`}
                >
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: BOF_COLORS.category[cat] }}
                  />
                  <span className="flex-1">{CATEGORY_CONFIG[cat].label}</span>
                  <span className="text-xs text-ctp-overlay0">{count}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* BOF List */}
      <div className="w-72 border-r border-ctp-surface0 flex flex-col">
        <div className="p-3 border-b border-ctp-surface0">
          <h3 className="text-sm font-medium text-ctp-text">
            {selectedCategory === 'all' ? 'All BOFs' : CATEGORY_CONFIG[selectedCategory].label}
          </h3>
          <p className="text-xs text-ctp-subtext0">{filteredBofs.length} available</p>
        </div>

        <div className="flex-1 overflow-y-auto">
          {filteredBofs.map((bof) => {
            const isCompatible = bof.platforms.some(
              (p) => p.os === sessionOs && p.arch === sessionArch
            );
            return (
              <button
                key={bof.id}
                onClick={() => {
                  setSelectedBof(bof);
                  setArgs({});
                }}
                className={`w-full p-3 border-b border-ctp-surface0 text-left transition-colors ${
                  selectedBof?.id === bof.id
                    ? 'bg-ctp-surface0'
                    : 'hover:bg-ctp-surface0/50'
                } ${!isCompatible ? 'opacity-50' : ''}`}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-sm font-medium text-ctp-text">{bof.name}</div>
                    <div className="text-xs text-ctp-subtext0 mt-0.5">{bof.description}</div>
                  </div>
                  {!isCompatible && (
                    <span className="px-1.5 py-0.5 text-xs rounded bg-ctp-red/20 text-ctp-red">
                      !
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1 mt-2">
                  <span
                    className="px-1.5 py-0.5 text-xs rounded"
                    style={{
                      backgroundColor: BOF_COLORS.category[bof.category] + '20',
                      color: BOF_COLORS.category[bof.category],
                    }}
                  >
                    {bof.category}
                  </span>
                  <span className="text-xs text-ctp-overlay0">v{bof.version}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* BOF Detail & Execution */}
      <div className="flex-1 flex flex-col">
        {selectedBof ? (
          <>
            {/* BOF Header */}
            <div className="p-4 border-b border-ctp-surface0">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-lg font-semibold text-ctp-text">{selectedBof.name}</h2>
                  <p className="text-sm text-ctp-subtext1 mt-1">{selectedBof.description}</p>
                </div>
                <div className="flex items-center gap-2">
                  {selectedBof.platforms.map((p) => (
                    <span
                      key={`${p.os}-${p.arch}`}
                      className={`px-2 py-1 text-xs rounded ${
                        p.os === sessionOs && p.arch === sessionArch
                          ? 'bg-ctp-green/20 text-ctp-green'
                          : 'bg-ctp-surface0 text-ctp-subtext0'
                      }`}
                    >
                      {p.os}/{p.arch}
                    </span>
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-4 mt-3 text-xs text-ctp-subtext0">
                <span>Author: {selectedBof.author}</span>
                <span>Version: {selectedBof.version}</span>
                {selectedBof.repoUrl && (
                  <a href={selectedBof.repoUrl} target="_blank" rel="noopener noreferrer" className="text-ctp-blue hover:underline">
                    Source
                  </a>
                )}
              </div>
            </div>

            {/* OPSEC Warning Banner - ALWAYS VISIBLE */}
            <div className={`p-4 border-b ${
              opsecAssessment?.archMatch === false
                ? 'bg-ctp-red/10 border-ctp-red/30'
                : 'bg-ctp-yellow/10 border-ctp-yellow/30'
            }`}>
              <div className="flex items-start gap-3">
                <svg className={`w-5 h-5 flex-shrink-0 ${
                  opsecAssessment?.archMatch === false ? 'text-ctp-red' : 'text-ctp-yellow'
                }`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <p className={`text-sm font-medium ${
                    opsecAssessment?.archMatch === false ? 'text-ctp-red' : 'text-ctp-yellow'
                  }`}>
                    {opsecAssessment?.archMatch === false
                      ? 'CRITICAL: Architecture Mismatch - Execution WILL crash the session'
                      : 'BOF Execution Warning'}
                  </p>
                  <p className="text-xs text-ctp-subtext1 mt-1">
                    BOFs execute inside the agent process. A crash will terminate your session.
                  </p>
                  {opsecAssessment && opsecAssessment.detectionVectors.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {opsecAssessment.detectionVectors.map((v, i) => (
                        <span key={i} className="px-2 py-0.5 text-xs rounded bg-ctp-surface0 text-ctp-subtext0">
                          {v}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Arguments Form */}
            <div className="flex-1 overflow-y-auto p-4">
              {selectedBof.arguments.length > 0 ? (
                <div className="space-y-4">
                  <h3 className="text-sm font-medium text-ctp-text">Arguments</h3>
                  {selectedBof.arguments.map((arg) => (
                    <div key={arg.name}>
                      <label className="flex items-center gap-2 text-sm text-ctp-subtext1 mb-1">
                        <span>{arg.name}</span>
                        <span
                          className="px-1.5 py-0.5 text-xs rounded"
                          style={{
                            backgroundColor: BOF_COLORS.argType[arg.type] + '20',
                            color: BOF_COLORS.argType[arg.type],
                          }}
                        >
                          {ARG_TYPE_CONFIG[arg.type].label}
                        </span>
                        {arg.optional && (
                          <span className="text-xs text-ctp-overlay0">(optional)</span>
                        )}
                      </label>
                      <p className="text-xs text-ctp-subtext0 mb-2">{arg.description}</p>

                      {ARG_TYPE_CONFIG[arg.type].inputType === 'number' ? (
                        <input
                          type="number"
                          value={args[arg.name] as number || ''}
                          onChange={(e) => handleArgChange(arg.name, parseInt(e.target.value) || 0)}
                          placeholder={arg.defaultValue?.toString()}
                          className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-mauve font-mono"
                        />
                      ) : ARG_TYPE_CONFIG[arg.type].inputType === 'file' ? (
                        <div className="flex items-center gap-2">
                          <input
                            type="file"
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (file) handleArgChange(arg.name, file.name);
                            }}
                            className="flex-1 px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 text-sm file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:bg-ctp-surface1 file:text-ctp-text"
                          />
                        </div>
                      ) : (
                        <input
                          type="text"
                          value={args[arg.name] as string || ''}
                          onChange={(e) => handleArgChange(arg.name, e.target.value)}
                          placeholder={arg.defaultValue?.toString()}
                          className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-mauve font-mono"
                        />
                      )}
                      {ARG_TYPE_CONFIG[arg.type].hint && (
                        <p className="text-xs text-ctp-overlay0 mt-1">{ARG_TYPE_CONFIG[arg.type].hint}</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-ctp-subtext0">This BOF takes no arguments.</p>
              )}

              {selectedBof.longDescription && (
                <div className="mt-6">
                  <h3 className="text-sm font-medium text-ctp-text mb-2">Documentation</h3>
                  <div className="prose prose-sm prose-invert max-w-none">
                    <pre className="p-3 rounded-lg bg-ctp-surface0 text-xs text-ctp-subtext1 whitespace-pre-wrap">
                      {selectedBof.longDescription}
                    </pre>
                  </div>
                </div>
              )}
            </div>

            {/* Execute Button */}
            <div className="p-4 border-t border-ctp-surface0">
              <button
                onClick={() => setShowConfirm(true)}
                disabled={opsecAssessment?.archMatch === false}
                className={`w-full py-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-2 ${
                  opsecAssessment?.archMatch === false
                    ? 'bg-ctp-surface0 text-ctp-overlay0 cursor-not-allowed'
                    : 'bg-ctp-mauve text-ctp-crust hover:bg-ctp-mauve/90'
                }`}
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Execute BOF
              </button>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <svg className="w-12 h-12 mx-auto text-ctp-overlay0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
              <p className="mt-3 text-sm text-ctp-subtext0">Select a BOF to view details</p>
            </div>
          </div>
        )}
      </div>

      {/* Confirmation Modal */}
      {showConfirm && selectedBof && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-ctp-crust/80 backdrop-blur-sm" onClick={() => setShowConfirm(false)} />
          <div className="relative w-full max-w-md mx-4 bg-ctp-base rounded-xl border border-ctp-surface0 shadow-xl">
            <div className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-ctp-yellow/20 flex items-center justify-center">
                  <svg className="w-5 h-5 text-ctp-yellow" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-ctp-text">Confirm BOF Execution</h3>
                  <p className="text-sm text-ctp-subtext0">{selectedBof.name}</p>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-ctp-red/10 border border-ctp-red/30 mb-4">
                <p className="text-sm text-ctp-red">
                  This BOF will execute inside the agent process. If it crashes, you will lose this session.
                </p>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => setShowConfirm(false)}
                  className="flex-1 py-2 rounded-lg bg-ctp-surface0 text-ctp-text hover:bg-ctp-surface1 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleExecute}
                  disabled={isExecuting}
                  className="flex-1 py-2 rounded-lg bg-ctp-red text-ctp-crust hover:bg-ctp-red/90 transition-colors flex items-center justify-center gap-2"
                >
                  {isExecuting ? (
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  ) : null}
                  Execute Anyway
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default BOFExecutionPanel;
