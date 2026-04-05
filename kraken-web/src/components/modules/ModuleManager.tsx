// Module Manager - Professional module catalog and management UI
// Based on research: Mythic capabilities, Sliver armory, Metasploit search operators

import { useState, useMemo } from 'react';
import {
  ModuleManifest,
  LoadedModule,
  ModuleType,
  ReliabilityRank,
  ModuleFilterState,
  MODULE_COLORS,
  MODULE_TYPE_CONFIG,
  RELIABILITY_CONFIG,
  getConfirmationSeverity,
} from './types';

interface ModuleManagerProps {
  availableModules: ModuleManifest[];
  loadedModules: LoadedModule[];
  onLoad: (moduleId: string) => Promise<void>;
  onUnload: (moduleId: string) => Promise<void>;
  connectedSessions?: Array<{ os: string; arch: string }>;
}

export function ModuleManager({
  availableModules,
  loadedModules,
  onLoad,
  onUnload,
  connectedSessions = [],
}: ModuleManagerProps) {
  const [activeTab, setActiveTab] = useState<'available' | 'loaded' | 'updates'>('available');
  const [filters, setFilters] = useState<ModuleFilterState>({
    search: '',
    status: [],
    types: [],
    platforms: [],
    reliability: [],
    capabilities: [],
    showOnlyCompatible: false,
  });
  const [selectedModule, setSelectedModule] = useState<ModuleManifest | null>(null);
  const [showLoadModal, setShowLoadModal] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Filter modules based on current filters
  const filteredModules = useMemo(() => {
    return availableModules.filter((mod) => {
      // Search filter (supports operator syntax: type:bof platform:windows)
      if (filters.search) {
        const searchTerms = filters.search.toLowerCase().split(' ');
        for (const term of searchTerms) {
          if (term.startsWith('type:')) {
            const type = term.slice(5);
            if (!mod.type.toLowerCase().includes(type)) return false;
          } else if (term.startsWith('platform:')) {
            const platform = term.slice(9);
            if (!mod.platforms.some(p => p.os.includes(platform) || p.arch.includes(platform))) return false;
          } else if (term.startsWith('author:')) {
            const author = term.slice(7);
            if (!mod.author.toLowerCase().includes(author)) return false;
          } else if (term.startsWith('tag:')) {
            const tag = term.slice(4);
            if (!mod.tags.some(t => t.toLowerCase().includes(tag))) return false;
          } else {
            // General search
            const matchesGeneral =
              mod.name.toLowerCase().includes(term) ||
              mod.description.toLowerCase().includes(term) ||
              mod.tags.some(t => t.toLowerCase().includes(term));
            if (!matchesGeneral) return false;
          }
        }
      }

      // Type filter
      if (filters.types.length > 0 && !filters.types.includes(mod.type)) return false;

      // Reliability filter
      if (filters.reliability.length > 0 && !filters.reliability.includes(mod.reliability)) return false;

      // Compatibility filter
      if (filters.showOnlyCompatible && connectedSessions.length > 0) {
        const isCompatible = mod.platforms.some(p =>
          connectedSessions.some(s => s.os === p.os && s.arch === p.arch)
        );
        if (!isCompatible) return false;
      }

      return true;
    });
  }, [availableModules, filters, connectedSessions]);

  const handleLoad = async () => {
    if (!selectedModule) return;
    setIsLoading(true);
    try {
      await onLoad(selectedModule.id);
      setShowLoadModal(false);
    } finally {
      setIsLoading(false);
    }
  };

  const handleUnload = async (moduleId: string) => {
    setIsLoading(true);
    try {
      await onUnload(moduleId);
    } finally {
      setIsLoading(false);
    }
  };

  const confirmationSeverity = selectedModule
    ? getConfirmationSeverity(selectedModule, loadedModules)
    : 'none';

  const moduleTypes = Object.keys(MODULE_TYPE_CONFIG) as ModuleType[];
  const reliabilityRanks = Object.keys(RELIABILITY_CONFIG) as ReliabilityRank[];

  return (
    <div className="flex h-full bg-ctp-base">
      {/* Filter Sidebar */}
      <div className="w-64 border-r border-ctp-surface0 flex flex-col">
        <div className="p-4 border-b border-ctp-surface0">
          <h2 className="text-lg font-semibold text-ctp-text">Modules</h2>
          <p className="text-xs text-ctp-subtext0 mt-1">
            {filteredModules.length} of {availableModules.length} modules
          </p>
        </div>

        {/* Search */}
        <div className="p-3 border-b border-ctp-surface0">
          <div className="relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ctp-overlay0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={filters.search}
              onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
              placeholder="type:bof platform:win"
              className="w-full pl-9 pr-3 py-2 text-sm rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-mauve"
            />
          </div>
          <p className="text-xs text-ctp-overlay0 mt-1">
            Operators: type: platform: author: tag:
          </p>
        </div>

        {/* Filters */}
        <div className="flex-1 overflow-y-auto p-3 space-y-4">
          {/* Type Filter */}
          <div>
            <h4 className="text-xs font-medium text-ctp-subtext0 uppercase tracking-wide mb-2">Type</h4>
            <div className="space-y-1">
              {moduleTypes.map((type) => (
                <label key={type} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={filters.types.includes(type)}
                    onChange={(e) => {
                      setFilters(f => ({
                        ...f,
                        types: e.target.checked
                          ? [...f.types, type]
                          : f.types.filter(t => t !== type)
                      }));
                    }}
                    className="rounded border-ctp-surface1 bg-ctp-surface0 text-ctp-mauve focus:ring-ctp-mauve"
                  />
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: MODULE_COLORS.type[type] }}
                  />
                  <span className="text-sm text-ctp-subtext1">{MODULE_TYPE_CONFIG[type].label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Reliability Filter */}
          <div>
            <h4 className="text-xs font-medium text-ctp-subtext0 uppercase tracking-wide mb-2">Reliability</h4>
            <div className="space-y-1">
              {reliabilityRanks.slice(0, 4).map((rank) => (
                <label key={rank} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={filters.reliability.includes(rank)}
                    onChange={(e) => {
                      setFilters(f => ({
                        ...f,
                        reliability: e.target.checked
                          ? [...f.reliability, rank]
                          : f.reliability.filter(r => r !== rank)
                      }));
                    }}
                    className="rounded border-ctp-surface1 bg-ctp-surface0 text-ctp-mauve focus:ring-ctp-mauve"
                  />
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: MODULE_COLORS.reliability[rank] }}
                  />
                  <span className="text-sm text-ctp-subtext1">{RELIABILITY_CONFIG[rank].label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Compatibility Toggle */}
          <div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={filters.showOnlyCompatible}
                onChange={(e) => setFilters(f => ({ ...f, showOnlyCompatible: e.target.checked }))}
                className="rounded border-ctp-surface1 bg-ctp-surface0 text-ctp-mauve focus:ring-ctp-mauve"
              />
              <span className="text-sm text-ctp-subtext1">Compatible only</span>
            </label>
            <p className="text-xs text-ctp-overlay0 mt-1">
              Show only modules compatible with connected sessions
            </p>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Tabs */}
        <div className="px-4 pt-4 border-b border-ctp-surface0">
          <div className="flex gap-1">
            {(['available', 'loaded', 'updates'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                  activeTab === tab
                    ? 'bg-ctp-surface0 text-ctp-text'
                    : 'text-ctp-subtext0 hover:text-ctp-text'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
                {tab === 'loaded' && (
                  <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-ctp-green/20 text-ctp-green">
                    {loadedModules.length}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Module Grid/List */}
        <div className="flex-1 overflow-y-auto p-4">
          {activeTab === 'available' && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredModules.map((mod) => {
                const isLoaded = loadedModules.some(l => l.moduleId === mod.id);
                return (
                  <div
                    key={mod.id}
                    onClick={() => setSelectedModule(mod)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      selectedModule?.id === mod.id
                        ? 'border-ctp-mauve bg-ctp-mauve/5'
                        : 'border-ctp-surface0 hover:border-ctp-surface1 bg-ctp-mantle'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <h3 className="text-sm font-medium text-ctp-text">{mod.name}</h3>
                        <p className="text-xs text-ctp-subtext0 mt-1 line-clamp-2">{mod.description}</p>
                      </div>
                      {isLoaded && (
                        <span className="px-1.5 py-0.5 text-xs rounded bg-ctp-green/20 text-ctp-green">
                          Loaded
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2 mt-3">
                      <span
                        className="px-2 py-0.5 text-xs rounded"
                        style={{
                          backgroundColor: MODULE_COLORS.type[mod.type] + '20',
                          color: MODULE_COLORS.type[mod.type],
                        }}
                      >
                        {mod.type}
                      </span>
                      <span
                        className="px-2 py-0.5 text-xs rounded"
                        style={{
                          backgroundColor: MODULE_COLORS.reliability[mod.reliability] + '20',
                          color: MODULE_COLORS.reliability[mod.reliability],
                        }}
                      >
                        {mod.reliability}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 mt-2 text-xs text-ctp-overlay0">
                      <span>v{mod.version}</span>
                      <span>·</span>
                      <span>{mod.author}</span>
                      <span>·</span>
                      <span>{(mod.size / 1024).toFixed(1)} KB</span>
                    </div>

                    {!isLoaded && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedModule(mod);
                          setShowLoadModal(true);
                        }}
                        className="mt-3 w-full py-2 text-xs font-medium rounded-lg bg-ctp-blue text-ctp-crust hover:bg-ctp-blue/90 transition-colors"
                      >
                        Load Module
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {activeTab === 'loaded' && (
            <div className="space-y-2">
              {loadedModules.length === 0 ? (
                <div className="text-center py-12">
                  <svg className="w-12 h-12 mx-auto text-ctp-overlay0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                  </svg>
                  <p className="mt-3 text-sm text-ctp-subtext0">No modules loaded</p>
                </div>
              ) : (
                loadedModules.map((mod) => (
                  <div
                    key={mod.id}
                    className="p-4 rounded-xl bg-ctp-mantle border border-ctp-surface0 flex items-center justify-between"
                  >
                    <div className="flex items-center gap-4">
                      <div
                        className="w-2 h-2 rounded-full animate-pulse"
                        style={{ backgroundColor: MODULE_COLORS.status[mod.status] }}
                      />
                      <div>
                        <h3 className="text-sm font-medium text-ctp-text">{mod.manifest.name}</h3>
                        <p className="text-xs text-ctp-subtext0">
                          v{mod.manifest.version} · {(mod.memorySize / 1024).toFixed(1)} KB
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-xs text-ctp-overlay0">
                        {mod.manifest.commands.length} commands
                      </span>
                      <button
                        onClick={() => handleUnload(mod.moduleId)}
                        disabled={isLoading}
                        className="px-3 py-1.5 text-xs font-medium rounded-lg bg-ctp-red/20 text-ctp-red hover:bg-ctp-red/30 transition-colors"
                      >
                        Unload
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'updates' && (
            <div className="text-center py-12">
              <svg className="w-12 h-12 mx-auto text-ctp-green" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="mt-3 text-sm text-ctp-subtext0">All modules are up to date</p>
            </div>
          )}
        </div>
      </div>

      {/* Load Confirmation Modal */}
      {showLoadModal && selectedModule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-ctp-crust/80 backdrop-blur-sm" onClick={() => setShowLoadModal(false)} />
          <div className="relative w-full max-w-md mx-4 bg-ctp-base rounded-xl border border-ctp-surface0 shadow-xl">
            <div className="p-6">
              <h3 className="text-lg font-semibold text-ctp-text">Load Module</h3>
              <p className="text-sm text-ctp-subtext0 mt-1">{selectedModule.name} v{selectedModule.version}</p>

              <div className="mt-4 p-4 rounded-lg bg-ctp-surface0">
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-ctp-subtext0">Type</span>
                    <span className="text-ctp-text">{selectedModule.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-ctp-subtext0">Size</span>
                    <span className="text-ctp-text">{(selectedModule.size / 1024).toFixed(1)} KB</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-ctp-subtext0">Commands</span>
                    <span className="text-ctp-text">{selectedModule.commands.length}</span>
                  </div>
                </div>
              </div>

              {confirmationSeverity === 'dependencies' && (
                <div className="mt-4 p-3 rounded-lg bg-ctp-yellow/10 border border-ctp-yellow/30">
                  <p className="text-xs text-ctp-yellow">
                    Missing dependencies will be automatically installed.
                  </p>
                </div>
              )}

              {confirmationSeverity === 'conflicts' && (
                <div className="mt-4 p-3 rounded-lg bg-ctp-peach/10 border border-ctp-peach/30">
                  <p className="text-xs text-ctp-peach">
                    This module conflicts with loaded modules. They will be unloaded.
                  </p>
                </div>
              )}

              {confirmationSeverity === 'opsec' && (
                <div className="mt-4 p-3 rounded-lg bg-ctp-red/10 border border-ctp-red/30">
                  <p className="text-xs text-ctp-red">
                    This module type has OPSEC implications. Review before loading.
                  </p>
                </div>
              )}

              <div className="mt-6 flex gap-3">
                <button
                  onClick={() => setShowLoadModal(false)}
                  className="flex-1 py-2 rounded-lg bg-ctp-surface0 text-ctp-text hover:bg-ctp-surface1 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleLoad}
                  disabled={isLoading}
                  className={`flex-1 py-2 rounded-lg font-medium transition-colors flex items-center justify-center gap-2 ${
                    confirmationSeverity === 'opsec'
                      ? 'bg-ctp-red text-ctp-crust hover:bg-ctp-red/90'
                      : 'bg-ctp-blue text-ctp-crust hover:bg-ctp-blue/90'
                  }`}
                >
                  {isLoading && (
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                  {confirmationSeverity === 'opsec' ? 'Load Anyway' : 'Load Module'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ModuleManager;
