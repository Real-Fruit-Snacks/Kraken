// Mesh Control Panel - Professional P2P networking controls
// Based on research: CS arrow colors, Mythic react-flow, explicit role selector

import { useState, useCallback } from 'react';
import {
  MeshRole,
  MeshTransport,
  PeerConnectionRequest,
  MESH_COLORS,
  ROLE_CONFIG,
  TRANSPORT_CONFIG,
} from './types';

interface MeshControlPanelProps {
  sessionName: string;
  onConnect: (request: PeerConnectionRequest) => Promise<void>;
  onSetRole: (role: MeshRole) => Promise<void>;
  currentRole: MeshRole;
  isConnecting?: boolean;
}

export function MeshControlPanel({
  sessionName,
  onConnect,
  onSetRole,
  currentRole,
  isConnecting = false,
}: MeshControlPanelProps) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [transport, setTransport] = useState<MeshTransport>('tcp');
  const [role, setRole] = useState<MeshRole>(currentRole);
  const [address, setAddress] = useState('');
  const [port, setPort] = useState(TRANSPORT_CONFIG.tcp.defaultPort || 4444);
  const [pipeName, setPipeName] = useState('');
  const [showWizard, setShowWizard] = useState(false);

  const handleSubmit = useCallback(async () => {
    const request: PeerConnectionRequest = {
      transport,
      role,
      address,
      port: transport === 'tcp' ? port : undefined,
      pipeName: transport !== 'tcp' ? pipeName : undefined,
    };

    await onConnect(request);
    setShowWizard(false);
    setStep(1);
  }, [transport, role, address, port, pipeName, onConnect]);

  const resetWizard = () => {
    setStep(1);
    setTransport('tcp');
    setRole(currentRole);
    setAddress('');
    setPort(4444);
    setPipeName('');
  };

  return (
    <div className="bg-ctp-mantle rounded-xl border border-ctp-surface0 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-ctp-surface0 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-ctp-surface0 flex items-center justify-center">
            <svg className="w-4 h-4 text-ctp-blue" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-medium text-ctp-text">Mesh Commands</h3>
            <p className="text-xs text-ctp-subtext0">{sessionName}</p>
          </div>
        </div>
        <button
          onClick={() => { resetWizard(); setShowWizard(true); }}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-ctp-blue text-ctp-crust hover:bg-ctp-blue/90 transition-colors"
        >
          Connect to Peer
        </button>
      </div>

      {/* Current Role Display */}
      <div className="px-4 py-3 border-b border-ctp-surface0">
        <div className="flex items-center justify-between">
          <span className="text-xs text-ctp-subtext0">Current Role</span>
          <div className="flex items-center gap-2">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: ROLE_CONFIG[currentRole].color }}
            />
            <span className="text-sm text-ctp-text">{ROLE_CONFIG[currentRole].label}</span>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="p-4 grid grid-cols-2 gap-2">
        <button
          onClick={() => setShowWizard(true)}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-ctp-surface0 hover:bg-ctp-surface1 transition-colors text-left"
        >
          <svg className="w-4 h-4 text-ctp-blue" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
          <div>
            <div className="text-xs font-medium text-ctp-text">Connect</div>
            <div className="text-xs text-ctp-subtext0">Link to peer</div>
          </div>
        </button>

        <button
          onClick={() => onSetRole('router')}
          disabled={currentRole === 'router'}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-ctp-surface0 hover:bg-ctp-surface1 transition-colors text-left disabled:opacity-50"
        >
          <svg className="w-4 h-4 text-ctp-mauve" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
          <div>
            <div className="text-xs font-medium text-ctp-text">Set Router</div>
            <div className="text-xs text-ctp-subtext0">Relay mode</div>
          </div>
        </button>

        <button
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-ctp-surface0 hover:bg-ctp-surface1 transition-colors text-left"
        >
          <svg className="w-4 h-4 text-ctp-green" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z" />
          </svg>
          <div>
            <div className="text-xs font-medium text-ctp-text">Listen</div>
            <div className="text-xs text-ctp-subtext0">Accept peers</div>
          </div>
        </button>

        <button
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-ctp-surface0 hover:bg-ctp-surface1 transition-colors text-left"
        >
          <svg className="w-4 h-4 text-ctp-peach" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
          </svg>
          <div>
            <div className="text-xs font-medium text-ctp-text">Topology</div>
            <div className="text-xs text-ctp-subtext0">View graph</div>
          </div>
        </button>
      </div>

      {/* Connection Wizard Modal */}
      {showWizard && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-ctp-crust/80 backdrop-blur-sm"
            onClick={() => setShowWizard(false)}
          />
          <div className="relative w-full max-w-lg mx-4 bg-ctp-base rounded-xl border border-ctp-surface0 shadow-xl">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-ctp-surface0 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-ctp-text">Connect to Peer</h2>
                <p className="text-sm text-ctp-subtext0">Step {step} of 3</p>
              </div>
              <button
                onClick={() => setShowWizard(false)}
                className="p-1 rounded-lg hover:bg-ctp-surface0 transition-colors"
              >
                <svg className="w-5 h-5 text-ctp-subtext0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Progress Bar */}
            <div className="px-6 py-3 border-b border-ctp-surface0">
              <div className="flex items-center gap-2">
                {[1, 2, 3].map((s) => (
                  <div key={s} className="flex-1 flex items-center">
                    <div
                      className={`w-full h-1 rounded-full transition-colors ${
                        s <= step ? 'bg-ctp-blue' : 'bg-ctp-surface0'
                      }`}
                    />
                  </div>
                ))}
              </div>
              <div className="flex justify-between mt-2 text-xs text-ctp-subtext0">
                <span>Transport</span>
                <span>Target</span>
                <span>Confirm</span>
              </div>
            </div>

            {/* Step Content */}
            <div className="p-6">
              {step === 1 && (
                <div className="space-y-4">
                  <p className="text-sm text-ctp-subtext1">Select transport protocol:</p>
                  <div className="grid grid-cols-3 gap-3">
                    {(Object.keys(TRANSPORT_CONFIG) as MeshTransport[]).map((t) => (
                      <button
                        key={t}
                        onClick={() => setTransport(t)}
                        className={`p-4 rounded-lg border-2 transition-all ${
                          transport === t
                            ? 'border-ctp-blue bg-ctp-blue/10'
                            : 'border-ctp-surface0 hover:border-ctp-surface1'
                        }`}
                      >
                        <div
                          className="w-8 h-8 mx-auto mb-2 rounded-lg flex items-center justify-center"
                          style={{ backgroundColor: MESH_COLORS.transport[t] + '20' }}
                        >
                          <span style={{ color: MESH_COLORS.transport[t] }} className="text-lg font-bold">
                            {t === 'tcp' ? 'T' : t === 'smb' ? 'S' : 'P'}
                          </span>
                        </div>
                        <div className="text-sm font-medium text-ctp-text">{TRANSPORT_CONFIG[t].label}</div>
                        <div className="text-xs text-ctp-subtext0 mt-1">{TRANSPORT_CONFIG[t].description}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {step === 2 && (
                <div className="space-y-4">
                  <p className="text-sm text-ctp-subtext1">Enter target details:</p>

                  {TRANSPORT_CONFIG[transport].fields.includes('address') && (
                    <div>
                      <label className="block text-xs font-medium text-ctp-subtext0 mb-1">
                        Target Address
                      </label>
                      <input
                        type="text"
                        value={address}
                        onChange={(e) => setAddress(e.target.value)}
                        placeholder="192.168.1.100"
                        className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
                      />
                    </div>
                  )}

                  {TRANSPORT_CONFIG[transport].fields.includes('port') && (
                    <div>
                      <label className="block text-xs font-medium text-ctp-subtext0 mb-1">
                        Port
                      </label>
                      <input
                        type="number"
                        value={port}
                        onChange={(e) => setPort(parseInt(e.target.value) || 0)}
                        placeholder="4444"
                        className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
                      />
                    </div>
                  )}

                  {TRANSPORT_CONFIG[transport].fields.includes('pipeName') && (
                    <div>
                      <label className="block text-xs font-medium text-ctp-subtext0 mb-1">
                        Pipe Name
                      </label>
                      <input
                        type="text"
                        value={pipeName}
                        onChange={(e) => setPipeName(e.target.value)}
                        placeholder="\\.\pipe\kraken"
                        className="w-full px-3 py-2 rounded-lg bg-ctp-surface0 text-ctp-text border border-ctp-surface1 placeholder:text-ctp-overlay0 focus:outline-none focus:border-ctp-blue"
                      />
                    </div>
                  )}

                  <div>
                    <label className="block text-xs font-medium text-ctp-subtext0 mb-2">
                      Role Assignment
                    </label>
                    <div className="space-y-2">
                      {(Object.keys(ROLE_CONFIG) as MeshRole[]).map((r) => (
                        <button
                          key={r}
                          onClick={() => setRole(r)}
                          className={`w-full p-3 rounded-lg border-2 text-left transition-all flex items-center gap-3 ${
                            role === r
                              ? 'border-ctp-blue bg-ctp-blue/10'
                              : 'border-ctp-surface0 hover:border-ctp-surface1'
                          }`}
                        >
                          <div
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: ROLE_CONFIG[r].color }}
                          />
                          <div>
                            <div className="text-sm font-medium text-ctp-text">{ROLE_CONFIG[r].label}</div>
                            <div className="text-xs text-ctp-subtext0">{ROLE_CONFIG[r].description}</div>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {step === 3 && (
                <div className="space-y-4">
                  <p className="text-sm text-ctp-subtext1">Review connection details:</p>

                  <div className="p-4 rounded-lg bg-ctp-surface0 space-y-3">
                    <div className="flex justify-between">
                      <span className="text-xs text-ctp-subtext0">Transport</span>
                      <span
                        className="px-2 py-0.5 rounded text-xs font-medium"
                        style={{
                          backgroundColor: MESH_COLORS.transport[transport] + '20',
                          color: MESH_COLORS.transport[transport],
                        }}
                      >
                        {TRANSPORT_CONFIG[transport].label}
                      </span>
                    </div>

                    {address && (
                      <div className="flex justify-between">
                        <span className="text-xs text-ctp-subtext0">Address</span>
                        <span className="text-sm text-ctp-text font-mono">{address}</span>
                      </div>
                    )}

                    {transport === 'tcp' && (
                      <div className="flex justify-between">
                        <span className="text-xs text-ctp-subtext0">Port</span>
                        <span className="text-sm text-ctp-text font-mono">{port}</span>
                      </div>
                    )}

                    {pipeName && (
                      <div className="flex justify-between">
                        <span className="text-xs text-ctp-subtext0">Pipe</span>
                        <span className="text-sm text-ctp-text font-mono">{pipeName}</span>
                      </div>
                    )}

                    <div className="flex justify-between">
                      <span className="text-xs text-ctp-subtext0">Role</span>
                      <div className="flex items-center gap-1.5">
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: ROLE_CONFIG[role].color }}
                        />
                        <span className="text-sm text-ctp-text">{ROLE_CONFIG[role].label}</span>
                      </div>
                    </div>
                  </div>

                  {/* OPSEC Notice */}
                  <div className="p-3 rounded-lg bg-ctp-yellow/10 border border-ctp-yellow/30">
                    <div className="flex items-start gap-2">
                      <svg className="w-4 h-4 text-ctp-yellow mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                      <div>
                        <p className="text-xs font-medium text-ctp-yellow">OPSEC Consideration</p>
                        <p className="text-xs text-ctp-subtext1 mt-1">
                          Peer connections create network traffic that may be logged.
                          Ensure target is reachable before connecting.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-4 border-t border-ctp-surface0 flex justify-between">
              <button
                onClick={() => step > 1 ? setStep((step - 1) as 1 | 2 | 3) : setShowWizard(false)}
                className="px-4 py-2 text-sm font-medium text-ctp-subtext1 hover:text-ctp-text transition-colors"
              >
                {step > 1 ? 'Back' : 'Cancel'}
              </button>

              {step < 3 ? (
                <button
                  onClick={() => setStep((step + 1) as 1 | 2 | 3)}
                  disabled={step === 2 && !address && transport !== 'pipe'}
                  className="px-4 py-2 text-sm font-medium rounded-lg bg-ctp-blue text-ctp-crust hover:bg-ctp-blue/90 transition-colors disabled:opacity-50"
                >
                  Continue
                </button>
              ) : (
                <button
                  onClick={handleSubmit}
                  disabled={isConnecting}
                  className="px-4 py-2 text-sm font-medium rounded-lg bg-ctp-green text-ctp-crust hover:bg-ctp-green/90 transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  {isConnecting && (
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                  Connect
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default MeshControlPanel;
