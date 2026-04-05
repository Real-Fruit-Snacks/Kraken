import { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { CollabProvider } from './contexts/CollabContext';
import { KeyboardShortcutsProvider } from './contexts/KeyboardShortcutsContext';
import { ToastProvider } from './contexts/ToastContext';
import { EventToast } from './components/EventToast';
import { ToastContainer } from './components/ToastContainer';

const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })));
const Sessions = lazy(() => import('./pages/Sessions').then(m => ({ default: m.Sessions })));
const SessionDetail = lazy(() => import('./pages/SessionDetail').then(m => ({ default: m.SessionDetail })));
const Topology = lazy(() => import('./pages/Topology').then(m => ({ default: m.Topology })));
const Listeners = lazy(() => import('./pages/Listeners').then(m => ({ default: m.Listeners })));
const Loot = lazy(() => import('./pages/Loot').then(m => ({ default: m.Loot })));
const Modules = lazy(() => import('./pages/Modules').then(m => ({ default: m.Modules })));
const Reports = lazy(() => import('./pages/Reports').then(m => ({ default: m.Reports })));
const Operators = lazy(() => import('./pages/Operators').then(m => ({ default: m.Operators })));
const Defender = lazy(() => import('./pages/Defender').then(m => ({ default: m.Defender })));
const Payloads = lazy(() => import('./pages/Payloads').then(m => ({ default: m.Payloads })));
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.Settings })));
const Audit = lazy(() => import('./pages/Audit').then(m => ({ default: m.Audit })));
const Jobs = lazy(() => import('./pages/Jobs').then(m => ({ default: m.Jobs })));
const Files = lazy(() => import('./pages/Files').then(m => ({ default: m.Files })));
const Processes = lazy(() => import('./pages/Processes').then(m => ({ default: m.Processes })));

function App() {
  return (
    <ToastProvider>
      <KeyboardShortcutsProvider>
        <CollabProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Dashboard /></Suspense>} />
              <Route path="sessions" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Sessions /></Suspense>} />
              <Route path="sessions/:sessionId" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><SessionDetail /></Suspense>} />
              <Route path="topology" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Topology /></Suspense>} />
              <Route path="listeners" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Listeners /></Suspense>} />
              <Route path="loot" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Loot /></Suspense>} />
              <Route path="files/:sessionId" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Files /></Suspense>} />
              <Route path="processes/:sessionId" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Processes /></Suspense>} />
              <Route path="modules" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Modules /></Suspense>} />
              <Route path="reports" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Reports /></Suspense>} />
              <Route path="operators" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Operators /></Suspense>} />
              <Route path="defender" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Defender /></Suspense>} />
              <Route path="payloads" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Payloads /></Suspense>} />
              <Route path="settings" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Settings /></Suspense>} />
              <Route path="audit" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Audit /></Suspense>} />
              <Route path="jobs" element={<Suspense fallback={<div className="p-4 text-ctp-subtext0">Loading...</div>}><Jobs /></Suspense>} />
            </Route>
          </Routes>
          <EventToast />
          <ToastContainer />
        </CollabProvider>
      </KeyboardShortcutsProvider>
    </ToastProvider>
  );
}

export default App;
