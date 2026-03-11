import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './auth';
import { Layout } from './layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Findings from './pages/Findings';
import KevAlerts from './pages/KevAlerts';
import Pipeline from './pages/Pipeline';
import Reports from './pages/Reports';
import Connectors from './pages/Connectors';
import Account from './pages/Account';
import Settings from './pages/Settings';

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (this.state.error) {
      const err = this.state.error as Error;
      return (
        <div className="min-h-screen bg-slate-900 flex items-center justify-center p-8">
          <div className="max-w-lg w-full bg-slate-800 border border-red-700/50 rounded-xl p-6">
            <h1 className="text-red-400 font-bold text-lg mb-2">Something went wrong</h1>
            <pre className="text-slate-300 text-xs whitespace-pre-wrap bg-slate-900 rounded p-3 overflow-auto max-h-64">
              {err.message}{'\n\n'}{err.stack}
            </pre>
            <button
              onClick={() => { localStorage.clear(); window.location.href = '/'; }}
              className="mt-4 px-4 py-2 bg-indigo-500 hover:bg-indigo-600 text-white text-sm rounded-lg"
            >
              Clear storage and reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { token, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-500 text-sm">Loading Warden...</p>
        </div>
      </div>
    );
  }

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return <Layout>{children}</Layout>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { token, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (token) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <PublicRoute>
            <Login />
          </PublicRoute>
        }
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />
      <Route
        path="/findings"
        element={
          <ProtectedRoute>
            <Findings />
          </ProtectedRoute>
        }
      />
      <Route
        path="/kev"
        element={
          <ProtectedRoute>
            <KevAlerts />
          </ProtectedRoute>
        }
      />
      <Route
        path="/pipeline"
        element={
          <ProtectedRoute>
            <Pipeline />
          </ProtectedRoute>
        }
      />
      <Route
        path="/reports"
        element={
          <ProtectedRoute>
            <Reports />
          </ProtectedRoute>
        }
      />
      <Route
        path="/connectors"
        element={
          <ProtectedRoute>
            <Connectors />
          </ProtectedRoute>
        }
      />
      <Route
        path="/account"
        element={
          <ProtectedRoute>
            <Account />
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <Settings />
          </ProtectedRoute>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
