import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Play,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  Activity,
  Shield,
} from 'lucide-react';
import { runPipeline, runKevSync, getPipelineTask } from '../api';
import type { PipelineTask } from '../types';

interface TaskRecord {
  taskId: string;
  type: 'full_scan' | 'kev_sync';
  startedAt: Date;
  task: PipelineTask | null;
}

function StatusIcon({ status }: { status: PipelineTask['status'] | 'starting' }) {
  if (status === 'starting' || status === 'pending' || status === 'running') {
    return <Loader2 size={16} className="text-indigo-500 animate-spin" />;
  }
  if (status === 'completed') {
    return <CheckCircle2 size={16} className="text-green-500" />;
  }
  if (status === 'failed') {
    return <XCircle size={16} className="text-red-500" />;
  }
  return <Clock size={16} className="text-slate-400" />;
}

function StatusBadge({ status }: { status: PipelineTask['status'] | 'starting' }) {
  const map: Record<string, string> = {
    starting: 'bg-indigo-50 text-indigo-600',
    pending: 'bg-indigo-50 text-indigo-600',
    running: 'bg-blue-50 text-blue-600',
    completed: 'bg-green-50 text-green-700',
    failed: 'bg-red-50 text-red-700',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold capitalize ${map[status] ?? 'bg-slate-100 text-slate-600'}`}>
      {status}
    </span>
  );
}

function TaskCard({ record, onRefresh }: { record: TaskRecord; onRefresh: (taskId: string) => void }) {
  const task = record.task;
  const isRunning = !task || task.status === 'pending' || task.status === 'running';

  const elapsed = task?.started_at
    ? Math.round((Date.now() - new Date(task.started_at).getTime()) / 1000)
    : null;

  const duration =
    task?.started_at && task?.completed_at
      ? Math.round(
          (new Date(task.completed_at).getTime() - new Date(task.started_at).getTime()) / 1000
        )
      : null;

  return (
    <div
      className={`card p-5 border-l-4 ${
        !task || task.status === 'running' || task.status === 'pending'
          ? 'border-l-indigo-400'
          : task.status === 'completed'
          ? 'border-l-green-500'
          : 'border-l-red-500'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <StatusIcon status={task?.status ?? 'starting'} />
          <div>
            <div className="text-sm font-semibold text-slate-800">
              {record.type === 'full_scan' ? 'Full Pipeline Scan' : 'KEV Sync'}
            </div>
            <div className="text-xs text-slate-400 mt-0.5 font-mono">{record.taskId}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <StatusBadge status={task?.status ?? 'starting'} />
          {isRunning && (
            <button
              onClick={() => onRefresh(record.taskId)}
              className="text-slate-400 hover:text-slate-600 transition-colors"
              title="Refresh status"
            >
              <RefreshCw size={14} />
            </button>
          )}
        </div>
      </div>

      <div className="mt-3 grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
        <div>
          <span className="text-slate-400">Started</span>
          <div className="text-slate-700 font-medium">
            {record.startedAt.toLocaleTimeString()}
          </div>
        </div>
        {task?.completed_at && (
          <div>
            <span className="text-slate-400">Completed</span>
            <div className="text-slate-700 font-medium">
              {new Date(task.completed_at).toLocaleTimeString()}
            </div>
          </div>
        )}
        {duration !== null ? (
          <div>
            <span className="text-slate-400">Duration</span>
            <div className="text-slate-700 font-medium">{duration}s</div>
          </div>
        ) : elapsed !== null ? (
          <div>
            <span className="text-slate-400">Elapsed</span>
            <div className="text-slate-700 font-medium">{elapsed}s</div>
          </div>
        ) : null}
      </div>

      {task?.result && Object.keys(task.result).length > 0 && (
        <div className="mt-3 bg-green-50 rounded-lg p-3">
          <div className="text-xs font-semibold text-green-700 mb-1.5">Results</div>
          <div className="grid grid-cols-2 gap-1.5">
            {Object.entries(task.result).map(([k, v]) => (
              <div key={k} className="flex justify-between gap-2 text-xs">
                <span className="text-green-600 capitalize">{k.replace(/_/g, ' ')}</span>
                <span className="font-semibold text-green-800">{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {task?.error && (
        <div className="mt-3 bg-red-50 rounded-lg p-3">
          <div className="text-xs font-semibold text-red-700 mb-1">Error</div>
          <p className="text-xs text-red-600 font-mono leading-relaxed">{task.error}</p>
        </div>
      )}
    </div>
  );
}

export default function Pipeline() {
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [scanning, setScanning] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const pollingRef = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());

  const startPolling = useCallback((taskId: string) => {
    if (pollingRef.current.has(taskId)) return;
    const interval = setInterval(async () => {
      try {
        const task = await getPipelineTask(taskId);
        setTasks((prev) =>
          prev.map((r) => (r.taskId === taskId ? { ...r, task } : r))
        );
        if (task.status === 'completed' || task.status === 'failed') {
          clearInterval(interval);
          pollingRef.current.delete(taskId);
        }
      } catch {
        // stop polling on error
        clearInterval(interval);
        pollingRef.current.delete(taskId);
      }
    }, 2000);
    pollingRef.current.set(taskId, interval);
  }, []);

  const handleRefreshTask = useCallback(
    async (taskId: string) => {
      try {
        const task = await getPipelineTask(taskId);
        setTasks((prev) =>
          prev.map((r) => (r.taskId === taskId ? { ...r, task } : r))
        );
        if (task.status === 'running' || task.status === 'pending') {
          startPolling(taskId);
        }
      } catch {
        // ignore
      }
    },
    [startPolling]
  );

  // Cleanup on unmount
  useEffect(() => {
    const intervals = pollingRef.current;
    return () => {
      intervals.forEach((interval) => clearInterval(interval));
      intervals.clear();
    };
  }, []);

  const handleRunPipeline = async () => {
    setScanning(true);
    setRunError(null);
    try {
      const res = await runPipeline();
      const record: TaskRecord = {
        taskId: res.task_id,
        type: 'full_scan',
        startedAt: new Date(),
        task: null,
      };
      setTasks((prev) => [record, ...prev]);
      startPolling(res.task_id);
    } catch (e) {
      setRunError(e instanceof Error ? e.message : 'Failed to start pipeline');
    } finally {
      setScanning(false);
    }
  };

  const handleKevSync = async () => {
    setSyncing(true);
    setRunError(null);
    try {
      const res = await runKevSync();
      const record: TaskRecord = {
        taskId: res.task_id,
        type: 'kev_sync',
        startedAt: new Date(),
        task: null,
      };
      setTasks((prev) => [record, ...prev]);
      startPolling(res.task_id);
    } catch (e) {
      setRunError(e instanceof Error ? e.message : 'Failed to start KEV sync');
    } finally {
      setSyncing(false);
    }
  };

  const activeTasks = tasks.filter(
    (t) => !t.task || t.task.status === 'pending' || t.task.status === 'running'
  );
  const completedTasks = tasks.filter(
    (t) => t.task && (t.task.status === 'completed' || t.task.status === 'failed')
  );

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900">Pipeline</h1>
        <p className="text-slate-500 text-sm mt-0.5">
          Trigger scans and sync operations
        </p>
      </div>

      {/* Action cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
        {/* Full Scan */}
        <div className="card p-6">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-indigo-100 flex items-center justify-center flex-shrink-0">
              <Activity size={22} className="text-indigo-600" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-base font-semibold text-slate-900 mb-1">Full Pipeline Scan</h3>
              <p className="text-sm text-slate-500 leading-relaxed mb-4">
                Run the complete vulnerability ingestion pipeline. Fetches data from all configured
                scanners, deduplicates findings, calculates risk scores, and updates the database.
              </p>
              <button
                onClick={() => void handleRunPipeline()}
                disabled={scanning}
                className="btn-primary"
              >
                {scanning ? (
                  <>
                    <Loader2 size={14} className="animate-spin" />
                    Starting...
                  </>
                ) : (
                  <>
                    <Play size={14} />
                    Run Full Scan
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* KEV Sync */}
        <div className="card p-6">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-red-100 flex items-center justify-center flex-shrink-0">
              <Shield size={22} className="text-red-600" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-base font-semibold text-slate-900 mb-1">CISA KEV Sync</h3>
              <p className="text-sm text-slate-500 leading-relaxed mb-4">
                Synchronize the CISA Known Exploited Vulnerabilities catalog. Marks affected
                findings and calculates SLA due dates based on CISA mandates.
              </p>
              <button
                onClick={() => void handleKevSync()}
                disabled={syncing}
                className="btn-danger"
              >
                {syncing ? (
                  <>
                    <Loader2 size={14} className="animate-spin" />
                    Syncing...
                  </>
                ) : (
                  <>
                    <RefreshCw size={14} />
                    Sync KEV
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {runError && (
        <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          <XCircle size={16} />
          {runError}
        </div>
      )}

      {/* Active tasks */}
      {activeTasks.length > 0 && (
        <div className="mb-6">
          <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wide mb-3 flex items-center gap-2">
            <Loader2 size={13} className="animate-spin text-indigo-500" />
            Running ({activeTasks.length})
          </h2>
          <div className="space-y-3">
            {activeTasks.map((t) => (
              <TaskCard key={t.taskId} record={t} onRefresh={(id) => void handleRefreshTask(id)} />
            ))}
          </div>
        </div>
      )}

      {/* Completed tasks */}
      {completedTasks.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wide mb-3">
            Recent Runs ({completedTasks.length})
          </h2>
          <div className="space-y-3">
            {completedTasks.map((t) => (
              <TaskCard key={t.taskId} record={t} onRefresh={(id) => void handleRefreshTask(id)} />
            ))}
          </div>
        </div>
      )}

      {/* Empty state */}
      {tasks.length === 0 && (
        <div className="card p-12 text-center">
          <div className="w-14 h-14 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Play size={24} className="text-slate-400" />
          </div>
          <h3 className="text-slate-700 font-semibold mb-1">No pipeline runs yet</h3>
          <p className="text-slate-400 text-sm">
            Trigger a full scan or KEV sync to see task progress here.
          </p>
        </div>
      )}

      {/* Info section */}
      <div className="mt-6 card p-5 bg-slate-50">
        <h3 className="text-sm font-semibold text-slate-700 mb-3">Pipeline Notes</h3>
        <ul className="space-y-1.5 text-sm text-slate-600">
          <li className="flex items-start gap-2">
            <div className="w-1 h-1 rounded-full bg-slate-400 mt-2 flex-shrink-0" />
            Task status is polled every 2 seconds automatically while running.
          </li>
          <li className="flex items-start gap-2">
            <div className="w-1 h-1 rounded-full bg-slate-400 mt-2 flex-shrink-0" />
            Full scans may take several minutes depending on scanner volume.
          </li>
          <li className="flex items-start gap-2">
            <div className="w-1 h-1 rounded-full bg-slate-400 mt-2 flex-shrink-0" />
            KEV sync fetches the latest CISA catalog and updates all affected findings.
          </li>
          <li className="flex items-start gap-2">
            <div className="w-1 h-1 rounded-full bg-slate-400 mt-2 flex-shrink-0" />
            Refresh the Findings and KEV Alerts pages after a pipeline run to see updated data.
          </li>
        </ul>
      </div>
    </div>
  );
}
