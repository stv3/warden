import React, { useEffect, useState, useCallback } from 'react';
import { AlertTriangle, Clock, Server, Activity, RefreshCw } from 'lucide-react';
import { getActiveKevFindings, updateFindingStatus } from '../api';
import type { Finding } from '../types';

function daysRemaining(dueDate: string | null): number | null {
  if (!dueDate) return null;
  return Math.ceil((new Date(dueDate).getTime() - Date.now()) / 86400000);
}

function DaysRemainingBadge({ dueDate }: { dueDate: string | null }) {
  const days = daysRemaining(dueDate);
  if (days === null) return <span className="text-slate-400 text-sm">No due date</span>;

  if (days < 0) {
    return (
      <div className="flex items-center gap-1.5">
        <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-red-600 text-white rounded-full text-xs font-bold">
          <Clock size={10} />
          {Math.abs(days)}d overdue
        </span>
      </div>
    );
  }
  if (days === 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-red-500 text-white rounded-full text-xs font-bold">
        <Clock size={10} />
        Due today
      </span>
    );
  }
  if (days <= 7) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-orange-500 text-white rounded-full text-xs font-bold">
        <Clock size={10} />
        {days}d remaining
      </span>
    );
  }
  if (days <= 30) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-yellow-500 text-white rounded-full text-xs font-bold">
        <Clock size={10} />
        {days}d remaining
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-100 text-slate-600 rounded-full text-xs font-medium">
      <Clock size={10} />
      {days}d remaining
    </span>
  );
}

function urgencyClass(dueDate: string | null): string {
  const days = daysRemaining(dueDate);
  if (days === null) return 'border-slate-200';
  if (days < 0) return 'border-l-red-600 border-l-4';
  if (days <= 7) return 'border-l-orange-500 border-l-4';
  if (days <= 30) return 'border-l-yellow-400 border-l-4';
  return 'border-l-slate-200 border-l-4';
}

function urgencyBg(dueDate: string | null): string {
  const days = daysRemaining(dueDate);
  if (days === null) return 'bg-white';
  if (days < 0) return 'bg-red-50/60';
  if (days <= 7) return 'bg-orange-50/60';
  if (days <= 30) return 'bg-yellow-50/40';
  return 'bg-white';
}

interface KevCardProps {
  finding: Finding;
  onStatusUpdate: (id: string, status: Finding['status']) => Promise<void>;
}

function KevCard({ finding, onStatusUpdate }: KevCardProps) {
  const [updating, setUpdating] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const handleQuickStatus = async (status: Finding['status']) => {
    setUpdating(true);
    try {
      await onStatusUpdate(finding.id, status);
    } finally {
      setUpdating(false);
    }
  };

  const days = daysRemaining(finding.kev_due_date);

  return (
    <div
      className={`rounded-xl border ${urgencyBg(finding.kev_due_date)} ${urgencyClass(finding.kev_due_date)} shadow-sm overflow-hidden`}
    >
      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1.5">
              <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-red-600 text-white rounded text-xs font-bold uppercase">
                <AlertTriangle size={10} />
                KEV
              </span>
              {finding.cve_id && (
                <span className="text-xs font-mono font-semibold text-slate-700 bg-slate-100 px-2 py-0.5 rounded">
                  {finding.cve_id}
                </span>
              )}
              <span
                className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase ${
                  finding.severity === 'critical'
                    ? 'bg-red-100 text-red-700'
                    : finding.severity === 'high'
                    ? 'bg-orange-100 text-orange-700'
                    : 'bg-yellow-100 text-yellow-700'
                }`}
              >
                {finding.severity}
              </span>
            </div>
            <h3 className="text-sm font-semibold text-slate-900 leading-tight mb-1">
              {finding.title}
            </h3>
          </div>
          <div className="flex-shrink-0">
            <DaysRemainingBadge dueDate={finding.kev_due_date} />
          </div>
        </div>

        {/* Asset row */}
        <div className="flex items-center gap-4 text-xs text-slate-600 mb-3 flex-wrap">
          <div className="flex items-center gap-1.5">
            <Server size={12} className="text-slate-400" />
            <span className="font-medium">{finding.asset_name}</span>
            {finding.asset_ip && (
              <span className="text-slate-400 font-mono">{finding.asset_ip}</span>
            )}
          </div>
          <span
            className={`px-1.5 py-0.5 rounded text-xs font-medium ${
              finding.asset_environment === 'production'
                ? 'bg-purple-100 text-purple-700'
                : finding.asset_environment === 'staging'
                ? 'bg-blue-100 text-blue-600'
                : 'bg-slate-100 text-slate-600'
            }`}
          >
            {finding.asset_environment}
          </span>
        </div>

        {/* KEV details */}
        <div className="flex items-center gap-4 text-xs flex-wrap mb-4">
          {finding.kev_due_date && (
            <div className="flex items-center gap-1.5 text-slate-600">
              <Clock size={11} className="text-slate-400" />
              <span>Due:</span>
              <span
                className={`font-semibold ${
                  days !== null && days < 0
                    ? 'text-red-600'
                    : days !== null && days <= 7
                    ? 'text-orange-600'
                    : 'text-slate-700'
                }`}
              >
                {new Date(finding.kev_due_date).toLocaleDateString('en-US', {
                  month: 'short',
                  day: 'numeric',
                  year: 'numeric',
                })}
              </span>
            </div>
          )}
          {finding.kev_ransomware_use && (
            <div className="flex items-center gap-1.5">
              <Activity size={11} className="text-red-500" />
              <span className="text-red-600 font-medium">
                Ransomware: {finding.kev_ransomware_use}
              </span>
            </div>
          )}
          <div className="flex items-center gap-1.5 text-slate-600">
            <span>Risk Score:</span>
            <span className="font-bold text-slate-800">{finding.risk_score.toFixed(1)}</span>
          </div>
        </div>

        {/* Expand toggle for remediation */}
        {finding.remediation_action && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-xs text-indigo-600 hover:text-indigo-700 font-medium mb-3"
          >
            {expanded ? 'Hide remediation' : 'Show remediation'}
          </button>
        )}
        {expanded && finding.remediation_action && (
          <div className="mb-4 text-xs text-slate-700 bg-white/80 rounded-lg p-3 border border-slate-200 leading-relaxed">
            {finding.remediation_action}
          </div>
        )}

        {/* Status actions */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-slate-500">Quick update:</span>
          {(['open', 'in_progress', 'resolved', 'accepted_risk'] as Finding['status'][])
            .filter((s) => s !== finding.status)
            .map((s) => (
              <button
                key={s}
                onClick={() => handleQuickStatus(s)}
                disabled={updating}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors disabled:opacity-50 ${
                  s === 'resolved'
                    ? 'bg-green-100 text-green-700 hover:bg-green-200'
                    : s === 'in_progress'
                    ? 'bg-blue-100 text-blue-700 hover:bg-blue-200'
                    : s === 'accepted_risk'
                    ? 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    : 'bg-red-100 text-red-700 hover:bg-red-200'
                }`}
              >
                {updating ? '...' : s.replace('_', ' ')}
              </button>
            ))}
          <span
            className={`ml-auto px-2 py-0.5 rounded text-xs font-medium ${
              finding.status === 'open'
                ? 'bg-red-100 text-red-700'
                : finding.status === 'in_progress'
                ? 'bg-blue-100 text-blue-700'
                : finding.status === 'resolved'
                ? 'bg-green-100 text-green-700'
                : 'bg-slate-100 text-slate-600'
            }`}
          >
            {finding.status.replace('_', ' ')}
          </span>
        </div>
      </div>
    </div>
  );
}

export default function KevAlerts() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterEnv, setFilterEnv] = useState('');
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getActiveKevFindings(filterEnv || undefined);
      // Sort: overdue first, then by days remaining ascending
      data.sort((a, b) => {
        const da = daysRemaining(a.kev_due_date) ?? 9999;
        const db = daysRemaining(b.kev_due_date) ?? 9999;
        return da - db;
      });
      setFindings(data);
      setLastRefresh(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load KEV alerts');
    } finally {
      setLoading(false);
    }
  }, [filterEnv]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleStatusUpdate = async (id: string, status: Finding['status']): Promise<void> => {
    await updateFindingStatus(id, status);
    setFindings((prev) =>
      prev.map((f) => (f.id === id ? { ...f, status } : f))
    );
  };

  const overdue = findings.filter((f) => {
    const d = daysRemaining(f.kev_due_date);
    return d !== null && d < 0;
  });
  const dueSoon = findings.filter((f) => {
    const d = daysRemaining(f.kev_due_date);
    return d !== null && d >= 0 && d <= 7;
  });
  const other = findings.filter((f) => {
    const d = daysRemaining(f.kev_due_date);
    return d === null || d > 7;
  });

  const skeletonCards = Array.from({ length: 4 });

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-2xl font-bold text-slate-900">KEV Alerts</h1>
            <span className="inline-flex items-center gap-1 px-2.5 py-1 bg-red-600 text-white rounded-full text-xs font-bold">
              <AlertTriangle size={11} />
              {loading ? '…' : findings.length}
            </span>
          </div>
          <p className="text-slate-500 text-sm">
            CISA Known Exploited Vulnerabilities requiring immediate action
          </p>
          <p className="text-slate-400 text-xs mt-0.5">
            Last refreshed: {lastRefresh.toLocaleTimeString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={filterEnv}
            onChange={(e) => setFilterEnv(e.target.value)}
            className="px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All Environments</option>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
          </select>
          <button
            onClick={() => void load()}
            disabled={loading}
            className="btn-secondary"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* Summary stats */}
      {!loading && findings.length > 0 && (
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="card p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-100 flex items-center justify-center flex-shrink-0">
              <Clock size={18} className="text-red-600" />
            </div>
            <div>
              <div className="text-2xl font-bold text-red-600">{overdue.length}</div>
              <div className="text-xs text-slate-500">Overdue</div>
            </div>
          </div>
          <div className="card p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-orange-100 flex items-center justify-center flex-shrink-0">
              <AlertTriangle size={18} className="text-orange-600" />
            </div>
            <div>
              <div className="text-2xl font-bold text-orange-600">{dueSoon.length}</div>
              <div className="text-xs text-slate-500">Due within 7 days</div>
            </div>
          </div>
          <div className="card p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-100 flex items-center justify-center flex-shrink-0">
              <Activity size={18} className="text-indigo-600" />
            </div>
            <div>
              <div className="text-2xl font-bold text-slate-700">{findings.length}</div>
              <div className="text-xs text-slate-500">Total Active KEV</div>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="space-y-4">
          {skeletonCards.map((_, i) => (
            <div key={i} className="skeleton h-40 w-full rounded-xl" />
          ))}
        </div>
      ) : findings.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="w-14 h-14 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <AlertTriangle size={24} className="text-green-600" />
          </div>
          <h3 className="text-slate-700 font-semibold mb-1">No Active KEV Findings</h3>
          <p className="text-slate-400 text-sm">
            {filterEnv
              ? `No KEV findings in the ${filterEnv} environment.`
              : 'No active CISA KEV findings detected.'}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {overdue.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="h-px flex-1 bg-red-200" />
                <span className="text-xs font-bold text-red-600 uppercase tracking-wider flex items-center gap-1">
                  <Clock size={11} />
                  Overdue ({overdue.length})
                </span>
                <div className="h-px flex-1 bg-red-200" />
              </div>
              <div className="space-y-3">
                {overdue.map((f) => (
                  <KevCard key={f.id} finding={f} onStatusUpdate={handleStatusUpdate} />
                ))}
              </div>
            </div>
          )}

          {dueSoon.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3 mt-2">
                <div className="h-px flex-1 bg-orange-200" />
                <span className="text-xs font-bold text-orange-600 uppercase tracking-wider flex items-center gap-1">
                  <AlertTriangle size={11} />
                  Due within 7 days ({dueSoon.length})
                </span>
                <div className="h-px flex-1 bg-orange-200" />
              </div>
              <div className="space-y-3">
                {dueSoon.map((f) => (
                  <KevCard key={f.id} finding={f} onStatusUpdate={handleStatusUpdate} />
                ))}
              </div>
            </div>
          )}

          {other.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3 mt-2">
                <div className="h-px flex-1 bg-slate-200" />
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  Other Active KEV ({other.length})
                </span>
                <div className="h-px flex-1 bg-slate-200" />
              </div>
              <div className="space-y-3">
                {other.map((f) => (
                  <KevCard key={f.id} finding={f} onStatusUpdate={handleStatusUpdate} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
