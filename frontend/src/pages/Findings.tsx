import React, { useEffect, useState, useCallback } from 'react';
import {
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Filter,
  ExternalLink,
  AlertTriangle,
  X,
  SlidersHorizontal,
} from 'lucide-react';
import { getFindings, updateFindingStatus, getFilterOptions } from '../api';
import type { Finding, FindingsFilters } from '../types';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

function SeverityBadge({ severity }: { severity: Finding['severity'] }) {
  const classes: Record<string, string> = {
    critical: 'severity-badge severity-critical',
    high: 'severity-badge severity-high',
    medium: 'severity-badge severity-medium',
    low: 'severity-badge severity-low',
  };
  return <span className={classes[severity] ?? 'severity-badge'}>{severity}</span>;
}

function StatusBadge({ status }: { status: Finding['status'] }) {
  const map: Record<string, string> = {
    open: 'bg-red-100 text-red-700',
    in_progress: 'bg-blue-100 text-blue-700',
    resolved: 'bg-green-100 text-green-700',
    accepted_risk: 'bg-slate-100 text-slate-600',
  };
  const labels: Record<string, string> = {
    open: 'Open',
    in_progress: 'In Progress',
    resolved: 'Resolved',
    accepted_risk: 'Accepted Risk',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${map[status] ?? ''}`}>
      {labels[status] ?? status}
    </span>
  );
}

function EnvBadge({ env }: { env: Finding['asset_environment'] }) {
  const map: Record<string, string> = {
    production: 'bg-purple-100 text-purple-700',
    staging: 'bg-blue-100 text-blue-600',
    development: 'bg-slate-100 text-slate-600',
    unknown: 'bg-slate-50 text-slate-400',
  };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${map[env] ?? ''}`}>
      {env}
    </span>
  );
}

function slaStatus(due: string | null): { label: string; color: string } {
  if (!due) return { label: '—', color: 'text-slate-400' };
  const days = Math.ceil((new Date(due).getTime() - Date.now()) / 86400000);
  if (days < 0) return { label: `${Math.abs(days)}d overdue`, color: 'text-red-600 font-semibold' };
  if (days === 0) return { label: 'Due today', color: 'text-red-600 font-semibold' };
  if (days <= 7) return { label: `${days}d left`, color: 'text-orange-600 font-semibold' };
  if (days <= 30) return { label: `${days}d left`, color: 'text-yellow-600' };
  return { label: `${days}d left`, color: 'text-slate-500' };
}

function FilterSelect({
  label,
  value,
  onChange,
  children,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
      >
        {children}
      </select>
    </div>
  );
}

function FilterInput({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
      />
    </div>
  );
}

function DetailPanel({
  finding,
  onClose,
  onStatusUpdate,
}: {
  finding: Finding;
  onClose: () => void;
  onStatusUpdate: (id: string, status: Finding['status'], owner?: string) => Promise<void>;
}) {
  const [status, setStatus] = useState<Finding['status']>(finding.status);
  const [owner, setOwner] = useState(finding.owner ?? '');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const handleSave = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      await onStatusUpdate(finding.id, status, owner || undefined);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Update failed');
    } finally {
      setSaving(false);
    }
  };

  const sla = slaStatus(finding.sla_due_date);

  return (
    <div className="fixed inset-0 z-40 flex">
      <div className="flex-1 bg-black/30 cursor-pointer" onClick={onClose} />
      <div className="w-full max-w-xl bg-white shadow-2xl overflow-y-auto flex flex-col">
        <div
          className={`px-6 py-4 border-b border-slate-200 flex-shrink-0 ${
            finding.in_kev ? 'border-l-4 border-l-red-500' : ''
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <SeverityBadge severity={finding.severity} />
                {finding.in_kev && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-red-100 text-red-700 rounded text-xs font-semibold">
                    <AlertTriangle size={10} /> KEV
                  </span>
                )}
                {finding.cve_id && (
                  <span className="text-xs text-slate-500 font-mono">{finding.cve_id}</span>
                )}
              </div>
              <h3 className="text-sm font-semibold text-slate-900 leading-tight">{finding.title}</h3>
            </div>
            <button onClick={onClose} className="text-slate-400 hover:text-slate-600 flex-shrink-0 mt-0.5">
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="flex-1 p-6 space-y-5">
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-slate-50 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-slate-900">{finding.risk_score.toFixed(1)}</div>
              <div className="text-xs text-slate-500">Risk Score</div>
            </div>
            <div className="bg-slate-50 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-slate-900">
                {finding.cvss_score?.toFixed(1) ?? '—'}
              </div>
              <div className="text-xs text-slate-500">CVSS</div>
            </div>
            <div className="bg-slate-50 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-slate-900">
                {finding.epss_score !== null ? `${(finding.epss_score * 100).toFixed(1)}%` : '—'}
              </div>
              <div className="text-xs text-slate-500">EPSS</div>
            </div>
          </div>

          <div>
            <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Asset</h4>
            <div className="space-y-1.5 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-500">Host</span>
                <span className="font-medium text-slate-800">{finding.asset_name}</span>
              </div>
              {finding.asset_ip && (
                <div className="flex justify-between">
                  <span className="text-slate-500">IP Address</span>
                  <span className="font-mono text-slate-700">{finding.asset_ip}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-slate-500">Environment</span>
                <EnvBadge env={finding.asset_environment} />
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Criticality</span>
                <span className="font-medium text-slate-800">{finding.asset_criticality}/10</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Finding Type</span>
                <span className="text-slate-700 capitalize">{finding.finding_type}</span>
              </div>
            </div>
          </div>

          {finding.in_kev && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <h4 className="text-xs font-semibold text-red-700 uppercase tracking-wide mb-2 flex items-center gap-1">
                <AlertTriangle size={12} /> KEV Details
              </h4>
              <div className="space-y-1.5 text-sm">
                {finding.kev_due_date && (
                  <div className="flex justify-between">
                    <span className="text-red-600">Due Date</span>
                    <span className="font-semibold text-red-700">
                      {new Date(finding.kev_due_date).toLocaleDateString()}
                    </span>
                  </div>
                )}
                {finding.kev_ransomware_use && (
                  <div className="flex justify-between">
                    <span className="text-red-600">Ransomware Use</span>
                    <span className="font-medium text-red-700">{finding.kev_ransomware_use}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          <div>
            <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">SLA</h4>
            <div className="space-y-1.5 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-500">Due Date</span>
                <span className={sla.color}>{sla.label}</span>
              </div>
              {finding.sla_due_date && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Date</span>
                  <span className="text-slate-700">
                    {new Date(finding.sla_due_date).toLocaleDateString()}
                  </span>
                </div>
              )}
            </div>
          </div>

          <div>
            <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Sources</h4>
            <div className="flex flex-wrap gap-1.5">
              {(finding.sources ?? []).map((s) => (
                <span
                  key={s}
                  className="inline-flex items-center px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded text-xs font-medium"
                >
                  {s}
                </span>
              ))}
            </div>
          </div>

          {finding.remediation_action && (
            <div>
              <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
                Remediation
              </h4>
              <p className="text-sm text-slate-700 bg-slate-50 rounded-lg p-3 leading-relaxed">
                {finding.remediation_action}
              </p>
            </div>
          )}

          {((finding.nist_csf_controls ?? []).length > 0 || (finding.cis_controls ?? []).length > 0) && (
            <div>
              <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
                Security Controls
              </h4>
              {(finding.nist_csf_controls ?? []).length > 0 && (
                <div className="mb-2">
                  <p className="text-xs text-slate-400 mb-1">NIST CSF</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(finding.nist_csf_controls ?? []).map((c) => (
                      <span key={c} className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-xs font-mono">
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {(finding.cis_controls ?? []).length > 0 && (
                <div>
                  <p className="text-xs text-slate-400 mb-1">CIS Controls</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(finding.cis_controls ?? []).map((c) => (
                      <span key={c} className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded text-xs font-mono">
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {finding.ticket_id && (
            <div>
              <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Ticket</h4>
              <div className="flex items-center gap-2">
                <span className="text-sm text-slate-700">{finding.ticket_id}</span>
                {finding.ticket_url && (
                  <a
                    href={finding.ticket_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-indigo-500 hover:text-indigo-600"
                  >
                    <ExternalLink size={14} />
                  </a>
                )}
              </div>
            </div>
          )}

          <div>
            <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Timeline</h4>
            <div className="space-y-1.5 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-500">First Seen</span>
                <span className="text-slate-700">{new Date(finding.first_seen).toLocaleDateString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Last Seen</span>
                <span className="text-slate-700">{new Date(finding.last_seen).toLocaleDateString()}</span>
              </div>
              {finding.resolved_at && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Resolved</span>
                  <span className="text-green-600">{new Date(finding.resolved_at).toLocaleDateString()}</span>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="p-6 border-t border-slate-200 bg-slate-50 flex-shrink-0">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
            Update Status
          </h4>
          <div className="flex flex-col gap-2">
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as Finding['status'])}
              className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="accepted_risk">Accepted Risk</option>
            </select>
            <input
              type="text"
              placeholder="Assign owner (email or username)"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            {saveError && <p className="text-red-600 text-xs">{saveError}</p>}
            <button
              onClick={handleSave}
              disabled={saving}
              className="btn-primary w-full justify-center"
            >
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;

  // Basic filters
  const [filterStatus, setFilterStatus] = useState('open');
  const [filterSeverity, setFilterSeverity] = useState('');

  // Advanced filters
  const [filterEnv, setFilterEnv] = useState('');
  const [filterKev, setFilterKev] = useState('');
  const [filterSource, setFilterSource] = useState('');
  const [filterFindingType, setFilterFindingType] = useState('');
  const [filterSlaStatus, setFilterSlaStatus] = useState('');
  const [filterAssetName, setFilterAssetName] = useState('');
  const [filterCveId, setFilterCveId] = useState('');
  const [filterOwner, setFilterOwner] = useState('');
  const [filterNist, setFilterNist] = useState('');
  const [filterCis, setFilterCis] = useState('');
  const [filterMinRisk, setFilterMinRisk] = useState('');
  const [filterMaxRisk, setFilterMaxRisk] = useState('');

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [filterOptions, setFilterOptions] = useState<{
    finding_types: string[];
    sources: string[];
    owners: string[];
  }>({ finding_types: [], sources: [], owners: [] });

  const [sortKey, setSortKey] = useState<keyof Finding>('risk_score');
  const [sortAsc, setSortAsc] = useState(false);

  useEffect(() => {
    getFilterOptions().then(setFilterOptions).catch(() => {});
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const filters: FindingsFilters = {
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    };
    if (filterStatus) filters.status = filterStatus;
    if (filterSeverity) filters.severity = filterSeverity;
    if (filterEnv) filters.environment = filterEnv;
    if (filterKev === 'true') filters.in_kev = true;
    if (filterKev === 'false') filters.in_kev = false;
    if (filterSource) filters.source = filterSource;
    if (filterFindingType) filters.finding_type = filterFindingType;
    if (filterSlaStatus) filters.sla_status = filterSlaStatus;
    if (filterAssetName) filters.asset_name = filterAssetName;
    if (filterCveId) filters.cve_id = filterCveId;
    if (filterOwner) filters.owner = filterOwner;
    if (filterNist) filters.nist_control = filterNist;
    if (filterCis) filters.cis_control = filterCis;
    if (filterMinRisk) filters.min_risk_score = parseFloat(filterMinRisk);
    if (filterMaxRisk) filters.max_risk_score = parseFloat(filterMaxRisk);

    try {
      const data = await getFindings(filters);
      setFindings(data.findings);
      setTotal(data.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load findings');
    } finally {
      setLoading(false);
    }
  }, [
    page, filterStatus, filterSeverity, filterEnv, filterKev, filterSource,
    filterFindingType, filterSlaStatus, filterAssetName, filterCveId, filterOwner,
    filterNist, filterCis, filterMinRisk, filterMaxRisk,
  ]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleStatusUpdate = async (
    id: string,
    status: Finding['status'],
    owner?: string
  ): Promise<void> => {
    const updated = await updateFindingStatus(id, status, owner);
    setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
    if (selectedFinding?.id === id) {
      setSelectedFinding(updated);
    }
  };

  const handleSort = (key: keyof Finding) => {
    if (sortKey === key) {
      setSortAsc((v) => !v);
    } else {
      setSortKey(key);
      setSortAsc(false);
    }
  };

  const sortedFindings = [...findings].sort((a, b) => {
    const av = a[sortKey];
    const bv = b[sortKey];
    if (av === null || av === undefined) return 1;
    if (bv === null || bv === undefined) return -1;
    if (sortKey === 'severity') {
      const ai = SEVERITY_ORDER.indexOf(a.severity);
      const bi = SEVERITY_ORDER.indexOf(b.severity);
      return sortAsc ? ai - bi : bi - ai;
    }
    if (typeof av === 'number' && typeof bv === 'number') {
      return sortAsc ? av - bv : bv - av;
    }
    const as = String(av);
    const bs = String(bv);
    return sortAsc ? as.localeCompare(bs) : bs.localeCompare(as);
  });

  function SortIcon({ col }: { col: keyof Finding }) {
    if (sortKey !== col) return <ChevronDown size={12} className="text-slate-300 ml-0.5" />;
    return sortAsc ? (
      <ChevronUp size={12} className="text-indigo-500 ml-0.5" />
    ) : (
      <ChevronDown size={12} className="text-indigo-500 ml-0.5" />
    );
  }

  const resetPage = () => setPage(0);

  const clearFilters = () => {
    setFilterStatus('open');
    setFilterSeverity('');
    setFilterEnv('');
    setFilterKev('');
    setFilterSource('');
    setFilterFindingType('');
    setFilterSlaStatus('');
    setFilterAssetName('');
    setFilterCveId('');
    setFilterOwner('');
    setFilterNist('');
    setFilterCis('');
    setFilterMinRisk('');
    setFilterMaxRisk('');
    setPage(0);
  };

  const advancedCount = [
    filterEnv, filterKev, filterSource, filterFindingType, filterSlaStatus,
    filterAssetName, filterCveId, filterOwner, filterNist, filterCis,
    filterMinRisk, filterMaxRisk,
  ].filter(Boolean).length;

  const hasFilters = filterStatus !== 'open' || filterSeverity || advancedCount > 0;

  const skeletonRows = Array.from({ length: 10 });

  return (
    <div>
      <div className="mb-6 flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Findings</h1>
          <p className="text-slate-500 text-sm mt-0.5">
            {loading ? 'Loading...' : `${total.toLocaleString()} total findings`}
          </p>
        </div>
      </div>

      {/* Filter panel */}
      <div className="card p-4 mb-4">
        {/* Basic filter row */}
        <div className="flex items-center gap-2 flex-wrap">
          <Filter size={14} className="text-slate-400 flex-shrink-0" />

          <select
            value={filterStatus}
            onChange={(e) => { setFilterStatus(e.target.value); resetPage(); }}
            className="px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="accepted_risk">Accepted Risk</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => { setFilterSeverity(e.target.value); resetPage(); }}
            className="px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <button
            onClick={() => setShowAdvanced((v) => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
              showAdvanced || advancedCount > 0
                ? 'bg-indigo-50 border-indigo-200 text-indigo-700'
                : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
            }`}
          >
            <SlidersHorizontal size={13} />
            Advanced
            {advancedCount > 0 && (
              <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-indigo-600 text-white text-xs font-bold">
                {advancedCount}
              </span>
            )}
            {showAdvanced ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>

          {hasFilters && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1 px-3 py-1.5 text-slate-500 hover:text-slate-700 text-sm border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors"
            >
              <X size={12} />
              Clear
            </button>
          )}
        </div>

        {/* Advanced filter panel */}
        {showAdvanced && (
          <div className="mt-4 pt-4 border-t border-slate-100">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
              <FilterSelect label="Environment" value={filterEnv} onChange={(v) => { setFilterEnv(v); resetPage(); }}>
                <option value="">All Environments</option>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
                <option value="unknown">Unknown</option>
              </FilterSelect>

              <FilterSelect label="KEV" value={filterKev} onChange={(v) => { setFilterKev(v); resetPage(); }}>
                <option value="">All</option>
                <option value="true">In KEV only</option>
                <option value="false">Not in KEV</option>
              </FilterSelect>

              <FilterSelect
                label="Finding Type"
                value={filterFindingType}
                onChange={(v) => { setFilterFindingType(v); resetPage(); }}
              >
                <option value="">All Types</option>
                {filterOptions.finding_types.length > 0
                  ? filterOptions.finding_types.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))
                  : (
                    <>
                      <option value="network">Network</option>
                      <option value="application">Application</option>
                      <option value="code">Code</option>
                      <option value="configuration">Configuration</option>
                      <option value="dependency">Dependency</option>
                    </>
                  )}
              </FilterSelect>

              <FilterSelect label="SLA Status" value={filterSlaStatus} onChange={(v) => { setFilterSlaStatus(v); resetPage(); }}>
                <option value="">All</option>
                <option value="overdue">Overdue</option>
                <option value="due_soon">Due within 7 days</option>
                <option value="ok">On track (&gt;7 days)</option>
                <option value="none">No SLA set</option>
              </FilterSelect>

              <FilterInput
                label="Asset / IP"
                value={filterAssetName}
                onChange={(v) => { setFilterAssetName(v); resetPage(); }}
                placeholder="hostname or IP..."
              />

              <FilterInput
                label="CVE ID"
                value={filterCveId}
                onChange={(v) => { setFilterCveId(v); resetPage(); }}
                placeholder="CVE-2024-..."
              />

              <FilterInput
                label="Source"
                value={filterSource}
                onChange={(v) => { setFilterSource(v); resetPage(); }}
                placeholder="nessus, qualys..."
              />

              <FilterInput
                label="Owner"
                value={filterOwner}
                onChange={(v) => { setFilterOwner(v); resetPage(); }}
                placeholder="email or username..."
              />

              <FilterInput
                label="NIST CSF Control"
                value={filterNist}
                onChange={(v) => { setFilterNist(v); resetPage(); }}
                placeholder="e.g. DE.CM, PR.AC..."
              />

              <FilterInput
                label="CIS Control"
                value={filterCis}
                onChange={(v) => { setFilterCis(v); resetPage(); }}
                placeholder="e.g. CIS-1, CIS-7..."
              />

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Risk Score (min)</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  value={filterMinRisk}
                  onChange={(e) => { setFilterMinRisk(e.target.value); resetPage(); }}
                  placeholder="0.0"
                  className="w-full px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Risk Score (max)</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  value={filterMaxRisk}
                  onChange={(e) => { setFilterMaxRisk(e.target.value); resetPage(); }}
                  placeholder="10.0"
                  className="w-full px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200">
                <th
                  className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide cursor-pointer hover:text-slate-700 whitespace-nowrap"
                  onClick={() => handleSort('severity')}
                >
                  <span className="flex items-center">
                    Severity <SortIcon col="severity" />
                  </span>
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">
                  CVE ID
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                  Title
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">
                  Asset
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">
                  Env
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">
                  Sources
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide cursor-pointer hover:text-slate-700 whitespace-nowrap"
                  onClick={() => handleSort('risk_score')}
                >
                  <span className="flex items-center">
                    Risk <SortIcon col="risk_score" />
                  </span>
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">
                  Status
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide cursor-pointer hover:text-slate-700 whitespace-nowrap"
                  onClick={() => handleSort('sla_due_date')}
                >
                  <span className="flex items-center">
                    SLA <SortIcon col="sla_due_date" />
                  </span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading
                ? skeletonRows.map((_, i) => (
                    <tr key={i}>
                      {Array.from({ length: 9 }).map((__, j) => (
                        <td key={j} className="px-4 py-3">
                          <div className="skeleton h-4 w-full" />
                        </td>
                      ))}
                    </tr>
                  ))
                : sortedFindings.length === 0
                ? (
                    <tr>
                      <td colSpan={9} className="px-4 py-12 text-center text-slate-400 text-sm">
                        No findings match the current filters
                      </td>
                    </tr>
                  )
                : sortedFindings.map((f) => {
                    const sla = slaStatus(f.sla_due_date);
                    return (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`cursor-pointer hover:bg-slate-50 transition-colors ${
                          f.in_kev ? 'border-l-2 border-l-red-500' : ''
                        }`}
                      >
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <SeverityBadge severity={f.severity} />
                            {f.in_kev && (
                              <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-xs font-semibold">
                                <AlertTriangle size={9} />KEV
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span className="text-xs font-mono text-slate-600">
                            {f.cve_id ?? '—'}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-xs">
                          <span className="text-slate-800 text-xs leading-snug line-clamp-2">
                            {f.title}
                          </span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="text-xs text-slate-700 font-medium">{f.asset_name}</div>
                          {f.asset_ip && (
                            <div className="text-xs text-slate-400 font-mono">{f.asset_ip}</div>
                          )}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <EnvBadge env={f.asset_environment} />
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="flex gap-1 flex-wrap max-w-24">
                            {(f.sources ?? []).map((s) => (
                              <span
                                key={s}
                                className="px-1.5 py-0.5 bg-indigo-50 text-indigo-600 rounded text-xs"
                              >
                                {s}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span className="text-sm font-semibold text-slate-800">
                            {f.risk_score.toFixed(1)}
                          </span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <StatusBadge status={f.status} />
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span className={`text-xs ${sla.color}`}>{sla.label}</span>
                        </td>
                      </tr>
                    );
                  })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="px-4 py-3 border-t border-slate-200 flex items-center justify-between bg-slate-50">
          <span className="text-xs text-slate-500">
            Page {page + 1} · {PAGE_SIZE} per page · {total.toLocaleString()} total
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0 || loading}
              className="btn-secondary px-2 py-1 text-xs"
            >
              <ChevronLeft size={14} />
              Prev
            </button>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={findings.length < PAGE_SIZE || loading}
              className="btn-secondary px-2 py-1 text-xs"
            >
              Next
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {selectedFinding && (
        <DetailPanel
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onStatusUpdate={handleStatusUpdate}
        />
      )}
    </div>
  );
}
