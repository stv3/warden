import React, { useEffect, useState } from 'react';
import {
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import {
  ShieldAlert,
  AlertTriangle,
  Clock,
  TrendingUp,
  Activity,
  Server,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import {
  getKevExposure,
  getMttr,
  getSlaCompliance,
  getScannerCoverage,
  getRiskTrend,
} from '../api';
import type {
  KevExposureMetric,
  MttrMetric,
  SlaComplianceMetric,
  ScannerCoverage,
  RiskTrendPoint,
} from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#60a5fa',
};

function StatCard({
  label,
  value,
  sub,
  icon,
  accent,
  loading,
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ReactNode;
  accent: string;
  loading: boolean;
}) {
  return (
    <div className="card p-5 flex items-start gap-4">
      <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${accent}`}>
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-slate-500 text-xs font-medium uppercase tracking-wide mb-0.5">{label}</p>
        {loading ? (
          <>
            <div className="skeleton h-7 w-16 mb-1" />
            <div className="skeleton h-3 w-24" />
          </>
        ) : (
          <>
            <p className="text-2xl font-bold text-slate-900">{value}</p>
            {sub && <p className="text-xs text-slate-500 mt-0.5 truncate">{sub}</p>}
          </>
        )}
      </div>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wide mb-3">{children}</h2>;
}

export default function Dashboard() {
  const [kev, setKev] = useState<KevExposureMetric | null>(null);
  const [mttr, setMttr] = useState<MttrMetric[]>([]);
  const [sla, setSla] = useState<SlaComplianceMetric[]>([]);
  const [scanners, setScanners] = useState<ScannerCoverage[]>([]);
  const [riskTrend, setRiskTrend] = useState<RiskTrendPoint[]>([]);
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({});
  const [totalOpen, setTotalOpen] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadAll() {
      setLoading(true);
      setError(null);
      try {
        const [kevData, mttrData, slaData, scanData, trendData] = await Promise.all([
          getKevExposure(),
          getMttr(90),
          getSlaCompliance(),
          getScannerCoverage(),
          getRiskTrend(30),
        ]);

        setKev(kevData);
        setMttr(mttrData);
        setSla(slaData);
        setScanners(scanData);
        setRiskTrend(trendData);

        // Use accurate open-by-severity counts from the kev-exposure endpoint
        setSeverityCounts(kevData.open_by_severity ?? {});
        setTotalOpen(kevData.total_findings);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load dashboard data');
      } finally {
        setLoading(false);
      }
    }
    void loadAll();
  }, []);

  const criticalHighCount = (severityCounts['critical'] ?? 0) + (severityCounts['high'] ?? 0);
  const slaOverdue = sla.reduce((sum, s) => sum + s.overdue, 0);

  const donutData = Object.entries(severityCounts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  const trendFormatted = riskTrend.map((p) => ({
    ...p,
    date: new Date(p.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
  }));

  const totalDedupSavings = scanners.reduce((sum, s) => sum + (s.dedup_savings ?? 0), 0);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900">Dashboard</h1>
        <p className="text-slate-500 text-sm mt-0.5">Vulnerability intelligence overview</p>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          <XCircle size={16} />
          {error}
        </div>
      )}

      {/* Row 1: Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <StatCard
          label="Total Open Findings"
          value={totalOpen.toLocaleString()}
          sub="Across all environments"
          icon={<ShieldAlert size={18} className="text-indigo-600" />}
          accent="bg-indigo-50"
          loading={loading}
        />
        <StatCard
          label="Critical / High"
          value={criticalHighCount.toLocaleString()}
          sub={`${severityCounts['critical'] ?? 0} critical, ${severityCounts['high'] ?? 0} high`}
          icon={<AlertTriangle size={18} className="text-red-600" />}
          accent="bg-red-50"
          loading={loading}
        />
        <StatCard
          label="In KEV"
          value={kev?.kev_findings.toLocaleString() ?? '—'}
          sub={kev ? `${kev.kev_percentage.toFixed(1)}% of all findings` : undefined}
          icon={<Activity size={18} className="text-orange-600" />}
          accent="bg-orange-50"
          loading={loading}
        />
        <StatCard
          label="SLA Overdue"
          value={slaOverdue.toLocaleString()}
          sub="Requires immediate attention"
          icon={<Clock size={18} className="text-yellow-600" />}
          accent="bg-yellow-50"
          loading={loading}
        />
      </div>

      {/* Row 2: Severity donut + Risk trend */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* Severity breakdown donut */}
        <div className="card p-5">
          <SectionTitle>Severity Breakdown</SectionTitle>
          {loading ? (
            <div className="h-56 flex items-center justify-center">
              <div className="skeleton w-40 h-40 rounded-full" />
            </div>
          ) : donutData.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-slate-400 text-sm">
              No findings data available
            </div>
          ) : (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="60%" height={220}>
                <PieChart>
                  <Pie
                    data={donutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {donutData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={SEVERITY_COLORS[entry.name] ?? '#94a3b8'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value: number) => [value.toLocaleString(), 'Findings']}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-col gap-2 flex-1">
                {donutData.map((entry) => (
                  <div key={entry.name} className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div
                        className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                        style={{ backgroundColor: SEVERITY_COLORS[entry.name] ?? '#94a3b8' }}
                      />
                      <span className="text-sm text-slate-600 capitalize">{entry.name}</span>
                    </div>
                    <span className="text-sm font-semibold text-slate-800">
                      {entry.value.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Risk trend line chart */}
        <div className="card p-5">
          <SectionTitle>Risk Trend (Last 30 Days)</SectionTitle>
          {loading ? (
            <div className="h-56 skeleton" />
          ) : trendFormatted.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-slate-400 text-sm">
              No trend data available
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trendFormatted} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 11, fill: '#94a3b8' }}
                  tickLine={false}
                  interval="preserveStartEnd"
                />
                <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }}
                />
                <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12 }} />
                <Line
                  type="monotone"
                  dataKey="critical"
                  stroke="#dc2626"
                  strokeWidth={2}
                  dot={false}
                  name="Critical"
                />
                <Line
                  type="monotone"
                  dataKey="high"
                  stroke="#f97316"
                  strokeWidth={2}
                  dot={false}
                  name="High"
                />
                <Line
                  type="monotone"
                  dataKey="medium"
                  stroke="#eab308"
                  strokeWidth={2}
                  dot={false}
                  name="Medium"
                />
                <Line
                  type="monotone"
                  dataKey="low"
                  stroke="#60a5fa"
                  strokeWidth={2}
                  dot={false}
                  name="Low"
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Row 3: KEV Exposure + MTTR */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* KEV Exposure */}
        <div className="card p-5">
          <SectionTitle>KEV Exposure</SectionTitle>
          {loading ? (
            <div className="space-y-3">
              <div className="skeleton h-16 w-32" />
              <div className="skeleton h-4 w-48" />
              <div className="skeleton h-4 w-36" />
            </div>
          ) : kev ? (
            <div>
              <div className="flex items-end gap-3 mb-4">
                <span className="text-5xl font-bold text-red-600">{kev.kev_findings}</span>
                <div className="mb-1">
                  <span className="text-slate-500 text-sm">active KEV findings</span>
                  <div className="text-xs text-slate-400">{kev.kev_percentage.toFixed(1)}% of total</div>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-red-50 rounded-lg p-3 text-center">
                  <div className="text-xl font-bold text-red-600">{kev.overdue_count}</div>
                  <div className="text-xs text-red-500 mt-0.5">Overdue</div>
                </div>
                <div className="bg-orange-50 rounded-lg p-3 text-center">
                  <div className="text-xl font-bold text-orange-600">{kev.due_within_7_days}</div>
                  <div className="text-xs text-orange-500 mt-0.5">Due &lt; 7d</div>
                </div>
                <div className="bg-yellow-50 rounded-lg p-3 text-center">
                  <div className="text-xl font-bold text-yellow-600">{kev.due_within_30_days}</div>
                  <div className="text-xs text-yellow-500 mt-0.5">Due &lt; 30d</div>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-slate-400 text-sm">No KEV data available</div>
          )}
        </div>

        {/* MTTR by Severity */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-3">
            <SectionTitle>Mean Time to Remediate</SectionTitle>
            <span className="text-xs text-slate-400">Last 90 days</span>
          </div>
          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="skeleton h-8 w-full" />
              ))}
            </div>
          ) : mttr.length === 0 ? (
            <div className="text-slate-400 text-sm">No MTTR data available</div>
          ) : (
            <div className="space-y-3">
              {mttr.map((m) => (
                <div key={m.severity} className="flex items-center gap-3">
                  <div className="w-16 text-xs font-medium text-slate-600 capitalize flex-shrink-0">
                    {m.severity}
                  </div>
                  <div className="flex-1 bg-slate-100 rounded-full h-2">
                    <div
                      className="h-2 rounded-full transition-all"
                      style={{
                        width: `${Math.min(100, (m.average_days / 90) * 100)}%`,
                        backgroundColor: SEVERITY_COLORS[m.severity] ?? '#94a3b8',
                      }}
                    />
                  </div>
                  <div className="w-20 text-right text-sm font-semibold text-slate-700 flex-shrink-0">
                    {m.average_days.toFixed(1)}d
                  </div>
                  <div className="w-16 text-right text-xs text-slate-400 flex-shrink-0">
                    n={m.sample_size}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Row 4: Scanner Coverage */}
      <div className="card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <SectionTitle>Scanner Coverage</SectionTitle>
            {!loading && totalDedupSavings > 0 && (
              <p className="text-xs text-slate-500 -mt-2">
                {totalDedupSavings.toLocaleString()} duplicate findings deduplicated across scanners
              </p>
            )}
          </div>
          <Server size={16} className="text-slate-400" />
        </div>
        {loading ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="skeleton h-20" />
            ))}
          </div>
        ) : scanners.length === 0 ? (
          <div className="text-slate-400 text-sm">No scanner data available</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {scanners.map((s) => (
              <div key={s.scanner} className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold text-slate-700 capitalize">{s.scanner}</span>
                  <CheckCircle2 size={14} className="text-green-500" />
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-500">Findings</span>
                    <span className="font-medium text-slate-700">{s.finding_count.toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-500">Unique Assets</span>
                    <span className="font-medium text-slate-700">{s.unique_assets.toLocaleString()}</span>
                  </div>
                  {s.dedup_savings > 0 && (
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-500">Dedup Savings</span>
                      <span className="font-medium text-green-600">
                        -{s.dedup_savings.toLocaleString()}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* SLA Compliance summary */}
      <div className="card p-5 mt-4">
        <div className="flex items-center justify-between mb-4">
          <SectionTitle>SLA Compliance by Severity</SectionTitle>
          <TrendingUp size={16} className="text-slate-400" />
        </div>
        {loading ? (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="skeleton h-24" />
            ))}
          </div>
        ) : sla.length === 0 ? (
          <div className="text-slate-400 text-sm">No SLA data available</div>
        ) : (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {sla.map((s) => (
              <div key={s.severity} className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                <div
                  className="text-xs font-semibold uppercase tracking-wide mb-2 capitalize"
                  style={{ color: SEVERITY_COLORS[s.severity] ?? '#94a3b8' }}
                >
                  {s.severity}
                </div>
                <div className="text-2xl font-bold text-slate-900 mb-1">
                  {s.compliance_rate.toFixed(0)}%
                </div>
                <div className="text-xs text-slate-500">
                  {s.compliant} / {s.total} compliant
                </div>
                <div className="mt-2 bg-slate-200 rounded-full h-1.5">
                  <div
                    className="h-1.5 rounded-full"
                    style={{
                      width: `${s.compliance_rate}%`,
                      backgroundColor: s.compliance_rate >= 80 ? '#22c55e' : s.compliance_rate >= 60 ? '#eab308' : '#ef4444',
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
