import { useState, useEffect } from 'react';
import {
  SlidersHorizontal,
  Clock,
  Loader2,
  CheckCircle2,
  XCircle,
  Info,
  Server,
} from 'lucide-react';

interface RiskModel {
  weights: { cvss_base: number; kev_active: number; asset_criticality: number; epss_score: number };
  kev_multiplier: number;
  severity_thresholds: Record<string, number>;
  sla_days: { critical: number; high: number; medium: number; low: number };
  asset_criticality: Record<string, number>;
}

interface SystemInfo {
  version: string;
  environment: string;
  debug: boolean;
  uptime_human: string;
  connectors_configured: Record<string, boolean>;
  risk_model_path: string;
  kev_poll_interval_hours: number;
}

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem('warden_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function getRiskModel(): Promise<RiskModel> {
  const res = await fetch('/api/settings/risk-model', { headers: getAuthHeaders() });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function saveRiskModel(body: {
  weights: RiskModel['weights'];
  kev_multiplier: number;
  sla_days: RiskModel['sla_days'];
}): Promise<void> {
  const res = await fetch('/api/settings/risk-model', {
    method: 'PUT',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Save failed');
  }
}

async function getSystemInfo(): Promise<SystemInfo> {
  const res = await fetch('/api/settings/system', { headers: getAuthHeaders() });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

function NumberInput({
  label,
  value,
  onChange,
  min,
  max,
  step = 0.01,
  hint,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  step?: number;
  hint?: string;
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-500 mb-1">
        {label}
        {hint && <span className="text-slate-400 font-normal ml-1">({hint})</span>}
      </label>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        step={step}
        onChange={(e) => onChange(parseFloat(e.target.value) || 0)}
        className="w-full text-sm border border-slate-200 rounded-lg px-3 py-2 text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-400"
      />
    </div>
  );
}

function WeightBar({ label, value }: { label: string; value: number }) {
  const pct = Math.min(100, Math.round(value * 100));
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-slate-500 w-32 flex-shrink-0">{label}</span>
      <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
        <div className="h-full bg-indigo-500 rounded-full" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-slate-600 w-10 text-right">{pct}%</span>
    </div>
  );
}

export default function Settings() {
  const [model, setModel] = useState<RiskModel | null>(null);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  // Local editable state
  const [weights, setWeights] = useState({ cvss_base: 0.30, kev_active: 0.40, asset_criticality: 0.20, epss_score: 0.10 });
  const [kevMultiplier, setKevMultiplier] = useState(2.0);
  const [slaDays, setSlaDays] = useState({ critical: 15, high: 30, medium: 90, low: 180 });

  useEffect(() => {
    Promise.all([getRiskModel(), getSystemInfo()])
      .then(([m, s]) => {
        setModel(m);
        setSystem(s);
        setWeights(m.weights);
        setKevMultiplier(m.kev_multiplier);
        setSlaDays(m.sla_days);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const weightSum = Object.values(weights).reduce((a, b) => a + b, 0);
  const weightValid = Math.abs(weightSum - 1.0) < 0.011;

  const handleSave = async () => {
    setSaving(true);
    setResult(null);
    try {
      await saveRiskModel({ weights, kev_multiplier: kevMultiplier, sla_days: slaDays });
      setResult({ ok: true, msg: 'Saved. Changes apply on the next pipeline run.' });
    } catch (e: unknown) {
      setResult({ ok: false, msg: e instanceof Error ? e.message : 'Save failed' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-3xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">Settings</h1>
        <p className="text-slate-500 text-sm mt-1">
          Configure risk scoring weights, SLA targets, and view system information.
        </p>
      </div>

      {loading ? (
        <div className="flex items-center gap-3 text-slate-400 py-12 justify-center">
          <Loader2 size={18} className="animate-spin" /> Loading…
        </div>
      ) : (
        <>
          {/* Risk Scoring Weights */}
          <section className="bg-white border border-slate-200 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-full bg-indigo-50 flex items-center justify-center">
                <SlidersHorizontal size={18} className="text-indigo-600" />
              </div>
              <div>
                <h2 className="font-semibold text-slate-800">Risk Scoring Weights</h2>
                <p className="text-xs text-slate-400">Must sum to exactly 1.0</p>
              </div>
            </div>

            {/* Live weight bar preview */}
            <div className="my-5 space-y-2 p-3 bg-slate-50 rounded-lg">
              <WeightBar label="CVSS Base Score" value={weights.cvss_base} />
              <WeightBar label="KEV Active" value={weights.kev_active} />
              <WeightBar label="Asset Criticality" value={weights.asset_criticality} />
              <WeightBar label="EPSS Score" value={weights.epss_score} />
              <div className={`text-xs font-mono text-right mt-1 ${weightValid ? 'text-emerald-600' : 'text-red-500'}`}>
                Sum: {weightSum.toFixed(3)} {weightValid ? '✓' : '— must equal 1.0'}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <NumberInput label="CVSS Base Score" value={weights.cvss_base} min={0} max={1}
                onChange={(v) => setWeights((w) => ({ ...w, cvss_base: v }))}
                hint="0.0 – 1.0" />
              <NumberInput label="KEV Active" value={weights.kev_active} min={0} max={1}
                onChange={(v) => setWeights((w) => ({ ...w, kev_active: v }))}
                hint="0.0 – 1.0" />
              <NumberInput label="Asset Criticality" value={weights.asset_criticality} min={0} max={1}
                onChange={(v) => setWeights((w) => ({ ...w, asset_criticality: v }))}
                hint="0.0 – 1.0" />
              <NumberInput label="EPSS Score" value={weights.epss_score} min={0} max={1}
                onChange={(v) => setWeights((w) => ({ ...w, epss_score: v }))}
                hint="0.0 – 1.0" />
            </div>

            <div className="mt-5 pt-4 border-t border-slate-100">
              <NumberInput label="KEV Multiplier" value={kevMultiplier} min={1} max={10} step={0.1}
                onChange={setKevMultiplier}
                hint="multiplies final score when finding is in KEV" />
            </div>
          </section>

          {/* SLA Targets */}
          <section className="bg-white border border-slate-200 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-9 h-9 rounded-full bg-amber-50 flex items-center justify-center">
                <Clock size={18} className="text-amber-600" />
              </div>
              <div>
                <h2 className="font-semibold text-slate-800">SLA Targets</h2>
                <p className="text-xs text-slate-400">Days to remediate by severity</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
                <NumberInput
                  key={sev}
                  label={sev.charAt(0).toUpperCase() + sev.slice(1)}
                  value={slaDays[sev]}
                  min={1}
                  max={3650}
                  step={1}
                  hint="days"
                  onChange={(v) => setSlaDays((s) => ({ ...s, [sev]: Math.round(v) }))}
                />
              ))}
            </div>

            <div className="mt-4 flex items-start gap-2 text-xs text-slate-400 bg-slate-50 rounded-lg p-3">
              <Info size={13} className="flex-shrink-0 mt-0.5" />
              Critical SLA of 15 days aligns with the CISA KEV federal remediation deadline.
              SLA compliance is tracked in the Reports page.
            </div>
          </section>

          {/* Save */}
          <div className="flex items-center gap-4">
            <button
              onClick={handleSave}
              disabled={saving || !weightValid}
              className="flex items-center gap-2 text-sm font-medium px-5 py-2.5 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg disabled:opacity-50 transition-colors"
            >
              {saving ? <Loader2 size={14} className="animate-spin" /> : <SlidersHorizontal size={14} />}
              Save settings
            </button>

            {result && (
              <div className={`flex items-center gap-2 text-sm ${result.ok ? 'text-emerald-600' : 'text-red-600'}`}>
                {result.ok ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
                {result.msg}
              </div>
            )}
          </div>

          {/* System Info */}
          {system && (
            <section className="bg-white border border-slate-200 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-9 h-9 rounded-full bg-slate-100 flex items-center justify-center">
                  <Server size={18} className="text-slate-600" />
                </div>
                <h2 className="font-semibold text-slate-800">System Information</h2>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                <div className="bg-slate-50 rounded-lg p-3">
                  <div className="text-xs text-slate-400 mb-0.5">Version</div>
                  <div className="font-mono font-medium text-slate-800">v{system.version}</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <div className="text-xs text-slate-400 mb-0.5">Environment</div>
                  <div className="font-medium text-slate-800 capitalize">{system.environment}</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <div className="text-xs text-slate-400 mb-0.5">Uptime</div>
                  <div className="font-medium text-slate-800">{system.uptime_human}</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-3">
                  <div className="text-xs text-slate-400 mb-0.5">KEV Poll Interval</div>
                  <div className="font-medium text-slate-800">Every {system.kev_poll_interval_hours}h</div>
                </div>
              </div>

              <div className="mt-4">
                <div className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">
                  Configured integrations
                </div>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(system.connectors_configured).map(([name, configured]) => (
                    <span
                      key={name}
                      className={`inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-full font-medium ${
                        configured
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          : 'bg-slate-100 text-slate-400 border border-slate-200'
                      }`}
                    >
                      {configured ? <CheckCircle2 size={10} /> : <XCircle size={10} />}
                      {name}
                    </span>
                  ))}
                </div>
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}
