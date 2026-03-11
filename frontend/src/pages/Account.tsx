import { useState, useEffect } from 'react';
import {
  User,
  KeyRound,
  Clock,
  Shield,
  CheckCircle2,
  XCircle,
  Loader2,
  Eye,
  EyeOff,
} from 'lucide-react';
import { getMe } from '../api';
import { useAuth } from '../auth';

interface AccountInfo {
  username: string;
  role: string;
  token_expires_at: string | null;
  token_issued_at: string | null;
  token_lifetime_minutes: number;
  session_ip: string | null;
}

interface TokenInfo {
  algorithm: string;
  token_lifetime_minutes: number;
  expires_at: string | null;
  seconds_remaining: number;
  minutes_remaining: number;
}

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem('warden_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function getAccountInfo(): Promise<AccountInfo> {
  const res = await fetch('/api/account/me', { headers: getAuthHeaders() });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function getTokenInfo(): Promise<TokenInfo> {
  const res = await fetch('/api/account/token-info', { headers: getAuthHeaders() });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function changePassword(current: string, next: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch('/api/account/password', {
    method: 'POST',
    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: current, new_password: next }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Request failed');
  }
  return res.json();
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between py-3 border-b border-slate-100 last:border-0">
      <span className="text-sm text-slate-500">{label}</span>
      <span className="text-sm font-medium text-slate-800 text-right max-w-xs">{value}</span>
    </div>
  );
}

function PasswordField({
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
  const [show, setShow] = useState(false);
  return (
    <div>
      <label className="block text-xs font-medium text-slate-500 mb-1">{label}</label>
      <div className="relative">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="w-full text-sm border border-slate-200 rounded-lg px-3 py-2 pr-9 text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-400"
        />
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
        >
          {show ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      </div>
    </div>
  );
}

export default function Account() {
  const { user } = useAuth();
  const [info, setInfo] = useState<AccountInfo | null>(null);
  const [tokenInfo, setTokenInfo] = useState<TokenInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [pwSaving, setPwSaving] = useState(false);
  const [pwResult, setPwResult] = useState<{ ok: boolean; msg: string } | null>(null);

  useEffect(() => {
    Promise.all([getAccountInfo(), getTokenInfo()])
      .then(([a, t]) => { setInfo(a); setTokenInfo(t); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleChangePassword = async () => {
    setPwResult(null);
    if (newPw !== confirmPw) {
      setPwResult({ ok: false, msg: 'New passwords do not match' });
      return;
    }
    if (newPw.length < 12) {
      setPwResult({ ok: false, msg: 'Password must be at least 12 characters' });
      return;
    }
    setPwSaving(true);
    try {
      const res = await changePassword(currentPw, newPw);
      setPwResult({ ok: true, msg: res.message });
      setCurrentPw(''); setNewPw(''); setConfirmPw('');
    } catch (e: unknown) {
      setPwResult({ ok: false, msg: e instanceof Error ? e.message : 'Failed' });
    } finally {
      setPwSaving(false);
    }
  };

  const formatDate = (iso: string | null) => {
    if (!iso) return '—';
    return new Date(iso).toLocaleString();
  };

  const progressPct = tokenInfo
    ? Math.round((tokenInfo.seconds_remaining / (tokenInfo.token_lifetime_minutes * 60)) * 100)
    : 0;

  return (
    <div className="max-w-2xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">My Account</h1>
        <p className="text-slate-500 text-sm mt-1">Manage your profile, session, and security settings.</p>
      </div>

      {loading ? (
        <div className="flex items-center gap-3 text-slate-400 py-12 justify-center">
          <Loader2 size={18} className="animate-spin" /> Loading…
        </div>
      ) : (
        <>
          {/* Profile */}
          <section className="bg-white border border-slate-200 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-9 h-9 rounded-full bg-indigo-100 flex items-center justify-center">
                <User size={18} className="text-indigo-600" />
              </div>
              <h2 className="font-semibold text-slate-800">Profile</h2>
            </div>
            <InfoRow label="Username" value={info?.username ?? user?.username ?? '—'} />
            <InfoRow
              label="Role"
              value={
                <span className="inline-flex items-center gap-1 text-xs font-medium bg-indigo-50 text-indigo-700 border border-indigo-200 rounded-full px-2 py-0.5">
                  <Shield size={10} /> {info?.role ?? 'admin'}
                </span>
              }
            />
            <InfoRow label="Session IP" value={info?.session_ip ?? '—'} />
          </section>

          {/* Session */}
          <section className="bg-white border border-slate-200 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-9 h-9 rounded-full bg-amber-50 flex items-center justify-center">
                <Clock size={18} className="text-amber-600" />
              </div>
              <h2 className="font-semibold text-slate-800">Session</h2>
            </div>
            <InfoRow label="Issued at" value={formatDate(info?.token_issued_at ?? null)} />
            <InfoRow label="Expires at" value={formatDate(info?.token_expires_at ?? null)} />
            <InfoRow
              label="Time remaining"
              value={
                tokenInfo ? (
                  <span className={tokenInfo.minutes_remaining < 30 ? 'text-red-600' : 'text-slate-800'}>
                    {tokenInfo.minutes_remaining.toFixed(0)} min
                  </span>
                ) : '—'
              }
            />
            {tokenInfo && (
              <div className="mt-3">
                <div className="flex justify-between text-xs text-slate-400 mb-1">
                  <span>Session life</span>
                  <span>{progressPct}% remaining</span>
                </div>
                <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${progressPct > 30 ? 'bg-indigo-500' : 'bg-red-500'}`}
                    style={{ width: `${progressPct}%` }}
                  />
                </div>
              </div>
            )}
            <InfoRow label="Token algorithm" value={tokenInfo?.algorithm ?? 'HS256'} />
          </section>

          {/* Change password */}
          <section className="bg-white border border-slate-200 rounded-xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-9 h-9 rounded-full bg-emerald-50 flex items-center justify-center">
                <KeyRound size={18} className="text-emerald-600" />
              </div>
              <h2 className="font-semibold text-slate-800">Change Password</h2>
            </div>

            <div className="space-y-4">
              <PasswordField
                label="Current password"
                value={currentPw}
                onChange={setCurrentPw}
                placeholder="Enter current password"
              />
              <PasswordField
                label="New password"
                value={newPw}
                onChange={setNewPw}
                placeholder="Minimum 12 characters"
              />
              <PasswordField
                label="Confirm new password"
                value={confirmPw}
                onChange={setConfirmPw}
                placeholder="Re-enter new password"
              />

              {pwResult && (
                <div
                  className={`flex items-start gap-2 text-xs rounded-lg p-3 ${
                    pwResult.ok
                      ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      : 'bg-red-50 text-red-700 border border-red-200'
                  }`}
                >
                  {pwResult.ok
                    ? <CheckCircle2 size={13} className="flex-shrink-0 mt-0.5" />
                    : <XCircle size={13} className="flex-shrink-0 mt-0.5" />}
                  {pwResult.msg}
                </div>
              )}

              <button
                onClick={handleChangePassword}
                disabled={pwSaving || !currentPw || !newPw || !confirmPw}
                className="flex items-center gap-2 text-sm font-medium px-4 py-2 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg disabled:opacity-50 transition-colors"
              >
                {pwSaving ? <Loader2 size={14} className="animate-spin" /> : <KeyRound size={14} />}
                Update password
              </button>

              <p className="text-xs text-slate-400">
                Password is stored in <code className="bg-slate-100 px-1 rounded font-mono">.env</code> and
                takes effect immediately. All active sessions remain valid until they expire.
              </p>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
