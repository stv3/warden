import { useRef, useState, useEffect } from 'react';
import {
  CheckCircle2,
  XCircle,
  ExternalLink,
  Loader2,
  Plug,
  Shield,
  Code2,
  Rss,
  Webhook,
  FlaskConical,
  ChevronDown,
  ChevronUp,
  Save,
  Eye,
  EyeOff,
  Upload,
  FileText,
  AlertCircle,
} from 'lucide-react';
import { getConnectors, testConnector, saveConnectorConfig, uploadConnectorFile, getConnectorUploads } from '../api';
import type { ConnectorStatus, ConnectorField, ConnectorsResponse } from '../types';

// ── Category metadata ──────────────────────────────────────────────────────

const CATEGORY_META: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  scanner:     { label: 'Vulnerability Scanners', icon: <Shield size={15} />,  color: 'text-indigo-500' },
  appsec:      { label: 'AppSec Tools',           icon: <Code2 size={15} />,   color: 'text-violet-500' },
  feed:        { label: 'Threat Feeds',            icon: <Rss size={15} />,    color: 'text-amber-500'  },
  integration: { label: 'Integrations',            icon: <Webhook size={15} />, color: 'text-teal-500'  },
};

// Accepted file types per connector name
const CONNECTOR_ACCEPT: Record<string, string> = {
  sast: '.json',
  sca:  '.txt',
  dast: '.xml,.json',
};

// ── Helpers ─────────────────────────────────────────────────────────────────

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

// ── Field input ────────────────────────────────────────────────────────────

function FieldInput({
  field,
  value,
  onChange,
}: {
  field: ConnectorField;
  value: string;
  onChange: (v: string) => void;
}) {
  const [show, setShow] = useState(false);

  if (field.type === 'boolean') {
    return (
      <label className="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={value === 'true'}
          onChange={(e) => onChange(e.target.checked ? 'true' : 'false')}
          className="w-4 h-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
        />
        <span className="text-sm text-slate-600">Enable</span>
      </label>
    );
  }

  const isPassword = field.type === 'password';
  const inputType = isPassword && !show ? 'password' : 'text';

  return (
    <div className="relative">
      <input
        type={inputType}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={field.placeholder}
        className="w-full text-sm border border-slate-200 rounded-lg px-3 py-2 pr-8 text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent"
      />
      {isPassword && (
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
        >
          {show ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      )}
    </div>
  );
}

// ── Config form ────────────────────────────────────────────────────────────

function ConfigForm({
  connector,
  onSaved,
}: {
  connector: ConnectorStatus;
  onSaved: () => void;
}) {
  const [values, setValues] = useState<Record<string, string>>(
    Object.fromEntries(connector.fields.map((f) => [f.key, f.current_value]))
  );
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  const handleSave = async () => {
    setSaving(true);
    setResult(null);
    try {
      await saveConnectorConfig(connector.name, values);
      setResult({ ok: true, msg: 'Saved. Restart the API server for changes to take full effect.' });
      onSaved();
    } catch (e: unknown) {
      setResult({ ok: false, msg: e instanceof Error ? e.message : 'Save failed' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="border-t border-slate-100 pt-4 mt-2 space-y-3">
      {connector.fields.map((field) => (
        <div key={field.key}>
          <label className="block text-xs font-medium text-slate-500 mb-1">
            {field.label}
            {field.required && <span className="text-red-400 ml-0.5">*</span>}
          </label>
          <FieldInput
            field={field}
            value={values[field.key] ?? ''}
            onChange={(v) => setValues((prev) => ({ ...prev, [field.key]: v }))}
          />
        </div>
      ))}

      {result && (
        <div
          className={`flex items-start gap-2 text-xs rounded-lg p-3 ${
            result.ok
              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
              : 'bg-red-50 text-red-700 border border-red-200'
          }`}
        >
          {result.ok ? <CheckCircle2 size={13} className="flex-shrink-0 mt-0.5" /> : <XCircle size={13} className="flex-shrink-0 mt-0.5" />}
          {result.msg}
        </div>
      )}

      <button
        onClick={handleSave}
        disabled={saving}
        className="flex items-center gap-2 text-sm font-medium px-4 py-2 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg disabled:opacity-60 transition-colors"
      >
        {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
        Save credentials
      </button>
    </div>
  );
}

// ── File upload row ────────────────────────────────────────────────────────

type UploadedFile = { name: string; size_bytes: number | null; uploaded_at: string | null };

function FileUploadRow({
  connectorName,
  filename,
  accept,
  uploadedFile,
  onUploaded,
}: {
  connectorName: string;
  filename: string;
  accept: string;
  uploadedFile: UploadedFile | undefined;
  onUploaded: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [justUploaded, setJustUploaded] = useState(false);

  const present = uploadedFile && uploadedFile.size_bytes !== null;

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setError(null);
    setJustUploaded(false);
    try {
      await uploadConnectorFile(connectorName, filename, file);
      setJustUploaded(true);
      onUploaded();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
      // Reset so the same file can be re-uploaded
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  return (
    <div className="flex items-center gap-3 py-2.5 border-b border-slate-100 last:border-0">
      {/* Hidden file input */}
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={handleFileChange}
      />

      {/* File icon + name */}
      <div className="flex items-center gap-2 flex-1 min-w-0">
        <FileText
          size={14}
          className={present || justUploaded ? 'text-violet-500 flex-shrink-0' : 'text-slate-300 flex-shrink-0'}
        />
        <code className="text-xs font-mono text-slate-700 truncate">{filename}</code>
      </div>

      {/* Status */}
      <div className="flex items-center gap-2 flex-shrink-0">
        {uploading ? (
          <span className="flex items-center gap-1 text-xs text-slate-500">
            <Loader2 size={11} className="animate-spin" /> Uploading…
          </span>
        ) : justUploaded ? (
          <span className="flex items-center gap-1 text-xs text-emerald-600 font-medium">
            <CheckCircle2 size={11} /> Uploaded
          </span>
        ) : present ? (
          <span className="text-xs text-slate-400">
            {fmtBytes(uploadedFile.size_bytes!)} · {fmtDate(uploadedFile.uploaded_at!)}
          </span>
        ) : (
          <span className="flex items-center gap-1 text-xs text-amber-600">
            <AlertCircle size={11} /> Not uploaded
          </span>
        )}
      </div>

      {/* Upload button */}
      <button
        onClick={() => inputRef.current?.click()}
        disabled={uploading}
        className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-violet-50 hover:bg-violet-100 text-violet-700 border border-violet-200 transition-colors disabled:opacity-50 flex-shrink-0"
      >
        <Upload size={11} />
        {present || justUploaded ? 'Replace' : 'Upload'}
      </button>

      {error && (
        <span className="text-xs text-red-600 flex-shrink-0 max-w-[140px] truncate" title={error}>
          {error}
        </span>
      )}
    </div>
  );
}

// ── File upload section ─────────────────────────────────────────────────────

function FileUploadSection({
  connector,
}: {
  connector: ConnectorStatus;
}) {
  const [uploads, setUploads] = useState<UploadedFile[]>([]);
  const [loading, setLoading] = useState(true);
  const accept = CONNECTOR_ACCEPT[connector.name] ?? '*';

  const refresh = () => {
    getConnectorUploads(connector.name)
      .then((r) => setUploads(r.files))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { refresh(); }, [connector.name]);

  const inputFiles = connector.input_files ?? [];

  return (
    <div className="border-t border-slate-100 pt-3 mt-1">
      <div className="flex items-center gap-1.5 mb-2">
        <Upload size={12} className="text-violet-500" />
        <span className="text-xs font-semibold text-slate-600 uppercase tracking-wide">
          Input Files
        </span>
      </div>
      {loading ? (
        <div className="flex items-center gap-2 text-xs text-slate-400 py-2">
          <Loader2 size={11} className="animate-spin" /> Checking files…
        </div>
      ) : (
        <div>
          {inputFiles.map((fname) => (
            <FileUploadRow
              key={fname}
              connectorName={connector.name}
              filename={fname}
              accept={accept}
              uploadedFile={uploads.find((u) => u.name === fname)}
              onUploaded={refresh}
            />
          ))}
        </div>
      )}
      <p className="text-xs text-slate-400 mt-2">
        Files are stored on the server and picked up automatically when the pipeline runs.
      </p>
    </div>
  );
}

// ── Connector card ─────────────────────────────────────────────────────────

function ConnectorCard({
  connector,
  onRefresh,
}: {
  connector: ConnectorStatus;
  onRefresh: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const isFileBased = (connector.input_files?.length ?? 0) > 0;

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const r = await testConnector(connector.name);
      setTestResult(r);
    } catch {
      setTestResult({ success: false, message: 'Request failed — check that the API is running' });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 flex flex-col gap-3">
      {/* Header row */}
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center flex-wrap gap-2 mb-1">
            <h3 className="font-semibold text-slate-800 text-sm">{connector.label}</h3>
            {connector.configured ? (
              <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-full px-2 py-0.5">
                <CheckCircle2 size={10} /> Configured
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 bg-slate-100 border border-slate-200 rounded-full px-2 py-0.5">
                <XCircle size={10} /> Not configured
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 leading-relaxed">{connector.description}</p>
        </div>
        {connector.finding_count > 0 && (
          <div className="text-right flex-shrink-0">
            <div className="text-lg font-bold text-slate-800">{connector.finding_count.toLocaleString()}</div>
            <div className="text-xs text-slate-400">findings</div>
          </div>
        )}
      </div>

      {/* File-based connector: upload section */}
      {isFileBased && <FileUploadSection connector={connector} />}

      {/* Test result */}
      {testResult && (
        <div
          className={`flex items-start gap-2 text-xs rounded-lg p-3 ${
            testResult.success
              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
              : 'bg-red-50 text-red-700 border border-red-200'
          }`}
        >
          {testResult.success
            ? <CheckCircle2 size={13} className="flex-shrink-0 mt-0.5" />
            : <XCircle size={13} className="flex-shrink-0 mt-0.5" />}
          {testResult.message}
        </div>
      )}

      {/* Config form (expand/collapse) */}
      {connector.configurable && expanded && (
        <ConfigForm connector={connector} onSaved={onRefresh} />
      )}

      {/* Footer actions */}
      <div className="flex items-center gap-2 pt-1 border-t border-slate-100">
        {connector.testable && (
          <button
            onClick={handleTest}
            disabled={testing || !connector.configured}
            title={!connector.configured ? 'Configure credentials first' : undefined}
            className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors ${
              connector.configured
                ? 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                : 'bg-slate-50 text-slate-300 cursor-not-allowed'
            }`}
          >
            {testing ? <Loader2 size={12} className="animate-spin" /> : <FlaskConical size={12} />}
            Test connection
          </button>
        )}

        {connector.configurable && (
          <button
            onClick={() => setExpanded((e) => !e)}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 transition-colors"
          >
            {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            {expanded ? 'Hide config' : 'Configure'}
          </button>
        )}

        <a
          href={connector.docs_url}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 text-xs text-slate-400 hover:text-indigo-500 transition-colors ml-auto"
        >
          Docs <ExternalLink size={11} />
        </a>
      </div>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

const CATEGORY_ORDER = ['scanner', 'appsec', 'feed', 'integration'];

export default function Connectors() {
  const [data, setData] = useState<ConnectorsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    getConnectors()
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  return (
    <div className="space-y-8">
      {/* Page header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Connectors</h1>
          <p className="text-slate-500 text-sm mt-1">
            Connect Warden to your security tools. Credentials are saved to{' '}
            <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded font-mono">.env</code>{' '}
            and take effect immediately (full restart recommended for production).
          </p>
        </div>
        {data && (
          <div className="flex gap-5 text-right flex-shrink-0">
            <div>
              <div className="text-2xl font-bold text-slate-800">
                {data.summary.configured}/{data.summary.total}
              </div>
              <div className="text-xs text-slate-400">configured</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-indigo-600">{data.summary.scanners_configured}</div>
              <div className="text-xs text-slate-400">scanners active</div>
            </div>
          </div>
        )}
      </div>

      {loading && (
        <div className="flex items-center gap-3 text-slate-500 py-16 justify-center">
          <Loader2 size={20} className="animate-spin" />
          Loading connectors…
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl p-4 text-sm">
          Failed to load connectors: {error}
        </div>
      )}

      {data &&
        CATEGORY_ORDER.map((cat) => {
          const meta = CATEGORY_META[cat];
          const connectors = data.connectors.filter((c) => c.category === cat);
          if (!connectors.length) return null;
          return (
            <section key={cat}>
              <div className={`flex items-center gap-2 mb-4 ${meta.color}`}>
                {meta.icon}
                <h2 className="text-sm font-semibold uppercase tracking-wide">{meta.label}</h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {connectors.map((c) => (
                  <ConnectorCard key={c.name} connector={c} onRefresh={load} />
                ))}
              </div>
            </section>
          );
        })}

      {/* Dev guide */}
      {data && (
        <section className="bg-slate-800 text-slate-300 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-3 text-slate-100">
            <Plug size={15} />
            <h2 className="font-semibold text-sm">Adding a custom connector</h2>
          </div>
          <ol className="space-y-2 text-sm text-slate-400 list-decimal list-inside">
            <li>
              Create{' '}
              <code className="text-slate-200 bg-slate-700 px-1.5 py-0.5 rounded font-mono text-xs">connectors/your_tool.py</code>{' '}
              extending{' '}
              <code className="text-slate-200 bg-slate-700 px-1.5 py-0.5 rounded font-mono text-xs">BaseConnector</code> —
              implement <code className="text-slate-200 bg-slate-700 px-1.5 py-0.5 rounded font-mono text-xs">test_connection()</code> and{' '}
              <code className="text-slate-200 bg-slate-700 px-1.5 py-0.5 rounded font-mono text-xs">fetch_findings()</code>.
            </li>
            <li>
              Add credentials to{' '}
              <code className="text-slate-200 bg-slate-700 px-1.5 py-0.5 rounded font-mono text-xs">config/settings.py</code>.
            </li>
            <li>
              Register in{' '}
              <code className="text-slate-200 bg-slate-700 px-1.5 py-0.5 rounded font-mono text-xs">orchestrator/pipeline.py → _fetch_all_sources()</code>.
            </li>
            <li>
              Add a field schema in{' '}
              <code className="text-slate-200 bg-slate-700 px-1.5 py-0.5 rounded font-mono text-xs">api/routes/connectors.py → CONNECTOR_FIELDS</code>{' '}
              to enable UI configuration.
            </li>
          </ol>
        </section>
      )}
    </div>
  );
}
