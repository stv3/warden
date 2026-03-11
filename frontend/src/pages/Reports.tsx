import React, { useEffect, useState } from 'react';
import {
  FileDown,
  Link,
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  BarChart2,
  Table2,
} from 'lucide-react';
import { downloadFindingsCsv, downloadKevSummaryCsv, getTableauConnectionInfo } from '../api';
import type { TableauConnectionInfo } from '../types';

function DownloadCard({
  title,
  description,
  icon,
  fileName,
  onDownload,
}: {
  title: string;
  description: string;
  icon: React.ReactNode;
  fileName: string;
  onDownload: () => Promise<void>;
}) {
  const [downloading, setDownloading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleClick = async () => {
    setDownloading(true);
    setError(null);
    setSuccess(false);
    try {
      await onDownload();
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Download failed');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="card p-6">
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 rounded-xl bg-indigo-50 flex items-center justify-center flex-shrink-0">
          {icon}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-base font-semibold text-slate-900 mb-0.5">{title}</h3>
          <p className="text-sm text-slate-500 mb-1">{description}</p>
          <p className="text-xs text-slate-400 font-mono mb-4">{fileName}</p>
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={() => void handleClick()}
              disabled={downloading}
              className="btn-primary"
            >
              {downloading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Downloading...
                </>
              ) : success ? (
                <>
                  <CheckCircle2 size={14} />
                  Downloaded!
                </>
              ) : (
                <>
                  <FileDown size={14} />
                  Download CSV
                </>
              )}
            </button>
            {error && (
              <div className="flex items-center gap-1.5 text-red-600 text-sm">
                <AlertTriangle size={13} />
                {error}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function CopyableField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  return (
    <div>
      <label className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-1 block">
        {label}
      </label>
      <div className="flex items-center gap-2">
        <div className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-700 break-all">
          {value}
        </div>
        <button
          onClick={() => void handleCopy()}
          className="flex-shrink-0 p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
          title="Copy to clipboard"
        >
          {copied ? (
            <CheckCircle2 size={15} className="text-green-500" />
          ) : (
            <Copy size={15} />
          )}
        </button>
      </div>
    </div>
  );
}

export default function Reports() {
  const [connInfo, setConnInfo] = useState<TableauConnectionInfo | null>(null);
  const [connLoading, setConnLoading] = useState(true);
  const [connError, setConnError] = useState<string | null>(null);

  useEffect(() => {
    getTableauConnectionInfo()
      .then(setConnInfo)
      .catch((e) => setConnError(e instanceof Error ? e.message : 'Failed to load connection info'))
      .finally(() => setConnLoading(false));
  }, []);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900">Reports & Export</h1>
        <p className="text-slate-500 text-sm mt-0.5">
          Download data exports and connect BI tools to Warden
        </p>
      </div>

      {/* CSV Downloads */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wide mb-3 flex items-center gap-2">
          <FileDown size={14} />
          CSV Exports
        </h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <DownloadCard
            title="All Findings"
            description="Complete export of all vulnerability findings with full metadata, scores, and remediation details."
            icon={<Table2 size={22} className="text-indigo-600" />}
            fileName="warden-findings.csv"
            onDownload={downloadFindingsCsv}
          />
          <DownloadCard
            title="KEV Summary"
            description="Focused export of CISA KEV findings with due dates, ransomware indicators, and asset context."
            icon={<AlertTriangle size={22} className="text-orange-500" />}
            fileName="warden-kev-summary.csv"
            onDownload={downloadKevSummaryCsv}
          />
        </div>
      </section>

      {/* BI Tool Connection */}
      <section className="mb-8">
        <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wide mb-3 flex items-center gap-2">
          <Link size={14} />
          BI Tool Connection
        </h2>

        {connLoading ? (
          <div className="card p-6">
            <div className="space-y-3">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="skeleton h-10 w-full" />
              ))}
            </div>
          </div>
        ) : connError ? (
          <div className="card p-6 flex items-center gap-2 text-red-700 text-sm">
            <AlertTriangle size={16} />
            {connError}
          </div>
        ) : connInfo ? (
          <div className="card p-6">
            <div className="space-y-4">
              <CopyableField label="Base URL" value={connInfo.base_url} />
              <CopyableField
                label="Findings Endpoint"
                value={connInfo.endpoints?.findings ?? `${connInfo.base_url}/api/export/tableau/findings.csv`}
              />
              <CopyableField
                label="KEV Summary Endpoint"
                value={connInfo.endpoints?.kev_summary ?? `${connInfo.base_url}/api/export/tableau/kev-summary.csv`}
              />
              <CopyableField
                label="Auth Header"
                value={connInfo.auth_header ?? 'Authorization: Bearer <your-token>'}
              />
              {connInfo.refresh_schedule && (
                <CopyableField label="Suggested Refresh Schedule" value={connInfo.refresh_schedule} />
              )}
            </div>
          </div>
        ) : null}
      </section>

      {/* Instructions */}
      <section>
        <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wide mb-3 flex items-center gap-2">
          <BarChart2 size={14} />
          BI Tool Setup Instructions
        </h2>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Tableau */}
          <div className="card p-6">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <BarChart2 size={16} className="text-white" />
              </div>
              <h3 className="font-semibold text-slate-900">Tableau</h3>
            </div>
            <ol className="space-y-2.5 text-sm text-slate-600">
              <li className="flex gap-2">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs flex items-center justify-center font-bold">1</span>
                Open Tableau Desktop and select <strong>Web Data Connector</strong> or <strong>Other Databases (JDBC)</strong>.
              </li>
              <li className="flex gap-2">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs flex items-center justify-center font-bold">2</span>
                Choose <strong>Text File</strong> or <strong>Web Data Connector</strong> and enter the Findings Endpoint URL above.
              </li>
              <li className="flex gap-2">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs flex items-center justify-center font-bold">3</span>
                Add the Authorization header with your API token from the Auth Header field above.
              </li>
              <li className="flex gap-2">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs flex items-center justify-center font-bold">4</span>
                Set up a scheduled extract refresh matching the suggested refresh schedule.
              </li>
            </ol>
          </div>

          {/* Power BI / Other */}
          <div className="card p-6">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 bg-yellow-500 rounded-lg flex items-center justify-center">
                <BarChart2 size={16} className="text-white" />
              </div>
              <h3 className="font-semibold text-slate-900">Power BI / Other Tools</h3>
            </div>
            <ol className="space-y-2.5 text-sm text-slate-600">
              <li className="flex gap-2">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-yellow-100 text-yellow-700 text-xs flex items-center justify-center font-bold">1</span>
                In Power BI, select <strong>Get Data → Web</strong> and enter the CSV endpoint URL.
              </li>
              <li className="flex gap-2">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-yellow-100 text-yellow-700 text-xs flex items-center justify-center font-bold">2</span>
                In the <strong>Advanced</strong> section, add an HTTP request header:<br />
                <code className="text-xs bg-slate-100 px-1 py-0.5 rounded font-mono">Authorization: Bearer &lt;token&gt;</code>
              </li>
              <li className="flex gap-2">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-yellow-100 text-yellow-700 text-xs flex items-center justify-center font-bold">3</span>
                Click <strong>Transform Data</strong> to map columns and create your model.
              </li>
              <li className="flex gap-2">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-yellow-100 text-yellow-700 text-xs flex items-center justify-center font-bold">4</span>
                Schedule a daily dataset refresh in the Power BI service.
              </li>
            </ol>
          </div>

          {/* Direct API */}
          <div className="card p-6 lg:col-span-2">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 bg-slate-700 rounded-lg flex items-center justify-center">
                <ExternalLink size={16} className="text-white" />
              </div>
              <h3 className="font-semibold text-slate-900">Direct API / Custom Integration</h3>
            </div>
            <p className="text-sm text-slate-600 mb-3">
              All Warden endpoints are accessible via standard HTTP. Use any HTTP client or ETL
              pipeline to fetch data programmatically.
            </p>
            <div className="bg-slate-900 rounded-lg p-4 font-mono text-xs text-slate-300 overflow-x-auto">
              <div className="text-slate-500 mb-1"># Fetch all findings as CSV</div>
              <div>
                curl -H "Authorization: Bearer $WARDEN_TOKEN" \
              </div>
              <div className="pl-4">
                http://localhost:8000/api/export/tableau/findings.csv \
              </div>
              <div className="pl-4">
                -o findings.csv
              </div>
              <div className="mt-3 text-slate-500"># Fetch KEV summary as CSV</div>
              <div>
                curl -H "Authorization: Bearer $WARDEN_TOKEN" \
              </div>
              <div className="pl-4">
                http://localhost:8000/api/export/tableau/kev-summary.csv \
              </div>
              <div className="pl-4">
                -o kev-summary.csv
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
