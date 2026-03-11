import type {
  Finding,
  FindingsFilters,
  KevExposureMetric,
  MttrMetric,
  SlaComplianceMetric,
  FindingsByControl,
  ScannerCoverage,
  RiskTrendPoint,
  PipelineTask,
  TableauConnectionInfo,
  User,
  AuthToken,
  ConnectorsResponse,
  ConnectorTestResult,
} from './types';

// Empty string = relative URLs → Vite proxy in dev, nginx in production.
// Never hardcode a host here; both environments handle routing for /api, /auth, /health.
const BASE_URL = '';

function getToken(): string | null {
  return localStorage.getItem('warden_token');
}

function authHeaders(): HeadersInit {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    localStorage.removeItem('warden_token');
    localStorage.removeItem('warden_user');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API error ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// Auth
export async function login(username: string, password: string): Promise<AuthToken> {
  const form = new FormData();
  form.append('username', username);
  form.append('password', password);
  const res = await fetch(`${BASE_URL}/auth/token`, { method: 'POST', body: form });
  if (!res.ok) {
    throw new Error('Invalid credentials');
  }
  return res.json() as Promise<AuthToken>;
}

export async function getMe(): Promise<User> {
  const res = await fetch(`${BASE_URL}/auth/me`, { headers: authHeaders() });
  return handleResponse<User>(res);
}

// Health
export async function getHealth(): Promise<{ status: string }> {
  const res = await fetch(`${BASE_URL}/health`, { headers: authHeaders() });
  return handleResponse<{ status: string }>(res);
}

// Findings
export async function getFindings(
  filters: FindingsFilters
): Promise<{ total: number; findings: Finding[] }> {
  const params = new URLSearchParams();
  if (filters.status) params.set('status', filters.status);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.in_kev !== undefined) params.set('in_kev', String(filters.in_kev));
  if (filters.environment) params.set('environment', filters.environment);
  if (filters.source) params.set('source', filters.source);
  if (filters.finding_type) params.set('finding_type', filters.finding_type);
  if (filters.nist_control) params.set('nist_control', filters.nist_control);
  if (filters.cis_control) params.set('cis_control', filters.cis_control);
  if (filters.min_risk_score !== undefined) params.set('min_risk_score', String(filters.min_risk_score));
  if (filters.max_risk_score !== undefined) params.set('max_risk_score', String(filters.max_risk_score));
  if (filters.cve_id) params.set('cve_id', filters.cve_id);
  if (filters.asset_name) params.set('asset_name', filters.asset_name);
  if (filters.sla_status) params.set('sla_status', filters.sla_status);
  if (filters.owner) params.set('owner', filters.owner);
  params.set('limit', String(filters.limit));
  params.set('offset', String(filters.offset));

  const res = await fetch(`${BASE_URL}/api/findings/?${params.toString()}`, {
    headers: authHeaders(),
  });
  const data = await handleResponse<{ total: number; findings: Finding[] }>(res);
  return { total: data.total ?? 0, findings: data.findings ?? [] };
}

export async function getFinding(id: string): Promise<Finding> {
  const res = await fetch(`${BASE_URL}/api/findings/${id}`, { headers: authHeaders() });
  return handleResponse<Finding>(res);
}

export async function updateFindingStatus(
  id: string,
  status: Finding['status'],
  owner?: string
): Promise<Finding> {
  const body: { status: string; owner?: string } = { status };
  if (owner !== undefined) body.owner = owner;
  const res = await fetch(`${BASE_URL}/api/findings/${id}/status`, {
    method: 'PATCH',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return handleResponse<Finding>(res);
}

export async function getActiveKevFindings(environment?: string): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (environment) params.set('environment', environment);
  const res = await fetch(`${BASE_URL}/api/findings/kev/active?${params.toString()}`, {
    headers: authHeaders(),
  });
  // API returns {count, findings: [...]}
  const data = await handleResponse<{ findings: Finding[] }>(res);
  return data.findings ?? [];
}

export async function getFilterOptions(): Promise<{
  finding_types: string[];
  sources: string[];
  owners: string[];
}> {
  const res = await fetch(`${BASE_URL}/api/findings/filter-options`, { headers: authHeaders() });
  return handleResponse(res);
}

// Metrics — each function normalizes the raw API shape to match the TypeScript types

export async function getKevExposure(): Promise<KevExposureMetric> {
  const res = await fetch(`${BASE_URL}/api/metrics/kev-exposure`, { headers: authHeaders() });
  // API: {total_open_findings, in_kev, kev_percentage, overdue_kev, by_severity, by_environment}
  const raw = await handleResponse<Record<string, unknown>>(res);
  return {
    total_findings:    (raw.total_open_findings as number) ?? 0,
    kev_findings:      (raw.in_kev as number) ?? 0,
    kev_percentage:    (raw.kev_percentage as number) ?? 0,
    overdue_count:     (raw.overdue_kev as number) ?? 0,
    due_within_7_days:  (raw.due_within_7_days as number) ?? 0,
    due_within_30_days: (raw.due_within_30_days as number) ?? 0,
    open_by_severity:  (raw.open_by_severity as Record<string, number>) ?? {},
  };
}

export async function getMttr(days = 90): Promise<MttrMetric[]> {
  const res = await fetch(`${BASE_URL}/api/metrics/mttr?days=${days}`, { headers: authHeaders() });
  // API: {window_days, mttr_by_severity: {critical: float, ...}, total_resolved}
  const raw = await handleResponse<Record<string, unknown>>(res);
  const bySev = (raw.mttr_by_severity as Record<string, number>) ?? {};
  return Object.entries(bySev).map(([severity, avg_days]) => ({
    severity,
    average_days: avg_days ?? 0,
    sample_size:  (raw.total_resolved as number) ?? 0,
  }));
}

export async function getSlaCompliance(): Promise<SlaComplianceMetric[]> {
  const res = await fetch(`${BASE_URL}/api/metrics/sla-compliance`, { headers: authHeaders() });
  // API: {sla_compliance: {low: {total, within_sla, overdue, compliance_rate}, ...}}
  const raw = await handleResponse<Record<string, unknown>>(res);
  const byS = (raw.sla_compliance as Record<string, Record<string, number>>) ?? {};
  return Object.entries(byS).map(([severity, d]) => ({
    severity,
    compliant:       d.within_sla ?? 0,
    overdue:         d.overdue ?? 0,
    total:           d.total ?? 0,
    compliance_rate: d.compliance_rate ?? 0,
  }));
}

export async function getFindingsByControl(): Promise<FindingsByControl[]> {
  const res = await fetch(`${BASE_URL}/api/metrics/findings-by-control`, { headers: authHeaders() });
  return handleResponse<FindingsByControl[]>(res);
}

export async function getScannerCoverage(): Promise<ScannerCoverage[]> {
  const res = await fetch(`${BASE_URL}/api/metrics/scanner-coverage`, { headers: authHeaders() });
  // API: {total_open_findings, by_scanner: {nessus: N, ...}, multi_scanner_findings, deduplication_savings}
  const raw = await handleResponse<Record<string, unknown>>(res);
  const byScanner = (raw.by_scanner as Record<string, number>) ?? {};
  const dedup = (raw.deduplication_savings as number) ?? 0;
  return Object.entries(byScanner).map(([scanner, finding_count]) => ({
    scanner,
    finding_count,
    unique_assets: 0,
    dedup_savings: dedup,
  }));
}

export async function getRiskTrend(days = 30): Promise<RiskTrendPoint[]> {
  const res = await fetch(`${BASE_URL}/api/metrics/risk-trend?days=${days}`, { headers: authHeaders() });
  // API: {days, trend: {"YYYY-MM-DD": {critical: N, high: N, medium: N, low: N}}}
  const raw = await handleResponse<Record<string, unknown>>(res);
  const trend = (raw.trend as Record<string, Record<string, number>>) ?? {};
  return Object.entries(trend)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, counts]) => ({
      date,
      critical:       counts.critical ?? 0,
      high:           counts.high ?? 0,
      medium:         counts.medium ?? 0,
      low:            counts.low ?? 0,
      total:          Object.values(counts).reduce((s, v) => s + v, 0),
      risk_score_avg: 0,
    }));
}

// Pipeline
export async function runPipeline(): Promise<{ task_id: string }> {
  const res = await fetch(`${BASE_URL}/api/pipeline/run`, {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
  });
  return handleResponse<{ task_id: string }>(res);
}

export async function runKevSync(): Promise<{ task_id: string }> {
  const res = await fetch(`${BASE_URL}/api/pipeline/kev-sync`, {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
  });
  return handleResponse<{ task_id: string }>(res);
}

export async function getPipelineTask(taskId: string): Promise<PipelineTask> {
  const res = await fetch(`${BASE_URL}/api/pipeline/task/${taskId}`, { headers: authHeaders() });
  return handleResponse<PipelineTask>(res);
}

// Connectors
export async function getConnectors(): Promise<ConnectorsResponse> {
  const res = await fetch(`${BASE_URL}/api/connectors/`, { headers: authHeaders() });
  return handleResponse<ConnectorsResponse>(res);
}

export async function testConnector(name: string): Promise<ConnectorTestResult> {
  const res = await fetch(`${BASE_URL}/api/connectors/${name}/test`, {
    method: 'POST',
    headers: authHeaders(),
  });
  return handleResponse<ConnectorTestResult>(res);
}

export async function saveConnectorConfig(
  name: string,
  values: Record<string, string>
): Promise<{ saved: boolean; connector: string; keys_written: string[] }> {
  const res = await fetch(`${BASE_URL}/api/connectors/${name}/config`, {
    method: 'PUT',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ values }),
  });
  return handleResponse(res);
}

export async function uploadConnectorFile(
  name: string,
  filename: string,
  file: File,
): Promise<{ uploaded: string; connector: string; size_bytes: number }> {
  const token = getToken();
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(
    `${BASE_URL}/api/connectors/${encodeURIComponent(name)}/upload?filename=${encodeURIComponent(filename)}`,
    { method: 'POST', headers: token ? { Authorization: `Bearer ${token}` } : {}, body: form },
  );
  return handleResponse(res);
}

export async function getConnectorUploads(
  name: string,
): Promise<{ connector: string; files: { name: string; size_bytes: number | null; uploaded_at: string | null }[] }> {
  const res = await fetch(`${BASE_URL}/api/connectors/${encodeURIComponent(name)}/uploads`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// Export
export async function downloadFindingsCsv(): Promise<void> {
  const token = getToken();
  const res = await fetch(`${BASE_URL}/api/export/tableau/findings.csv`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error('Export failed');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'warden-findings.csv';
  a.click();
  URL.revokeObjectURL(url);
}

export async function downloadKevSummaryCsv(): Promise<void> {
  const token = getToken();
  const res = await fetch(`${BASE_URL}/api/export/tableau/kev-summary.csv`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error('Export failed');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'warden-kev-summary.csv';
  a.click();
  URL.revokeObjectURL(url);
}

export async function getTableauConnectionInfo(): Promise<TableauConnectionInfo> {
  const res = await fetch(`${BASE_URL}/api/export/tableau/connection-info`, {
    headers: authHeaders(),
  });
  return handleResponse<TableauConnectionInfo>(res);
}
