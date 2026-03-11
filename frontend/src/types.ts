export interface Finding {
  id: string;
  cve_id: string | null;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  risk_score: number;
  cvss_score: number | null;
  epss_score: number | null;
  in_kev: boolean;
  kev_due_date: string | null;
  kev_ransomware_use: string | null;
  asset_name: string;
  asset_ip: string | null;
  asset_environment: 'production' | 'staging' | 'development' | 'unknown';
  asset_criticality: number;
  sources: string[];
  finding_type: 'network' | 'application' | 'code' | 'configuration' | 'dependency';
  status: 'open' | 'in_progress' | 'resolved' | 'accepted_risk';
  owner: string | null;
  ticket_id: string | null;
  ticket_url: string | null;
  sla_due_date: string | null;
  nist_csf_controls: string[];
  cis_controls: string[];
  remediation_action: string | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
}

export interface KevExposureMetric {
  total_findings: number;
  kev_findings: number;
  kev_percentage: number;
  overdue_count: number;
  due_within_7_days: number;
  due_within_30_days: number;
  open_by_severity: Record<string, number>;
}

export interface MttrMetric {
  severity: string;
  average_days: number;
  sample_size: number;
}

export interface SlaComplianceMetric {
  severity: string;
  compliant: number;
  overdue: number;
  total: number;
  compliance_rate: number;
}

export interface FindingsByControl {
  control: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScannerCoverage {
  scanner: string;
  finding_count: number;
  unique_assets: number;
  dedup_savings: number;
}

export interface RiskTrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  risk_score_avg: number;
}

export interface PipelineTask {
  task_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string | null;
  completed_at: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
}

export interface TableauConnectionInfo {
  base_url: string;
  endpoints: {
    findings: string;
    kev_summary: string;
  };
  auth_header: string;
  refresh_schedule: string;
}

export interface User {
  username: string;
  role: string;
}

export interface AuthToken {
  access_token: string;
  token_type: string;
}

export interface ConnectorField {
  key: string;
  label: string;
  type: 'text' | 'password' | 'url' | 'boolean';
  placeholder: string;
  required: boolean;
  current_value: string;
}

export interface ConnectorStatus {
  name: string;
  label: string;
  category: 'scanner' | 'appsec' | 'feed' | 'integration';
  description: string;
  configured: boolean;
  testable: boolean;
  configurable: boolean;
  finding_count: number;
  fields: ConnectorField[];
  input_files?: string[];
  docs_url: string;
}

export interface ConnectorsResponse {
  connectors: ConnectorStatus[];
  summary: {
    total: number;
    configured: number;
    scanners_configured: number;
  };
}

export interface ConnectorTestResult {
  connector: string;
  success: boolean;
  message: string;
}

export interface FindingsFilters {
  status?: string;
  severity?: string;
  in_kev?: boolean;
  environment?: string;
  source?: string;
  finding_type?: string;
  nist_control?: string;
  cis_control?: string;
  min_risk_score?: number;
  max_risk_score?: number;
  cve_id?: string;
  asset_name?: string;
  sla_status?: string;
  owner?: string;
  limit: number;
  offset: number;
}
