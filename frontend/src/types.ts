export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' | 'Unknown';
export interface Finding {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  framework: string;
  frameworks: string[];
  file: string;
  file_id: string;
  workspace_id: string;
  source_digest: string;
  scan_id: string;
  resource: string;
  line: number;
  description: string;
  remediation: string;
  remediation_eligible: boolean;
  compliance_framework?: string;
  before: string;
  after: string;
  status: 'Open' | 'Fixed' | 'Accepted';
  detected: string;
}

export interface BackendFinding extends Omit<Finding, 'severity' | 'status' | 'framework' | 'before' | 'after'> {
  severity: string;
  status: string;
  filename: string;
}

export function normalizeSeverity(value: unknown): Severity {
  switch (String(value).toUpperCase()) {
    case 'CRITICAL': return 'Critical';
    case 'HIGH': return 'High';
    case 'MEDIUM': return 'Medium';
    case 'LOW': return 'Low';
    case 'INFORMATIONAL': case 'INFO': return 'Informational';
    default: return 'Unknown';
  }
}

export function normalizeFinding(item: BackendFinding): Finding {
  if (!item.id || !item.rule_id) throw new Error('Backend finding identity is unavailable; rescan legacy evidence.');
  return { ...item, file: item.file || item.filename, severity: normalizeSeverity(item.severity),
    framework: item.frameworks[0] ?? 'No mapping supplied', before: '', after: '',
    status: item.status.toUpperCase() === 'RESOLVED' ? 'Fixed' : item.status.toUpperCase() === 'ACCEPTED' ? 'Accepted' : 'Open' };
}

export type Page = 'overview' | 'scan' | 'findings' | 'compliance' | 'secrets' | 'history' | 'reports' | 'ai' | 'settings';
