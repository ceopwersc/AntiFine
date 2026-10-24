export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' | 'Unknown';
export interface Verification {
  state: 'not_requested' | 'verification_pending' | 'verified_resolved' | 'resolved_with_findings' | 'verification_failed' | 'resolved_by_scan' | 'reopened';
  scan_id?: string;
  backup_id?: string;
  recorded_at?: string;
  remaining_count?: number;
  introduced_count?: number;
  rollback_completed?: boolean;
}
export interface FileCoverage {
  file_id: string; file: string; status: 'evaluated' | 'unsupported' | 'error';
  rules_evaluated: boolean; rule_families?: string[]; attempted_rule_families?: string[]; error?: string;
}
export interface ScanRun {
  id: string; target: string; status: 'completed' | 'partial' | 'error'; coverage: FileCoverage[];
  timestamp: string; time: string; type: string; findings_count: number; duration: string;
  enumeration_complete: boolean;
}
export interface ScanResponse {
  status: ScanRun['status']; target: string; scan_id: string; findings_count: number;
  findings: BackendFinding[]; coverage: FileCoverage[]; summary: string;
}
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
  resource_label: string;
  resource_key: string;
  family: string;
  evidence: string;
  verification: Verification;
  line: number;
  description: string;
  remediation: string;
  remediation_eligible: boolean;
  compliance_framework?: string;
  before: string;
  after: string;
  status: 'Open' | 'Resolved' | 'Accepted' | 'Unknown';
  detected: string;
}

export interface BackendFinding extends Omit<Finding, 'severity' | 'status' | 'framework' | 'before' | 'after' | 'verification'> {
  severity: string;
  status: string;
  filename: string;
  verification?: Verification;
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
    verification: item.verification ?? {state: 'not_requested'},
    resource_label: item.resource_label || item.resource || 'Location unavailable', family: item.family || 'unknown', evidence: item.evidence || 'Rescan to record evidence.',
    status: item.status.toUpperCase() === 'RESOLVED' ? 'Resolved' : item.status.toUpperCase() === 'ACCEPTED' ? 'Accepted' : item.status.toUpperCase() === 'OPEN' ? 'Open' : 'Unknown' };
}

export function findingState(finding: Finding): string {
  if (finding.status === 'Resolved') {
    if (finding.verification.state === 'verified_resolved') return 'Verified resolved';
    if (finding.verification.state === 'resolved_with_findings') return 'Resolved; findings remain';
    return 'Resolved by rescan';
  }
  if (finding.verification.state === 'verification_pending') return 'Verification pending';
  if (finding.verification.state === 'verification_failed') return 'Verification failed';
  if (finding.status !== 'Open') return finding.status;
  return finding.remediation_eligible ? 'Fix available' : 'Manual action required';
}

export type Page = 'overview' | 'scan' | 'findings' | 'compliance' | 'secrets' | 'history' | 'reports' | 'ai' | 'settings';
