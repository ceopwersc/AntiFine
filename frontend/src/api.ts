import axios from 'axios';
import type { BackendFinding, ScanResponse, ScanRun, FileCoverage, BackupInspection, RestorePreview, RestoreResult, RestorationEvent } from './types';

const apiClient = axios.create({
  baseURL: '/api',
  withCredentials: true,
});

let session: Promise<unknown> | undefined;
apiClient.interceptors.request.use(async (config) => {
  session ??= axios.post('/api/session', {}, { withCredentials: true, headers: { 'X-AntiFine-Request': '1' } }).catch(error => { session = undefined; throw error; });
  await session;
  return config;
});
apiClient.interceptors.response.use(response => response, async error => {
  if (error.response?.status === 401 && !error.config._sessionRetried) {
    session = undefined; error.config._sessionRetried = true;
    return apiClient.request(error.config);
  }
  throw error;
});

export const fetchFindings = async (): Promise<{ findings: BackendFinding[] }> => (await apiClient.get('/findings')).data;

export interface ExplainableFinding {
  id?: string;
  rule_name: string;
  severity: string;
  filename: string;
  frameworks: string[];
  remediation: string;
  description: string;
}

export interface FindingExplanation {
  finding_id: string;
  model: string;
  provider: string;
  explanation: string;
  generated_locally: boolean;
}

export interface AIHealth {
  enabled: boolean;
  available: boolean;
  provider: string;
  model: string;
  error?: string;
}

export interface AskSource {
  title: string;
  source: string;
  rule_id?: string | null;
}

export interface AskResponse {
  answer: string;
  model: string;
  provider: string;
  sources: AskSource[];
}

export interface AskContext {
  finding_id: string;
  rule_id?: string;
  title: string;
  severity: string;
  technology: string;
  framework?: string;
  frameworks?: string[];
  file?: string;
  line?: number;
  status?: string;
  description?: string;
  remediation?: string;
  code_context?: string;
}

export interface AskMessage {
  role: 'user' | 'assistant';
  content: string;
}

export const fetchAIHealth = async (): Promise<AIHealth> => {
  return (await apiClient.get<AIHealth>('/ai/health')).data;
};

export const askAntiFine = async (question: string, context?: AskContext, messages: AskMessage[] = []): Promise<AskResponse> => {
  const response = await apiClient.post<AskResponse>('/ai/ask', {
    question,
    context: context ? {
      source: 'finding',
      finding: {
        finding_id: context.finding_id,
        rule_id: context.rule_id,
        title: context.title,
        severity: context.severity,
        technology: context.technology,
        file: context.file ?? context.finding_id,
        line: context.line,
        frameworks: context.frameworks ?? (context.framework ? [context.framework] : []),
        status: context.status,
        description: context.description,
        remediation: context.remediation,
      },
    } : undefined,
    messages: messages.slice(-10).map(({ role, content }) => ({ role, content: content.slice(0, 1200) })),
  });
  return response.data;
};

export interface RemediationExplanationRequest {
  preview_id?: string;
  finding: ExplainableFinding;
  before: string;
  after: string;
  diff: string;
  remediation: string;
  frameworks: string[];
}

export interface RemediationExplanation extends FindingExplanation {}

export const explainRemediation = async (
  request: RemediationExplanationRequest,
): Promise<RemediationExplanation> => {
  const response = await apiClient.post<RemediationExplanation>('/ai/remediation/explain', request);
  return response.data;
};

export interface DashboardStats {
  status: string;
  counts: Record<string, number>;
  compliance: Record<string, string>;
  total_findings: number;
  total_secrets: number;
}

export const fetchDashboardStats = async (): Promise<DashboardStats> => {
  return (await apiClient.get<DashboardStats>('/dashboard')).data;
};

export interface SecretFinding {
  rule_name: string;
  severity: string;
  status: string;
  filename: string;
  detected: string;
}

export const fetchSecretFindings = async (): Promise<{ status: string; findings: SecretFinding[] }> => {
  return (await apiClient.get<{ status: string; findings: SecretFinding[] }>('/findings/secrets')).data;
};

export const runScan = async (target: string, type: string): Promise<ScanResponse> => {
  const isIaC = type === 'IaC Config Audit';
  const endpoint = isIaC ? '/scan/iac' : '/scan/ssrf';
  const body = isIaC ? { target_path: target } : { target_url: target };
  return (await apiClient.post(endpoint, body)).data;
};

export const uploadScanWorkspace = async (files: File[]): Promise<{ target_path: string }> => {
  const formData = new FormData();
  const relativePaths = files.map(f => f.webkitRelativePath || f.name);
  files.forEach(f => formData.append('files', f));
  formData.append('relative_paths', JSON.stringify(relativePaths));
  return (await apiClient.post('/scan/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })).data;
};

export const fetchScanHistory = async () => {
  return (await apiClient.get<{scans: ScanRun[]}>('/scan/history')).data;
};
export const createDemoWorkspace = async (): Promise<{target_path: string}> => (await apiClient.post('/scan/demo')).data;
export const rescanFinding = async (findingId: string): Promise<ScanResponse> => (await apiClient.post(`/findings/${encodeURIComponent(findingId)}/rescan`)).data;

export const fetchBackups = async (): Promise<{backups: BackupInspection[]}> => (await apiClient.get('/backups')).data;
export const inspectBackup = async (backupId: string): Promise<BackupInspection> => (await apiClient.get(`/backups/${encodeURIComponent(backupId)}`)).data;
export const previewRestore = async (backupId: string): Promise<RestorePreview> => (await apiClient.post(`/backups/${encodeURIComponent(backupId)}/restore/preview`)).data;
export const restoreBackup = async (backupId: string, previewId: string): Promise<RestoreResult> =>
  (await apiClient.post(`/backups/${encodeURIComponent(backupId)}/restore`, {preview_id: previewId, confirmed: true})).data;
export const fetchRestorations = async (): Promise<{restorations: RestorationEvent[]}> => (await apiClient.get('/restorations')).data;

export interface FixResult {
  status: string;
  verified: boolean;
  target: string;
  backup_id: string;
  backup: string;
  action: string;
  findings_count: number;
  findings: BackendFinding[];
  scan_id: string;
  original_resolved: boolean;
  introduced_count: number;
  remediation_id: string;
  coverage: FileCoverage[];
}
export const remediateFinding = async (findingId: string, previewId: string): Promise<FixResult> =>
  (await apiClient.post('/scan/iac/remediate', { finding_id: findingId, preview_id: previewId, approved: true })).data;

export const previewRemediation = async (findingId: string): Promise<{
  preview_id: string; finding_id: string; source_digest: string; target: string; action: string; before: string; after: string;
  diff: string; start_line: number; end_line: number; changed_line: number; rule_id: string; resource_label: string; conditions: string[];
}> => (await apiClient.post('/scan/iac/remediation/preview', { finding_id: findingId })).data;

export const explainFinding = async (
  finding: ExplainableFinding,
  codeContext?: string,
): Promise<FindingExplanation> => {
  const response = await apiClient.post<FindingExplanation>('/ai/findings/explain', {
    finding,
    code_context: codeContext,
  });
  return response.data;
};

export const generateReport = async (format: string) => {
  if (format === 'sarif') {
    const resp = await apiClient.get('/scan/iac/export/sarif');
    const blob = new Blob([JSON.stringify(resp.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    return { status: 'success', message: 'SARIF report generated', downloadUrl: url, downloadName: 'antifine-results.sarif' };
  }
  const resp = await apiClient.post('/report/generate');
  const data = resp.data;
  if (data.results?.markdown?.status !== 'success') throw new Error('Report generation failed.');
  const content = await apiClient.get(`/reports/${encodeURIComponent(data.results.markdown.file)}`, {responseType: 'blob'});
  return {status: 'success', message: 'Markdown evidence report generated', downloadUrl: URL.createObjectURL(content.data), downloadName: 'antifine-evidence.md', results: data.results};
};

export const getWebhooks = async () => {
  return (await apiClient.get('/integrations/webhooks')).data;
};

export const saveWebhook = async (url: string, min_severity: string) => {
  return (await apiClient.post('/integrations/webhooks', { url, min_severity })).data;
};

export const testWebhook = async (url: string) => {
  return (await apiClient.post('/integrations/test', { url })).data;
};

export const fetchAnalyticsDashboard = async () => {
  return (await apiClient.get('/analytics/dashboard')).data;
};
