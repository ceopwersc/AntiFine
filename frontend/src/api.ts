import axios from 'axios';

const apiClient = axios.create({
  baseURL: 'http://localhost:8000/api',
});

export const fetchDashboardStats = async () => {
  return (await apiClient.get('/dashboard')).data;
};

export const runScan = async (target: string, type: string) => {
  const isIaC = type === 'IaC Config Audit';
  const endpoint = isIaC ? '/scan/iac' : '/scan/ssrf';
  const body = isIaC ? { target_path: target } : { target_url: target };
  return (await apiClient.post(endpoint, body)).data;
};

export const generateReport = async (format: string) => {
  if (format === 'sarif') {
    const resp = await apiClient.get('/scan/iac/export/sarif');
    const blob = new Blob([JSON.stringify(resp.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    return { status: 'success', message: 'SARIF report generated', downloadUrl: url };
  }
  const resp = await apiClient.post('/report/generate');
  const data = resp.data;
  return {
    status: data.status,
    message: data.results?.markdown?.status === 'success'
      ? `Markdown report written to ${data.results.markdown.file} (${data.results.markdown.findings} findings)`
      : data.results?.markdown?.message || 'Report generated',
    results: data.results,
  };
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
