import axios from 'axios';

const apiClient = axios.create({
  baseURL: 'http://localhost:8000/api',
});

export const fetchDashboardStats = async () => {
  return (await apiClient.get('/dashboard')).data;
};

export const runScan = async (target: string, type: string) => {
  // return (await apiClient.post('/scan', { target, type })).data;
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        status: 'success',
        message: `Scan initialized for ${target} (${type})`,
        logs: `[INFO] Connecting to target ${target}...
[INFO] Applying audit rules for ${type}...
[WARN] Found exposed endpoint!
[INFO] Scan completed.`
      });
    }, 1500);
  });
};

export const generateReport = async (format: string) => {
  // return (await apiClient.post('/report', { format })).data;
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        status: 'success',
        message: `Report generated in ${format} format`,
        url: `/downloads/report.${format === 'markdown' ? 'md' : 'sarif'}`
      });
    }, 800);
  });
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
