import axios from 'axios';

const apiClient = axios.create({
  baseURL: 'http://localhost:8000/api',
});

export const fetchDashboardStats = async () => {
  // In a real app, this would hit the API
  // return (await apiClient.get('/stats')).data;
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        critical: 2,
        high: 14,
        medium: 38,
        low: 102
      });
    }, 500);
  });
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
