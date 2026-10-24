import { defineConfig, devices } from '@playwright/test';
import os from 'node:os';
import path from 'node:path';

process.env.ANTIFINE_E2E_MANIFEST ??= path.join(os.tmpdir(), `antifine-e2e-manifest-${process.pid}.json`);

export default defineConfig({
  testDir: './tests/e2e',
  outputDir: process.env.ANTIFINE_E2E_OUTPUT ?? path.join(os.tmpdir(), `antifine-playwright-${process.pid}`),
  timeout: 45_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:5173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: `${process.env.ANTIFINE_TEST_PYTHON ?? 'python'} -m tests.e2e_server`,
      cwd: '..',
      url: 'http://127.0.0.1:8000/api/health',
      timeout: 30_000,
      reuseExistingServer: false,
    },
    {
      command: 'npm run preview -- --host 127.0.0.1 --port 5173',
      cwd: '.',
      url: 'http://127.0.0.1:5173',
      timeout: 30_000,
      reuseExistingServer: false,
    },
  ],
});
