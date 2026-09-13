import { expect, test } from '@playwright/test';
import { readFile, stat } from 'node:fs/promises';
import { createPublicDatabaseFixture, removeSyntheticFixture, type SyntheticFixture } from './helpers/fixture';

let fixture: SyntheticFixture | undefined;

test.beforeEach(async () => {
  fixture = await createPublicDatabaseFixture();
});

test.afterEach(async () => {
  await removeSyntheticFixture(fixture);
  fixture = undefined;
});

test('P0: scans, reviews, remediates, backs up, and verifies a synthetic public database', async ({ page }) => {
  const consoleErrors: string[] = [];
  const failedApiRequests: string[] = [];
  const apiResponses: Array<{ method: string; path: string; status: number; body: unknown }> = [];

  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', (error) => consoleErrors.push(error.message));
  page.on('response', async (response) => {
    const url = new URL(response.url());
    if (url.port !== '8000' || !url.pathname.startsWith('/api/')) return;
    if (response.status() >= 400) failedApiRequests.push(`${response.request().method()} ${url.pathname} ${response.status()}`);
    if (url.pathname === '/api/scan/iac' || url.pathname === '/api/scan/iac/remediate') {
      apiResponses.push({ method: response.request().method(), path: url.pathname, status: response.status(), body: await response.json() });
    }
  });

  await page.goto('/');
  await page.getByRole('button', { name: 'Scan', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'New security scan' })).toBeVisible();
  await page.locator('input[type="file"]').setInputFiles(fixture!.absolutePath);
  await expect(page.getByText('public-database-', { exact: false })).toBeVisible();
  await page.locator('#target').fill(fixture!.relativePath);

  const firstScan = page.waitForResponse((response) => response.url().endsWith('/api/scan/iac') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Run scan' }).click();
  const firstScanResponse = await firstScan;
  expect(firstScanResponse.status()).toBe(200);
  const firstScanPayload = await firstScanResponse.json();
  expect(firstScanPayload.findings_count).toBe(1);
  expect(firstScanPayload.findings[0]).toMatchObject({ severity: 'CRITICAL' });
  expect(firstScanPayload.findings[0].rule_name).toContain('Publicly Accessible Database');

  const findingRow = page.getByRole('button', { name: /Publicly Accessible Database/ });
  await expect(findingRow).toContainText('Critical');
  await findingRow.click();
  const drawer = page.getByRole('dialog', { name: 'Finding details' });
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText(firstScanPayload.findings[0].frameworks[0]);

  await drawer.getByRole('button', { name: 'Review fix' }).click();
  const modal = page.getByRole('dialog', { name: 'Review remediation' });
  await expect(modal).toBeVisible();
  await expect(modal.locator('.diff-view')).toContainText('publicly_accessible = true');
  await expect(modal.locator('.diff-view')).toContainText('publicly_accessible = false');

  const remediation = page.waitForResponse((response) => response.url().endsWith('/api/scan/iac/remediate') && response.request().method() === 'POST');
  const rescan = page.waitForResponse((response) => response.url().endsWith('/api/scan/iac') && response.request().method() === 'POST');
  await modal.getByRole('button', { name: 'Apply deterministic fix' }).click();
  const remediationResponse = await remediation;
  expect(remediationResponse.status()).toBe(200);
  const remediationPayload = await remediationResponse.json();
  expect(remediationPayload.findings_count).toBe(0);
  await expect(stat(fixture!.backupPath)).resolves.toBeDefined();

  const rescanResponse = await rescan;
  expect(rescanResponse.status()).toBe(200);
  expect((await rescanResponse.json()).findings_count).toBe(0);
  await expect(modal).toContainText('Verification completed');
  await modal.getByRole('button', { name: 'Fix applied' }).click();
  await expect(page.getByRole('button', { name: /Publicly Accessible Database/ })).toContainText('Fixed');
  await expect(readFile(fixture!.absolutePath, 'utf8')).resolves.toContain('publicly_accessible = false');

  expect(apiResponses.map((response) => `${response.method} ${response.path} ${response.status}`)).toEqual([
    'POST /api/scan/iac 200',
    'POST /api/scan/iac/remediate 200',
    'POST /api/scan/iac 200',
  ]);
  expect(failedApiRequests).toEqual([]);
  expect(consoleErrors).toEqual([]);
});
