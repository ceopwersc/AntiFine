import {expect, test, type Page} from '@playwright/test';
import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {createPublicDatabaseFixture, removeSyntheticFixture, runtime} from './helpers/fixture';

async function review(page: Page, id: string) {
  await page.getByRole('button', {name: new RegExp(id)}).first().click();
  await page.getByRole('dialog', {name: 'Finding details'}).getByRole('button', {name: 'Review fix'}).click();
  const modal = page.getByRole('dialog', {name: 'Review remediation'});
  await expect(modal.getByLabel('Proposed diff')).toContainText('publicly_accessible = false');
  await expect(modal.getByRole('button', {name: 'Apply deterministic fix'})).toBeDisabled();
  await page.keyboard.press('Shift+Tab');
  expect(await modal.evaluate(element => element.contains(document.activeElement))).toBe(true);
  await page.keyboard.press('Tab');
  expect(await modal.evaluate(element => element.contains(document.activeElement))).toBe(true);
  return modal;
}

test('Sprint 1: safe demo, exact approval, reload and downloadable evidence', async ({page}, testInfo) => {
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  const unexpected: string[] = []; page.on('response', response => {if (response.url().includes('/api/') && response.status() >= 400) unexpected.push(`${response.status()} ${response.url()}`);});
  await page.goto('/'); await page.getByRole('button', {name: 'Scan', exact: true}).click();
  const demo = page.waitForResponse(response => response.url().endsWith('/api/scan/demo'));
  const scanning = page.waitForResponse(response => response.url().endsWith('/api/scan/iac'));
  await page.getByRole('button', {name: 'Try safe Terraform demo'}).click();
  const workspace = (await (await demo).json()).workspace_id;
  const scan = await (await scanning).json();
  expect(scan.status).toBe('completed'); expect(scan.coverage).toHaveLength(2);
  const selected = scan.findings.find((finding: {file: string; rule_id: string}) => finding.file === 'dev/main.tf' && finding.rule_id === 'terraform.public-database');
  await page.getByLabel('Filter by file').selectOption(selected.file_id);
  await page.getByLabel('Filter by rule family').selectOption('terraform');
  const modal = await review(page, selected.id);
  await expect(modal).toContainText('aws_db_instance.customer_demo');
  await page.screenshot({path: testInfo.outputPath('approval-preview.png')});
  await modal.getByRole('checkbox').check();
  const applying = page.waitForResponse(response => response.url().endsWith('/api/scan/iac/remediate'));
  await modal.getByRole('button', {name: 'Apply deterministic fix'}).click();
  const applied = await (await applying).json();
  expect(applied.original_resolved).toBe(true); expect(applied.verified).toBe(true);
  await modal.getByRole('button', {name: 'Fix applied', exact: true}).click();
  const state = await runtime();
  expect(await readFile(path.join(state.data_dir, 'imports', workspace, 'prod/main.tf'), 'utf8')).toContain('publicly_accessible = true');
  await page.reload(); await page.getByRole('button', {name: /^Findings/}).first().click();
  await expect(page.getByRole('button', {name: new RegExp(selected.id)})).toContainText('Verified resolved');
  await page.getByLabel('Filter by status').selectOption('Resolved');
  await expect(page.getByRole('button', {name: new RegExp(selected.id)})).toBeVisible();
  await page.screenshot({path: testInfo.outputPath('persisted-findings.png')});
  await page.getByRole('button', {name: 'Reports', exact: true}).click();
  for (const [button, extension] of [['Export SARIF', '.sarif'], ['Generate report', '.md']]) {
    const downloading = page.waitForEvent('download');
    await page.getByRole('button', {name: button, exact: true}).click();
    const download = await downloading; expect(download.suggestedFilename()).toContain(extension);
    const evidence = await readFile((await download.path())!, 'utf8');
    expect(evidence).toContain(applied.scan_id); expect(evidence).toContain(applied.backup_id);
    expect(evidence).toContain('verified_resolved');
  }
  expect(errors).toEqual([]); expect(unexpected).toEqual([]);
});

test('Sprint 1: identical basenames and sizes preserve exact file and resource targeting', async ({page}) => {
  const source = 'resource "aws_db_instance" "first" {\n publicly_accessible = true\n}\nresource "aws_db_instance" "second" {\n publicly_accessible = true\n}\n';
  await page.goto('/'); await page.getByRole('button', {name: 'Scan', exact: true}).click();
  await page.getByLabel('Import files', {exact: true}).evaluate((input, body) => {
    const transfer = new DataTransfer();
    for (const location of ['dev/main.tf', 'prod/main.tf']) {
      const file = new File([body], 'main.tf', {type: 'text/plain'});
      Object.defineProperty(file, 'webkitRelativePath', {value: location}); transfer.items.add(file);
    }
    (input as HTMLInputElement).files = transfer.files; input.dispatchEvent(new Event('change', {bubbles: true}));
  }, source);
  await expect(page.locator('.queue-row')).toHaveCount(2);
  const uploading = page.waitForResponse(response => response.url().endsWith('/api/scan/upload'));
  const scanning = page.waitForResponse(response => response.url().endsWith('/api/scan/iac'));
  await page.getByRole('button', {name: 'Run scan', exact: true}).click();
  const workspace = (await (await uploading).json()).workspace_id;
  const scan = await (await scanning).json(); expect(scan.findings).toHaveLength(4);
  const selected = scan.findings.find((finding: {file: string; resource_label: string}) => finding.file === 'dev/main.tf' && finding.resource_label === 'aws_db_instance.second');
  const modal = await review(page, selected.id); await modal.getByRole('checkbox').check();
  const applying = page.waitForResponse(response => response.url().endsWith('/api/scan/iac/remediate'));
  await modal.getByRole('button', {name: 'Apply deterministic fix'}).click();
  const applied = await (await applying).json(); expect(applied.verified).toBe(false); expect(applied.original_resolved).toBe(true); expect(applied.introduced_count).toBe(0);
  await expect(modal).toContainText('Original finding resolved; findings remain');
  const state = await runtime();
  expect(await readFile(path.join(state.data_dir, 'imports', workspace, 'prod/main.tf'), 'utf8')).toBe(source);
  expect(await readFile(path.join(state.data_dir, 'imports', workspace, 'dev/main.tf'), 'utf8')).toBe(source.replace('"second" {\n publicly_accessible = true', '"second" {\n publicly_accessible = false'));
  expect(await readFile(path.join(state.data_dir, 'backups', applied.backup_id + '.bak'), 'utf8')).toBe(source);
  await modal.getByRole('button', {name: 'Close applied change'}).click(); await page.reload();
  await page.getByRole('button', {name: /^Findings/}).first().click();
  await expect(page.getByRole('button', {name: new RegExp(selected.id)})).toContainText('Resolved; findings remain');
});

test('Sprint 1: malformed and unsupported project input exposes partial coverage', async ({page}) => {
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto('/'); await page.getByRole('button', {name: 'Scan', exact: true}).click();
  await page.getByLabel('Import files', {exact: true}).setInputFiles([
    {name: 'safe.tf', mimeType: 'text/plain', buffer: Buffer.from('# no deployable resources')},
    {name: 'broken.tf', mimeType: 'text/plain', buffer: Buffer.from('resource {')},
    {name: 'unsupported.txt', mimeType: 'text/plain', buffer: Buffer.from('not evaluated')},
  ]);
  const scanning = page.waitForResponse(response => response.url().endsWith('/api/scan/iac'));
  await page.getByRole('button', {name: 'Run scan', exact: true}).click(); const scan = await (await scanning).json();
  expect(scan.status).toBe('partial'); expect(scan.coverage.map((file: {status: string}) => file.status).sort()).toEqual(['error', 'evaluated', 'unsupported']);
  await expect(page.locator('.coverage-panel').first()).toContainText('partial');
  await expect(page.locator('.coverage-panel').first()).toContainText('Not evaluated');
  await expect(page.locator('.coverage-panel').first()).toContainText('unsupported.txt');
  await page.reload(); await page.getByRole('button', {name: /^Findings/}).first().click();
  await expect(page.locator('.coverage-panel').first()).toContainText(scan.scan_id);
  expect(errors).toEqual([]);
});

test('Sprint 1: stale source rejects apply and offers a real rescan', async ({page}) => {
  const fixture = await createPublicDatabaseFixture();
  try {
    await page.goto('/'); await page.getByRole('button', {name: 'Scan', exact: true}).click();
    await page.getByRole('button', {name: /Server-local path/}).click(); await page.locator('#target').fill(fixture.relativePath);
    const scanning = page.waitForResponse(response => response.url().endsWith('/api/scan/iac'));
    await page.getByRole('button', {name: 'Run scan', exact: true}).click(); const scan = await (await scanning).json();
    const modal = await review(page, scan.findings[0].id);
    const changed = await readFile(fixture.absolutePath, 'utf8') + '# concurrent developer edit\n';
    await writeFile(fixture.absolutePath, changed); await modal.getByRole('checkbox').check();
    const applying = page.waitForResponse(response => response.url().endsWith('/api/scan/iac/remediate'));
    await modal.getByRole('button', {name: 'Apply deterministic fix'}).click(); expect((await applying).status()).toBe(409);
    await expect(modal.getByRole('alert')).toContainText('Apply rejected');
    await expect(modal.getByRole('button', {name: 'Apply deterministic fix'})).toBeDisabled();
    expect(await readFile(fixture.absolutePath, 'utf8')).toBe(changed);
    const rescanning = page.waitForResponse(response => response.url().endsWith('/rescan'));
    await modal.getByRole('button', {name: 'Rescan source and return to findings'}).click();
    expect((await rescanning).status()).toBe(200); await expect(modal).toHaveCount(0);
    const fresh = await review(page, scan.findings[0].id); await expect(fresh.getByRole('checkbox')).not.toBeChecked();
  } finally {await removeSyntheticFixture(fixture);}
});
