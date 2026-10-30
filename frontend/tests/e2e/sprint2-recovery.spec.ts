import {expect, test, type Page} from '@playwright/test';
import {readFile, unlink, writeFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import path from 'node:path';
import {createPublicDatabaseFixture, removeSyntheticFixture, runtime} from './helpers/fixture';

async function remediate(page: Page) {
  const fixture = await createPublicDatabaseFixture();
  const original = await readFile(fixture.absolutePath, 'utf8');
  await page.goto('/'); await page.getByRole('button', {name: 'Scan', exact: true}).click();
  await page.getByRole('button', {name: /Server-local path/}).click(); await page.locator('#target').fill(fixture.relativePath);
  const scanning = page.waitForResponse(response => response.url().endsWith('/api/scan/iac'));
  await page.getByRole('button', {name: 'Run scan', exact: true}).click();
  const finding = (await (await scanning).json()).findings[0];
  await page.getByRole('button', {name: new RegExp(finding.id)}).first().click();
  await page.getByRole('dialog', {name: 'Finding details'}).getByRole('button', {name: 'Review fix'}).click();
  const modal = page.getByRole('dialog', {name: 'Review remediation'});
  await expect(modal.getByLabel('Proposed diff')).toContainText('publicly_accessible = false');
  await modal.getByRole('checkbox').check();
  const applying = page.waitForResponse(response => response.url().endsWith('/api/scan/iac/remediate'));
  await modal.getByRole('button', {name: 'Apply deterministic fix'}).click();
  const applied = await (await applying).json(); expect(applied.verified).toBe(true);
  await modal.getByRole('button', {name: 'Fix applied', exact: true}).click();
  return {fixture, original, finding, applied};
}

async function inspect(page: Page, backupId: string) {
  await page.getByRole('button', {name: 'Recovery', exact: true}).click();
  await page.getByRole('button', {name: `Inspect backup ${backupId}`, exact: true}).click();
  const modal = page.getByRole('dialog', {name: 'Inspect remediation backup'});
  await expect(modal.getByRole('heading', {name: 'Inspect remediation backup'})).toBeVisible();
  await expect(modal.getByRole('button', {name: 'Restore original and rescan'})).toBeDisabled();
  return modal;
}

test('Sprint 2: inspect, explicitly confirm, restore immutable backup, reopen and export evidence', async ({page}, testInfo) => {
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  const unexpected: string[] = []; page.on('response', response => {if (response.url().includes('/api/') && response.status() >= 400) unexpected.push(`${response.status()} ${response.url()}`);});
  const context = await remediate(page);
  try {
    const state = await runtime();
    const backup = path.join(state.data_dir, 'backups', context.applied.backup_id + '.bak');
    const originalBytes = await readFile(backup);
    const fixed = await readFile(context.fixture.absolutePath);
    const modal = await inspect(page, context.applied.backup_id);
    await expect(modal).toContainText(context.finding.id); await expect(modal).toContainText(context.finding.file_id);
    await expect(modal.getByLabel('Restoration diff')).toContainText('+  publicly_accessible = true');
    await modal.getByRole('button', {name: 'Review restore', exact: true}).click();
    await expect(modal.getByRole('checkbox')).not.toBeChecked();
    await expect(modal.getByRole('button', {name: 'Restore original and rescan'})).toBeDisabled();
    for (const [width, height] of [[1280,800],[1440,900],[1920,1080],[1024,768],[768,1024]]) {
      await page.setViewportSize({width, height});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
    await page.setViewportSize({width:1280, height:800});
    await page.keyboard.press('Shift+Tab'); expect(await modal.evaluate(element => element.contains(document.activeElement))).toBe(true);
    await page.screenshot({path: testInfo.outputPath('restore-review.png')});
    await modal.getByRole('checkbox').check();
    const restoring = page.waitForResponse(response => response.url().endsWith(`/backups/${context.applied.backup_id}/restore`));
    await modal.getByRole('button', {name: 'Restore original and rescan'}).click();
    const response = await restoring; expect(response.status()).toBe(200); expect(response.request().postDataJSON().confirmed).toBe(true);
    const restored = await response.json(); expect(restored.verified).toBe(false); expect(restored.finding_reopened).toBe(true); expect(restored.findings_count).toBe(1);
    await expect(modal).toContainText('Source restored and rescanned'); await expect(modal).toContainText('not a verified security remediation');
    expect(await readFile(context.fixture.absolutePath)).toEqual(originalBytes); expect(await readFile(backup)).toEqual(originalBytes);
    expect(await readFile(path.join(state.data_dir, 'backups', restored.pre_restore_backup_id + '.bak'))).toEqual(fixed);
    await modal.getByRole('button', {name: 'Close recovery result'}).click();
    await page.reload(); await expect(page.getByText(restored.restoration_id, {exact: true}).first()).toBeVisible();
    const operationRows = page.getByRole('row').filter({hasText: restored.restoration_id});
    await expect(operationRows).toHaveCount(2);
    await expect(operationRows.filter({hasText: 'Needs review'})).toHaveCount(0);
    await expect(operationRows.filter({hasText: 'Restoration started'})).toHaveCount(1);
    await page.getByRole('button', {name: /^Findings/}).first().click();
    await expect(page.getByRole('button', {name: new RegExp(context.finding.id)})).toContainText('Reopened after restore');
    await page.getByRole('button', {name: 'Scan history', exact: true}).click();
    await page.getByLabel('Filter scan type').selectOption('Restoration rescan');
    await expect(page.locator('.history-table')).toContainText(restored.scan_id);
    await page.getByRole('button', {name: 'Reports', exact: true}).click();
    for (const button of ['Export SARIF', 'Generate report']) {
      const downloading = page.waitForEvent('download'); await page.getByRole('button', {name: button, exact: true}).click();
      const evidence = await readFile((await (await downloading).path())!, 'utf8');
      expect(evidence).toContain(restored.restoration_id); expect(evidence).toContain(restored.scan_id);
      if (button === 'Export SARIF') expect(JSON.parse(evidence).runs[0].properties.restoration_history[0].verified).toBe(false);
    }
    expect(errors).toEqual([]); expect(unexpected).toEqual([]);
  } finally {await removeSyntheticFixture(context.fixture);}
});

test('Sprint 2: external edit after restore review is rejected without overwriting source', async ({page}) => {
  const context = await remediate(page);
  try {
    const modal = await inspect(page, context.applied.backup_id);
    await modal.getByRole('button', {name: 'Review restore', exact: true}).click(); await modal.getByRole('checkbox').check();
    const changed = await readFile(context.fixture.absolutePath, 'utf8') + '# external source edit\n';
    await writeFile(context.fixture.absolutePath, changed);
    const restoring = page.waitForResponse(response => response.url().endsWith(`/backups/${context.applied.backup_id}/restore`));
    await modal.getByRole('button', {name: 'Restore original and rescan'}).click(); expect((await restoring).status()).toBe(409);
    await expect(modal.getByRole('alert')).toContainText('Restore rejected');
    await expect(modal).toContainText('Needs review'); await expect(modal.getByRole('button', {name: 'Restore original and rescan'})).toBeDisabled();
    expect(await readFile(context.fixture.absolutePath, 'utf8')).toBe(changed);
  } finally {await removeSyntheticFixture(context.fixture);}
});

for (const damage of ['missing', 'corrupt']) test(`Sprint 2: ${damage} backup stays unavailable for restoration`, async ({page}) => {
  const context = await remediate(page);
  try {
    const state = await runtime(); const backup = path.join(state.data_dir, 'backups', context.applied.backup_id + '.bak');
    const fixed = await readFile(context.fixture.absolutePath);
    if (damage === 'missing') await unlink(backup); else await writeFile(backup, 'synthetic corruption');
    const modal = await inspect(page, context.applied.backup_id);
    await expect(modal).toContainText('Needs review'); await expect(modal).toContainText(damage === 'missing' ? 'missing' : 'do not match');
    await expect(modal.getByRole('button', {name: 'Review restore', exact: true})).toHaveCount(0);
    expect(await readFile(context.fixture.absolutePath)).toEqual(fixed);
  } finally {await removeSyntheticFixture(context.fixture);}
});

test('Sprint 2: interrupted restoration remains Needs review after reload', async ({page}) => {
  const context = await remediate(page);
  try {
    const modal = await inspect(page, context.applied.backup_id);
    const reviewing = page.waitForResponse(response => response.url().endsWith('/restore/preview'));
    await modal.getByRole('button', {name: 'Review restore', exact: true}).click(); const token = (await (await reviewing).json()).preview_id;
    const state = await runtime(); const fixed = await readFile(context.fixture.absolutePath);
    // Inject a real service interruption against only the harness's synthetic private state.
    const code = `import os,sys\nfrom unittest.mock import patch\nos.environ.update(ANTIFINE_DB_PATH=sys.argv[1],ANTIFINE_WORKSPACE_ROOT=sys.argv[2],ANTIFINE_DATA_DIR=sys.argv[3],OLLAMA_ENABLED='false')\nfrom src.services import restoration_service as service\nfrom src.services.scan_repository import ScanRepository\nclass Interrupted(BaseException): pass\nwith patch.object(service,'atomic_write',side_effect=Interrupted):\n try: service.restore(ScanRepository(sys.argv[1]),sys.argv[4],sys.argv[5],confirmed=True)\n except Interrupted: pass\n`;
    await promisify(execFile)(process.env.ANTIFINE_TEST_PYTHON ?? 'python', ['-c', code, state.database, state.workspace, state.data_dir, context.applied.backup_id, token], {cwd: path.resolve('..')});
    await modal.getByRole('button', {name: 'Cancel', exact: true}).click(); await page.reload();
    const reopened = await inspect(page, context.applied.backup_id);
    await expect(reopened).toContainText('Needs review'); await expect(reopened).toContainText('unfinished operation');
    await expect(reopened.getByRole('button', {name: 'Restore original and rescan'})).toBeDisabled();
    expect(await readFile(context.fixture.absolutePath)).toEqual(fixed);
  } finally {await removeSyntheticFixture(context.fixture);}
});
