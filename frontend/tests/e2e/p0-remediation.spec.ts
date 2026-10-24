import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {createPublicDatabaseFixture, removeSyntheticFixture, runtime} from './helpers/fixture';

test('P0: real scan, exact preview, apply, immutable backup, persisted verification and reload', async ({page}) => {
 const fixture=await createPublicDatabaseFixture();
 const errors:string[]=[]; page.on('pageerror',e=>errors.push(e.message));
 const unexpected:string[]=[];page.on('response',r=>{if(r.url().includes('/api/')&&r.status()>=400)unexpected.push(`${r.status()} ${r.url()}`)});
 try {
  await page.goto('/');await page.getByRole('button',{name:'Scan',exact:true}).click();await page.getByRole('button',{name:/Server-local path/}).click();await page.locator('#target').fill(fixture.relativePath);
  const scan=page.waitForResponse(r=>r.url().endsWith('/api/scan/iac')&&r.request().method()==='POST');await page.getByRole('button',{name:'Run scan',exact:true}).click();const payload=await(await scan).json();
  expect(payload.findings_count).toBe(1);expect(payload.findings[0].rule_id).toBe('terraform.public-database');
  const row=page.getByRole('button',{name:new RegExp(payload.findings[0].id)}).filter({hasText:'Publicly Accessible Database'}).first();
  await expect(row).toContainText('Critical');await row.click();
  const drawer=page.getByRole('dialog',{name:'Finding details'});await expect(drawer).toBeVisible();await drawer.getByRole('button',{name:'Review fix'}).click();
  const modal=page.getByRole('dialog',{name:'Review remediation'});await expect(modal.locator('.diff-view')).toContainText('publicly_accessible = false');
  const apply=page.waitForResponse(r=>r.url().endsWith('/api/scan/iac/remediate'));await expect(modal.getByRole('button',{name:'Apply deterministic fix'})).toBeDisabled();await modal.getByRole('checkbox').check();await modal.getByRole('button',{name:'Apply deterministic fix'}).click();const result=await(await apply).json();
  expect(result.verified).toBe(true);expect(result.findings_count).toBe(0);await expect(modal).toContainText('Verification completed');
  const state=await runtime();expect(await readFile(path.join(state.data_dir,'backups',result.backup_id+'.bak'),'utf8')).toContain('publicly_accessible = true');expect(await readFile(fixture.absolutePath,'utf8')).toContain('publicly_accessible = false');
  await modal.getByRole('button',{name:'Fix applied',exact:true}).click();await page.reload();await page.getByRole('button',{name:/^Findings/}).first().click();await expect(page.getByRole('button',{name:new RegExp(payload.findings[0].id)}).filter({hasText:'Publicly Accessible Database'}).first()).toContainText('Verified resolved');
  expect(errors).toEqual([]);expect(unexpected).toEqual([]);
 } finally {await removeSyntheticFixture(fixture)}
});
