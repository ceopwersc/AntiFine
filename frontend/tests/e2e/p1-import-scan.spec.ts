import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {createPublicDatabaseFixture, removeSyntheticFixture, runtime} from './helpers/fixture';

test('P1: nested multi-file import to verified remediation and evidence export', async ({page}) => {
 const fixture=await createPublicDatabaseFixture();const state=await runtime();
 try {
  await page.goto('/');await page.getByRole('button',{name:'Scan',exact:true}).click();
  // Browser directory uploads preserve webkitRelativePath. Use two genuine File objects.
  const content=await readFile(fixture.absolutePath,'utf8');
  await page.locator('input[type=file]').evaluate((input, source)=>{
   const transfer=new DataTransfer();for(const [name,body,relative] of [['main.tf',source,'audit/infra/main.tf'],['safe.tf','# evaluated empty Terraform','audit/other/safe.tf']]) {
    const file=new File([body],name,{type:'text/plain'});Object.defineProperty(file,'webkitRelativePath',{value:relative});transfer.items.add(file);
   }
   (input as HTMLInputElement).files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));
  },content);
  const upload=page.waitForResponse(r=>r.url().endsWith('/api/scan/upload'));const scan=page.waitForResponse(r=>r.url().endsWith('/api/scan/iac'));
  await page.getByRole('button',{name:'Run scan',exact:true}).click();const workspace=(await(await upload).json()).workspace_id;const findings=(await(await scan).json()).findings;expect(findings).toHaveLength(1);expect(findings[0].file).toBe('audit/infra/main.tf');
  await page.getByRole('button',{name:/Publicly Accessible Database/}).first().click();await page.getByRole('dialog',{name:'Finding details'}).getByRole('button',{name:'Review fix'}).click();const modal=page.getByRole('dialog',{name:'Review remediation'});await expect(modal.locator('.diff-view')).toContainText('publicly_accessible = false');
  const applying=page.waitForResponse(r=>r.url().endsWith('/api/scan/iac/remediate'));await modal.getByRole('button',{name:'Apply deterministic fix'}).click();const result=await(await applying).json();expect(result.verified).toBe(true);await expect(modal).toContainText('Verification completed');
  expect(await readFile(path.join(state.data_dir,'backups',result.backup_id+'.bak'),'utf8')).toBe(content);
  expect(await readFile(path.join(state.data_dir,'imports',workspace,'audit/other/safe.tf'),'utf8')).toBe('# evaluated empty Terraform');
  await modal.getByRole('button',{name:'Fix applied',exact:true}).click();await page.getByRole('button',{name:'Reports',exact:true}).click();const download=page.waitForEvent('download');await page.getByRole('button',{name:'Export SARIF',exact:true}).click();expect((await download).suggestedFilename()).toBe('antifine-results.sarif');
 } finally {await removeSyntheticFixture(fixture)}
});

test('P1: failed preview is visible and Apply is disabled', async ({page})=>{
 const fixture=await createPublicDatabaseFixture();
 try{
  await page.goto('/');await page.getByRole('button',{name:'Scan',exact:true}).click();await page.locator('input[type=file]').setInputFiles(fixture.absolutePath);const scan=page.waitForResponse(r=>r.url().endsWith('/api/scan/iac'));await page.getByRole('button',{name:'Run scan',exact:true}).click();await scan;
  await page.route('**/api/scan/iac/remediation/preview',route=>route.fulfill({status:422,json:{detail:'Synthetic preview rejection'}}));
  await page.getByRole('button',{name:/Publicly Accessible Database/}).first().click();await page.getByRole('dialog',{name:'Finding details'}).getByRole('button',{name:'Review fix'}).click();const modal=page.getByRole('dialog',{name:'Review remediation'});await expect(modal.getByRole('alert')).toBeVisible();await expect(modal.getByRole('button',{name:'Apply deterministic fix'})).toBeDisabled();
 }finally{await removeSyntheticFixture(fixture)}
});
