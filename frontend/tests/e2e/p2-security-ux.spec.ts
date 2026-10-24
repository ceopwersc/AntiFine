import {expect,test} from '@playwright/test';
import path from 'node:path';
import {runtime} from './helpers/fixture';

async function importDatabase(page: import('@playwright/test').Page, secret=false) {
  const source='resource "aws_db_instance" "ux_audit" {\n publicly_accessible = true\n}\n'+(secret?'locals {\n token = "ghp_'+'a'.repeat(36)+'"\n}\n':'');
  await page.getByRole('button',{name:'Scan',exact:true}).click();
  await page.getByLabel('Import files',{exact:true}).setInputFiles({name:'ux.tf',mimeType:'text/plain',buffer:Buffer.from(source)});
  const scan=page.waitForResponse(r=>r.url().endsWith('/api/scan/iac'));await page.getByRole('button',{name:'Run scan',exact:true}).click();
  return (await(await scan).json()).findings;
}

test('P2: navigation, keyboard focus, filters and all supported viewport sizes',async({page})=>{
  const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('/');
  for(const [button,title] of [['Scan','New security scan'],['Findings','Findings'],['Compliance','Compliance'],['Secrets','Secrets'],['Scan history','Scan history'],['Reports','Reports'],['Ask AntiFine','Ask AntiFine'],['Settings','Settings'],['Overview','Overview']]) {
    await page.getByRole('button',{name:new RegExp('^'+button+'(?: \\d+)?$')}).first().click();await expect(page.getByRole('heading',{name:title,exact:true})).toBeVisible();
  }
  const findings=await importDatabase(page);
  await page.getByLabel('Filter by file').selectOption(findings[0].file_id);
  const search=page.getByPlaceholder('Search rule IDs, files, paths, frameworks');await search.fill('absent-ux-finding');await expect(page.getByText('No findings match these filters')).toBeVisible();await search.fill('');
  await page.getByLabel('Filter by severity').selectOption('High');await expect(page.getByText('No findings match these filters')).toBeVisible();await page.getByLabel('Filter by severity').selectOption('Critical');
  await page.getByRole('button',{name:new RegExp(findings[0].id)}).first().click();const drawer=page.getByRole('dialog',{name:'Finding details'});await expect(drawer).toBeVisible();await page.keyboard.press('Shift+Tab');expect(await drawer.evaluate(el=>el.contains(document.activeElement))).toBe(true);await page.keyboard.press('Escape');await expect(drawer).toHaveCount(0);
  for(const [width,height] of [[1280,800],[1440,900],[1920,1080],[1024,768],[768,1024]]){
    await page.setViewportSize({width,height});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  }
  expect(errors).toEqual([]);
});

test('P2: uploaded source never becomes a static asset, even with its private ID',async({page})=>{
  await page.goto('/');const findings=await importDatabase(page,true);const id=findings[0].workspace_id;
  const state=await runtime();const token='ghp_'+'a'.repeat(36);
  for(const url of ['/tests/e2e/.tmp/'+id+'/ux.tf','/@fs/'+path.join(state.data_dir,'imports',id,'ux.tf').replaceAll('\\','/')]){
    const response=await page.request.get(url);expect(await response.text()).not.toContain(token);
  }
  await page.getByRole('button',{name:new RegExp(findings.find((f: {rule_id:string})=>f.rule_id==='terraform.public-database').id)}).first().click();await page.getByRole('dialog',{name:'Finding details'}).getByRole('button',{name:'Review fix'}).click();await expect(page.getByRole('dialog',{name:'Review remediation'}).locator('.diff-view')).toContainText('publicly_accessible = false');expect(await page.locator('body').innerText()).not.toContain(token);
});

test('P2: history filters work and report failures do not claim a queue',async({page})=>{
  await page.goto('/');await importDatabase(page);
  await page.getByRole('button',{name:'Scan history',exact:true}).click();const selector=page.getByLabel('Filter scan type');await expect(page.locator('.history-table > tbody > tr').first()).toBeVisible();await selector.selectOption('SSRF Web Audit');await expect(page.locator('.history-table > tbody > tr')).toHaveCount(0);await selector.selectOption('IaC Config Audit');await expect(page.locator('.history-table > tbody > tr').first()).toBeVisible();
  await page.getByRole('button',{name:'Reports',exact:true}).click();await page.route('**/api/report/generate',r=>r.fulfill({status:503,json:{detail:'Synthetic failure'}}));await page.getByRole('button',{name:'Generate report',exact:true}).click();await expect(page.getByText('Report generation failed. Reconnect the local API and retry.')).toBeVisible();await expect(page.getByText(/Report queued/)).toHaveCount(0);
});
