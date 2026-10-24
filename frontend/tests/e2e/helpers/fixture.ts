import { copyFile, mkdir, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(currentDirectory, '../../../..');
export type SyntheticFixture = {absolutePath: string; relativePath: string; backupPath: string};
export async function runtime() : Promise<{root:string;data_dir:string;workspace:string;database:string}> {
  return JSON.parse(await readFile(process.env.ANTIFINE_E2E_MANIFEST!, 'utf8'));
}
export async function createPublicDatabaseFixture(): Promise<SyntheticFixture> {
  const state = await runtime();
  const filename = `public-database-${process.pid}-${Date.now()}.tf`;
  const absolutePath = path.join(state.workspace, filename);
  await mkdir(state.workspace, {recursive:true});
  await copyFile(path.join(projectRoot,'tests/fixtures/public-database.tf'), absolutePath);
  return {absolutePath, relativePath:filename, backupPath:''};
}
export async function removeSyntheticFixture(fixture: SyntheticFixture | undefined) {
  if (fixture) await rm(fixture.absolutePath, {force:true});
}
