import { copyFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(currentDirectory, '../../../..');
const fixtureSource = path.join(projectRoot, 'tests', 'fixtures', 'public-database.tf');
const fixtureDirectory = path.join(projectRoot, 'frontend', 'tests', 'e2e', '.tmp');

export type SyntheticFixture = {
  absolutePath: string;
  relativePath: string;
  backupPath: string;
};

export async function createPublicDatabaseFixture(): Promise<SyntheticFixture> {
  await mkdir(fixtureDirectory, { recursive: true });
  const filename = `public-database-${process.pid}-${Date.now()}.tf`;
  const absolutePath = path.join(fixtureDirectory, filename);
  await copyFile(fixtureSource, absolutePath);
  return {
    absolutePath,
    relativePath: path.posix.join('frontend', 'tests', 'e2e', '.tmp', filename),
    backupPath: `${absolutePath}.bak`,
  };
}

export async function removeSyntheticFixture(fixture: SyntheticFixture | undefined): Promise<void> {
  if (!fixture) return;
  await Promise.all([
    rm(fixture.absolutePath, { force: true }),
    rm(fixture.backupPath, { force: true }),
  ]);
}
