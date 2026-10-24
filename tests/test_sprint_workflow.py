import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from src.services.settings import workspace_root, data_root


def database(name='selected', public=True):
    return f'resource "aws_db_instance" "{name}" {{\n publicly_accessible = {str(public).lower()}\n}}\n'


def scan(client, content, name='main.tf'):
    path = workspace_root() / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    response = client.post('/api/scan/iac', json={'target_path': name})
    assert response.status_code == 200, response.text
    return response.json()


def test_multiple_resources_have_unique_stable_identity_and_evidence(client):
    result = scan(client, 'resource "aws_s3_bucket" "alpha" {}\nresource "aws_s3_bucket" "beta" {}\n')
    assert len(result['findings']) == 4
    assert len({finding['id'] for finding in result['findings']}) == 4
    assert {finding['resource_label'] for finding in result['findings']} == {'aws_s3_bucket.alpha', 'aws_s3_bucket.beta'}
    assert all(finding['evidence'] and finding['description'] for finding in result['findings'])
    assert result['coverage'][0]['rule_families'] == ['terraform', 'secrets']
    report = client.post('/api/report/generate').json()['results']['markdown']['file']
    content = client.get('/api/reports/' + report).text
    assert 'aws_s3_bucket.alpha' in content and 'Observed evidence:' in content
    first = scan(client, database('alpha') + database('beta'))['findings']
    second = scan(client, database('beta') + database('alpha'))['findings']
    assert {f['resource_label']: f['id'] for f in first} == {f['resource_label']: f['id'] for f in second}
    persisted = client.get('/api/findings').json()['findings']
    target = next(f for f in persisted if f['id'] == second[1]['id'])
    assert target['resource'] == 'terraform/1'


def test_import_same_basename_and_unsupported_coverage(client):
    files = [('files', ('main.tf', database('one'))), ('files', ('main.tf', database('two'))), ('files', ('README.md', 'Scan-only fixture'))]
    upload = client.post('/api/scan/upload', files=files,
        data={'relative_paths': json.dumps(['dev/main.tf', 'prod/main.tf', 'README.md'])}).json()
    result = client.post('/api/scan/iac', json={'target_path': upload['target_path']}).json()
    assert result['status'] == 'partial'
    assert {finding['file'] for finding in result['findings']} == {'dev/main.tf', 'prod/main.tf'}
    assert len({finding['file_id'] for finding in result['findings']}) == 2
    unsupported = next(item for item in result['coverage'] if item['file'] == 'README.md')
    assert unsupported['status'] == 'unsupported' and unsupported['rule_families'] == []
    assert unsupported['rules_evaluated'] is False


def test_apply_needs_approval_and_persists_verified_evidence(client):
    finding = scan(client, database())['findings'][0]
    preview = client.post('/api/scan/iac/remediation/preview', json={'finding_id': finding['id']}).json()
    request = {'finding_id': finding['id'], 'preview_id': preview['preview_id']}
    assert client.post('/api/scan/iac/remediate', json=request).status_code == 422
    assert (workspace_root() / 'main.tf').read_text() == database()
    assert '- publicly_accessible = true' in preview['diff']
    assert '+ publicly_accessible = false' in preview['diff']
    assert preview['resource_label'] == 'aws_db_instance.selected'
    applied = client.post('/api/scan/iac/remediate', json=request | {'approved': True})
    assert applied.status_code == 200, applied.text
    result = applied.json()
    assert result['verified'] and result['original_resolved'] and result['introduced_count'] == 0
    assert (data_root() / 'backups' / (result['backup_id'] + '.bak')).read_text() == database()
    persisted = next(f for f in client.get('/api/findings').json()['findings'] if f['id'] == finding['id'])
    assert persisted['status'] == 'RESOLVED' and persisted['verification']['state'] == 'verified_resolved'
    assert persisted['verification']['scan_id'] == result['scan_id']
    events = client.get('/api/remediations').json()['remediations']
    assert events[0]['finding_id'] == finding['id'] and events[0]['approved'] is True
    report = client.post('/api/report/generate').json()['results']['markdown']['file']
    assert result['scan_id'] in client.get('/api/reports/' + report).text
    sarif = client.get('/api/scan/iac/export/sarif').json()
    assert sarif['runs'][0]['properties']['remediation_history'][0]['status'] == 'verified_resolved'


def test_cli_unsupported_requires_explicit_decision(tmp_path):
    (tmp_path / 'main.tf').write_text(database(public=False), encoding='utf-8')
    (tmp_path / 'README.md').write_text('not assessed', encoding='utf-8')
    command = [sys.executable, '-m', 'src.cli.gate', '--file', str(tmp_path)]
    assert subprocess.run(command, capture_output=True, timeout=20).returncode == 1
    decision = subprocess.run(command + ['--allow-unsupported'], capture_output=True, text=True, timeout=20)
    assert decision.returncode == 0 and 'unsupported files are not a security pass' in decision.stdout
    (tmp_path / 'main.tf').write_text('resource {', encoding='utf-8')
    assert subprocess.run(command + ['--allow-unsupported'], capture_output=True, timeout=20).returncode == 1
    (tmp_path / 'main.tf').unlink()
    assert subprocess.run(command + ['--allow-unsupported'], capture_output=True, timeout=20).returncode == 1


@pytest.mark.parametrize('approval', [False, 'true', 1, None])
def test_only_explicit_boolean_approval_authorizes_source_write(client, approval):
    finding = scan(client, database())['findings'][0]
    preview = client.post('/api/scan/iac/remediation/preview', json={'finding_id': finding['id']}).json()
    response = client.post('/api/scan/iac/remediate', json={
        'finding_id': finding['id'], 'preview_id': preview['preview_id'], 'approved': approval})
    assert response.status_code == 422
    assert (workspace_root() / 'main.tf').read_text() == database()
    assert client.get('/api/remediations').json()['remediations'] == []


@pytest.mark.parametrize('failure', ['introduced', 'not_evaluated', 'exception'])
def test_failed_verification_rolls_back_and_records_failure(client, failure):
    from src.services import remediation_apply
    from src.models.finding import Finding
    finding = scan(client, database())['findings'][0]
    preview = client.post('/api/scan/iac/remediation/preview', json={'finding_id': finding['id']}).json()
    run = {'status': 'completed', 'id': 'synthetic-verification', 'coverage': [{'status': 'evaluated'}]}
    extra = [Finding('Synthetic new finding', 'HIGH', 'main.tf', rule_id='terraform.synthetic-new')]
    kwargs = {'return_value': (run, extra)}
    if failure == 'not_evaluated':
        kwargs = {'return_value': (run | {'status': 'partial', 'coverage': []}, [])}
    if failure == 'exception':
        kwargs = {'side_effect': ValueError('synthetic verification failure')}
    with patch.object(remediation_apply, 'scan_target', **kwargs):
        response = client.post('/api/scan/iac/remediate', json={
            'finding_id': finding['id'], 'preview_id': preview['preview_id'], 'approved': True})
    assert response.status_code == 409
    assert (workspace_root() / 'main.tf').read_text() == database()
    persisted = client.get('/api/findings').json()['findings'][0]
    assert persisted['status'] == 'OPEN'
    assert persisted['verification']['state'] == 'verification_failed'
    assert persisted['verification']['rollback_completed'] is True
    assert persisted['verification']['introduced_count'] == (1 if failure == 'introduced' else 0)
    assert (data_root() / 'backups' / (persisted['verification']['backup_id'] + '.bak')).read_text() == database()


def test_demo_is_private_exact_targeting_and_reload_is_persistent(client):
    from src.services.settings import PROJECT_ROOT
    from src.services.workspaces import resolve_workspace
    originals = {name: (PROJECT_ROOT / 'examples/terraform-workflow' / name).read_bytes()
        for name in ('dev/main.tf', 'prod/main.tf')}
    demo = client.post('/api/scan/demo').json()
    root = resolve_workspace(demo['workspace_id'])
    result = client.post('/api/scan/iac', json={'target_path': demo['target_path']}).json()
    assert result['status'] == 'completed' and len(result['coverage']) == 2
    selected = next(f for f in result['findings'] if f['file'] == 'dev/main.tf' and f['rule_id'] == 'terraform.public-database')
    response = client.post('/api/scan/iac/remediation/preview', json={'finding_id': selected['id']})
    assert response.status_code == 200, response.text
    preview = response.json()
    fixed = client.post('/api/scan/iac/remediate', json={'finding_id': selected['id'], 'preview_id': preview['preview_id'], 'approved': True}).json()
    assert fixed['verified']
    assert (root / 'prod/main.tf').read_bytes() == originals['prod/main.tf']
    assert 'publicly_accessible = false' in (root / 'dev/main.tf').read_text()
    assert all((PROJECT_ROOT / 'examples/terraform-workflow' / name).read_bytes() == original for name, original in originals.items())
    from src.services.scan_repository import ScanRepository
    from src.services.settings import database_path
    reloaded = ScanRepository(database_path()).findings()
    assert next(f for f in reloaded if f['id'] == selected['id'])['verification']['state'] == 'verified_resolved'
    assert any(f['status'] == 'OPEN' and f['file'] == 'prod/main.tf' for f in reloaded)


def test_v3_migration_preserves_run_evidence_and_adds_history(tmp_path):
    import sqlite3
    from src.services.scan_repository import ScanRepository
    from src.services.scanning import scan_target
    root = tmp_path / 'source'; root.mkdir()
    (root / 'main.tf').write_text(database(), encoding='utf-8')
    repo = ScanRepository(tmp_path / 'v3.db')
    run, findings = scan_target(root, root, 'local', repo, isolated=False)
    with sqlite3.connect(repo.path) as db:
        evidence = db.execute('SELECT evidence FROM scan_evidence').fetchall()
        # Recreate the exact additive migration shape from schema v3.
        db.execute('DROP TABLE remediation_runs')
        db.execute('ALTER TABLE scan_runs DROP COLUMN enumeration_complete')
        for column in ('family', 'resource_key', 'resource_label', 'evidence'):
            db.execute('ALTER TABLE scan_results DROP COLUMN ' + column)
        db.execute('PRAGMA user_version=3')
    assert repo.findings()[0]['id'] == findings[0].id
    assert repo.history()[0]['id'] == run['id']
    assert repo.history()[0]['enumeration_complete'] == 1
    assert repo.remediations() == []
    with sqlite3.connect(repo.path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 4
        assert db.execute('SELECT evidence FROM scan_evidence').fetchall() == evidence
