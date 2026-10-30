import hashlib
import json
import sqlite3
from unittest.mock import patch

import pytest

from src.services.scan_repository import ScanRepository
from src.services.settings import data_root, database_path, workspace_root

TF = 'resource "aws_db_instance" "recovery" {\n publicly_accessible = true\n}\n'


def remediated(client, name='main.tf', secret=False, raw_source=None):
    source = TF + ('locals {\n token = "ghp_' + 'a' * 36 + '"\n}\n' if secret else '')
    path = workspace_root() / name
    if raw_source is None:
        path.write_text(source, encoding='utf-8')
    else:
        path.write_bytes(raw_source)
    findings = client.post('/api/scan/iac', json={'target_path': name}).json()['findings']
    finding = next(f for f in findings if f['rule_id'] == 'terraform.public-database')
    preview = client.post('/api/scan/iac/remediation/preview', json={'finding_id': finding['id']}).json()
    response = client.post('/api/scan/iac/remediate', json={
        'finding_id': finding['id'], 'preview_id': preview['preview_id'], 'approved': True})
    assert response.status_code == 200, response.text
    return path, source, finding, response.json()['backup_id']


def preview(client, backup_id):
    response = client.post(f'/api/backups/{backup_id}/restore/preview')
    assert response.status_code == 200, response.text
    return response.json()['preview_id']


def restore(client, backup_id, preview_id):
    return client.post(f'/api/backups/{backup_id}/restore', json={'preview_id': preview_id, 'confirmed': True})


def rewrite_events(function):
    with sqlite3.connect(database_path()) as db:
        for row_id, details in db.execute('SELECT id,details FROM remediation_runs').fetchall():
            event = json.loads(details)
            function(event)
            db.execute('UPDATE remediation_runs SET details=? WHERE id=?', (json.dumps(event), row_id))


def test_authorized_restore_reopens_finding_and_persists_independent_history(client):
    path, original, finding, backup_id = remediated(client)
    fixed = path.read_bytes()
    backup = data_root() / 'backups' / (backup_id + '.bak')
    before_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
    inspection = client.get(f'/api/backups/{backup_id}').json()
    assert inspection['can_restore'] and inspection['backup_status'] == 'available'
    assert inspection['finding_id'] == finding['id'] and inspection['file_id'] == finding['file_id']
    assert inspection['remediation_id'] and inspection['remediated_at']
    assert '- publicly_accessible = false' in inspection['changes']['diff']
    assert '+ publicly_accessible = true' in inspection['changes']['diff']
    response = restore(client, backup_id, preview(client, backup_id))
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['status'] == 'restored' and result['verified'] is False
    assert result['finding_reopened'] and result['findings_count'] == 1
    assert path.read_text() == original
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == before_hash
    assert (data_root() / 'backups' / (result['pre_restore_backup_id'] + '.bak')).read_bytes() == fixed
    restarted = ScanRepository(database_path())
    persisted = next(f for f in restarted.findings() if f['id'] == finding['id'])
    assert persisted['status'] == 'OPEN' and persisted['verification']['state'] == 'reopened'
    assert persisted['restoration']['status'] == 'restored' and persisted['recovery_state'] == 'restored'
    assert restarted.history()[0]['type'] == 'Restoration rescan'
    assert restarted.history()[0]['id'] == result['scan_id']
    assert [e['status'] for e in restarted.restorations(backup_id)] == ['restored', 'restore_pending']
    inspected_again = client.get(f'/api/backups/{backup_id}').json()
    assert inspected_again['state'] == 'restored' and not inspected_again['can_restore']
    assert restore(client, backup_id, preview_id='0' * 64).status_code == 409


@pytest.mark.parametrize('confirmation', [False, 'true', 1, None])
def test_restore_requires_strict_operator_confirmation(client, confirmation):
    path, _, _, backup_id = remediated(client)
    fixed = path.read_bytes()
    response = client.post(f'/api/backups/{backup_id}/restore', json={'preview_id': preview(client, backup_id), 'confirmed': confirmation})
    assert response.status_code == 422 and path.read_bytes() == fixed
    assert not ScanRepository(database_path()).restorations()


def test_restore_api_authentication_and_forged_reference(client):
    path, _, _, backup_id = remediated(client)
    fixed = path.read_bytes()
    for endpoint in ('/api/backups', f'/api/backups/{backup_id}', '/api/restorations'):
        assert client.get(endpoint, headers={'X-AntiFine-Token': ''}).status_code == 401
    token = preview(client, backup_id)
    assert client.post(f'/api/backups/{backup_id}/restore', headers={'X-AntiFine-Token': ''}, json={'preview_id': token, 'confirmed': True}).status_code == 401
    assert client.get('/api/backups/' + 'f' * 64).status_code == 404
    assert restore(client, 'f' * 64, token).status_code == 404
    assert client.get('/api/backups/not-a-backup').status_code == 404
    assert path.read_bytes() == fixed


@pytest.mark.parametrize('when', ['before_preview', 'after_preview'])
def test_external_changes_are_never_overwritten(client, when):
    path, _, _, backup_id = remediated(client)
    token = preview(client, backup_id) if when == 'after_preview' else '0' * 64
    external = path.read_text() + '# outside edit\n'
    path.write_text(external, encoding='utf-8')
    assert not client.get(f'/api/backups/{backup_id}').json()['can_restore']
    assert client.post(f'/api/backups/{backup_id}/restore/preview').status_code == 409
    assert restore(client, backup_id, token).status_code == 409
    assert path.read_text() == external


@pytest.mark.parametrize('damage', ['missing', 'corrupt'])
def test_backup_missing_or_corrupted_after_preview(client, damage):
    path, _, _, backup_id = remediated(client)
    fixed = path.read_bytes()
    token = preview(client, backup_id)
    backup = data_root() / 'backups' / (backup_id + '.bak')
    if damage == 'missing':
        backup.unlink()
    else:
        backup.write_bytes(b'corrupted synthetic backup')
    inspection = client.get(f'/api/backups/{backup_id}').json()
    assert inspection['backup_status'] == damage and not inspection['can_restore']
    assert restore(client, backup_id, token).status_code == 409 and path.read_bytes() == fixed


def test_preview_cannot_authorize_another_backup_or_caller_path(client):
    first, _, _, one = remediated(client)
    second, _, _, two = remediated(client, 'other.tf')
    token = preview(client, one)
    assert restore(client, two, token).status_code == 409
    assert client.post(f'/api/backups/{one}/restore', json={
        'preview_id': token, 'confirmed': True, 'target_path': '../outside.tf', 'workspace_id': 'forged'}).status_code == 422
    assert 'false' in first.read_text() and 'false' in second.read_text()


def test_legacy_ownership_and_changed_workspace_fail_closed(client, tmp_path, monkeypatch):
    path, _, _, backup_id = remediated(client)
    other = tmp_path / 'other'; other.mkdir()
    (other / path.name).write_bytes(path.read_bytes())
    monkeypatch.setenv('ANTIFINE_WORKSPACE_ROOT', str(other))
    inspection = client.get(f'/api/backups/{backup_id}').json()
    assert not inspection['can_restore'] and 'differs' in inspection['reason']
    monkeypatch.setenv('ANTIFINE_WORKSPACE_ROOT', str(path.parent))
    rewrite_events(lambda event: (event.pop('root_id', None), event.pop('workspace_id', None)))
    inspection = client.get(f'/api/backups/{backup_id}').json()
    assert inspection['backup_available'] and not inspection['can_restore'] and 'Legacy' in inspection['reason']
    assert client.post(f'/api/backups/{backup_id}/restore/preview').status_code == 409


@pytest.mark.parametrize('invalid', ['../escape', 'workspace_' + 'z' * 32])
def test_invalid_persisted_workspace_identity(client, invalid):
    path, _, _, backup_id = remediated(client)
    fixed = path.read_bytes()
    with sqlite3.connect(database_path()) as db:
        db.execute('UPDATE scan_results SET workspace_id=?', (invalid,))
    rewrite_events(lambda event: event.update(workspace_id=invalid))
    assert not client.get(f'/api/backups/{backup_id}').json()['can_restore']
    assert client.post(f'/api/backups/{backup_id}/restore/preview').status_code == 409
    assert path.read_bytes() == fixed


def test_secret_redaction_and_no_raw_paths_in_inspection_or_events(client):
    path, _, _, backup_id = remediated(client, secret=True)
    token = 'ghp_' + 'a' * 36
    for response in (client.get('/api/backups'), client.get(f'/api/backups/{backup_id}'),
            client.post(f'/api/backups/{backup_id}/restore/preview')):
        assert response.status_code == 200
        assert token not in response.text and str(path.parent) not in response.text and str(data_root()) not in response.text
    result = restore(client, backup_id, preview(client, backup_id))
    assert result.status_code == 200 and result.json()['findings_count'] > 1
    assert token not in client.get('/api/restorations').text
    assert token.encode() not in database_path().read_bytes()


@pytest.mark.parametrize('original', [TF.encode(), b'\xef\xbb\xbf' + TF.replace('\n', '\r\n').encode()])
def test_restore_preserves_exact_encoding_and_newline_bytes(client, original):
    path, _, _, backup_id = remediated(client, raw_source=original)
    assert restore(client, backup_id, preview(client, backup_id)).status_code == 200
    assert path.read_bytes() == original
    assert (data_root() / 'backups' / (backup_id + '.bak')).read_bytes() == original


def test_v4_to_v5_migration_preserves_existing_evidence(client):
    _, _, finding, _ = remediated(client)
    with sqlite3.connect(database_path()) as db:
        evidence = db.execute('SELECT evidence FROM scan_evidence ORDER BY rowid').fetchall()
        events = db.execute('SELECT details FROM remediation_runs ORDER BY rowid').fetchall()
        db.execute('DROP TABLE restoration_runs')
        db.execute('PRAGMA user_version=4')
    reloaded = ScanRepository(database_path())
    assert reloaded.restorations() == []
    assert any(f['id'] == finding['id'] for f in reloaded.findings())
    with sqlite3.connect(database_path()) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 5
        assert db.execute('SELECT evidence FROM scan_evidence ORDER BY rowid').fetchall() == evidence
        assert db.execute('SELECT details FROM remediation_runs ORDER BY rowid').fetchall() == events


def test_nested_import_restore_targets_only_its_original_file(client):
    from src.services.workspaces import resolve_workspace
    uploaded = client.post('/api/scan/upload', files=[('files', ('main.tf', TF)), ('files', ('main.tf', TF))],
        data={'relative_paths': json.dumps(['dev/main.tf', 'prod/main.tf'])}).json()
    root = resolve_workspace(uploaded['workspace_id'])
    findings = client.post('/api/scan/iac', json={'target_path': uploaded['target_path']}).json()['findings']
    selected = next(f for f in findings if f['file'] == 'dev/main.tf')
    proposed = client.post('/api/scan/iac/remediation/preview', json={'finding_id': selected['id']}).json()
    fixed = client.post('/api/scan/iac/remediate', json={
        'finding_id': selected['id'], 'preview_id': proposed['preview_id'], 'approved': True}).json()
    other_bytes = (root / 'prod/main.tf').read_bytes()
    backup_id = fixed['backup_id']
    assert restore(client, backup_id, preview(client, backup_id)).status_code == 200
    assert (root / 'dev/main.tf').read_bytes() == TF.encode()
    assert (root / 'prod/main.tf').read_bytes() == other_bytes
    assert len([f for f in client.get('/api/findings').json()['findings'] if f['status'] == 'OPEN']) == 2


def test_expired_restore_preview_is_rejected(client):
    path, _, _, backup_id = remediated(client)
    fixed = path.read_bytes()
    token = preview(client, backup_id)
    record_path = data_root() / 'restore-previews' / (token + '.json')
    record = json.loads(record_path.read_text(encoding='utf-8'))
    record['expires'] = 0
    record_path.write_text(json.dumps(record), encoding='utf-8')
    assert restore(client, backup_id, token).status_code == 409 and path.read_bytes() == fixed
