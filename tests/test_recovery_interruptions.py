from unittest.mock import patch
import sqlite3

import pytest

from src.services import restoration_service
from src.services.scan_repository import ScanRepository
from src.services.settings import data_root, database_path
from tests.test_recovery import remediated, preview, restore


@pytest.mark.parametrize('after_write', [False, True])
def test_interrupted_restore_survives_restart_as_needs_review(client, after_write):
    path, original, finding, backup_id = remediated(client)
    fixed = path.read_bytes()
    token = preview(client, backup_id)
    original_bytes = (data_root() / 'backups' / (backup_id + '.bak')).read_bytes()
    real_write = restoration_service.atomic_write

    class Interrupted(BaseException):
        pass

    def interrupt(*args):
        if after_write:
            real_write(*args)
        raise Interrupted()

    with patch.object(restoration_service, 'atomic_write', side_effect=interrupt):
        with pytest.raises(Interrupted):
            restoration_service.restore(ScanRepository(database_path()), backup_id, token, confirmed=True)
    assert path.read_bytes() == (original_bytes if after_write else fixed)
    restarted = ScanRepository(database_path())
    events = restarted.restorations(backup_id)
    assert len(events) == 1 and events[0]['status'] == 'restore_pending'
    assert (data_root() / 'backups' / (events[0]['pre_restore_backup_id'] + '.bak')).read_bytes() == fixed
    inspection = client.get(f'/api/backups/{backup_id}').json()
    assert inspection['state'] == 'needs_review' and not inspection['can_restore']
    assert next(f for f in restarted.findings() if f['id'] == finding['id'])['recovery_state'] == 'needs_review'
    assert restore(client, backup_id, token).status_code == 409
    # Even a real read-only rescan cannot silently authorize a new write over an unfinished operation.
    if after_write:
        client.post(f"/api/findings/{finding['id']}/rescan")
        reviewed = client.post('/api/scan/iac/remediation/preview', json={'finding_id': finding['id']}).json()
        assert client.post('/api/scan/iac/remediate', json={
            'finding_id': finding['id'], 'preview_id': reviewed['preview_id'], 'approved': True}).status_code == 409


@pytest.mark.parametrize('failure', ['rescan', 'persistence', 'after_replace'])
def test_failed_restore_rolls_back_without_modifying_original_backup(client, failure):
    path, original, _, backup_id = remediated(client)
    fixed = path.read_bytes()
    token = preview(client, backup_id)
    if failure == 'rescan':
        replacement = patch.object(restoration_service, 'scan_target', side_effect=ValueError('synthetic scan failure'))
    elif failure == 'persistence':
        replacement = patch.object(ScanRepository, 'save_run', side_effect=OSError('synthetic database failure'))
    else:
        real_write = restoration_service.atomic_write
        calls = []

        def post_replace_error(*args):
            real_write(*args)
            calls.append(True)
            if len(calls) == 1:
                raise OSError('synthetic post-replace failure')

        replacement = patch.object(restoration_service, 'atomic_write', side_effect=post_replace_error)
    with replacement:
        response = restore(client, backup_id, token)
    assert response.status_code == 409 and path.read_bytes() == fixed
    assert (data_root() / 'backups' / (backup_id + '.bak')).read_text() == original
    event = ScanRepository(database_path()).restorations(backup_id)[0]
    assert event['status'] == 'restore_failed' and event['rollback_completed']
    assert event['verified'] is False and not event['finding_reopened']


def test_concurrent_outside_edit_prevents_unsafe_rollback(client):
    path, _, finding, backup_id = remediated(client)
    token = preview(client, backup_id)
    outside = '# independent outside edit\n'

    def failed_scan(*args, **kwargs):
        path.write_text(outside, encoding='utf-8')
        raise ValueError('synthetic concurrent verification failure')

    with patch.object(restoration_service, 'scan_target', side_effect=failed_scan):
        response = restore(client, backup_id, token)
    assert response.status_code == 409 and path.read_text() == outside
    event = ScanRepository(database_path()).restorations(backup_id)[0]
    assert event['status'] == 'restore_needs_review' and event['rollback_completed'] is False
    assert client.get(f'/api/backups/{backup_id}').json()['state'] == 'needs_review'
    assert next(f for f in client.get('/api/findings').json()['findings'] if f['id'] == finding['id'])['recovery_state'] == 'needs_review'


def test_lock_and_pending_remediation_are_visible_and_never_cleared_automatically(client):
    path, _, finding, backup_id = remediated(client)
    lock = path.with_name(path.name + '.antifine-lock')
    lock.write_text('synthetic interrupted lock', encoding='utf-8')
    assert not client.get(f'/api/backups/{backup_id}').json()['can_restore']
    assert lock.read_text() == 'synthetic interrupted lock'
    lock.unlink()
    with sqlite3.connect(database_path()) as db:
        db.execute("DELETE FROM remediation_runs WHERE json_extract(details,'$.status') IN ('verified_resolved','resolved_with_findings')")
    assert client.get(f'/api/backups/{backup_id}').json()['state'] == 'needs_review'
    assert next(f for f in client.get('/api/findings').json()['findings'] if f['id'] == finding['id'])['recovery_state'] == 'needs_review'


def test_owner_record_mismatch_cannot_locate_a_different_file(client):
    from tests.test_recovery import rewrite_events
    path, _, _, backup_id = remediated(client)
    fixed = path.read_bytes()
    rewrite_events(lambda event: event.update(file_id='f' * 64))
    assert not client.get(f'/api/backups/{backup_id}').json()['can_restore']
    assert client.post(f'/api/backups/{backup_id}/restore/preview').status_code == 409
    assert path.read_bytes() == fixed
