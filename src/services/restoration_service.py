"""Explicitly confirmed, version-bound restoration with separate durable evidence."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import time
from typing import Iterator

from src.services.backup_store import create_backup, identifier, valid_id
from src.services.filesystem import contained, read_source
from src.services.recovery_inspection import RecoveryConflict, RestorePlan, WARNING, digest, inspect_plan
from src.services.remediation_service import atomic_write
from src.services.scan_repository import ScanRepository
from src.services.scanning import scan_target
from src.services.settings import data_root


def _previews() -> Path:
    private = data_root()
    path = contained(private, private / 'restore-previews', exists=False)
    path.mkdir(exist_ok=True, mode=0o700)
    return contained(private, path)


def _binding(backup_id: str, plan: RestorePlan) -> dict:
    return {'kind': 'restore', 'backup_id': backup_id, 'remediation_id': plan.event['operation_id'],
        'finding_id': plan.metadata['id'], 'file_id': plan.metadata['file_id'],
        'workspace_id': plan.metadata['workspace_id'], 'root_id': plan.event['root_id'],
        'source_digest': digest(plan.current), 'restore_digest': digest(plan.original)}


def preview_restore(repository: ScanRepository, backup_id: str) -> dict:
    inspection, plan = inspect_plan(repository, backup_id)
    if plan is None:
        raise RecoveryConflict(inspection['reason'])
    directory = _previews()
    for old in directory.glob('*.json'):
        checked = contained(directory, old)
        if time.time() - checked.stat().st_mtime > 600:
            checked.unlink()
    if sum(1 for _ in directory.glob('*.json')) >= 500:
        raise RecoveryConflict('Restore preview capacity reached; retry after expiry')
    preview_id = identifier()
    record = _binding(backup_id, plan) | {'expires': time.time() + 600}
    with (directory / (preview_id + '.json')).open('x', encoding='utf-8') as output:
        os.chmod(output.name, 0o600)
        json.dump(record, output)
    return inspection | {'preview_id': preview_id}


@contextmanager
def _file_lock(plan: RestorePlan) -> Iterator[None]:
    path = contained(plan.root, plan.path.with_name(plan.path.name + '.antifine-lock'), exists=False)
    try:
        lock = path.open('x')
    except FileExistsError:
        raise RecoveryConflict('The source is locked; review the active or interrupted operation') from None
    try:
        yield
    finally:
        try:
            lock.close()
            path.unlink(missing_ok=True)
        except OSError:
            pass  # A leftover lock blocks later writes; never delete it automatically.


def _rollback(plan: RestorePlan) -> bool:
    try:
        current_digest = digest(read_source(plan.root, plan.path))
        if current_digest == digest(plan.current):
            return True
        if current_digest != digest(plan.original):
            return False
        atomic_write(plan.root, plan.path, plan.current, digest(plan.original))
        return digest(read_source(plan.root, plan.path)) == digest(plan.current)
    except (OSError, ValueError):
        return False


def restore(repository: ScanRepository, backup_id: str, preview_id: str, *, confirmed: bool = False) -> dict:
    if confirmed is not True or not valid_id(preview_id):
        raise RecoveryConflict('Explicit confirmation and a current restore preview are required')
    preview_path = _previews() / (preview_id + '.json')
    try:
        record = json.loads(read_source(_previews(), preview_path).decode('utf-8'))
        if not isinstance(record, dict) or record.get('expires', 0) < time.time():
            raise ValueError('Expired')
    except (OSError, ValueError, TypeError):
        raise RecoveryConflict('Restore preview expired or unavailable') from None
    _, initial = inspect_plan(repository, backup_id)
    if initial is None:
        raise RecoveryConflict('Restoration is no longer safe; inspect the backup again')
    with _file_lock(initial):
        _, plan = inspect_plan(repository, backup_id, owns_lock=True)
        if plan is None or any(record.get(key) != value for key, value in _binding(backup_id, plan).items()):
            raise RecoveryConflict('Source, backup or ownership changed after review')
        safety_backup = create_backup(plan.current)
        restoration_id = identifier()
        event = {'id': identifier(), 'restoration_id': restoration_id, 'backup_id': backup_id,
            'remediation_id': plan.event['operation_id'], 'finding_id': plan.metadata['id'],
            'file_id': plan.metadata['file_id'], 'workspace_id': plan.metadata['workspace_id'],
            'file': plan.metadata['file'], 'rule_id': plan.metadata['rule_id'],
            'resource_label': plan.metadata['resource_label'], 'root_id': plan.event['root_id'],
            'source_digest': digest(plan.current), 'restored_digest': digest(plan.original),
            'pre_restore_backup_id': safety_backup, 'confirmed': True, 'status': 'restore_pending',
            'scan_id': '', 'findings_count': None, 'finding_reopened': False, 'verified': False}
        repository.record_restoration(event)
        try:
            atomic_write(plan.root, plan.path, plan.original, digest(plan.current))
            run, findings = scan_target(plan.root, plan.path, plan.metadata['workspace_id'], isolated=True)
            evaluated = run['coverage']
            if (run['status'] != 'completed' or len(evaluated) != 1 or not evaluated[0]['rules_evaluated']
                    or evaluated[0]['file_id'] != plan.metadata['file_id']
                    or digest(read_source(plan.root, plan.path)) != digest(plan.original)):
                raise RecoveryConflict('Restoration rescan did not evaluate the original file reliably')
            run['scan_type'] = 'Restoration rescan'
            event.update(id=identifier(), status='restored', scan_id=run['id'], findings_count=len(findings),
                finding_reopened=any(finding.id == plan.metadata['id'] for finding in findings))
            preview_path.unlink(missing_ok=True)
            repository.save_run(run, findings, restoration=event)
            return {'status': 'restored', 'restoration_id': restoration_id, 'backup_id': backup_id,
                'pre_restore_backup_id': safety_backup, 'scan_id': run['id'], 'findings_count': len(findings),
                'finding_reopened': event['finding_reopened'], 'verified': False, 'coverage': run['coverage'], 'warning': WARNING}
        except Exception:
            rolled_back = _rollback(plan)
            repository.record_restoration(event | {'id': identifier(),
                'status': 'restore_failed' if rolled_back else 'restore_needs_review',
                'rollback_completed': rolled_back, 'scan_id': '', 'finding_reopened': False, 'verified': False})
            raise RecoveryConflict('Restoration could not be completed; inspect the recorded outcome and safety backup') from None
