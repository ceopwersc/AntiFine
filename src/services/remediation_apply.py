"""Approved atomic apply with durable pending/final deterministic evidence."""
from dataclasses import asdict
import hashlib
import json
import os
import time
import uuid

from src.scanners.remediation import RemediationError
from src.models.finding import Finding
from src.services.scan_repository import ScanRepository
from src.services.filesystem import contained
from src.services.scan_worker import isolated_file
from src.services.scanning import scan_target
from src.services.settings import data_root
from src.services.remediation_service import _finding, atomic_write


def identifier() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def key(finding: Finding) -> tuple[str, str]:
    return finding.rule_id, finding.resource_key or finding.resource


def apply(repository: ScanRepository, finding_id: str, preview_id: str, *, approved: bool = False) -> dict:
    if approved is not True:
        raise RemediationError('Explicit approval of the current preview is required')
    if len(preview_id) != 64 or any(value not in '0123456789abcdef' for value in preview_id):
        raise RemediationError('Invalid preview ID')
    record_path = data_root() / 'previews' / (preview_id + '.json')
    try:
        record = json.loads(record_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise RemediationError('Preview expired or unavailable') from None
    if record.get('finding_id') != finding_id or record.get('expires', 0) < time.time():
        raise RemediationError('Preview does not authorize this finding')
    metadata, root, path, original, updated, _, _, action = _finding(repository, finding_id)
    updated_digest = hashlib.sha256(updated).hexdigest()
    if record.get('digest') != metadata['source_digest'] or record.get('after_digest') != updated_digest:
        raise RemediationError('Stale or changed candidate')
    baseline = {key(finding) for finding in isolated_file(path, root)}
    lock_path = path.with_name(path.name + '.antifine-lock')
    contained(root, lock_path, exists=False)
    try:
        lock = lock_path.open('x')
    except FileExistsError:
        raise RemediationError('Another remediation owns this file') from None
    backup_id, operation_id = identifier(), identifier()
    backups = data_root() / 'backups'
    backups.mkdir(exist_ok=True, mode=0o700)
    event = {'id': identifier(), 'operation_id': operation_id, 'finding_id': finding_id,
        'preview_id': preview_id, 'approved': True, 'status': 'verification_pending',
        'file': metadata['file'], 'file_id': metadata['file_id'], 'rule_id': metadata['rule_id'],
        'resource_label': metadata['resource_label'], 'backup_id': backup_id,
        'source_digest': record['digest'], 'after_digest': updated_digest, 'scan_id': '',
        'file_verified': False, 'original_resolved': False, 'introduced_count': 0, 'remaining_count': None}
    wrote = False
    pending = False
    try:
        if sum(item.stat().st_size for item in backups.glob('*.bak')) + len(original) > 128 * 1024 * 1024:
            raise RemediationError('Backup quota reached; archive recoverable backups before applying more fixes')
        with (backups / (backup_id + '.bak')).open('xb') as backup:
            os.chmod(backup.name, 0o600)
            backup.write(original)
            backup.flush()
            os.fsync(backup.fileno())
        if (backups / (backup_id + '.bak')).read_bytes() != original:
            raise RemediationError('Backup verification failed')
        repository.record_remediation(event)
        pending = True
        atomic_write(root, path, updated, record['digest'])
        wrote = True
        run, findings = scan_target(root, path, metadata['workspace_id'], isolated=True)
        event['introduced_count'] = len({key(finding) for finding in findings} - baseline)
        selected = metadata['rule_id'], metadata.get('resource_key') or metadata['resource']
        if run['status'] != 'completed' or not run['coverage'] or selected in {key(f) for f in findings} or event['introduced_count']:
            raise RemediationError('Deterministic verification failed or introduced a finding')
        verified = not findings
        event.update(id=identifier(), status='verified_resolved' if verified else 'resolved_with_findings',
            original_resolved=True, file_verified=verified, scan_id=run['id'], remaining_count=len(findings))
        result = {'status': 'verified' if verified else 'applied', 'verified': verified, 'original_resolved': True,
            'introduced_count': 0, 'remediation_id': operation_id, 'target': metadata['file'],
            'backup': backup_id, 'backup_id': backup_id, 'action': action, 'findings_count': len(findings),
            'findings': [asdict(f) for f in findings], 'scan_id': run['id'], 'coverage': run['coverage']}
        record_path.unlink(missing_ok=True)
        repository.save_run(run, findings, remediation=event)
        return result
    except Exception:
        rollback = not wrote
        if wrote:
            try:
                atomic_write(root, path, original, updated_digest)
                rollback = True
            except (OSError, ValueError):
                rollback = False
        if pending:
            repository.record_remediation(event | {'id': identifier(), 'status': 'verification_failed',
                'file_verified': False, 'original_resolved': False, 'rollback_completed': rollback})
        raise RemediationError('Apply could not be verified; inspect recorded status and backup before retrying') from None
    finally:
        lock.close()
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            # A leftover lock blocks further edits for operator review, but must
            # not turn committed verification into a false failure response.
            pass
