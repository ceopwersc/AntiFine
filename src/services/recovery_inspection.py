"""Resolve recovery ownership internally; expose bounded, sanitized review data."""
from dataclasses import dataclass
import hashlib
from pathlib import Path, PureWindowsPath
import re

from src.services.backup_store import read_backup, root_identity, valid_id
from src.services.filesystem import contained, read_source
from src.services.remediation_preview import review_text
from src.services.remediation_service import source_root
from src.services.scan_repository import ScanRepository
from src.services.scanning import locate_file
from src.services.secret_boundary import sanitize_path, sanitize_text

WARNING = 'Restoring original source may reintroduce security findings. Restoration is not a security remediation.'


class UnknownBackup(ValueError):
    pass


class RecoveryConflict(ValueError):
    pass


@dataclass
class RestorePlan:
    event: dict
    metadata: dict
    root: Path
    path: Path
    current: bytes
    original: bytes


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _owner(repository: ScanRepository, backup_id: str) -> tuple[dict, dict | None]:
    if not valid_id(backup_id):
        raise UnknownBackup('Backup unavailable')
    events = repository.backup_events(backup_id)
    if not events:
        raise UnknownBackup('Backup unavailable')
    latest = events[-1]
    fields = ('operation_id', 'finding_id', 'file_id', 'source_digest', 'after_digest', 'workspace_id', 'root_id')
    consistent = all(isinstance(event.get(key, ''), str) for event in events for key in fields)
    consistent = consistent and len({tuple(event.get(key) for key in fields) for event in events}) == 1
    matches = [finding for finding in repository.findings() if finding['id'] == latest.get('finding_id')]
    if not consistent or len(matches) != 1:
        return latest, None
    metadata = matches[0]
    if latest.get('file_id') != metadata['file_id'] or latest.get('workspace_id', metadata['workspace_id']) != metadata['workspace_id']:
        return latest, None
    return latest, metadata


def inspect_plan(repository: ScanRepository, backup_id: str, *, owns_lock: bool = False) -> tuple[dict, RestorePlan | None]:
    event, metadata = _owner(repository, backup_id)
    history = repository.restorations(backup_id)
    latest_restore = history[0] if history else None
    workspace_id = metadata['workspace_id'] if metadata else ''
    if workspace_id != 'local' and not re.fullmatch('workspace_[0-9a-f]{32}', workspace_id):
        workspace_id = ''
    display_file = metadata['file'] if metadata else 'Identity unavailable'
    if Path(display_file).is_absolute() or PureWindowsPath(display_file).drive or '..' in Path(display_file).parts:
        display_file = 'Location withheld'
    def safe_id(key: str) -> str:
        return event[key] if valid_id(event.get(key, '')) else ''
    result = {'backup_id': backup_id, 'remediation_id': safe_id('operation_id'),
        'finding_id': safe_id('finding_id'), 'file_id': safe_id('file_id'),
        'workspace_id': workspace_id,
        'file': sanitize_path(display_file),
        'rule_id': sanitize_text(metadata['rule_id'] if metadata else 'unknown'),
        'resource_label': sanitize_text(metadata['resource_label'] if metadata else 'unknown'),
        'remediated_at': event['recorded_at'], 'remediation_status': event.get('status', 'unknown'),
        'original_digest': safe_id('source_digest'), 'remediated_digest': safe_id('after_digest'),
        'current_digest': None, 'backup_status': 'unavailable', 'backup_available': False,
        'state': 'needs_review', 'can_restore': False, 'reason': 'Backup ownership cannot be proven.',
        'changes': None, 'restoration': latest_restore, 'warning': WARNING}
    if metadata is None or not all(valid_id(event.get(key, '')) for key in ('operation_id', 'finding_id', 'file_id', 'source_digest', 'after_digest')):
        return result, None
    try:
        original = read_backup(backup_id)
        if digest(original) != event['source_digest']:
            result.update(backup_status='corrupt', reason='Backup bytes do not match the recorded original version.')
            return result, None
        result['backup_status'] = 'available'
        result['backup_available'] = True
    except FileNotFoundError:
        result.update(backup_status='missing', reason='The immutable backup is missing.')
        return result, None
    except (OSError, ValueError):
        result['reason'] = 'The backup cannot be read safely.'
        return result, None
    if not valid_id(event.get('root_id', '')) or not event.get('workspace_id'):
        result['reason'] = 'Legacy backup lacks provable workspace ownership; manual review is required.'
        return result, None
    try:
        root = source_root(metadata['workspace_id'])
        if root_identity(root) != event['root_id']:
            result['reason'] = 'The configured workspace differs from the recorded owner.'
            return result, None
        path = locate_file(root, metadata['workspace_id'], metadata['file_id'])
        current = read_source(root, path)
        result['current_digest'] = digest(current)
        lock_path = contained(root, path.with_name(path.name + '.antifine-lock'), exists=False)
        if lock_path.exists() and not owns_lock:
            result['reason'] = 'The source is locked by an operation or an interrupted operation; review is required.'
            return result, None
    except (OSError, ValueError):
        result['reason'] = 'The original source or authorized workspace is unavailable.'
        return result, None
    if event['status'] == 'verification_pending' or repository.has_pending_file(metadata['file_id'], metadata['workspace_id']):
        result['reason'] = 'An interrupted or unfinished operation on this file needs review.'
        return result, None
    if latest_restore and latest_restore['status'] == 'restored':
        if digest(current) == event['source_digest']:
            result.update(state='restored', reason='Original bytes were restored and rescanned; review the resulting findings.')
        else:
            result['reason'] = 'This backup was already restored. Inspect the current source and its latest remediation backup.'
        return result, None
    if event['status'] not in {'verified_resolved', 'resolved_with_findings'}:
        result['reason'] = 'The remediation did not complete successfully; manual review is required.'
        return result, None
    if digest(current) != event['after_digest']:
        result['reason'] = 'Source changed after remediation. External changes will not be overwritten.'
        return result, None
    try:
        result['changes'] = review_text(current.decode('utf-8-sig'), original.decode('utf-8-sig'), 1, result['file'])
    except (ValueError, UnicodeError):
        result['reason'] = 'The reverse change cannot be reviewed safely; manual review is required.'
        return result, None
    result.update(state='restorable', can_restore=True, reason='Current source and immutable backup match their recorded versions.')
    return result, RestorePlan(event, metadata, root, path, current, original)


def inspect_backup(repository: ScanRepository, backup_id: str) -> dict:
    return inspect_plan(repository, backup_id)[0]


def list_backups(repository: ScanRepository) -> list[dict]:
    return [inspect_backup(repository, event['backup_id']) for event in repository.backup_events()]
