"""Bounded immutable backup bytes. No public path or source download contract."""
import hashlib
import os
from pathlib import Path
import re
import threading
import uuid

from src.services.filesystem import BoundaryError, MAX_FILE_BYTES, contained, read_source
from src.services.settings import data_root

_quota_lock = threading.Lock()
MAX_BACKUP_BYTES = 128 * 1024 * 1024


def identifier() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def valid_id(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def root_identity(root: Path) -> str:
    return hashlib.sha256(os.path.normcase(str(root.resolve(strict=True))).encode()).hexdigest()


def directory() -> Path:
    private = data_root()
    path = contained(private, private / 'backups', exists=False)
    path.mkdir(exist_ok=True, mode=0o700)
    return contained(private, path)


def read_backup(backup_id: str) -> bytes:
    if not valid_id(backup_id):
        raise BoundaryError('Unknown backup')
    root = directory()
    path = contained(root, root / (backup_id + '.bak'), exists=False)
    if not path.exists():
        raise FileNotFoundError('Backup unavailable')
    return read_source(root, path)


def create_backup(content: bytes) -> str:
    if len(content) > MAX_FILE_BYTES:
        raise BoundaryError('Backup source exceeds the file limit')
    with _quota_lock:
        root = directory()
        if sum(contained(root, item).stat().st_size for item in root.glob('*.bak')) + len(content) > MAX_BACKUP_BYTES:
            raise BoundaryError('Backup quota reached; archive recoverable backups before writing')
        backup_id = identifier()
        path = contained(root, root / (backup_id + '.bak'), exists=False)
        with path.open('xb') as output:
            os.chmod(path, 0o600)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if read_backup(backup_id) != content:
            raise BoundaryError('Backup verification failed')
        if os.name != 'nt':
            descriptor = os.open(root, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return backup_id
