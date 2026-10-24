"""Private, expiring imports. No source file is placed under a web root."""
import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

from src.services.filesystem import BoundaryError, contained, MAX_FILE_BYTES
from src.services.settings import data_root

MAX_FILES = 100
MAX_WORKSPACE_BYTES = 16 * 1024 * 1024
MAX_DISK_BYTES = 128 * 1024 * 1024
RETENTION_SECONDS = 24 * 60 * 60
_quota_lock = threading.Lock()


def import_root() -> Path:
    path = data_root() / "imports"
    path.mkdir(exist_ok=True, mode=0o700)
    return path


def cleanup() -> None:
    root = import_root()
    for child in root.iterdir():
        try:
            checked = contained(root, child)
            if checked.is_dir() and child.name.startswith("workspace_") and time.time() - checked.stat().st_mtime > RETENTION_SECONDS:
                shutil.rmtree(checked)
        except (OSError, BoundaryError):
            continue


def resolve_workspace(identifier: str) -> Path:
    if not identifier.startswith("workspace_") or len(identifier) != 42 or not all(c in "0123456789abcdef" for c in identifier[10:]):
        raise BoundaryError("Unknown import workspace")
    cleanup()
    path = contained(import_root(), import_root() / identifier)
    if not path.is_dir():
        raise BoundaryError("Unknown import workspace")
    return path


def store_uploads(files, relative_paths: str) -> str:
    # Entire operation is synchronous and is called in a worker thread. Serialize
    # reservations so simultaneous uploads cannot race the disk quota.
    with _quota_lock:
        cleanup()
        if not files or len(files) > MAX_FILES:
            raise BoundaryError("Too many files uploaded (limit 100), or empty upload")
        try:
            names = json.loads(relative_paths)
        except (ValueError, TypeError):
            raise BoundaryError("Invalid relative_paths JSON") from None
        if not isinstance(names, list) or any(not isinstance(x, str) for x in names):
            raise BoundaryError("relative_paths must be a list of strings")
        root = import_root()
        used = sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and not p.is_symlink())
        identifier = "workspace_" + uuid.uuid4().hex
        target = root / identifier
        target.mkdir(mode=0o700)
        total = 0
        seen = set()
        try:
            for i, upload in enumerate(files):
                name = names[i] if i < len(names) and names[i] else upload.filename or ""
                # Deliberately reject ambiguous/path-traversal names; never silently rename.
                rel = Path(name.replace("\\", "/"))
                if not name or rel.is_absolute() or rel.drive or ".." in rel.parts or any(":" in p for p in rel.parts):
                    raise BoundaryError("Invalid uploaded path")
                if rel.as_posix().casefold() in seen:
                    raise BoundaryError("Duplicate uploaded path")
                seen.add(rel.as_posix().casefold())
                destination = contained(target, target / rel, exists=False)
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                contained(target, destination.parent)
                count = 0
                with destination.open("xb") as output:
                    os.chmod(destination, 0o600)
                    while chunk := upload.file.read(64 * 1024):
                        count += len(chunk)
                        total += len(chunk)
                        if count > MAX_FILE_BYTES or total > MAX_WORKSPACE_BYTES or used + total > MAX_DISK_BYTES:
                            raise BoundaryError("Upload quota exceeded")
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            return identifier
        except Exception:
            shutil.rmtree(contained(root, target))
            raise
