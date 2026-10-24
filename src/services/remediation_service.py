"""Version-bound previews, immutable backups and atomic verified apply."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

from src.scanners.remediation import RemediationError, build_candidate
from src.services.filesystem import contained, read_source
from src.services.scan_worker import isolated_file
from src.services.scanning import locate_file
from src.services.scan_repository import ScanRepository
from src.services.settings import data_root, workspace_root
from src.services.workspaces import resolve_workspace


def source_root(workspace_id: str) -> Path:
    return workspace_root() if workspace_id == "local" else resolve_workspace(workspace_id)


def _finding(repository: ScanRepository, finding_id: str) -> tuple:
    metadata = repository.get(finding_id)
    if not metadata["remediation_eligible"]:
        raise RemediationError("Finding requires manual remediation")
    root = source_root(metadata["workspace_id"])
    path = locate_file(root, metadata["workspace_id"], metadata["file_id"])
    raw = read_source(root, path)
    if hashlib.sha256(raw).hexdigest() != metadata["source_digest"]:
        raise RemediationError("Source changed; rescan before reviewing a fix")
    candidates = [f for f in isolated_file(path, root) if (f.rule_id, f.resource_key or f.resource) == (metadata['rule_id'], metadata.get('resource_key') or metadata['resource'])]
    if len(candidates) != 1 or not candidates[0].remediation_eligible:
        raise RemediationError("Finding could not be reproduced unambiguously")
    before = raw.decode("utf-8-sig")
    after, action = build_candidate(before, candidates[0], path.suffix.lower())
    encoded = (b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b"") + after.encode()
    return metadata, root, path, raw, encoded, before, after, action


def preview(repository: ScanRepository, finding_id: str) -> dict:
    from src.services.remediation_preview import review_text
    metadata, _, _, _, updated, before, after, action = _finding(repository, finding_id)
    display = review_text(before, after, metadata['line'], metadata['file'])
    identifier = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    directory = data_root() / "previews"
    directory.mkdir(exist_ok=True, mode=0o700)
    for old in directory.glob("*.json"):
        if time.time() - old.stat().st_mtime > 600:
            old.unlink()
    record = {"finding_id": finding_id, "digest": metadata["source_digest"],
        'after_digest': hashlib.sha256(updated).hexdigest(), "expires": time.time() + 600}
    with (directory / (identifier + ".json")).open("x", encoding="utf-8") as output:
        os.chmod(output.name, 0o600)
        json.dump(record, output)
    return {"preview_id": identifier, "finding_id": finding_id, "source_digest": metadata["source_digest"],
        'target': metadata['file'], 'rule_id': metadata['rule_id'], 'resource_label': metadata['resource_label'],
        'evidence': metadata['evidence'], 'conditions': ['Approve only this source version and selected resource.',
            'Other remaining findings prevent file verification.', 'A failed verification rolls back when safe.'],
        **display, 'action': action}


def atomic_write(root: Path, path: Path, content: bytes, expected_digest: str) -> None:
    contained(root, path)
    descriptor, temporary = tempfile.mkstemp(prefix=".antifine-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content); output.flush(); os.fsync(output.fileno())
        if hashlib.sha256(read_source(root, path)).hexdigest() != expected_digest:
            raise RemediationError("Concurrent source edit rejected")
        contained(root, path)
        os.chmod(temporary, path.stat().st_mode)
        os.replace(temporary, path)
        if os.name != "nt":
            fd = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def apply(repository: ScanRepository, finding_id: str, preview_id: str, *, approved: bool = False) -> dict:
    from src.services.remediation_apply import apply as approved_apply
    return approved_apply(repository, finding_id, preview_id, approved=approved)
