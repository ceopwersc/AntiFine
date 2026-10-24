"""Version-bound previews, immutable backups and atomic verified apply."""
from dataclasses import asdict
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
from src.services.scanning import locate_file, scan_target
from src.services.secret_boundary import sanitize_text
from src.services.settings import data_root, workspace_root
from src.services.workspaces import resolve_workspace


def source_root(workspace_id):
    return workspace_root() if workspace_id == "local" else resolve_workspace(workspace_id)


def _finding(repository, finding_id):
    metadata = repository.get(finding_id)
    if not metadata["remediation_eligible"]:
        raise RemediationError("Finding requires manual remediation")
    root = source_root(metadata["workspace_id"])
    path = locate_file(root, metadata["workspace_id"], metadata["file_id"])
    raw = read_source(root, path)
    if hashlib.sha256(raw).hexdigest() != metadata["source_digest"]:
        raise RemediationError("Source changed; rescan before reviewing a fix")
    candidates = [f for f in isolated_file(path, root) if (f.rule_id, f.resource) == (metadata["rule_id"], metadata["resource"])]
    if len(candidates) != 1 or not candidates[0].remediation_eligible:
        raise RemediationError("Finding could not be reproduced unambiguously")
    before = raw.decode("utf-8-sig")
    after, action = build_candidate(before, candidates[0], path.suffix.lower())
    encoded = (b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b"") + after.encode()
    return metadata, root, path, raw, encoded, before, after, action


def preview(repository, finding_id):
    metadata, _, _, _, _, before, after, action = _finding(repository, finding_id)
    identifier = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    directory = data_root() / "previews"
    directory.mkdir(exist_ok=True, mode=0o700)
    for old in directory.glob("*.json"):
        if time.time() - old.stat().st_mtime > 600:
            old.unlink()
    record = {"finding_id": finding_id, "digest": metadata["source_digest"], "expires": time.time() + 600}
    with (directory / (identifier + ".json")).open("x", encoding="utf-8") as output:
        os.chmod(output.name, 0o600)
        json.dump(record, output)
    return {"preview_id": identifier, "finding_id": finding_id, "source_digest": metadata["source_digest"],
        "target": metadata["file"], "before": sanitize_text(before, limit=12000),
        "after": sanitize_text(after, limit=12000), "action": action}


def atomic_write(root, path, content, expected_digest):
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


def apply(repository, finding_id, preview_id):
    if len(preview_id) != 64 or any(c not in "0123456789abcdef" for c in preview_id):
        raise RemediationError("Invalid preview ID")
    record_path = data_root() / "previews" / (preview_id + ".json")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RemediationError("Preview expired or unavailable") from None
    if record["finding_id"] != finding_id or record["expires"] < time.time():
        raise RemediationError("Preview does not authorize this finding")
    metadata, root, path, original, updated, _, _, action = _finding(repository, finding_id)
    if record["digest"] != metadata["source_digest"]:
        raise RemediationError("Stale preview")
    lock_path = path.with_name(path.name + ".antifine-lock")
    contained(root, lock_path, exists=False)
    try:
        lock = lock_path.open("x")
    except FileExistsError:
        raise RemediationError("Another remediation owns this file") from None
    backup_id = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    backups = data_root() / "backups"
    backups.mkdir(exist_ok=True, mode=0o700)
    try:
        if sum(p.stat().st_size for p in backups.glob("*.bak")) + len(original) > 128 * 1024 * 1024:
            raise RemediationError("Backup quota reached; archive recoverable backups before applying more fixes")
        with (backups / (backup_id + ".bak")).open("xb") as backup:
            os.chmod(backup.name, 0o600)
            backup.write(original); backup.flush(); os.fsync(backup.fileno())
        if (backups / (backup_id + ".bak")).read_bytes() != original:
            raise RemediationError("Backup verification failed")
        atomic_write(root, path, updated, record["digest"])
        try:
            run, findings = scan_target(root, path, metadata["workspace_id"], isolated=True)
            if run["status"] != "completed" or any((f.rule_id, f.resource) == (metadata["rule_id"], metadata["resource"]) for f in findings):
                raise RemediationError("Deterministic verification failed")
            repository.save_run(run, findings)
        except Exception:
            atomic_write(root, path, original, hashlib.sha256(updated).hexdigest())
            raise
        record_path.unlink()
        verified = not findings
        return {"status": "verified" if verified else "applied", "verified": verified,
            "target": metadata["file"], "backup": backup_id, "backup_id": backup_id, "action": action,
            "findings_count": len(findings), "findings": [asdict(f) for f in findings], "scan_id": run["id"], "coverage": run["coverage"]}
    finally:
        lock.close()
        lock_path.unlink(missing_ok=True)
