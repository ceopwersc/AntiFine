"""Scan orchestration with explicit coverage and redacted, stable identities."""
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import uuid
import time

from src.models.finding import Finding
from src.services.filesystem import BoundaryError, contained, read_source
from src.services.scan_worker import isolated_file
from src.services.secret_boundary import sanitize_path

EXCLUDED = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build", ".pytest_cache", ".terraform"}
MAX_FILES = 500
MAX_SCAN_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 2000


def identity(*parts):
    return hashlib.sha256("\0".join(str(p) for p in parts).encode()).hexdigest()


def supported(path: Path):
    return "dockerfile" in path.name.lower() or path.suffix.lower() in {".tf", ".yaml", ".yml", ".env", ".json", ".conf"} or path.name.startswith(".env")


def rule_families(path: Path) -> list[str]:
    if 'dockerfile' in path.name.lower():
        return ['docker', 'secrets']
    if path.suffix.lower() == '.tf':
        return ['terraform', 'secrets']
    if path.suffix.lower() in {'.yaml', '.yml'}:
        return ['kubernetes', 'secrets']
    return ['secrets'] if supported(path) else []


def discover(root: Path, target: Path):
    target = contained(root, target)
    if target.is_file():
        return [target], []
    paths, errors = [], []
    deadline = time.monotonic() + 5
    entries = 0
    def error(_exc):
        errors.append("Directory could not be enumerated")
    for directory, directories, files in os.walk(target, followlinks=False, onerror=error):
        entries += len(directories) + len(files)
        if time.monotonic() > deadline or entries > 5000:
            raise BoundaryError('Directory discovery quota exceeded')
        for name in list(directories):
            child = Path(directory) / name
            if name in EXCLUDED:
                directories.remove(name)
                continue
            try:
                contained(root, child)
            except (BoundaryError, OSError):
                directories.remove(name)
                errors.append("Linked or inaccessible directory rejected")
        for name in files:
            child = Path(directory) / name
            paths.append(child)
            if len(paths) > MAX_FILES:
                raise BoundaryError("Scan file quota exceeded")
    return sorted(paths), errors


def scan_target(root: Path, target: Path, workspace_id: str, repository=None, *, isolated=True):
    from src.scanners.iac_audit import scan_file
    root, target = root.resolve(), contained(root, target)
    files, listing_errors = discover(root, target)
    scan_id = identity(uuid.uuid4().hex)
    findings, coverage = [], []
    total = 0
    deadline = time.monotonic() + 30
    for path in files:
        relative = path.relative_to(root).as_posix()
        file_id = identity(workspace_id, relative)
        item = {"file_id": file_id, "file": sanitize_path(relative), "status": "unsupported", "rules_evaluated": False,
                'attempted_rule_families': rule_families(path), 'rule_families': []}
        if supported(path):
            try:
                if time.monotonic() > deadline:
                    raise BoundaryError("Scan processing deadline exceeded")
                data = read_source(root, path)
                total += len(data)
                if total > MAX_SCAN_BYTES:
                    raise BoundaryError("Aggregate scan quota exceeded")
                digest = hashlib.sha256(data).hexdigest()
                values = isolated_file(path, root) if isolated else scan_file(path)
                if len(findings) + len(values) > MAX_FINDINGS:
                    raise BoundaryError("Aggregate finding quota exceeded")
                # Detect writes racing the child scan; do not persist inconsistent evidence.
                if hashlib.sha256(read_source(root, path)).hexdigest() != digest:
                    raise BoundaryError("Source changed during scan")
                item["status"] = "error" if any(f.rule_id.startswith("parser.") for f in values) else "evaluated"
                item["rules_evaluated"] = item["status"] == "evaluated"
                item['rule_families'] = rule_families(path) if item['rules_evaluated'] else []
                for f in values:
                    f.filename = sanitize_path(relative)
                    f.file_id, f.source_digest, f.scan_id = file_id, digest, scan_id
                    f.workspace_id = workspace_id
                    f.id = identity(workspace_id, file_id, f.rule_id, f.resource_key or f.resource)
                    f.end_line = max(f.line, f.end_line)
                if len({f.id for f in values}) != len(values):
                    raise BoundaryError('Ambiguous finding identities; file was not evaluated')
                findings.extend(values)
            except (OSError, ValueError, RuntimeError):
                item["status"] = "error"
                item['rules_evaluated'] = False
                item['rule_families'] = []
                item["error"] = "File evaluation failed or exceeded scan limits"
        coverage.append(item)
    status = "completed" if files and all(c["status"] == "evaluated" for c in coverage) and not listing_errors else "partial" if any(c["status"] == "evaluated" for c in coverage) else "error"
    # A completely enumerated empty directory may close removed files, but never
    # carries a compliant/verified assertion. Keep coverage explicit.
    if not files and not listing_errors and target.is_dir():
        status = "completed"
    run = {"id": scan_id, "workspace_id": workspace_id, "scope_id": identity(target.relative_to(root).as_posix()),
        "target": sanitize_path(target.relative_to(root).as_posix()), "status": status, "coverage": coverage,
        "listing_errors": listing_errors, "findings_count": len(findings)}
    run['enumeration_complete'] = not listing_errors
    if repository:
        repository.save_run(run, findings)
    return run, findings


def locate_file(root: Path, workspace_id: str, file_id: str) -> Path:
    files, errors = discover(root, root)
    if errors:
        raise BoundaryError("Workspace enumeration incomplete")
    matches = [p for p in files if identity(workspace_id, p.relative_to(root).as_posix()) == file_id]
    if len(matches) != 1:
        raise BoundaryError("Finding source is unavailable or ambiguous")
    return contained(root, matches[0])
