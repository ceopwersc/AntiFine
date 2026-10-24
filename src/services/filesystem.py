"""Fail-closed containment and bounded reads, including Windows reparse points."""
import os
import stat
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{prefix}{n}" for prefix in ("COM", "LPT") for n in range(1, 10)}


class BoundaryError(ValueError):
    pass


def _validate_component(part: str):
    if part in ("..", ".") or any(c in '<>:"|?*' or ord(c) < 32 for c in part) or part.endswith((".", " ")) or part.split(".", 1)[0].upper() in _RESERVED:
        raise BoundaryError("Invalid path component")


def contained(root: Path, path: Path, *, exists: bool = True) -> Path:
    root = root.resolve(strict=True)
    # Validate spelling before Windows GetFullPathName normalizes trailing dots.
    for part in path.parts[1:] if path.anchor else path.parts:
        _validate_component(part)
    absolute = Path(os.path.abspath(path))
    if not absolute.is_relative_to(root):
        raise BoundaryError("Target must remain within its authorized workspace")
    # Reject all link/reparse traversal, even links that currently resolve inside.
    current = root
    for part in absolute.relative_to(root).parts:
        _validate_component(part)
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if exists:
                raise BoundaryError("Target does not exist") from None
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BoundaryError("Links, junctions and reparse points are not scan targets")
    resolved = absolute.resolve(strict=exists)
    if not resolved.is_relative_to(root):
        raise BoundaryError("Target escaped its authorized workspace")
    return resolved


def relative_target(root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or path.drive or ".." in path.parts:
        raise BoundaryError("Provide a relative path within the workspace")
    return contained(root, root / path)


def read_source(root: Path, path: Path) -> bytes:
    path = contained(root, path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
        raise BoundaryError("Source must be a regular file no larger than 2 MiB")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise BoundaryError("Source changed while opening")
        contained(root, path)
        data = source.read(MAX_FILE_BYTES + 1)
        after = os.fstat(source.fileno())
    if len(data) > MAX_FILE_BYTES or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise BoundaryError("Source changed or exceeded its size limit")
    return data
