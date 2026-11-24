"""Safe archive extraction (docs/stage5.md section 3). Parse-only: nothing extracted is ever executed.

Rejects absolute paths, ``..``, symlinks/hardlinks, device files; enforces archive size, total size,
file count, depth and a decompression-ratio (zip bomb) guard.
"""
from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 50 * 1024 * 1024
MAX_TOTAL = 200 * 1024 * 1024
MAX_FILES = 5000
MAX_DEPTH = 10
MAX_RATIO = 100


class UnsafeArchive(Exception):
    pass


def _check_name(name: str) -> PurePosixPath:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchive(f"absolute path {name!r}")
    if ".." in p.parts:
        raise UnsafeArchive(f"path traversal {name!r}")
    if len(p.parts) > MAX_DEPTH:
        raise UnsafeArchive(f"too deep {name!r}")
    return p


def safe_extract(archive: Path, dest: Path) -> list[str]:
    """Extract ``archive`` (.whl/.zip/.tar.gz/.tgz) into ``dest``; returns relative file paths."""
    archive, dest = Path(archive), Path(dest)
    size = archive.stat().st_size
    if size > MAX_ARCHIVE:
        raise UnsafeArchive(f"archive larger than {MAX_ARCHIVE} bytes")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    out: list[str] = []
    total = 0

    def target(p: PurePosixPath) -> Path:
        t = (root / Path(*p.parts)).resolve()
        if not t.is_relative_to(root):
            raise UnsafeArchive(f"escapes destination {p}")
        return t

    name = archive.name.lower()
    if name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            if len(infos) > MAX_FILES:
                raise UnsafeArchive("too many files")
            declared = sum(i.file_size for i in infos)
            if declared > MAX_TOTAL or (size and declared / size > MAX_RATIO):
                raise UnsafeArchive("decompression ratio or total size too large")
            for i in infos:
                p = _check_name(i.filename)
                if i.is_dir():
                    continue
                if (i.external_attr >> 16) & 0o170000 == 0o120000:
                    raise UnsafeArchive(f"symlink {i.filename!r}")
                data = z.read(i)
                total += len(data)
                if total > MAX_TOTAL:
                    raise UnsafeArchive("extracted size too large")
                t = target(p)
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(data)
                out.append(p.as_posix())
    elif name.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            if len(members) > MAX_FILES:
                raise UnsafeArchive("too many files")
            for mbr in members:
                p = _check_name(mbr.name)
                if mbr.issym() or mbr.islnk():
                    raise UnsafeArchive(f"link {mbr.name!r}")
                if mbr.isdev() or mbr.ischr() or mbr.isblk() or mbr.isfifo():
                    raise UnsafeArchive(f"device file {mbr.name!r}")
                if mbr.isdir():
                    continue
                total += mbr.size
                if total > MAX_TOTAL or (size and total / size > MAX_RATIO):
                    raise UnsafeArchive("extracted size or ratio too large")
                f = tar.extractfile(mbr)
                if f is None:
                    continue
                t = target(p)
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(f.read())
                out.append(p.as_posix())
    else:
        raise UnsafeArchive(f"unsupported archive type {archive.name}")
    return out
