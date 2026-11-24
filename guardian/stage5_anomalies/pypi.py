"""PyPI JSON API client for Stage 5 (metadata, release history, files, published hashes, downloads).

``GUARDIAN_PYPI_URL`` (default https://pypi.org/pypi) may also be a local folder or ``file://`` URL laid
out like the JSON API (``<name>/json``, ``<name>/<version>/json``), e.g. the fixture's ``fake-pypi/pypi``.
Relative file URLs resolve against the index root. Downloads are verified against the published sha256
before anything is passed to the sandbox.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urljoin, urlparse

from guardian.purl import normalize_name
from guardian.stage4_vulns.sources import HttpCache, USER_AGENT

DEFAULT = "https://pypi.org/pypi"


class PyPIClient:
    def __init__(self, cache: HttpCache, base: Optional[str] = None, dist_dir: Optional[Path] = None):
        self.cache = cache
        self.base = (base or os.environ.get("GUARDIAN_PYPI_URL") or DEFAULT).rstrip("/")
        self.dist_dir = Path(dist_dir or cache.root / "dists")
        self.errors: list[str] = []
        p = urlparse(self.base)
        self.local: Optional[Path] = None
        if p.scheme == "file":
            self.local = Path(unquote(p.path.lstrip("/") if os.name == "nt" else p.path))
        elif p.scheme in ("", None) or (len(p.scheme) == 1 and os.name == "nt"):
            self.local = Path(self.base)

    @property
    def source(self) -> str:
        return str(self.local) if self.local else self.base

    def _json(self, rel: str) -> Optional[dict]:
        if self.local:
            p = self.local / rel / "json"
            if not p.exists():
                return None
            import json
            return json.loads(p.read_text(encoding="utf-8"))
        data = self.cache.fetch_json(f"{self.base}/{rel}/json", max_age=24 * 3600)
        if not data or data.get("__status") == 404:
            return None
        return data

    def project(self, name: str) -> Optional[dict]:
        return self._json(normalize_name(name))

    def release(self, name: str, version: str) -> Optional[dict]:
        return self._json(f"{normalize_name(name)}/{version}")

    def files(self, name: str, version: str) -> list[dict]:
        rel = self.release(name, version)
        if rel and rel.get("urls"):
            return rel["urls"]
        proj = self.project(name) or {}
        return (proj.get("releases") or {}).get(version, []) or []

    def hashes(self, name: str, version: str) -> set[str]:
        return {f.get("digests", {}).get("sha256") for f in self.files(name, version) if f.get("digests")} - {None}

    def _url(self, url: str) -> str:
        if urlparse(url).scheme in ("http", "https", "file"):
            return url
        root = (self.local.parent.as_uri() + "/") if self.local else self.base.rsplit("/", 1)[0] + "/"
        return urljoin(root, url)

    def download(self, name: str, version: str, prefer: Optional[str] = None) -> tuple[Optional[Path], dict, Optional[str]]:
        """Download one file of a release (``prefer``: sdist | bdist_wheel). Returns (path, file entry, error)."""
        files = self.files(name, version)
        if prefer:
            files = sorted(files, key=lambda f: f.get("packagetype") != prefer)
        if not files:
            return None, {}, f"no files published for {name} {version}"
        f = files[0]
        sha = (f.get("digests") or {}).get("sha256")
        url = f.get("url")
        if not url:
            return None, f, "no download URL"
        dest = self.dist_dir / f"{sha or 'nosha'}-{f['filename']}"
        if not dest.exists():
            full = self._url(url)
            try:
                if full.startswith("file:"):
                    p = Path(unquote(urlparse(full).path.lstrip("/") if os.name == "nt" else urlparse(full).path))
                    data = p.read_bytes()
                else:
                    if self.cache.offline:
                        return None, f, "offline: distribution not downloaded"
                    import httpx
                    r = httpx.get(full, timeout=60, follow_redirects=True, headers={"User-Agent": USER_AGENT})
                    r.raise_for_status()
                    data = r.content
            except Exception as exc:
                return None, f, f"download failed: {exc}"[:200]
            if sha and hashlib.sha256(data).hexdigest() != sha:
                return None, f, "sha256 does not match the published hash: refused"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        return dest, f, None
