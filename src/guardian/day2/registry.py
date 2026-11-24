"""Registry facts for remediation: available versions, per-version dependencies, integrity, publisher.

Live sources (cached through CachedHttp, so the Day 1 cache is reused): npm packuments, PyPI JSON API.
Offline: the HTTP cache, or a registry snapshot file (`Settings.registry_snapshot`) with the shape
  {"npm": {"<name>": {"versions": {"<v>": {"dependencies": {..}, "integrity": .., "tarball": .., "published": ..,
                                           "publisher": .., "provenance": bool}}, "maintainers": [..], "created": ..}},
   "pypi": {...same...}}
Unknown stays unknown: every method returns None when the data is not available.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import httpx
from packaging.requirements import InvalidRequirement, Requirement

from ..httpcache import CacheMiss, CachedHttp
from ..purl import normalize_name

NPM = "https://registry.npmjs.org"
PYPI = "https://pypi.org/pypi"


class RegistryClient:
    def __init__(self, http: CachedHttp, snapshot: Path | None = None):
        self.http = http
        self.snapshot: dict = {}
        if snapshot and Path(snapshot).is_file():
            self.snapshot = json.loads(Path(snapshot).read_text(encoding="utf-8"))
        self.notes: list[str] = []
        self._docs: dict[tuple[str, str], dict | None] = {}

    # ----------------------------------------------------------------- raw documents
    def _snap(self, eco: str, name: str) -> dict | None:
        pkgs = self.snapshot.get(eco) or {}
        n = normalize_name(eco, name)
        for k, v in pkgs.items():
            if normalize_name(eco, k) == n:
                return v
        return None

    def _doc(self, eco: str, name: str) -> dict | None:
        key = (eco, normalize_name(eco, name))
        if key in self._docs:
            return self._docs[key]
        doc = self._snap(eco, name)
        if doc is None:
            try:
                if eco == "npm":
                    raw, _ = self.http.request_json("GET", f"{NPM}/{quote(name, safe='@').replace('/', '%2F')}")
                    doc = self._from_npm(raw) if raw else None
                elif eco == "pypi":
                    raw, _ = self.http.request_json("GET", f"{PYPI}/{quote(name)}/json")
                    doc = self._from_pypi(raw) if raw else None
            except (CacheMiss, httpx.HTTPError, ValueError) as e:
                self.notes.append(f"registry data for {eco}/{name} unavailable ({type(e).__name__})")
                doc = None
        self._docs[key] = doc
        return doc

    @staticmethod
    def _from_npm(raw: dict) -> dict:
        times = raw.get("time") or {}
        vers = {}
        for v, meta in (raw.get("versions") or {}).items():
            dist = meta.get("dist") or {}
            vers[v] = {"dependencies": meta.get("dependencies") or {}, "integrity": dist.get("integrity"),
                       "tarball": dist.get("tarball"), "published": times.get(v),
                       "publisher": (meta.get("_npmUser") or {}).get("name"),
                       "maintainers": [m.get("name") for m in meta.get("maintainers") or [] if isinstance(m, dict)],
                       "provenance": bool(dist.get("attestations")) if dist else None,
                       "deprecated": bool(meta.get("deprecated")),
                       "has_install_script": bool(meta.get("hasInstallScript")) or any(
                           k in (meta.get("scripts") or {}) for k in ("preinstall", "install", "postinstall")),
                       "repository": (meta.get("repository") or {}).get("url") if isinstance(meta.get("repository"), dict) else meta.get("repository")}
        return {"versions": vers, "created": times.get("created"),
                "maintainers": [m.get("name") for m in raw.get("maintainers") or [] if isinstance(m, dict)]}

    @staticmethod
    def _from_pypi(raw: dict) -> dict:
        vers = {}
        for v, files in (raw.get("releases") or {}).items():
            if not files:
                continue
            up = min((f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")), default=None)
            sha = [f"sha256:{f['digests']['sha256']}" for f in files if (f.get("digests") or {}).get("sha256")]
            vers[v] = {"dependencies": None, "integrity": sha[0] if sha else None, "hashes": sha, "published": up,
                       "yanked": all(f.get("yanked") for f in files), "provenance": None,
                       "tarball": next((f.get("url") for f in files if f.get("packagetype") == "sdist"), None),
                       "wheel": next((f.get("url") for f in files if f.get("packagetype") == "bdist_wheel"), None)}
        info = raw.get("info") or {}
        return {"versions": vers, "maintainers": [m for m in (info.get("maintainer"), info.get("author")) if m]}

    # ----------------------------------------------------------------- queries
    def versions(self, eco: str, name: str, include_yanked: bool = False) -> list[str] | None:
        doc = self._doc(eco, name)
        if not doc:
            return None
        return [v for v, m in (doc.get("versions") or {}).items()
                if include_yanked or not (m or {}).get("yanked") and not (m or {}).get("deprecated")]

    def info(self, eco: str, name: str, version: str) -> dict | None:
        doc = self._doc(eco, name)
        if not doc:
            return None
        meta = (doc.get("versions") or {}).get(version)
        if meta is None:
            return None
        if eco == "pypi" and meta.get("dependencies") is None and not self.snapshot:
            try:
                raw, _ = self.http.request_json("GET", f"{PYPI}/{quote(name)}/{quote(version)}/json")
                deps = {}
                for r in ((raw or {}).get("info") or {}).get("requires_dist") or []:
                    try:
                        req = Requirement(r)
                    except InvalidRequirement:
                        continue
                    if req.marker and "extra" in str(req.marker):
                        continue
                    deps[req.name] = str(req.specifier) or "*"
                meta = {**meta, "dependencies": deps}
            except (CacheMiss, httpx.HTTPError, ValueError):
                pass
        return meta

    def package(self, eco: str, name: str) -> dict | None:
        return self._doc(eco, name)

    def tarball_url(self, eco: str, name: str, version: str) -> str | None:
        meta = self.info(eco, name, version) or {}
        if meta.get("tarball"):
            return meta["tarball"]
        if eco == "npm":
            base = name.split("/")[-1]
            return f"{NPM}/{name}/-/{base}-{version}.tgz"
        return None
