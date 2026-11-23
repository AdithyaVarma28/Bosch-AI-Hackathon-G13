"""Registry metadata: "where each component originates" (PyPI JSON API, npm registry)."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import httpx

from ..httpcache import CacheMiss, CachedHttp
from ..models import Component, PackageMetadata

PYPI = "https://pypi.org/pypi"
NPM = "https://registry.npmjs.org"


_HOST_REPO = re.compile(r"(github\.com|gitlab\.com|bitbucket\.org)[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?]|$)")


def _repo_url(urls: dict[str, str]) -> str | None:
    preferred = [urls.get(k) for k in ("Source", "Source Code", "Repository", "Code", "source", "repository")]
    for v in [u for u in preferred if u] + list(urls.values()):
        m = _HOST_REPO.search(v or "")
        if m:
            return f"https://{m.group(1)}/{m.group(2)}/{m.group(3)}"
    return next((u for u in preferred if u), None)


def pypi_metadata(http: CachedHttp, name: str, version: str | None) -> PackageMetadata:
    data, src = http.request_json("GET", f"{PYPI}/{quote(name)}/json")
    if not data:
        return PackageMetadata(status=src)
    info = data.get("info") or {}
    releases = data.get("releases") or {}
    uploads = [f.get("upload_time_iso_8601") for files in releases.values() for f in files if f.get("upload_time_iso_8601")]
    files = releases.get(version or "", []) if version else []
    urls = {k: v for k, v in (info.get("project_urls") or {}).items() if v}
    if info.get("home_page"):
        urls.setdefault("Homepage", info["home_page"])
    maint = [m for m in (info.get("maintainer"), info.get("author"), info.get("author_email")) if m]
    return PackageMetadata(
        version_uploaded=min((f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")), default=None),
        first_release=min(uploads) if uploads else None,
        release_count=len([v for v, fs in releases.items() if fs]),
        maintainers=maint[:5], project_urls=urls, source_repo=_repo_url(urls),
        yanked=any(f.get("yanked") for f in files) if files else None,
        sdist_only=(all(f.get("packagetype") == "sdist" for f in files) if files else None),
        registry_hashes=[f"sha256:{f['digests']['sha256']}" for f in files if (f.get("digests") or {}).get("sha256")],
        status=src)


def npm_metadata(http: CachedHttp, name: str, version: str | None) -> PackageMetadata:
    path = quote(name, safe="@") .replace("/", "%2F")
    data, src = http.request_json("GET", f"{NPM}/{path}")
    if not data:
        return PackageMetadata(status=src)
    times = data.get("time") or {}
    vers = data.get("versions") or {}
    v = vers.get(version or "") or {}
    repo = data.get("repository") or v.get("repository")
    repo_url = repo.get("url") if isinstance(repo, dict) else repo
    repo_url = _repo_url({"repository": repo_url}) if repo_url else None
    created = times.get("created")
    dist = v.get("dist") or {}
    return PackageMetadata(
        version_uploaded=times.get(version) if version else None, first_release=created,
        release_count=len(vers), maintainers=[m.get("name", "") for m in data.get("maintainers") or []][:10],
        project_urls={k: x for k, x in {"homepage": data.get("homepage"), "repository": repo_url}.items() if x},
        source_repo=repo_url, deprecated=bool(v.get("deprecated")) if v else None,
        registry_hashes=[dist["integrity"]] if dist.get("integrity") else [], status=src)


def fetch_metadata(components: list[Component], http: CachedHttp, max_workers: int = 8) -> tuple[dict[str, PackageMetadata], list[str]]:
    errors: list[str] = []

    def one(c: Component) -> tuple[str, PackageMetadata]:
        try:
            if c.ecosystem == "pypi":
                return c.purl, pypi_metadata(http, c.name, c.version)
            if c.ecosystem == "npm":
                return c.purl, npm_metadata(http, c.name, c.version)
        except CacheMiss:
            return c.purl, PackageMetadata(status="unavailable")
        except (httpx.HTTPError, ValueError) as e:
            errors.append(f"registry metadata {c.purl}: {type(e).__name__}")
        return c.purl, PackageMetadata(status="unavailable")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = dict(ex.map(one, components))
    return results, errors
