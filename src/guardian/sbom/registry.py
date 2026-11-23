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


def _iso_ms(ms: int | None) -> str | None:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat() if ms else None


def crates_metadata(http: CachedHttp, name: str, version: str | None) -> PackageMetadata:
    data, src = http.request_json("GET", f"https://crates.io/api/v1/crates/{quote(name)}")
    if not data:
        return PackageMetadata(status=src)
    crate, vers = data.get("crate") or {}, data.get("versions") or []
    v = next((x for x in vers if x.get("num") == version), {})
    repo = crate.get("repository")
    return PackageMetadata(version_uploaded=v.get("created_at"), first_release=crate.get("created_at"),
                           release_count=len(vers), project_urls={k: crate[k] for k in ("homepage", "repository", "documentation") if crate.get(k)},
                           source_repo=_repo_url({"repository": repo}) if repo else None, yanked=v.get("yanked"),
                           registry_hashes=[f"sha256:{v['checksum']}"] if v.get("checksum") else [], status=src)


def rubygems_metadata(http: CachedHttp, name: str, version: str | None) -> PackageMetadata:
    vers, src = http.request_json("GET", f"https://rubygems.org/api/v1/versions/{quote(name)}.json")
    if not vers:
        return PackageMetadata(status=src)
    info, _ = http.request_json("GET", f"https://rubygems.org/api/v1/gems/{quote(name)}.json")
    info = info or {}
    v = next((x for x in vers if x.get("number") == version), {})
    urls = {k: info[k] for k in ("source_code_uri", "homepage_uri", "project_uri") if info.get(k)}
    return PackageMetadata(version_uploaded=v.get("created_at"), first_release=min((x.get("created_at") for x in vers if x.get("created_at")), default=None),
                           release_count=len(vers), maintainers=[info["authors"]] if info.get("authors") else [],
                           project_urls=urls, source_repo=_repo_url(urls), status=src,
                           registry_hashes=[f"sha256:{v['sha']}"] if v.get("sha") else [])


def packagist_metadata(http: CachedHttp, name: str, version: str | None) -> PackageMetadata:
    data, src = http.request_json("GET", f"https://repo.packagist.org/p2/{name}.json")
    vers = ((data or {}).get("packages") or {}).get(name) or []
    if not vers:
        return PackageMetadata(status=src)
    v = next((x for x in vers if str(x.get("version", "")).lstrip("v") == (version or "").lstrip("v")), {})
    repo = ((v or vers[0]).get("source") or {}).get("url")
    return PackageMetadata(version_uploaded=v.get("time"), first_release=min((x.get("time") for x in vers if x.get("time")), default=None),
                           release_count=len(vers), maintainers=[a.get("name", "") for a in (vers[0].get("authors") or [])][:5],
                           source_repo=_repo_url({"repository": repo}) if repo else None, status=src)


def go_metadata(http: CachedHttp, module: str, version: str | None) -> PackageMetadata:
    esc = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)
    data, src = http.request_json("GET", f"https://proxy.golang.org/{esc}/@v/{version}.info") if version else (None, "unavailable")
    m = _HOST_REPO.search(module)
    return PackageMetadata(version_uploaded=(data or {}).get("Time"),
                           source_repo=f"https://{m.group(1)}/{m.group(2)}/{m.group(3)}" if m else None,
                           status=src if data else "unavailable")


def nuget_metadata(http: CachedHttp, name: str, version: str | None) -> PackageMetadata:
    data, src = http.request_json("GET", f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/index.json")
    if not data:
        return PackageMetadata(status=src)
    return PackageMetadata(release_count=len(data.get("versions") or []), status=src)


def maven_metadata(http: CachedHttp, name: str, version: str | None) -> PackageMetadata:
    g, _, a = name.partition(":")
    data, src = http.request_json("GET", f"https://search.maven.org/solrsearch/select?q=g:%22{quote(g)}%22+AND+a:%22{quote(a)}%22&rows=1&wt=json")
    docs = (((data or {}).get("response") or {}).get("docs")) or []
    if not docs:
        return PackageMetadata(status=src if data is not None else "unavailable")
    d = docs[0]
    return PackageMetadata(release_count=d.get("versionCount"), status=src,
                           project_urls={"latest": f"{name}:{d.get('latestVersion')}", "latest_published": _iso_ms(d.get("timestamp")) or ""})


FETCHERS = {"pypi": lambda h, c: pypi_metadata(h, c.name, c.version), "npm": lambda h, c: npm_metadata(h, c.name, c.version),
            "cargo": lambda h, c: crates_metadata(h, c.name, c.version), "gem": lambda h, c: rubygems_metadata(h, c.name, c.version),
            "composer": lambda h, c: packagist_metadata(h, c.name, c.version), "golang": lambda h, c: go_metadata(h, c.name, c.version),
            "nuget": lambda h, c: nuget_metadata(h, c.name, c.version), "maven": lambda h, c: maven_metadata(h, c.name, c.version)}


def fetch_metadata(components: list[Component], http: CachedHttp, max_workers: int = 8) -> tuple[dict[str, PackageMetadata], list[str]]:
    errors: list[str] = []

    def one(c: Component) -> tuple[str, PackageMetadata]:
        try:
            if c.ecosystem in FETCHERS:
                return c.purl, FETCHERS[c.ecosystem](http, c)
        except CacheMiss:
            return c.purl, PackageMetadata(status="unavailable")
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as e:
            errors.append(f"registry metadata {c.purl}: {type(e).__name__}")
        return c.purl, PackageMetadata(status="unavailable")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = dict(ex.map(one, components))
    return results, errors
