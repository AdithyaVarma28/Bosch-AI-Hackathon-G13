from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional
import httpx

from guardian.models.facts import PackageMetadata, ResolvedPackage

CACHE_DIR = Path(".guardian_cache") / "pypi"


def get_cache_path(name: str, version: str) -> Path:
    safe_name = f"{name.lower()}_{version}.json"
    return CACHE_DIR / safe_name


def fetch_pypi_metadata(
    resolved_packages: List[ResolvedPackage],
    offline: bool = False
) -> Dict[str, PackageMetadata]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    metadata_map: Dict[str, PackageMetadata] = {}

    client = httpx.Client(timeout=10.0, follow_redirects=True) if not offline else None

    for pkg in resolved_packages:
        cache_file = get_cache_path(pkg.name, pkg.version)
        data = None

        if cache_file.is_file():
            try:
                with open(cache_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                data = None

        if data is None and client and not offline:
            url = f"https://pypi.org/pypi/{pkg.name}/{pkg.version}/json"
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    with open(cache_file, "w", encoding="utf-8") as fh:
                        json.dump(data, fh)
            except Exception:
                data = None

        if data:
            info = data.get("info", {})
            releases = data.get("releases", {})
            urls = data.get("urls", [])

            # Extract upload date for this version
            version_uploaded = None
            if urls:
                version_uploaded = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time")

            # Extract first release date
            first_release = None
            for ver, ver_urls in releases.items():
                if ver_urls:
                    dt = ver_urls[0].get("upload_time_iso_8601") or ver_urls[0].get("upload_time")
                    if dt and (first_release is None or dt < first_release):
                        first_release = dt

            # Hashes from PyPI
            pypi_hashes = []
            for u in urls:
                digests = u.get("digests", {})
                if "sha256" in digests:
                    pypi_hashes.append(f"sha256:{digests['sha256']}")

            # Check if only sdist exists
            packagetypes = {u.get("packagetype") for u in urls}
            sdist_only = "bdist_wheel" not in packagetypes and "sdist" in packagetypes

            metadata_map[pkg.purl] = PackageMetadata(
                version_uploaded=version_uploaded,
                first_release=first_release,
                release_count=len(releases),
                maintainers=[info.get("author") or info.get("maintainer") or "unknown"],
                project_urls=info.get("project_urls") or {},
                yanked=bool(info.get("yanked", False)),
                sdist_only=sdist_only,
                hashes=pypi_hashes
            )
        else:
            # Fallback when offline or not found
            metadata_map[pkg.purl] = PackageMetadata(
                hashes=pkg.hashes
            )

    if client:
        client.close()

    return metadata_map
