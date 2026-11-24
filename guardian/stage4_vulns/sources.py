"""Vulnerability data sources (docs/stage4.md section 2). Deterministic: no AI touches these values.

* OSV.dev API: ``POST /v1/querybatch`` (purls -> ids) then ``GET /v1/vulns/{id}`` (full records).
* OSV PyPI dump (``all.zip``) for offline scans: indexed once per download, matched locally with the
  same OSV range semantics.
* CISA KEV (actively exploited), EPSS (exploit probability), CVSS vectors scored with the ``cvss`` library.
* Grype for container images and SBOMs (optional binary).

Every network response is cached on disk (``<cache>/vulndb``). ``offline=True`` never touches the
network and only uses the dump and earlier cached responses.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from packaging.version import InvalidVersion, Version

from guardian.purl import normalize_name

from .schema import CVSS, EPSS, AffectedRange, Reference, band_of

OSV_API = "https://api.osv.dev/v1"
OSV_DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
DAY = 24 * 3600
USER_AGENT = "guardian-supply-chain-scanner/0.1"


def default_cache_dir() -> Path:
    return Path(os.environ.get("GUARDIAN_VULNDB") or ".guardian_cache/vulndb")


class SourceError(Exception):
    pass


class HttpCache:
    """GET/POST JSON with an on-disk cache. Offline: cache only."""

    def __init__(self, root: Path, offline: bool = False, timeout: float = 30.0):
        self.root = Path(root)
        self.offline = offline
        self.timeout = timeout
        self.errors: list[str] = []
        self.network_calls = 0
        self.cache_hits = 0

    def _path(self, key: str) -> Path:
        h = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.root / "http" / h[:2] / f"{h}.json"

    def get_cached(self, key: str, max_age: Optional[float] = None) -> Optional[Any]:
        p = self._path(key)
        if not p.exists():
            return None
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if max_age is not None and not self.offline and time.time() - doc.get("fetched", 0) > max_age:
            return None
        self.cache_hits += 1
        return doc.get("data")

    def put(self, key: str, data: Any) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"fetched": time.time(), "data": data}), encoding="utf-8")

    def fetch_json(self, url: str, *, key: Optional[str] = None, body: Optional[dict] = None,
                   max_age: Optional[float] = None, params: Optional[dict] = None) -> Optional[Any]:
        key = key or f"{url}|{json.dumps(params, sort_keys=True) if params else ''}|{json.dumps(body, sort_keys=True) if body else ''}"
        cached = self.get_cached(key, max_age)
        if cached is not None:
            return cached
        if self.offline:
            return None
        import httpx
        try:
            self.network_calls += 1
            with httpx.Client(timeout=self.timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as c:
                r = c.post(url, json=body) if body is not None else c.get(url, params=params)
            if r.status_code == 404:
                self.put(key, {"__status": 404})
                return {"__status": 404}
            r.raise_for_status()
            data = r.json()
        except Exception as exc:  # network failure must not stop the scan
            self.errors.append(f"{url}: {type(exc).__name__}: {exc}"[:300])
            return None
        self.put(key, data)
        return data

    def fetch_text(self, url: str, max_bytes: int = 400_000) -> Optional[str]:
        key = f"text|{url}"
        cached = self.get_cached(key)
        if cached is not None:
            return cached
        if self.offline:
            return None
        import httpx
        try:
            self.network_calls += 1
            with httpx.Client(timeout=self.timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as c:
                r = c.get(url)
            if r.status_code != 200:
                return None
            text = r.text[:max_bytes]
        except Exception as exc:
            self.errors.append(f"{url}: {type(exc).__name__}: {exc}"[:300])
            return None
        self.put(key, text)
        return text


# --------------------------------------------------------------------------- versions + ranges

def parse_version(v: Optional[str]) -> Optional[Version]:
    if v in (None, ""):
        return None
    try:
        return Version(str(v))
    except InvalidVersion:
        return None


def version_in_events(version: Version, events: list[dict]) -> bool:
    """OSV ECOSYSTEM range semantics: introduced / fixed / last_affected events in version order."""
    def key(ev: dict):
        kind, val = next(iter(ev.items()))
        if val == "0":
            return (Version("0"), 0)
        pv = parse_version(val)
        return (pv or Version("0"), {"introduced": 0, "fixed": 1, "last_affected": 2, "limit": 3}.get(kind, 4))

    affected = False
    for ev in sorted((e for e in events if e), key=key):
        kind, val = next(iter(ev.items()))
        pv = Version("0") if val == "0" else parse_version(val)
        if pv is None:
            continue
        if kind == "introduced" and version >= pv:
            affected = True
        elif kind == "fixed" and version >= pv:
            affected = False
        elif kind == "last_affected" and version > pv:
            affected = False
    return affected


def affected_entries(record: dict, name: str, ecosystem: str = "PyPI") -> list[dict]:
    n = normalize_name(name)
    return [a for a in record.get("affected", []) or []
            if (a.get("package") or {}).get("ecosystem") == ecosystem
            and normalize_name((a.get("package") or {}).get("name", "")) == n]


def is_affected(record: dict, name: str, version: str) -> bool:
    pv = parse_version(version)
    for a in affected_entries(record, name):
        if version in (a.get("versions") or []):
            return True
        if pv is None:
            continue
        for rng in a.get("ranges") or []:
            if rng.get("type") in ("ECOSYSTEM", "SEMVER") and version_in_events(pv, rng.get("events") or []):
                return True
    return False


def ranges_and_fixes(record: dict, name: str) -> tuple[list[AffectedRange], list[str]]:
    ranges: list[AffectedRange] = []
    fixes: list[str] = []
    for a in affected_entries(record, name):
        for rng in a.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            cur: dict[str, Optional[str]] = {}
            for ev in rng.get("events") or []:
                kind, val = next(iter(ev.items()))
                if kind == "introduced":
                    if cur:
                        ranges.append(AffectedRange(**cur))
                    cur = {"introduced": val}
                elif kind in ("fixed", "last_affected"):
                    cur[kind] = val
                    if kind == "fixed":
                        fixes.append(val)
                    ranges.append(AffectedRange(**cur))
                    cur = {}
            if cur:
                ranges.append(AffectedRange(**cur))
    fixes = sorted(set(fixes), key=lambda v: parse_version(v) or Version("0"))
    return ranges, fixes


# --------------------------------------------------------------------------- CVSS

def score_vector(vector: str) -> tuple[Optional[float], Optional[str]]:
    """Base score of a CVSS v2/v3/v4 vector string (``cvss`` library)."""
    try:
        import cvss
    except ImportError:
        return None, None
    try:
        if vector.startswith("CVSS:4"):
            return float(cvss.CVSS4(vector).base_score), "4.0"
        if vector.startswith("CVSS:3"):
            return float(cvss.CVSS3(vector).scores()[0]), vector.split("/")[0].split(":")[1]
        return float(cvss.CVSS2(vector).scores()[0]), "2.0"
    except Exception:
        return None, None


DB_SEVERITY_BAND = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def cvss_from_record(record: dict) -> CVSS:
    best: Optional[CVSS] = None
    order = {"CVSS_V3": 0, "CVSS_V4": 1, "CVSS_V2": 2}
    for sev in sorted(record.get("severity") or [], key=lambda s: order.get(s.get("type"), 9)):
        vec = sev.get("score") or ""
        if not vec.startswith("CVSS") and sev.get("type") != "CVSS_V2":
            continue
        score, ver = score_vector(vec)
        if score is not None:
            best = CVSS(vector=vec, score=score, band=band_of(score), version=ver, source=record.get("id"))
            break
    if best:
        return best
    db = ((record.get("database_specific") or {}).get("severity") or "").upper()
    if db in DB_SEVERITY_BAND:
        return CVSS(band=DB_SEVERITY_BAND[db], source=f"{record.get('id')} (database severity)")
    return CVSS(source=record.get("id"))


def better_cvss(a: CVSS, b: CVSS) -> CVSS:
    """Prefer a scored vector, then a GHSA source, then the higher score."""
    def rank(c: CVSS):
        return (c.score is not None, bool(c.source and c.source.startswith("GHSA")), c.score or 0,
                c.band not in ("unknown",))
    return a if rank(a) >= rank(b) else b


# --------------------------------------------------------------------------- OSV

ID_PREFERENCE = ("GHSA-", "PYSEC-", "CVE-")


def preferred_id(ids: Iterable[str]) -> str:
    ids = sorted(set(ids))
    for prefix in ID_PREFERENCE:
        for i in ids:
            if i.startswith(prefix):
                return i
    return ids[0]


class OSVClient:
    def __init__(self, cache: HttpCache, dump_path: Optional[Path] = None, prefer_dump: bool = False):
        self.cache = cache
        self.dump_path = Path(dump_path) if dump_path else None
        if self.dump_path is None and os.environ.get("GUARDIAN_OSV_DUMP"):
            self.dump_path = Path(os.environ["GUARDIAN_OSV_DUMP"])
        if self.dump_path is None:
            default = cache.root / "osv-PyPI-all.zip"
            self.dump_path = default if default.exists() else None
        self.prefer_dump = prefer_dump
        self.mode = "none"
        self.notes: list[str] = []
        self._index: Optional[dict[str, list[str]]] = None

    @property
    def dump_available(self) -> bool:
        return bool(self.dump_path and self.dump_path.exists())

    # -------------------------------------------------------------- public
    def query(self, packages: list[tuple[str, str]]) -> dict[tuple[str, str], list[dict]]:
        """{(name, version): [OSV records affecting that version]}"""
        if not packages:
            return {}
        if self.dump_available and (self.cache.offline or self.prefer_dump):
            self.mode = "osv-dump"
            return self._from_dump(packages)
        if self.cache.offline:
            self.mode = "none"
            self.notes.append("offline and no OSV dump: Python packages were not checked "
                              "(run `guardian vulndb download` while online)")
            return {}
        res = self._from_api(packages)
        if res is None:
            if self.dump_available:
                self.notes.append("OSV API unreachable: used the local OSV dump")
                self.mode = "osv-dump"
                return self._from_dump(packages)
            self.mode = "none"
            self.notes.append("OSV API unreachable and no local dump")
            return {}
        self.mode = "osv"
        return res

    # -------------------------------------------------------------- API
    def _from_api(self, packages: list[tuple[str, str]]) -> Optional[dict]:
        out: dict[tuple[str, str], list[dict]] = {}
        ids_for: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for i in range(0, len(packages), 500):
            chunk = packages[i:i + 500]
            body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]}
            # querybatch answers change as advisories are published: cache for a day only
            data = self.cache.fetch_json(f"{OSV_API}/querybatch", body=body, max_age=DAY)
            if not data or "results" not in data:
                return None
            for (n, v), res in zip(chunk, data["results"]):
                ids_for[(n, v)] = [(x["id"], x.get("modified", "")) for x in res.get("vulns", []) or []]
        wanted = {vid: mod for lst in ids_for.values() for vid, mod in lst}

        def fetch(item):
            vid, mod = item
            return vid, self.cache.fetch_json(f"{OSV_API}/vulns/{vid}", key=f"osv|{vid}|{mod}")

        with ThreadPoolExecutor(8) as ex:
            records = {vid: rec for vid, rec in ex.map(fetch, wanted.items()) if rec and "id" in rec}
        for key, lst in ids_for.items():
            out[key] = [records[vid] for vid, _ in lst if vid in records]
        return out

    # -------------------------------------------------------------- dump
    def _index_path(self) -> Path:
        st = self.dump_path.stat()
        tag = hashlib.sha256(f"{self.dump_path.resolve()}|{st.st_size}|{int(st.st_mtime)}".encode()).hexdigest()[:12]
        return self.cache.root / f"osv-index-{tag}.json"

    def _load_index(self) -> dict[str, list[str]]:
        if self._index is not None:
            return self._index
        ip = self._index_path()
        if ip.exists():
            self._index = json.loads(ip.read_text(encoding="utf-8"))
            return self._index
        index: dict[str, list[str]] = {}
        with zipfile.ZipFile(self.dump_path) as z:
            for name in z.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    rec = json.loads(z.read(name))
                except (json.JSONDecodeError, KeyError):
                    continue
                for a in rec.get("affected") or []:
                    pkg = a.get("package") or {}
                    if pkg.get("ecosystem") == "PyPI" and pkg.get("name"):
                        index.setdefault(normalize_name(pkg["name"]), []).append(name)
        ip.parent.mkdir(parents=True, exist_ok=True)
        ip.write_text(json.dumps(index), encoding="utf-8")
        self._index = index
        return index

    def _from_dump(self, packages: list[tuple[str, str]]) -> dict:
        index = self._load_index()
        out: dict[tuple[str, str], list[dict]] = {}
        with zipfile.ZipFile(self.dump_path) as z:
            for n, v in packages:
                recs = []
                for entry in dict.fromkeys(index.get(normalize_name(n), [])):
                    try:
                        rec = json.loads(z.read(entry))
                    except (json.JSONDecodeError, KeyError):
                        continue
                    if rec.get("withdrawn"):
                        continue
                    if is_affected(rec, n, v):
                        recs.append(rec)
                out[(n, v)] = recs
        return out


def download_dump(dest: Path, url: str = OSV_DUMP_URL, log: Callable[[str], None] = print) -> Path:
    import httpx
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".part")
    with httpx.stream("GET", url, timeout=120, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as r:
        r.raise_for_status()
        total = 0
        with open(tmp, "wb") as fh:
            for chunk in r.iter_bytes(1 << 20):
                fh.write(chunk)
                total += len(chunk)
    with zipfile.ZipFile(tmp) as z:   # refuse a broken download
        bad = z.testzip()
        if bad:
            raise SourceError(f"corrupt OSV dump entry {bad}")
    tmp.replace(dest)
    log(f"OSV PyPI dump: {total / 1e6:.1f} MB -> {dest}")
    return dest


# --------------------------------------------------------------------------- KEV + EPSS

def load_kev(cache: HttpCache) -> tuple[set[str], Optional[str]]:
    data = cache.fetch_json(KEV_URL, key="kev", max_age=DAY)
    if not data or "vulnerabilities" not in data:
        return set(), None
    return {v.get("cveID") for v in data["vulnerabilities"] if v.get("cveID")}, data.get("dateReleased")


def load_epss(cves: Iterable[str], cache: HttpCache) -> dict[str, EPSS]:
    cves = sorted({c for c in cves if c and c.startswith("CVE-")})
    out: dict[str, EPSS] = {}
    for i in range(0, len(cves), 80):
        chunk = cves[i:i + 80]
        # refreshed daily online; offline reuses any earlier answer for the same CVE set
        data = cache.fetch_json(EPSS_URL, key=f"epss|{','.join(chunk)}", params={"cve": ",".join(chunk)}, max_age=DAY)
        for row in (data or {}).get("data", []) or []:
            try:
                out[row["cve"]] = EPSS(score=float(row["epss"]), percentile=float(row["percentile"]), date=row.get("date"))
            except (KeyError, ValueError):
                continue
    return out


# --------------------------------------------------------------------------- Grype

def grype_binary() -> Optional[str]:
    return os.environ.get("GUARDIAN_GRYPE") or shutil.which("grype")


def run_grype(target: str, cache: HttpCache, timeout: int = 900) -> tuple[Optional[dict], Optional[str]]:
    """``grype <target> -o json``. Results are cached per target per day."""
    key = f"grype|{target}|{datetime.now(timezone.utc).strftime('%Y-%m-%d') if not target.startswith('sbom:') else ''}"
    cached = cache.get_cached(key)
    if cached is not None:
        return cached, None
    if cache.offline and not target.startswith("sbom:"):
        return None, "offline: container image not pulled"
    exe = grype_binary()
    if not exe:
        return None, "grype is not installed (set GUARDIAN_GRYPE or add it to PATH)"
    try:
        res = subprocess.run([exe, target, "-o", "json", "-q"], capture_output=True, text=True, timeout=timeout,
                             encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"grype failed: {exc}"
    if res.returncode not in (0, 1) or not res.stdout.strip():
        return None, f"grype exited {res.returncode}: {res.stderr.strip()[-300:]}"
    try:
        doc = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None, "grype output was not JSON"
    cache.put(key, doc)
    return doc, None


GRYPE_SEVERITY = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low", "Negligible": "low"}


def grype_records(doc: dict) -> list[dict]:
    """Flatten Grype matches into OSV-like dicts that discovery can merge."""
    out = []
    for m in doc.get("matches", []) or []:
        v, art = m.get("vulnerability") or {}, m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        aliases = sorted({r.get("id") for r in related if r.get("id")} - {v.get("id")})
        vec_score: Optional[CVSS] = None
        for c in (v.get("cvss") or []) + [c for r in related for c in (r.get("cvss") or [])]:
            vec = c.get("vector") or ""
            score = (c.get("metrics") or {}).get("baseScore")
            if vec and score is not None:
                cand = CVSS(vector=vec if vec.startswith("CVSS") else f"CVSS:{c.get('version')}/{vec}",
                            score=float(score), band=band_of(float(score)), version=str(c.get("version")), source="grype")
                vec_score = cand if not vec_score else better_cvss(vec_score, cand)
        cvss = vec_score or CVSS(band=GRYPE_SEVERITY.get(v.get("severity"), "unknown"), source="grype severity")
        desc = v.get("description") or next((r.get("description") for r in related if r.get("description")), "") or ""
        out.append({
            "id": v.get("id"), "aliases": aliases, "summary": desc.split(". ")[0][:200], "details": desc,
            "cvss": cvss, "fixed_versions": list((v.get("fix") or {}).get("versions") or []),
            "fix_state": (v.get("fix") or {}).get("state"),
            "references": [Reference(type="ADVISORY", url=u) for u in (v.get("urls") or [])[:6]] +
                          ([Reference(type="WEB", url=v["dataSource"])] if v.get("dataSource") else []),
            "artifact": {"name": art.get("name"), "version": art.get("version"), "type": art.get("type"),
                         "purl": art.get("purl"), "locations": [l.get("path") for l in art.get("locations") or []][:3]},
        })
    return out


# --------------------------------------------------------------------------- fix commits

GITHUB_COMMIT = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})")
HUNK_FN = re.compile(r"^@@[^@]*@@\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)")
DEF_LINE = re.compile(r"^[+-]\s*(?:async\s+)?def\s+([A-Za-z_]\w*)")


def fix_commit_functions(references: list[Reference], cache: HttpCache, limit: int = 2) -> list[str]:
    """Function/class names touched by the FIX commit(s) (hunk headers + changed defs), for the analyst."""
    names: list[str] = []
    urls = [r.url for r in references if r.type in ("FIX", "PACKAGE") and GITHUB_COMMIT.match(r.url)][:limit]
    for url in urls:
        m = GITHUB_COMMIT.match(url)
        diff = cache.fetch_text(f"https://github.com/{m.group(1)}/{m.group(2)}/commit/{m.group(3)}.diff")
        if not diff:
            continue
        current_file = ""
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
            if not current_file.endswith(".py") or "/test" in current_file or current_file.startswith("test"):
                continue
            hm = HUNK_FN.match(line) or DEF_LINE.match(line)
            if hm and hm.group(1) not in names:
                names.append(hm.group(1))
    return names[:20]
