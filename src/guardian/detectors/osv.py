"""OSV client, CVSS v3 scoring, KEV and EPSS enrichment (all cached, offline-capable)."""
from __future__ import annotations

import math
import re

import httpx

from ..httpcache import CacheMiss, CachedHttp
from ..purl import OSV_ECOSYSTEM

OSV = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


class OsvClient:
    def __init__(self, http: CachedHttp):
        self.http = http

    def query_batch(self, purls: list[str]) -> tuple[dict[str, list[str]], str]:
        """purl -> [vuln ids]. Returns (results, source) where source is live|cache|mixed."""
        out: dict[str, list[str]] = {}
        sources = set()
        for i in range(0, len(purls), 500):
            chunk = purls[i:i + 500]
            body = {"queries": [{"package": {"purl": p}} for p in chunk]}
            data, src = self.http.request_json("POST", f"{OSV}/querybatch", body)
            sources.add(src)
            for p, res in zip(chunk, (data or {}).get("results", [])):
                ids = [v["id"] for v in (res or {}).get("vulns", []) or []]
                if ids:
                    out[p] = ids
        return out, sources.pop() if len(sources) == 1 else "mixed"

    def get_vuln(self, vid: str) -> dict | None:
        data, _ = self.http.request_json("GET", f"{OSV}/vulns/{vid}")
        return data

    def query_versions(self, ecosystem: str, name: str, versions: list[str]) -> dict[str, list[str]]:
        """version -> [vuln ids] for candidate versions of one package (used by Day 2 remediation)."""
        from ..purl import make_purl
        purls = {make_purl(ecosystem, name, v): v for v in versions}
        hits, _ = self.query_batch(list(purls))
        return {purls[p]: ids for p, ids in hits.items()}


class LocalOsvClient:
    """Offline advisory snapshot: a JSON list of OSV records (same schema as api.osv.dev).

    Used for air-gapped demos and tests (`Settings.advisory_db`). Matching follows OSV semantics:
    explicit `versions` lists, or ECOSYSTEM/SEMVER `ranges` with introduced/fixed/last_affected events."""

    def __init__(self, path):
        import json
        from pathlib import Path
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.records: dict[str, dict] = {r["id"]: r for r in (data.get("vulns", data) if isinstance(data, dict) else data)}

    def matches(self, ecosystem: str, name: str, version: str) -> list[str]:
        return [vid for vid, r in self.records.items() if affected_by(r, ecosystem, name, version)]

    def query_batch(self, purls: list[str]) -> tuple[dict[str, list[str]], str]:
        from ..purl import parse_purl
        out = {}
        for p in purls:
            try:
                eco, name, ver = parse_purl(p)
            except ValueError:
                continue
            if ver:
                ids = self.matches(eco, name, ver)
                if ids:
                    out[p] = ids
        return out, "snapshot"

    def get_vuln(self, vid: str) -> dict | None:
        return self.records.get(vid)

    def query_versions(self, ecosystem: str, name: str, versions: list[str]) -> dict[str, list[str]]:
        return {v: ids for v in versions if (ids := self.matches(ecosystem, name, v))}


def affected_by(record: dict, ecosystem: str, name: str, version: str) -> bool:
    from ..day2.versions import compare
    eco = OSV_ECOSYSTEM.get(ecosystem, ecosystem)
    norm = name.lower().replace("_", "-")
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != eco or pkg.get("name", "").lower().replace("_", "-") != norm:
            continue
        if version in (aff.get("versions") or []):
            return True
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            affected = False
            events = sorted(rng.get("events") or [], key=lambda e: 0 if "introduced" in e else 1)
            intro = [e["introduced"] for e in events if "introduced" in e]
            fixed = [e["fixed"] for e in events if "fixed" in e]
            last = [e["last_affected"] for e in events if "last_affected" in e]
            for i in intro:
                lo_ok = i == "0" or compare(ecosystem, version, i) >= 0
                if not lo_ok:
                    continue
                ups = [f for f in fixed if i == "0" or compare(ecosystem, f, i) > 0]
                lasts = [x for x in last if i == "0" or compare(ecosystem, x, i) >= 0]
                if ups:
                    up = min(ups, key=_vkey)
                    affected = compare(ecosystem, version, up) < 0
                elif lasts:
                    affected = compare(ecosystem, version, min(lasts, key=_vkey)) <= 0
                else:
                    affected = True
                if affected:
                    return True
    return False


def make_osv(settings, http: CachedHttp):
    """The advisory source for a run: the offline snapshot when configured, else OSV."""
    path = getattr(settings, "advisory_db", None)
    return LocalOsvClient(path) if path else OsvClient(http)


# ----------------------------------------------------------------------------- CVSS v3.x base score
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
    "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl), 10)) if scope_changed else _roundup(min(impact + expl, 10))


def band_for_score(s: float) -> str:
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low" if s > 0 else "None"


def severity_band(record: dict) -> tuple[float | None, str | None, str | None]:
    """(cvss score, band, vector). OSV gives vectors, not scores, so compute v3 scores ourselves."""
    score, vector = None, None
    for sev in record.get("severity") or []:
        s = sev.get("score", "")
        if sev.get("type") == "CVSS_V3" or s.startswith("CVSS:3"):
            vector, score = s, cvss3_score(s)
            break
        if sev.get("type") == "CVSS_V4" and vector is None:
            vector = s
    if score is not None:
        return score, band_for_score(score), vector
    db = (record.get("database_specific") or {}).get("severity")
    if isinstance(db, str):
        b = {"LOW": "Low", "MODERATE": "Medium", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}.get(db.upper())
        if b:
            return None, b, vector
    for aff in record.get("affected") or []:
        s = (aff.get("ecosystem_specific") or {}).get("severity") or (aff.get("database_specific") or {}).get("severity")
        if isinstance(s, str) and s.upper() in ("LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"):
            return None, {"MODERATE": "Medium"}.get(s.upper(), s.capitalize()), vector
    return None, None, vector


def fixed_versions(record: dict, ecosystem: str, name: str) -> list[str]:
    out = []
    eco = OSV_ECOSYSTEM.get(ecosystem, ecosystem)
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != eco or pkg.get("name", "").lower().replace("_", "-") != name.lower().replace("_", "-"):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    out.append(ev["fixed"])
    return sorted(set(out), key=_vkey)


def _vkey(v: str):
    # (0, int) for numeric parts, (1, str) otherwise: ints and strings never compare directly
    # (e.g. "1.2.0" vs "1.2.0-rc1" or Go "v1.2.3"), which used to raise TypeError
    return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"[.\-+]", (v or "").lstrip("vV"))]


def cve_aliases(record: dict) -> list[str]:
    return sorted({a for a in [record.get("id", "")] + (record.get("aliases") or []) if a.startswith("CVE-")})


def load_kev(http: CachedHttp) -> tuple[set[str], str]:
    try:
        data, src = http.request_json("GET", KEV_URL)
        return {v["cveID"] for v in (data or {}).get("vulnerabilities", [])}, src
    except (CacheMiss, httpx.HTTPError, ValueError):
        return set(), "unavailable"


def load_epss(http: CachedHttp, cves: list[str]) -> tuple[dict[str, float], str]:
    out: dict[str, float] = {}
    src = "unavailable"
    for i in range(0, len(cves), 50):
        chunk = sorted(set(cves))[i:i + 50]
        if not chunk:
            continue
        try:
            data, src = http.request_json("GET", f"{EPSS_URL}?cve={','.join(chunk)}")
            for row in (data or {}).get("data", []):
                out[row["cve"]] = float(row["epss"])
        except (CacheMiss, httpx.HTTPError, ValueError, KeyError):
            src = "unavailable"
    return out, src
