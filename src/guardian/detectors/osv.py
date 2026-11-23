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
    return [int(x) if x.isdigit() else x for x in re.split(r"[.\-+]", v)]


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
