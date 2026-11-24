"""Version ordering and range matching across ecosystems (no network, no package manager).

* PyPI: PEP 440 through `packaging`.
* Everything else: a semver-like key (numeric segments, pre-releases sort before the release).
* npm ranges: ^ ~ x-ranges, comparators, hyphen ranges and `||` (enough for lockfile and override work).
"""
from __future__ import annotations

import re
from functools import cmp_to_key

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

_NUM = re.compile(r"^\d+$")


def _semver_parts(v: str) -> tuple[list[int], list[str]]:
    v = v.strip().lstrip("vV=").split("+", 1)[0]
    core, _, pre = v.partition("-")
    nums = []
    for p in core.split("."):
        m = re.match(r"^(\d+)", p)
        nums.append(int(m.group(1)) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return nums, [x for x in pre.split(".") if x] if pre else []


def _cmp_pre(a: list[str], b: list[str]) -> int:
    if not a and not b:
        return 0
    if not a:
        return 1          # release > pre-release
    if not b:
        return -1
    for x, y in zip(a, b):
        if x == y:
            continue
        if _NUM.match(x) and _NUM.match(y):
            return -1 if int(x) < int(y) else 1
        if _NUM.match(x):
            return -1
        if _NUM.match(y):
            return 1
        return -1 if x < y else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def compare(ecosystem: str, a: str, b: str) -> int:
    """-1, 0, 1. Falls back to the semver key when a PyPI version is not PEP 440."""
    if ecosystem == "pypi":
        try:
            va, vb = Version(a), Version(b)
            return (va > vb) - (va < vb)
        except InvalidVersion:
            pass
    (na, pa), (nb, pb) = _semver_parts(a), _semver_parts(b)
    if na != nb:
        return -1 if na < nb else 1
    return _cmp_pre(pa, pb)


def sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    return sorted(set(versions), key=cmp_to_key(lambda x, y: compare(ecosystem, x, y)))


def is_prerelease(ecosystem: str, v: str) -> bool:
    if ecosystem == "pypi":
        try:
            return Version(v).is_prerelease
        except InvalidVersion:
            return False
    return bool(_semver_parts(v)[1])


def major(v: str | None) -> int | None:
    if not v:
        return None
    m = re.match(r"^\D*(\d+)", v)
    return int(m.group(1)) if m else None


def bump_kind(ecosystem: str, old: str | None, new: str | None) -> str:
    """patch | minor | major | downgrade | same | unknown (0.x minors count as major, as in semver)."""
    if not old or not new:
        return "unknown"
    c = compare(ecosystem, new, old)
    if c == 0:
        return "same"
    if c < 0:
        return "downgrade"
    (o, _), (n, _) = _semver_parts(old), _semver_parts(new)
    if o[0] != n[0] or (o[0] == 0 and o[1] != n[1]):
        return "major"
    if o[1] != n[1]:
        return "minor"
    return "patch"


# ----------------------------------------------------------------------------- npm ranges
def _expand_x(v: str) -> tuple[str, str]:
    """'1.2.x' -> (op, base) helpers for x-ranges."""
    parts = v.lstrip("vV=").split(".")
    return parts[0] if parts else "*", ".".join(parts)


def _comparators(rng: str) -> list[tuple[str, str]]:
    rng = rng.strip()
    if rng in ("", "*", "x", "X", "latest"):
        return []
    m = re.match(r"^([\w.+-]+)\s+-\s+([\w.+-]+)$", rng)
    if m:
        return [(">=", m.group(1)), ("<=", m.group(2))]
    out: list[tuple[str, str]] = []
    for tok in re.findall(r"(\^|~|>=|<=|>|<|=)?\s*([vV]?[\w.*+-]+)", rng):
        op, ver = tok[0] or "", tok[1]
        parts = ver.lstrip("vV=").split(".")
        wild = [p in ("x", "X", "*") for p in parts]
        nums = [int(p) if p.isdigit() else 0 for p in parts]
        if op in ("", "=") and (any(wild) or len(parts) < 3):
            k = next((i for i, w in enumerate(wild) if w), len(parts))
            if k == 0:
                continue
            lo = nums[:k] + [0] * (3 - k)
            hi = nums[:k]
            hi[-1] += 1
            hi += [0] * (3 - k)
            out += [(">=", ".".join(map(str, lo))), ("<", ".".join(map(str, hi)) + "-0")]
            continue
        base = ".".join(str(n) for n in (nums + [0, 0, 0])[:3])
        if "-" in ver:
            base = ver.lstrip("vV=")
        if op == "^":
            n = (nums + [0, 0, 0])[:3]
            if n[0] > 0 or len(parts) == 1:
                hi = f"{n[0] + 1}.0.0-0"
            elif n[1] > 0 or len(parts) == 2:
                hi = f"0.{n[1] + 1}.0-0"
            else:
                hi = f"0.0.{n[2] + 1}-0"
            out += [(">=", base), ("<", hi)]
        elif op == "~":
            n = (nums + [0, 0, 0])[:3]
            hi = f"{n[0]}.{n[1] + 1}.0-0" if len(parts) >= 2 else f"{n[0] + 1}.0.0-0"
            out += [(">=", base), ("<", hi)]
        else:
            out.append((op or "=", base))
    return out


def npm_satisfies(version: str, rng: str) -> bool:
    if not rng or rng.strip() in ("*", "latest", ""):
        return not is_prerelease("npm", version)
    for alt in rng.split("||"):
        comps = _comparators(alt)
        ok = True
        for op, ver in comps:
            c = compare("npm", version, ver)
            ok = {"=": c == 0, ">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0}[op]
            if not ok:
                break
        if ok and (not is_prerelease("npm", version) or any("-" in v and v.split("-")[1] != "0" for _, v in comps)):
            return True
    return False


def satisfies(ecosystem: str, version: str, spec: str | None) -> bool:
    if spec is None or spec.strip() in ("", "*"):
        return True
    if ecosystem == "pypi":
        try:
            return Version(version) in SpecifierSet(spec)
        except (InvalidSpecifier, InvalidVersion):
            return spec.strip().lstrip("=") == version
    return npm_satisfies(version, spec)


def max_satisfying(ecosystem: str, versions: list[str], spec: str | None) -> str | None:
    ok = [v for v in versions if satisfies(ecosystem, v, spec) and not is_prerelease(ecosystem, v)]
    return sort_versions(ecosystem, ok)[-1] if ok else None


def min_satisfying(ecosystem: str, versions: list[str], spec: str | None) -> str | None:
    ok = [v for v in versions if satisfies(ecosystem, v, spec) and not is_prerelease(ecosystem, v)]
    return sort_versions(ecosystem, ok)[0] if ok else None


def range_floor(ecosystem: str, spec: str | None) -> str | None:
    """Lowest version a range can resolve to (npm ^1.2.6 -> 1.2.6, pip ==2.0 -> 2.0)."""
    if not spec:
        return None
    if ecosystem == "pypi":
        m = re.search(r"(==|>=|~=)\s*([\w.]+)", spec)
        return m.group(2) if m else None
    lows = [v for alt in spec.split("||") for op, v in _comparators(alt) if op in (">=", "=", ">")]
    return sort_versions("npm", lows)[0] if lows else None
