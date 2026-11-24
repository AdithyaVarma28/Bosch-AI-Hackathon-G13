"""D1 Typosquatting: names close to a top PyPI package. Name match alone = medium (never strong by itself;
grouping raises it to strong only when D4 finds install behaviour in the same package)."""
from __future__ import annotations

from guardian.purl import normalize_name

from ..context import Stage5Context
from ..schema import Signal

AFFIXES = ("py-", "python-", "pip-", "-py", "-python", "-lib", "-dev", "-sdk", "-api", "-client")
LOOKALIKE = (("rn", "m"), ("1", "l"), ("0", "o"), ("vv", "w"), ("5", "s"))


def osa(a: str, b: str, limit: int = 2) -> int:
    """Optimal-string-alignment (Damerau) distance, with early exit above ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def candidates(name: str, top: dict[str, int]) -> list[dict]:
    n = normalize_name(name)
    out = []
    flat = n.replace("-", "")
    for t, downloads in top.items():
        if t == n or downloads < 1_000_000:
            continue
        how = None
        if flat == t.replace("-", "") :
            how = ("separator", 0)
        elif any(n == f"{a}{t}" if a.endswith("-") else n == f"{t}{a}" for a in AFFIXES):
            how = ("affix", 0)
        else:
            for x, y in LOOKALIKE:
                if n.replace(x, y) == t or n.replace(y, x) == t:
                    how = ("lookalike", 0)
                    break
        if not how and len(n) >= 5 and len(t) >= 4:
            d = osa(n, t, 2 if len(t) >= 8 else 1)
            if d <= (2 if len(t) >= 8 else 1):
                how = ("edit_distance", d)
        if how:
            out.append({"looks_like": t, "check": how[0], "distance": how[1], "downloads": downloads})
    return sorted(out, key=lambda c: (-c["downloads"], c["distance"]))[:3]


def detect(ctx: Stage5Context) -> list[Signal]:
    sigs = []
    for pid in ctx.package_nodes():
        d = ctx.G.nodes[pid]
        name = normalize_name(d.get("name", ""))
        if name in ctx.top or name in ctx.allowlist:
            continue
        cands = candidates(name, ctx.top)
        if not cands:
            continue
        best = cands[0]
        meta = ctx.pypi.project(name) or {}
        releases = meta.get("releases") or {}
        ev = [e for e in d.get("evidence", []) if e.get("file")][:1] + [{"pypi": name}]
        sigs.append(Signal(
            detector="D1", check=f"typosquat_{best['check']}", subject=pid, subject_label=d.get("name", pid),
            data={"looks_like": best["looks_like"], "distance": best["distance"], "rule": best["check"],
                  "target_downloads": best["downloads"]},
            context={"release_count": len(releases) or None, "has_source_repo": any(
                "github.com" in (u or "") for u in ((meta.get("info") or {}).get("project_urls") or {}).values()),
                     "pypi_found": bool(meta)},
            evidence=ev, strength="medium", metadata_only=True,
            text=f"{d.get('name')} looks like the popular package {best['looks_like']} "
                 f"({best['check'].replace('_', ' ')}{', distance ' + str(best['distance']) if best['distance'] else ''})"))
    return sigs
