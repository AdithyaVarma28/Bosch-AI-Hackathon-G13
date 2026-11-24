"""Step 2 Prioritization queue (deterministic). The score orders investigation only; it is not risk.

priority = 100*kev + 10*cvss + 20*(blast radius large) + 10*(public) + 5*(runtime) + 10*epss_percentile
           - 30*(test_only or dev)
"""
from __future__ import annotations

from .context import Stage4Context
from .graphfacts import files_using, used_requirers
from .schema import VulnMatch

BAND_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0, "none": 0.0, "unknown": 5.0}


def cvss_value(m: VulnMatch) -> float:
    return m.cvss.score if m.cvss.score is not None else BAND_SCORE.get(m.cvss.band, 5.0)


def priority(ctx: Stage4Context, m: VulnMatch) -> float:
    radius = (ctx.s3.blast.get(m.package) or {}).get("radius")
    p = 100 * m.kev + 10 * cvss_value(m) + 20 * (radius == "large") + 10 * (radius == "public") \
        + 5 * (m.scope == "runtime") + 10 * (m.epss.percentile if m.epss else 0.0) \
        - 30 * (m.scope in ("test_only", "dev"))
    return round(p, 2)


def not_imported(ctx: Stage4Context, m: VulnMatch) -> bool:
    """Zero USES_PACKAGE edges and not required by a package that is used."""
    G = ctx.G
    if m.package not in G:
        return False
    runtime, tests = files_using(G, m.package)
    return not runtime and not tests and not used_requirers(G, m.package)


def plan(ctx: Stage4Context, matches: list[VulnMatch]) -> tuple[list[dict], list[dict]]:
    """Split into deep investigations (top N by priority) and the light pass, each with a reason."""
    deep_cands, light = [], []
    for m in matches:
        item = {"match": m, "priority": priority(ctx, m)}
        if m.scope == "container_os":
            light.append({**item, "reason": "container OS package: usage analysis does not apply",
                          "usage": "not_applicable"})
        elif not_imported(ctx, m):
            light.append({**item, "reason": "no file imports the package and no used package requires it",
                          "usage": "package_not_imported"})
        elif m.scope in ("dev", "test_only", "build"):
            light.append({**item, "reason": f"{m.scope} dependency: rules only", "usage": None})
        else:
            deep_cands.append(item)
    deep_cands.sort(key=lambda x: (-x["priority"], x["match"].match_id))
    deep = deep_cands[: ctx.budgets.deep]
    for item in deep_cands[ctx.budgets.deep:]:
        light.append({**item, "reason": f"outside the top {ctx.budgets.deep} by priority", "usage": None})
    light.sort(key=lambda x: (-x["priority"], x["match"].match_id))
    for rank, item in enumerate(deep, 1):
        item["rank"] = rank
    return deep, light
