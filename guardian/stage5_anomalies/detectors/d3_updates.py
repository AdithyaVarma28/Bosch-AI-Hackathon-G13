"""D3 Suspicious package updates: for each version change in the dependency history, compare release
metadata; when a medium signal fires, download both distributions into the sandbox and diff them."""
from __future__ import annotations

import re
from datetime import datetime

from guardian.purl import normalize_name

from ..context import Stage5Context
from ..schema import Signal

BEHAVIOUR = {"network": "network call", "subprocess": "subprocess", "code_exec": "exec/eval",
             "obfuscated_exec": "exec of decoded (base64) data", "env_read": "environment read", "domain": "URL",
             "install_hook": "install hook"}
STRONG_CATS = ("network", "subprocess", "code_exec", "obfuscated_exec")


def _ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _ver(spec: str) -> str:
    return re.sub(r"^[=<>!~ ]+", "", str(spec or "")).strip()


def release_info(ctx: Stage5Context, name: str, version: str) -> dict:
    rel = ctx.pypi.release(name, version) or {}
    files = ctx.pypi.files(name, version)
    info = rel.get("info") or {}
    return {"found": bool(rel or files), "author": info.get("author"), "maintainer": info.get("maintainer"),
            "author_email": info.get("author_email"), "project_urls": info.get("project_urls") or {},
            "requires_dist": info.get("requires_dist") or [], "files": files,
            "wheel": any(f.get("packagetype") == "bdist_wheel" for f in files),
            "sdist_only": bool(files) and all(f.get("packagetype") == "sdist" for f in files),
            "yanked": any(f.get("yanked") for f in files),
            "uploaded": min((t for t in (_ts(f.get("upload_time_iso_8601")) for f in files) if t), default=None)}


def code_diff(ctx: Stage5Context, name: str, old: str, new: str, old_info: dict, new_info: dict) -> dict:
    a = ctx.analyze_dist(name, old, "bdist_wheel" if old_info.get("wheel") else "sdist")
    b = ctx.analyze_dist(name, new, "bdist_wheel" if new_info.get("wheel") else "sdist")
    if a.get("error") or b.get("error"):
        return {"error": a.get("error") or b.get("error")}

    def strip(p: str) -> str:   # sdists have a "<name>-<ver>/" prefix
        parts = p.split("/")
        return "/".join(parts[1:]) if len(parts) > 1 and re.match(rf"{re.escape(name.replace('-', '_'))}-", parts[0], re.I) else p

    fa = {strip(k): v for k, v in a["files"].items() if ".dist-info/" not in k and not k.endswith("PKG-INFO")}
    fb = {strip(k): (k, v) for k, v in b["files"].items() if ".dist-info/" not in k and not k.endswith("PKG-INFO")}
    changed = sorted(p for p in fb if p not in fa or fa[p]["sha256"] != fb[p][1]["sha256"])
    old_ast = {strip(k): {(f["category"], f["target"]) for f in v} for k, v in a["ast"].items()}
    new_behaviour = []
    for p in changed:
        orig = fb[p][0]
        for f in b["ast"].get(orig, []):
            if (f["category"], f["target"]) not in old_ast.get(p, set()) and f["category"] in BEHAVIOUR:
                new_behaviour.append({**f, "file": orig})
    return {"changed_files": changed, "new_behaviour": new_behaviour, "isolation": b.get("isolation"),
            "removed_files": sorted(p for p in fa if p not in fb)}


def detect(ctx: Stage5Context) -> list[Signal]:
    sigs: list[Signal] = []
    seen = set()
    for h in ctx.s3.facts.get("dependency_history", []) or []:
        for ch in h.get("changed", []) or []:
            name, old, new = ch.get("name"), _ver(ch.get("from")), _ver(ch.get("to"))
            key = (normalize_name(name or ""), old, new)
            if not name or not old or not new or key in seen:
                continue
            seen.add(key)
            pid = next((p for p in ctx.package_nodes() if normalize_name(ctx.G.nodes[p].get("name", "")) == key[0]), None)
            subject = pid or f"pkg:pypi/{key[0]}@{new}"
            oi, ni = release_info(ctx, name, old), release_info(ctx, name, new)
            if not (oi["found"] and ni["found"]):
                ctx.note("d3_skipped", f"{name} {old} -> {new}: release metadata not available from {ctx.pypi.source}")
                continue
            base = dict(detector="D3", subject=subject, subject_label=f"{name} {old} → {new}", commit=h["commit"][:7],
                        context={"old": {k: oi[k] for k in ("author", "maintainer", "project_urls")},
                                 "new": {k: ni[k] for k in ("author", "maintainer", "project_urls")}, "message": h.get("message")})
            ev = [{"pypi": f"{name}=={new}"}, {"commit": h["commit"]}]
            local = []
            cdate = _ts(h.get("date"))
            if ni["uploaded"] and cdate and 0 <= (cdate - ni["uploaded"]).days < 7:
                local.append(Signal(**base, check="recent_release", data={"days_before_commit": (cdate - ni["uploaded"]).days,
                                    "uploaded": ni["uploaded"].isoformat()}, evidence=ev, strength="weak", metadata_only=True,
                                    text=f"{name} {new} was released {(cdate - ni['uploaded']).days} day(s) before the commit that pulled it in"))
            for fld in ("author", "maintainer", "project_urls"):
                if (oi[fld] or None) != (ni[fld] or None):
                    local.append(Signal(**base, check=f"{fld}_changed", data={"from": oi[fld], "to": ni[fld]}, evidence=ev,
                                        strength="medium", metadata_only=True, text=f"{fld.replace('_', ' ')} changed between {old} and {new}"))
            if oi["wheel"] and ni["sdist_only"]:
                local.append(Signal(**base, check="wheel_to_sdist_only", data={"old_wheel": True, "new_sdist_only": True},
                                    evidence=ev, strength="medium", metadata_only=True,
                                    text=f"{old} shipped wheels; {new} is sdist-only, so build code now runs on install"))
            new_req = sorted(set(ni["requires_dist"]) - set(oi["requires_dist"]))
            if new_req:
                local.append(Signal(**base, check="new_install_requirements", data={"added": new_req}, evidence=ev,
                                    strength="medium", metadata_only=True, text=f"{new} adds install requirements {', '.join(new_req[:3])}"))
            if ni["yanked"]:
                local.append(Signal(**base, check="yanked_version", data={}, evidence=ev, strength="medium", metadata_only=True,
                                    text=f"{name} {new} is yanked"))
            if any(s.strength == "medium" for s in local):
                diff = code_diff(ctx, name, old, new, oi, ni)
                if diff.get("error"):
                    ctx.note("d3_deep_check", f"{name}: {diff['error']}")
                elif diff["new_behaviour"]:
                    nb = diff["new_behaviour"]
                    strong = [f for f in nb if f["category"] in STRONG_CATS]
                    local.append(Signal(**{**base, "context": {**base["context"], "changed_files": diff["changed_files"]}},
                                        check="new_behaviour_in_update",
                                        data={"behaviour": [{k: f[k] for k in ("category", "target", "line", "file")} for f in nb][:8],
                                              "changed_files": diff["changed_files"]},
                                        evidence=[{"package_file": f"{name}@{new}/{f['file']}", "lines": f"{f['line']}-{f['end_line']}"}
                                                  for f in (strong or nb)[:3]] + ev,
                                        strength="strong" if strong else "medium", behaviour=True,
                                        text=f"{new} adds {', '.join(sorted({BEHAVIOUR[f['category']] for f in nb}))} in "
                                             f"{', '.join(sorted({f['file'].split('/', 1)[-1] for f in nb}))}"))
                else:
                    ctx.analyses[f"diff:{key[0]}@{old}->{new}"] = {"changed_files": diff["changed_files"], "new_behaviour": []}
                    for s in local:
                        s.context["deep_check"] = (f"no new behaviour in {len(diff['changed_files'])} changed file(s): "
                                                   f"{', '.join(diff['changed_files'][:4])}")
            sigs += local
    return sigs
