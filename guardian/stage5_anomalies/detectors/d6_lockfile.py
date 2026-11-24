"""D6 Lockfile integrity & provenance: lock-only commits, hashes that differ from PyPI, source/index
changes, dependency confusion."""
from __future__ import annotations

from guardian.purl import normalize_name

from ..context import LOCKFILES, MANIFEST_RE, Stage5Context
from ..schema import Signal


def _pid(ctx: Stage5Context, name: str) -> str | None:
    n = normalize_name(name)
    return next((p for p in ctx.package_nodes() if normalize_name(ctx.G.nodes[p].get("name", "")) == n), None)


def detect(ctx: Stage5Context) -> list[Signal]:
    sigs: list[Signal] = []
    hist = ctx.s3.facts.get("dependency_history", []) or []
    src = ctx.s3.source
    for h in hist:
        changed = h.get("files_changed") or []
        locks = [f for f in changed if f.rsplit("/", 1)[-1] in LOCKFILES]
        if not locks or any(MANIFEST_RE.search(f) for f in changed):
            continue
        for lf in locks:
            parent = src.git("rev-parse", f"{h['commit']}^") if src.is_git else None
            new = ctx.lock_at(h["commit"], lf)
            old = ctx.lock_at(parent.strip(), lf) if parent else {}
            diffs = sorted(n for n in set(new) | set(old) if new.get(n) != old.get(n))
            for n in diffs or [None]:
                subject = (_pid(ctx, n) if n else None) or (f"file:{lf}")
                what = {}
                if n:
                    o, w = old.get(n) or {}, new.get(n) or {}
                    what = {"package": n, "version": [o.get("version"), w.get("version")],
                            "hashes_added": sorted(set(w.get("hashes", [])) - set(o.get("hashes", []))),
                            "hashes_removed": sorted(set(o.get("hashes", [])) - set(w.get("hashes", [])))}
                sigs.append(Signal(detector="D6", check="lockfile_only_change", subject=subject, subject_label=n or lf,
                                   data={"lockfile": lf, **what}, commit=h["commit"][:7],
                                   context={"message": h.get("message")}, evidence=[{"file": lf}, {"commit": h["commit"]}],
                                   strength="medium", text=f"{lf} changed in {h['commit'][:7]} (\"{h.get('message')}\") with no manifest change"
                                   + (f": {n} entry modified" if n else "")))
    # lock hashes vs PyPI's published hashes
    lf = next((f for f in LOCKFILES if src.available and (src.root / f).exists()), None)
    if lf:
        lock = ctx.lock_at("HEAD", lf)
        text_lines = [t for _, t in src.read_lines(lf)]
        for n, e in sorted(lock.items()):
            if not e.get("hashes") or not e.get("version"):
                continue
            published = ctx.pypi.hashes(e["name"], e["version"])
            if not published:
                ctx.note("d6_unchecked", f"{e['name']} {e['version']}: no published hashes from {ctx.pypi.source}")
                continue
            bad = [x for x in e["hashes"] if x not in published]
            if bad:
                line = next((i for i, t in enumerate(text_lines, 1) if bad[0] in t), None)
                sigs.append(Signal(detector="D6", check="hash_mismatch", subject=_pid(ctx, n) or f"pkg:pypi/{n}@{e['version']}",
                                   subject_label=f"{e['name']} {e['version']}",
                                   data={"lockfile": lf, "lock_hash": bad[0], "published": sorted(published)},
                                   evidence=[{"file": lf, "line": line}, {"pypi": f"{e['name']}=={e['version']}"}],
                                   strength="strong", behaviour=True,
                                   text=f"{lf} pins {e['name']} {e['version']} to sha256:{bad[0][:12]}…, which PyPI does not publish for that version"))
            if e.get("source") and isinstance(e["source"], dict) and e["source"].get("type") in ("git", "url"):
                sigs.append(Signal(detector="D6", check="source_not_registry", subject=_pid(ctx, n) or n, subject_label=e["name"],
                                   data={"source": e["source"]}, evidence=[{"file": lf}], strength="medium",
                                   text=f"{e['name']} is locked to a {e['source'].get('type')} source"))
    # dependency confusion: extra index + internal-looking names that also exist on public PyPI
    idx = ctx.s3.facts.get("package_indexes", []) or []
    extra = [i for i in idx if i.get("type") in ("extra-index-url", "poetry-source", "uv-index")]
    if extra:
        for pid in ctx.package_nodes():
            d = ctx.G.nodes[pid]
            n = normalize_name(d.get("name", ""))
            if n in ctx.top or not d.get("direct"):
                continue
            if ctx.pypi.project(n):
                sigs.append(Signal(detector="D6", check="dependency_confusion", subject=pid, subject_label=d.get("name"),
                                   data={"extra_index": extra[0].get("url")}, strength="medium",
                                   evidence=[{"file": extra[0].get("source_file"), "line": extra[0].get("line")}],
                                   text=f"an extra index is configured and {d.get('name')} also exists on the public index"))
    return sigs
