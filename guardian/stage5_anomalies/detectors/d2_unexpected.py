"""D2 Unexpected changes: new unused dependencies, new transitive packages without a parent change, and
code-behaviour changes from the Stage 3 diff (new outbound domain / secret read / exec in a recent commit)."""
from __future__ import annotations

import re

from guardian.purl import normalize_name
from guardian.stage3_knowledge.graph_builder import pred, succ
from guardian.stage3_knowledge.schema import short_label
from guardian.stage4_vulns.graphfacts import classify, inputs_on_paths, reach

from ..context import Stage5Context
from ..schema import Signal


def _added_in(ctx: Stage5Context) -> dict[str, dict]:
    """normalized package name -> commit dict where it was added (most recent)."""
    out: dict[str, dict] = {}
    hist = ctx.s3.facts.get("dependency_history", []) or []
    for h in reversed(hist):                         # oldest first, so later commits overwrite
        if h is hist[-1]:
            continue                                 # the oldest commit is the baseline
        for a in h.get("added", []) or []:
            out[normalize_name(re.split(r"[<>=!~ \[;]", str(a))[0])] = h
    return out


def detect(ctx: Stage5Context) -> list[Signal]:
    G = ctx.G
    sigs: list[Signal] = []
    added = _added_in(ctx)
    for pid in ctx.package_nodes():
        d = G.nodes[pid]
        n = normalize_name(d.get("name", ""))
        h = added.get(n)
        if not h or not d.get("direct"):
            continue
        ev = [e for e in d.get("evidence", []) if e.get("file")][:1] + [{"commit": h["commit"]}]
        users = d.get("used_by_files") or []
        same_commit_users = [u for u in users if u in (h.get("files_changed") or [])]
        if "declared_unused" in (d.get("tags") or []):
            sigs.append(Signal(detector="D2", check="new_dependency_unused", subject=pid, subject_label=d.get("name"),
                               data={"added_in": h["commit"][:7], "imported_by": []}, commit=h["commit"][:7],
                               context={"message": h.get("message")}, evidence=ev, strength="medium",
                               text=f"{d.get('name')} was added in {h['commit'][:7]} but no code imports it"))
        elif users and set(users) <= set(same_commit_users):
            sigs.append(Signal(detector="D2", check="new_dependency_new_file_only", subject=pid, subject_label=d.get("name"),
                               data={"added_in": h["commit"][:7], "imported_by": users}, commit=h["commit"][:7],
                               evidence=ev, strength="medium",
                               text=f"{d.get('name')} is only used by files added in the same commit"))
        msg = (h.get("message") or "").lower()
        if d.get("name", "").lower() not in msg and n not in msg:
            sigs.append(Signal(detector="D2", check="commit_message_silent", subject=pid, subject_label=d.get("name"),
                               data={"commit": h["commit"][:7], "message": h.get("message")}, commit=h["commit"][:7],
                               evidence=[{"commit": h["commit"]}], strength="weak", metadata_only=True,
                               text=f"commit {h['commit'][:7]} (\"{h.get('message')}\") does not mention {d.get('name')}"))

    # new transitive packages whose parents did not change: needs a baseline lock (Stage 3 diff snapshots)
    # code behaviour changes: Stage 3 3D notable outbound findings + new contacts in the diff
    for f in ctx.s3.findings:
        if f.get("kind") not in ("outbound_data", "new_contact") or not f.get("notable"):
            continue
        fn = f["subject"]
        if fn not in G:
            continue
        fd = G.nodes[fn]
        svcs = [s for s in succ(G, fn, "CONTACTS")]
        domains = [G.nodes[s].get("name", s) for s in svcs]
        r = reach(G, fn)
        inputs = inputs_on_paths(G, [e for e in r["entries"] if e["public"]])
        secrets = [e for e in succ(G, fn, "READS_ENV") if G.nodes[e].get("secret_like")]
        user_data = bool(inputs) or bool(secrets)
        commit = next((e.get("commit") for e in f.get("evidence", []) if e.get("commit")), None)
        line_ev = [{"file": e["file"], "lines": e.get("lines") or str(e.get("line"))} for e in f.get("evidence", []) if e.get("file")][:3]
        input_ev = [{"file": i["file"], "line": i["line"]} for i in inputs if i.get("file") and i.get("line")][:1]
        strong = user_data and classify(r["entries"]) == "public_path"
        sigs.append(Signal(
            detector="D2", check="new_outbound_domain", subject=f"file:{fd.get('file')}", subject_label=fd.get("file"),
            data={"function": fn, "domains": domains, "user_data": user_data,
                  "inputs": sorted({i["source"] for i in inputs}), "entries": [e["label"] for e in r["entries"]]},
            context={"commit_message": next((c.get("title") for c in ctx.s3.changes.get("commits", []) if commit and c.get("short") == commit[:7]), None)},
            commit=commit[:7] if commit else None, evidence=line_ev + input_ev + ([{"commit": commit}] if commit else []),
            strength="strong" if strong else "medium", behaviour=True,
            text=(f"{short_label(fn)} sends data to {', '.join(domains) or 'a new domain'} introduced in a recent commit"
                  + (f"; user input ({', '.join(sorted({i['source'] for i in inputs}))}) reaches it from a public route" if strong else ""))))
    for item in ctx.s3.changes.get("items", []) or []:
        lab = item.get("label", "")
        if lab.startswith("+READS_ENV") and any(k in lab for k in ("KEY", "SECRET", "TOKEN", "PASS")):
            m = re.search(r"fn:(\S+?)::", lab)
            path = m.group(1) if m else None
            if path:
                sigs.append(Signal(detector="D2", check="new_secret_read", subject=f"file:{path}", subject_label=path,
                                   data={"change": lab}, evidence=[{"file": path}], strength="medium", behaviour=True,
                                   text=f"new secret read: {lab}"))
    return sigs
