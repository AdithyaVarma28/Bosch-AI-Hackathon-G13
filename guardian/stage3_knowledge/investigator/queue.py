"""3D question queue: specific open questions drawn from 3A/3B/3C results.

Priority: new in diff (5) > touches secret / input / external (4) > large radius (3)
> low-confidence card (2) > other (1).
"""
from __future__ import annotations

import hashlib

from ..context import Stage3Context
from ..graph_builder import nodes_of, out_edges
from ..schema import Question, short_label

KIND_ORDER = ["outbound_data", "new_contact", "new_module", "new_package", "declared_unused", "large_radius",
              "low_confidence", "undeclared_import", "tightly_coupled", "dynamic_import", "followup"]


def build_queue(ctx: Stage3Context) -> list[Question]:
    G = ctx.G
    qs: dict[tuple[str, str], Question] = {}

    def add(kind: str, subject: str, text: str, priority: int, source: str, **context) -> None:
        key = (kind, subject)
        if key in qs and qs[key].priority >= priority:
            return
        qid = "q:" + hashlib.sha1(f"{kind}|{subject}".encode()).hexdigest()[:10]
        qs[key] = Question(id=qid, text=text, subject=subject, kind=kind, priority=priority, source=source,
                           context=context)

    new_edges = {(i.get("from"), i.get("to"), i["type"]) for i in ctx.changes.get("items", [])
                 if i["kind"] == "edge" and i["op"] == "+"}

    # user input and an external service on the same path
    for p in ctx.paths:
        if not p.get("input"):
            continue
        for sd in p.get("sink_details", []):
            if sd["via"] == "CONTACTS":
                fn = sd["function"]
                vias = {d.get("via") for _, v, d in out_edges(G, fn, "CONTACTS") if v == sd["id"]}
                if vias <= {"sdk-import"}:      # SDK only imported here: no call to ask about
                    continue
                is_new = G.nodes[fn].get("new_in_diff") or (fn, sd["id"], "CONTACTS") in new_edges
                add("outbound_data", fn, f"What data does `{short_label(fn)}` send, and where?", 5 if is_new else 4,
                    "3C execution path", service=sd["id"], entry=p["entry"], path=p["id"], input=p.get("input"))

    # new in the time-travel diff
    commit_of = {i["id"]: i.get("commit") for i in ctx.changes.get("items", [])}
    for it in ctx.changes.get("items", []):
        if it["op"] != "+":
            continue
        sha = (it.get("commit") or "")[:7]
        if it["type"] == "Module" and it["id"] in G:
            add("new_module", it["id"], f"Why was module `{G.nodes[it['id']].get('path')}` added in commit {sha}?",
                5, "3C diff", commit=it.get("commit"))
        elif it["type"] == "CONTACTS" and it.get("from") in G and ("outbound_data", it["from"]) not in qs:
            add("new_contact", it["from"], f"Why does `{short_label(it['from'])}` contact "
                f"{G.nodes[it['to']].get('name', it['to'])}, which is new in commit {sha}?", 5, "3C diff",
                service=it["to"], commit=it.get("commit"))

    for p in nodes_of(G, "Package"):
        d = G.nodes[p]
        tags = d.get("tags", [])
        is_new = bool(d.get("new_in_diff"))
        if "declared_unused" in tags:
            add("declared_unused", p, f"Is `{d.get('name')}` used anywhere (scripts, configs, entry points)?",
                5 if is_new else 1, "3A declared-vs-used", commit=commit_of.get(p))
        elif is_new and d.get("direct"):
            add("new_package", p, f"What uses `{d.get('name')}`, which is new since the baseline?", 5, "3C diff")
        if "undeclared_import" in tags:
            add("undeclared_import", p, f"Where does `{d.get('name')}` come from: transitive, vendored, or missing?",
                1, "3A declared-vs-used")
        br = ctx.blast.get(p) or {}
        if br.get("radius") == "large" and d.get("direct"):
            add("large_radius", p, f"Which exact `{d.get('name')}` APIs are used, and with what data?", 3,
                "3C blast radius")
    for u in G.graph.get("unresolved_imports", []):
        name = (u.get("import") or "").split(".")[0]
        if name:
            add("undeclared_import", f"import:{name}", f"Where does `{name}` come from: transitive, vendored, or missing?",
                1, "3A unresolved import", file=u.get("file"), line=u.get("line"))

    can_explain = ctx.llm.available or ctx.llm.cache_dir.exists()
    needs_llm = []
    for nid, card in ctx.cards.items():
        if card.get("needs_investigation") and G.nodes[nid].get("type") in ("Module", "Repo"):
            if not can_explain:          # only an LLM can explain code without docstrings
                needs_llm.append(nid)
                continue
            label = G.nodes[nid].get("path") or G.nodes[nid].get("name") or nid
            add("low_confidence", nid, f"What does `{label}` actually do?", 2, "3B card",
                confidence=card.get("confidence"), open_questions=card.get("open_questions", []))

    seen_pairs = set()
    for m in nodes_of(G, "Module"):
        for other in G.nodes[m].get("tightly_coupled_with", []) or []:
            pair = tuple(sorted((m, other)))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            a, b = (G.nodes[x].get("name") for x in pair)
            add("tightly_coupled", f"{pair[0]}|{pair[1]}", f"Are `{a}` and `{b}` really separate modules?", 1,
                "3A Louvain reconcile", modules=list(pair))

    for f in nodes_of(G, "File"):
        for di in G.nodes[f].get("dynamic_imports", []) or []:
            line = di.get("line") if isinstance(di, dict) else None
            expr = (di.get("expr") or di.get("target") or "importlib.import_module(...)") if isinstance(di, dict) else str(di)
            add("dynamic_import", f"{f}:{line}", f"What can `{expr}` at {G.nodes[f]['path']}:{line} load?", 1,
                "Stage 2 dynamic import", file=G.nodes[f]["path"], line=line, expr=expr)

    ctx.questions["needs_llm"] = needs_llm
    order = {k: i for i, k in enumerate(KIND_ORDER)}
    return sorted(qs.values(), key=lambda q: (-q.priority, order.get(q.kind, 99), q.subject))
