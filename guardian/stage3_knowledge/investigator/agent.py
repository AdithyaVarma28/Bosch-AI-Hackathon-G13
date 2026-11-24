"""3D Contextual Investigator: one bounded agent that works the question queue.

pick question -> plan -> call tools -> enough evidence? -> write Finding (+ follow-ups) -> next.

With an LLM this is a plain tool-calling loop (the spec allows it instead of LangGraph): at most
``steps_per_question`` tool calls, then ``submit_finding``. Without an LLM, or when a call fails,
a deterministic playbook per question kind uses the same tools, so findings are produced the same
way and pass the same evidence check.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Optional

from ..context import Stage3Context
from ..graph_builder import in_edges, out_edges, pred, succ
from ..schema import Evidence, Finding, Question, short_label
from ..timetravel import fmt_date
from .queue import build_queue
from .tools import SUBMIT_SPEC, TOOL_SPECS, Toolbox, tool_result_text

PROMPTS = Path(__file__).resolve().parent.parent / "prompts"


# --------------------------------------------------------------------------- driver

def investigate(ctx: Stage3Context) -> list[dict]:
    ctx.questions = {}
    queue = build_queue(ctx)
    budget = ctx.budgets.questions
    ctx.questions.update({"queued": len(queue), "skipped": [], "asked": []})
    findings: list[dict] = []
    while queue and len(findings) < budget:
        q = queue.pop(0)
        tb = Toolbox(ctx)
        raw = None
        if ctx.llm.available or ctx.llm.cache_dir.exists():
            raw = llm_investigate(ctx, q, tb)
        if raw is None:
            tb = Toolbox(ctx)
            raw = run_playbook(ctx, q, tb)
            raw["discovered_by"] = "algorithm"
        finding = validate_finding(q, raw, tb)
        write_back(ctx, finding)
        findings.append(finding)
        ctx.questions["asked"].append(q.id)
        for text in finding.get("new_questions", [])[:2]:
            if len(findings) + len(queue) < budget:
                queue.append(Question(id=f"{q.id}.{len(queue)}", text=text, subject=q.subject, kind="followup",
                                      priority=1, source=f"follow-up of {q.id}"))
    ctx.questions["skipped"] = [q.model_dump() for q in queue]
    ctx.findings = findings
    return findings


def validate_finding(q: Question, raw: dict, tb: Toolbox) -> dict:
    """Keep only evidence that a tool returned in this run; downgrade when claims are dropped."""
    evidence, dropped = [], []
    for item in raw.get("evidence", []) or []:
        item = {k: v for k, v in (item or {}).items() if v not in (None, "")}
        if not item:
            continue
        e = Evidence(**item)
        if tb.ledger.covers(e):
            evidence.append(e)
        else:
            dropped.append(e.label() or json.dumps(item))
    status = raw.get("status") if raw.get("status") in ("resolved", "unresolved") else "unresolved"
    try:
        conf = min(1.0, max(0.0, float(raw.get("confidence", 0.5))))
    except (TypeError, ValueError):
        conf = 0.5
    if dropped:
        conf = round(conf * 0.85, 2)
    if not evidence and status == "resolved":
        status = "unresolved"
        conf = min(conf, 0.4)
    f = Finding(
        id=f"finding:{q.id[2:]}", question=q.text, answer=str(raw.get("answer") or "No answer."),
        subject=q.subject, kind=q.kind, evidence=evidence, confidence=conf, status=status,
        notable=bool(raw.get("notable")) and bool(evidence),
        notable_reason=(raw.get("notable_reason") or None) if raw.get("notable") else None,
        new_questions=[s for s in raw.get("new_questions", []) or [] if s][:2],
        steps_used=tb.steps, dropped_evidence=dropped, discovered_by=raw.get("discovered_by", "ai"),
    )
    return f.model_dump()


def write_back(ctx: Stage3Context, f: dict) -> None:
    G = ctx.G
    subjects = [s for s in f["subject"].split("|") if s in G]
    for s in subjects:
        G.nodes[s].setdefault("findings", []).append(f["id"])
        if f["notable"]:
            G.nodes[s]["notable"] = True
            G.nodes[s]["notable_reason"] = f["notable_reason"]


# --------------------------------------------------------------------------- LLM loop

def llm_investigate(ctx: Stage3Context, q: Question, tb: Toolbox) -> Optional[dict]:
    max_steps = ctx.budgets.steps_per_question
    system = (PROMPTS / "investigator_system.md").read_text(encoding="utf-8").replace("{max_steps}", str(max_steps))
    subject = tb.summary(q.subject) if q.subject in ctx.G else {"id": q.subject}
    tb.ledger = type(tb.ledger)()  # the subject summary above is context, not evidence
    user = (f"Question: {q.text}\nSubject: {q.subject}\nWhy it was asked: {q.source}\n"
            f"Context: {json.dumps(q.context, default=str)}\nSubject node: {json.dumps(subject, default=str)[:4000]}")
    messages: list[dict] = [{"role": "user", "content": user}]
    tools = TOOL_SPECS + [SUBMIT_SPEC]
    for _ in range(max_steps + 3):
        resp = ctx.llm.create("investigator", system, messages, tools=tools, max_tokens=16000)
        if resp is None:
            return None
        content = resp.get("content", [])
        messages.append({"role": "assistant", "content": content})
        uses = [b for b in content if b.get("type") == "tool_use"]
        submit = next((b for b in uses if b.get("name") == "submit_finding"), None)
        if submit:
            out = dict(submit.get("input") or {})
            out["discovered_by"] = "ai"
            return out
        if not uses:
            messages.append({"role": "user", "content": "Call submit_finding now with what you have."})
            continue
        results = []
        for b in uses:
            if tb.steps >= max_steps:
                text, err = "Step budget exhausted. Call submit_finding now.", True
            else:
                out = tb.call(b.get("name"), b.get("input") or {})
                text, err = tool_result_text(out), "error" in out
            results.append({"type": "tool_result", "tool_use_id": b.get("id"), "content": text, "is_error": err})
        messages.append({"role": "user", "content": results})
    return {"answer": "The investigator did not submit a finding within its step budget.", "status": "unresolved",
            "confidence": 0.2, "evidence": [], "discovered_by": "ai"}


# --------------------------------------------------------------------------- playbooks (no LLM)

def run_playbook(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    fn = PLAYBOOKS.get(q.kind, pb_generic)
    try:
        return fn(ctx, q, tb)
    except Exception as exc:  # fail soft: keep the question as unresolved
        return {"answer": f"Investigation failed: {type(exc).__name__}: {exc}", "status": "unresolved",
                "confidence": 0.1, "evidence": []}


def _commit_of(ctx: Stage3Context, node: str) -> Optional[dict]:
    """The commit that introduced/changed a node (CHANGED_IN), as a dict."""
    G = ctx.G
    for _, c, d in out_edges(G, node, "CHANGED_IN"):
        cd = G.nodes[c]
        return {"sha": cd.get("sha") or c[7:], "date": cd.get("date"), "message": cd.get("message"),
                "change": d.get("change")}
    return None


def _git_first_commit(hist: dict) -> Optional[dict]:
    commits = hist.get("commits") or []
    return commits[-1] if commits else None


def _line_text(read: dict, line: int) -> str:
    for l in read.get("lines", []):
        num, _, text = l.partition(": ")
        if num.isdigit() and int(num) == line:
            return text
    return ""


def pb_outbound(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    G = ctx.G
    fn = q.subject
    d = G.nodes[fn]
    name = short_label(fn)
    tb.call("query_graph", {"node_id": fn, "edge_types": ["CALLS", "CONTACTS", "CALLS_API"], "direction": "both"})
    body = tb.call("read_code", {"file": d["file"], "start": d["line"], "end": d["end_line"]})
    evidence = [{"file": d["file"], "lines": f"{d['line']}-{d['end_line']}"}]

    svc = q.context.get("service") or next(iter(succ(G, fn, "CONTACTS")), None)
    svc_name = G.nodes[svc].get("name", svc) if svc in G else "an external service"
    methods = sorted({c.get("target") for c in d.get("external_calls", []) if c.get("target")})
    urls = [u.get("url") for u in G.nodes[f"file:{d['file']}"].get("string_urls", [])
            if d["line"] <= (u.get("line") or 0) <= d["end_line"]]
    if not urls:
        urls = re.findall(r"https?://[^\s'\"]+", " ".join(body.get("lines", [])))

    # what data: payload keys at the call sites + parameters
    fields: list[str] = []
    call_sites: list[str] = []
    callers = []
    for u, _, e in in_edges(G, fn, "CALLS"):
        callers.append(u)
        for item in e.get("evidence", [])[:1]:
            line = item.get("line")
            if not line:
                continue
            site = tb.call("read_code", {"file": item["file"], "start": line, "end": line})
            text = _line_text(site, line)
            fields += re.findall(r"['\"](\w+)['\"]\s*:", text)
            m = re.search(re.escape(d.get("name", "")) + r"\((.*)\)", text)
            if m and not fields:
                call_sites.append(f"{d.get('name')}({m.group(1).strip()[:80]}) at {item['file']}:{line}")
            evidence.append({"file": item["file"], "lines": str(line)})
    fields = list(dict.fromkeys(fields))
    params = [p for p in d.get("params", []) if p not in ("self", "cls")]
    hist = tb.call("git_history", {"target": d["file"]})
    intro = _git_first_commit(hist)
    is_new = bool(d.get("new_in_diff"))
    if intro and intro.get("commit"):
        evidence.append({"commit": intro["commit"]})

    what = (", ".join(fields) + (f" (plus the {', '.join(params)} arguments)" if params else "")) if fields \
        else (f"its arguments ({', '.join(params)})" if params else "data built inside the function")
    how = f" via {', '.join(methods)}" if methods else ""
    where = urls[0] if urls else svc_name
    caller_txt = ", ".join(short_label(c) for c in callers) or "no resolved caller"
    entry = q.context.get("entry")
    answer = (f"{name} sends {what}{how} to {where}. It is called from {caller_txt}"
              + (f", reached from {entry[6:] if entry and entry.startswith('route:') else entry} with {q.context.get('input')}" if entry else "")
              + ".")
    if call_sites:
        answer += f" Call site: {'; '.join(call_sites[:2])}."
    if intro:
        answer += (f" {d['file']} {'was added' if is_new else 'was last changed'} in commit {intro['commit'][:7]} "
                   f"({fmt_date(intro.get('date'))}, \"{intro.get('message')}\").")
    domain = re.sub(r"^https?://([^/]+).*$", r"\1", where)
    return {"answer": answer, "evidence": evidence, "confidence": 0.85 if fields else 0.7, "status": "resolved",
            "notable": is_new,
            "notable_reason": f"user-reachable data leaves the system to {domain}, introduced in a recent commit" if is_new else "",
            "new_questions": []}


def pb_new_contact(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    q2 = Question(**{**q.model_dump(), "kind": "outbound_data"})
    out = pb_outbound(ctx, q2, tb)
    return out


def pb_declared_unused(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    G = ctx.G
    d = G.nodes[q.subject]
    name = d.get("name")
    info = tb.call("pypi_info", {"package": name})
    names = info.get("import_names") or [name.lower()]
    alt = "|".join(re.escape(n) for n in names)
    py = tb.call("grep", {"pattern": rf"^\s*(import|from)\s+({alt})\b", "glob": "**/*.py"})
    other = tb.call("grep", {"pattern": rf"\b({alt})\b", "glob": "**/*"})
    manifests = [m for m in other.get("matches", []) if re.search(r"(requirements.*\.txt|pyproject\.toml|setup\.cfg|Pipfile|\.lock)$", m["file"])]
    elsewhere = [m for m in other.get("matches", []) if m not in manifests and not m["file"].endswith(".py")]
    hist = tb.call("git_history", {"target": name})
    added = next((c for c in hist.get("commits", []) if "added" in c.get("changes", [])), None)
    evidence = [e for e in info.get("declared_at", []) if e.get("file")][:2]
    if added:
        evidence.append({"commit": added["commit"]})
    for m in (py.get("matches", []) + elsewhere)[:3]:
        evidence.append({"file": m["file"], "lines": str(m["line"])})
    used = py.get("matches") or elsewhere
    where = f"{py.get('files_searched', 0)} Python files" + (" and all text files" if other.get("source") == "repository" else "")
    if used:
        answer = (f"{name} is referenced outside the manifests: " +
                  ", ".join(f"{m['file']}:{m['line']}" for m in (py.get("matches", []) + elsewhere)[:4]) + ".")
        status, notable = "resolved", False
    else:
        decl = ", ".join(f"{e['file']}:{e.get('line')}" for e in info.get("declared_at", []) if e.get("file")) or "the manifest"
        answer = f"No import or reference to {name} ({', '.join(names)}) was found in {where}; it only appears in {decl}."
        status, notable = "resolved", bool(d.get("new_in_diff"))
    if added:
        same = next((c for c in ctx.changes.get("commits", []) if c["commit"] == added["commit"]), None)
        others = [i.lstrip("+ ").replace("+", "new ") for i in (same or {}).get("items", [])
                  if name.lower() not in i.lower()][:3]
        answer += (f" It was added in commit {added['commit'][:7]} ({fmt_date(added.get('date'))}, \"{added.get('message')}\")"
                   + (f", the same commit that introduced {'; '.join(others)}." if others else "."))
    return {"answer": answer, "evidence": evidence, "confidence": 0.9 if other.get("source") == "repository" else 0.7,
            "status": status, "notable": notable,
            "notable_reason": "a declared-but-unused package arrived in the same recent commit as other changes" if notable else "",
            "new_questions": []}


def pb_new_package(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    G = ctx.G
    d = G.nodes[q.subject]
    info = tb.call("pypi_info", {"package": d.get("name")})
    hist = tb.call("git_history", {"target": d.get("name")})
    br = ctx.blast.get(q.subject, {})
    evidence = [e for e in info.get("declared_at", []) if e.get("file")][:1]
    evidence += [{"file": e.get("file"), "lines": str(e.get("line"))} for e in br.get("evidence", [])[:2] if e.get("file")]
    for e in br.get("evidence", [])[:2]:
        tb.ledger.add(e)
    commit = next((c for c in hist.get("commits", [])), None)
    if commit:
        evidence.append({"commit": commit["commit"]})
    answer = (f"{d.get('name')} {d.get('version') or ''} is used by {', '.join(br.get('file_list', [])) or 'no file'}"
              f" (blast radius: {br.get('radius', 'unknown')}).")
    if commit:
        answer += f" Change: {', '.join(commit.get('changes', []))} in commit {commit['commit'][:7]} (\"{commit.get('message')}\")."
    return {"answer": answer, "evidence": evidence, "confidence": 0.8, "status": "resolved", "notable": False,
            "notable_reason": "", "new_questions": []}


def pb_large_radius(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    G = ctx.G
    d = G.nodes[q.subject]
    info = tb.call("pypi_info", {"package": d.get("name")})
    br = ctx.blast.get(q.subject, {})
    uses = []
    evidence = []
    for u, _, e in in_edges(G, q.subject, "CALLS_API")[:4]:
        item = (e.get("evidence") or [{}])[0]
        line = item.get("line")
        args: list[str] = []
        if item.get("file") and line:
            site = tb.call("read_code", {"file": item["file"], "start": line, "end": line + 2})
            text = " ".join(_line_text(site, n) for n in range(line, line + 3))
            m = re.search(re.escape(e.get("target", "").split(".")[-1]) + r"\((.*?)\)", text)
            args = re.findall(r"(\w+)\s*=", m.group(1) if m else text)
            evidence.append({"file": item["file"], "lines": str(line)})
        uses.append(f"{e.get('target')} in {short_label(u)}" + (f" at {item.get('file')}:{line}" if line else "")
                    + (f" with {', '.join(args)}" if args else ""))
    if not uses:
        for f in br.get("file_list", [])[:2]:
            r = tb.call("grep", {"pattern": rf"\b{re.escape(d.get('name', '').lower())}\.", "glob": f})
            for m in r.get("matches", [])[:2]:
                uses.append(f"{m['text']} at {m['file']}:{m['line']}")
                evidence.append({"file": m["file"], "lines": str(m["line"])})
    evidence += [e for e in info.get("declared_at", []) if e.get("file")][:1]
    nearby = [s[4:] for s in br.get("secrets_nearby", [])] + [t[6:] + " table" for t in br.get("tables_nearby", [])] + \
             [G.nodes[s].get("name", s) for s in br.get("services_nearby", [])]
    answer = (f"{d.get('name')} is used as: " + ("; ".join(uses) if uses else "import only (no API call recorded)") +
              f". Reachable from {', '.join(r[6:] for r in br.get('routes_reaching', [])) or 'no route'}"
              + (f"; nearby: {', '.join(nearby)}." if nearby else "."))
    return {"answer": answer, "evidence": evidence, "confidence": 0.85 if uses else 0.6, "status": "resolved",
            "notable": False, "notable_reason": "", "new_questions": []}


def pb_new_module(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    G = ctx.G
    m = q.subject
    d = G.nodes[m]
    tb.call("query_graph", {"node_id": m, "edge_types": ["DEPENDS_ON", "CONTAINS"], "direction": "both"})
    card = tb.call("get_card", {"node_id": m}).get("card", {})
    files = d.get("files", [])
    main = next((f for f in files if not f.endswith("__init__.py")), files[0] if files else None)
    hist = tb.call("git_history", {"target": main}) if main else {}
    intro = _git_first_commit(hist)
    users = [G.nodes[x].get("name") for x in pred(G, m, "DEPENDS_ON")]
    evidence = [e for e in card.get("evidence", [])[:2]]
    if intro:
        evidence.append({"commit": intro["commit"]})
    services = sorted({G.nodes[s].get("name") for f in files for fn in succ(G, f"file:{f}", "CONTAINS")
                       for s in succ(G, fn, "CONTACTS")})
    answer = (f"Module {d.get('path')} ({len(files)} file{'s' if len(files) != 1 else ''}: {', '.join(files)})"
              + (f" was added in commit {intro['commit'][:7]} ({fmt_date(intro.get('date'))}, \"{intro.get('message')}\")" if intro else " is new since the baseline")
              + f". {card.get('purpose', '')}"
              + (f" It is used by {', '.join(users)}." if users else " Nothing imports it yet."))
    notable = bool(services)
    return {"answer": answer.strip(), "evidence": evidence, "confidence": 0.8, "status": "resolved",
            "notable": notable,
            "notable_reason": f"new module contacts {', '.join(services)}" if notable else "", "new_questions": []}


def pb_tightly_coupled(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    G = ctx.G
    a, b = q.context.get("modules") or q.subject.split("|")
    tb.call("query_graph", {"node_id": a, "edge_types": ["DEPENDS_ON"], "direction": "both"})
    w_ab = sum(d.get("weight", 1) for _, v, d in out_edges(G, a, "DEPENDS_ON") if v == b)
    w_ba = sum(d.get("weight", 1) for _, v, d in out_edges(G, b, "DEPENDS_ON") if v == a)
    evidence = [e for _, v, d in out_edges(G, a, "DEPENDS_ON") + out_edges(G, b, "DEPENDS_ON")
                if v in (a, b) for e in d.get("evidence", [])[:1]]
    na, nb = G.nodes[a].get("name"), G.nodes[b].get("name")
    shape = "mutual" if w_ab and w_ba else "one-directional"
    answer = (f"{na} → {nb}: {w_ab} import(s); {nb} → {na}: {w_ba}. Import clustering groups their files together, "
              f"but the dependency is {shape}" + (", so the folders still read as separate layers." if shape == "one-directional"
                                                  else ", so they behave like one unit split across folders."))
    return {"answer": answer, "evidence": evidence, "confidence": 0.7, "status": "resolved", "notable": False,
            "notable_reason": "", "new_questions": []}


def pb_undeclared(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    name = q.subject.removeprefix("import:")
    if name.startswith("pkg:"):
        name = ctx.G.nodes[name].get("name", name)
    info = tb.call("pypi_info", {"package": name})
    imports = tb.call("grep", {"pattern": rf"^\s*(import|from)\s+{re.escape(name)}\b"})
    evidence = [{"file": m["file"], "lines": str(m["line"])} for m in imports.get("matches", [])[:3]]
    if "error" not in info:
        req = info.get("required_by") or []
        answer = (f"{name} {info.get('version') or ''} is not declared directly; it is installed transitively"
                  + (f" because {', '.join(map(str, req))} require{'s' if len(req) == 1 else ''} it." if req else "."))
        status = "resolved"
    else:
        local = tb.call("grep", {"pattern": ".", "glob": f"**/{name}/__init__.py"})
        if local.get("matches"):
            answer = f"{name} is vendored in the repository ({local['matches'][0]['file']})."
            evidence.append({"file": local["matches"][0]["file"], "lines": "1"})
            status = "resolved"
        else:
            answer = f"{name} is imported but neither declared, resolved nor vendored: its origin is missing from the manifests."
            status = "resolved" if evidence else "unresolved"
    return {"answer": answer, "evidence": evidence, "confidence": 0.75, "status": status, "notable": False,
            "notable_reason": "", "new_questions": []}


def pb_dynamic(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    f, line = q.context.get("file"), q.context.get("line")
    evidence = []
    expr = q.context.get("expr")
    if f and line:
        r = tb.call("read_code", {"file": f, "start": line, "end": line})
        expr = _line_text(r, line).strip() or expr
        evidence.append({"file": f, "lines": str(line)})
    return {"answer": f"`{expr}` computes the module name at runtime; static analysis cannot list what it loads.",
            "evidence": evidence, "confidence": 0.5, "status": "unresolved", "notable": False, "notable_reason": "",
            "new_questions": []}


def pb_generic(ctx: Stage3Context, q: Question, tb: Toolbox) -> dict:
    G = ctx.G
    evidence = []
    facts = ""
    if q.subject in G:
        card = tb.call("get_card", {"node_id": q.subject}).get("card")
        g = tb.call("query_graph", {"node_id": q.subject, "direction": "out"})
        fns = [n["node"] for n in g.get("neighbours", []) if n.get("node_type") == "Function"][:2]
        for fn in fns:
            fd = G.nodes[fn]
            tb.call("read_code", {"file": fd["file"], "start": fd["line"], "end": fd["end_line"]})
            evidence.append({"file": fd["file"], "lines": f"{fd['line']}-{fd['end_line']}"})
        if card:
            facts = f" Facts gathered: {card.get('purpose')}"
    return {"answer": "Needs an LLM to interpret the code; the deterministic investigator only collected facts." + facts,
            "evidence": evidence, "confidence": 0.3, "status": "unresolved", "notable": False, "notable_reason": "",
            "new_questions": []}


PLAYBOOKS: dict[str, Callable[[Stage3Context, Question, Toolbox], dict]] = {
    "outbound_data": pb_outbound,
    "new_contact": pb_new_contact,
    "declared_unused": pb_declared_unused,
    "new_package": pb_new_package,
    "large_radius": pb_large_radius,
    "new_module": pb_new_module,
    "tightly_coupled": pb_tightly_coupled,
    "undeclared_import": pb_undeclared,
    "dynamic_import": pb_dynamic,
    "low_confidence": pb_generic,
    "followup": pb_generic,
}
