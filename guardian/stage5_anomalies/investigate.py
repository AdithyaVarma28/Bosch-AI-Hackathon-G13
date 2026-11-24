"""Stage 5 investigator: the Stage 4 pattern (bounded tools, evidence ledger, verifier) per subject.

Extra tools: pypi_info, compare_names, package_diff, read_package_file, scan_install_hooks, exposure.
Package-file evidence is cited as ``pkg:<name>@<version>/<path>`` with line ranges and is only accepted
if ``read_package_file`` returned those lines.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from guardian.stage3_knowledge.schema import Evidence
from guardian.stage4_vulns.agent import run_tool_agent
from guardian.stage4_vulns.tools import TOOL_SPECS as S4_SPECS
from guardian.stage4_vulns.tools import VulnToolbox, dumps
from guardian.stage4_vulns.verifier import deterministic_check

from .context import Stage5Context
from .detectors.d1_typosquat import candidates
from .detectors.d3_updates import code_diff, release_info
from .rules import exposure, subject_name
from .schema import AnomalyClaim, AnomalyInvestigation, Behaviour, Signal

PROMPTS = Path(__file__).resolve().parent / "prompts"
PKG_FILE = re.compile(r"^pkg:([^@]+)@([^/]+)/(.+)$")


def _s4spec(name):
    return next(s for s in S4_SPECS if s["name"] == name)


TOOL_SPECS = [_s4spec(n) for n in ("query_graph", "read_code", "search_code", "git_history")] + [
    {"name": "pypi_info", "description": "Release metadata of a package version: authors, maintainers, project URLs, files, hashes, upload times, releases.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}, "version": {"type": "string"}}, "required": ["name"]}},
    {"name": "compare_names", "description": "Closest popular PyPI packages to a name, with the rule that matched and download counts.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "package_diff", "description": "Files changed between two versions and behaviour (network, exec, subprocess, env, URLs) added in them; parse-only sandbox.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}, "old": {"type": "string"}, "new": {"type": "string"}},
                      "required": ["name", "old", "new"]}},
    {"name": "read_package_file", "description": "Lines (max 120) of a file inside an unpacked distribution, e.g. path 'reqeusts-2.31.0/setup.py'.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}, "version": {"type": "string"}, "path": {"type": "string"},
                                                       "start": {"type": "integer"}, "end": {"type": "integer"}},
                      "required": ["name", "version", "path", "start", "end"]}},
    {"name": "scan_install_hooks", "description": "Install-time behaviour of a package version (setup.py, build hooks, .pth files).",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}, "version": {"type": "string"}}, "required": ["name", "version"]}},
    {"name": "exposure", "description": "Whether a subject is in the install set, whether its code runs on install or import, who imports it, blast radius.",
     "input_schema": {"type": "object", "properties": {"subject": {"type": "string"}}, "required": ["subject"]}},
]

SUBMIT_SPEC = {
    "name": "submit_anomaly", "description": "Record the investigation of this subject. Call exactly once.", "strict": True,
    "input_schema": {"type": "object", "properties": {
        "normal_explanation": {"type": "string", "description": "Empty if none was found"},
        "behaviour": {"type": "array", "items": {"type": "object", "properties": {
            "type": {"type": "string"}, "file": {"type": "string"}, "lines": {"type": "string"}, "detail": {"type": "string"}},
            "required": ["type", "file", "lines", "detail"], "additionalProperties": False}},
        "capability": {"type": "string"},
        "claims": {"type": "array", "items": {"type": "object", "properties": {
            "text": {"type": "string"}, "evidence": {"type": "array", "items": {"type": "object", "properties": {
                "file": {"type": "string"}, "lines": {"type": "string"}}, "required": ["file", "lines"], "additionalProperties": False}}},
            "required": ["text", "evidence"], "additionalProperties": False}},
        "unknowns": {"type": "array", "items": {"type": "string"}}},
        "required": ["normal_explanation", "behaviour", "capability", "claims", "unknowns"], "additionalProperties": False},
}


class AnomalyToolbox(VulnToolbox):
    def __init__(self, ctx5: Stage5Context, sigs: list[Signal], budget: int = 10, emit=lambda e: None, stage="investigator"):
        super().__init__(ctx5.s4, budget=budget, emit=emit, stage=stage)
        self.ctx5 = ctx5
        self.sigs = sigs

    def t_pypi_info(self, name: str, version: Optional[str] = None) -> dict:
        proj = self.ctx5.pypi.project(name)
        if not proj:
            return {"error": f"{name} not found on {self.ctx5.pypi.source}"}
        info = release_info(self.ctx5, name, version) if version else {}
        self.ledger.urls.add(f"pypi:{name}")
        return {"name": name, "releases": sorted((proj.get("releases") or {}).keys())[-12:],
                "latest": (proj.get("info") or {}).get("version"),
                "version": version, **{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in info.items() if k != "files"},
                "files": [{k: f.get(k) for k in ("filename", "packagetype", "upload_time_iso_8601")} | {"sha256": (f.get("digests") or {}).get("sha256")}
                          for f in info.get("files", [])]}

    def t_compare_names(self, name: str) -> dict:
        return {"name": name, "in_top_list": name.lower() in self.ctx5.top, "closest": candidates(name, self.ctx5.top)}

    def t_package_diff(self, name: str, old: str, new: str) -> dict:
        d = code_diff(self.ctx5, name, old, new, release_info(self.ctx5, name, old), release_info(self.ctx5, name, new))
        return d

    def t_scan_install_hooks(self, name: str, version: str) -> dict:
        a = self.ctx5.analyze_dist(name, version, "sdist")
        if a.get("error"):
            return {"error": a["error"]}
        hooks = {k: v for k, v in a.get("ast", {}).items() if k.rsplit("/", 1)[-1] in ("setup.py", "build_backend.py")}
        return {"files": list(a.get("files", {}))[:30], "install_files": hooks, "pth": a.get("pth"), "isolation": a.get("isolation")}

    def t_read_package_file(self, name: str, version: str, path: str, start: int, end: int) -> dict:
        start, end = int(start), int(end)
        lines = self.ctx5.package_file_lines(name, version, path, start, end)
        if not lines:
            # analyse on demand (sdist first), then retry
            self.ctx5.analyze_dist(name, version, "sdist")
            self.ctx5.analyze_dist(name, version, "bdist_wheel")
            lines = self.ctx5.package_file_lines(name, version, path, start, end)
        if not lines:
            return {"error": f"{path} not found in the unpacked {name} {version}"}
        self.ledger.add_file(f"pkg:{name}@{version}/{path}", lines[0][0], lines[-1][0])
        return {"package": f"{name}@{version}", "path": path, "lines": [f"{i}: {t}" for i, t in lines]}

    def t_exposure(self, subject: str) -> dict:
        exp, note = exposure(self.ctx5, subject, [s for s in self.sigs if s.subject == subject] or self.sigs)
        if subject in self.G:
            self.ledger.nodes.add(subject)
        br = self.ctx.blast.get(subject) or {}
        return {"subject": subject, "exposure": exp, "note": note, "blast_radius": br.get("radius"),
                "used_by_files": self.G.nodes.get(subject, {}).get("used_by_files")}


def _pkg_ev(ev: dict) -> Optional[tuple[str, str, str, int, int]]:
    m = PKG_FILE.match(ev.get("package_file", "") and f"pkg:{ev['package_file']}")
    if not m:
        return None
    rng = Evidence(lines=ev.get("lines")).line_range() or (1, 1)
    return m.group(1), m.group(2), m.group(3), rng[0], rng[1]


def _tokens(s: Signal) -> list[str]:
    toks = []
    for b in s.data.get("behaviour", []) or []:
        t = str(b.get("target", "")).split(".")[-1]
        if re.fullmatch(r"\w{3,}", t):
            toks.append(t)
    toks += [x for x in (s.data.get("domains") or [])]
    if s.check == "hash_mismatch":
        toks.append(s.data.get("lock_hash", ""))
    if s.check == "pull_request_target_checkout_head":
        toks += ["pull_request_target", "head"]
    if s.check == "new_outbound_domain":
        toks += [d.split(".")[0] for d in s.data.get("domains", [])] + ["post", "get", "request"]
    return [t for t in dict.fromkeys(toks) if t]


def playbook(ctx: Stage5Context, subject: str, sigs: list[Signal], tb: AnomalyToolbox) -> AnomalyInvestigation:
    inv = AnomalyInvestigation(subject=subject, signals=[s.signal_id for s in sigs])
    exp = tb.call("exposure", {"subject": subject})
    inv.exposure, inv.exposure_note = exp.get("exposure", "unknown"), exp.get("note", "")
    G = ctx.G
    is_pkg = subject in G and G.nodes[subject].get("type") == "Package"
    name = G.nodes[subject].get("name") if is_pkg else None
    ver = ctx.pkg_version(subject) if is_pkg else None
    if is_pkg and not tb.exhausted:
        tb.call("pypi_info", {"name": name, "version": ver})
    if any(s.detector == "D1" for s in sigs) and not tb.exhausted:
        tb.call("compare_names", {"name": name or subject})
    for s in sigs:
        if tb.exhausted:
            inv.budget_exhausted = True
            break
        cited: list[Evidence] = []
        for ev in s.evidence[:2]:
            pe = _pkg_ev(ev)
            if pe:
                n, v, path, a, b = pe
                r = tb.call("read_package_file", {"name": n, "version": v, "path": path, "start": a, "end": b})
                if "error" not in r:
                    cited.append(Evidence(file=f"pkg:{n}@{v}/{path}", lines=f"{a}-{b}"))
                    inv.behaviour.append(Behaviour(type=s.check, file=f"pkg:{n}@{v}/{path}", lines=f"{a}-{b}", detail=s.text))
            elif ev.get("file") and (ev.get("line") or ev.get("lines")):
                rng = Evidence(**{k: ev[k] for k in ("file", "line", "lines") if k in ev}).line_range()
                if rng and ctx.s3.source.available:
                    tb.call("read_code", {"file": ev["file"], "start": rng[0], "end": rng[1]})
                    cited.append(Evidence(file=ev["file"], lines=f"{rng[0]}-{rng[1]}"))
                    if s.behaviour:
                        inv.behaviour.append(Behaviour(type=s.check, file=ev["file"], lines=f"{rng[0]}-{rng[1]}", detail=s.text))
            elif ev.get("commit"):
                tb.ledger.commits.add(ev["commit"])
                cited.append(Evidence(commit=ev["commit"]))
        toks = _tokens(s)
        text = f"{s.signal_id}: {s.text}" + (f" (`{'`, `'.join(toks[:3])}`)" if toks else "")
        if cited:
            inv.claims.append(AnomalyClaim(text=text, evidence=cited))
    # normal explanation (D3 routine release): same people, wheels, and no behaviour added by the update
    d3 = [s for s in sigs if s.detector == "D3"]
    if d3 and not any(s.behaviour for s in sigs) and not any(s.detector in ("D1", "D4", "D6") for s in sigs):
        ctxd = d3[0].context
        old, new = ctxd.get("old", {}), ctxd.get("new", {})
        same_people = old.get("author") == new.get("author") and (old.get("maintainer") or "") == (new.get("maintainer") or "")
        hosts_old = {re.sub(r"^https?://([^/]+)/?([^/]*).*$", r"\1/\2", u) for u in (old.get("project_urls") or {}).values()}
        hosts_new = {re.sub(r"^https?://([^/]+)/?([^/]*).*$", r"\1/\2", u) for u in (new.get("project_urls") or {}).values()}
        deep = ctxd.get("deep_check", "")
        no_sdist_only = not any(s.check == "wheel_to_sdist_only" for s in d3)
        if same_people and hosts_new <= hosts_old | hosts_old and no_sdist_only and deep.startswith("no new behaviour"):
            label = d3[0].subject_label
            n = name or label.split()[0]
            parts = label.split()
            if len(parts) >= 4 and not tb.exhausted:
                diff = tb.call("package_diff", {"name": n, "old": parts[1], "new": parts[3]})
                if not diff.get("error") and not diff.get("new_behaviour"):
                    inv.normal_explanation = (f"routine release by the same author ({new.get('author')}); both versions ship wheels; "
                                              f"project URLs stay under the same project; the sandbox diff of "
                                              f"{len(diff.get('changed_files', []))} changed file(s) found no new behaviour")
                    inv.normal_explanation_verified = True
    caps = sorted({b.detail for b in inv.behaviour})
    inv.capability = "; ".join(caps)[:400] if caps else ("no dangerous behaviour found" if inv.normal_explanation else "metadata signals only")
    if not ctx.s3.source.available:
        inv.unknowns.append("repository source unavailable: repo-file evidence not re-read")
    if inv.exposure == "install_path":
        inv.unknowns.append("whether this project is actually installed from source in your CI or deployment")
    inv.tool_calls_used = tb.steps
    return inv


def agent(ctx: Stage5Context, subject: str, sigs: list[Signal], tb: AnomalyToolbox, base: AnomalyInvestigation) -> Optional[AnomalyInvestigation]:
    system = (PROMPTS / "anomaly_system.md").read_text(encoding="utf-8").replace("{max_steps}", str(tb.budget))
    user = (f"Subject: {subject} ({subject_name(ctx, subject)})\nSignals:\n" +
            "\n".join(f"- {s.signal_id} [{s.detector} {s.check}, {s.strength}] {s.text}; data={dumps(s.data)[:400]}; "
                      f"evidence={dumps(s.evidence)}; context={dumps(s.context)[:300]}" for s in sigs) +
            f"\nExposure (rules): {base.exposure} - {base.exposure_note}")
    raw = run_tool_agent(ctx.llm, "anomaly_investigator", system, user, tb, TOOL_SPECS, SUBMIT_SPEC)
    if raw is None:
        return None
    inv = base.model_copy(deep=True)
    inv.discovered_by = "ai"
    if raw.get("__budget_exhausted"):
        inv.budget_exhausted = True
        return inv
    claims = []
    for c in raw.get("claims") or []:
        ev = [Evidence(file=e["file"], lines=e["lines"]) for e in c.get("evidence") or [] if e.get("file")]
        good = [e for e in ev if tb.ledger.covers(e)]
        if not good:
            inv.dropped.append(f"claim without tool-returned evidence: {c.get('text', '')[:100]}")
            continue
        claims.append(AnomalyClaim(text=c["text"][:400], evidence=good))
    if claims:
        inv.claims = claims + [c for c in base.claims if c.text.split(":", 1)[0] not in {x.text.split(":", 1)[0] for x in claims}]
    if raw.get("capability"):
        inv.capability = raw["capability"][:400]
    ne = (raw.get("normal_explanation") or "").strip()
    if ne and not base.normal_explanation:
        inv.normal_explanation, inv.normal_explanation_verified = ne[:400], False   # AI-only: not verified by rules
    inv.unknowns = list(dict.fromkeys(base.unknowns + [u for u in raw.get("unknowns") or [] if u]))[:6]
    inv.tool_calls_used = tb.steps
    return inv


def investigate(ctx: Stage5Context, subject: str, sigs: list[Signal], emit=lambda e: None) -> tuple[AnomalyInvestigation, list[dict]]:
    budget = ctx.budgets.tool_calls
    base_tb = AnomalyToolbox(ctx, sigs, budget=budget, emit=emit)
    base = playbook(ctx, subject, sigs, base_tb)
    if ctx.llm.available or ctx.llm.cache_dir.exists():
        tb = AnomalyToolbox(ctx, sigs, budget=budget, emit=emit)
        inv = agent(ctx, subject, sigs, tb, base)
        if inv is not None:
            return inv, base_tb.activity + tb.activity
    return base, base_tb.activity


def verify(ctx: Stage5Context, inv: AnomalyInvestigation, sigs: list[Signal], emit=lambda e: None) -> tuple[bool, list[dict], list[dict]]:
    """Re-read every cited line (repo or package file) and check the claim's code names appear."""
    tb = AnomalyToolbox(ctx, sigs, budget=max(4, 2 * len(inv.claims) + 2), emit=emit, stage="verifier")
    checks = []
    for c in inv.claims:
        texts: list[str] = []
        for e in c.evidence[:2]:
            if not e.file:
                continue
            rng = e.line_range() or (1, 1)
            m = PKG_FILE.match(e.file)
            if m:
                r = tb.call("read_package_file", {"name": m.group(1), "version": m.group(2), "path": m.group(3),
                                                  "start": rng[0], "end": rng[1]})
                texts += r.get("lines") or []
            else:
                r = tb.call("verify_evidence", {"file": e.file, "lines": f"{rng[0]}-{rng[1]}"})
                texts += r.get("text") or []
        if any(e.commit for e in c.evidence) and not texts:
            ok, why = True, "commit evidence from the repository history"
        else:
            # only the backticked names are checked: the free text also names files and commits
            ok, why = deterministic_check(ctx.G, " ".join(re.findall(r"`[^`]+`", c.text)), c.evidence, texts)
        c.verified = ok
        checks.append({"text": c.text, "ok": ok, "reason": why, "lines": texts[:6]})
    return all(x["ok"] for x in checks), checks, tb.activity
