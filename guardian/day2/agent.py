"""Step B: the remediation agent (docs/DAY_2_PLAN.md section 4.2). A bounded tool loop (the Stage 4 loop) with
Agent Skills loaded on demand. Its submission is validated like any untrusted input: edits must apply, files must be
allowed by the chosen skill, versions must have been checked, evidence ids must exist."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from packaging.version import InvalidVersion, Version

from . import skills as skillmod
from .common import load_config, read_json, REGISTER_FILE
from .critic import expected_after
from .patches import check as patch_check, safe_path

PROMPTS = Path(__file__).parent / "prompts"
DEFAULT_LARGE = "openai/gpt-oss-120b"

EDIT_ITEM = {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string"},
                                             "new_text": {"type": "string"}}, "required": ["path", "old_text", "new_text"]}
TOOLS = [
    {"name": "load_skill", "description": "Load the full playbook of one skill from the skill index.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "get_evidence", "description": "The finding's evidence: call sites, trigger conditions, evidence ids, advisory fix.",
     "input_schema": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
    {"name": "read_file", "description": "Read lines of a repository file (read-only).",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "start": {"type": "integer"},
                                                       "end": {"type": "integer"}}, "required": ["path"]}},
    {"name": "list_candidates", "description": "The deterministic remediation candidates with their check results.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "check_version", "description": "Check a package version: known vulnerabilities (OSV), dependency constraints, availability, Python compatibility.",
     "input_schema": {"type": "object", "properties": {"package": {"type": "string"}, "version": {"type": "string"}},
                      "required": ["package", "version"]}},
    {"name": "make_patch", "description": "Validate exact-snippet edits against the repository and get the unified diff.",
     "input_schema": {"type": "object", "properties": {"edits": {"type": "array", "items": EDIT_ITEM}}, "required": ["edits"]}},
]
SUBMIT = {"name": "submit_proposal", "description": "Submit the final proposal.",
          "input_schema": {"type": "object", "properties": {
              "skill": {"type": "string", "description": "the skill you loaded and followed"},
              "action": {"type": "string", "description": "one plain-English sentence for the reviewer, e.g. 'Replace yaml.load(..., FullLoader) with yaml.safe_load in load_settings()'"},
              "edits": {"type": "array", "items": EDIT_ITEM},
              "target_version": {"type": "string"},
              "expected_effect": {"type": "string", "enum": ["resolved", "reduced", "partly resolved", "unchanged"]},
              "compatibility": {"type": "array", "items": {"type": "string"}},
              "rollback": {"type": "string"},
              "alternatives_rejected": {"type": "array", "items": {"type": "object", "properties": {
                  "candidate": {"type": "string"}, "why": {"type": "string"}}}},
              "evidence_ids": {"type": "array", "items": {"type": "string"}}},
              "required": ["skill", "action", "edits", "expected_effect", "compatibility", "rollback", "evidence_ids"]}}


class Toolbox:
    def __init__(self, out: Path, unit: dict, register: dict[str, dict], repo: Optional[Path], budget: int):
        from .candidates import RepoFiles, VersionTools
        self.out, self.unit, self.register, self.repo = out, unit, register, repo
        self.budget, self.used = budget, 0
        self.skills = skillmod.discover()
        self.loaded: set[str] = set()
        self.checked: set[tuple[str, str]] = set()
        self.vt = VersionTools(out, RepoFiles(repo))
        self.trace: list[dict] = []

    @property
    def exhausted(self) -> bool:
        return self.used >= self.budget

    def call(self, name: str, args: dict) -> dict:
        self.used += 1
        try:
            out = getattr(self, f"t_{name}")(**args)
        except AttributeError:
            out = {"error": f"unknown tool {name}"}
        except TypeError as exc:
            out = {"error": f"bad arguments: {exc}"}
        except Exception as exc:
            out = {"error": f"{type(exc).__name__}: {exc}"}
        self.trace.append({"tool": name, "input": json.dumps(args)[:300], "ok": "error" not in out,
                           "result": (out.get("error") or out.get("summary") or "ok")[:300]})
        return out

    def t_load_skill(self, name: str) -> dict:
        s = self.skills.get(name)
        if not s:
            return {"error": f"no skill {name!r}; choose one of {list(self.skills)}"}
        self.loaded.add(name)
        return {"summary": f"loaded {name}", "skill": s.body(), "allowed_files": s.allowed_files}

    def t_get_evidence(self, finding_id: str) -> dict:
        e = self.register.get(finding_id)
        if not e or finding_id not in self.unit["finding_ids"]:
            return {"error": f"{finding_id} is not part of this remediation ({self.unit['finding_ids']})"}
        keys = ("finding_id", "title", "component", "vuln_id", "summary", "usage", "reachability", "exposure", "scope",
                "usage_sites", "conditions", "evidence", "recommendation", "fixed_versions", "signals", "priority",
                "decision", "decision_why")
        return {"summary": f"evidence for {finding_id}", **{k: e.get(k) for k in keys if e.get(k) not in (None, [], {})}}

    def t_read_file(self, path: str, start: int = 1, end: int = 120, **_ignored) -> dict:
        if not self.repo:
            return {"error": "repository not on disk"}
        p = safe_path(self.repo, path)
        if not p.is_file():
            return {"error": f"{path} not found"}
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        start, end = max(1, int(start)), min(len(lines), int(end), int(start) + 199)
        return {"summary": f"{path}:{start}-{end}", "lines": "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))}

    def t_list_candidates(self) -> dict:
        return {"summary": f"{len(self.unit['candidates'])} candidates", "candidates": [
            {"cid": c["cid"], "kind": c["kind"], "skill": c.get("skill"), "label": c["label"],
             "target_version": c.get("target_version"), "excluded": c.get("excluded", False),
             "checks": {k: v["status"] + ": " + v["detail"] for k, v in (c.get("checks") or {}).items()},
             "notes": c.get("notes"), "edits": c.get("edits")} for c in self.unit["candidates"]]}

    def t_check_version(self, package: str, version: str) -> dict:
        res = self.vt.check(package, version)
        self.checked.add((package.lower(), version))
        return {"summary": f"{package} {version}: " + ", ".join(f"{k} {v['status']}" for k, v in res.items()), "checks": res}

    def t_make_patch(self, edits: list[dict]) -> dict:
        ok, detail, diff = patch_check(self.repo, edits)
        return {"summary": detail, "applies": ok, "diff": diff[:4000]} if ok else {"error": detail}


def make_llm(out: Path, large: bool):
    from guardian.stage3_knowledge.llm import LLM, _load_dotenv
    _load_dotenv()                    # GROQ_API_KEY may only be in .env: load it before choosing the large model
    model = None
    if large:
        model = os.environ.get("GUARDIAN_MODEL_LARGE") or (DEFAULT_LARGE if os.environ.get("GROQ_API_KEY") else None)
    llm = LLM(cache_dir=Path(out) / ".llm_cache", model=model)
    llm.purposes = None               # a person asked for this call: it is not limited by the scan-time purposes
    return llm


def unit_prompt(unit: dict, register: dict[str, dict], feedback: Optional[str], current: Optional[dict]) -> str:
    fs = []
    for fid in unit["finding_ids"]:
        e = register.get(fid, {})
        fs.append(f"- {fid} [{e.get('kind')}/{e.get('subtype')}] {e.get('title')} — priority {e.get('priority')}, "
                  f"decision {e.get('decision')}; usage {e.get('usage') or e.get('exposure')}")
    cur = (f"Current proposal (v{len(unit['proposals'])}, by {current['author']}): {current['action']}\n"
           f"Its checks: " + ", ".join(f"{k}={v.get('status')}" for k, v in (current.get('checks') or {}).items())) if current else "No proposal yet."
    return "\n".join([
        f"Remediation {unit['rid']} for {unit['target_label']} ({unit['target']}). Findings:", *fs, "", cur, "",
        "Candidates (call list_candidates for details): " + "; ".join(f"#{c['cid']} {c['label']}" for c in unit["candidates"]),
        "", f"Human feedback: {feedback}" if feedback else "No human feedback: propose the safest effective fix.",
        "", "Skill index:", skillmod.index_text(skillmod.discover()),
    ])


def validate_submission(sub: dict, tb: Toolbox, unit: dict) -> tuple[Optional[dict], str]:
    sk = skillmod.get(sub.get("skill"))
    action = (sub.get("action") or "").strip()
    if action in ("submit_proposal", "make_patch") or (action and " " not in action):
        action = ""           # the model echoed a tool name: rebuild a readable action below
    edits = sub.get("edits") or []
    if not action and edits:
        files = sorted({e.get("path") for e in edits})
        action = f"{(sk.name if sk else 'change').replace('-', ' ').capitalize()}: edit {', '.join(files)}"
    if not action:
        return None, "empty action"
    if not edits and not action.lower().startswith("escalate"):
        return None, "no edits and not an escalation"
    if edits and not sk:
        return None, f"unknown skill {sub.get('skill')!r}"
    if edits:
        bad = [e.get("path") for e in edits if not sk.allows(e.get("path", ""))]
        if bad:
            return None, f"skill {sk.name} may not change {bad}"
        ok, detail, _ = patch_check(tb.repo, edits)
        if not ok:
            return None, f"patch does not apply: {detail}"
    known = {x["id"] for fid in unit["finding_ids"] for x in tb.register.get(fid, {}).get("evidence") or []}
    bad_ids = [i for i in sub.get("evidence_ids") or [] if i not in known]
    if bad_ids:
        return None, f"unknown evidence ids {bad_ids}"
    tv = (sub.get("target_version") or "").strip() or None
    from .common import purl_name_version
    pname, cur = purl_name_version(unit["target"])
    if tv:
        cand_versions = {c.get("target_version") for c in unit["candidates"] if not c.get("excluded")}
        if tv not in cand_versions and (pname.lower(), tv) not in tb.checked:
            return None, f"version {tv} was neither a candidate nor checked with check_version"
    kind = {"upgrade-dependency": "upgrade", "replace-unsafe-api": "replace_api", "remove-or-block-package": "remove",
            "harden-ci-cd": "harden_ci"}.get(sk.name if sk else "", "escalate")
    if kind == "upgrade" and tv and cur:
        try:
            if Version(tv) < Version(cur):
                kind = "pin_back"
        except InvalidVersion:
            pass
    if kind == "remove" and edits and all("sha256:" in (e.get("old_text") or "") for e in edits):
        kind = "restore_hash"
    checks = tb.vt.check(pname, tv) if tv and pname else {}
    eff = sub.get("expected_effect") or "resolved"
    notes = []
    if kind == "replace_api" and eff == "resolved" and unit["target"].startswith("pkg:"):
        eff = "reduced"       # the advisory still matches the installed version: be honest about it
        notes.append("effect set to 'reduced': the vulnerable call is gone but the package version still matches the advisory")
    if sk and sk.name not in tb.loaded:
        notes.append(f"the agent did not load the {sk.name} playbook before proposing (scope still enforced)")
    return {"kind": kind, "skill": sk.name if sk else None, "action": action, "edits": edits, "target_version": tv,
            "expected_risk": {"before": unit["priority"], "after": expected_after(unit["priority"], eff), "effect": eff},
            "compatibility": sub.get("compatibility") or [], "notes": notes, "rollback": sub.get("rollback"),
            "alternatives_rejected": sub.get("alternatives_rejected") or [], "evidence_ids": sub.get("evidence_ids") or [],
            "candidate_checks": checks, "_current_version": cur or None}, "ok"


def run_agent(out: Path, unit: dict, feedback: Optional[str], large: bool = False) -> tuple[Optional[dict], dict]:
    """(proposal fields or None, info{model, trace, error, skills_loaded})."""
    from guardian.stage4_vulns.agent import run_tool_agent
    from .common import repo_path
    out = Path(out)
    register = {e["finding_id"]: e for e in read_json(out / REGISTER_FILE, []) or []}
    repo = repo_path(out)
    current = unit["proposals"][-1] if unit["proposals"] else None
    info: dict = {}
    for attempt_large in ([True, False] if large else [False]):
        llm = make_llm(out, attempt_large)
        info = {"model": llm.model, "provider": llm.provider_name}
        if not llm.available:
            info["error"] = f"no LLM available: {llm.disabled_reason}"
            continue
        tb = Toolbox(out, unit, register, repo, budget=12 if attempt_large else 8)
        sub = run_tool_agent(llm, "remediate", (PROMPTS / "remediate_system.md").read_text(encoding="utf-8"),
                             unit_prompt(unit, register, feedback, current), tb, TOOLS, SUBMIT)
        info.update({"trace": tb.trace, "skills_loaded": sorted(tb.loaded), "tool_calls": tb.used})
        if sub is None:
            info["error"] = "the model did not answer (" + ("; ".join(llm.errors[-1:]) or "unavailable") + ")"
            continue
        if sub.get("__budget_exhausted"):
            info["error"] = "tool budget exhausted before a proposal was submitted"
            return None, info
        prop, why = validate_submission(sub, tb, unit)
        if prop is None:
            info["error"] = f"agent proposal rejected: {why}"
            return None, info
        return prop, info
    return None, info
