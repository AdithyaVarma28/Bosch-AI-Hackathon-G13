"""GitHub Actions workflow parsing. Facts only: triggers, permissions, uses (pinning), run steps, secret names."""
from __future__ import annotations

import re

import yaml

from ..models import RunStep, UsesRef, WorkflowFacts

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
OTHER_CI = (".gitlab-ci.yml", ".travis.yml", "Jenkinsfile", "azure-pipelines.yml", ".circleci/config.yml",
            "bitbucket-pipelines.yml", ".drone.yml")


def _triggers(on) -> list[str]:
    if on is None:
        return []
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(x) for x in on]
    if isinstance(on, dict):
        return [str(k) for k in on]
    return [str(on)]


def parse_workflow(rel_path: str, text: str) -> WorkflowFacts:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        data = {}
    # PyYAML (YAML 1.1) parses a bare `on:` key as boolean True.
    on = data.get("on", data.get(True))
    wf = WorkflowFacts(file=rel_path, name=data.get("name"), triggers=_triggers(on),
                       permissions=data.get("permissions"))
    for jname, job in (data.get("jobs") or {}).items():
        if isinstance(job, dict) and "permissions" in job:
            wf.job_permissions[str(jname)] = job["permissions"]

    # Line-accurate pass over the text for uses/run (YAML loses line numbers).
    lines = text.splitlines()
    in_jobs, job, job_indent = False, None, None
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if re.match(r"^jobs:\s*$", raw):
            in_jobs = True
        elif in_jobs and stripped and not stripped.startswith("#"):
            if job_indent is None and re.match(r"^[\w-]+:\s*$", stripped) and indent > 0:
                job_indent = indent
            if job_indent is not None and indent == job_indent and re.match(r"^[\w-]+:\s*$", stripped):
                job = stripped[:-1]
        m = re.match(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)", raw)
        if m:
            uses = m.group(1)
            action, _, ref = uses.partition("@")
            wf.actions.append(UsesRef(line=i + 1, uses=uses, action=action, ref=ref or None,
                                      pinned_to_sha=bool(ref and SHA_RE.match(ref)) or action.startswith("./"),
                                      job=job))
        m = re.match(r"^(\s*)(?:-\s*)?run:\s*(.*)$", raw)
        if m:
            first = m.group(2).strip()
            if first in ("|", ">", "|-", ">-", "|+", ">+") or first == "":
                body, j = [], i + 1
                base = None
                while j < len(lines):
                    nxt = lines[j]
                    if nxt.strip() == "":
                        body.append("")
                        j += 1
                        continue
                    ind = len(nxt) - len(nxt.lstrip())
                    if base is None:
                        base = ind
                    if ind < base or ind <= len(m.group(1)):
                        break
                    body.append(nxt[base:])
                    j += 1
                cmd = "\n".join(body).strip()
            else:
                cmd = first
            wf.run_steps.append(RunStep(line=i + 1, cmd=cmd[:2000], job=job))
        i += 1
    wf.secrets_used = sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text)) - {"GITHUB_TOKEN"} | (
        {"GITHUB_TOKEN"} if "secrets.GITHUB_TOKEN" in text else set()))
    return wf
