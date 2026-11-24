"""D5 Untrusted build environment: container base images, Dockerfile steps and CI/CD workflows."""
from __future__ import annotations

import re

import yaml

from guardian.stage3_knowledge.graph_builder import nodes_of

from ..context import Stage5Context
from ..schema import Signal

OFFICIAL_REGISTRIES = ("docker.io", "index.docker.io", "registry-1.docker.io")
PIPE_SH = re.compile(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b")
PIP_INSTALL = re.compile(r"pip3?\s+install\s+(.+)")


def _images(ctx: Stage5Context) -> list[Signal]:
    sigs = []
    G = ctx.G
    for img in sorted(nodes_of(G, "Image")):
        d = G.nodes[img]
        ref = d.get("ref") or img[6:]
        ev = [e for e in d.get("evidence", []) if e.get("file")][:1]
        tag = d.get("image_tag") or (ref.split(":")[-1] if ":" in ref.split("/")[-1] else None)
        if not d.get("digest"):
            weak_why = "uses the 'latest' tag" if tag == "latest" else ("has no tag" if not tag else f"is pinned by tag ({tag}), not digest")
            sigs.append(Signal(detector="D5", check="image_not_digest_pinned", subject=img, subject_label=ref,
                               data={"tag": tag, "digest": None}, evidence=ev, strength="weak",
                               text=f"base image {ref} {weak_why}"))
        name = ref.split("@")[0].rsplit(":", 1)[0] if ":" in ref.split("/")[-1] else ref.split("@")[0]
        parts = name.split("/")
        registry = parts[0] if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]) else "docker.io"
        if registry not in OFFICIAL_REGISTRIES:
            sigs.append(Signal(detector="D5", check="image_unknown_registry", subject=img, subject_label=ref,
                               data={"registry": registry}, evidence=ev, strength="medium",
                               text=f"{ref} comes from registry {registry}"))
        elif len(parts) > 1 and parts[0] != "library" and registry == "docker.io":
            sigs.append(Signal(detector="D5", check="image_non_official", subject=img, subject_label=ref,
                               data={"namespace": parts[0]}, evidence=ev, strength="medium",
                               text=f"{ref} is not an official Docker Hub image"))
    declared = {n.lower() for n in (d.get("name", "") for d in ctx.s3.facts.get("declared_dependencies", []) or [])}
    for c in ctx.s3.facts.get("containers", []) or []:
        f = c.get("file")
        img = next((f"image:{b['ref']}" for b in c.get("base_images", []) or []), f"file:{f}")
        for rf in c.get("remote_fetches", []) or []:
            cmd = rf.get("cmd", "")
            if PIPE_SH.search(cmd) or cmd.upper().startswith("ADD"):
                sigs.append(Signal(detector="D5", check="remote_script", subject=img, subject_label=f,
                                   data={"cmd": cmd[:160], "file": f}, evidence=[{"file": f, "line": rf.get("line")}],
                                   strength="medium", behaviour=True,
                                   text=f"{f}:{rf.get('line')} downloads and runs a remote script ({cmd[:60]})"))
        for pi in c.get("pip_installs", []) or []:
            m = PIP_INSTALL.search(pi.get("cmd", ""))
            if not m:
                continue
            pkgs = [t for t in m.group(1).split() if not t.startswith("-") and "requirements" not in t and "." != t]
            shadow = [p for p in pkgs if re.split(r"[<>=!~\[]", p)[0].lower() not in declared]
            if shadow:
                sigs.append(Signal(detector="D5", check="shadow_install", subject=img, subject_label=f,
                                   data={"packages": shadow}, evidence=[{"file": f, "line": pi.get("line")}], strength="medium",
                                   text=f"{f} installs {', '.join(shadow)}, which no manifest declares"))
    return sigs


def _line_of(lines: list[str], pattern: str) -> int | None:
    for i, l in enumerate(lines, 1):
        if re.search(pattern, l):
            return i
    return None


def _workflows(ctx: Stage5Context) -> list[Signal]:
    sigs = []
    src = ctx.s3.source
    for wf in ctx.s3.facts.get("ci_workflows", []) or []:
        f = wf.get("file")
        wid = f"workflow:{f}"
        text = "\n".join(t for _, t in src.read_lines(f)) if src.available else ""
        lines = text.splitlines()
        try:
            doc = yaml.safe_load(text) if text else {}
        except yaml.YAMLError:
            doc = {}
        triggers = set(wf.get("triggers") or [])
        if isinstance(doc, dict):
            on = doc.get("on", doc.get(True))
            triggers |= set(on if isinstance(on, (list, dict)) else [on] if on else [])
        for a in wf.get("actions", []) or []:
            owner = (a.get("uses") or "").split("/")[0]
            if not a.get("pinned_to_sha") and owner not in ("actions", "github"):
                sigs.append(Signal(detector="D5", check="action_not_sha_pinned", subject=wid, subject_label=f,
                                   data={"action": f"{a.get('uses')}@{a.get('ref')}"}, evidence=[{"file": f, "line": a.get("line")}],
                                   strength="weak", text=f"third-party action {a.get('uses')}@{a.get('ref')} is pinned by tag, not SHA"))
        if "pull_request_target" in triggers:
            ln = _line_of(lines, r"github\.event\.pull_request\.head\.(sha|ref)|refs/pull/")
            if ln:
                sigs.append(Signal(detector="D5", check="pull_request_target_checkout_head", subject=wid, subject_label=f,
                                   data={"trigger": "pull_request_target"},
                                   evidence=[{"file": f, "line": _line_of(lines, r"pull_request_target")}, {"file": f, "line": ln}],
                                   strength="strong", behaviour=True,
                                   text=f"{f} runs on pull_request_target and checks out the PR head: fork code runs with repository secrets"))
        perms = wf.get("permissions") if wf.get("permissions") is not None else (doc or {}).get("permissions") if isinstance(doc, dict) else None
        if perms is None or perms == "write-all":
            sigs.append(Signal(detector="D5", check="permissions_missing_or_write_all", subject=wid, subject_label=f,
                               data={"permissions": perms}, evidence=[{"file": f, "line": 1}], strength="weak",
                               text=f"{f} " + ("grants write-all" if perms == "write-all" else "sets no permissions (defaults apply)")))
        pr = triggers & {"pull_request", "pull_request_target"}
        for st in wf.get("run_steps", []) or []:
            if PIPE_SH.search(st.get("cmd", "")):
                sigs.append(Signal(detector="D5", check="ci_remote_script", subject=wid, subject_label=f, data={"cmd": st["cmd"][:120]},
                                   evidence=[{"file": f, "line": st.get("line")}], strength="medium",
                                   text=f"{f}:{st.get('line')} pipes a download into a shell"))
        if pr and wf.get("secrets_used"):
            ln = _line_of(lines, r"secrets\.")
            sigs.append(Signal(detector="D5", check="secrets_in_pr_workflow", subject=wid, subject_label=f,
                               data={"secrets": wf["secrets_used"], "triggers": sorted(pr)}, evidence=[{"file": f, "line": ln or 1}],
                               strength="medium", text=f"{f} exposes secrets {', '.join(wf['secrets_used'])} to a PR-triggered run"))
    return sigs


def detect(ctx: Stage5Context) -> list[Signal]:
    return _images(ctx) + _workflows(ctx)
