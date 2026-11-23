"""Container (Dockerfile/compose), CI (GitHub Actions) and secrets rules over S1 facts."""
from __future__ import annotations

import hashlib
import re
from importlib import resources

import yaml

from ..context import RunContext
from ..fsutil import read_text, rel, walk_files
from ..models import Finding

RULES = {
    "DF001": "Base image uses the mutable 'latest' tag (or no tag)",
    "DF002": "Base image is not pinned by digest",
    "DF003": "Container runs as root (no USER, or USER root)",
    "DF004": "ADD fetches a remote URL at build time",
    "DF005": "RUN pipes a remote download into a shell",
    "DF006": "Package install without pinned versions in RUN",
    "DF007": "End-of-life base image",
    "DC001": "Compose service image not pinned by digest",
    "CI001": "Third-party action pinned to a tag/branch, not a commit SHA",
    "CI002": "Workflow triggered by pull_request_target",
    "CI003": "Broad or missing workflow permissions",
    "CI004": "Untrusted GitHub context interpolated into a run step (script injection)",
    "SEC001": "Hard-coded credential in repository",
}

SECRET_PATTERNS = {
    "github_token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----"),
    "slack_token": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    "stripe_live_key": re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "npm_token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
}
SECRET_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".woff", ".woff2", ".ttf",
                   ".lock", ".svg", ".mp4", ".mp3", ".exe", ".dll", ".so", ".pyc", ".jar", ".class", ".bin"}
UNTRUSTED_CTX = re.compile(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|pages|commits|head_commit|discussion)[\w.\[\]*]*"
                           r"\.(title|body|message|label|name|email|ref|head_ref|default_branch|page_name)|github\.head_ref)\s*\}\}")


def _eol() -> dict:
    try:
        return yaml.safe_load(resources.files("guardian.data").joinpath("eol.yaml").read_text(encoding="utf-8")) or {}
    except (FileNotFoundError, ModuleNotFoundError):
        return {}


def redact(s: str) -> str:
    return s[:4] + "****" + f"({len(s)} chars)"


def _f(ctx, cls, rule, subject, locator, cls_sig, evidence_ids, **signals) -> Finding:
    return Finding(cls=cls, subject=subject, title=RULES[rule] + (f": {signals.get('detail')}" if signals.get("detail") else ""),
                   locator=locator, detector=cls, classification=cls_sig, raw_evidence_ids=[e for e in evidence_ids if e],
                   signals={"rule": rule, **signals})


def detect_container(ctx: RunContext) -> list[Finding]:
    out: list[Finding] = []
    if not ctx.facts:
        return out
    eol = _eol()
    stage_names = set()
    for df in ctx.facts.dockerfiles:
        stage_names |= {s.name for s in df.stages if s.name}
        for st in df.stages:
            if st.base_image in stage_names or st.base_image == "scratch":
                continue
            ref = st.base_image + (f":{st.tag}" if st.tag else "")
            loc = f"{df.file}:{st.line}"
            ev = ctx.store.add_evidence("raw", "dockerfile", loc, f"FROM {ref}{'@' + st.digest if st.digest else ''}").id
            if not st.digest and (st.tag in (None, "latest")):
                out.append(_f(ctx, "container", "DF001", ref, loc, "W", [ev], detail=ref, image=ref))
            elif not st.digest:
                out.append(_f(ctx, "container", "DF002", ref, loc, "W", [ev], detail=ref, image=ref))
            name = st.base_image.split("/")[-1]
            tag = st.tag or ""
            for bad in (eol.get("images") or {}).get(name, []):
                if tag == bad or tag.startswith(bad + ".") or tag.startswith(bad + "-"):
                    out.append(_f(ctx, "container", "DF007", ref, loc, "W", [ev], detail=f"{ref} (EOL as of {eol.get('as_of')})",
                                  image=ref, eol_as_of=eol.get("as_of")))
                    break
        if df.stages and (df.user in (None, "root", "0")):
            loc = f"{df.file}:{df.stages[-1].line}"
            out.append(_f(ctx, "container", "DF003", df.file, loc, "W", [df.evidence_id], detail=f"final stage user={df.user or 'unset'}"))
        for ins in df.remote_fetches:
            loc = f"{df.file}:{ins.line}"
            ev = ctx.store.add_evidence("raw", "dockerfile", loc, f"{ins.op} {ins.args}").id
            if ins.op == "ADD":
                out.append(_f(ctx, "container", "DF004", df.file, loc, "S" if "http://" in ins.args else "W", [ev], detail=ins.args[:120]))
            elif re.search(r"\|\s*(ba|z|da)?sh\b", ins.args):
                out.append(_f(ctx, "container", "DF005", df.file, loc, "S", [ev], detail=ins.args[:120]))
        for ins in df.package_installs:
            if re.search(r"(pip3? install|npm (i|install)|yarn add|apk add|apt-get install)", ins.args) and \
                    not re.search(r"(-r |--requirement|requirements|==|@\d|npm ci|--frozen|--no-install-recommends\s+\S+=)", ins.args) \
                    and re.search(r"(install|add)\s+(-[\w-]+\s+)*[a-zA-Z]", ins.args) and "install -r" not in ins.args \
                    and not re.search(r"npm (i|install)\s*($|&&|;)", ins.args):
                loc = f"{df.file}:{ins.line}"
                ev = ctx.store.add_evidence("raw", "dockerfile", loc, f"RUN {ins.args}").id
                out.append(_f(ctx, "container", "DF006", df.file, loc, "W", [ev], detail=ins.args[:120]))
    for s in ctx.facts.config.compose_services:
        if s.image and not s.digest:
            loc = f"{s.file}:{s.line or 1}"
            ev = ctx.store.add_evidence("raw", "compose", loc, f"service {s.name}: image {s.image}").id
            out.append(_f(ctx, "container", "DC001", s.image, loc, "W", [ev], detail=f"{s.name} -> {s.image}", image=s.image))
    return out


def detect_ci(ctx: RunContext) -> list[Finding]:
    out: list[Finding] = []
    for wf in (ctx.facts.ci_workflows if ctx.facts else []):
        write_perm = wf.permissions in ("write-all",) or (isinstance(wf.permissions, dict) and
                                                          any(v == "write" for v in wf.permissions.values()))
        prt = "pull_request_target" in wf.triggers or "workflow_run" in wf.triggers
        for a in wf.actions:
            if a.pinned_to_sha or a.action.startswith(("./", "docker://")):
                continue
            loc = f"{wf.file}:{a.line}"
            ev = ctx.store.add_evidence("raw", "workflow", loc, f"uses: {a.uses}").id
            first_party = a.action.split("/")[0] in ("actions", "github")
            out.append(_f(ctx, "ci", "CI001", a.uses, loc, "W", [ev], detail=a.uses, action=a.action, ref=a.ref,
                          first_party=first_party))
        if prt:
            ev = ctx.store.add_evidence("raw", "workflow", f"{wf.file}:on", f"on: {', '.join(wf.triggers)}").id
            checks_out_head = any("checkout" in a.action for a in wf.actions)
            out.append(_f(ctx, "ci", "CI002", wf.file, f"{wf.file}:on", "S" if (write_perm or wf.permissions is None) and checks_out_head else "W",
                          [ev], detail=", ".join(wf.triggers), with_write_permissions=write_perm or wf.permissions is None,
                          checks_out_code=checks_out_head))
        if wf.permissions == "write-all" or (wf.permissions is None and not wf.job_permissions):
            ev = ctx.store.add_evidence("raw", "workflow", f"{wf.file}:permissions", f"permissions: {wf.permissions}").id
            out.append(_f(ctx, "ci", "CI003", wf.file, f"{wf.file}:permissions", "W", [ev],
                          detail=f"permissions={wf.permissions if wf.permissions is not None else 'unset (defaults apply)'}"))
        for r in wf.run_steps:
            m = UNTRUSTED_CTX.search(r.cmd)
            if m:
                loc = f"{wf.file}:{r.line}"
                ev = ctx.store.add_evidence("raw", "workflow", loc, f"run: {r.cmd[:400]}").id
                out.append(_f(ctx, "ci", "CI004", wf.file, loc, "S", [ev], detail=m.group(0), expression=m.group(0)))
    return out


def detect_secrets(ctx: RunContext) -> list[Finding]:
    out: list[Finding] = []
    root = ctx.root
    for p in walk_files(root):
        if p.suffix.lower() in SECRET_SKIP_EXT or p.name in ("package-lock.json", "yarn.lock", "poetry.lock", "uv.lock"):
            continue
        text = read_text(p, limit=1_000_000)
        if not text or "\x00" in text[:1000]:
            continue
        r = rel(root, p)
        for i, line in enumerate(text.splitlines(), 1):
            for kind, rx in SECRET_PATTERNS.items():
                m = rx.search(line)
                if not m:
                    continue
                secret = m.group(0)
                digest = hashlib.sha256(secret.encode()).hexdigest()
                red = redact(secret)
                # evidence never contains the secret value: the line is stored with the match replaced
                ev = ctx.store.add_evidence("raw", "secrets", f"{r}:{i}", line.replace(secret, red)[:300]).id
                example = any(x in r.lower() for x in ("example", "sample", "test", "fixture", "mock"))
                out.append(_f(ctx, "secret", "SEC001", f"{r}:{kind}", f"{r}:{i}", "W" if example else "S", [ev],
                              detail=f"{kind} in {r}", kind=kind, sha256=digest, preview=red, path=r, line=i))
    return out
