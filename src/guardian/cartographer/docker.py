"""Dockerfile and docker-compose parsing (static, no build)."""
from __future__ import annotations

import re

import yaml

from ..fsutil import find_line
from ..models import ComposeService, DockerfileFacts, DockerInstr, DockerStage

INSTALL_RE = re.compile(r"\b(pip3?|python3? -m pip|npm|yarn|pnpm|apt-get|apk|gem|go|cargo)\s+(install|add|i|ci)\b")
FETCH_RE = re.compile(r"\b(curl|wget)\b[^|;&]*https?://")


def parse_image_ref(ref: str) -> tuple[str, str | None, str | None]:
    """'postgres:16' -> ('postgres','16',None); 'node@sha256:..' -> ('node',None,'sha256:..')."""
    ref = ref.strip()
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name_part, tag = last.rsplit(":", 1)
        ref = ref[: len(ref) - len(last)] + name_part
    return ref, tag, digest


def _logical(text: str):
    buf, start = "", None
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not buf and (not s or s.startswith("#")):
            continue
        if start is None:
            start = i
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        yield start, buf
        buf, start = "", None
    if buf:
        yield start or 1, buf


def parse_dockerfile(rel_path: str, text: str) -> DockerfileFacts:
    facts = DockerfileFacts(file=rel_path)
    stage_names: set[str] = set()
    user_by_stage: list[str | None] = []
    for line, instr in _logical(text):
        op, _, args = instr.partition(" ")
        op = op.upper()
        args = args.strip()
        facts.instructions.append(DockerInstr(line=line, op=op, args=args[:500]))
        if op == "FROM":
            toks = [t for t in args.split() if not t.startswith("--")]
            if not toks:
                continue
            image = toks[0]
            name = toks[2] if len(toks) >= 3 and toks[1].upper() == "AS" else None
            if image in stage_names:
                facts.stages.append(DockerStage(base_image=image, tag=None, digest=None, name=name, line=line))
            else:
                base, tag, digest = parse_image_ref(image)
                facts.stages.append(DockerStage(base_image=base, tag=tag, digest=digest, name=name, line=line))
            if name:
                stage_names.add(name)
            user_by_stage.append(None)
        elif op == "USER":
            if user_by_stage:
                user_by_stage[-1] = args.split()[0] if args else None
        elif op == "EXPOSE":
            for p in args.split():
                m = re.match(r"(\d+)", p)
                if m:
                    facts.exposed_ports.append(int(m.group(1)))
        elif op == "RUN":
            if INSTALL_RE.search(args):
                facts.package_installs.append(DockerInstr(line=line, op=op, args=args[:500]))
            if FETCH_RE.search(args):
                facts.remote_fetches.append(DockerInstr(line=line, op=op, args=args[:500]))
        elif op == "ADD" and re.search(r"https?://", args):
            facts.remote_fetches.append(DockerInstr(line=line, op=op, args=args[:500]))
    facts.user = user_by_stage[-1] if user_by_stage else None
    return facts


def parse_compose(rel_path: str, text: str) -> list[ComposeService]:
    data = yaml.safe_load(text) or {}
    out = []
    for name, svc in ((data.get("services") or {}) if isinstance(data, dict) else {}).items():
        svc = svc or {}
        image = svc.get("image")
        tag = digest = None
        if image:
            _, tag, digest = parse_image_ref(str(image))
        deps = svc.get("depends_on") or []
        if isinstance(deps, dict):
            deps = list(deps)
        out.append(ComposeService(file=rel_path, name=str(name), image=str(image) if image else None, tag=tag,
                                  digest=digest, build="build" in svc,
                                  ports=[str(p) for p in svc.get("ports") or []], depends_on=[str(d) for d in deps],
                                  line=find_line(text, f"{name}:")))
    return out
