"""Agent Skills (SKILL.md) for the remediation agent, loaded with progressive disclosure: the agent first sees only
each skill's name and description, and the full playbook enters its context when it calls load_skill(name).
SKILL.md is only the format: discovery, loading and the file scope each skill allows are implemented here."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

SKILLS_DIR = Path(__file__).parent / "skills"


@dataclass
class Skill:
    name: str
    description: str
    allowed_files: list[str]
    path: Path

    def body(self) -> str:
        text = self.path.read_text(encoding="utf-8")
        return re.sub(r"^---\n.*?\n---\n", "", text, count=1, flags=re.S).strip()

    def allows(self, rel: str) -> bool:
        rel = rel.replace("\\", "/")
        return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel.rsplit("/", 1)[-1], g) for g in self.allowed_files)


def _front(text: str) -> dict[str, str]:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    out = {}
    for line in (m.group(1) if m else "").splitlines():
        k, _, v = line.partition(":")
        if v:
            out[k.strip()] = v.strip()
    return out


def discover(root: Path = SKILLS_DIR) -> dict[str, Skill]:
    skills = {}
    for p in sorted(root.glob("*/SKILL.md")):
        fm = _front(p.read_text(encoding="utf-8"))
        if fm.get("name") and fm.get("description"):
            skills[fm["name"]] = Skill(fm["name"], fm["description"],
                                       [g.strip() for g in fm.get("allowed_files", "").split(",") if g.strip()], p)
    return skills


def index_text(skills: dict[str, Skill]) -> str:
    return "\n".join(f"- {s.name}: {s.description}" for s in skills.values())


def get(name: Optional[str]) -> Optional[Skill]:
    return discover().get(name or "")
