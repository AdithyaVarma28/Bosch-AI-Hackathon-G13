"""Shared state for Stage 5 (reuses the Stage 4 context: graph, LLM, caches, budgets)."""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from guardian.purl import normalize_name
from guardian.stage3_knowledge.graph_builder import nodes_of
from guardian.stage4_vulns.context import Stage4Context

from .pypi import PyPIClient
from .sandbox import analyze

DATA = Path(__file__).resolve().parent / "data"
LOCKFILES = ("poetry.lock", "Pipfile.lock", "uv.lock", "requirements.lock", "pdm.lock")
MANIFEST_RE = re.compile(r"(requirements.*\.(txt|in)|pyproject\.toml|setup\.(py|cfg)|Pipfile)$")


@dataclass
class Budgets5:
    deep: int = 15
    tool_calls: int = 10


@dataclass
class Stage5Context:
    s4: Stage4Context
    pypi: PyPIClient
    budgets: Budgets5 = field(default_factory=Budgets5)
    analyses: dict[str, dict] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    top: dict[str, int] = field(default_factory=dict)
    allowlist: dict[str, str] = field(default_factory=dict)

    @property
    def G(self):
        return self.s4.G

    @property
    def s3(self):
        return self.s4.s3

    @property
    def llm(self):
        return self.s4.llm

    @property
    def output_dir(self) -> Path:
        return self.s4.output_dir

    def note(self, key: str, msg: str) -> None:
        lst = self.coverage.setdefault(key, [])
        if msg not in lst:
            lst.append(msg)

    # ------------------------------------------------------------------ packages
    def package_nodes(self) -> list[str]:
        return sorted(p for p in nodes_of(self.G, "Package") if self.G.nodes[p].get("version") or self.G.nodes[p].get("checked_version"))

    def pkg_version(self, pid: str) -> Optional[str]:
        d = self.G.nodes[pid]
        return d.get("version") or d.get("checked_version")

    def analyze_dist(self, name: str, version: str, prefer: Optional[str] = None) -> dict:
        """Download (hash-verified) + sandbox-analyze one distribution. Cached per (name, version, type)."""
        key = f"{normalize_name(name)}@{version}:{prefer or 'any'}"
        if key in self.analyses:
            return self.analyses[key]
        path, entry, err = self.pypi.download(name, version, prefer)
        if err:
            res = {"error": err, "file": entry.get("filename")}
        else:
            dest = self.output_dir / ".sandbox" / f"{normalize_name(name)}-{version}-{entry.get('packagetype', 'dist')}"
            res = analyze(path, dest)
            res.update({"file": entry.get("filename"), "packagetype": entry.get("packagetype"), "dir": str(dest),
                        "sha256": (entry.get("digests") or {}).get("sha256")})
        self.analyses[key] = res
        return res

    def package_file_lines(self, name: str, version: str, path: str, start: int, end: int) -> list[tuple[int, str]]:
        for a in self.analyses.values():
            if a.get("dir") and Path(a["dir"]).name.startswith(f"{normalize_name(name)}-{version}-"):
                p = (Path(a["dir"]) / path).resolve()
                if p.is_relative_to(Path(a["dir"]).resolve()) and p.exists() and p.stat().st_size < 1_000_000:
                    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                    end = min(end, len(lines), start + 119)
                    return [(i, lines[i - 1]) for i in range(max(1, start), end + 1)]
        return []

    # ------------------------------------------------------------------ lockfiles
    def lock_at(self, commit: str, lockfile: str = "poetry.lock") -> dict[str, dict]:
        src = self.s3.source
        text = src.git("show", f"{commit}:{lockfile}") if src.is_git else None
        return parse_lock(text or "", lockfile)


def parse_lock(text: str, lockfile: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not text:
        return out
    try:
        if lockfile.endswith(".lock") and lockfile != "Pipfile.lock":
            data = tomllib.loads(text)
            for p in data.get("package", []) or []:
                hashes = [f.get("hash", "").removeprefix("sha256:") for f in p.get("files", []) or [] if f.get("hash")]
                hashes += [w.get("hash", "").removeprefix("sha256:") for w in p.get("wheels", []) or [] if w.get("hash")]
                out[normalize_name(p.get("name", ""))] = {"name": p.get("name"), "version": p.get("version"),
                                                           "hashes": hashes, "source": p.get("source")}
        else:
            data = json.loads(text)
            for sec in ("default", "develop"):
                for n, info in (data.get(sec) or {}).items():
                    out[normalize_name(n)] = {"name": n, "version": (info.get("version") or "").lstrip("="),
                                              "hashes": [h.removeprefix("sha256:") for h in info.get("hashes", [])],
                                              "source": info.get("index")}
    except Exception:
        return {}
    return out


def load_top() -> dict[str, int]:
    data = json.loads((DATA / "top_pypi.json").read_text(encoding="utf-8"))
    return {normalize_name(n): c for n, c in data["packages"]}


def load_allowlist() -> dict[str, str]:
    import yaml
    data = yaml.safe_load((DATA / "allowlist.yaml").read_text(encoding="utf-8")) or {}
    return {normalize_name(k): str(v) for k, v in data.items()}
