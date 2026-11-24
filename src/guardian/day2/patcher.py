"""Turns typed Edits into file changes on a throwaway copy of the repository, and produces the unified diff.

The scanned checkout is never modified: every function here takes the copy's root. Formatting is preserved
where it matters for review (JSON keeps 2-space indent and key order; text edits touch only the target line).
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
from pathlib import Path

import yaml

from ..purl import normalize_pypi
from .models import Edit

IGNORE_COPY = shutil.ignore_patterns("node_modules", ".venv", "venv", "__pycache__", ".guardian-venv", ".pytest_cache",
                                     ".mypy_cache", "dist", "build", ".tox", "target")


class PatchError(RuntimeError):
    pass


def copy_tree(src: Path, dst: Path, with_git: bool = True) -> Path:
    dst = Path(dst)
    if dst.exists():
        rmtree(dst)
    ignore = IGNORE_COPY if with_git else shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "__pycache__",
                                                                 ".guardian-venv", ".pytest_cache", "dist", "build", "target")
    shutil.copytree(src, dst, ignore=ignore, symlinks=True)
    return dst


def rmtree(p: Path) -> None:
    def onerror(func, path, _):
        try:
            os.chmod(path, 0o700)
            func(path)
        except OSError:
            pass
    shutil.rmtree(p, onerror=onerror)


def _confine(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    if not p.is_relative_to(root.resolve()) or ".git" in p.relative_to(root.resolve()).parts:
        raise PatchError(f"edit path escapes the repository: {rel}")
    return p


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="")


def _json_dump(data, original: str) -> str:
    indent = 2
    m = re.search(r'\n( +)"', original)
    if m:
        indent = len(m.group(1))
    out = json.dumps(data, indent=indent, ensure_ascii=False)
    return out + ("\n" if original.endswith("\n") or not original else "")


DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _npm_registry_url(name: str, version: str) -> str:
    base = name.split("/")[-1]
    return f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz"


def apply_edit(root: Path, e: Edit) -> None:
    p = _confine(root, e.file)
    k, a = e.kind, e.params
    if k in ("npm_set_dep", "npm_remove_dep", "npm_override", "npm_remove_script"):
        text = _read(p)
        data = json.loads(text) if text else {}
        if k == "npm_set_dep":
            sec = next((s for s in DEP_SECTIONS if a["name"] in (data.get(s) or {})), a.get("section", "dependencies"))
            data.setdefault(sec, {})[a["name"]] = a["spec"]
        elif k == "npm_remove_dep":
            for s in DEP_SECTIONS:
                (data.get(s) or {}).pop(a["name"], None)
        elif k == "npm_override":
            data.setdefault("overrides", {})[a["name"]] = a["spec"]
        elif k == "npm_remove_script":
            (data.get("scripts") or {}).pop(a["script"], None)
        _write(p, _json_dump(data, text))
    elif k in ("npm_lock_set", "npm_lock_remove"):
        text = _read(p)
        if not text:
            raise PatchError(f"{e.file} not found")
        data = json.loads(text)
        name = a["name"]
        pk = data.get("packages")
        if isinstance(pk, dict):
            key = f"node_modules/{name}"
            if k == "npm_lock_remove":
                pk.pop(key, None)
                for s in DEP_SECTIONS:
                    (pk.get("", {}).get(s) or {}).pop(name, None)
            else:
                ent = dict(pk.get(key) or {})
                ent["version"] = a["version"]
                ent["resolved"] = a.get("resolved") or _npm_registry_url(name, a["version"])
                if a.get("integrity"):
                    ent["integrity"] = a["integrity"]
                else:
                    ent.pop("integrity", None)
                if a.get("dependencies") is not None:
                    if a["dependencies"]:
                        ent["dependencies"] = a["dependencies"]
                    else:
                        ent.pop("dependencies", None)
                if a.get("drop_install_script"):
                    ent.pop("hasInstallScript", None)
                # keep key order stable: node_modules/* entries sorted
                pk[key] = ent
                if a.get("root_spec"):
                    root_ent = pk.setdefault("", {})
                    sec = next((s for s in DEP_SECTIONS if name in (root_ent.get(s) or {})), "dependencies")
                    root_ent.setdefault(sec, {})[name] = a["root_spec"]
                data["packages"] = {"": pk.get("", {}), **{kk: pk[kk] for kk in sorted(x for x in pk if x)}}
        else:  # lockfile v1
            deps = data.setdefault("dependencies", {})
            if k == "npm_lock_remove":
                deps.pop(name, None)
            else:
                ent = dict(deps.get(name) or {})
                ent["version"] = a["version"]
                ent["resolved"] = a.get("resolved") or _npm_registry_url(name, a["version"])
                if a.get("integrity"):
                    ent["integrity"] = a["integrity"]
                else:
                    ent.pop("integrity", None)
                if a.get("dependencies") is not None:
                    ent["requires"] = a["dependencies"]
                deps[name] = ent
        _write(p, _json_dump(data, text))
    elif k in ("pip_set_pin", "pip_remove", "pip_add_pin"):
        text = _read(p)
        lines = text.splitlines(keepends=True)
        want = normalize_pypi(a["name"])
        rx = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*)(===?|>=|~=|<=|!=|>|<)?\s*([^\s;#\\]*)(.*)$", re.S)
        hit = False
        out = []
        for ln in lines:
            m = rx.match(ln.rstrip("\r\n"))
            eol = ln[len(ln.rstrip("\r\n")):]
            if m and normalize_pypi(m.group(2)) == want and not ln.lstrip().startswith(("#", "-")):
                hit = True
                if k == "pip_remove":
                    continue
                if k == "pip_set_pin":
                    ln = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}=={a['version']}{m.group(7)}{eol}"
                elif k == "pip_add_pin":
                    ln = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}=={a['version']}{m.group(7)}{eol}"
            out.append(ln)
        if k == "pip_add_pin" and not hit:
            if out and not out[-1].endswith(("\n", "\r\n")):
                out[-1] += "\n"
            comment = f"  # {a['comment']}" if a.get("comment") else ""
            out.append(f"{a['name']}=={a['version']}{comment}\n")
        elif not hit and k != "pip_add_pin":
            raise PatchError(f"{a['name']} not found in {e.file}")
        _write(p, "".join(out))
    elif k == "docker_from":
        text = _read(p)
        lines = text.splitlines(keepends=True)
        idx = int(a.get("line", 0)) - 1
        rx = re.compile(r"^(\s*FROM\s+(?:--platform=\S+\s+)?)" + re.escape(a["old"]) + r"(\s|$)", re.I)
        targets = [idx] if 0 <= idx < len(lines) and rx.match(lines[idx]) else [i for i, l in enumerate(lines) if rx.match(l)][:1]
        if not targets:
            raise PatchError(f"FROM {a['old']} not found in {e.file}")
        i = targets[0]
        lines[i] = rx.sub(lambda m: m.group(1) + a["new"] + m.group(2), lines[i], count=1)
        _write(p, "".join(lines))
    elif k == "gha_pin":
        text = _read(p)
        rx = re.compile(r"(uses:\s*['\"]?)" + re.escape(a["uses_old"]) + r"(['\"]?)(\s*(#.*)?)$", re.M)
        new, n = rx.subn(lambda m: f"{m.group(1)}{a['uses_new']}{m.group(2)} # {a['uses_old'].split('@')[-1]}", text)
        if not n:
            raise PatchError(f"uses: {a['uses_old']} not found in {e.file}")
        _write(p, new)
    elif k == "gha_permissions":
        text = _read(p)
        perms = a.get("permissions") or {"contents": "read"}
        block = "permissions:\n" + "".join(f"  {kk}: {vv}\n" for kk, vv in perms.items())
        rx = re.compile(r"^permissions:[ \t]*\S[^\n]*\n", re.M)
        if rx.search(text):
            new = rx.sub(block, text, count=1)
        else:
            m = re.search(r"^jobs:", text, re.M)
            if not m:
                raise PatchError(f"no jobs: section in {e.file}")
            new = text[:m.start()] + block + text[m.start():]
        _write(p, new)
    elif k == "policy_block":
        text = _read(p)
        doc = (yaml.safe_load(text) or {}) if text else {}
        if not isinstance(doc, dict):
            doc = {}
        doc.setdefault("blocked_packages", [])
        item = {"ecosystem": a.get("ecosystem"), "name": a["name"], "reason": a.get("reason", "")}
        if item not in doc["blocked_packages"]:
            doc["blocked_packages"].append(item)
        header = "" if text else "# Guardian policy (policy-as-code). See docs/day2_plan.md section 9.\n"
        _write(p, header + yaml.safe_dump(doc, sort_keys=False))
    else:
        raise PatchError(f"unsupported edit kind {k}")


def apply_edits(root: Path, edits: list[Edit]) -> list[str]:
    changed = []
    for e in edits:
        apply_edit(Path(root), e)
        if e.file not in changed:
            changed.append(e.file)
    return changed


def unified_diff(original_root: Path, patched_root: Path, files: list[str]) -> str:
    out = []
    for rel in sorted(set(files)):
        a = _read(Path(original_root) / rel).splitlines(keepends=True)
        b = _read(Path(patched_root) / rel).splitlines(keepends=True)
        out += difflib.unified_diff(a, b, fromfile=f"a/{rel}", tofile=f"b/{rel}", n=2)
    text = "".join(out)
    return text if text.endswith("\n") or not text else text + "\n"


def diff_sha(diff: str) -> str:
    return hashlib.sha256(diff.replace("\r\n", "\n").encode()).hexdigest()
