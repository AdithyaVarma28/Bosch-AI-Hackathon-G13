"""D4 Unsafe install behaviour: AST-scan setup.py / build hooks of sdist-only packages, VCS/URL
dependencies and anything D1/D3 flagged; ``.pth`` files with code in wheels."""
from __future__ import annotations

from guardian.purl import normalize_name

from ..context import Stage5Context
from ..schema import Signal

HOOK_FILES = ("setup.py", "build_backend.py", "_build.py", "conftest.py")
STRONG = ("network", "subprocess", "code_exec", "obfuscated_exec")
LABEL = {"network": "network request", "subprocess": "subprocess", "code_exec": "exec/eval",
         "obfuscated_exec": "exec of decoded data", "env_read": "environment read", "install_hook": "install hook",
         "domain": "URL", "decode": "base64 decode", "encoded_blob": "encoded blob"}


def targets(ctx: Stage5Context, flagged: set[str]) -> list[tuple[str, str, str, str]]:
    out = []
    for pid in ctx.package_nodes():
        d = ctx.G.nodes[pid]
        name, ver = d.get("name"), ctx.pkg_version(pid)
        files = ctx.pypi.files(name, ver) if ver else []
        sdist_only = bool(files) and all(f.get("packagetype") == "sdist" for f in files)
        if d.get("dep_kind") in ("vcs", "url"):
            out.append((pid, name, ver, "VCS/URL dependency"))
        elif sdist_only:
            out.append((pid, name, ver, "sdist-only release"))
        elif pid in flagged and files:
            out.append((pid, name, ver, "flagged by another detector"))
    return out


def detect(ctx: Stage5Context, flagged: set[str]) -> list[Signal]:
    sigs = []
    for pid, name, ver, why in targets(ctx, flagged):
        files = ctx.pypi.files(name, ver)
        has_sdist = any(f.get("packagetype") == "sdist" for f in files)
        a = ctx.analyze_dist(name, ver, "sdist" if has_sdist else "bdist_wheel")
        if a.get("error"):
            ctx.note("d4_skipped", f"{name} {ver}: {a['error']}")
            continue
        for rel, findings in a.get("ast", {}).items():
            base = rel.rsplit("/", 1)[-1]
            if base not in HOOK_FILES:
                continue
            if base == "conftest.py" and set(rel.lower().split("/")[:-1]) & {"tests", "test", "testing"}:
                continue        # a test-suite conftest only runs under pytest, never on install
            found = [f for f in findings if f["category"] in LABEL]
            if not found:
                continue
            strong = [f for f in found if f["category"] in STRONG]
            cats = sorted({LABEL[f["category"]] for f in found})
            domains = sorted({f["target"] for f in found if f["category"] == "domain"})
            sigs.append(Signal(
                detector="D4", check="install_hook_behaviour", subject=pid, subject_label=f"{name} {ver}",
                data={"file": rel, "behaviour": [{k: f[k] for k in ("category", "target", "line")} for f in found][:10],
                      "domains": domains, "why_scanned": why, "isolation": a.get("isolation")},
                evidence=[{"package_file": f"{name}@{ver}/{rel}", "lines": f"{f['line']}-{f['end_line']}"} for f in (strong or found)[:3]],
                strength="strong" if strong else "medium", behaviour=True,
                text=f"{rel} in {name} {ver} contains {', '.join(cats)}" + (f" (to {', '.join(domains)})" if domains else "")))
        for pth in a.get("pth", []):
            sigs.append(Signal(detector="D4", check="pth_code", subject=pid, subject_label=f"{name} {ver}",
                               data={"file": pth["file"]}, behaviour=True, strength="strong",
                               evidence=[{"package_file": f"{name}@{ver}/{pth['file']}", "lines": str(pth["lines"][0])}],
                               text=f"{pth['file']} runs code on every Python start"))
        if a.get("console_scripts"):
            sigs.append(Signal(detector="D4", check="console_scripts", subject=pid, subject_label=f"{name} {ver}",
                               data={"scripts": a["console_scripts"]}, strength="weak", evidence=[{"pypi": normalize_name(name)}],
                               text=f"installs console scripts {', '.join(a['console_scripts'][:3])}"))
    return sigs
