"""Classify imports as internal (repo), stdlib or external, and resolve internal ones to files."""
import sys

STDLIB = sys.stdlib_module_names


class ModuleMap:
    """Maps dotted module names defined in the repo to their repo-relative file paths."""

    def __init__(self, module_to_file: dict[str, str], all_files: list[str] | None = None):
        self.module_to_file = module_to_file
        self.top_levels = {m.split(".")[0] for m in module_to_file}
        self.files = set(all_files if all_files is not None else module_to_file.values())

    def resolve_nearby(self, name: str, file_dir: str) -> str | None:
        """Script-style imports: `import libuser` inside bad/x.py means bad/libuser.py (or bad/libuser/)."""
        parts = name.split(".")
        dirs = [file_dir]
        while dirs[-1]:
            dirs.append(dirs[-1].rpartition("/")[0])
        for d in dirs:
            prefix = f"{d}/" if d else ""
            for i in range(len(parts), 0, -1):
                stem = prefix + "/".join(parts[:i])
                for cand in (f"{stem}.py", f"{stem}/__init__.py"):
                    if cand in self.files:
                        return cand
        return None

    def is_module(self, name: str) -> bool:
        return name in self.module_to_file

    def resolve(self, name: str) -> str | None:
        """File for the longest dotted prefix of `name` that is a repo module."""
        parts = name.split(".")
        for i in range(len(parts), 0, -1):
            hit = self.module_to_file.get(".".join(parts[:i]))
            if hit:
                return hit
        return None

    def classify(self, name: str) -> str:
        top = name.split(".")[0]
        if top in self.top_levels:
            return "internal"
        if top in STDLIB:
            return "stdlib"
        return "external"
