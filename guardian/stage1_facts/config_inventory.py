from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Tuple
import yaml

from guardian.models.facts import (
    ComposeService,
    ConfigInventory,
    EnvFileInventory,
)

ENV_VAR_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def parse_config_inventory(repo_path: Path) -> Tuple[ConfigInventory, List[str]]:
    env_files: List[EnvFileInventory] = []
    config_files: List[str] = []
    compose_services: List[ComposeService] = []
    migration_dirs: List[str] = []
    errors: List[str] = []

    for root, dirs, files in os.walk(repo_path):
        # Exclude hidden and non-project directories
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "node_modules", "output"}]
        rel_root = Path(root).relative_to(repo_path)

        # 1. Detect migration directories
        for d in dirs:
            if d == "migrations" or (d == "versions" and rel_root.name == "alembic"):
                mig_path = (rel_root / d).as_posix()
                migration_dirs.append(mig_path)

        for f in sorted(files):
            file_p = Path(root) / f
            rel_file = file_p.relative_to(repo_path).as_posix()

            # 2. .env files: strictly variable names only, NEVER values
            if f.startswith(".env"):
                var_names: List[str] = []
                line_count = 0
                try:
                    with open(file_p, "r", encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            line_count += 1
                            m = ENV_VAR_RE.match(line)
                            if m:
                                var_names.append(m.group(1))
                    env_files.append(EnvFileInventory(
                        file=rel_file,
                        var_names=sorted(set(var_names)),
                        line_count=line_count
                    ))
                except Exception as e:
                    errors.append(f"Failed to read env file {rel_file}: {e}")

            # 3. Config files
            if f in {"settings.py", "alembic.ini"} or (
                rel_file.startswith("config/") and f.endswith((".yaml", ".yml", ".toml", ".ini", ".json"))
            ):
                config_files.append(rel_file)

            # 4. Docker compose services
            if f in COMPOSE_NAMES or f.startswith("docker-compose."):
                try:
                    with open(file_p, "r", encoding="utf-8", errors="replace") as fh:
                        raw_lines = fh.readlines()
                    raw_content = "".join(raw_lines)
                    data = yaml.safe_load(raw_content) or {}
                    services_data = data.get("services", {})

                    for svc_name, svc_info in services_data.items():
                        if not isinstance(svc_info, dict):
                            continue
                        img = svc_info.get("image")
                        ports_raw = svc_info.get("ports", [])
                        ports = [str(p) for p in ports_raw]
                        depends_on_raw = svc_info.get("depends_on", [])
                        if isinstance(depends_on_raw, dict):
                            depends_on = list(depends_on_raw.keys())
                        elif isinstance(depends_on_raw, list):
                            depends_on = [str(d) for d in depends_on_raw]
                        else:
                            depends_on = []

                        digest = None
                        if img and "@sha256:" in img:
                            digest = "sha256:" + img.split("@sha256:")[1]

                        # Find line number where service is defined
                        svc_line = 1
                        for idx, l in enumerate(raw_lines, start=1):
                            if re.match(rf"^\s*{re.escape(svc_name)}\s*:", l):
                                svc_line = idx
                                break

                        compose_services.append(ComposeService(
                            file=rel_file,
                            name=svc_name,
                            image=img,
                            digest=digest,
                            ports=ports,
                            depends_on=depends_on,
                            line=svc_line
                        ))
                except Exception as e:
                    errors.append(f"Failed to parse compose file {rel_file}: {e}")

    return ConfigInventory(
        env_files=env_files,
        config_files=sorted(config_files),
        compose_services=compose_services,
        migration_dirs=sorted(set(migration_dirs))
    ), errors
