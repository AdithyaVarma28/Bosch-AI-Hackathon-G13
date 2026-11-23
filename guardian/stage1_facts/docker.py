from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Tuple

from guardian.models.facts import (
    ContainerBaseImage,
    ContainerFile,
    ContainerPipInstall,
    ContainerRemoteFetch,
)

FROM_RE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+[aA][sS]\s+(\S+))?", re.IGNORECASE)
PIP_INSTALL_RE = re.compile(r"pip\s+install\s+.*", re.IGNORECASE)
REMOTE_FETCH_RE = re.compile(r"(curl\s+.*|wget\s+.*|ADD\s+https?://\S+)", re.IGNORECASE)


def parse_dockerfiles(repo_path: Path) -> Tuple[List[ContainerFile], List[str]]:
    containers: List[ContainerFile] = []
    errors: List[str] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "node_modules"}]
        for f in sorted(files):
            if f == "Dockerfile" or f.startswith("Dockerfile.") or f.endswith(".dockerfile"):
                df_path = Path(root) / f
                rel_path = df_path.relative_to(repo_path).as_posix()
                try:
                    base_images: List[ContainerBaseImage] = []
                    pip_installs: List[ContainerPipInstall] = []
                    remote_fetches: List[ContainerRemoteFetch] = []
                    multi_stage: List[str] = []

                    with open(df_path, "r", encoding="utf-8", errors="replace") as fh:
                        for line_idx, raw_line in enumerate(fh, start=1):
                            line = raw_line.strip()
                            if not line or line.startswith("#"):
                                continue

                            # FROM line
                            from_match = FROM_RE.match(line)
                            if from_match:
                                img_ref = from_match.group(1)
                                as_stage = from_match.group(2)
                                if as_stage:
                                    multi_stage.append(as_stage)

                                tag = None
                                digest = None
                                if "@sha256:" in img_ref:
                                    digest = "sha256:" + img_ref.split("@sha256:")[1]
                                elif ":" in img_ref:
                                    tag = img_ref.split(":")[-1]

                                base_images.append(ContainerBaseImage(
                                    ref=img_ref,
                                    tag=tag,
                                    digest=digest,
                                    line=line_idx
                                ))

                            # pip install in RUN
                            if "pip install" in line:
                                pip_match = PIP_INSTALL_RE.search(line)
                                if pip_match:
                                    pip_installs.append(ContainerPipInstall(
                                        line=line_idx,
                                        cmd=pip_match.group(0)
                                    ))

                            # Remote fetches: curl, wget, ADD http
                            fetch_match = REMOTE_FETCH_RE.search(line)
                            if fetch_match:
                                remote_fetches.append(ContainerRemoteFetch(
                                    line=line_idx,
                                    cmd=fetch_match.group(0)
                                ))

                    containers.append(ContainerFile(
                        file=rel_path,
                        base_images=base_images,
                        pip_installs=pip_installs,
                        remote_fetches=remote_fetches,
                        multi_stage=multi_stage,
                        discovered_by="dockerfile"
                    ))
                except Exception as e:
                    errors.append(f"Error parsing Dockerfile {rel_path}: {e}")

    return containers, errors
