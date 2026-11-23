from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Tuple
import yaml

from guardian.models.facts import CIWorkflow, WorkflowAction, WorkflowRunStep

HEX_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SECRET_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")


def is_sha_ref(ref: str) -> bool:
    return bool(HEX_40_RE.match(ref))


def parse_workflows(repo_path: Path) -> Tuple[List[CIWorkflow], List[str]]:
    workflows: List[CIWorkflow] = []
    errors: List[str] = []

    wf_dir = repo_path / ".github" / "workflows"
    if not wf_dir.is_dir():
        return workflows, errors

    for root, _, files in os.walk(wf_dir):
        for f in sorted(files):
            if f.endswith((".yml", ".yaml")):
                wf_path = Path(root) / f
                rel_path = wf_path.relative_to(repo_path).as_posix()
                try:
                    with open(wf_path, "r", encoding="utf-8", errors="replace") as fh:
                        raw_lines = fh.readlines()
                    raw_content = "".join(raw_lines)

                    try:
                        data = yaml.safe_load(raw_content) or {}
                    except Exception as e:
                        errors.append(f"Failed to parse workflow YAML {rel_path}: {e}")
                        data = {}

                    # 1. Triggers
                    triggers: List[str] = []
                    on_block = data.get("on") or data.get(True)  # YAML parses 'on' as boolean True sometimes!
                    if isinstance(on_block, str):
                        triggers.append(on_block)
                    elif isinstance(on_block, list):
                        triggers.extend([str(t) for t in on_block])
                    elif isinstance(on_block, dict):
                        triggers.extend(list(on_block.keys()))

                    # 2. Permissions
                    permissions = data.get("permissions")

                    # 3. Actions and Run steps with line numbers
                    actions: List[WorkflowAction] = []
                    run_steps: List[WorkflowRunStep] = []

                    for idx, line in enumerate(raw_lines, start=1):
                        stripped = line.strip()
                        # uses: foo/bar@ref
                        if stripped.startswith("uses:") or "- uses:" in stripped:
                            parts = stripped.split("uses:", 1)[1].strip().strip('"\'')
                            if "@" in parts:
                                action_name, ref = parts.split("@", 1)
                                actions.append(WorkflowAction(
                                    uses=action_name.strip(),
                                    ref=ref.strip(),
                                    pinned_to_sha=is_sha_ref(ref.strip()),
                                    line=idx
                                ))

                        # run: command
                        if stripped.startswith("run:") or "- run:" in stripped:
                            cmd_part = stripped.split("run:", 1)[1].strip()
                            run_steps.append(WorkflowRunStep(
                                line=idx,
                                cmd=cmd_part
                            ))

                    # 4. Secrets used (names only)
                    secrets_found = set(SECRET_RE.findall(raw_content))

                    workflows.append(CIWorkflow(
                        file=rel_path,
                        triggers=triggers,
                        permissions=permissions,
                        actions=actions,
                        run_steps=run_steps,
                        secrets_used=sorted(secrets_found),
                        discovered_by="yaml"
                    ))
                except Exception as e:
                    errors.append(f"Error processing workflow {rel_path}: {e}")

    return workflows, errors
