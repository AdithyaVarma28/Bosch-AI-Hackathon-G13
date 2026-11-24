"""Stage 3 data contracts: node/edge vocabulary, stable IDs and Pydantic models.

Every node and edge in the knowledge graph carries ``discovered_by``, ``evidence``,
``confidence``, ``commit`` and ``analyzed_at`` (see graph_builder.add_node/add_edge).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from guardian.purl import make_purl, normalize_name as _purl_normalize

# --------------------------------------------------------------------------- vocabulary

NODE_TYPES = (
    "Repo", "Module", "File", "Function", "Class", "Package", "Route", "CLIEntry",
    "EnvVar", "Table", "ExternalService", "Workflow", "Action", "Image", "Commit",
    "Vulnerability", "Anomaly",          # added by Stage 4 / Stage 5
)

EDGE_TYPES = (
    "CONTAINS", "IMPORTS", "DEPENDS_ON", "USES_PACKAGE", "CALLS", "CALLS_API", "REQUIRES",
    "HANDLES", "RECEIVES_INPUT", "READS_ENV", "READS", "WRITES", "MAPS_TO", "CONTACTS",
    "USES_ACTION", "USES_IMAGE", "CHANGED_IN",
    "AFFECTS", "USED_AT", "REACHED_VIA",  # Stage 4: Vulnerability -> Package / Function / entry point
    "FLAGS",                              # Stage 5: Anomaly -> Package / File / Image / Workflow / Commit
)

DISCOVERED_BY = (
    "ast", "manifest", "lockfile", "pip-report", "syft", "sbom", "pypi", "git", "yaml",
    "dockerfile", "algorithm", "ai", "osv", "osv-dump", "grype", "detector",
)

# Function-level tags produced by 3A (propagated up to files and modules).
SENSITIVE_TAGS = (
    "reads_secret_env", "writes_db", "contacts_external", "network", "subprocess",
    "code_exec", "deserialize",
)
FUNCTION_TAGS = ("entry_point", "receives_user_input", "reads_db") + SENSITIVE_TAGS


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- stable IDs

def normalize_name(name: str) -> str:
    """PEP 503 normalisation (same rule as guardian.purl), used to match packages everywhere."""
    return _purl_normalize((name or "").strip())


def purl(name: str, version: Optional[str] = None) -> str:
    return make_purl("pypi", name, version) if version else f"pkg:pypi/{normalize_name(name)}"


def repo_id(name: str) -> str: return f"repo:{name}"
def module_id(path: str) -> str: return f"module:{path}"
def file_id(path: str) -> str: return f"file:{path}"
def fn_id(def_id: str) -> str: return f"fn:{def_id}"
def class_id(def_id: str) -> str: return f"class:{def_id}"
def route_id(method: str, path: str) -> str: return f"route:{(method or 'ANY').upper()} {path}"
def cli_id(name: str) -> str: return f"cli:{name}"
def env_id(name: str) -> str: return f"env:{name}"
def table_id(name: str) -> str: return f"table:{name}"
def svc_id(name: str) -> str: return f"svc:{name}"
def commit_id(sha: str) -> str: return f"commit:{(sha or '')[:7]}"
def workflow_id(path: str) -> str: return f"workflow:{path}"
def image_id(ref: str) -> str: return f"image:{ref}"


def action_id(uses: str, ref: Optional[str]) -> str:
    return f"action:{uses}@{ref}" if ref else f"action:{uses}"


def short_label(node_id: str) -> str:
    """Human label: 'fn:app/x.py::Cls.meth' -> 'Cls.meth()', 'svc:Stripe' -> 'Stripe'."""
    kind, _, rest = node_id.partition(":")
    if kind in ("fn",):
        return rest.split("::")[-1] + "()"
    if kind == "class":
        return rest.split("::")[-1]
    if kind == "pkg":
        return rest.split("/", 1)[-1]
    if kind == "table":
        return f"{rest} table"
    return rest or node_id


# --------------------------------------------------------------------------- models

class Evidence(BaseModel):
    """Where a claim comes from: file + line(s), a commit, or a graph node."""
    model_config = ConfigDict(extra="ignore")

    file: Optional[str] = None
    line: Optional[int] = None
    lines: Optional[str] = None          # "5-8" or "7"
    commit: Optional[str] = None
    node: Optional[str] = None

    def line_range(self) -> Optional[tuple[int, int]]:
        if self.lines:
            m = re.match(r"^\s*(\d+)\s*(?:[-–:]\s*(\d+))?\s*$", str(self.lines))
            if m:
                a = int(m.group(1))
                b = int(m.group(2) or a)
                return (min(a, b), max(a, b))
            return None
        if self.line is not None:
            return (int(self.line), int(self.line))
        return None

    def label(self) -> str:
        if self.file:
            rng = self.line_range()
            if rng:
                return f"{self.file}:{rng[0]}" if rng[0] == rng[1] else f"{self.file}:{rng[0]}–{rng[1]}"
            return self.file
        if self.commit:
            return f"commit:{self.commit[:7]}"
        return self.node or ""


class Card(BaseModel):
    """3B semantic card (module, file or repo)."""
    model_config = ConfigDict(extra="ignore")

    id: str
    purpose: str
    responsibilities: list[str] = []
    inputs: list[str] = []
    outputs: list[str] = []
    data_touched: list[str] = []
    external: list[str] = []
    sensitivity: Literal["low", "medium", "high"] = "low"
    sensitivity_reasons: list[str] = []
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = []
    open_questions: list[str] = []
    discovered_by: str = "ai"
    analyzed_at: str = Field(default_factory=now_iso)
    commit: Optional[str] = None
    dropped_claims: list[str] = []


class ExecutionPath(BaseModel):
    id: str
    entry: str
    input: Optional[str] = None
    steps: list[str]
    sinks: list[str]
    sink_details: list[dict[str, Any]] = []
    evidence: list[Evidence] = []
    confidence: float = 1.0
    discovered_by: str = "algorithm"


class BlastRadius(BaseModel):
    package: str
    name: str
    version: Optional[str] = None
    direct: bool = False
    via_direct: list[str] = []
    files: int = 0
    file_list: list[str] = []
    functions: list[str] = []
    modules: list[str] = []
    routes_reaching: list[str] = []
    cli_reaching: list[str] = []
    secrets_nearby: list[str] = []
    tables_nearby: list[str] = []
    services_nearby: list[str] = []
    api_calls: list[str] = []
    radius: Literal["none", "internal", "public", "large"] = "none"
    reasons: list[str] = []
    evidence: list[Evidence] = []
    discovered_by: str = "algorithm"


class Question(BaseModel):
    id: str
    text: str
    subject: str
    kind: str
    priority: int = 1
    source: str = ""
    context: dict[str, Any] = {}


class Finding(BaseModel):
    """3D investigator output."""
    model_config = ConfigDict(extra="ignore")

    id: str = ""
    question: str
    answer: str
    subject: str
    kind: str = ""
    evidence: list[Evidence] = []
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    status: Literal["resolved", "unresolved"] = "unresolved"
    notable: bool = False
    notable_reason: Optional[str] = None
    new_questions: list[str] = []
    steps_used: int = 0
    dropped_evidence: list[str] = []
    discovered_by: str = "ai"
    analyzed_at: str = Field(default_factory=now_iso)


# JSON schema the LLM must follow for cards (structured outputs: all keys required,
# additionalProperties false).
CARD_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "purpose": {"type": "string"},
        "responsibilities": {"type": "array", "items": {"type": "string"}},
        "inputs": {"type": "array", "items": {"type": "string"}},
        "outputs": {"type": "array", "items": {"type": "string"}},
        "data_touched": {"type": "array", "items": {"type": "string"}},
        "external": {"type": "array", "items": {"type": "string"}},
        "sensitivity": {"type": "string", "enum": ["low", "medium", "high"]},
        "sensitivity_reasons": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"file": {"type": "string"}, "lines": {"type": "string"}},
                "required": ["file", "lines"],
                "additionalProperties": False,
            },
        },
        "open_questions": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "purpose", "responsibilities", "inputs", "outputs", "data_touched", "external",
        "sensitivity", "sensitivity_reasons", "confidence", "evidence", "open_questions",
    ],
    "additionalProperties": False,
}
