"""Human-in-the-loop remediation workflow (docs/DAY_2_PLAN.md section 5): one LangGraph thread per remediation,
checkpointed in remediation.sqlite, with two human interrupts.

    propose -> critic -> PROPOSAL_REVIEW --approve--> validate (sandbox) -> PATCH_REVIEW --approve--> apply (branch)
                              |  revise / regenerate / alternative -> propose ...       |  revise -> propose
                              +-- reject -> closed                                      +-- reject -> closed

Every thread pauses at PROPOSAL_REVIEW; the gate only decides which tab it is shown in. Nothing is ever applied
without the patch approval."""
from __future__ import annotations

import sqlite3
import threading
import traceback
from pathlib import Path
from typing import Any, Callable, Optional, TypedDict

from . import critic, sandbox
from .common import (REGISTER_FILE, WORKFLOW_DB, band_idx, get_rem, now, put_rem, read_json, repo_path, scan_lock)
from .history import audit

try:
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Command, interrupt
    HAVE_LANGGRAPH = True
except ImportError:  # pragma: no cover
    HAVE_LANGGRAPH = False

MAX_REVISIONS = 3
SCAN_LLM: dict[str, Any] = {}        # scan-time LLM per output folder (not serialisable into the checkpoint)


# ------------------------------------------------------------------ gate
def gate(unit: dict) -> dict:
    p = unit["proposals"][unit["current"]] if unit.get("proposals") else {}
    fc, fconf = p.get("fix_confidence", "low"), unit["finding_confidence"]
    high = band_idx(unit["priority"]) >= band_idx("high")
    needs = (high or unit.get("downgrade_limited")) and (fconf != "high" or fc != "high")
    reasons = []
    if needs:
        if unit.get("downgrade_limited") and not high:
            reasons.append(f"the contextual decision lowered a {unit['stage_risk']} rule-based risk: a human confirms the downgrade")
        else:
            reasons.append(f"priority {unit['priority']}")
        if fconf != "high":
            reasons.append(f"finding confidence {fconf}")
        if fc != "high":
            reasons.append(f"fix confidence {fc}")
    status = unit.get("status")
    if status in ("applied", "rejected"):
        tab = "decided"
    elif needs:
        tab = "decide"
    elif high:
        tab = "ready"
    elif fconf == "low":
        tab = "unresolved"
    else:
        tab = "auto"
    return {"needs_proposal_review": bool(needs), "tab": tab, "reasons": reasons,
            "patch_review_required": True}


def _refresh(unit: dict) -> dict:
    unit["gate"] = gate(unit)
    unit["tab"] = unit["gate"]["tab"]
    unit["updated_at"] = now()
    return unit


def _evidence(out: Path, unit: dict) -> list[dict]:
    reg = {e["finding_id"]: e for e in read_json(Path(out) / REGISTER_FILE, []) or []}
    return [x for fid in unit["finding_ids"] for x in reg.get(fid, {}).get("evidence") or []]


# ------------------------------------------------------------------ node bodies (shared by LangGraph and direct mode)
def do_propose(out: Path, rid: str, cmd: dict) -> None:
    out = Path(out)
    unit = get_rem(out, rid)
    action = cmd.get("action", "init")
    feedback = cmd.get("feedback")
    llm_for_critic = SCAN_LLM.get(str(out))
    agent_info = None
    prop = None
    if action in ("revise", "regenerate") or (action == "init" and cmd.get("use_agent")):
        from .agent import make_llm, run_agent
        prop, agent_info = run_agent(out, unit, feedback, large=bool(cmd.get("large")))
        llm_for_critic = make_llm(out, False)
        if prop is not None:
            prop["author"] = f"agent:{agent_info.get('model')}"
            prop["feedback"] = feedback
            prop["created_at"] = now()
            prop["agent"] = {k: agent_info.get(k) for k in ("model", "skills_loaded", "tool_calls", "trace")}
    if prop is None:
        if action in ("revise", "regenerate"):
            unit = get_rem(out, rid)
            unit["last_agent_error"] = (agent_info or {}).get("error") or "the agent produced no proposal"
            unit["last_agent_trace"] = (agent_info or {}).get("trace")
            audit(out, "agent_failed", rid, error=unit["last_agent_error"], feedback=feedback,
                  model=(agent_info or {}).get("model"))
            unit["status"] = "awaiting_proposal_review"
            put_rem(out, _refresh(unit))
            return
        k = cmd.get("alternative")
        cands = [c for c in unit["candidates"] if not c.get("excluded")]
        cand = next((c for c in unit["candidates"] if c["cid"] == k), None) if k is not None else (cands[0] if cands else None)
        if cand is None:
            cand = unit["candidates"][0]
        prop = critic.proposal_from_candidate(unit, cand, "template", feedback=feedback)
        if action == "alternative":
            prop["selected_by"] = cmd.get("reviewer") or "reviewer"
    prop["version"] = len(unit["proposals"]) + 1
    critic.review(unit, prop, repo_path(out), llm_for_critic, _evidence(out, unit))
    unit = get_rem(out, rid)
    unit["proposals"].append(prop)
    unit["current"] = len(unit["proposals"]) - 1
    unit["status"] = "awaiting_proposal_review"
    unit.pop("validation", None)
    unit["last_agent_error"] = None
    put_rem(out, _refresh(unit))
    audit(out, "proposal_created", rid, version=prop["version"], author=prop["author"], skill=prop.get("skill"),
          action=prop["action"], fix_confidence=prop["fix_confidence"], feedback=feedback,
          checks={k: v.get("status") for k, v in (prop.get("checks") or {}).items()})


def do_validate(out: Path, rid: str, log: Callable[[str], None] = lambda m: None) -> None:
    out = Path(out)
    unit = get_rem(out, rid)
    prop = unit["proposals"][unit["current"]]
    old = (unit.get("validation") or {}).get("worktree")
    if old:
        sandbox.remove_worktree(out, old)

    def progress(msg):
        u = get_rem(out, rid)
        u.setdefault("working", {})["step"] = msg
        put_rem(out, u)

    v = sandbox.validate(out, unit, prop, log=progress)
    unit = get_rem(out, rid)
    unit["validation"] = v
    prop = unit["proposals"][unit["current"]]
    for k in ("build", "tests", "rescan_resolved", "no_new_vulns"):
        if k in v.get("checks", {}):
            prop["checks"][k] = v["checks"][k]
    prop["fix_confidence"], prop["fix_confidence_reasons"] = critic.fix_confidence(prop, v)
    unit["status"] = "awaiting_patch_review"
    put_rem(out, _refresh(unit))
    audit(out, "validation_result", rid, version=prop["version"], status=v["status"],
          checks={k: c.get("status") for k, c in v.get("checks", {}).items()}, commit=v.get("commit"),
          sbom_diff=(v.get("rescan") or {}).get("sbom_diff"), detail=v.get("detail"))


def do_apply(out: Path, rid: str) -> None:
    unit = get_rem(out, rid)
    res = sandbox.apply_branch(out, unit, unit.get("validation") or {})
    unit["applied"] = res
    unit["status"] = "applied" if res.get("ok") else "awaiting_patch_review"
    put_rem(out, _refresh(unit))
    audit(out, "branch_applied" if res.get("ok") else "apply_failed", rid, **{k: v for k, v in res.items() if k != "ok"})


def do_close(out: Path, rid: str, cmd: dict) -> None:
    unit = get_rem(out, rid)
    sandbox.remove_worktree(out, (unit.get("validation") or {}).get("worktree"))
    unit["status"] = "rejected"
    unit["rejection"] = {"stage": cmd.get("stage"), "reason": cmd.get("reason"), "by": cmd.get("reviewer"), "at": now()}
    put_rem(out, _refresh(unit))


# ------------------------------------------------------------------ LangGraph
class RemState(TypedDict, total=False):
    out: str
    rid: str
    cmd: dict


def _n_propose(s: RemState) -> dict:
    do_propose(Path(s["out"]), s["rid"], s.get("cmd") or {})
    return {}


def _n_proposal_review(s: RemState) -> dict:
    unit = get_rem(Path(s["out"]), s["rid"])
    cmd = interrupt({"stage": "proposal", "rid": s["rid"], "version": len(unit["proposals"])})
    return {"cmd": cmd}


def _n_validate(s: RemState) -> dict:
    do_validate(Path(s["out"]), s["rid"])
    return {}


def _n_patch_review(s: RemState) -> dict:
    cmd = interrupt({"stage": "patch", "rid": s["rid"]})
    return {"cmd": cmd}


def _n_apply(s: RemState) -> dict:
    do_apply(Path(s["out"]), s["rid"])
    return {}


def _n_close(s: RemState) -> dict:
    do_close(Path(s["out"]), s["rid"], s.get("cmd") or {})
    return {}


def _route(s: RemState) -> str:
    a = (s.get("cmd") or {}).get("action")
    return {"approve": "validate", "reject": "close", "revise": "propose", "regenerate": "propose",
            "alternative": "propose", "revalidate": "validate"}.get(a, "proposal_review")


def _route_patch(s: RemState) -> str:
    a = (s.get("cmd") or {}).get("action")
    return {"approve": "apply", "reject": "close", "revise": "propose", "regenerate": "propose",
            "alternative": "propose", "revalidate": "validate"}.get(a, "patch_review")


class WorkflowManager:
    _instances: dict[str, "WorkflowManager"] = {}

    @classmethod
    def for_dir(cls, out: Path) -> "WorkflowManager":
        key = str(Path(out).resolve())
        if key not in cls._instances:
            cls._instances[key] = cls(Path(out))
        return cls._instances[key]

    def __init__(self, out: Path):
        self.out = Path(out)
        self.lock = threading.Lock()
        self.graph = None
        if HAVE_LANGGRAPH:
            from langgraph.checkpoint.sqlite import SqliteSaver
            self.conn = sqlite3.connect(str(self.out / WORKFLOW_DB), check_same_thread=False)
            b = StateGraph(RemState)
            for name, fn in (("propose", _n_propose), ("proposal_review", _n_proposal_review), ("validate", _n_validate),
                             ("patch_review", _n_patch_review), ("apply", _n_apply), ("close", _n_close)):
                b.add_node(name, fn)
            b.add_edge(START, "propose")
            b.add_edge("propose", "proposal_review")
            b.add_conditional_edges("proposal_review", _route, ["validate", "close", "propose", "proposal_review"])
            b.add_edge("validate", "patch_review")
            b.add_conditional_edges("patch_review", _route_patch, ["apply", "close", "propose", "validate", "patch_review"])
            b.add_edge("apply", END)
            b.add_edge("close", END)
            self.graph = b.compile(checkpointer=SqliteSaver(self.conn))

    @property
    def engine(self) -> str:
        return "langgraph" if self.graph is not None else "direct"

    def _cfg(self, unit: dict) -> dict:
        return {"configurable": {"thread_id": unit["thread_id"]}}

    def start(self, unit: dict, use_agent: bool = False) -> None:
        cmd = {"action": "init", "use_agent": use_agent}
        with self.lock:
            if self.graph is not None:
                self.graph.invoke({"out": str(self.out), "rid": unit["rid"], "cmd": cmd}, config=self._cfg(unit))
            else:
                do_propose(self.out, unit["rid"], cmd)

    def paused_at(self, unit: dict) -> Optional[str]:
        if self.graph is None:
            return {"awaiting_proposal_review": "proposal_review", "awaiting_patch_review": "patch_review"}.get(unit.get("status"))
        st = self.graph.get_state(self._cfg(unit))
        return st.next[0] if st.next else None

    def resume(self, unit: dict, cmd: dict) -> None:
        with self.lock:
            if self.graph is not None:
                self.graph.invoke(Command(resume=cmd), config=self._cfg(unit))
                return
        # direct mode: same transitions without LangGraph
        a = cmd["action"]
        if a in ("revise", "regenerate", "alternative"):
            do_propose(self.out, unit["rid"], cmd)
        elif a == "reject":
            do_close(self.out, unit["rid"], cmd)
        elif cmd["stage"] == "proposal" and a in ("approve", "revalidate") or a == "revalidate":
            do_validate(self.out, unit["rid"])
        elif cmd["stage"] == "patch" and a == "approve":
            do_apply(self.out, unit["rid"])


class DecisionError(ValueError):
    pass


def validate_cmd(unit: dict, cmd: dict, paused: Optional[str]) -> dict:
    stage, action = cmd.get("stage"), cmd.get("action")
    if unit.get("working"):
        raise DecisionError("this remediation is still being worked on; wait for the current step to finish")
    if unit.get("status") in ("applied", "rejected"):
        raise DecisionError(f"this remediation is already {unit['status']}")
    expected = {"proposal_review": "proposal", "patch_review": "patch"}.get(paused or "")
    if expected is None:
        raise DecisionError("this remediation is not waiting for a decision")
    if stage != expected:
        raise DecisionError(f"it is waiting for a {expected} decision, not a {stage} decision")
    if action not in ("approve", "reject", "revise", "regenerate", "alternative", "revalidate"):
        raise DecisionError(f"unknown action {action!r}")
    if action == "reject" and not (cmd.get("reason") or "").strip():
        raise DecisionError("a reason is required to reject")
    if action == "revise" and not (cmd.get("feedback") or "").strip():
        raise DecisionError("tell the agent what to change (feedback is required for revise)")
    if action in ("revise", "regenerate"):
        n = sum(1 for p in unit["proposals"] if str(p.get("author", "")).startswith("agent"))
        if n >= MAX_REVISIONS:
            raise DecisionError(f"the agent already proposed {n} times for this item (limit {MAX_REVISIONS}); "
                                "choose a candidate, approve or reject")
    if action == "alternative":
        k = cmd.get("alternative")
        c = next((c for c in unit["candidates"] if c["cid"] == k), None)
        if c is None or c.get("excluded"):
            raise DecisionError("pick one of the listed (not excluded) candidates")
    if action == "approve" and stage == "patch" and (unit.get("validation") or {}).get("status") != "passed":
        if not (cmd.get("reason") or "").strip():
            raise DecisionError("validation did not pass: give a reason to approve this patch anyway")
    if action == "approve" and stage == "proposal" and not unit["proposals"][unit["current"]].get("edits"):
        raise DecisionError("this proposal has no code change; reject it with a reason (e.g. accepted risk) or ask the agent")
    if action == "revalidate" and stage != "patch":
        raise DecisionError("revalidate is a patch-stage action")
    return cmd


def submit(out: Path, rid: str, cmd: dict, background: bool = True) -> dict:
    out = Path(out)
    mgr = WorkflowManager.for_dir(out)
    with scan_lock(out):
        unit = get_rem(out, rid)
        if unit is None:
            raise KeyError(rid)
        validate_cmd(unit, cmd, mgr.paused_at(unit))
        cmd = {**cmd, "at": now()}
        what = {"approve": "validating in the sandbox (build, tests, rescan)" if cmd["stage"] == "proposal" else "creating the fix branch",
                "revise": "the agent is revising the proposal", "regenerate": "the agent is writing a proposal",
                "alternative": "checking the selected candidate", "reject": "closing",
                "revalidate": "validating in the sandbox"}[cmd["action"]]
        unit["working"] = {"what": what, "since": now()}
        unit.setdefault("decisions", []).append({k: cmd.get(k) for k in ("stage", "action", "reason", "feedback", "alternative",
                                                                          "reviewer", "at", "source", "large")})
        put_rem(out, unit)
    audit(out, "review_decision", rid, stage=cmd["stage"], action=cmd["action"], reason=cmd.get("reason"),
          feedback=cmd.get("feedback"), reviewer=cmd.get("reviewer"), source=cmd.get("source"),
          proposal_version=len(unit["proposals"]))

    def work():
        try:
            mgr.resume(unit, cmd)
        except Exception as exc:
            u = get_rem(out, rid)
            u["last_error"] = f"{type(exc).__name__}: {exc}"
            audit(out, "workflow_error", rid, error=u["last_error"], trace=traceback.format_exc()[-1500:])
            put_rem(out, u)
        finally:
            u = get_rem(out, rid)
            u.pop("working", None)
            put_rem(out, _refresh(u))

    if background:
        threading.Thread(target=work, daemon=True, name=f"guardian-{rid}").start()
    else:
        work()
    return get_rem(out, rid)
