"""A bounded tool-calling loop shared by the Stage 4 and Stage 5 investigators.

The model may call the toolbox's tools until it calls the submit tool or the tool budget runs out.
Nothing it says is trusted: callers validate the submitted object against the evidence ledger.
"""
from __future__ import annotations

from typing import Optional

from .tools import result_text


def run_tool_agent(llm, purpose: str, system: str, user: str, tb, tool_specs: list[dict], submit_spec: dict,
                   extra_turns: int = 3) -> Optional[dict]:
    """Returns the submit tool's input, ``{"__budget_exhausted": True}``, or ``None`` if the LLM is unavailable."""
    messages: list[dict] = [{"role": "user", "content": user}]
    tools = tool_specs + [submit_spec]
    for _ in range(tb.budget + extra_turns):
        resp = llm.create(purpose, system, messages, tools=tools, max_tokens=16000)
        if resp is None:
            return None
        content = resp.get("content", [])
        messages.append({"role": "assistant", "content": content})
        uses = [b for b in content if b.get("type") == "tool_use"]
        submit = next((b for b in uses if b.get("name") == submit_spec["name"]), None)
        if submit:
            return dict(submit.get("input") or {})
        if not uses:
            messages.append({"role": "user", "content": f"Call {submit_spec['name']} now with what you have."})
            continue
        results = []
        for b in uses:
            if tb.exhausted:
                text, err = f"Tool budget exhausted. Call {submit_spec['name']} now with what is proven.", True
            else:
                out = tb.call(b.get("name"), b.get("input") or {})
                text, err = result_text(out), "error" in out
            results.append({"type": "tool_result", "tool_use_id": b.get("id"), "content": text, "is_error": err})
        messages.append({"role": "user", "content": results})
    return {"__budget_exhausted": True}
