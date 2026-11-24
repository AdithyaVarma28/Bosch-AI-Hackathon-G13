"""Groq / Gemini provider (OpenAI-compatible) against a mocked HTTP endpoint: no network, no key needed."""
import json

import httpx
import pytest

from guardian.stage3_knowledge import llm as llm_mod
from guardian.stage3_knowledge.llm import LLM, OpenAICompatProvider
from guardian.stage4_vulns.agent import run_tool_agent


def make_llm(monkeypatch, tmp_path, name, handler, purposes="all"):
    monkeypatch.setenv("GROQ_API_KEY" if name == "groq" else "GEMINI_API_KEY", "test-key")
    if purposes is None:
        monkeypatch.delenv("GUARDIAN_LLM_PURPOSES", raising=False)
    else:
        monkeypatch.setenv("GUARDIAN_LLM_PURPOSES", purposes)
    monkeypatch.setenv("GUARDIAN_LLM_RPM", "100000")
    monkeypatch.setenv("GUARDIAN_ENV_FILE", str(tmp_path / "no.env"))
    monkeypatch.setattr(llm_mod.time if hasattr(llm_mod, "time") else __import__("time"), "sleep", lambda s: None)
    llm = LLM(provider=name, cache_dir=tmp_path / "cache")
    assert llm.available, llm.disabled_reason
    llm.provider.client = httpx.Client(transport=httpx.MockTransport(handler))
    return llm


def reply(message, finish="stop"):
    return httpx.Response(200, json={"model": "m", "choices": [{"message": message, "finish_reason": finish}],
                                     "usage": {"prompt_tokens": 3, "completion_tokens": 2}})


def test_complete_json_strips_fences_and_sends_schema(monkeypatch, tmp_path):
    seen = []

    def handler(req):
        seen.append(json.loads(req.content))
        return reply({"role": "assistant", "content": "```json\n{\"purpose\": \"payments\"}\n```"})

    llm = make_llm(monkeypatch, tmp_path, "groq", handler)
    out = llm.complete_json("card", "sys", "describe", {"type": "object", "properties": {"purpose": {"type": "string"}}})
    assert out == {"purpose": "payments"}
    body = seen[0]
    assert body["model"] == "openai/gpt-oss-120b" and body["response_format"] == {"type": "json_object"}
    assert body["messages"][0]["role"] == "system" and "JSON Schema" in body["messages"][0]["content"]
    assert llm.stats()["provider"] == "groq"
    # cached: a second identical call makes no request
    assert llm.complete_json("card", "sys", "describe", {"type": "object", "properties": {"purpose": {"type": "string"}}})
    assert len(seen) == 1


def test_tool_loop_round_trip(monkeypatch, tmp_path):
    bodies = []

    def handler(req):
        body = json.loads(req.content)
        bodies.append(body)
        if len(bodies) == 1:
            return reply({"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "read_code", "arguments": "{\"file\": \"a.py\"}"},
                 "extra_content": {"google": {"thought_signature": "sig"}}}]}, "tool_calls")
        return reply({"role": "assistant", "content": None, "tool_calls": [
            {"id": "c2", "type": "function", "function": {"name": "submit", "arguments": "{\"usage\": \"symbol_called\"}"}}]},
            "tool_calls")

    class TB:
        budget, exhausted = 5, False

        def call(self, name, args):
            return {"file": args["file"], "lines": ["x = 1"]}

    llm = make_llm(monkeypatch, tmp_path, "gemini", handler)
    spec = {"name": "read_code", "description": "read", "input_schema": {
        "type": "object", "properties": {"file": {"type": "string"}, "n": {"type": "integer", "minimum": 1}},
        "required": ["file"], "additionalProperties": False}}
    submit = {"name": "submit", "description": "done", "input_schema": {"type": "object", "properties": {}}}
    out = run_tool_agent(llm, "investigator", "sys", "investigate", TB(), [spec], submit)
    assert out == {"usage": "symbol_called"}
    params = bodies[0]["tools"][0]["function"]["parameters"]
    assert "additionalProperties" not in params and "minimum" not in params["properties"]["n"]   # gemini subset
    second = bodies[1]["messages"]
    assistant = next(m for m in second if m["role"] == "assistant")
    assert assistant["tool_calls"][0]["id"] == "c1"
    assert assistant["tool_calls"][0]["extra_content"] == {"google": {"thought_signature": "sig"}}
    tool = next(m for m in second if m["role"] == "tool")
    assert tool["tool_call_id"] == "c1" and "a.py" in tool["content"]


def test_rate_limit_retry_then_success(monkeypatch, tmp_path):
    calls = []

    def handler(req):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "1"}, text="Rate limit reached: tokens per minute")
        return reply({"role": "assistant", "content": "{\"ok\": true}"})

    llm = make_llm(monkeypatch, tmp_path, "groq", handler)
    assert llm.complete_json("x", "s", "p", {"type": "object"}) == {"ok": True}
    assert len(calls) == 2


def test_daily_quota_and_bad_key_disable_provider(monkeypatch, tmp_path):
    llm = make_llm(monkeypatch, tmp_path, "groq",
                   lambda req: httpx.Response(429, text="Rate limit reached on tokens per day (TPD)"))
    assert llm.complete_json("x", "s", "p", {"type": "object"}) is None
    assert not llm.available and "quota" in llm.disabled_reason

    llm = make_llm(monkeypatch, tmp_path / "b", "gemini", lambda req: httpx.Response(401, text="bad key"))
    assert llm.complete_json("x", "s", "p", {"type": "object"}) is None
    assert not llm.available and "rejected the key" in llm.disabled_reason


def test_auto_picks_groq_from_dotenv_and_falls_back_offline(monkeypatch, tmp_path):
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GROQ_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
              "GUARDIAN_LLM", "GUARDIAN_MODEL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("GUARDIAN_ENV_FILE", str(tmp_path / "missing.env"))
    off = LLM(provider="auto", cache_dir=tmp_path)
    assert not off.available and "GROQ_API_KEY" in off.disabled_reason

    env = tmp_path / ".env"
    env.write_text('# keys\nGROQ_API_KEY="gsk_test"\n', encoding="utf-8")
    monkeypatch.setenv("GUARDIAN_ENV_FILE", str(env))
    on = LLM(provider="auto", cache_dir=tmp_path)
    assert on.available and on.provider_name == "groq" and on.model == "openai/gpt-oss-120b"


def test_free_providers_default_to_card_and_explain_only(monkeypatch, tmp_path):
    seen = []

    def handler(req):
        seen.append(1)
        return reply({"role": "assistant", "content": "{\"ok\": true}"})

    llm = make_llm(monkeypatch, tmp_path, "groq", handler, purposes=None)
    assert llm.complete_json("card", "s", "p", {"type": "object"}) == {"ok": True}
    assert llm.complete_json("explain", "s", "p2", {"type": "object"}) == {"ok": True}
    assert llm.create("investigator", "s", [{"role": "user", "content": "x"}]) is None   # -> playbook
    assert llm.complete_json("verifier", "s", "p", {"type": "object"}) is None
    assert len(seen) == 2 and llm.stats()["skipped_to_rules"] == {"investigator": 1, "verifier": 1}

    llm = make_llm(monkeypatch, tmp_path / "all", "groq", handler, purposes="all")
    assert llm.complete_json("verifier", "s", "p", {"type": "object"}) == {"ok": True}


def test_unknown_provider_name_is_reported(tmp_path):
    assert "unknown LLM provider" in LLM(provider="nope", cache_dir=tmp_path).disabled_reason
    with pytest.raises(KeyError):
        OpenAICompatProvider("nope")


def test_dotenv_model_applies_to_first_llm(monkeypatch, tmp_path):
    for v in ("GROQ_API_KEY", "GUARDIAN_MODEL", "GUARDIAN_LLM"):
        monkeypatch.delenv(v, raising=False)
    env = tmp_path / ".env"
    env.write_text("GROQ_API_KEY=gsk_test\nGUARDIAN_MODEL=openai/gpt-oss-20b\n", encoding="utf-8")
    monkeypatch.setenv("GUARDIAN_ENV_FILE", str(env))
    assert LLM(provider="groq", cache_dir=tmp_path).model == "openai/gpt-oss-20b"
