"""LLM client (Groq) with JSON mode, one repair retry, record/replay cache and a pluggable provider.

Configure with environment variables:
  GROQ_API_KEY   required for live calls
  GROQ_MODEL     optional, default openai/gpt-oss-120b
LLM output is never trusted: callers validate it and the Verifier checks every claim against evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Callable, Literal

DEFAULT_MODEL = "openai/gpt-oss-120b"
Provider = Callable[[list[dict], str], str]   # (messages, model) -> raw text


class LLMUnavailable(RuntimeError):
    pass


def groq_provider(api_key: str) -> Provider:
    from groq import Groq  # imported lazily so the pipeline runs without the SDK configured

    client = Groq(api_key=api_key, max_retries=2, timeout=60)

    def call(messages: list[dict], model: str) -> str:
        try:
            resp = client.chat.completions.create(model=model, messages=messages, temperature=0,
                                                  response_format={"type": "json_object"}, max_tokens=2048)
        except Exception as e:
            # Groq rejects replies that fail its JSON-mode check (HTTP 400 json_validate_failed).
            # Retry once in free-text mode; our own parser + repair step handle the result.
            if "validate json" not in str(e).lower() and "json_validate_failed" not in str(e).lower():
                raise
            resp = client.chat.completions.create(model=model, messages=messages, temperature=0, max_tokens=2048)
        return resp.choices[0].message.content or ""
    return call


def _load_dotenv(path: Path) -> None:
    """Read GROQ_* settings from a local, git-ignored .env (never overrides real environment variables)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and k.strip() in ("GROQ_API_KEY", "GROQ_MODEL") and not os.environ.get(k.strip()):
            os.environ[k.strip()] = v.strip().strip('"').strip("'")


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        obj = json.loads(m.group(0))
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    return obj


class LLMClient:
    def __init__(self, provider: Provider | None = None, model: str | None = None, cache_dir: Path = Path(".guardian_cache"),
                 mode: Literal["live", "record", "replay", "auto"] = "auto"):
        self.provider = provider
        self.model = model or os.environ.get("GROQ_MODEL") or DEFAULT_MODEL
        self.dir = Path(cache_dir) / "llm"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.calls = 0
        self.cache_hits = 0
        self.name = f"groq:{self.model}"

    @classmethod
    def from_env(cls, cache_dir: Path, model: str | None = None, offline: bool = False) -> "LLMClient | None":
        _load_dotenv(Path.cwd() / ".env")
        key = os.environ.get("GROQ_API_KEY")
        if offline:
            c = cls(None, model, cache_dir, mode="replay")
            return c if any(c.dir.glob("*.json")) else None
        if not key:
            return None
        return cls(groq_provider(key), model, cache_dir, mode="auto")

    def _key(self, messages: list[dict]) -> Path:
        h = hashlib.sha256((self.model + json.dumps(messages, sort_keys=True)).encode()).hexdigest()
        return self.dir / f"{h}.json"

    def _raw(self, messages: list[dict]) -> str:
        path = self._key(messages)
        if self.mode in ("replay", "auto") and path.exists():
            self.cache_hits += 1
            return json.loads(path.read_text(encoding="utf-8"))["text"]
        if self.mode == "replay" or self.provider is None:
            raise LLMUnavailable("no cached response (replay/offline mode)")
        last = None
        for attempt in range(3):
            try:
                self.calls += 1
                text = self.provider(messages, self.model)
                path.write_text(json.dumps({"model": self.model, "text": text}), encoding="utf-8")
                return text
            except Exception as e:  # network, rate limit, auth
                last = e
                if "rate" in str(e).lower() or "429" in str(e):
                    time.sleep(2 * (attempt + 1))
                    continue
                break
        raise LLMUnavailable(f"{type(last).__name__}: {str(last)[:200]}")

    def complete_json(self, system: str, user: str, history: list[dict] | None = None) -> dict:
        """One schema-repair retry, then LLMUnavailable."""
        messages = [{"role": "system", "content": system}, *(history or []), {"role": "user", "content": user}]
        text = self._raw(messages)
        try:
            return _extract_json(text)
        except (json.JSONDecodeError, ValueError):
            repair = messages + [{"role": "assistant", "content": text[:4000]},
                                 {"role": "user", "content": "That was not a valid JSON object. Reply with ONLY the JSON object."}]
            try:
                return _extract_json(self._raw(repair))
            except (json.JSONDecodeError, ValueError) as e:
                raise LLMUnavailable(f"invalid JSON after repair: {e}") from e


def fence(text: str, limit: int = 6000) -> str:
    """Wrap untrusted repository text so the model treats it as data. Neutralise closing tags inside it."""
    safe = (text or "")[:limit].replace("</repo_data>", "</repo_data_>").replace("<repo_data>", "<repo_data_>")
    return f"<repo_data>\n{safe}\n</repo_data>"
