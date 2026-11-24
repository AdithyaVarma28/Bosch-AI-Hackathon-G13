"""One LLM wrapper for 3B and 3D, so providers can be switched in one place.

* Provider ``anthropic`` (default when the SDK and credentials are available) calls Claude.
* Provider ``offline`` makes no calls; 3B and 3D then use their deterministic fallbacks.
* Every response is cached on disk, keyed by sha256 of the full request, so the same input
  gives the same output and a re-scan of an unchanged repo makes no new calls.

* Providers ``groq`` and ``gemini`` use their free OpenAI-compatible APIs (GROQ_API_KEY / GEMINI_API_KEY).
  ``auto`` picks Anthropic, then Groq, then Gemini, else offline. Keys may live in a gitignored ``.env``.

Environment: ``GUARDIAN_LLM`` (auto|groq|gemini|anthropic|offline), ``GUARDIAN_MODEL``, ``GUARDIAN_LLM_RPM``,
``GUARDIAN_LLM_CACHE`` (cache folder).
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Optional, Protocol

DEFAULT_MODEL = "claude-opus-5-5"


class ProviderUnavailable(Exception):
    """The provider cannot be used for the rest of this scan (no SDK, no credentials, no network)."""


class Provider(Protocol):
    name: str
    model: str

    def create(self, *, system: str, messages: list[dict], tools: Optional[list[dict]],
               json_schema: Optional[dict], max_tokens: int, effort: str) -> dict: ...


class AnthropicProvider:
    """Claude via the official Anthropic SDK (Messages API)."""
    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ProviderUnavailable("anthropic SDK is not installed (pip install anthropic)") from exc
        self.anthropic = anthropic
        self.model = model
        try:
            self.client = anthropic.Anthropic()
        except Exception as exc:
            raise ProviderUnavailable(f"no Anthropic credentials: {exc}") from exc

    def create(self, *, system, messages, tools, json_schema, max_tokens, effort) -> dict:
        a = self.anthropic
        output_config: dict[str, Any] = {"effort": effort}
        if json_schema:
            output_config["format"] = {"type": "json_schema", "schema": json_schema}
        kwargs: dict[str, Any] = dict(
            model=self.model, max_tokens=max_tokens, system=system, messages=messages,
            output_config=output_config,
            # server-side refusal fallback: a declined request is re-run on a fallback model
            betas=["server-side-fallback-2026-07-01"], fallbacks="default",
        )
        if tools:
            kwargs["tools"] = tools
        try:
            resp = self.client.beta.messages.create(**kwargs)
        except (a.AuthenticationError, a.PermissionDeniedError) as exc:
            raise ProviderUnavailable(f"Anthropic API rejected the credentials: {exc}") from exc
        except a.APIConnectionError as exc:
            raise ProviderUnavailable(f"cannot reach the Anthropic API: {exc}") from exc
        return {
            "content": [b.model_dump(mode="json", exclude_none=True) for b in resp.content],
            "stop_reason": resp.stop_reason,
            "model": resp.model,
            "usage": {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens},
        }


def _load_dotenv() -> None:
    """Read ``KEY=value`` lines from ``./.env`` into the environment (existing variables win).

    Lets a free Groq / Gemini key live in a gitignored ``.env`` file instead of the shell profile."""
    path = Path(os.environ.get("GUARDIAN_ENV_FILE") or ".env")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip().removeprefix("export ").strip(), v.strip().strip('"').strip("'")
        if k and v and k not in os.environ:
            os.environ[k] = v


# name -> (endpoint, key env vars, default model, default requests/minute, max output tokens)
OPENAI_COMPAT = {
    "groq": ("https://api.groq.com/openai/v1/chat/completions", ("GROQ_API_KEY",),
             "openai/gpt-oss-120b", 25, 8192),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
               ("GEMINI_API_KEY", "GOOGLE_API_KEY"), "gemini-2.5-flash", 9, 8192),
}

_GEMINI_SCHEMA_KEYS = {"type", "properties", "items", "required", "description", "enum", "format", "nullable"}


def _gemini_schema(s: Any) -> Any:
    """Gemini accepts only an OpenAPI subset: drop additionalProperties, minimum, maximum, ..."""
    if isinstance(s, dict):
        out = {k: v for k, v in s.items() if k in _GEMINI_SCHEMA_KEYS}
        if "properties" in out:
            out["properties"] = {k: _gemini_schema(v) for k, v in out["properties"].items()}
        if "items" in out:
            out["items"] = _gemini_schema(out["items"])
        return out
    return s


def _json_text(text: str) -> str:
    """Strip ```json fences / chatter around a JSON object so ``json.loads`` works."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t[3:]
        t = t.rsplit("```", 1)[0]
    t = t.strip()
    if not t.startswith(("{", "[")):
        a, b = t.find("{"), t.rfind("}")
        if a != -1 and b > a:
            t = t[a:b + 1]
    return t


class OpenAICompatProvider:
    """Groq or Gemini through their OpenAI-compatible chat endpoint (free API keys work).

    Requests and responses are translated to and from the Anthropic Messages shape (text /
    tool_use / tool_result blocks) that the Stage 3-5 agents use, so no caller changes."""

    def __init__(self, name: str, model: Optional[str] = None):
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ProviderUnavailable("httpx is not installed (pip install httpx)") from exc
        self.httpx = httpx
        self.name = name
        self.url, key_vars, default_model, rpm, self.max_out = OPENAI_COMPAT[name]
        self.key = next((os.environ[v] for v in key_vars if os.environ.get(v)), None)
        if not self.key:
            raise ProviderUnavailable(f"no {name} API key (set {' or '.join(key_vars)}, e.g. in .env)")
        self.model = model if model and not model.startswith("claude") else default_model
        self.max_out = int(os.environ.get("GUARDIAN_LLM_MAX_TOKENS") or self.max_out)
        self.min_interval = 60.0 / max(1, int(os.environ.get("GUARDIAN_LLM_RPM") or rpm))
        self._next_at = 0.0
        import threading
        self._lock = threading.Lock()
        self.client = httpx.Client(timeout=httpx.Timeout(120.0, connect=15.0))

    # ---------------------------------------------------------- translation
    def _messages(self, system: str, messages: list[dict], json_schema: Optional[dict]) -> list[dict]:
        if json_schema:
            schema = _gemini_schema(json_schema) if self.name == "gemini" else json_schema
            system = (f"{system}\n\nRespond with ONLY one JSON object (no markdown, no prose) that matches "
                      f"this JSON Schema:\n{json.dumps(schema)}")
        out: list[dict] = [{"role": "system", "content": system}]
        for m in messages:
            content = m.get("content")
            if isinstance(content, str):
                out.append({"role": m["role"], "content": content})
                continue
            blocks = content or []
            if m["role"] == "assistant":
                text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
                calls = [{"id": b.get("id"), "type": "function",
                          "function": {"name": b.get("name"), "arguments": json.dumps(b.get("input") or {})},
                          **({"extra_content": b["_extra"]} if b.get("_extra") else {})}
                         for b in blocks if b.get("type") == "tool_use"]
                msg: dict[str, Any] = {"role": "assistant", "content": text or (None if calls else "(no reply)")}
                if calls:
                    msg["tool_calls"] = calls
                out.append(msg)
            else:
                for b in blocks:
                    if b.get("type") == "tool_result":
                        c = b.get("content")
                        if isinstance(c, list):
                            c = "".join(x.get("text", "") for x in c if isinstance(x, dict))
                        out.append({"role": "tool", "tool_call_id": b.get("tool_use_id"),
                                    "content": ("ERROR: " if b.get("is_error") else "") + str(c or "")})
                text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
                if text:
                    out.append({"role": "user", "content": text})
        return out

    def _tools(self, tools: list[dict]) -> list[dict]:
        conv = _gemini_schema if self.name == "gemini" else (lambda s: s)
        return [{"type": "function", "function": {
            "name": t["name"], "description": t.get("description", ""),
            "parameters": conv(t.get("input_schema") or {"type": "object", "properties": {}})}} for t in tools]

    # ---------------------------------------------------------- transport
    def _throttle(self) -> None:
        import time
        with self._lock:
            now = time.monotonic()
            wait = self._next_at - now
            self._next_at = max(now, self._next_at) + self.min_interval
        if wait > 0:
            time.sleep(wait)

    @staticmethod
    def _retry_after(resp) -> float:
        h = resp.headers.get("retry-after")
        try:
            return float(h) if h else 0.0
        except ValueError:
            return 0.0

    def _post(self, body: dict) -> dict:
        import time
        httpx = self.httpx
        headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}
        tried_without_format = False
        for attempt in range(5):
            self._throttle()
            try:
                r = self.client.post(self.url, json=body, headers=headers)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                raise ProviderUnavailable(f"cannot reach the {self.name} API: {exc}") from exc
            except httpx.TimeoutException:
                if attempt >= 2:
                    raise
                continue
            if r.status_code == 200:
                return r.json()
            detail = r.text[:300]
            if r.status_code in (401, 403):
                raise ProviderUnavailable(f"{self.name} API rejected the key ({r.status_code}): {detail}")
            if r.status_code == 429:
                wait = self._retry_after(r) or min(60.0, 5.0 * 2 ** attempt)
                if wait > 90 or "per day" in detail.lower() or "quota" in detail.lower() and attempt >= 2:
                    raise ProviderUnavailable(f"{self.name} rate limit / free quota reached: {detail}")
                time.sleep(wait)
                continue
            if r.status_code >= 500:
                time.sleep(2.0 * (attempt + 1))
                continue
            if r.status_code == 400 and "response_format" in body and not tried_without_format:
                body = {k: v for k, v in body.items() if k != "response_format"}
                tried_without_format = True
                continue
            if r.status_code == 400 and "tool_use_failed" in detail and attempt == 0:
                continue  # the model wrote a malformed tool call; one retry usually fixes it
            raise RuntimeError(f"{self.name} HTTP {r.status_code}: {detail}")
        raise RuntimeError(f"{self.name}: gave up after retries")

    def create(self, *, system, messages, tools, json_schema, max_tokens, effort) -> dict:
        body: dict[str, Any] = {"model": self.model, "messages": self._messages(system, messages, json_schema),
                                "max_tokens": min(max_tokens, self.max_out), "temperature": 0}
        if "gpt-oss" in self.model:   # reasoning model: keep hidden reasoning short (it is never shown)
            body["reasoning_effort"] = os.environ.get("GUARDIAN_REASONING_EFFORT", "low")
        if tools:
            body["tools"] = self._tools(tools)
            body["tool_choice"] = "auto"
        elif json_schema:
            body["response_format"] = {"type": "json_object"}
        data = self._post(body)
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        content: list[dict] = []
        text = msg.get("content") or ""
        if isinstance(text, list):
            text = "".join(p.get("text", "") for p in text if isinstance(p, dict))
        if text:
            content.append({"type": "text", "text": _json_text(text) if json_schema else text})
        for i, call in enumerate(msg.get("tool_calls") or []):
            fn = call.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            block = {"type": "tool_use", "id": call.get("id") or f"call_{i}_{len(messages)}",
                     "name": fn.get("name"), "input": args if isinstance(args, dict) else {}}
            if call.get("extra_content"):   # Gemini thought signature: must be sent back next turn
                block["_extra"] = call["extra_content"]
            content.append(block)
        finish = choice.get("finish_reason")
        stop = ("tool_use" if any(b["type"] == "tool_use" for b in content)
                else "max_tokens" if finish == "length" else "end_turn")
        usage = data.get("usage") or {}
        return {"content": content, "stop_reason": stop, "model": data.get("model", self.model),
                "usage": {"input_tokens": usage.get("prompt_tokens", 0),
                          "output_tokens": usage.get("completion_tokens", 0)}}


def _auto_provider(model: str) -> tuple[Optional[Provider], Optional[str]]:
    """First usable provider: Anthropic (if a key is set), then Groq, then Gemini."""
    reasons = []
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        try:
            return AnthropicProvider(model), None
        except ProviderUnavailable as exc:
            reasons.append(str(exc))
    for name in ("groq", "gemini"):
        try:
            return OpenAICompatProvider(name, model), None
        except ProviderUnavailable as exc:
            reasons.append(str(exc))
    return None, "no LLM key found (set GROQ_API_KEY or GEMINI_API_KEY, e.g. in .env); " + "; ".join(reasons)


class LLM:
    def __init__(self, provider: str | Provider | None = None, model: Optional[str] = None,
                 cache_dir: Optional[str | Path] = None, effort: str = "medium"):
        _load_dotenv()   # before reading GUARDIAN_MODEL / keys, so .env settings apply to the first LLM too
        self.model = model or os.environ.get("GUARDIAN_MODEL") or DEFAULT_MODEL
        self.effort = effort
        self.cache_dir = Path(cache_dir or os.environ.get("GUARDIAN_LLM_CACHE") or ".guardian_cache/llm")
        self.calls = Counter()        # real API calls per purpose
        self.cache_hits = Counter()
        self.errors: list[str] = []
        self.disabled_reason: Optional[str] = None
        self.provider: Optional[Provider] = None

        choice = provider if provider is not None else os.environ.get("GUARDIAN_LLM", "auto")
        if isinstance(choice, str) and choice == "auto" and os.environ.get("GUARDIAN_LLM"):
            choice = os.environ["GUARDIAN_LLM"]   # e.g. GUARDIAN_LLM=groq in .env picks the provider
        if not isinstance(choice, str):
            self.provider = choice
            self.model = getattr(choice, "model", self.model)
        elif choice == "offline":
            self.disabled_reason = "offline mode (no LLM calls)"
        elif choice == "auto":
            self.provider, self.disabled_reason = _auto_provider(self.model)
        elif choice in ("anthropic", *OPENAI_COMPAT):
            try:
                self.provider = (AnthropicProvider(self.model) if choice == "anthropic"
                                 else OpenAICompatProvider(choice, self.model))
            except ProviderUnavailable as exc:
                self.disabled_reason = str(exc)
        else:
            self.disabled_reason = f"unknown LLM provider {choice!r}"
        if self.provider is not None:
            self.model = getattr(self.provider, "model", self.model)
        # Which jobs may use the LLM. Small free models (Groq / Gemini) write good summaries and
        # explanations but weak tool-calling investigations, so by default they only get "card" and
        # "explain"; investigations then use the deterministic playbooks. GUARDIAN_LLM_PURPOSES=all
        # (or a comma list such as card,explain,analyst) overrides this.
        env = (os.environ.get("GUARDIAN_LLM_PURPOSES") or "").strip().lower()
        if env:
            self.purposes: Optional[set[str]] = None if env == "all" else {p.strip() for p in env.split(",") if p.strip()}
        else:
            self.purposes = {"card", "explain"} if isinstance(self.provider, OpenAICompatProvider) else None
        self.skipped = Counter()

    # ------------------------------------------------------------------ state
    @property
    def available(self) -> bool:
        return self.provider is not None and self.disabled_reason is None

    @property
    def provider_name(self) -> str:
        return getattr(self.provider, "name", "offline") if self.available else "offline"

    def used(self, purpose: str) -> int:
        return self.calls[purpose]

    def stats(self) -> dict:
        return {"provider": self.provider_name, "model": self.model if self.available else None,
                "calls": dict(self.calls), "cache_hits": dict(self.cache_hits),
                "disabled_reason": self.disabled_reason, "errors": self.errors[-10:],
                "purposes": sorted(self.purposes) if self.purposes is not None else "all",
                "skipped_to_rules": dict(self.skipped)}

    # ------------------------------------------------------------------ calls
    def _key(self, payload: dict) -> str:
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def create(self, purpose: str, system: str, messages: list[dict], tools: Optional[list[dict]] = None,
               json_schema: Optional[dict] = None, max_tokens: int = 16000,
               effort: Optional[str] = None) -> Optional[dict]:
        """One cached Messages call. Returns ``None`` if no provider can answer."""
        if self.purposes is not None and purpose not in self.purposes:
            self.skipped[purpose] += 1      # caller falls back to its deterministic path
            return None
        effort = effort or self.effort
        payload = {"model": self.model, "system": system, "messages": messages, "tools": tools,
                   "schema": json_schema, "max_tokens": max_tokens, "effort": effort}
        key = self._key(payload)
        path = self.cache_dir / key[:2] / f"{key}.json"
        if path.exists():
            try:
                self.cache_hits[purpose] += 1
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        if not self.available:
            return None
        try:
            resp = self.provider.create(system=system, messages=messages, tools=tools,
                                        json_schema=json_schema, max_tokens=max_tokens, effort=effort)
        except ProviderUnavailable as exc:
            self.disabled_reason = str(exc)
            self.errors.append(str(exc))
            return None
        except Exception as exc:  # one failed call must not stop the scan
            self.errors.append(f"{purpose}: {type(exc).__name__}: {exc}")
            self.calls[purpose] += 1
            return None
        self.calls[purpose] += 1
        if resp.get("stop_reason") == "refusal":
            self.errors.append(f"{purpose}: model declined the request")
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(resp, ensure_ascii=False), encoding="utf-8")
        return resp

    def complete_json(self, purpose: str, system: str, prompt: str, schema: dict,
                      effort: Optional[str] = None) -> Optional[dict]:
        resp = self.create(purpose, system, [{"role": "user", "content": prompt}], json_schema=schema,
                           max_tokens=16000, effort=effort)
        if not resp:
            return None
        text = next((b.get("text") for b in resp.get("content", []) if b.get("type") == "text"), None)
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            self.errors.append(f"{purpose}: response was not valid JSON")
            return None
