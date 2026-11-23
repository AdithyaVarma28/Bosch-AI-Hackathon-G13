"""Cached HTTP client with offline mode. Every external call goes through here."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx


class CacheMiss(RuntimeError):
    pass


class CachedHttp:
    def __init__(self, cache_dir: Path, offline: bool = False, timeout: float = 20.0, client: httpx.Client | None = None):
        self.dir = Path(cache_dir) / "http"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self._client = client
        self.timeout = timeout
        self.stats = {"live": 0, "cache": 0, "miss": 0, "error": 0}

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, headers={"User-Agent": "guardian-supply-chain-scanner/0.1"},
                                        follow_redirects=True)
        return self._client

    def _key(self, method: str, url: str, body: Any) -> Path:
        h = hashlib.sha256(f"{method}|{url}|{json.dumps(body, sort_keys=True) if body is not None else ''}".encode()).hexdigest()
        return self.dir / f"{h}.json"

    def request_json(self, method: str, url: str, body: Any = None) -> tuple[Any, str]:
        """Returns (json, 'live'|'cache'). Raises CacheMiss offline, httpx errors online. 404 -> (None, src)."""
        path = self._key(method, url, body)
        if path.exists():
            self.stats["cache"] += 1
            cached = json.loads(path.read_text(encoding="utf-8"))
            return cached.get("body"), "cache"
        if self.offline:
            self.stats["miss"] += 1
            raise CacheMiss(url)
        try:
            r = self.client.request(method, url, json=body) if body is not None else self.client.request(method, url)
        except httpx.HTTPError:
            self.stats["error"] += 1
            raise
        if r.status_code == 404:
            path.write_text(json.dumps({"status": 404, "body": None}), encoding="utf-8")
            self.stats["live"] += 1
            return None, "live"
        r.raise_for_status()
        data = r.json()
        path.write_text(json.dumps({"status": r.status_code, "body": data}), encoding="utf-8")
        self.stats["live"] += 1
        return data, "live"
