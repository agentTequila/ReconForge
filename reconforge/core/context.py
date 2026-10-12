"""ScanContext: everything a recon module needs to do its job."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from reconforge.core.cache import ResponseCache
from reconforge.core.events import EventBus
from reconforge.core.ratelimit import TokenBucket

USER_AGENT = "ReconForge/0.1.0 (+https://github.com/ReconForge/ReconForge)"


@dataclass
class ModuleResult:
    module_id: str
    status: str = "ok"  # ok | skipped | error | timeout
    data: Any = None
    findings: list[str] = field(default_factory=list)
    error: str | None = None
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id,
            "status": self.status,
            "data": self.data,
            "findings": self.findings,
            "error": self.error,
            "duration_s": round(self.duration_s, 3),
        }


class ScanContext:
    def __init__(
        self,
        keys: dict[str, str] | None = None,
        events: EventBus | None = None,
        cache: ResponseCache | None = None,
        output_dir: Path | None = None,
        proxy: str | None = None,
        use_cache: bool = True,
        redact: bool = False,
        yes: bool = False,
        module_timeout: int = 120,
    ) -> None:
        self.keys = {k: v for k, v in (keys or {}).items() if v}
        self.events = events or EventBus()
        self.cache = cache or ResponseCache(enabled=False)
        self.output_dir = output_dir
        self.proxy = proxy
        self.redact = redact
        self.yes = yes
        self.module_timeout = module_timeout
        self.limiter = TokenBucket(rate=5.0, burst=15)
        self.options: dict[str, Any] = {}

        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def emit(self, event_type: str, **data: Any) -> None:
        self.events.emit(event_type, **data)

    def log(self, message: str, level: str = "info") -> None:
        self.emit("log", level=level, message=message)

    def finding(self, message: str, module_id: str = "") -> None:
        self.emit("finding", message=message, module_id=module_id)

    def http(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Rate-limited session request with sane defaults."""
        self.limiter.acquire()
        kwargs.setdefault("timeout", 30)
        cache_key = f"{method}:{url}:{json.dumps(kwargs.get('params') or {}, sort_keys=True)}"
        if method.upper() == "GET":
            cached = self.cache.get(cache_key)
            if cached is not None:
                return _CachedResponse(cached)  # type: ignore[return-value]
        response = self.session.request(method, url, **kwargs)
        if method.upper() == "GET" and response.status_code == 200:
            try:
                self.cache.set(
                    cache_key,
                    {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "text": response.text[:2_000_000],
                        "url": response.url,
                    },
                )
            except ValueError:
                pass
        return response

    def has_key(self, name: str) -> bool:
        return bool(self.keys.get(name))

    def save(self, filename: str, data: Any) -> Path | None:
        if not self.output_dir:
            return None
        path = self.output_dir / filename
        try:
            if isinstance(data, (dict, list)):
                path.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
            else:
                path.write_text(str(data), encoding="utf-8")
        except OSError:
            return None
        return path


class _CachedResponse:
    """Minimal response-like object served from cache."""

    def __init__(self, payload: dict) -> None:
        self.status_code = payload.get("status_code", 200)
        self.headers = payload.get("headers", {})
        self.text = payload.get("text", "")
        self.url = payload.get("url", "")
        self.content = self.text.encode("utf-8", errors="ignore")
        self.from_cache = True

    def json(self) -> Any:
        return json.loads(self.text)
