"""File-based response cache with TTL to reduce repeat API calls."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

DEFAULT_TTL = 6 * 3600  # 6 hours


class ResponseCache:
    def __init__(self, directory: Path | None = None, ttl: int = DEFAULT_TTL,
                 enabled: bool = True) -> None:
        self.enabled = enabled
        self.ttl = ttl
        self.directory = directory
        if enabled and directory:
            directory.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path | None:
        if not self.enabled or not self.directory:
            return None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.directory / f"{digest}.json"

    def get(self, key: str) -> Any | None:
        path = self._path(key)
        if not path or not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if time.time() - payload.get("ts", 0) > self.ttl:
            try:
                path.unlink()
            except OSError:
                pass
            return None
        return payload.get("data")

    def set(self, key: str, data: Any) -> None:
        path = self._path(key)
        if not path:
            return
        try:
            path.write_text(
                json.dumps({"ts": time.time(), "data": data}, ensure_ascii=False),
                encoding="utf-8",
            )
        except (OSError, TypeError, ValueError):
            pass
