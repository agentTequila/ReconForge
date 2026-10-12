"""Shared helpers for recon modules."""

from __future__ import annotations

import concurrent.futures
from typing import Any, Callable, Iterable

OK = "2XX"  # sentinel meaning "treat as success" in detection specs


def chunked_map(func: Callable, items: Iterable, max_workers: int = 30) -> list:
    items = list(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(func, items))


def pick(obj: dict, *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = obj.get(key)
        if value is not None:
            return value
    return default
