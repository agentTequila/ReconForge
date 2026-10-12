"""Event bus: core emits, frontends subscribe. Keeps the engine UI-free."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

Listener = Callable[["Event"], None]


@dataclass
class Event:
    type: str  # scan_started | module_started | module_finished | log | finding | scan_finished
    data: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EventBus:
    def __init__(self) -> None:
        self._listeners: list[Listener] = []

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def emit(self, type: str, **data: Any) -> None:
        event = Event(type=type, data=data)
        for listener in list(self._listeners):
            try:
                listener(event)
            except Exception:
                pass
