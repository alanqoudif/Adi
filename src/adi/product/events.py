"""Typed event bus for the Product layer (plain shell + future TUI).

Core (orchestrator, executor, validation engine, ...) does not depend on
this module and does not import Textual or any UI library — events are
emitted *by the Product layer* while it drives Core, not by Core itself.
This keeps the dependency direction Core <- Product <- UI, as required by
docs/product-implementation-status.md.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    ASSESSMENT_STARTED = "assessment_started"
    ASSESSMENT_RESUMED = "assessment_resumed"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    MODEL_ERROR = "model_error"
    CAPABILITY_REQUESTED = "capability_requested"
    CAPABILITY_SELECTED = "capability_selected"
    TOOL_STARTED = "tool_started"
    TOOL_PROGRESS = "tool_progress"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"
    FALLBACK_SELECTED = "fallback_selected"
    OBSERVATION_CREATED = "observation_created"
    ENDPOINT_DISCOVERED = "endpoint_discovered"
    SOURCE_ROUTE_DISCOVERED = "source_route_discovered"
    CORRELATION_CREATED = "correlation_created"
    HYPOTHESIS_CREATED = "hypothesis_created"
    VALIDATION_STARTED = "validation_started"
    VALIDATION_COMPLETED = "validation_completed"
    HYPOTHESIS_REJECTED = "hypothesis_rejected"
    FINDING_CONFIRMED = "finding_confirmed"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_RESOLVED = "approval_resolved"
    REPORT_GENERATED = "report_generated"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_PAUSED = "assessment_paused"
    ASSESSMENT_STOPPED = "assessment_stopped"
    SCOPE_CHANGED = "scope_changed"
    NOTICE = "notice"
    ERROR = "error"


@dataclass(frozen=True)
class Event:
    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


Listener = Callable[[Event], "Awaitable[None] | None"]


class EventBus:
    """Minimal async-safe pub/sub. Listeners may be sync or async callables;
    a raising listener never aborts emission to the remaining listeners or
    to the emitting workflow — it is recorded as a NOTICE-less best effort
    and swallowed, since UI rendering bugs must never break an assessment.
    """

    def __init__(self) -> None:
        self._listeners: list[Listener] = []
        self.history: list[Event] = []
        self.max_history = 2000

    def subscribe(self, listener: Listener) -> Callable[[], None]:
        self._listeners.append(listener)

        def _unsubscribe() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return _unsubscribe

    async def emit(self, type: EventType, **data: Any) -> Event:
        event = Event(type=type, data=data)
        self.history.append(event)
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history :]
        for listener in list(self._listeners):
            try:
                result = listener(event)
                if result is not None and hasattr(result, "__await__"):
                    await result
            except Exception:
                continue
        return event
