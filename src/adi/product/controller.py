"""ProductController: the single seam between the Product layer (chat,
plain shell, future TUI) and the real Core (`Assessment`, `Orchestrator`,
`ScopeEngine`, ...).

    user message
      -> ProductController.handle_message
      -> (scope/slash interpretation, or) goal update
      -> Assessment.build_orchestrator(llm)
      -> Orchestrator.run(max_iterations=1) in a loop   [background task]
      -> Core: planner -> capability -> scope -> tool -> evidence -> ...
      -> StepOutcome
      -> typed Event on the EventBus
      -> UI (plain shell today, Textual later) renders the event

No raw shell path exists from the model to the runtime here: the model
only ever produces a `PlannedAction` consumed by the existing, unmodified
`ToolExecutor`/`ScopeEngine`. This module adds *no* new execution path —
it only sequences the existing one and narrates it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from adi.agent.orchestrator import StepOutcome
from adi.assessment import Assessment
from adi.config.models import AdiConfig
from adi.llm.base import LLMError
from adi.product.events import EventBus, EventType
from adi.product.models import ModelManager
from adi.product.sessions import SessionRegistry
from adi.scope.models import AssessmentMode, Scope


class ControllerState:
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"


class ProductController:
    """Owns one active `Assessment` plus the background task driving its
    `Orchestrator`. One controller per Product Shell process (plain or
    TUI)."""

    def __init__(
        self,
        config: AdiConfig,
        project_root: Path | None = None,
        events: EventBus | None = None,
    ):
        self.config = config
        self.project_root = project_root or Path.cwd()
        self.events = events or EventBus()
        self.models = ModelManager(self.project_root)
        self.sessions = SessionRegistry(self.project_root)

        self.assessment: Assessment | None = None
        self.session_name: str | None = None
        self.state: str = ControllerState.IDLE
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # not paused by default
        self._stop_requested = False
        self._task: asyncio.Task | None = None

    # -- lifecycle --------------------------------------------------------

    async def new_assessment(
        self, target: str, *, mode: AssessmentMode = AssessmentMode.LAB,
        source_root: str | None = None, name: str | None = None,
        max_actions: int = 150,
    ) -> Assessment:
        notes = [f"source_root: {source_root}"] if source_root else []
        scope = Scope(
            name=target, mode=mode, targets=[target],
            notes=notes, max_actions=max_actions,
        )
        self.assessment = Assessment.create(scope, self.config, self.project_root)
        record = self.sessions.register(self.assessment.id, target, name=name)
        self.session_name = record.name
        await self.events.emit(
            EventType.ASSESSMENT_STARTED,
            assessment_id=self.assessment.id, session=record.name, target=target,
        )
        self.state = ControllerState.IDLE
        return self.assessment

    async def resume_assessment(self, session_name: str) -> Assessment:
        record = self.sessions.get(session_name)
        if record is None:
            raise ValueError(f"no session named '{session_name}'")
        self.assessment = Assessment.resume(record.assessment_id, self.config, self.project_root)
        self.session_name = session_name
        self.sessions.touch(session_name)
        await self.events.emit(
            EventType.ASSESSMENT_RESUMED,
            assessment_id=self.assessment.id, session=session_name,
        )
        self.state = ControllerState.IDLE
        return self.assessment

    def auto_resume_candidate(self) -> "SessionRecordLike | None":
        return self.sessions.most_recent()

    # -- running ----------------------------------------------------------

    async def start(self, role: str = "planner", data_category: str = "general_planning") -> None:
        """Start (or resume) the orchestrator loop as a background task."""
        if self.assessment is None:
            raise RuntimeError("no active assessment — call new_assessment()/resume_assessment() first")
        if self._task is not None and not self._task.done():
            return
        self._stop_requested = False
        self._pause_event.set()
        self._task = asyncio.create_task(self._drive(role, data_category))

    async def _drive(self, role: str, data_category: str) -> None:
        assert self.assessment is not None
        try:
            llm = self.models.provider_for(role, data_category=data_category)  # type: ignore[arg-type]
        except LLMError as exc:
            await self.events.emit(EventType.MODEL_ERROR, error=str(exc))
            self.state = ControllerState.IDLE
            return

        orchestrator = self.assessment.build_orchestrator(llm)
        self.state = ControllerState.RUNNING
        while True:
            if self._stop_requested:
                self.assessment.workspace.set_assessment_status("stopped")
                await self.events.emit(EventType.ASSESSMENT_STOPPED, assessment_id=self.assessment.id)
                self.state = ControllerState.STOPPED
                return

            await self._pause_event.wait()
            if self._stop_requested:
                continue

            try:
                outcomes = await orchestrator.run(max_iterations=1)
            except LLMError as exc:
                await self.events.emit(EventType.MODEL_ERROR, error=str(exc))
                self.state = ControllerState.IDLE
                return

            for outcome in outcomes:
                await self._emit_for_outcome(outcome)
                if outcome.status in ("completed_assessment", "paused", "stopped"):
                    self.state = (
                        ControllerState.COMPLETED if outcome.status == "completed_assessment"
                        else ControllerState.IDLE
                    )
                    return

    async def _emit_for_outcome(self, outcome: StepOutcome) -> None:
        action = outcome.action
        capability = getattr(action, "capability", None) if action else None
        if outcome.status == "completed" and action is not None:
            await self.events.emit(
                EventType.TOOL_COMPLETED, capability=capability, detail=outcome.detail,
            )
        elif outcome.status == "blocked":
            await self.events.emit(EventType.APPROVAL_REQUIRED, capability=capability, detail=outcome.detail)
        elif outcome.status == "failed":
            await self.events.emit(EventType.TOOL_FAILED, capability=capability, detail=outcome.detail)
        elif outcome.status == "completed_assessment":
            await self.events.emit(EventType.ASSESSMENT_COMPLETED, detail=outcome.detail)
        elif outcome.status == "paused":
            await self.events.emit(EventType.ASSESSMENT_PAUSED, detail=outcome.detail)
        else:
            await self.events.emit(EventType.NOTICE, status=outcome.status, detail=outcome.detail)

    async def pause(self) -> None:
        self._pause_event.clear()
        self.state = ControllerState.PAUSED
        await self.events.emit(EventType.ASSESSMENT_PAUSED)

    async def continue_(self) -> None:
        self._pause_event.set()
        if self.state == ControllerState.PAUSED:
            self.state = ControllerState.RUNNING

    async def stop(self) -> None:
        self._stop_requested = True
        self._pause_event.set()
        if self._task is not None:
            await self._task
        self.state = ControllerState.STOPPED

    async def wait_idle(self) -> None:
        if self._task is not None:
            await self._task


class SessionRecordLike:  # pragma: no cover - typing helper only
    name: str
