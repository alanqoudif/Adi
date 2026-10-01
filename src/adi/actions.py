"""Shared action types.

These live outside both `adi.agent` and `adi.scope` because both depend on
them: the planner produces `PlannedAction`s, and the scope engine authorizes
them before execution. Keeping the type here avoids a circular import
between those two packages.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    RUN_TOOL = "run_tool"
    HTTP_REQUEST = "http_request"
    BROWSER_ACTION = "browser_action"
    READ_FILE = "read_file"
    SEARCH_CODE = "search_code"
    LOAD_SKILL = "load_skill"
    UPDATE_HYPOTHESIS = "update_hypothesis"
    VERIFY_FINDING = "verify_finding"
    GENERATE_REPORT = "generate_report"
    ASK_USER = "ask_user"
    COMPLETE = "complete"


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    ELEVATED = "elevated"
    HIGH = "high"


class PlannedAction(BaseModel):
    """A typed action proposed by the planner.

    The LLM is asked to produce this schema rather than a raw shell command
    or free-form instruction — see docs/agent-loop.md.
    """

    action_type: ActionType
    capability: str = ""
    reason_summary: str = ""
    expected_information_gain: str = ""
    related_hypothesis_id: str | None = None

    target: str | None = None
    tool: str | None = None
    parameters: dict = Field(default_factory=dict)
    risk: RiskLevel = RiskLevel.LOW
