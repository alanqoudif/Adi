"""Typed evidence model (spec Phase 4 section 2).

A Finding must be traceable back to the evidence that supports it, and
evidence must never leak secrets into planner/critic context. Raw content
may live on disk (`raw_reference`); only `sanitized_preview` — bounded and
redacted — ever reaches an LLM prompt.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from adi.knowledge.db import EvidenceRecord


class EvidenceType(str, Enum):
    HTTP_EXCHANGE = "http_exchange"
    BROWSER_STATE = "browser_state"
    SCREENSHOT = "screenshot"
    TOOL_RESULT = "tool_result"
    SOURCE_SNIPPET = "source_snippet"
    SOURCE_ROUTE = "source_route"
    SOURCE_CONFIG = "source_config"
    DEPENDENCY_RECORD = "dependency_record"
    SECRET_INDICATION = "secret_indication"
    SAST_RESULT = "sast_result"
    SOURCE_LOCATION = "source_location"
    CONFIGURATION = "configuration"
    RESPONSE_COMPARISON = "response_comparison"
    SESSION_COMPARISON = "session_comparison"
    REPRODUCTION_RESULT = "reproduction_result"
    SCANNER_INDICATION = "scanner_indication"
    MANUAL_NOTE = "manual_note"


class Evidence(BaseModel):
    id: str | None = None
    type: EvidenceType
    source: str = ""
    subject: str = ""
    summary: str = ""
    raw_reference: str | None = None
    sanitized_preview: str = ""
    hash: str = ""
    related_hypothesis_ids: list[str] = Field(default_factory=list)
    related_finding_ids: list[str] = Field(default_factory=list)
    confidence: float = 1.0
    metadata: dict = Field(default_factory=dict)
    created_at: datetime | None = None

    @classmethod
    def from_record(cls, record: EvidenceRecord) -> Evidence:
        import json

        return cls(
            id=record.id,
            type=EvidenceType(record.type),
            source=record.source,
            subject=record.subject,
            summary=record.summary,
            raw_reference=record.raw_reference,
            sanitized_preview=record.sanitized_preview,
            hash=record.hash,
            related_hypothesis_ids=json.loads(record.related_hypothesis_ids_json),
            related_finding_ids=json.loads(record.related_finding_ids_json),
            confidence=record.confidence,
            metadata=json.loads(record.metadata_json),
            created_at=record.created_at,
        )
