"""EvidenceStore: the only place that creates an `Evidence` row.

Centralizing creation here means redaction and hashing happen exactly
once, consistently, regardless of which validator or capability is
recording the evidence.
"""

from __future__ import annotations

import json

from adi.evidence.integrity import hash_text
from adi.evidence.models import Evidence, EvidenceType
from adi.evidence.redaction import sanitize_for_evidence
from adi.knowledge.workspace import Workspace


class EvidenceStore:
    def __init__(self, workspace: Workspace):
        self.workspace = workspace

    def create(
        self,
        type: EvidenceType,
        *,
        source: str,
        subject: str = "",
        summary: str = "",
        raw_text: str = "",
        raw_reference: str | None = None,
        content_type: str = "",
        confidence: float = 1.0,
        related_hypothesis_ids: list[str] | None = None,
        related_finding_ids: list[str] | None = None,
        metadata: dict | None = None,
    ) -> Evidence:
        sanitized = sanitize_for_evidence(raw_text, content_type=content_type) if raw_text else ""
        evidence_hash = hash_text(raw_text) if raw_text else ""

        evidence_id = self.workspace.record_evidence(
            type=type.value,
            source=source,
            subject=subject,
            summary=summary,
            raw_reference=raw_reference,
            sanitized_preview=sanitized,
            hash=evidence_hash,
            related_hypothesis_ids_json=json.dumps(related_hypothesis_ids or []),
            related_finding_ids_json=json.dumps(related_finding_ids or []),
            confidence=confidence,
            metadata_json=json.dumps(metadata or {}),
        )
        record = self.workspace.get_evidence(evidence_id)
        assert record is not None
        return Evidence.from_record(record)

    def get(self, evidence_id: str) -> Evidence | None:
        record = self.workspace.get_evidence(evidence_id)
        return Evidence.from_record(record) if record else None

    def list(self) -> list[Evidence]:
        return [Evidence.from_record(r) for r in self.workspace.list_evidence()]

    def for_hypothesis(self, hypothesis_id: str) -> list[Evidence]:
        return [e for e in self.list() if hypothesis_id in e.related_hypothesis_ids]

    def for_finding(self, finding_id: str) -> list[Evidence]:
        return [e for e in self.list() if finding_id in e.related_finding_ids]

    def link_to_finding(self, evidence_id: str, finding_id: str) -> None:
        self.workspace.link_evidence_to_finding(evidence_id, finding_id)
